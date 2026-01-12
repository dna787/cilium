// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package cmd

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"unsafe"

	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"
	"github.com/go-openapi/strfmt"
	"github.com/sirupsen/logrus"
	versionapi "k8s.io/apimachinery/pkg/version"

	"github.com/cilium/cilium/api/v1/models"
	. "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/annotation"
	"github.com/cilium/cilium/pkg/backoff"
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/controller"
	"github.com/cilium/cilium/pkg/datapath/linux/probes"
	datapathOption "github.com/cilium/cilium/pkg/datapath/option"
	datapathTables "github.com/cilium/cilium/pkg/datapath/tables"
	datapath "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/identity"
	lxcmap "github.com/cilium/cilium/pkg/ipcache"
	k8smetrics "github.com/cilium/cilium/pkg/k8s/metrics"
	"github.com/cilium/cilium/pkg/kvstore"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	ipcachemap "github.com/cilium/cilium/pkg/maps/ipcache"
	ipmasqmap "github.com/cilium/cilium/pkg/maps/ipmasq"
	"github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/metricsmap"
	"github.com/cilium/cilium/pkg/maps/ratelimitmap"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	tunnelmap "github.com/cilium/cilium/pkg/maps/tunnel"
	nodeTypes "github.com/cilium/cilium/pkg/node/types"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/status"
	"github.com/cilium/cilium/pkg/time"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/ebpf"
)

const (
	// k8sVersionCheckInterval is the interval in which the Kubernetes
	// version is verified even if connectivity is given
	k8sVersionCheckInterval = 15 * time.Minute

	// k8sMinimumEventHeartbeat is the time interval in which any received
	// event will be considered proof that the apiserver connectivity is
	// healthy
	k8sMinimumEventHeartbeat = time.Minute
)

type k8sVersion struct {
	version          string
	lastVersionCheck time.Time
	lock             lock.Mutex
}

func (k *k8sVersion) cachedVersion() (string, bool) {
	k.lock.Lock()
	defer k.lock.Unlock()

	if time.Since(k8smetrics.LastSuccessInteraction.Time()) > k8sMinimumEventHeartbeat {
		return "", false
	}

	if k.version == "" || time.Since(k.lastVersionCheck) > k8sVersionCheckInterval {
		return "", false
	}

	return k.version, true
}

func (k *k8sVersion) update(version *versionapi.Info) string {
	k.lock.Lock()
	defer k.lock.Unlock()

	k.version = fmt.Sprintf("%s.%s (%s) [%s]", version.Major, version.Minor, version.GitVersion, version.Platform)
	k.lastVersionCheck = time.Now()
	return k.version
}

var k8sVersionCache k8sVersion

func (d *Daemon) getK8sStatus() *models.K8sStatus {
	if !d.clientset.IsEnabled() {
		return &models.K8sStatus{State: models.StatusStateDisabled}
	}

	version, valid := k8sVersionCache.cachedVersion()
	if !valid {
		k8sVersion, err := d.clientset.Discovery().ServerVersion()
		if err != nil {
			return &models.K8sStatus{State: models.StatusStateFailure, Msg: err.Error()}
		}

		version = k8sVersionCache.update(k8sVersion)
	}

	k8sStatus := &models.K8sStatus{
		State:          models.StatusStateOk,
		Msg:            version,
		K8sAPIVersions: d.k8sWatcher.GetAPIGroups(),
	}

	return k8sStatus
}

func (d *Daemon) getMasqueradingStatus() *models.Masquerading {
	s := &models.Masquerading{
		Enabled: option.Config.MasqueradingEnabled(),
		EnabledProtocols: &models.MasqueradingEnabledProtocols{
			IPV4: option.Config.EnableIPv4Masquerade,
			IPV6: option.Config.EnableIPv6Masquerade,
		},
	}

	if !option.Config.MasqueradingEnabled() {
		return s
	}

	localNode, err := d.nodeLocalStore.Get(context.TODO())
	if err != nil {
		return s
	}

	if option.Config.EnableIPv4 {
		// SnatExclusionCidr is the legacy field, continue to provide
		// it for the time being
		s.SnatExclusionCidr = datapath.RemoteSNATDstAddrExclusionCIDRv4(localNode).String()
		s.SnatExclusionCidrV4 = datapath.RemoteSNATDstAddrExclusionCIDRv4(localNode).String()
	}

	if option.Config.EnableIPv6 {
		s.SnatExclusionCidrV6 = datapath.RemoteSNATDstAddrExclusionCIDRv6(localNode).String()
	}

	if option.Config.EnableBPFMasquerade {
		s.Mode = models.MasqueradingModeBPF
		s.IPMasqAgent = option.Config.EnableIPMasqAgent
		return s
	}

	s.Mode = models.MasqueradingModeIptables
	return s
}

func (d *Daemon) getSRv6Status() *models.Srv6 {
	return &models.Srv6{
		Enabled:       option.Config.EnableSRv6,
		Srv6EncapMode: option.Config.SRv6EncapMode,
	}
}

func (d *Daemon) getIPV6BigTCPStatus() *models.IPV6BigTCP {
	s := &models.IPV6BigTCP{
		Enabled: d.bigTCPConfig.EnableIPv6BIGTCP,
		MaxGRO:  int64(d.bigTCPConfig.GetGROIPv6MaxSize()),
		MaxGSO:  int64(d.bigTCPConfig.GetGSOIPv6MaxSize()),
	}

	return s
}

func (d *Daemon) getIPV4BigTCPStatus() *models.IPV4BigTCP {
	s := &models.IPV4BigTCP{
		Enabled: d.bigTCPConfig.EnableIPv4BIGTCP,
		MaxGRO:  int64(d.bigTCPConfig.GetGROIPv4MaxSize()),
		MaxGSO:  int64(d.bigTCPConfig.GetGSOIPv4MaxSize()),
	}

	return s
}

func (d *Daemon) getBandwidthManagerStatus() *models.BandwidthManager {
	s := &models.BandwidthManager{
		Enabled: d.bwManager.Enabled(),
	}

	if !d.bwManager.Enabled() {
		return s
	}

	s.CongestionControl = models.BandwidthManagerCongestionControlCubic
	if d.bwManager.BBREnabled() {
		s.CongestionControl = models.BandwidthManagerCongestionControlBbr
	}

	devs, _ := datapathTables.SelectedDevices(d.devices, d.db.ReadTxn())
	s.Devices = datapathTables.DeviceNames(devs)
	return s
}

func (d *Daemon) getRoutingStatus() *models.Routing {
	s := &models.Routing{
		IntraHostRoutingMode: models.RoutingIntraHostRoutingModeBPF,
		InterHostRoutingMode: models.RoutingInterHostRoutingModeTunnel,
		TunnelProtocol:       d.tunnelConfig.Protocol().String(),
	}
	if option.Config.EnableHostLegacyRouting {
		s.IntraHostRoutingMode = models.RoutingIntraHostRoutingModeLegacy
	}
	if option.Config.RoutingMode == option.RoutingModeNative {
		s.InterHostRoutingMode = models.RoutingInterHostRoutingModeNative
	}
	return s
}

func (d *Daemon) getHostFirewallStatus() *models.HostFirewall {
	mode := models.HostFirewallModeDisabled
	if option.Config.EnableHostFirewall {
		mode = models.HostFirewallModeEnabled
	}
	devs, _ := datapathTables.SelectedDevices(d.devices, d.db.ReadTxn())
	return &models.HostFirewall{
		Mode:    mode,
		Devices: datapathTables.DeviceNames(devs),
	}
}

func (d *Daemon) getClockSourceStatus() *models.ClockSource {
	return timestamp.GetClockSourceFromOptions()
}

func (d *Daemon) getAttachModeStatus() models.AttachMode {
	mode := models.AttachModeTc
	if option.Config.EnableTCX && probes.HaveTCX() == nil {
		mode = models.AttachModeTcx
	}
	return mode
}

func (d *Daemon) getDatapathModeStatus() models.DatapathMode {
	mode := models.DatapathModeVeth
	switch option.Config.DatapathMode {
	case datapathOption.DatapathModeNetkit:
		mode = models.DatapathModeNetkit
	case datapathOption.DatapathModeNetkitL2:
		mode = models.DatapathModeNetkitDashL2
	}
	return mode
}

func (d *Daemon) getCNIChainingStatus() *models.CNIChainingStatus {
	mode := d.cniConfigManager.GetChainingMode()
	if len(mode) == 0 {
		mode = models.CNIChainingStatusModeNone
	}
	return &models.CNIChainingStatus{
		Mode: mode,
	}
}

func (d *Daemon) getKubeProxyReplacementStatus() *models.KubeProxyReplacement {
	var mode string
	switch option.Config.KubeProxyReplacement {
	case option.KubeProxyReplacementTrue:
		mode = models.KubeProxyReplacementModeTrue
	case option.KubeProxyReplacementFalse:
		mode = models.KubeProxyReplacementModeFalse
	}

	devices, _ := datapathTables.SelectedDevices(d.devices, d.db.ReadTxn())
	devicesList := make([]*models.KubeProxyReplacementDeviceListItems0, len(devices))
	for i, dev := range devices {
		info := &models.KubeProxyReplacementDeviceListItems0{
			Name: dev.Name,
			IP:   make([]string, len(dev.Addrs)),
		}
		for _, addr := range dev.Addrs {
			info.IP = append(info.IP, addr.Addr.String())
		}
		devicesList[i] = info
	}

	features := &models.KubeProxyReplacementFeatures{
		NodePort:              &models.KubeProxyReplacementFeaturesNodePort{},
		HostPort:              &models.KubeProxyReplacementFeaturesHostPort{},
		ExternalIPs:           &models.KubeProxyReplacementFeaturesExternalIPs{},
		SocketLB:              &models.KubeProxyReplacementFeaturesSocketLB{},
		SocketLBTracing:       &models.KubeProxyReplacementFeaturesSocketLBTracing{},
		SessionAffinity:       &models.KubeProxyReplacementFeaturesSessionAffinity{},
		GracefulTermination:   &models.KubeProxyReplacementFeaturesGracefulTermination{},
		Nat46X64:              &models.KubeProxyReplacementFeaturesNat46X64{},
		BpfSocketLBHostnsOnly: option.Config.BPFSocketLBHostnsOnly,
	}
	if option.Config.EnableNodePort {
		features.NodePort.Enabled = true
		features.NodePort.Mode = strings.ToUpper(option.Config.NodePortMode)
		switch option.Config.LoadBalancerDSRDispatch {
		case option.DSRDispatchIPIP:
			features.NodePort.DsrMode = models.KubeProxyReplacementFeaturesNodePortDsrModeIPIP
		case option.DSRDispatchOption:
			features.NodePort.DsrMode = models.KubeProxyReplacementFeaturesNodePortDsrModeIPOptionExtension
		case option.DSRDispatchGeneve:
			features.NodePort.DsrMode = models.KubeProxyReplacementFeaturesNodePortDsrModeGeneve
		}
		if option.Config.NodePortMode == option.NodePortModeHybrid {
			//nolint:staticcheck
			features.NodePort.Mode = strings.Title(option.Config.NodePortMode)
		}
		features.NodePort.Algorithm = models.KubeProxyReplacementFeaturesNodePortAlgorithmRandom
		if option.Config.NodePortAlg == option.NodePortAlgMaglev {
			features.NodePort.Algorithm = models.KubeProxyReplacementFeaturesNodePortAlgorithmMaglev
			features.NodePort.LutSize = int64(d.maglevConfig.MaglevTableSize)
		}
		if option.Config.LoadBalancerAlgorithmAnnotation {
			features.NodePort.LutSize = int64(d.maglevConfig.MaglevTableSize)
		}
		if option.Config.NodePortAcceleration == option.NodePortAccelerationGeneric {
			features.NodePort.Acceleration = models.KubeProxyReplacementFeaturesNodePortAccelerationGeneric
		} else {
			features.NodePort.Acceleration = strings.Title(option.Config.NodePortAcceleration)
		}
		features.NodePort.PortMin = int64(option.Config.NodePortMin)
		features.NodePort.PortMax = int64(option.Config.NodePortMax)
	}
	if option.Config.EnableHostPort {
		features.HostPort.Enabled = true
	}
	if option.Config.EnableExternalIPs {
		features.ExternalIPs.Enabled = true
	}
	if option.Config.EnableSocketLB {
		features.SocketLB.Enabled = true
		features.SocketLBTracing.Enabled = true
	}
	if option.Config.EnableSessionAffinity {
		features.SessionAffinity.Enabled = true
	}
	if option.Config.EnableK8sTerminatingEndpoint {
		features.GracefulTermination.Enabled = true
	}
	if option.Config.NodePortNat46X64 || option.Config.EnableNat46X64Gateway {
		features.Nat46X64.Enabled = true
		gw := &models.KubeProxyReplacementFeaturesNat46X64Gateway{
			Enabled:  option.Config.EnableNat46X64Gateway,
			Prefixes: make([]string, 0),
		}
		if option.Config.EnableNat46X64Gateway {
			gw.Prefixes = append(gw.Prefixes, option.Config.IPv6NAT46x64CIDR)
		}
		features.Nat46X64.Gateway = gw

		svc := &models.KubeProxyReplacementFeaturesNat46X64Service{
			Enabled: option.Config.NodePortNat46X64,
		}
		features.Nat46X64.Service = svc
	}
	if option.Config.EnableNodePort {
		if option.Config.LoadBalancerAlgorithmAnnotation {
			features.Annotations = append(features.Annotations, annotation.ServiceLoadBalancingAlgorithm)
		}
		if option.Config.LoadBalancerModeAnnotation {
			features.Annotations = append(features.Annotations, annotation.ServiceForwardingMode)
		}
		features.Annotations = append(features.Annotations, annotation.ServiceNodeExposure)
		features.Annotations = append(features.Annotations, annotation.ServiceTypeExposure)
		if option.Config.EnableSVCSourceRangeCheck {
			features.Annotations = append(features.Annotations, annotation.ServiceSourceRangesPolicy)
		}
		sort.Strings(features.Annotations)
	}

	var directRoutingDevice string
	drd, _ := d.directRoutingDev.Get(context.TODO(), d.db.ReadTxn())
	if drd != nil {
		directRoutingDevice = drd.Name
	}

	return &models.KubeProxyReplacement{
		Mode:                mode,
		Devices:             datapathTables.DeviceNames(devices),
		DeviceList:          devicesList,
		DirectRoutingDevice: directRoutingDevice,
		Features:            features,
	}
}

func (d *Daemon) getBPFMapStatus() *models.BPFMapStatus {
	return &models.BPFMapStatus{
		DynamicSizeRatio: option.Config.BPFMapsDynamicSizeRatio,
		Maps: []*models.BPFMapProperties{
			{
				Name: "Auth",
				Size: int64(option.Config.AuthMapEntries),
			},
			{
				Name: "Non-TCP connection tracking",
				Size: int64(option.Config.CTMapEntriesGlobalAny),
			},
			{
				Name: "TCP connection tracking",
				Size: int64(option.Config.CTMapEntriesGlobalTCP),
			},
			{
				Name: "Endpoint policy",
				Size: int64(lxcmap.MaxEntries),
			},
			{
				Name: "IP cache",
				Size: int64(ipcachemap.MaxEntries),
			},
			{
				Name: "IPv4 masquerading agent",
				Size: int64(ipmasqmap.MaxEntriesIPv4),
			},
			{
				Name: "IPv6 masquerading agent",
				Size: int64(ipmasqmap.MaxEntriesIPv6),
			},
			{
				Name: "IPv4 fragmentation",
				Size: int64(option.Config.FragmentsMapEntries),
			},
			{
				Name: "IPv4 service", // cilium_lb4_services_v2
				Size: int64(lbmap.ServiceMapMaxEntries),
			},
			{
				Name: "IPv6 service", // cilium_lb6_services_v2
				Size: int64(lbmap.ServiceMapMaxEntries),
			},
			{
				Name: "IPv4 service backend", // cilium_lb4_backends_v2
				Size: int64(lbmap.ServiceBackEndMapMaxEntries),
			},
			{
				Name: "IPv6 service backend", // cilium_lb6_backends_v2
				Size: int64(lbmap.ServiceBackEndMapMaxEntries),
			},
			{
				Name: "IPv4 service reverse NAT", // cilium_lb4_reverse_nat
				Size: int64(lbmap.RevNatMapMaxEntries),
			},
			{
				Name: "IPv6 service reverse NAT", // cilium_lb6_reverse_nat
				Size: int64(lbmap.RevNatMapMaxEntries),
			},
			{
				Name: "Metrics",
				Size: int64(metricsmap.MaxEntries),
			},
			{
				Name: "Ratelimit metrics",
				Size: int64(ratelimitmap.MaxMetricsEntries),
			},
			{
				Name: "NAT",
				Size: int64(option.Config.NATMapEntriesGlobal),
			},
			{
				Name: "Neighbor table",
				Size: int64(option.Config.NeighMapEntriesGlobal),
			},
			{
				Name: "Global policy",
				Size: int64(option.Config.PolicyMapEntries),
			},
			{
				Name: "Session affinity",
				Size: int64(lbmap.AffinityMapMaxEntries),
			},
			{
				Name: "Sock reverse NAT",
				Size: int64(option.Config.SockRevNatEntries),
			},
			{
				Name: "Tunnel",
				Size: int64(tunnelmap.MaxEntries),
			},
		},
	}
}

func getHealthzHandler(d *Daemon, params GetHealthzParams) middleware.Responder {
	brief := params.Brief != nil && *params.Brief
	requireK8sConnectivity := params.RequireK8sConnectivity != nil && *params.RequireK8sConnectivity
	sr := d.getStatus(brief, requireK8sConnectivity)
	return NewGetHealthzOK().WithPayload(&sr)
}

func getIncHandler(d *Daemon, params GetIncParams) middleware.Responder {
	fmt.Printf("DEBUG getIncHandler\n")
	newVal := params.X + 1
	sr := models.IncResponse{Value: &newVal}
	return NewGetIncOK().WithPayload(&sr)
}

func deserializeConntrackFromReader(
	r io.Reader,
) (*ctmap.CtKey4Global, *ctmap.CtEntry, error) {

	order := binary.LittleEndian

	key := &ctmap.CtKey4Global{}
	entry := &ctmap.CtEntry{}

	if _, err := io.ReadFull(r, key.DestAddr[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, key.SourceAddr[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[2]byte)(unsafe.Pointer(&key.DestPort))[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[2]byte)(unsafe.Pointer(&key.SourcePort))[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[1]byte)(unsafe.Pointer(&key.NextHeader))[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[1]byte)(unsafe.Pointer(&key.Flags))[:]); err != nil {
		return nil, nil, err
	}

	if err := binary.Read(r, order, &entry.Reserved0); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.BackendID); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Packets); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Bytes); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Lifetime); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Flags); err != nil {
		return nil, nil, err
	}
	// revnat value is already in network byte order
	if _, err := io.ReadFull(r, (*[2]byte)(unsafe.Pointer(&entry.RevNAT))[:]); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.TxFlagsSeen); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.RxFlagsSeen); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.SourceSecurityID); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.LastTxReport); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.LastRxReport); err != nil {
		return nil, nil, err
	}

	return key, entry, nil
}

type UnresolvedEntry struct {
	key *ctmap.CtKey4Global
	val *ctmap.CtEntry
}

type RevNatContext struct {
	// foreign node revnat mapping to current node revnat
	revnatMap map[uint16]uint16
	// entries waiting for revnat translation
	entries map[uint16][]UnresolvedEntry
}

func NewRevNatContext() *RevNatContext {
	return &RevNatContext{
		revnatMap: make(map[uint16]uint16, 256),
		entries:   make(map[uint16][]UnresolvedEntry, 256),
	}
}

type batchContext struct {
	m        *ctmap.Map
	keys     []ctmap.CtKey4Global
	values   []ctmap.CtEntry
	next     uint32
	capacity uint32
	revNat   *RevNatContext
}

func NewBatchContext(m *ctmap.Map, chunkSize uint32) (*batchContext, error) {
	_, err := ctmap.OpenCTMap(m)
	if err != nil {
		return nil, err
	}

	return &batchContext{
		m:        m,
		keys:     make([]ctmap.CtKey4Global, chunkSize),
		values:   make([]ctmap.CtEntry, chunkSize),
		next:     0,
		capacity: chunkSize,
		revNat:   NewRevNatContext(),
	}, nil
}

func (ctx *batchContext) Close() {
	if ctx.m != nil {
		ctx.m.Close()
	}
}

type RevNatDecision int

const (
	RevNatWrite RevNatDecision = iota
	RevNatFlush
	RevNatBuffered
)

func getOrOpenServiceMap() (*bpf.Map, error) {
	if m := bpf.GetMap(lbmap.Service4MapV2Name); m != nil {
		return m, nil
	}

	return bpf.OpenMap(bpf.MapPath(lbmap.Service4MapV2Name), &lbmap.Service4Key{}, &lbmap.Service4Value{})
}

func lookupService(key *lbmap.Service4Key) (*lbmap.Service4Value, error) {
	m, err := getOrOpenServiceMap()
	if err != nil || m == nil {
		return nil, err
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*lbmap.Service4Value), nil
}

func resolveForeignRevNat(key *ctmap.CtKey4Global) (uint16, error) {
	svcKey := lbmap.NewService4Key(key.DestAddr.IP(), key.SourcePort, key.NextHeader, lb.ScopeExternal, 0)
	svcVal, err := lookupService(svcKey)
	if err == nil {
		fmt.Printf("DEBUG SERVICE CT REVNAT %d\n", svcVal.RevNat)
		return svcVal.RevNat, nil
	}

	fmt.Printf("DEBUG SERVICE LB LOOKUP WAS FAILED, TRY INTERNAL SCOPE\n")
	svcKey.Scope = lb.ScopeInternal
	svcVal, err = lookupService(svcKey)
	if err != nil {
		return 0, fmt.Errorf("failed to lookup ct service: %w", err)
	}

	return svcVal.RevNat, nil
}

func (ctx *RevNatContext) Handle(
	key *ctmap.CtKey4Global,
	val *ctmap.CtEntry,
) RevNatDecision {
	// foreign-node revnat
	foreign := val.RevNAT
	if foreign == 0 {
		return RevNatWrite
	}

	if local, isExist := ctx.revnatMap[foreign]; isExist {
		// local-node revnat
		val.RevNAT = local
		return RevNatWrite
	}

	// buffer the entry with unknown local revnat
	ctx.entries[foreign] = append(
		ctx.entries[foreign],
		UnresolvedEntry{
			key: key,
			val: val,
		},
	)

	if key.Flags&ctmap.TUPLE_F_SERVICE == 0 {
		return RevNatBuffered
	}

	// conntrack have service type - try resolve local revnat
	local, err := resolveForeignRevNat(key)
	if err != nil {
		fmt.Printf("DEBUG resolveForeignRevNat failed %v\n", err)
		return RevNatBuffered
	}

	ctx.revnatMap[foreign] = local
	return RevNatFlush
}

type RevNatFlushCallback func(
	key *ctmap.CtKey4Global,
	val *ctmap.CtEntry,
)

func (ctx *RevNatContext) Flush(
	foreign uint16,
	cb RevNatFlushCallback,
) {
	entries, ok := ctx.entries[foreign]
	if !ok {
		return
	}

	local, ok := ctx.revnatMap[foreign]
	if !ok {
		return
	}

	for _, e := range entries {
		e.val.RevNAT = local
		cb(e.key, e.val)
	}

	delete(ctx.entries, foreign)
}

func (ctx *batchContext) Append(k *ctmap.CtKey4Global, v *ctmap.CtEntry) {
	state := ctx.revNat.Handle(k, v)
	switch state {
	case RevNatWrite:
		ctx.Write(k, v)
	case RevNatFlush:
		ctx.revNat.Flush(v.RevNAT, func(
			key *ctmap.CtKey4Global,
			val *ctmap.CtEntry,
		) {
			ctx.Write(key, val)
		})
	}
}

func (ctx *batchContext) Write(k *ctmap.CtKey4Global, v *ctmap.CtEntry) {
	curr := ctx.next
	if curr < ctx.capacity {
		ctx.keys[curr] = *k
		ctx.values[curr] = *v
		ctx.next++
	}

	isForced := false
	ctx.Flush(isForced)
}

func (ctx *batchContext) Flush(isForced bool) {
	currentCount := ctx.next
	if currentCount == 0 {
		return
	}

	isFull := currentCount == ctx.capacity
	if !isForced && !isFull {
		return
	}

	// only pass the filled part of the arrays
	keys := ctx.keys[:currentCount]
	values := ctx.values[:currentCount]

	// TODO handle errors where working with map have non-sense !!!
	// TODO handle correctly partial update !!!
	count, err := ctx.m.BatchUpdate(keys, values, nil)
	if err != nil {
		fmt.Printf("DEBUG BatchUpdate Failed = %v\n", err)
	}

	if uint32(count) != currentCount {
		fmt.Printf("DEBUG BatchUpdate Partial Update: %d %d\n", count, currentCount)
	}

	ctx.next = 0
}

func flushContexts(ctxs []*batchContext) {
	for _, ctx := range ctxs {
		if ctx != nil {
			ctx.Flush(true)
			ctx.Close()
		}
	}
}

func appendToContext(
	tcp *batchContext,
	udp *batchContext,
	k *ctmap.CtKey4Global,
	v *ctmap.CtEntry) {
	var ctx *batchContext
	if k.NextHeader == u8proto.TCP && tcp != nil {
		ctx = tcp
	} else if k.NextHeader != u8proto.TCP && udp != nil {
		ctx = udp
	} else {
		// context for this conntrack is not available, silently skip
		return
	}

	ctx.Append(k, v)
}

func createContexts() (tcp *batchContext, udp *batchContext, err error) {
	const chunkSize uint32 = 4096
	tcp, errTCP := NewBatchContext(ctmap.GetTCPCtMap(), chunkSize)
	if errTCP != nil {
		// TODO debug logs
		fmt.Printf("DEBUG NewBatchContext TCP Failed = %v\n", errTCP)
	}

	udp, errUDP := NewBatchContext(ctmap.GetAnyCtMap(), chunkSize)
	if errUDP != nil {
		// TODO debug logs
		fmt.Printf("DEBUG NewBatchContext Any Failed = %v\n", errUDP)
	}

	if tcp == nil && udp == nil {
		err = fmt.Errorf("failed open any ct map, tcp: %v, any: %v", errTCP, errUDP)
	}
	return
}

func postConntrackImportHandler(
	d *Daemon,
	params PostConntrackImportParams,
) middleware.Responder {
	r := params.HTTPRequest
	defer r.Body.Close()

	fmt.Printf("DEBUG postConntrackImportHandler\n")

	tcp, udp, err := createContexts()
	if err != nil {
		// TODO correct http error
		return NewPostConntrackImportOK()
	}

	for {
		k, v, err := deserializeConntrackFromReader(r.Body)
		if err != nil {
			break
		}

		appendToContext(tcp, udp, k, v)
	}

	flushContexts([]*batchContext{tcp, udp})

	return NewPostConntrackImportOK()
}

func getCtMaps() []*ctmap.Map {
	// our cilium build really support only ipv4
	ipv4, ipv6 := true, false
	return ctmap.GlobalMaps(ipv4, ipv6)
}

func parseIPv4ToBinary(s string) (types.IPv4, error) {
	var out types.IPv4

	ip := net.ParseIP(s)
	if ip == nil {
		return out, fmt.Errorf("invalid IP: %s", s)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return out, fmt.Errorf("not an IPv4 address: %s", s)
	}

	copy(out[:], ip4)
	return out, nil
}

func writeRawToBuf[T any](buf *bytes.Buffer, v *T) error {
	size := unsafe.Sizeof(*v)
	b := unsafe.Slice((*byte)(unsafe.Pointer(v)), size)
	_, err := buf.Write(b)
	return err
}

func serializeConntrack(
	key *ctmap.CtKey4Global,
	entry *ctmap.CtEntry,
) ([]byte, error) {
	// for performance buffer len must be equal to serialized data
	buf := bytes.NewBuffer(make([]byte, 0, 60))
	order := binary.LittleEndian

	// Key
	if _, err := buf.Write(key.DestAddr[:]); err != nil {
		return nil, err
	}
	if _, err := buf.Write(key.SourceAddr[:]); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.DestPort); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.SourcePort); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.NextHeader); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.Flags); err != nil {
		return nil, err
	}

	// Entry
	if err := binary.Write(buf, order, entry.Reserved0); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.BackendID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.Packets); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.Bytes); err != nil {
		return nil, err
	}
	// TODO convert from abs node specific to relative node-aware value
	if err := binary.Write(buf, order, entry.Lifetime); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.Flags); err != nil {
		return nil, err
	}
	// revnat value is already in network byte order
	if err := writeRawToBuf(buf, &entry.RevNAT); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.TxFlagsSeen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.RxFlagsSeen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.SourceSecurityID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.LastTxReport); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.LastRxReport); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func writeBinaryConntrack(
	w http.ResponseWriter,
	key *ctmap.CtKey4Global,
	entry *ctmap.CtEntry,
) error {

	data, err := serializeConntrack(key, entry)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func processCtMap(
	m *ctmap.Map,
	w http.ResponseWriter,
	ctx context.Context,
	ip4 types.IPv4,
	isConnClosed *bool,
) error {
	_, err := ctmap.OpenCTMap(m)
	if err != nil {
		return err
	}
	defer m.Close()

	const chunkSize uint32 = 4096
	kout := make([]ctmap.CtKey4Global, chunkSize)
	vout := make([]ctmap.CtEntry, chunkSize)

	totalCount := 0
	var cursor ebpf.MapBatchCursor
	for {
		// Check cancellation early
		select {
		case <-ctx.Done():
			*isConnClosed = true
			return nil
		default:
		}

		count, batchErr := m.BatchLookup(&cursor, kout, vout, nil)
		for i := range count {
			k := &kout[i]
			v := &vout[i]

			flags := k.GetFlags()
			src, dst := k.SourceAddr, k.DestAddr
			isIngress := flags&ctmap.TUPLE_F_IN != 0 || flags&ctmap.TUPLE_F_SERVICE != 0
			isEgress := flags == ctmap.TUPLE_F_OUT
			if !(isIngress && ip4 == src || isEgress && ip4 == dst) {
				continue
			}

			if err := writeBinaryConntrack(w, k, v); err != nil {
				log.WithFields(logrus.Fields{
					"map":   m,
					"error": err,
				}).Debug("Failed to serialize binary data and write to socket")
				*isConnClosed = true
				return nil
			}
			totalCount++
		}

		if batchErr != nil {
			if errors.Is(batchErr, ebpf.ErrKeyNotExist) {
				// end of map, we're done iterating
				fmt.Printf("DEBUG BatchLookup count = %d\n", totalCount)
				return nil
			}
			return batchErr
		}
	}
}

func getConntrackExportHandler(
	d *Daemon,
	params GetConntrackExportParams,
) middleware.Responder {
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		r := params.HTTPRequest
		ctx := r.Context()
		defer r.Body.Close()

		ip4, err := parseIPv4ToBinary(params.IP)
		if err != nil {
			http.Error(w, "Failed parse ipv4 address", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Transfer-Encoding", "chunked")
		w.WriteHeader(http.StatusOK)

		enc := json.NewEncoder(w)
		enc.SetEscapeHTML(false)

		isConnClosed := false
		maps := getCtMaps()
		for _, m := range maps {
			start := time.Now()
			if err = processCtMap(m, w, ctx, ip4, &isConnClosed); err != nil {
				log.WithFields(logrus.Fields{
					"map":   m,
					"error": err,
				}).Error("Failed to open conntrack map")
			}

			fmt.Printf("DEBUG duration = %d ms\n", time.Since(start).Milliseconds())
			if isConnClosed {
				log.Debug("HTTP client closed connection")
				break
			}
		}
	})
}

// getStatus returns the daemon status. If brief is provided a minimal version
// of the StatusResponse is provided.
func (d *Daemon) getStatus(brief bool, requireK8sConnectivity bool) models.StatusResponse {
	staleProbes := d.statusCollector.GetStaleProbes()
	stale := make(map[string]strfmt.DateTime, len(staleProbes))
	for probe, startTime := range staleProbes {
		stale[probe] = strfmt.DateTime(startTime)
	}

	d.statusCollectMutex.RLock()
	defer d.statusCollectMutex.RUnlock()

	var sr models.StatusResponse
	if brief {
		csCopy := new(models.ClusterStatus)
		if d.statusResponse.Cluster != nil && d.statusResponse.Cluster.CiliumHealth != nil {
			in, out := &d.statusResponse.Cluster.CiliumHealth, &csCopy.CiliumHealth
			*out = new(models.Status)
			**out = **in
		}
		var minimalControllers models.ControllerStatuses
		if d.statusResponse.Controllers != nil {
			for _, c := range d.statusResponse.Controllers {
				if c.Status == nil {
					continue
				}
				// With brief, the client should only care if a single controller
				// is failing and its status so we don't need to continuing
				// checking for failure messages for the remaining controllers.
				if c.Status.LastFailureMsg != "" {
					minimalControllers = append(minimalControllers, c.DeepCopy())
					break
				}
			}
		}
		sr = models.StatusResponse{
			Cluster:     csCopy,
			Controllers: minimalControllers,
		}
	} else {
		// d.statusResponse contains references, so we do a deep copy to be able to
		// safely use sr after the method has returned
		sr = *d.statusResponse.DeepCopy()
	}

	sr.Stale = stale

	// CiliumVersion definition
	ver := version.GetCiliumVersion()
	ciliumVer := fmt.Sprintf("%s (v%s-%s)", ver.Version, ver.Version, ver.Revision)

	switch {
	case len(sr.Stale) > 0:
		msg := "Stale status data"
		sr.Cilium = &models.Status{
			State: models.StatusStateWarning,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.Kvstore != nil &&
		d.statusResponse.Kvstore.State != models.StatusStateOk &&
		d.statusResponse.Kvstore.State != models.StatusStateDisabled:
		msg := "Kvstore service is not ready: " + d.statusResponse.Kvstore.Msg
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kvstore.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.ContainerRuntime != nil && d.statusResponse.ContainerRuntime.State != models.StatusStateOk:
		msg := "Container runtime is not ready: " + d.statusResponse.ContainerRuntime.Msg
		if d.statusResponse.ContainerRuntime.State == models.StatusStateDisabled {
			msg = "Container runtime is disabled"
		}
		sr.Cilium = &models.Status{
			State: d.statusResponse.ContainerRuntime.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.clientset.IsEnabled() && d.statusResponse.Kubernetes != nil && d.statusResponse.Kubernetes.State != models.StatusStateOk && requireK8sConnectivity:
		msg := "Kubernetes service is not ready: " + d.statusResponse.Kubernetes.Msg
		sr.Cilium = &models.Status{
			State: d.statusResponse.Kubernetes.State,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	case d.statusResponse.CniFile != nil && d.statusResponse.CniFile.State == models.StatusStateFailure:
		msg := "Could not write CNI config file: " + d.statusResponse.CniFile.Msg
		sr.Cilium = &models.Status{
			State: models.StatusStateFailure,
			Msg:   fmt.Sprintf("%s    %s", ciliumVer, msg),
		}
	default:
		sr.Cilium = &models.Status{
			State: models.StatusStateOk,
			Msg:   ciliumVer,
		}
	}

	return sr
}

func (d *Daemon) getIdentityRange() *models.IdentityRange {
	s := &models.IdentityRange{
		MinIdentity: int64(identity.GetMinimalAllocationIdentity(d.clusterInfo.ID)),
		MaxIdentity: int64(identity.GetMaximumAllocationIdentity(d.clusterInfo.ID)),
	}

	return s
}

func (d *Daemon) startStatusCollector(ctx context.Context, cleaner *daemonCleanup) error {
	probes := []status.Probe{
		{
			Name: "kvstore",
			Probe: func(ctx context.Context) (interface{}, error) {
				if option.Config.KVStore == "" {
					return &models.Status{State: models.StatusStateDisabled}, nil
				} else {
					return kvstore.Client().Status(), nil
				}
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err != nil {
					d.statusResponse.Kvstore = &models.Status{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}

				if kvstore, ok := status.Data.(*models.Status); ok {
					if kvstore.State == models.StatusStateWarning && option.Config.KVstorePodNetworkSupport {
						// Don't treat warnings as errors when the support for running
						// etcd in pod network is enabled. This is necessary to allow
						// Cilium turning ready even before connecting to the kvstore,
						// and break the chicken-and-egg dependency during startup.
						kvstore.State = models.StatusStateOk
					}

					d.statusResponse.Kvstore = kvstore
				}
			},
		},
		{
			Name: "kubernetes",
			Interval: func(failures int) time.Duration {
				if failures > 0 {
					// While failing, we want an initial
					// quick retry with exponential backoff
					// to avoid continuous load on the
					// apiserver
					return backoff.CalculateDuration(5*time.Second, 2*time.Minute, 2.0, false, failures)
				}

				// The base interval is dependant on the
				// cluster size. One status interval does not
				// automatically translate to an apiserver
				// interaction as any regular apiserver
				// interaction is also used as an indication of
				// successful connectivity so we can continue
				// to be fairly aggressive.
				//
				// 1     |    7s
				// 2     |   12s
				// 4     |   15s
				// 64    |   42s
				// 512   | 1m02s
				// 2048  | 1m15s
				// 8192  | 1m30s
				// 16384 | 1m32s
				return d.nodeDiscovery.Manager.ClusterSizeDependantInterval(10 * time.Second)
			},
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.getK8sStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err != nil {
					d.statusResponse.Kubernetes = &models.K8sStatus{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}
				if s, ok := status.Data.(*models.K8sStatus); ok {
					d.statusResponse.Kubernetes = s
				}
			},
		},
		{
			Name: "ipam",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.DumpIPAM(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// IPAMStatus has no way to show errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.IPAMStatus); ok {
						d.statusResponse.Ipam = s
					}
				}
			},
		},
		{
			Name: "node-monitor",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.monitorAgent.State(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// NodeMonitor has no way to show errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.MonitorStatus); ok {
						d.statusResponse.NodeMonitor = s
					}
				}
			},
		},
		{
			Name: "cluster",
			Probe: func(ctx context.Context) (interface{}, error) {
				clusterStatus := &models.ClusterStatus{
					Self: nodeTypes.GetAbsoluteNodeName(),
				}
				return clusterStatus, nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ClusterStatus has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.ClusterStatus); ok {
						if d.statusResponse.Cluster != nil {
							// NB: CiliumHealth is set concurrently by the
							// "cilium-health" probe, so do not override it
							s.CiliumHealth = d.statusResponse.Cluster.CiliumHealth
						}
						d.statusResponse.Cluster = s
					}
				}
			},
		},
		{
			Name: "cilium-health",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.ciliumHealth == nil {
					return nil, nil
				}
				return d.ciliumHealth.GetStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				if d.ciliumHealth == nil {
					return
				}

				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if d.statusResponse.Cluster == nil {
					d.statusResponse.Cluster = &models.ClusterStatus{}
				}
				if status.Err != nil {
					d.statusResponse.Cluster.CiliumHealth = &models.Status{
						State: models.StatusStateFailure,
						Msg:   status.Err.Error(),
					}
					return
				}
				if s, ok := status.Data.(*models.Status); ok {
					d.statusResponse.Cluster.CiliumHealth = s
				}
			},
		},
		{
			Name: "l7-proxy",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.l7Proxy == nil {
					return nil, nil
				}
				return d.l7Proxy.GetStatusModel(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ProxyStatus has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(*models.ProxyStatus); ok {
						d.statusResponse.Proxy = s
					}
				}
			},
		},
		{
			Name: "controllers",
			Probe: func(ctx context.Context) (interface{}, error) {
				return controller.GetGlobalStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				// ControllerStatuses has no way to report errors
				if status.Err == nil {
					if s, ok := status.Data.(models.ControllerStatuses); ok {
						d.statusResponse.Controllers = s
					}
				}
			},
		},
		{
			Name: "clustermesh",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.clustermesh == nil {
					return nil, nil
				}
				return d.clustermesh.Status(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.ClusterMeshStatus); ok {
						d.statusResponse.ClusterMesh = s
					}
				}
			},
		},
		{
			Name: "hubble",
			Probe: func(ctx context.Context) (interface{}, error) {
				return d.hubble.Status(ctx), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.HubbleStatus); ok {
						d.statusResponse.Hubble = s
					}
				}
			},
		},
		{
			Name: "encryption",
			Probe: func(ctx context.Context) (interface{}, error) {
				switch {
				case option.Config.EnableIPSec:
					return &models.EncryptionStatus{
						Mode: models.EncryptionStatusModeIPsec,
					}, nil
				case option.Config.EnableWireguard:
					var msg string
					status, err := d.wireguardAgent.Status(false)
					if err != nil {
						msg = err.Error()
					}
					return &models.EncryptionStatus{
						Mode:      models.EncryptionStatusModeWireguard,
						Msg:       msg,
						Wireguard: status,
					}, nil
				default:
					return &models.EncryptionStatus{
						Mode: models.EncryptionStatusModeDisabled,
					}, nil
				}
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.EncryptionStatus); ok {
						d.statusResponse.Encryption = s
					}
				}
			},
		},
		{
			Name: "kube-proxy-replacement",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.clientset.IsEnabled() || option.Config.DatapathMode == datapathOption.DatapathModeLBOnly {
					return d.getKubeProxyReplacementStatus(), nil
				} else {
					return nil, nil
				}
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.KubeProxyReplacement); ok {
						d.statusResponse.KubeProxyReplacement = s
					}
				}
			},
		},
		{
			Name: "auth-cert-provider",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.authManager == nil {
					return &models.Status{State: models.StatusStateDisabled}, nil
				}

				return d.authManager.CertProviderStatus(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.Status); ok {
						d.statusResponse.AuthCertificateProvider = s
					}
				}
			},
		},
		{
			Name: "cni-config",
			Probe: func(ctx context.Context) (interface{}, error) {
				if d.cniConfigManager == nil {
					return nil, nil
				}
				return d.cniConfigManager.Status(), nil
			},
			OnStatusUpdate: func(status status.Status) {
				d.statusCollectMutex.Lock()
				defer d.statusCollectMutex.Unlock()

				if status.Err == nil {
					if s, ok := status.Data.(*models.Status); ok {
						d.statusResponse.CniFile = s
					}
				}
			},
		},
	}

	d.statusResponse.Masquerading = d.getMasqueradingStatus()
	d.statusResponse.IPV6BigTCP = d.getIPV6BigTCPStatus()
	d.statusResponse.IPV4BigTCP = d.getIPV4BigTCPStatus()
	d.statusResponse.BandwidthManager = d.getBandwidthManagerStatus()
	d.statusResponse.HostFirewall = d.getHostFirewallStatus()
	d.statusResponse.Routing = d.getRoutingStatus()
	d.statusResponse.ClockSource = d.getClockSourceStatus()
	d.statusResponse.BpfMaps = d.getBPFMapStatus()
	d.statusResponse.CniChaining = d.getCNIChainingStatus()
	d.statusResponse.IdentityRange = d.getIdentityRange()
	d.statusResponse.Srv6 = d.getSRv6Status()
	d.statusResponse.AttachMode = d.getAttachModeStatus()
	d.statusResponse.DatapathMode = d.getDatapathModeStatus()

	d.statusCollector = status.NewCollector(probes, status.DefaultConfig)

	// Block until all probes have been executed at least once, to make sure that
	// the status has been fully initialized once we exit from this function.
	if err := d.statusCollector.WaitForFirstRun(ctx); err != nil {
		return fmt.Errorf("waiting for first run: %w", err)
	}

	// Set up a signal handler function which prints out logs related to daemon status.
	cleaner.cleanupFuncs.Add(func() {
		// If the KVstore state is not OK, print help for user.
		if d.statusResponse.Kvstore != nil &&
			d.statusResponse.Kvstore.State != models.StatusStateOk &&
			d.statusResponse.Kvstore.State != models.StatusStateDisabled {
			helpMsg := "cilium-agent depends on the availability of cilium-operator/etcd-cluster. " +
				"Check if the cilium-operator pod and etcd-cluster are running and do not have any " +
				"warnings or error messages."
			log.WithFields(logrus.Fields{
				"status":              d.statusResponse.Kvstore.Msg,
				logfields.HelpMessage: helpMsg,
			}).Error("KVStore state not OK")

		}

		d.statusCollector.Close()
	})

	return nil
}
