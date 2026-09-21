// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package watchers

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"

	"github.com/cilium/hive/cell"

	ipsec "github.com/cilium/cilium/pkg/datapath/linux/ipsec/types"
	"github.com/cilium/cilium/pkg/endpointmanager"
	hubblemetrics "github.com/cilium/cilium/pkg/hubble/metrics"
	"github.com/cilium/cilium/pkg/identity"
	"github.com/cilium/cilium/pkg/ipcache"
	cilium_api_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/k8s/resource"
	k8sSynced "github.com/cilium/cilium/pkg/k8s/synced"
	"github.com/cilium/cilium/pkg/k8s/types"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/node"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/policy"
	"github.com/cilium/cilium/pkg/source"
	ciliumTypes "github.com/cilium/cilium/pkg/types"
	wgTypes "github.com/cilium/cilium/pkg/wireguard/types"
)

type k8sCiliumEndpointsWatcherParams struct {
	cell.In

	Logger *slog.Logger

	CiliumSlimEndpoint  resource.Resource[*types.CiliumEndpoint]
	CiliumEndpointSlice resource.Resource[*cilium_api_v2a1.CiliumEndpointSlice]
	K8sResourceSynced   *k8sSynced.Resources
	K8sAPIGroups        *k8sSynced.APIGroups

	EndpointManager endpointmanager.EndpointManager
	PolicyUpdater   *policy.Updater
	IPCache         *ipcache.IPCache
	WgConfig        wgTypes.Config
	IPSecConfig     ipsec.Config
	LocalNodeStore  *node.LocalNodeStore
}

func newK8sCiliumEndpointsWatcher(params k8sCiliumEndpointsWatcherParams) *K8sCiliumEndpointsWatcher {
	return &K8sCiliumEndpointsWatcher{
		logger:              params.Logger,
		k8sResourceSynced:   params.K8sResourceSynced,
		k8sAPIGroups:        params.K8sAPIGroups,
		ciliumEndpointSlice: params.CiliumEndpointSlice,
		ciliumSlimEndpoint:  params.CiliumSlimEndpoint,
		endpointManager:     params.EndpointManager,
		policyManager:       params.PolicyUpdater,
		ipcache:             params.IPCache,
		wgConfig:            params.WgConfig,
		ipsecConfig:         params.IPSecConfig,
		localNodeStore:      params.LocalNodeStore,
	}
}

type K8sCiliumEndpointsWatcher struct {
	logger *slog.Logger
	// k8sResourceSynced maps a resource name to a channel. Once the given
	// resource name is synchronized with k8s, the channel for which that
	// resource name maps to is closed.
	k8sResourceSynced *k8sSynced.Resources

	// k8sAPIGroups is a set of k8s API in use. They are setup in watchers,
	// and may be disabled while the agent runs.
	k8sAPIGroups *k8sSynced.APIGroups

	endpointManager endpointManager
	policyManager   policyManager
	ipcache         ipcacheManager
	wgConfig        wgTypes.Config
	ipsecConfig     ipsec.Config
	localNodeStore  *node.LocalNodeStore

	ciliumSlimEndpoint  resource.Resource[*types.CiliumEndpoint]
	ciliumEndpointSlice resource.Resource[*cilium_api_v2a1.CiliumEndpointSlice]
}

// initCiliumEndpointOrSlices initializes the ciliumEndpoints or ciliumEndpointSlice
func (k *K8sCiliumEndpointsWatcher) initCiliumEndpointOrSlices(ctx context.Context) {
	// If CiliumEndpointSlice feature is enabled, Cilium-agent watches CiliumEndpointSlice
	// objects instead of CiliumEndpoints. Hence, skip watching CiliumEndpoints if CiliumEndpointSlice
	// feature is enabled.
	if option.Config.EnableCiliumEndpointSlice {
		k.ciliumEndpointSliceInit(ctx)
	} else {
		k.ciliumEndpointsInit(ctx)
	}
}

// GetCiliumEndpointResource returns Resource[T] slim CEP object
func (k *K8sCiliumEndpointsWatcher) GetCiliumEndpointResource() resource.Resource[*types.CiliumEndpoint] {
	return k.ciliumSlimEndpoint
}

// GetCiliumEndpointSliceResource returns Resource[T] slim CEP object
func (k *K8sCiliumEndpointsWatcher) GetCiliumEndpointSliceResource() resource.Resource[*cilium_api_v2a1.CiliumEndpointSlice] {
	return k.ciliumEndpointSlice
}

func (k *K8sCiliumEndpointsWatcher) ciliumEndpointsInit(ctx context.Context) {
	var synced atomic.Bool

	k.k8sResourceSynced.BlockWaitGroupToSyncResources(
		ctx.Done(),
		nil,
		func() bool { return synced.Load() },
		k8sAPIGroupCiliumEndpointV2,
	)
	k.k8sAPIGroups.AddAPI(k8sAPIGroupCiliumEndpointV2)

	go func() {
		events := k.ciliumSlimEndpoint.Events(ctx)
		cache := make(map[resource.Key]*types.CiliumEndpoint)
		for event := range events {
			switch event.Kind {
			case resource.Sync:
				synced.Store(true)
			case resource.Upsert:
				oldObj, ok := cache[event.Key]
				if !ok || !oldObj.DeepEqual(event.Object) {
					k.endpointUpdated(oldObj, event.Object)
					cache[event.Key] = event.Object
				}
			case resource.Delete:
				k.endpointDeleted(event.Object)
				delete(cache, event.Key)
			}
			event.Done(nil)
		}
	}()
}

// isLocalNodeIP reports whether the given address is this node's own.
func (k *K8sCiliumEndpointsWatcher) isLocalNodeIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	ln, err := k.localNodeStore.Get(context.TODO())
	if err != nil {
		return false
	}
	return ln.GetNodeIP(false).Equal(ip)
}

// mayUpdateIPcacheFor reports whether it is safe to run endpointUpdated for a
// departing CiliumEndpoint.
//
// Several CiliumEndpoints can share one address while a VM is migrating, and
// endpointUpdated upserts the address under the surviving endpoint's identity
// while deleting the departing one's. Run for an endpoint whose address is in
// fact held by another pod, it would take that pod's entry away and send its
// traffic to a pod that is going away. Upstream already guards the delete path
// this way through DeleteOnMetadataMatch; this is the same test for the update
// path.
//
// It is a veto, not an assertion of ownership: the answer is "no objection"
// unless something indicates the entry belongs to someone else. So an endpoint
// claiming no address passes -- there is nothing shared to protect, and upstream
// behaviour must not change for it -- while a single address that ipcache
// attributes to another pod blocks the whole update. An address ipcache has no
// record of, or one that cannot be parsed, blocks it too: ownership cannot be
// established, so the safe answer is to leave ipcache alone.
func (k *K8sCiliumEndpointsWatcher) mayUpdateIPcacheFor(c *types.CiliumEndpoint) bool {
	if c.Networking == nil {
		return true
	}

	for _, pair := range c.Networking.Addressing {
		if pair.IPV4 == "" {
			continue
		}
		addr, err := netip.ParseAddr(pair.IPV4)
		if err != nil {
			return false
		}
		meta := k.ipcache.GetK8sMetadata(addr)
		if meta == nil || meta.Namespace != c.Namespace || meta.PodName != c.Name {
			return false
		}
	}

	return true
}

func (k *K8sCiliumEndpointsWatcher) endpointUpdated(oldEndpoint, endpoint *types.CiliumEndpoint) {
	var namedPortsChanged bool
	defer func() {
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates("Named ports added or updated")
		}
	}()
	var ipsAdded []string
	if oldEndpoint != nil && oldEndpoint.Networking != nil {
		// Delete the old IP addresses from the IP cache
		defer func() {
			for _, oldPair := range oldEndpoint.Networking.Addressing {
				v4Added, v6Added := false, false
				for _, ipAdded := range ipsAdded {
					if ipAdded == oldPair.IPV4 {
						v4Added = true
					}
					if ipAdded == oldPair.IPV6 {
						v6Added = true
					}
				}
				if !v4Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
				if !v6Added {
					portsChanged := k.ipcache.DeleteOnMetadataMatch(oldPair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
					if portsChanged {
						namedPortsChanged = true
					}
				}
			}
		}()
	}

	ln, err := k.localNodeStore.Get(context.TODO())
	if err != nil {
		logging.Fatal(k.logger, "getLocalNode: unexpected error", logfields.Error, err)
	}

	// default to the standard key
	encryptionKey := node.GetEndpointEncryptKeyIndex(ln, k.wgConfig.Enabled(), k.ipsecConfig.Enabled())

	if endpoint.Encryption != nil {
		encryptionKey = uint8(endpoint.Encryption.Key)
	}

	id := identity.ReservedIdentityUnmanaged
	if endpoint.Identity != nil {
		id = identity.NumericIdentity(endpoint.Identity.ID)
	}

	if endpoint.Networking == nil || endpoint.Networking.NodeIP == "" {
		k.logger.Warn("NodeIP not available", logfields.Identity, id)
		// When upgrading from an older version, the nodeIP may
		// not be available yet in the CiliumEndpoint and we
		// have to wait for it to be propagated
		return
	}

	nodeIP := net.ParseIP(endpoint.Networking.NodeIP)
	if nodeIP == nil {
		k.logger.Warn(
			"Unable to parse node IP while processing CiliumEndpoint update",
			logfields.NodeIP, endpoint.Networking.NodeIP,
		)
		return
	}

	k8sMeta := &ipcache.K8sMetadata{
		Namespace:  endpoint.Namespace,
		PodName:    endpoint.Name,
		NamedPorts: make(ciliumTypes.NamedPortMap, len(endpoint.NamedPorts)),
	}
	for _, port := range endpoint.NamedPorts {
		if err := k8sMeta.NamedPorts.AddPort(port.Name, int(port.Port), port.Protocol); err != nil {
			k.logger.Error(
				"Parsing named port failed",
				logfields.Error, err,
				logfields.CEPName, endpoint.GetName(),
			)
			continue
		}
	}

	for _, pair := range endpoint.Networking.Addressing {
		if pair.IPV4 != "" {
			ipsAdded = append(ipsAdded, pair.IPV4)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV4, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}

		if pair.IPV6 != "" {
			ipsAdded = append(ipsAdded, pair.IPV6)
			portsChanged, _ := k.ipcache.Upsert(pair.IPV6, nodeIP, encryptionKey, k8sMeta,
				ipcache.Identity{ID: id, Source: source.CustomResource})
			if portsChanged {
				namedPortsChanged = true
			}
		}
	}
}

func (k *K8sCiliumEndpointsWatcher) endpointDeleted(endpoint *types.CiliumEndpoint) {
	if endpoint.Networking != nil {
		namedPortsChanged := false
		for _, pair := range endpoint.Networking.Addressing {
			if pair.IPV4 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV4, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}

			if pair.IPV6 != "" {
				portsChanged := k.ipcache.DeleteOnMetadataMatch(pair.IPV6, source.CustomResource, endpoint.Namespace, endpoint.Name)
				if portsChanged {
					namedPortsChanged = true
				}
			}
		}
		if namedPortsChanged {
			k.policyManager.TriggerPolicyUpdates("Named ports deleted")
		}
	}
	hubblemetrics.ProcessCiliumEndpointDeletion(endpoint)
}
