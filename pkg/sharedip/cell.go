// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package sharedip keeps the endpoints map in step with which node currently
// owns a shared pod address.
//
// DVP live-migrates a VM as two pods, on two nodes, holding the same IPv4 at
// once. Both nodes have a local endpoint for it, but only the owning node may
// have an entry in cilium_lxc, or both answer for the address.
//
// The two facts live in different subsystems: ipcache knows which node hosts an
// address, and lxcmap holds the entry. This package is the only place that
// knows about both. It listens to ipcache and tells lxcmap; nothing calls back
// the other way, so neither package depends on the other and both stay as
// upstream ships them.
package sharedip

import (
	"context"
	"log/slog"
	"net"
	"net/netip"

	"github.com/cilium/hive/cell"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/lxcmap"
	"github.com/cilium/cilium/pkg/node"
)

// Cell registers the ipcache listener that withholds and restores endpoints map
// entries as a shared address moves between nodes.
var Cell = cell.Module(
	"shared-ip-owner",
	"Tracks which node owns a shared pod address",

	cell.Provide(newListener),
	cell.Invoke(func(l *listener, ipc *ipcache.IPCache) { ipc.AddListener(l) }),
)

type listener struct {
	logger    *slog.Logger
	lxcMap    lxcmap.Map
	localNode *node.LocalNodeStore
}

func newListener(logger *slog.Logger, lxcMap lxcmap.Map, localNode *node.LocalNodeStore) *listener {
	return &listener{logger: logger, lxcMap: lxcMap, localNode: localNode}
}

// localIPv4 is read per event rather than cached. Caching it behind an observer
// looked cheaper, but the first ipcache events arrive before the observer has
// delivered anything, and for an address that never changes again those events
// are the only ones there will be -- so the ownership verdict was dropped and
// never revisited.
//
// Get blocks until the node store is initialised. That cannot stall an event:
// the listener is registered while the hive is populated, when ipcache is still
// empty, and the store is initialised before the watchers that fill it start.
func (l *listener) localIPv4() (netip.Addr, bool) {
	ln, err := l.localNode.Get(context.Background())
	if err != nil {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(ln.GetNodeIP(false).To4())
}

// OnIPIdentityCacheChange is called whenever ipcache learns something about an
// address. The only thing of interest here is the host holding it: when that
// stops being this node the local entry must go, and when it becomes this node
// again the entry must come back.
func (l *listener) OnIPIdentityCacheChange(modType ipcache.CacheModification,
	cidrCluster cmtypes.PrefixCluster, oldHostIP, newHostIP net.IP,
	_ *ipcache.Identity, _ ipcache.Identity, _ uint8,
	_ *ipcache.K8sMetadata, _ uint8) {

	// Single addresses only: a shared pod address is a /32, and a wider prefix
	// is a CIDR identity that owns no endpoint entry.
	prefix := cidrCluster.AsPrefix()
	if !prefix.IsSingleIP() || !prefix.Addr().Is4() {
		return
	}

	// An address ipcache no longer attributes to any node counts as this node's.
	// That is what the agent does for an address it has never heard of, and it
	// is also what clears the verdict again: the entry is remembered for as long
	// as ipcache says the address lives elsewhere, and no longer.
	if modType == ipcache.Delete || newHostIP == nil {
		l.apply(prefix.Addr(), false)
		return
	}
	if modType != ipcache.Upsert {
		return
	}
	if oldHostIP.Equal(newHostIP) {
		// Nothing moved; most upserts land here.
		return
	}

	hostIPv4, ok := netip.AddrFromSlice(newHostIP.To4())
	if !ok {
		return
	}
	local, ok := l.localIPv4()
	if !ok {
		return
	}
	l.apply(prefix.Addr(), local != hostIPv4)
}

// apply hands the verdict to lxcmap, which withholds or restores the entry.
func (l *listener) apply(addr netip.Addr, remote bool) {
	if err := l.lxcMap.AddressMoved(addr, remote); err != nil {
		l.logger.Warn("Failed to apply shared address ownership change",
			logfields.Error, err,
			logfields.IPAddr, addr,
		)
		return
	}

	l.logger.Debug("Shared address ownership changed",
		logfields.IPAddr, addr,
		"remote", remote,
	)
}

var _ ipcache.IPIdentityMappingListener = (*listener)(nil)
