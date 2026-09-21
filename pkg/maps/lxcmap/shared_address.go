// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package lxcmap

import (
	"net/netip"

	"github.com/cilium/cilium/pkg/lock"
)

// Shared-address ownership for the endpoints map.
//
// DVP live-migrates a VM as two pods, on two nodes, holding the same IPv4 at
// once. Both nodes have a local endpoint for that address, but only the node
// that currently owns it may have an entry in cilium_lxc -- otherwise both
// nodes answer for the address and traffic is delivered twice.
//
// Ownership is not decided here. The agent's ipcache knows which node hosts an
// address, and a listener feeds that verdict in through SetAddressRemote; this
// file only withholds and restores map entries accordingly. An entry withheld
// while the address lives elsewhere is remembered, so it can be put back the
// moment the address returns without waiting for the endpoint to regenerate.
//
// Keeping this inside package lxcmap is deliberate. The ownership check has to
// happen where the entry is written, and the map is reached through the Map
// interface provided by this package's cell -- so the dependency runs one way,
// from the listener into here, and the two packages stay independent.

// endpointEntry is what this node knows about an endpoint whose address may be
// shared: the map entry it would write, and whether that entry is present.
//
// Every endpoint is recorded, not only the withheld ones. An address usually
// becomes remote *after* its entry was written -- the pod starts here, and only
// later does ipcache learn the address moved -- so the entry to delete has to be
// known even though nothing was withheld at the time.
type endpointEntry struct {
	key    *EndpointKey
	info   *EndpointInfo
	active bool // present in the map right now
}

// sharedAddresses tracks which addresses are hosted on another node and the
// endpoint entries affected by that.
type sharedAddresses struct {
	mutex lock.Mutex

	// remote are the addresses currently hosted on another node.
	remote map[netip.Addr]struct{}

	// entries is every endpoint this node has written or withheld, by address.
	entries map[netip.Addr]endpointEntry
}

func newSharedAddresses() *sharedAddresses {
	return &sharedAddresses{
		remote:  make(map[netip.Addr]struct{}),
		entries: make(map[netip.Addr]endpointEntry),
	}
}

// record notes the entry for an address and reports whether it may be written:
// it may not while another node owns the address.
func (s *sharedAddresses) record(addr netip.Addr, key *EndpointKey, info *EndpointInfo) bool {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	_, remote := s.remote[addr]
	s.entries[addr] = endpointEntry{key: key, info: info, active: !remote}
	return !remote
}

// forget drops the entry for an address, for when the endpoint goes away.
//
// Which node owns the address is deliberately kept. Ownership is a property of
// the address, not of any endpoint this node happens to have: the usual case is
// a pod being created here for an address another node already owns, and the
// verdict for it arrived long before the pod did. Dropping it with the previous
// endpoint would leave the next one on that address writing its entry, and
// ipcache -- which has not changed its mind -- would never say so again. The
// verdict is dropped when ipcache drops the address itself.
func (s *sharedAddresses) forget(addr netip.Addr) {
	s.mutex.Lock()
	defer s.mutex.Unlock()
	delete(s.entries, addr)
}

// AddressMoved withholds or restores the entry for an address as ownership of it
// moves between nodes.
//
// Called from the ipcache listener. The map write happens outside the lock,
// because the lock only guards this bookkeeping.
func (m *lxcMap) AddressMoved(addr netip.Addr, remote bool) error {
	s := m.shared

	s.mutex.Lock()
	if remote {
		s.remote[addr] = struct{}{}
	} else {
		delete(s.remote, addr)
	}

	entry, known := s.entries[addr]
	if !known || entry.active == !remote {
		// Nothing written here, or already in the right state.
		s.mutex.Unlock()
		return nil
	}
	entry.active = !remote
	s.entries[addr] = entry
	s.mutex.Unlock()

	if remote {
		// Another node owns the address now: this node must stop answering for
		// it, but the entry is kept so it can be restored if it comes back.
		return m.bpfMap.Delete(entry.key)
	}
	return m.bpfMap.Update(entry.key, entry.info)
}
