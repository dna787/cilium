// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

// Package leastconn maintains the per-backend open connection counts that the
// least-conn load balancing algorithm selects on.
//
// The datapath increments and decrements these counters as connections open and
// close (see bpf/lib/least_conn.h), but it only sees the events it happens to
// handle: a connection whose conntrack entry simply times out is never observed
// closing, and a count that drifts upwards would permanently steer traffic away
// from a healthy backend. So the counts are treated as an approximation and the
// conntrack garbage collector corrects them: on every pass it recounts the live
// service entries per backend and writes the result back. See the Cached*
// functions below, driven from pkg/maps/ctmap.
package leastconn

import (
	"fmt"
	"log/slog"

	"github.com/cilium/cilium/pkg/bpf"
	datapathmaps "github.com/cilium/cilium/pkg/datapath/maps"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/registry"
)

const (
	ServiceMapName = datapathmaps.CiliumLB4LeastconnService
	BackendMapName = datapathmaps.CiliumLB4LeastconnBackend
)

// BackendKey is the key of the backend counter map, matching struct lb4_lct_key.
type BackendKey struct {
	BackendID uint32
}

func (k *BackendKey) New() bpf.MapKey { return &BackendKey{} }
func (k *BackendKey) String() string  { return fmt.Sprintf("backend=%d", k.BackendID) }

// BackendValue is the value of the backend counter map, matching
// struct lb4_lct_backend.
type BackendValue struct {
	Count uint32
}

func (v *BackendValue) New() bpf.MapValue { return &BackendValue{} }
func (v *BackendValue) String() string    { return fmt.Sprintf("count=%d", v.Count) }

// ServiceValue mirrors struct lb4_lct_service. The agent only ever deletes
// these entries, so the fields are carried for size and never interpreted here;
// the datapath owns them, including the embedded bpf_timer.
type ServiceValue struct {
	IsTmrActive uint32
	BackendID   uint32
	LastSlot    uint16
	RestCount   uint16
	Pad         [4]uint8
	Timer       [2]uint64
}

func (v *ServiceValue) New() bpf.MapValue { return &ServiceValue{} }
func (v *ServiceValue) String() string    { return fmt.Sprintf("backend=%d", v.BackendID) }

var (
	logger *slog.Logger

	backendMap *bpf.Map
	serviceMap *bpf.Map

	// backendCached is the count being rebuilt by the conntrack GC pass that is
	// currently running, and nil when no pass is in flight.
	backendCached map[BackendKey]BackendValue
)

// Init opens the backend counter map. Called once the agent knows the algorithm
// can be selected; without it every function here is a no-op, so an agent
// running without least-conn pays nothing.
func Init(log *slog.Logger, reg *registry.MapRegistry) error {
	m, err := bpf.NewMapFromRegistry(reg, BackendMapName, &BackendKey{}, &BackendValue{})
	if err != nil {
		return err
	}
	if err := m.OpenOrCreate(); err != nil {
		return err
	}

	sm, err := bpf.NewMapFromRegistry(reg, ServiceMapName, &lbmaps.Service4Key{}, &ServiceValue{})
	if err != nil {
		return err
	}
	if err := sm.OpenOrCreate(); err != nil {
		return err
	}

	logger = log
	backendMap = m
	serviceMap = sm

	// Drop whatever the previous agent left behind before the datapath can read
	// it. Failing the sweep must not fail the agent: a stale entry is a leak,
	// not an outage.
	if err := syncWithLiveState(reg); err != nil {
		logger.Warn("Unable to drop stale least-conn entries at startup", logfields.Error, err)
	}
	return nil
}

// syncWithLiveState drops every entry whose service or backend no longer exists.
//
// Both maps are pinned under /sys/fs/bpf, so they outlive the service, the agent
// and even a cilium reinstall, while entries are otherwise removed only as the
// reconciler observes a deletion. Anything that goes away while no agent runs is
// never cleaned up, and these are fixed-size hashes: the leak is permanent and
// eventually fills them. A full sweep at start is what closes that gap; keeping
// them in step while the agent runs is the reconciler's job.
//
// Live state is read from the load balancer's own pinned maps rather than from
// Kubernetes, so the sweep needs nothing to have synced yet and can run before
// the datapath serves a packet. Dropping an entry is safe either way: the
// datapath reads a missing backend counter as an idle backend, and the first
// conntrack GC pass rebuilds the counts from the connections that are really
// open.
func syncWithLiveState(reg *registry.MapRegistry) error {
	svcMap, err := bpf.NewMapFromRegistry(reg, lbmaps.Service4MapV2Name,
		&lbmaps.Service4Key{}, &lbmaps.Service4Value{})
	if err != nil {
		return fmt.Errorf("resolving %s: %w", lbmaps.Service4MapV2Name, err)
	}
	if err := svcMap.Open(); err != nil {
		// No load balancer map means no live state to compare against. Sweeping
		// on that basis would delete everything, so leave the maps alone.
		return fmt.Errorf("opening %s: %w", lbmaps.Service4MapV2Name, err)
	}
	defer svcMap.Close()

	bckMap, err := bpf.NewMapFromRegistry(reg, lbmaps.Backend4MapV3Name,
		&lbmaps.Backend4KeyV3{}, &lbmaps.Backend4ValueV3{})
	if err != nil {
		return fmt.Errorf("resolving %s: %w", lbmaps.Backend4MapV3Name, err)
	}
	if err := bckMap.Open(); err != nil {
		return fmt.Errorf("opening %s: %w", lbmaps.Backend4MapV3Name, err)
	}
	defer bckMap.Close()

	// Collect first, delete afterwards: deleting while iterating a hash map can
	// make the dump skip entries.
	var staleSvc []lbmaps.Service4Key
	if err := serviceMap.DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		key, ok := k.(*lbmaps.Service4Key)
		if !ok {
			return
		}
		if _, err := svcMap.Lookup(key); err != nil {
			staleSvc = append(staleSvc, *key)
		}
	}); err != nil {
		return fmt.Errorf("dumping %s: %w", ServiceMapName, err)
	}

	var staleBck []BackendKey
	if err := backendMap.DumpWithCallback(func(k bpf.MapKey, _ bpf.MapValue) {
		key, ok := k.(*BackendKey)
		if !ok {
			return
		}
		if _, err := bckMap.Lookup(lbmaps.NewBackend4KeyV3(lb.BackendID(key.BackendID))); err != nil {
			staleBck = append(staleBck, *key)
		}
	}); err != nil {
		return fmt.Errorf("dumping %s: %w", BackendMapName, err)
	}

	for i := range staleSvc {
		if err := serviceMap.Delete(&staleSvc[i]); err != nil {
			logger.Warn("Unable to drop a stale least-conn service entry",
				logfields.Error, err, logfields.ServiceKey, staleSvc[i].String())
		}
	}
	for i := range staleBck {
		if err := backendMap.Delete(&staleBck[i]); err != nil {
			logger.Warn("Unable to drop a stale least-conn backend entry",
				logfields.Error, err, logfields.BackendID, staleBck[i].BackendID)
		}
	}

	if len(staleSvc) > 0 || len(staleBck) > 0 {
		logger.Info("Dropped stale least-conn entries at startup",
			"services", len(staleSvc), "backends", len(staleBck))
	}
	return nil
}

// DeleteService drops a frontend's entry, which also releases the BPF timer it
// holds. Called when the service goes away; without it the timer would keep
// firing against a frontend that no longer exists.
func DeleteService(key *lbmaps.Service4Key) {
	if serviceMap == nil {
		return
	}

	k := key.ToNetwork().(*lbmaps.Service4Key)
	k.BackendSlot = 0
	if err := serviceMap.Delete(k); err != nil {
		logger.Debug("Unable to delete least-conn service entry",
			logfields.Error, err, logfields.ServiceKey, key)
	}
}

// DeleteBackendByID drops a backend's counter, for when the backend itself goes
// away.
func DeleteBackendByID(id lb.BackendID) {
	if backendMap == nil {
		return
	}

	key := BackendKey{BackendID: uint32(id)}
	if err := backendMap.Delete(&key); err != nil {
		logger.Debug("Unable to delete least-conn backend entry",
			logfields.Error, err, logfields.BackendID, id)
		return
	}
}

// DecrementCounterByID accounts for a connection the datapath did not see close,
// which is every service conntrack entry the GC removes other than a TCP session
// already marked closing.
func DecrementCounterByID(id lb.BackendID) {
	if backendMap == nil {
		return
	}

	key := BackendKey{BackendID: uint32(id)}
	v, err := backendMap.Lookup(&key)
	if err != nil {
		logger.Debug("Unable to look up least-conn backend entry",
			logfields.Error, err, logfields.BackendID, id)
		return
	}

	val, ok := v.(*BackendValue)
	if !ok || val.Count == 0 {
		return
	}
	// The datapath may be updating this counter at the same time. Losing an
	// update here is acceptable: the recount below is what makes it converge.
	val.Count--
	if err := backendMap.Update(&key, val); err != nil {
		logger.Warn("Unable to update least-conn backend entry",
			logfields.Error, err, logfields.BackendID, id)
	}
}

// InitCached starts a recount. Called at the beginning of a full conntrack GC
// pass, which is the only pass that sees every entry.
func InitCached() {
	if backendMap == nil {
		return
	}
	backendCached = make(map[BackendKey]BackendValue)
}

// IncrementCachedCounterByID counts one live service conntrack entry against its
// backend.
func IncrementCachedCounterByID(id lb.BackendID) {
	if backendCached == nil {
		return
	}

	key := BackendKey{BackendID: uint32(id)}
	val := backendCached[key]
	val.Count++
	backendCached[key] = val
}

// FlushCached writes the recounted values over whatever the datapath has
// accumulated, and ends the pass.
func FlushCached() {
	if backendCached == nil {
		return
	}
	defer func() { backendCached = nil }()

	if backendMap == nil {
		return
	}

	for key, val := range backendCached {
		if err := backendMap.Update(&key, &val); err != nil {
			logger.Error("Unable to flush least-conn backend entry",
				logfields.Error, err, logfields.BackendID, key.BackendID)
		}
	}
}
