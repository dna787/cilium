// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/ipam/service/ipallocator"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/metrics"
	"github.com/cilium/cilium/pkg/time"
)

const (
	metricAllocate = "allocate"
	metricRelease  = "release"
)

// Error definitions
var (
	// ErrIPv4Disabled is returned when IPv4 allocation is disabled
	ErrIPv4Disabled = errors.New("IPv4 allocation disabled")

	// ErrIPv6Disabled is returned when Ipv6 allocation is disabled
	ErrIPv6Disabled = errors.New("IPv6 allocation disabled")
)

func (ipam *IPAM) determineIPAMPool(owner string, family Family) (Pool, error) {
	pool, err := ipam.metadata.GetIPPoolForPod(owner, family)
	if err != nil {
		return "", fmt.Errorf("unable to determine IPAM pool for owner %q: %w", owner, err)
	}

	return Pool(pool), nil
}

// AllocateIP allocates an IP address.
func (ipam *IPAM) AllocateIP(ip netip.Addr, owner string, pool Pool) error {
	needSyncUpstream := true
	_, err := ipam.allocateIP(ip, owner, pool, needSyncUpstream)
	return err
}

// AllocateIPWithoutSyncUpstream allocates an IP address without syncing upstream.
func (ipam *IPAM) AllocateIPWithoutSyncUpstream(ip netip.Addr, owner string, pool Pool) (*AllocationResult, error) {
	needSyncUpstream := false
	return ipam.allocateIP(ip, owner, pool, needSyncUpstream)
}

// AllocateIPString is identical to AllocateIP but takes a string
func (ipam *IPAM) AllocateIPString(ipAddr, owner string, pool Pool) error {
	addr, err := netip.ParseAddr(ipAddr)
	if err != nil {
		return fmt.Errorf("Invalid IP address: %s", ipAddr)
	}
	return ipam.AllocateIP(addr, owner, pool)
}

func (ipam *IPAM) allocateIP(ip netip.Addr, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	return ipam.allocateIPLocked(ip, owner, pool, needSyncUpstream)
}

// allocateIPLocked is allocateIP without taking allocatorMutex, for callers
// that already hold it.
func (ipam *IPAM) allocateIPLocked(ip netip.Addr, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
	if pool == "" {
		return nil, fmt.Errorf("unable to restore IP %s for %q: pool name must be provided", ip, owner)
	}

	if !ip.IsValid() {
		return nil, fmt.Errorf("invalid IP address: %v", ip)
	}

	if ownedBy, ok := ipam.isIPExcluded(ip, pool); ok {
		err = fmt.Errorf("IP %s is excluded, owned by %s", ip, ownedBy)
		return
	}

	family := IPv4
	if ip.Is4() {
		if ipam.ipv4Allocator == nil {
			err = ErrIPv4Disabled
			return
		}

		if needSyncUpstream {
			if result, err = ipam.ipv4Allocator.Allocate(ip, owner, pool); err != nil {
				return
			}
		} else {
			if result, err = ipam.ipv4Allocator.AllocateWithoutSyncUpstream(ip, owner, pool); err != nil {
				return
			}
		}
		if ipam.config.IPAMMode() == ipamOption.IPAMClusterPool || ipam.config.IPAMMode() == ipamOption.IPAMKubernetes {
			metrics.IPAMCapacity.WithLabelValues(string(family), ipam.nodeAddressing.IPv4().AllocationCIDR().IPNet.String()).Set(float64(ipam.ipv4Allocator.Capacity()))
		} else {
			metrics.IPAMCapacity.WithLabelValues(string(family), "").Set(float64(ipam.ipv4Allocator.Capacity()))
		}
	} else {
		family = IPv6
		if ipam.ipv6Allocator == nil {
			err = ErrIPv6Disabled
			return
		}

		if needSyncUpstream {
			if result, err = ipam.ipv6Allocator.Allocate(ip, owner, pool); err != nil {
				return
			}
		} else {
			if result, err = ipam.ipv6Allocator.AllocateWithoutSyncUpstream(ip, owner, pool); err != nil {
				return
			}
		}
		if ipam.config.IPAMMode() == ipamOption.IPAMClusterPool || ipam.config.IPAMMode() == ipamOption.IPAMKubernetes {
			metrics.IPAMCapacity.WithLabelValues(string(family), ipam.nodeAddressing.IPv6().AllocationCIDR().IPNet.String()).Set(float64(ipam.ipv6Allocator.Capacity()))
		} else {
			metrics.IPAMCapacity.WithLabelValues(string(family), "").Set(float64(ipam.ipv6Allocator.Capacity()))
		}
	}

	// If the allocator did not populate the pool, we assume it does not
	// support IPAM pools and assign the default pool instead
	if result.IPPoolName == "" {
		result.IPPoolName = PoolDefault()
	}

	ipam.logger.Debug(
		"Allocated specific IP",
		logfields.IPAddr, ip,
		logfields.Owner, owner,
		logfields.PoolName, result.IPPoolName,
	)

	ipam.registerIPOwner(ip, owner, pool)
	metrics.IPAMEvent.WithLabelValues(metricAllocate, string(family)).Inc()
	return
}

// allocatePinnedIP allocates the address a pod pinned with
// annotation.PodAnnotationIPAddress. Must be called with allocatorMutex held.
//
// The address is not necessarily one this node's allocator can represent. DVP
// live-migrates a virtual machine by running a second pod for it on the target
// node while the first is still running, and both pods carry the VM's address:
// on the target node that address belongs to the source node's allocation CIDR,
// and a VM's address may come from a subnet unrelated to the pod subnet
// altogether. So ErrNotInRange is an expected outcome here, not a failure --
// such an address is accepted but left out of the local bitmap, which has no
// slot to represent it.
//
// Reserving a slot anyway is what the pre-1.20 version of this patch did, by
// deleting the range check from ipallocator.Range.Allocate. Because
// Range.contains reports offset 0 for anything out of range, every foreign
// address aliased onto the first address of the node's own CIDR: it consumed a
// real address, and the second such pod on a node then collided with the first
// -- which is why that version had to delete the ErrAllocated check as well,
// losing duplicate detection for ordinary addresses too.
//
// Duplicates are still refused per node: ErrAllocated for an address in the
// local CIDR, and the IP owner map for one outside it. Two pods on *different*
// nodes may hold the same address, which is the migration window itself; which
// of them owns it cluster-wide is decided by the pod-common-ip-priority label.
func (ipam *IPAM) allocatePinnedIP(addr netip.Addr, owner string, pool Pool, needSyncUpstream bool) (result *AllocationResult, err error) {
	ipam.logger.Debug(
		"Allocating pinned IP",
		logfields.IPAddr, addr,
		logfields.Owner, owner,
		logfields.PoolName, pool,
	)

	result, err = ipam.allocateIPLocked(addr, owner, pool, needSyncUpstream)
	if err == nil {
		return result, nil
	}

	// Anything other than "this node's allocator cannot represent that address"
	// is a real failure -- ErrAllocated in particular, which is how a second pod
	// on this node asking for an address already in use gets refused.
	var notInRange *ipallocator.ErrNotInRange
	if !errors.As(err, &notInRange) {
		return nil, err
	}

	// Excluded addresses need no check here: allocateIPLocked tests exclusion
	// before it reaches the allocator and fails with a plain error, so an
	// excluded address never gets this far.
	if prev := ipam.getIPOwner(addr.String(), pool); prev != "" && prev != owner {
		return nil, fmt.Errorf("pinned IP %s is already in use on this node by %s", addr, prev)
	}

	ipam.logger.Debug(
		"Allocated pinned IP from outside the local allocation CIDR",
		logfields.IPAddr, addr,
		logfields.Owner, owner,
	)
	ipam.registerIPOwner(addr, owner, pool)
	metrics.IPAMEvent.WithLabelValues(metricAllocate, string(DeriveFamily(addr))).Inc()

	return &AllocationResult{IP: addr, IPPoolName: pool}, nil
}

func (ipam *IPAM) allocateNextFamily(family Family, owner string, pool Pool, needSyncUpstream bool, pinned netip.Addr) (result *AllocationResult, err error) {
	var allocator Allocator
	switch family {
	case IPv6:
		allocator = ipam.ipv6Allocator
		if ipam.config.IPAMMode() == ipamOption.IPAMClusterPool || ipam.config.IPAMMode() == ipamOption.IPAMKubernetes {
			metrics.IPAMCapacity.WithLabelValues(string(family), ipam.nodeAddressing.IPv6().AllocationCIDR().IPNet.String()).Set(float64(ipam.ipv6Allocator.Capacity()))
		} else {
			metrics.IPAMCapacity.WithLabelValues(string(family), "").Set(float64(ipam.ipv6Allocator.Capacity()))
		}
	case IPv4:
		allocator = ipam.ipv4Allocator
		if ipam.config.IPAMMode() == ipamOption.IPAMClusterPool || ipam.config.IPAMMode() == ipamOption.IPAMKubernetes {
			metrics.IPAMCapacity.WithLabelValues(string(family), ipam.nodeAddressing.IPv4().AllocationCIDR().IPNet.String()).Set(float64(ipam.ipv4Allocator.Capacity()))
		} else {
			metrics.IPAMCapacity.WithLabelValues(string(family), "").Set(float64(ipam.ipv4Allocator.Capacity()))
		}

	default:
		err = fmt.Errorf("unknown address \"%s\" family requested", family)
		return
	}

	if allocator == nil {
		err = fmt.Errorf("%s allocator not available", family)
		return
	}

	if pool == "" {
		pool, err = ipam.determineIPAMPool(owner, family)
		if err != nil {
			return
		}
	}

	// The pod pinned its address with annotation.PodAnnotationIPAddress. It was
	// resolved by the caller, before allocatorMutex was taken -- see the
	// commentary in requested_ip.go for why the lookup cannot happen here.
	if pinned.IsValid() {
		return ipam.allocatePinnedIP(pinned, owner, pool, needSyncUpstream)
	}

	for {
		if needSyncUpstream {
			result, err = allocator.AllocateNext(owner, pool)
		} else {
			result, err = allocator.AllocateNextWithoutSyncUpstream(owner, pool)
		}
		if err != nil {
			return
		}

		// If the allocator did not populate the pool, we assume it does not
		// support IPAM pools and assign the default pool instead
		if result.IPPoolName == "" {
			result.IPPoolName = PoolDefault()
		}

		resultIP := result.IP
		if _, ok := ipam.isIPExcluded(resultIP, pool); !ok {
			ipam.logger.Debug(
				"Allocated random IP",
				logfields.IPAddr, result.IP,
				logfields.PoolName, result.IPPoolName,
				logfields.Owner, owner,
			)
			ipam.registerIPOwner(resultIP, owner, pool)
			metrics.IPAMEvent.WithLabelValues(metricAllocate, string(family)).Inc()
			return
		}

		// The allocated IP is excluded, do not use it. The excluded IP
		// is now allocated so it won't be allocated in the next
		// iteration.
		ipam.registerIPOwner(resultIP, fmt.Sprintf("%s (excluded)", owner), pool)
	}
}

// AllocateNextFamily allocates the next IP of the requested address family
func (ipam *IPAM) AllocateNextFamily(family Family, owner string, pool Pool) (result *AllocationResult, err error) {
	// Resolved before the lock is taken: the lookup reads a StateDB table and
	// may wait for the pod to appear in it, and allocatorMutex is the agent's
	// single global IPAM lock.
	pinned, err := ipam.resolveRequestedIP(owner, family)
	if err != nil {
		return nil, err
	}

	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	needSyncUpstream := true

	return ipam.allocateNextFamily(family, owner, pool, needSyncUpstream, pinned)
}

// AllocateNextFamilyWithoutSyncUpstream allocates the next IP of the requested address family
// without syncing upstream
func (ipam *IPAM) AllocateNextFamilyWithoutSyncUpstream(family Family, owner string, pool Pool) (result *AllocationResult, err error) {
	// See AllocateNextFamily: resolved outside allocatorMutex.
	pinned, err := ipam.resolveRequestedIP(owner, family)
	if err != nil {
		return nil, err
	}

	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	needSyncUpstream := false

	return ipam.allocateNextFamily(family, owner, pool, needSyncUpstream, pinned)
}

// AllocateNext allocates the next available IPv4 and IPv6 address out of the
// configured address pool. If family is set to "ipv4" or "ipv6", then
// allocation is limited to the specified address family. If the pool has been
// drained of addresses, an error will be returned.
func (ipam *IPAM) AllocateNext(family, owner string, pool Pool) (ipv4Result, ipv6Result *AllocationResult, err error) {
	if (family == "ipv6" || family == "") && ipam.ipv6Allocator != nil {
		ipv6Result, err = ipam.AllocateNextFamily(IPv6, owner, pool)
		if err != nil {
			return
		}

	}

	if (family == "ipv4" || family == "") && ipam.ipv4Allocator != nil {
		ipv4Result, err = ipam.AllocateNextFamily(IPv4, owner, pool)
		if err != nil {
			if ipv6Result != nil {
				ipam.ReleaseIP(ipv6Result.IP, ipv6Result.IPPoolName)
			}
			return
		}
	}

	return
}

// AllocateNextWithExpiration is identical to AllocateNext but registers an
// expiration timer as well. This is identical to using AllocateNext() in
// combination with StartExpirationTimer()
func (ipam *IPAM) AllocateNextWithExpiration(family, owner string, pool Pool, timeout time.Duration) (ipv4Result, ipv6Result *AllocationResult, err error) {
	ipv4Result, ipv6Result, err = ipam.AllocateNext(family, owner, pool)
	if err != nil {
		return nil, nil, err
	}

	if timeout != time.Duration(0) {
		for _, result := range []*AllocationResult{ipv4Result, ipv6Result} {
			if result != nil {
				result.ExpirationUUID, err = ipam.StartExpirationTimer(result.IP, result.IPPoolName, timeout)
				if err != nil {
					if ipv4Result != nil {
						ipam.ReleaseIP(ipv4Result.IP, ipv4Result.IPPoolName)
					}
					if ipv6Result != nil {
						ipam.ReleaseIP(ipv6Result.IP, ipv6Result.IPPoolName)
					}
					return
				}
			}
		}
	}

	return
}

func (ipam *IPAM) releaseIPLocked(ip netip.Addr, pool Pool) error {
	if pool == "" {
		return fmt.Errorf("no IPAM pool provided for IP release of %s", ip)
	}

	if !ip.IsValid() {
		return fmt.Errorf("invalid IP address: %v", ip)
	}

	family := IPv4
	if ip.Is4() {
		if ipam.ipv4Allocator == nil {
			return ErrIPv4Disabled
		}

		ipam.ipv4Allocator.Release(ip, pool)
		if ipam.config.IPAMMode() == ipamOption.IPAMClusterPool || ipam.config.IPAMMode() == ipamOption.IPAMKubernetes {
			metrics.IPAMCapacity.WithLabelValues(string(family), ipam.nodeAddressing.IPv4().AllocationCIDR().IPNet.String()).Set(float64(ipam.ipv4Allocator.Capacity()))
		} else {
			metrics.IPAMCapacity.WithLabelValues(string(family), "").Set(float64(ipam.ipv4Allocator.Capacity()))
		}
	} else {
		family = IPv6
		if ipam.ipv6Allocator == nil {
			return ErrIPv6Disabled
		}

		ipam.ipv6Allocator.Release(ip, pool)
		if ipam.config.IPAMMode() == ipamOption.IPAMClusterPool || ipam.config.IPAMMode() == ipamOption.IPAMKubernetes {
			metrics.IPAMCapacity.WithLabelValues(string(family), ipam.nodeAddressing.IPv6().AllocationCIDR().IPNet.String()).Set(float64(ipam.ipv6Allocator.Capacity()))
		} else {
			metrics.IPAMCapacity.WithLabelValues(string(family), "").Set(float64(ipam.ipv6Allocator.Capacity()))
		}
	}

	owner := ipam.releaseIPOwner(ip, pool)
	ipam.logger.Debug(
		"Released IP",
		logfields.IPAddr, ip,
		logfields.Owner, owner,
	)

	key := timerKey{ip: ip, pool: pool}
	if t, ok := ipam.expirationTimers[key]; ok {
		close(t.stop)
		delete(ipam.expirationTimers, key)
	}

	metrics.IPAMEvent.WithLabelValues(metricRelease, string(family)).Inc()
	return nil
}

// ReleaseIP releases an IP address. The pool argument must not be empty, it
// must be set to the pool name returned by the `Allocate*` functions when
// the IP was allocated.
func (ipam *IPAM) ReleaseIP(ip netip.Addr, pool Pool) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()
	return ipam.releaseIPLocked(ip, pool)
}

// Dump dumps the list of allocated IP addresses
func (ipam *IPAM) Dump() (allocv4 map[string]string, allocv6 map[string]string, status string) {
	var st4, st6 string
	var allocPerPool4, allocPerPool6 map[Pool]map[string]string

	allocv4 = make(map[string]string)
	allocv6 = make(map[string]string)

	ipam.allocatorMutex.RLock()
	defer ipam.allocatorMutex.RUnlock()

	if ipam.ipv4Allocator != nil {
		allocPerPool4, st4 = ipam.ipv4Allocator.Dump()
		st4 = "IPv4: " + st4
		for pool, alloc := range allocPerPool4 {
			for ip := range alloc {
				owner := ipam.getIPOwner(ip, pool)
				ipPrefix := ""
				if pool != PoolDefault() {
					ipPrefix = string(pool) + "/"
				}
				// If owner is not available, report IP but leave owner empty
				allocv4[ipPrefix+ip] = owner
			}
		}
	}

	if ipam.ipv6Allocator != nil {
		allocPerPool6, st6 = ipam.ipv6Allocator.Dump()
		st6 = "IPv6: " + st6
		for pool, alloc := range allocPerPool6 {
			for ip := range alloc {
				owner := ipam.getIPOwner(ip, pool)
				ipPrefix := ""
				if pool != PoolDefault() {
					ipPrefix = string(pool) + "/"
				}
				// If owner is not available, report IP but leave owner empty
				allocv6[ipPrefix+ip] = owner
			}
		}
	}

	status = strings.Join([]string{st4, st6}, ", ")
	if status == "" {
		status = "Not running"
	}

	return
}

// StartExpirationTimer installs an expiration timer for a previously allocated
// IP. Unless StopExpirationTimer is called in time, the IP will be released
// again after expiration of the specified timeout. The function will return a
// UUID representing the unique allocation attempt. The same UUID must be
// passed into StopExpirationTimer again.
//
// This function is to be used as allocation and use of an IP can be controlled
// by an external entity and that external entity can disappear. Therefore such
// users should register an expiration timer before returning the IP and then
// stop the expiration timer when the IP has been used.
func (ipam *IPAM) StartExpirationTimer(ip netip.Addr, pool Pool, timeout time.Duration) (string, error) {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	key := timerKey{ip: ip, pool: pool}
	if _, ok := ipam.expirationTimers[key]; ok {
		return "", fmt.Errorf("expiration timer already registered")
	}

	allocationUUID := uuid.New().String()
	stop := make(chan struct{})
	ipam.expirationTimers[key] = expirationTimer{
		uuid: allocationUUID,
		stop: stop,
	}

	go func(key timerKey, ip netip.Addr, pool Pool, allocationUUID string, timeout time.Duration, stop <-chan struct{}) {
		timer := time.NewTimerWithoutMaxDelay(timeout)
		select {
		case <-stop:
			// Expiration timer was explicitly stopped before timeout.
			// Ensure time.Timer can be garbage collected and exit
			timer.Stop()
			return
		case <-timer.C:
		}

		ipam.allocatorMutex.Lock()
		defer ipam.allocatorMutex.Unlock()

		if t, ok := ipam.expirationTimers[key]; ok {
			if t.uuid == allocationUUID {
				if err := ipam.releaseIPLocked(ip, pool); err != nil {
					ipam.logger.Warn(
						"Unable to release IP after expiration",
						logfields.Error, err,
						logfields.IPAddr, ip,
						logfields.PoolName, pool,
						logfields.UUID, allocationUUID,
					)
				} else {
					ipam.logger.Warn(
						"Released IP after expiration",
						logfields.IPAddr, ip,
						logfields.PoolName, pool,
						logfields.UUID, allocationUUID,
					)
				}
			} else {
				// This is an obsolete expiration timer. The IP
				// was reused and a new expiration timer is
				// already attached
			}
		} else {
			// Expiration timer was removed. No action is required
		}
	}(key, ip, pool, allocationUUID, timeout, stop)

	return allocationUUID, nil
}

// StopExpirationTimer will remove the expiration timer for a particular IP.
// The UUID returned by the symmetric StartExpirationTimer must be provided.
// The expiration timer will only be removed if the UUIDs match. Releasing an
// IP will also stop the expiration timer.
func (ipam *IPAM) StopExpirationTimer(ip netip.Addr, pool Pool, allocationUUID string) error {
	ipam.allocatorMutex.Lock()
	defer ipam.allocatorMutex.Unlock()

	key := timerKey{ip: ip, pool: pool}
	t, ok := ipam.expirationTimers[key]
	if !ok {
		return fmt.Errorf("no expiration timer registered")
	} else if t.uuid != allocationUUID {
		return fmt.Errorf("UUID mismatch, not stopping expiration timer")
	}

	close(t.stop)
	delete(ipam.expirationTimers, key)

	return nil
}
