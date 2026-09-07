// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipam

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/cilium/cilium/pkg/annotation"
	k8sTables "github.com/cilium/cilium/pkg/k8s/tables"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
)

// Pinning a pod's address with the cni.cilium.io/ipAddress annotation.
//
// Deckhouse needs a pod to come up with an address chosen by the caller instead
// of the next free one. The consumer is DVP: a virtual machine's address
// belongs to the VM rather than to the pod that happens to run it, and it has
// to survive that pod being replaced -- including a live migration, during
// which two pods for the same VM run on two different nodes and both carry the
// same IPv4 address.
//
// Behaviour, by case. Only the last three rows differ from upstream:
//
//	owner is not "<namespace>/<name>"       -> allocate normally (router, health,
//	                                           ingress, restored endpoints)
//	pod table not wired up                  -> allocate normally
//	pod carries no annotation               -> allocate normally
//	annotation is for the other family      -> allocate normally for this family
//	pod not in the table within the wait    -> allocate normally, warn
//	annotation is not an IP address         -> fail the allocation
//	address in this node's CIDR, free       -> allocate exactly that address
//	address in this node's CIDR, taken      -> fail the allocation (ErrAllocated)
//	address outside this node's CIDR        -> accept it and record the owner,
//	                                           but reserve nothing in the bitmap
//	address outside the CIDR, owned here    -> fail the allocation
//
// Nuances to keep in mind before changing any of this:
//
//   - A requested address cannot be validated against a CIDR. With
//     ipam: kubernetes every node allocates out of its own Node.spec.podCIDR, so
//     during a migration the VM's address belongs to the *source* node's CIDR as
//     far as the target node is concerned; and a VM's address may come from a
//     subnet unrelated to the pod subnet altogether. There is no bound to check
//     a request against. The only enforcement is "not already in use on this
//     node" -- cross-node duplicates are the migration window itself, and which
//     of the two pods owns the address cluster-wide is arbitrated separately by
//     the network.deckhouse.io/pod-common-ip-priority label.
//
//   - This runs on the allocation hot path, which every pod on the node goes
//     through, so a fault here is a node-wide outage. Hence the asymmetry above:
//     the only outcome that fails an allocation is an annotation that is present
//     and malformed -- a request that was made and cannot be honoured. Absence
//     of information (no table, no pod, no annotation) always falls back to
//     upstream behaviour.
//
//   - The pod is read from the local-pods StateDB table and not through
//     k8sWatcher.GetCachedPod. GetCachedPod does the very same table lookup, but
//     wraps it in <-controllersStarted and WaitForCacheSync, which wait for the
//     *initial* sync of all pods and not for this pod: it does not close the race
//     below, while it does add a blocking wait and a dependency on the watcher to
//     a package that needs one for nothing else.
//
//   - Table reads are lock-free snapshot reads, but they still must not happen
//     under allocatorMutex. That is the agent's single global IPAM lock, taken by
//     every allocate and every release, so the region it covers must hold
//     in-memory allocator work only: no k8s reads, no channel waits, no I/O.
//     resolveRequestedIP is therefore called by the exported AllocateNextFamily*
//     wrappers *before* they take the lock, and its result is passed down into
//     allocateNextFamily as an argument.
//
//   - There is deliberately no DNS1123 validation of the namespace and pod name
//     parsed out of the owner string. The table lookup is the authority on
//     whether a pod exists; a name check can only turn a valid pod into a missed
//     request, which is exactly the silent failure this code is built to avoid.

// podTableWaitTimeout bounds the wait for a pod that has not appeared in the
// local pod table yet.
//
// The table is fed by a watch-backed reflector that commits in batches every
// k8s.DefaultBufferWaitTime (50ms), so a CNI ADD can legitimately arrive before
// the pod it is for shows up there: kubelet learns of the pod from its own
// watch, and nothing orders the two. Waiting for a few buffer flushes closes
// that window in practice without letting a stale or broken cache turn into an
// allocation outage -- on timeout the allocation proceeds as upstream would.
const podTableWaitTimeout = 500 * time.Millisecond

// resolveRequestedIP returns the address the pod behind owner pinned with the
// annotation.PodAnnotationIPAddress annotation, or the zero Addr if it pinned
// none. The commentary above has the full behaviour table.
//
// Must be called *without* allocatorMutex held: it reads a StateDB table and may
// block for up to podTableWaitTimeout.
func (ipam *IPAM) resolveRequestedIP(owner string, family Family) (netip.Addr, error) {
	if ipam.pods == nil || ipam.db == nil {
		return netip.Addr{}, nil
	}

	namespace, name, isPod := strings.Cut(owner, "/")
	if !isPod {
		// Not a pod owner: "router", "health", "ingress", ...
		return netip.Addr{}, nil
	}

	pod, found := ipam.podForAllocation(namespace, name)
	if !found {
		// Warn loudly: a pinned pod caught in this window comes up with an
		// ordinary address for the rest of its life, and nothing else in the
		// system reports that it happened.
		ipam.logger.Warn(
			"Pod not found in the local pod table, allocating without checking for a requested address",
			logfields.Owner, owner,
			logfields.Timeout, podTableWaitTimeout,
		)
		return netip.Addr{}, nil
	}

	value := pod.Annotations[annotation.PodAnnotationIPAddress]
	if value == "" {
		return netip.Addr{}, nil
	}

	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("pod %s: annotation %s: %q is not an IP address",
			owner, annotation.PodAnnotationIPAddress, value)
	}
	addr = addr.Unmap()

	if DeriveFamily(addr) != family {
		// A pod pins one address, but a dual-stack allocation asks for both
		// families in turn. Report "no request" for the family the annotation is
		// not for, so that family still gets an ordinary address instead of the
		// whole allocation failing.
		return netip.Addr{}, nil
	}

	return addr, nil
}

// podForAllocation looks a pod up in the local pod table, waiting up to
// podTableWaitTimeout for it to appear.
//
// The wait is on the table's watch channel for this exact query, so it costs
// nothing in the common case where the pod is already there, and it returns as
// soon as the pod lands rather than after a fixed sleep.
func (ipam *IPAM) podForAllocation(namespace, name string) (k8sTables.LocalPod, bool) {
	query := k8sTables.PodByName(namespace, name)

	pod, _, watch, found := ipam.pods.GetWatch(ipam.db.ReadTxn(), query)
	if found {
		return pod, true
	}

	timer := time.NewTimer(podTableWaitTimeout)
	defer timer.Stop()

	for {
		select {
		case <-watch:
			pod, _, watch, found = ipam.pods.GetWatch(ipam.db.ReadTxn(), query)
			if found {
				return pod, true
			}
		case <-timer.C:
			return k8sTables.LocalPod{}, false
		}
	}
}
