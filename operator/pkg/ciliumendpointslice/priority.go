// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ciliumendpointslice

import (
	"math"
	"strconv"
	"strings"
	"time"

	cilium_api_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	cilium_v2a1 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2alpha1"
	"github.com/cilium/cilium/pkg/labels"
	"github.com/cilium/cilium/pkg/lock"
)

// ForceCESSyncTime short-circuits the normal sync delay for a high-priority
// endpoint. During a live migration the freshly started VM pod must publish its
// claim on the address as quickly as possible, because the old pod is already
// gone: until the CES carries the new owner, nothing in the cluster is
// advertising the address at all.
const ForceCESSyncTime = 5 * time.Millisecond

// cepPriority orders endpoints contending for one address. Lower wins.
type cepPriority uint32

const (
	High    cepPriority = 0
	Default cepPriority = math.MaxUint32
)

func (p cepPriority) isHigherThan(o cepPriority) bool { return p < o }

// cepKey identifies an endpoint independently of its address.
type cepKey struct {
	namespace string
	name      string
}

// cepEntry is one endpoint sharing an address.
type cepEntry struct {
	key      cepKey
	priority cepPriority
}

// priorityFilter decides which CiliumEndpoint owns a shared IPv4 address.
//
// DVP live-migrates a VM as two pods, on two nodes, holding the same address at
// once. Both have a CiliumEndpoint, but only one may advertise the address in a
// CiliumEndpointSlice -- otherwise other nodes have two places to send the same
// traffic. The winner is chosen by
//
//	network.deckhouse.io/pod-common-ip-priority: <number>   // lower number wins
//
// and the loser's Networking.Addressing is stripped from the CES.
//
// # Ownership rule
//
// The owner is the entry with the highest priority; on equal priority it is the
// one visited most recently. Entries are moved to the end of their list when
// their endpoint is updated, so the rule reads directly off the list: the owner
// is the last entry holding the highest priority.
//
// Ownership therefore moves on any CEP update, not only on a priority change.
// That is deliberate. An identity change is exactly a reason to re-take the
// address: the endpoint that just changed is the one whose state is freshest.
// Do not "stabilise" this by ordering on pod creation time or similar -- it
// would freeze ownership at pod age and ignore every later identity change,
// which removes the mechanism rather than protecting it.
//
// # Why no CoreCiliumEndpoint is stored here
//
// The filter holds only an endpoint's identity and priority. It is tempting to
// keep the CoreCiliumEndpoint and strip its address in place, and the original
// version did, but the object never survives to the API server: the CES manager
// reduces whatever it is handed to a name, and the reconciler rebuilds a fresh
// CoreCiliumEndpoint from the informer store on every pass via a deep copy that
// knows nothing about priority. A decision applied to the controller's copy is
// silently discarded, and the stripped address comes straight back.
//
// The decision is therefore applied at the only point the published object
// exists -- see priorityEndpointGetter, which decorates the reconciler's
// endpointGetter. Keeping no object here also means there is nothing shared for
// a reader and a writer to race on.
//
// # Why cepToIP exists
//
// A record must stay findable when its address changes. Indexed by address
// alone, an endpoint whose IP changed would be stranded under the old address
// forever, still winning comparisons for an address it no longer has.
//
// # Scope
//
// IPv4 only, and only the "default" CES controller mode. In "slim" mode
// (upstream a9c9c74861, hidden and new in 1.20) CiliumEndpoints are not created
// at all, so this filter has no input; patches 006, 007 and 008 all assume CEPs
// exist and would need re-evaluating before that mode could be used.
type priorityFilter struct {
	mutex lock.RWMutex

	// ipToCepList is every endpoint sharing one IPv4, in visit order.
	ipToCepList map[string][]cepEntry

	// cepToIP finds an endpoint when its address changes.
	cepToIP map[cepKey]string
}

// The zero value is ready to use: a DefaultController assembled by hand, as the
// upstream tests do, has a working filter without a constructor call.
func (f *priorityFilter) initLocked() {
	if f.ipToCepList == nil {
		f.ipToCepList = make(map[string][]cepEntry)
		f.cepToIP = make(map[cepKey]string)
	}
}

// ownerOf returns the entry that owns the address: the last one holding the
// highest priority.
func ownerOf(list []cepEntry) (cepKey, bool) {
	if len(list) == 0 {
		return cepKey{}, false
	}
	best := list[0]
	for _, e := range list[1:] {
		// Not "higher than" but "not lower than", so a tie keeps the later entry.
		if !best.priority.isHigherThan(e.priority) {
			best = e
		}
	}
	return best.key, true
}

// ownsAddress reports whether this endpoint may advertise the given address.
//
// The address is the one the endpoint is about to publish, not the one the
// filter has on record for its name, and that distinction is the whole point.
// Asking "is this name registered, and does it own its address?" answers yes for
// an endpoint the filter has never seen -- and it does not see every endpoint:
// a CiliumEndpoint that arrives without an address is skipped by upsert, and if
// nothing updates it again the endpoint stays unregistered while its object in
// the store carries the address perfectly well. Such an endpoint published a
// contended address alongside its rightful owner, which is the split brain this
// filter exists to prevent. Keying on the address instead means registration is
// never a precondition for being silenced.
//
// An address no one is claiming stays publishable: ordinary pods must be
// unaffected by any of this.
func (f *priorityFilter) ownsAddress(namespace, name, ipv4 string) bool {
	if ipv4 == "" {
		return true
	}

	f.mutex.RLock()
	defer f.mutex.RUnlock()

	list, contended := f.ipToCepList[ipv4]
	if !contended {
		return true
	}
	owner, ok := ownerOf(list)
	if !ok {
		// A claimed address with no claimants left is a bookkeeping slip, not a
		// free address: stay quiet rather than risk two nodes answering.
		return false
	}
	return owner == cepKey{namespace: namespace, name: name}
}

// upsert records an endpoint and returns the address owner before and after, so
// the caller can enqueue whichever CES changed.
func (f *priorityFilter) upsert(cep *cilium_api_v2.CiliumEndpoint) (before, after cepKey, priority cepPriority) {
	key := cepKey{namespace: cep.Namespace, name: cep.Name}
	priority = cepPriorityOf(cep)
	ip := sharedAddressOf(cep)

	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.initLocked()

	// An update that carries no address is not an endpoint giving up its claim,
	// and must leave the record alone. Dropping it here would leave the address
	// with one claimant fewer: the other endpoint then owns it whatever their
	// priorities, and if both are dropped the address is not contended at all
	// and every endpoint publishes it. Only a genuine address change strands the
	// old record; only a delete removes it.
	if ip == "" {
		return cepKey{}, cepKey{}, priority
	}

	if old, known := f.cepToIP[key]; known && old != ip {
		f.removeLocked(key, old)
	}

	before, _ = ownerOf(f.ipToCepList[ip])

	// Remove then append, so the list stays in visit order and the most
	// recently updated endpoint wins an equal priority.
	list := f.ipToCepList[ip]
	out := list[:0]
	for _, e := range list {
		if e.key != key {
			out = append(out, e)
		}
	}
	f.ipToCepList[ip] = append(out, cepEntry{key: key, priority: priority})
	f.cepToIP[key] = ip

	after, _ = ownerOf(f.ipToCepList[ip])
	return before, after, priority
}

// remove drops an endpoint and returns the address owner before and after.
func (f *priorityFilter) remove(cep *cilium_api_v2.CiliumEndpoint) (before, after cepKey) {
	key := cepKey{namespace: cep.Namespace, name: cep.Name}

	f.mutex.Lock()
	defer f.mutex.Unlock()
	f.initLocked()

	ip, known := f.cepToIP[key]
	if !known {
		return cepKey{}, cepKey{}
	}

	before, _ = ownerOf(f.ipToCepList[ip])
	f.removeLocked(key, ip)
	after, _ = ownerOf(f.ipToCepList[ip])
	return before, after
}

func (f *priorityFilter) removeLocked(key cepKey, ip string) {
	list := f.ipToCepList[ip]
	out := list[:0]
	for _, e := range list {
		if e.key != key {
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		delete(f.ipToCepList, ip)
	} else {
		f.ipToCepList[ip] = out
	}
	delete(f.cepToIP, key)
}

// sharedAddressOf returns the endpoint's IPv4 address, which is the only one a
// shared address can be.
func sharedAddressOf(cep *cilium_api_v2.CiliumEndpoint) string {
	if cep.Status.Networking == nil {
		return ""
	}
	for _, pair := range cep.Status.Networking.Addressing {
		if pair.IPV4 != "" {
			return pair.IPV4
		}
	}
	return ""
}

// cepPriorityOf reads the priority label, preferring the object's own labels
// over the identity's copy of them.
func cepPriorityOf(cep *cilium_api_v2.CiliumEndpoint) cepPriority {
	priority := Default

	if cep.Status.Identity != nil {
		for _, lbl := range cep.Status.Identity.Labels {
			// Identity labels are "source:key=value"; match the key exactly so
			// that a longer key, or a value mentioning it, does not count.
			kv := strings.SplitN(lbl, "=", 2)
			if len(kv) != 2 {
				continue
			}
			key := kv[0]
			if i := strings.IndexByte(key, ':'); i >= 0 {
				key = key[i+1:]
			}
			if key == labels.IDNamePriority {
				priority = parsePriority(kv[1])
				break
			}
		}
	}

	if lbl, ok := cep.Labels[labels.IDNamePriority]; ok {
		priority = parsePriority(lbl)
	}

	return priority
}

func parsePriority(s string) cepPriority {
	if num, err := strconv.ParseUint(s, 10, 32); err == nil {
		return cepPriority(num)
	}
	return Default
}

// priorityEndpointGetter applies the ownership decision to the object that is
// actually published. The reconciler rebuilds every CoreCiliumEndpoint from the
// informer store, so this is the only place a stripped address survives to the
// API server.
type priorityEndpointGetter struct {
	inner  endpointGetter
	filter *priorityFilter
}

func (g *priorityEndpointGetter) getCoreEndpointFromStore(cepName CEPName) *cilium_v2a1.CoreCiliumEndpoint {
	ccep := g.inner.getCoreEndpointFromStore(cepName)
	if ccep == nil || ccep.Networking == nil {
		return ccep
	}
	if !g.filter.ownsAddress(cepName.Namespace, ccep.Name, ipv4Of(ccep)) {
		// The entry stays in the slice with an empty address list rather than
		// being dropped from it, for two reasons. The CRD marks
		// networking.addressing as required, so a nil slice serialises as
		// absent and the API server rejects the whole CiliumEndpointSlice --
		// taking the owner's entry down with it. And the reconciler counts
		// every endpoint assigned to a CES as inserted, decrementing only for
		// those it finds in the stored object, so an endpoint left out is
		// forever "pending insert": the slice never compares equal and the
		// operator rewrites it on every reconcile.
		ccep.Networking.Addressing = cilium_api_v2.AddressPairList{}
	}
	return ccep
}

// ipv4Of returns the address this endpoint would publish, which is what decides
// whether it is contending with another endpoint.
func ipv4Of(ccep *cilium_v2a1.CoreCiliumEndpoint) string {
	for _, pair := range ccep.Networking.Addressing {
		if pair.IPV4 != "" {
			return pair.IPV4
		}
	}
	return ""
}
