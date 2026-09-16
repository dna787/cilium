/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright Authors of Cilium */

/*
 * least-conn: pick the backend with the fewest open connections.
 *
 * Plugs into upstream's out-of-tree algorithm hook, so a service opts in with
 *
 *     service.cilium.io/lb-algorithm: least-conn
 *
 * and nothing else is affected. It is reached only through that annotation:
 * bpf-lb-algorithm only accepts "random" and "maglev", so lb_default_algorithm()
 * can never return a custom value.
 *
 * Two maps carry the state:
 *
 *   cilium_lb4_leastconn_backend   backend id  -> open connection count
 *   cilium_lb4_leastconn_service   service key -> the backend to hand out next
 *
 * Selection on the packet path is a single lookup of the service map: whichever
 * backend the last scan decided on. Scanning every backend for the minimum is
 * far too expensive per packet, so it happens asynchronously in a BPF timer
 * armed from the packet path, at most every LEAST_CONN_TIMEOUT. The datapath is
 * therefore always acting on a slightly stale decision, which is the usual
 * trade-off for least-connection balancing and is why the counts do not need to
 * be exact.
 *
 * The counts are maintained here on connect and close, and are corrected by the
 * agent: every conntrack GC pass recounts the live service entries per backend
 * and writes the authoritative values back. See pkg/maps/lbmap/leastconn.go.
 */

#pragma once

#include "bpf/compiler.h"
#include "common.h"

/* Declared unconditionally, like upstream's cilium_lb_act: tools/dpgen builds
 * the map registry from objects compiled with the standard define set, so a map
 * behind a feature #ifdef would never reach it. BPF_F_NO_PREALLOC keeps an
 * unused map close to free.
 */

#define LEAST_CONN_MAX_ENTRIES 65536

struct lb4_lct_key {
	__u32 backend_id;
};

struct lb4_lct_backend {
	__u32 count;
};

struct lb4_lct_service {
	__u32 is_tmr_active;
	__u32 backend_id;
	__u16 last_slot;
	__u16 rest_count;
	/* Low 32 bits of ktime_get_ns() when the scan last ran, in the space the
	 * padding used to occupy so the map layout is unchanged.
	 */
	__u32 last_run;
	struct bpf_timer tmr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb4_lct_key);
	__type(value, struct lb4_lct_backend);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LEAST_CONN_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_lb4_leastconn_backend __section_maps_btf;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb4_key);
	__type(value, struct lb4_lct_service);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(max_entries, LEAST_CONN_MAX_ENTRIES);
	__uint(map_flags, BPF_F_NO_PREALLOC);
} cilium_lb4_leastconn_service __section_maps_btf;

#ifdef ENABLE_LEAST_CONN

/* How long a selection is reused before the timer re-scans.
 *
 * Measured across three 200-connection bursts over three backends, as max:min
 * skew of the connections each backend received:
 *
 *   10ms  2.15x 1.72x 2.15x      3ms  1.20x 1.05x 1.03x
 *    5ms  1.57x 1.05x 1.11x      2ms  1.09x 1.05x 1.02x
 *                                1ms  1.02x 1.02x 1.03x
 *
 * Most of the gain is in place by 3ms and the rest is marginal, so 3ms is the
 * point that buys an even spread without multiplying the scan rate further: the
 * callback walks up to LEAST_CONN_FOREACH_MAX_ENTRIES slots, and that cost rises
 * as this falls.
 */
#ifndef LEAST_CONN_TIMEOUT
#define LEAST_CONN_TIMEOUT 3000000ULL
#endif

/* Delay before resuming a scan that hit the per-run instruction budget. */
#define LEAST_CONN_NEXT_ITER_TIMEOUT 1000000ULL

#define UINT32_MAX 0xffffffff
#define CLOCK_MONOTONIC 1

/* the limit was selected due to verifier restriction on executing instructions */
#define LEAST_CONN_FOREACH_MAX_ENTRIES 100
/* stop scanning once a backend this idle is found -- it is good enough */
#define LEAST_CONN_THRESHOLD 5

static __always_inline int
is_backend_active(__u32 backend_id)
{
	const struct lb4_backend *bck = __lb4_lookup_backend(backend_id);

	return bck != NULL && bck->flags == BE_STATE_ACTIVE;
}

static __always_inline __u16
lb4_least_conn_get_slot(struct lb4_lct_service *svc, __u16 count)
{
	return (svc->last_slot >= 1 && svc->last_slot <= count) ? svc->last_slot : 1;
}

/* Timer callback: walk the service's backend slots and remember the least busy
 * one. Resumes where it left off, so a service with more backends than fit in
 * one run is covered across several.
 */
static int
lb4_select_least_conn_backend_cb(void *map __maybe_unused, struct lb4_key *k,
				 struct lb4_lct_service *svc)
{
	__u16 slot, max, i;
	const struct lb4_service *lb4_svc;
	struct lb4_lct_backend *bck;

	struct lb4_key key = *k;
	__u32 max_count = UINT32_MAX;

	svc->last_run = (__u32)ktime_get_ns();
	struct lb4_lct_key bck_key = {
		.backend_id = svc->backend_id,
	};

	lb4_svc = map_lookup_elem(&cilium_lb4_services_v2, k);
	if (lb4_svc == NULL) {
		svc->is_tmr_active = 0;
		return 0;
	}

	bck = map_lookup_elem(&cilium_lb4_leastconn_backend, &bck_key);
	if (bck != NULL && is_backend_active(svc->backend_id))
		max_count = bck->count;

	/* always start searching from next slot */
	svc->last_slot++;
	slot = lb4_least_conn_get_slot(svc, lb4_svc->count);
	max = svc->rest_count <= LEAST_CONN_FOREACH_MAX_ENTRIES ?
		svc->rest_count : LEAST_CONN_FOREACH_MAX_ENTRIES;
	for (i = 0; i < max; i++) {
		const struct lb4_service *lb4_bck;
		__u32 conn_count = 0;

		svc->rest_count--;
		slot = ((slot + i - 1) % lb4_svc->count) + 1;
		key.backend_slot = slot;
		lb4_bck = __lb4_lookup_backend_slot(&key);
		if (lb4_bck == NULL || !is_backend_active(lb4_bck->backend_id))
			continue;

		bck_key.backend_id = lb4_bck->backend_id;
		bck = map_lookup_elem(&cilium_lb4_leastconn_backend, &bck_key);
		if (bck != NULL)
			conn_count = bck->count;

		if (conn_count <= max_count) {
			max_count = conn_count;
			svc->backend_id = lb4_bck->backend_id;
			if (max_count <= LEAST_CONN_THRESHOLD) {
				svc->rest_count = 0;
				break;
			}
		}
	}
	if (svc->rest_count == 0) {
		svc->is_tmr_active = 0;
	} else {
		/* too big backend list - continue searching backend in next iteration */
		if (timer_start(&svc->tmr, LEAST_CONN_NEXT_ITER_TIMEOUT, 0)) {
			svc->rest_count = 0;
			svc->is_tmr_active = 0;
		}
	}
	svc->last_slot = slot;
	return 0;
}

static __always_inline void
start_timer(struct lb4_lct_service *svc, __u64 timeout, __u16 svc_count)
{
	__u32 since;

	if (svc->is_tmr_active)
		return;

	/* Run the scan at once when it has been idle rather than making the
	 * selection sit stale for a fixed delay: the counts the scan reads are
	 * already up to date by the time this is reached, so the wait bought
	 * nothing. The interval is still enforced, because the callback walks up
	 * to LEAST_CONN_FOREACH_MAX_ENTRIES slots and a busy service must not get
	 * one scan per packet.
	 *
	 * 32 bits of ktime is deliberate: it fits the space the padding already
	 * occupied, so the map value layout does not change. Unsigned arithmetic
	 * wraps correctly for any interval well under 4.2s; a service idle for
	 * longer than that simply waits out the full delay once.
	 */
	since = (__u32)ktime_get_ns() - svc->last_run;
	timeout = since < timeout ? timeout - since : 0;

	/* after cilium bpf prog update we must always replace callback on new version */
	/* otherwise old bpf prog will not deleted from system memory and its callback will be executed */
	if (timer_set_callback(&svc->tmr, lb4_select_least_conn_backend_cb))
		return;

	if (timer_start(&svc->tmr, timeout, 0))
		return;

	svc->rest_count = svc_count;
	svc->is_tmr_active = 1;
}

static __always_inline __u32
lb4_least_conn_select_backend_id_random(const struct __ctx_buff *ctx,
					struct lb4_key *key,
					const struct lb4_service *svc,
					__u16 *last_slot)
{
	/* Backend slot 0 is always reserved for the service frontend. */
	__u16 slot = (get_prandom_u32() % svc->count) + 1;
	const struct lb4_service *be = lb4_lookup_backend_slot(ctx, key, slot);

	if (be == NULL)
		return 0;

	*last_slot = slot;
	return be->backend_id;
}

static __always_inline __u32
lb4_select_backend_id_least_conn(const struct __ctx_buff *ctx __maybe_unused,
				 struct lb4_key *key __maybe_unused,
				 const struct ipv4_ct_tuple *tuple __maybe_unused,
				 const struct lb4_service *svc __maybe_unused)
{
	struct lb4_lct_service *val = map_lookup_elem(&cilium_lb4_leastconn_service, key);

	if (val == NULL) {
		struct lb4_lct_service new_val = {
			.is_tmr_active = 0,
			.last_slot = 1,
			.rest_count = 0,
		};

		new_val.backend_id = lb4_least_conn_select_backend_id_random(ctx, key, svc,
									     &new_val.last_slot);
		key->backend_slot = 0;

		/* On any failure below, fall back to the backend already picked at
		 * random: the service simply gets no scan until the next packet.
		 */
		if (map_update_elem(&cilium_lb4_leastconn_service, key, &new_val, BPF_ANY))
			return new_val.backend_id;

		val = map_lookup_elem(&cilium_lb4_leastconn_service, key);
		if (val == NULL)
			return new_val.backend_id;

		if (timer_init(&val->tmr, &cilium_lb4_leastconn_service, CLOCK_MONOTONIC))
			return new_val.backend_id;

		if (timer_set_callback(&val->tmr, lb4_select_least_conn_backend_cb))
			return new_val.backend_id;

		start_timer(val, is_backend_active(new_val.backend_id) ? LEAST_CONN_TIMEOUT : 1000,
			    svc->count);
		return new_val.backend_id;
	}

	if (!is_backend_active(val->backend_id))
		val->backend_id = lb4_select_backend_id_random(ctx, key, tuple, svc);

	start_timer(val, LEAST_CONN_TIMEOUT, svc->count);
	return val->backend_id;
}

static __always_inline void
_lb_lct_conn_closed(__u32 backend_id)
{
	struct lb4_lct_backend *val;
	struct lb4_lct_key key = {
		.backend_id = backend_id,
	};

	val = map_lookup_elem(&cilium_lb4_leastconn_backend, &key);
	if (val == NULL || val->count == 0)
		return;

	__sync_fetch_and_sub(&val->count, 1);
}

static __always_inline void
_lb_lct_conn_open(__u32 backend_id)
{
	struct lb4_lct_backend *val;
	struct lb4_lct_key key = {
		.backend_id = backend_id,
	};

	val = map_lookup_elem(&cilium_lb4_leastconn_backend, &key);
	if (val == NULL) {
		struct lb4_lct_backend new_val = {
			.count = 1,
		};

		map_update_elem(&cilium_lb4_leastconn_backend, &key, &new_val, BPF_ANY);
		return;
	}

	__sync_fetch_and_add(&val->count, 1);
}

/* Upstream's hook for out-of-tree algorithms, see lb4_select_backend_id(). */
#define lb4_select_backend_id_custom(alg, ctx, key, tuple, svc) \
	lb4_select_backend_id_least_conn(ctx, key, tuple, svc)

#else /* ENABLE_LEAST_CONN */

static __always_inline void _lb_lct_conn_closed(__u32 backend_id __maybe_unused) {}
static __always_inline void _lb_lct_conn_open(__u32 backend_id __maybe_unused) {}

#endif /* ENABLE_LEAST_CONN */
