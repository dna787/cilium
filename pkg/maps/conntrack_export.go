// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/go-openapi/runtime"
	"github.com/go-openapi/runtime/middleware"

	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/types"
)

func getCtMaps() []*ctmap.Map {
	// our cilium build really support only ipv4
	ipv4, ipv6 := true, false
	return ctmap.Maps(ipv4, ipv6)
}

func writeBinaryConntrack(
	w http.ResponseWriter,
	key *ctmap.CtKey4Global,
	entry *ctmap.CtEntry,
	currTime uint32,
) error {
	if entry.Lifetime < currTime {
		// skip expired conntrack
		return nil
	}
	// convert from absolute(node specific) to relative(node aware) value
	entry.Lifetime -= currTime

	data, err := serializeConntrack(key, entry)
	if err != nil {
		return err
	}

	_, err = w.Write(data)
	return err
}

func processCtMap(
	m *ctmap.Map,
	wc *writerContext,
	ip4 types.IPv4,
	currTime uint32,
) error {
	_, err := ctmap.OpenCTMap(m)
	if err != nil {
		return err
	}
	defer m.Close()

	const chunkSize uint32 = 4096
	kout := make([]ctmap.CtKey4Global, chunkSize)
	vout := make([]ctmap.CtEntry, chunkSize)

	var cursor ebpf.MapBatchCursor
	for {
		// Check cancellation early
		select {
		case <-wc.ctx.Done():
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
			isEgress := flags == ctmap.TUPLE_F_OUT || flags == ctmap.TUPLE_F_RELATED
			if !(isIngress && ip4 == src || isEgress && ip4 == dst) {
				continue
			}

			if err := wc.WriteBinaryConntrack(k, v, currTime); err != nil {
				return err
			}
		}

		if batchErr != nil {
			if errors.Is(batchErr, ebpf.ErrKeyNotExist) {
				return nil // finished
			}
			return batchErr
		}
	}
}

type writerContext struct {
	w   http.ResponseWriter
	ctx context.Context
	mu  sync.Mutex

	exported atomic.Uint64
}

func (wc *writerContext) WriteBinaryConntrack(
	k *ctmap.CtKey4Global,
	v *ctmap.CtEntry,
	currTime uint32,
) error {
	wc.mu.Lock()
	err := writeBinaryConntrack(wc.w, k, v, currTime)
	wc.mu.Unlock()
	if err == nil {
		wc.exported.Add(1)
	}
	return err
}

type getConntrackExportHandler struct {
	logger *slog.Logger
}

func (h *getConntrackExportHandler) Handle(params daemonapi.GetConntrackExportParams) middleware.Responder {
	return middleware.ResponderFunc(func(w http.ResponseWriter, _ runtime.Producer) {
		r := params.HTTPRequest
		ctx := r.Context()
		defer r.Body.Close()

		ip4, err := parseIPv4ToBinary(params.Ip4)
		if err != nil {
			http.Error(w, "invalid IPv4 address", http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cilium-Conntrack-Export-Version", "1")
		w.WriteHeader(http.StatusOK)

		t, _ := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions())
		currTime := uint32(t)

		wc := &writerContext{
			w:   w,
			ctx: ctx,
		}

		var wg sync.WaitGroup
		for _, ctMap := range getCtMaps() {
			wg.Add(1)
			go func(m *ctmap.Map) {
				defer wg.Done()

				if err := processCtMap(m, wc, ip4, currTime); err != nil {
					h.logger.Error("Failed process conntrack map",
						logfields.Error, err,
						logfields.BPFMapName, m.Name(),
					)
				}
			}(ctMap)
		}

		wg.Wait()

		h.logger.Info("Exported conntrack entries",
			logfields.IPAddr, params.Ip4,
			logfields.Count, wc.exported.Load(),
		)
	})
}
