// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"errors"
	"fmt"
	"log/slog"

	"golang.org/x/sys/unix"

	daemonapi "github.com/cilium/cilium/api/v1/server/restapi/daemon"
	"github.com/cilium/cilium/pkg/bpf"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	lbmaps "github.com/cilium/cilium/pkg/loadbalancer/maps"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/maps/timestamp"
	"github.com/cilium/cilium/pkg/u8proto"

	"github.com/go-openapi/runtime/middleware"
)

type UnresolvedEntry struct {
	key *ctmap.CtKey4Global
	val *ctmap.CtEntry
}

type RevNatContext struct {
	logger *slog.Logger
	// foreign node revnat mapping to current node revnat
	revnatMap map[uint16]uint16
	// entries waiting for revnat translation
	entries map[uint16][]UnresolvedEntry
}

func NewRevNatContext(logger *slog.Logger) *RevNatContext {
	return &RevNatContext{
		logger:    logger,
		revnatMap: make(map[uint16]uint16, 256),
		entries:   make(map[uint16][]UnresolvedEntry, 256),
	}
}

type batchContext struct {
	logger   *slog.Logger
	written  uint64
	m        *ctmap.Map
	keys     []ctmap.CtKey4Global
	values   []ctmap.CtEntry
	next     uint32
	capacity uint32
	revNat   *RevNatContext
}

func NewBatchContext(logger *slog.Logger, m *ctmap.Map, chunkSize uint32) (*batchContext, error) {
	_, err := ctmap.OpenCTMap(m)
	if err != nil {
		return nil, err
	}

	return &batchContext{
		logger:   logger,
		m:        m,
		keys:     make([]ctmap.CtKey4Global, chunkSize),
		values:   make([]ctmap.CtEntry, chunkSize),
		next:     0,
		capacity: chunkSize,
		revNat:   NewRevNatContext(logger),
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

func getOrOpenServiceMap(logger *slog.Logger) (*bpf.Map, error) {
	if m := bpf.GetMap(logger, lbmaps.Service4MapV2Name); m != nil {
		return m, nil
	}

	return bpf.OpenMap(bpf.MapPath(logger, lbmaps.Service4MapV2Name), &lbmaps.Service4Key{}, &lbmaps.Service4Value{})
}

func lookupService(logger *slog.Logger, key *lbmaps.Service4Key) (*lbmaps.Service4Value, error) {
	m, err := getOrOpenServiceMap(logger)
	if err != nil || m == nil {
		return nil, err
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*lbmaps.Service4Value), nil
}

func resolveForeignRevNat(logger *slog.Logger, key *ctmap.CtKey4Global) (uint16, error) {
	svcKey := lbmaps.NewService4Key(key.DestAddr.Addr().AsSlice(), key.SourcePort, key.NextHeader, lb.ScopeExternal, 0)
	svcVal, err := lookupService(logger, svcKey)
	if err == nil {
		return svcVal.RevNat, nil
	}

	svcKey.Scope = lb.ScopeInternal
	svcVal, err = lookupService(logger, svcKey)
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
	local, err := resolveForeignRevNat(ctx.logger, key)
	if err != nil {
		ctx.logger.Debug("Failed resolve foreign RevNat to local RevNat",
			logfields.Error, err,
			"revNat", foreign,
		)
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

	writtenCount := uint32(0)
	for writtenCount < currentCount {
		// only pass the filled and don't yet written part of the arrays
		keys := ctx.keys[writtenCount:currentCount]
		values := ctx.values[writtenCount:currentCount]
		count, err := ctx.m.BatchUpdate(keys, values, nil)
		if count <= 0 || (err != nil && errors.Is(err, unix.EFAULT)) {
			ctx.logger.Error("Failed batch update",
				logfields.Error, err,
			)
			break
		}
		writtenCount += uint32(count)
		ctx.written += uint64(count)
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

func appendToContext(tcp *batchContext, udp *batchContext,
	k *ctmap.CtKey4Global, v *ctmap.CtEntry) {
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

func createContexts(logger *slog.Logger) (tcp *batchContext, udp *batchContext) {
	const chunkSize uint32 = 4096
	tcp, errTCP := NewBatchContext(logger, ctmap.GetTCPCtMap(), chunkSize)
	if errTCP != nil {
		logger.Warn("Failed create batch context",
			logfields.Error, errTCP,
			logfields.BPFMapName, "tcp4",
		)
	}

	udp, errUDP := NewBatchContext(logger, ctmap.GetAnyCtMap(), chunkSize)
	if errUDP != nil {
		logger.Warn("Failed create batch context",
			logfields.Error, errUDP,
			logfields.BPFMapName, "any4",
		)
	}

	return
}

type postConntrackImportHandler struct {
	logger *slog.Logger
}

func (h *postConntrackImportHandler) Handle(params daemonapi.PostConntrackImportParams) middleware.Responder {
	r := params.HTTPRequest
	defer r.Body.Close()

	const SupportedExportVersion = "1"
	v := r.Header.Get("Cilium-Conntrack-Export-Version")
	if v != SupportedExportVersion {
		return daemonapi.NewPostConntrackImportBadRequest()
	}

	tcp, udp := createContexts(h.logger)
	if tcp == nil && udp == nil {
		return daemonapi.NewPostConntrackImportInternalServerError()
	}

	t, _ := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions())
	currTime := uint32(t)

	for {
		k, v, err := deserializeConntrackFromReader(r.Body)
		if err != nil {
			break
		}
		// convert from relative value to absolute
		v.Lifetime += currTime
		appendToContext(tcp, udp, k, v)
	}

	flushContexts([]*batchContext{tcp, udp})

	written, dropped := importStats(tcp, udp)
	h.logger.Info("Imported conntrack entries",
		logfields.Count, written,
		"droppedUnresolvedRevNat", dropped,
	)

	return daemonapi.NewPostConntrackImportOK()
}

// importStats reports how many entries were written and how many were dropped
// because their foreign RevNAT never resolved to a local one.
func importStats(ctxs ...*batchContext) (written, dropped uint64) {
	for _, ctx := range ctxs {
		if ctx == nil {
			continue
		}
		written += ctx.written
		for _, entries := range ctx.revNat.entries {
			dropped += uint64(len(entries))
		}
	}
	return written, dropped
}
