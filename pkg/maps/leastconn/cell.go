// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package leastconn

import (
	"log/slog"

	"github.com/cilium/hive/cell"

	"github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/maps/registry"
)

// Cell opens the least-conn maps when the algorithm can be selected.
//
// least-conn is only reachable through the service.cilium.io/lb-algorithm
// annotation -- bpf-lb-algorithm is validated against random and maglev, so it
// cannot be a node-wide default -- which is why this keys off the annotation
// setting alone. With it off, the maps stay closed and every counter helper is
// a no-op.
var Cell = cell.Module(
	"least-conn-maps",
	"Per-backend connection counters for the least-conn load balancing algorithm",

	cell.Invoke(func(lc cell.Lifecycle, log *slog.Logger, lbCfg loadbalancer.Config, reg *registry.MapRegistry) {
		if !lbCfg.AlgorithmAnnotation {
			return
		}
		lc.Append(cell.Hook{
			OnStart: func(cell.HookContext) error {
				return Init(log, reg)
			},
		})
	}),
)
