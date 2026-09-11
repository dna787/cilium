// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/require"
)

// The address of a VM that has just migrated off this node, and some other pod
// still running here.
var (
	vmAddr    = NetAddr{Addr: netip.MustParseAddr("10.0.0.5")}
	otherAddr = NetAddr{Addr: netip.MustParseAddr("10.0.0.9")}
)

// TestMigrationSafeCleanup pins down which conntrack entries survive when the
// endpoint being torn down has moved to another node. The entry that must
// survive is an outbound flow from a local client towards the migrated address:
// deleting it resets a connection that the migration is supposed to preserve.
func TestMigrationSafeCleanup(t *testing.T) {
	for _, tc := range []struct {
		name    string
		flags   uint8
		src     NetAddr
		dst     NetAddr
		migSafe bool
		want    action
	}{
		// The flows the departing VM itself owned: these go.
		{"out from the VM", TUPLE_F_OUT, vmAddr, otherAddr, true, deleteEntry},
		{"related from the VM", TUPLE_F_RELATED, vmAddr, otherAddr, true, deleteEntry},
		{"in towards the VM", TUPLE_F_IN, otherAddr, vmAddr, true, deleteEntry},
		// Service entries are stored with the addresses reversed, so the VM
		// being the destination is the equivalent of it being the source.
		{"service to the VM", TUPLE_F_SERVICE, otherAddr, vmAddr, true, deleteEntry},

		// The whole point: a local client's connection towards the address must
		// survive, because it is now forwarded over the tunnel to the new node.
		{"local client out to the VM", TUPLE_F_OUT, otherAddr, vmAddr, true, noAction},
		{"in from the VM", TUPLE_F_IN, vmAddr, otherAddr, true, noAction},
		{"service from the VM", TUPLE_F_SERVICE, vmAddr, otherAddr, true, noAction},
		{"related to the VM", TUPLE_F_RELATED, otherAddr, vmAddr, true, noAction},

		// Without the flag, the legacy behaviour: anything mentioning the
		// address is removed, including the local client's connection.
		{"legacy: local client out to the VM", TUPLE_F_OUT, otherAddr, vmAddr, false, deleteEntry},
		{"legacy: out from the VM", TUPLE_F_OUT, vmAddr, otherAddr, false, deleteEntry},

		// An address that is not being cleaned up is never touched.
		{"unrelated flow", TUPLE_F_OUT, otherAddr, otherAddr, true, noAction},
		{"legacy: unrelated flow", TUPLE_F_OUT, otherAddr, otherAddr, false, noAction},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := GCFilter{
				MatchIPs:             map[NetAddr]struct{}{vmAddr: {}},
				MigrationSafeCleanup: tc.migSafe,
			}
			got := f.doFiltering(tc.src, tc.dst, 0, 0, 0, tc.flags, &CtEntry{})
			require.Equal(t, tc.want, got)
		})
	}
}
