// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package maps

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/maps/ctmap"
	"github.com/cilium/cilium/pkg/types"
)

// Serialisation for the conntrack import/export endpoints, carried over from the
// 1.17 implementation. daemon/cmd/status.go no longer exists in 1.20, so this
// lives in pkg/maps next to the other map-facing API code.
//
// The byte layout is a published interface: other Deckhouse components produce
// and consume these streams, and the Cilium-Conntrack-Export-Version header pins
// it at "1". It is unchanged here -- upstream renamed CtEntry.Reserved0 and
// CtEntry.BackendID into the two words of CtEntry.Union0 without moving them.

func deserializeConntrackFromReader(
	r io.Reader,
) (*ctmap.CtKey4Global, *ctmap.CtEntry, error) {

	order := binary.LittleEndian

	key := &ctmap.CtKey4Global{}
	entry := &ctmap.CtEntry{}

	if _, err := io.ReadFull(r, key.DestAddr[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, key.SourceAddr[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[2]byte)(unsafe.Pointer(&key.DestPort))[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[2]byte)(unsafe.Pointer(&key.SourcePort))[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[1]byte)(unsafe.Pointer(&key.NextHeader))[:]); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(r, (*[1]byte)(unsafe.Pointer(&key.Flags))[:]); err != nil {
		return nil, nil, err
	}

	if err := binary.Read(r, order, &entry.Union0[0]); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Union0[1]); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Packets); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Bytes); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Lifetime); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.Flags); err != nil {
		return nil, nil, err
	}
	// revnat value is already in network byte order
	if _, err := io.ReadFull(r, (*[2]byte)(unsafe.Pointer(&entry.RevNAT))[:]); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.TxFlagsSeen); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.RxFlagsSeen); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.SourceSecurityID); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.LastTxReport); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(r, order, &entry.LastRxReport); err != nil {
		return nil, nil, err
	}

	return key, entry, nil
}

func parseIPv4ToBinary(s string) (types.IPv4, error) {
	var out types.IPv4

	ip := net.ParseIP(s)
	if ip == nil {
		return out, fmt.Errorf("invalid IP: %s", s)
	}

	ip4 := ip.To4()
	if ip4 == nil {
		return out, fmt.Errorf("not an IPv4 address: %s", s)
	}

	copy(out[:], ip4)
	return out, nil
}

func writeRawToBuf[T any](buf *bytes.Buffer, v *T) error {
	size := unsafe.Sizeof(*v)
	b := unsafe.Slice((*byte)(unsafe.Pointer(v)), size)
	_, err := buf.Write(b)
	return err
}

func serializeConntrack(
	key *ctmap.CtKey4Global,
	entry *ctmap.CtEntry,
) ([]byte, error) {
	// for performance buffer len must be equal to serialized data
	buf := bytes.NewBuffer(make([]byte, 0, 68))
	order := binary.LittleEndian

	// Key = 14 bytes
	if _, err := buf.Write(key.DestAddr[:]); err != nil {
		return nil, err
	}
	if _, err := buf.Write(key.SourceAddr[:]); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.DestPort); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.SourcePort); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.NextHeader); err != nil {
		return nil, err
	}
	if err := writeRawToBuf(buf, &key.Flags); err != nil {
		return nil, err
	}

	// Entry = 54 bytes
	if err := binary.Write(buf, order, entry.Union0[0]); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.Union0[1]); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.Packets); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.Bytes); err != nil {
		return nil, err
	}
	// TODO convert from abs node specific to relative node-aware value
	if err := binary.Write(buf, order, entry.Lifetime); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.Flags); err != nil {
		return nil, err
	}
	// revnat value is already in network byte order
	if err := writeRawToBuf(buf, &entry.RevNAT); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.TxFlagsSeen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.RxFlagsSeen); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.SourceSecurityID); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.LastTxReport); err != nil {
		return nil, err
	}
	if err := binary.Write(buf, order, entry.LastRxReport); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}
