// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ctmap

import (
	"encoding/json"
	"fmt"
	"net/netip"

	lbmap "github.com/cilium/cilium/pkg/maps/lbmap"
	"github.com/cilium/cilium/pkg/maps/timestamp"

	"github.com/cilium/cilium/pkg/bpf"
	lb "github.com/cilium/cilium/pkg/loadbalancer"
	"github.com/cilium/cilium/pkg/tuple"
	"github.com/cilium/cilium/pkg/types"
	"github.com/cilium/cilium/pkg/u8proto"
)

func createTupleKey(isGlobal bool, srcAddr, dstAddr string, proto u8proto.U8proto, ingress bool) (bpf.MapKey, bool, error) {
	srcAddrPort, err := netip.ParseAddrPort(srcAddr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid source address '%s': %w", srcAddr, err)
	}

	dstAddrPort, err := netip.ParseAddrPort(dstAddr)
	if err != nil {
		return nil, false, fmt.Errorf("invalid destination address '%s': %w", dstAddr, err)
	}

	if srcAddrPort.Addr().Is4() {
		if isGlobal {
			key := &CtKey4Global{
				TupleKey4Global: tuple.TupleKey4Global{
					TupleKey4: tuple.TupleKey4{
						SourcePort: uint16(srcAddrPort.Port()),
						DestPort:   uint16(dstAddrPort.Port()),
						NextHeader: proto,
						Flags:      TUPLE_F_OUT,
					},
				},
			}
			// CTmap has the addresses in the reverse order w.r.t. the original direction
			key.SourceAddr.FromAddr(dstAddrPort.Addr())
			key.DestAddr.FromAddr(srcAddrPort.Addr())
			if ingress {
				key.Flags = TUPLE_F_IN
			}
			return key.ToNetwork(), true, nil
		}

		key := &CtKey4{
			TupleKey4: tuple.TupleKey4{
				SourcePort: uint16(srcAddrPort.Port()),
				DestPort:   uint16(dstAddrPort.Port()),
				NextHeader: proto,
				Flags:      TUPLE_F_OUT,
			},
		}
		// CTmap has the addresses in the reverse order w.r.t. the original direction
		key.SourceAddr.FromAddr(dstAddrPort.Addr())
		key.DestAddr.FromAddr(srcAddrPort.Addr())
		if ingress {
			key.Flags = TUPLE_F_IN
		}
		return key.ToNetwork(), true, nil
	}

	if isGlobal {
		key := &CtKey6Global{
			TupleKey6Global: tuple.TupleKey6Global{
				TupleKey6: tuple.TupleKey6{
					SourcePort: uint16(srcAddrPort.Port()),
					DestPort:   uint16(dstAddrPort.Port()),
					NextHeader: proto,
					Flags:      TUPLE_F_OUT,
				},
			},
		}
		// CTmap has the addresses in the reverse order w.r.t. the original direction
		key.SourceAddr.FromAddr(dstAddrPort.Addr())
		key.DestAddr.FromAddr(srcAddrPort.Addr())
		if ingress {
			key.Flags = TUPLE_F_IN
		}
		return key.ToNetwork(), false, nil
	}

	key := &CtKey6{
		TupleKey6: tuple.TupleKey6{
			SourcePort: uint16(srcAddrPort.Port()),
			DestPort:   uint16(dstAddrPort.Port()),
			NextHeader: proto,
			Flags:      TUPLE_F_OUT,
		},
	}
	// CTmap has the addresses in the reverse order w.r.t. the original direction
	key.SourceAddr.FromAddr(dstAddrPort.Addr())
	key.DestAddr.FromAddr(srcAddrPort.Addr())
	if ingress {
		key.Flags = TUPLE_F_IN
	}
	return key.ToNetwork(), false, nil
}

func getMapName(mapname string, ipv4 bool, proto u8proto.U8proto) string {
	if ipv4 {
		if proto == u8proto.TCP {
			mapname = MapNameTCP4 + mapname
		} else {
			mapname = MapNameAny4 + mapname
		}
	} else {
		if proto == u8proto.TCP {
			mapname = MapNameTCP6 + mapname
		} else {
			mapname = MapNameAny6 + mapname
		}
	}
	return mapname
}

func getOrOpenMap(epname string, ipv4 bool, proto u8proto.U8proto) (*bpf.Map, error) {
	mapname := getMapName(epname, ipv4, proto)
	if m := bpf.GetMap(mapname); m != nil {
		return m, nil
	}

	if epname == "global" {
		if ipv4 {
			return bpf.OpenMap(bpf.MapPath(mapname), &CtKey4Global{}, &CtEntry{})
		}

		return bpf.OpenMap(bpf.MapPath(mapname), &CtKey6Global{}, &CtEntry{})
	}

	if ipv4 {
		return bpf.OpenMap(bpf.MapPath(mapname), &CtKey4{}, &CtEntry{})
	}

	return bpf.OpenMap(bpf.MapPath(mapname), &CtKey6{}, &CtEntry{})
}

// Lookup opens a conntrack map if necessary, and does a lookup on it with a key constructed from
// the parameters
// 'epname' is a 5-digit representation of the endpoint ID if local maps
// are to be used, or "global" if global maps should be used.
func Lookup(epname string, srcAddr, dstAddr string, proto u8proto.U8proto, ingress bool) (*CtEntry, error) {
	isGlobal := epname == "global"

	key, ipv4, err := createTupleKey(isGlobal, srcAddr, dstAddr, proto, ingress)
	if err != nil {
		return nil, err
	}

	m, err := getOrOpenMap(epname, ipv4, proto)
	if err != nil || m == nil {
		return nil, err
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return nil, err
	}

	return v.(*CtEntry), err
}

// Update opens a conntrack map if necessary, and does a lookup on it with a key constructed from
// the parameters, and updates the found entry (if any) via 'updateFn'.
// 'epname' is a 5-digit representation of the endpoint ID if local maps
// are to be used, or "global" if global maps should be used.
func Update(epname string, srcAddr, dstAddr string, proto u8proto.U8proto, ingress bool,
	updateFn func(*CtEntry) error) error {
	isGlobal := epname == "global"

	key, ipv4, err := createTupleKey(isGlobal, srcAddr, dstAddr, proto, ingress)
	if err != nil {
		return err
	}

	m, err := getOrOpenMap(epname, ipv4, proto)
	if err != nil || m == nil {
		return err
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return err
	}

	entry := v.(*CtEntry)
	err = updateFn(entry)
	if err != nil {
		return err
	}

	return m.Update(key, entry)
}

type jsonTupleKey struct {
	DestAddr   []uint8 `json:"DestAddr"`
	SourceAddr []uint8 `json:"SourceAddr"`
	DestPort   uint16  `json:"DestPort"`
	SourcePort uint16  `json:"SourcePort"`
	NextHeader uint8   `json:"NextHeader"`
	Flags      uint8   `json:"Flags"`
}

type jsonCtEntry struct {
	Reserved0        uint64 `json:"Reserved0"`
	BackendID        uint64 `json:"BackendID"`
	Packets          uint64 `json:"Packets"`
	Bytes            uint64 `json:"Bytes"`
	Lifetime         uint32 `json:"Lifetime"`
	Flags            uint16 `json:"Flags"`
	RevNAT           uint16 `json:"RevNAT"`
	IfIndex          uint16 `json:"IfIndex"`
	TxFlagsSeen      uint8  `json:"TxFlagsSeen"`
	RxFlagsSeen      uint8  `json:"RxFlagsSeen"`
	SourceSecurityID uint32 `json:"SourceSecurityID"`
	LastTxReport     uint32 `json:"LastTxReport"`
	LastRxReport     uint32 `json:"LastRxReport"`
}

type jsonCtRecord struct {
	Key   jsonTupleKey `json:"Key"`
	Value jsonCtEntry  `json:"Value"`
}

func (j jsonTupleKey) toCtKey4Global() *CtKey4Global {
	return &CtKey4Global{
		TupleKey4Global: tuple.TupleKey4Global{
			TupleKey4: tuple.TupleKey4{
				DestAddr:   types.IPv4{j.DestAddr[0], j.DestAddr[1], j.DestAddr[2], j.DestAddr[3]},
				SourceAddr: types.IPv4{j.SourceAddr[0], j.SourceAddr[1], j.SourceAddr[2], j.SourceAddr[3]},
				DestPort:   j.DestPort,
				SourcePort: j.SourcePort,
				NextHeader: u8proto.U8proto(j.NextHeader),
				Flags:      j.Flags,
			},
		},
	}
}

func (j jsonCtEntry) toCtEntry() CtEntry {
	return CtEntry(j)
}

func getOrOpenServiceMap() (*bpf.Map, error) {
	if m := bpf.GetMap(lbmap.Service4MapV2Name); m != nil {
		return m, nil
	}

	return bpf.OpenMap(bpf.MapPath(lbmap.Service4MapV2Name), &lbmap.Service4Key{}, &lbmap.Service4Value{})
}

func lookupService(key *lbmap.Service4Key) (*lbmap.Service4Value, error) {
	m, err := getOrOpenServiceMap()
	if err != nil || m == nil {
		return nil, err
	}

	v, err := m.Lookup(key)
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*lbmap.Service4Value), nil
}

func getActualRevNat(key *CtKey4Global) (uint16, error) {
	svcKey := lbmap.NewService4Key(key.DestAddr.IP(), key.SourcePort, key.NextHeader, lb.ScopeExternal, 0)
	svcVal, err := lookupService(svcKey)
	if err == nil {
		fmt.Printf("DEBUG SERVICE CT REVNAT %d\n", svcVal.RevNat)
		return svcVal.RevNat, nil
	}

	fmt.Printf("DEBUG SERVICE LB LOOKUP WAS FAILED, TRY INTERNAL SCOPE\n")
	svcKey.Scope = lb.ScopeInternal
	svcVal, err = lookupService(svcKey)
	if err != nil {
		return 0, fmt.Errorf("failed to lookup ct service: %w", err)
	}

	return svcVal.RevNat, nil
}

func InsertAll(rawData []byte) error {
	var records []jsonCtRecord
	if err := json.Unmarshal(rawData, &records); err != nil {
		return fmt.Errorf("failed to unmarshal ct dump: %w", err)
	}

	revnatMap := map[uint16]uint16{}
	for _, rec := range records {
		key := rec.Key.toCtKey4Global()
		val := rec.Value.toCtEntry()

		if key.Flags&TUPLE_F_SERVICE != 0 {
			// get correct revnat index for this node
			revNat, err := getActualRevNat(key)
			if err != nil {
				fmt.Printf("DEBUG FAILED MAP CT SERVICE TO REVNAT %s\n", err)
				continue
			}
			revnatMap[val.RevNAT] = revNat
			val.RevNAT = revNat

			if err := Insert(key, &val); err != nil {
				return fmt.Errorf("failed to insert ct entry to map: %w", err)
			}
		}
	}

	for _, rec := range records {
		key := rec.Key.toCtKey4Global()
		val := rec.Value.toCtEntry()

		if key.Flags&TUPLE_F_SERVICE != 0 {
			continue
		}

		if key.Flags == 0 && val.RevNAT != 0 {
			revNatTarget, ok := revnatMap[val.RevNAT]
			if !ok {
				// cannot translate RevNAT; either skip or strip
				fmt.Printf("DEBUG cannot translate RevNAT, set it to zero %d\n", val.RevNAT)
				val.RevNAT = 0
			} else {
				fmt.Printf("DEBUG SUCCESS translate RevNAT %d\n", revNatTarget)
				val.RevNAT = revNatTarget
			}
		}

		if err := Insert(key, &val); err != nil {
			return fmt.Errorf("failed to insert ct entry to map: %w", err)
		}
	}

	return nil
}

func Insert(key *CtKey4Global, entry *CtEntry) error {
	m, err := getOrOpenMap("global", true, key.NextHeader)
	if err != nil || m == nil {
		return err
	}

	return m.Update(key, entry)
}

func mustIPv4(a, b, c, d byte) types.IPv4 {
	return types.IPv4{a, b, c, d}
}

func FillCtMaps() error {
	m, err := getOrOpenMap("global", true, u8proto.TCP)
	if err != nil || m == nil {
		return err
	}

	// Get current CT time to set GC-safe Lifetime
	ctTime, _ := timestamp.GetCTCurTime(timestamp.GetClockSourceFromOptions())

	for i := 0; i < 300000; i++ {
		ipByte := byte(3)
		if i >= 100000 {
			ipByte = 4
		}
		srcPort := uint16(10000 + i%50000)
		dstPort := uint16(80 + i/50000) // increment DestPort every 50k entries
		key := &CtKey4Global{
			TupleKey4Global: tuple.TupleKey4Global{
				TupleKey4: tuple.TupleKey4{
					DestAddr:   mustIPv4(10, 0, 0, 2),
					SourceAddr: mustIPv4(10, 0, 0, ipByte),
					DestPort:   dstPort,
					SourcePort: srcPort,
					NextHeader: u8proto.TCP,
					Flags:      TUPLE_F_IN,
				},
			},
		}

		entry := &CtEntry{
			Reserved0:        0,
			BackendID:        0,
			Packets:          1,
			Bytes:            64,
			Lifetime:         uint32(ctTime) + 3600,
			Flags:            0,
			RevNAT:           0,
			IfIndex:          0,
			TxFlagsSeen:      0,
			RxFlagsSeen:      0,
			SourceSecurityID: 0,
			LastTxReport:     0,
			LastRxReport:     0,
		}

		if err := m.Update(key, entry); err != nil {
			return err
		}
	}

	return nil
}

func getMapWithName(epname string, ipv4 bool, proto u8proto.U8proto) *bpf.Map {
	return bpf.GetMap(getMapName(epname, ipv4, proto))
}

// CloseLocalMaps closes all local conntrack maps opened previously
// for lookup with the given 'mapname'.
func CloseLocalMaps(mapname string) {
	// only close local maps. Global map is kept open as long as cilium-agent is running.
	if mapname != "global" {
		// close IPv4 maps, if any
		if m := getMapWithName(mapname, true, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(mapname, true, u8proto.UDP); m != nil {
			m.Close()
		}

		// close IPv6 maps, if any
		if m := getMapWithName(mapname, false, u8proto.TCP); m != nil {
			m.Close()
		}
		if m := getMapWithName(mapname, false, u8proto.UDP); m != nil {
			m.Close()
		}
	}
}
