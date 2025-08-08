// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package metrics

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/singleflight"

	"github.com/cilium/cilium/pkg/version"
	"github.com/cilium/cilium/pkg/versioncheck"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type bpfCollector struct {
	sfg singleflight.Group

	bpfMapsCount          *prometheus.Desc
	bpfMapsMemory         *prometheus.Desc
	bpfProgramsCount      *prometheus.Desc
	bpfProgramsMemory     *prometheus.Desc
	bpfProgramsComplexity *prometheus.Desc
}

type bpfUsage struct {
	count                 uint32
	virtualMemoryMaxBytes uint32
}

func isVerifierComplexitySupported() string {
	minVersion := "5.16"

	v, err := versioncheck.Version(minVersion)
	if err != nil {
		return "Cannot parse minimum kernel version — this metric may not be supported"
	}

	kv, err := version.GetKernelVersion()
	if err != nil {
		return "Cannot determine current kernel version — this metric may not be supported"
	}

	if kv.LT(v) {
		return fmt.Sprintf(
			"Kernel verifier complexity metric is not available: running kernel %v < required %v",
			kv, minVersion,
		)
	}

	return ""
}

func newbpfCollector() *bpfCollector {
	metricInfo := "Maximum number of verified instructions among loaded BPF programs."
	metricDescription := isVerifierComplexitySupported()
	if len(metricDescription) > 0 {
		metricInfo = metricInfo + " " + metricDescription
	}

	return &bpfCollector{
		bpfMapsCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_maps"),
			"Total count of BPF maps.",
			nil, nil,
		),
		bpfMapsMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_maps_virtual_memory_max_bytes"),
			"BPF maps kernel max memory usage size in bytes.",
			nil, nil,
		),
		bpfProgramsCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs"),
			"Total count of BPF programs.",
			nil, nil,
		),
		bpfProgramsMemory: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs_virtual_memory_max_bytes"),
			"BPF programs kernel max memory usage size in bytes.",
			nil, nil,
		),
		bpfProgramsComplexity: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, "", "bpf_progs_complexity_max_verified_insts"),
			metricInfo,
			nil, nil,
		),
	}
}

func (s *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(s, ch)
}

func findFirstNumber(data []byte, start int) int {
	n := len(data)
	for start < n {
		c := data[start]
		switch {
		case c >= '0' && c <= '9':
			return start
		default:
			start++
		}
	}
	return -1
}

func getBpfMemory(fd int) (uint32, error) {
	path := fmt.Sprintf("/proc/self/fdinfo/%d", fd)
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()

	reader := bufio.NewReaderSize(f, 512)
	for {
		data, _, err := reader.ReadLine()
		if err != nil {
			if err == io.EOF {
				return 0, fmt.Errorf("memlock key not found in %s", path)
			}
			return 0, err
		}

		key := []byte("memlock:")
		idx := bytes.Index(data, key)
		if idx == -1 {
			continue
		}

		valueIdx := findFirstNumber(data, idx+len(key))
		if valueIdx == -1 {
			return 0, fmt.Errorf("memlock value not found")
		}

		valBytes := data[valueIdx:]
		var val uint32
		for _, c := range valBytes {
			if c < '0' || c > '9' {
				break
			}
			val = val*10 + uint32(c-'0')
		}
		return uint32(val), nil
	}
}

func getCiliumMapsStats() (mapIDs map[ebpf.MapID]struct{}, memorySum uint32, count uint32, err error) {
	mapIDs = make(map[ebpf.MapID]struct{}, 256)
	var startID ebpf.MapID = 0
	for {
		nextID, err := ebpf.MapGetNextID(startID)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				break
			}
			return nil, 0, 0, fmt.Errorf("failed to get next map ID after %d: %w", startID, err)
		}

		startID = nextID
		m, err := ebpf.NewMapFromID(nextID)
		if err != nil {
			continue
		}

		info, err := m.Info()
		if err != nil {
			m.Close()
			continue
		}

		if !strings.HasPrefix(info.Name, "cilium_") {
			m.Close()
			continue
		}

		mapMemory, err := getBpfMemory(int(m.FD()))
		m.Close()
		if err != nil {
			continue
		}

		mapIDs[nextID] = struct{}{}
		count++
		memorySum += mapMemory
	}
	return mapIDs, memorySum, count, nil
}

func getCiliumProgsStats(ciliumMapIDs map[ebpf.MapID]struct{}) (maxComplexity uint32, memorySum uint32, count uint32, err error) {
	var startID ebpf.ProgramID = 0
	for {
		nextID, err := ebpf.ProgramGetNextID(startID)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				break
			}
			return 0, 0, 0, fmt.Errorf("failed to get next program ID: %v", err)
		}

		startID = nextID
		prog, err := ebpf.NewProgramFromID(nextID)
		if err != nil {
			continue
		}

		info, err := prog.Info()
		if err != nil {
			prog.Close()
			continue
		}

		mapIDs, ok := info.MapIDs()
		if !ok {
			prog.Close()
			continue
		}

		usesCiliumMap := false
		for _, mapID := range mapIDs {
			if _, ok := ciliumMapIDs[mapID]; ok {
				usesCiliumMap = true
				break
			}
		}
		if !usesCiliumMap {
			prog.Close()
			continue
		}

		progMemory, err := getBpfMemory(int(prog.FD()))
		prog.Close()
		if err != nil {
			continue
		}

		insts, valid := info.VerifiedInstructions()
		if valid && insts > maxComplexity {
			maxComplexity = insts
		}

		count++
		memorySum += progMemory
	}
	return maxComplexity, memorySum, count, nil
}

func (s *bpfCollector) Collect(ch chan<- prometheus.Metric) {
	type bpfUsageResults struct {
		maps          bpfUsage
		programs      bpfUsage
		maxComplexity uint32
	}

	// Avoid querying BPF multiple times concurrently, if it happens, additional callers will wait for the
	// first one to finish and reuse its resulting values.
	results, err, _ := s.sfg.Do("collect", func() (interface{}, error) {
		var (
			results                                 = bpfUsageResults{}
			mapIDs                                  map[ebpf.MapID]struct{}
			mapMemorySum, mapCount                  uint32
			maxComplexity, progMemorySum, progCount uint32
			err                                     error
		)

		if mapIDs, mapMemorySum, mapCount, err = getCiliumMapsStats(); err != nil {
			return results, err
		}

		if maxComplexity, progMemorySum, progCount, err = getCiliumProgsStats(mapIDs); err != nil {
			return results, err
		}

		results = bpfUsageResults{
			maps: bpfUsage{
				count:                 mapCount,
				virtualMemoryMaxBytes: mapMemorySum,
			},
			programs: bpfUsage{
				count:                 progCount,
				virtualMemoryMaxBytes: progMemorySum,
			},
			maxComplexity: maxComplexity,
		}
		return results, nil
	})

	if err != nil {
		logrus.WithError(err).Error("retrieving BPF maps & programs usage")
		return
	}

	ch <- prometheus.MustNewConstMetric(
		s.bpfMapsCount,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).maps.count),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfMapsMemory,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).maps.virtualMemoryMaxBytes),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfProgramsCount,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).programs.count),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfProgramsMemory,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).programs.virtualMemoryMaxBytes),
	)

	ch <- prometheus.MustNewConstMetric(
		s.bpfProgramsComplexity,
		prometheus.GaugeValue,
		float64(results.(bpfUsageResults).maxComplexity),
	)
}
