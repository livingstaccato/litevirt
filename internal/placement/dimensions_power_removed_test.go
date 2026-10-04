package placement

import (
	"fmt"
	"math"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The power/thermal dimension was removed on 2026-10-04: it had no telemetry
// producer, so its Capacity was always 0 and scoreDimension skipped it. See
// docs/design/placement-power-dimension.md for what it needs to come back.

func TestAllDimensions_NoPower(t *testing.T) {
	want := []string{"cpu", "ram", "disk_iops", "net_bw", "numa", "host_gen"}
	dims := AllDimensions(DefaultWeights())
	var got []string
	for _, d := range dims {
		got = append(got, d.Name())
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("AllDimensions names = %v, want %v", got, want)
	}
}

// scoreIdentityFixture exercises every wired dimension: CPU/RAM usage from
// VMs, disk/net from labels plus sampled usage, NUMA and host generation from
// labels, and cost.hourly for cost-aware. Hosts differ on each axis so a
// change to any dimension's contribution moves at least one score.
func scoreIdentityFixture() *ClusterSnapshot {
	hosts := []corrosion.HostRecord{
		{Name: "a", State: "active", CPUTotal: 32, MemTotal: 131072, Labels: map[string]string{
			"placement.iops_capacity": "20000", "placement.netbw_mbps": "10000",
			"numa.preferred": "true", "host.generation": "4", "cost.hourly": "2.0",
		}},
		{Name: "b", State: "active", CPUTotal: 16, MemTotal: 65536, Labels: map[string]string{
			"placement.iops_capacity": "10000", "host.generation": "2", "cost.hourly": "1.0",
		}},
		{Name: "c", State: "active", CPUTotal: 64, MemTotal: 262144, Labels: map[string]string{
			"placement.netbw_mbps": "25000", "host.generation": "7", "cost.hourly": "3.5",
		}},
		{Name: "d", State: "active", CPUTotal: 8, MemTotal: 32768},
	}
	vms := []corrosion.VMRecord{
		{Name: "a1", HostName: "a", State: "running", CPUActual: 8, MemActual: 16384},
		{Name: "a2", HostName: "a", State: "running", CPUActual: 4, MemActual: 8192},
		{Name: "b1", HostName: "b", State: "running", CPUActual: 10, MemActual: 40960},
		{Name: "c1", HostName: "c", State: "running", CPUActual: 2, MemActual: 4096},
		{Name: "d1", HostName: "d", State: "creating", CPUActual: 2, MemActual: 8192},
	}
	usage := map[string]corrosion.HostRuntimeUsage{
		"a": {DiskIOPS: 6000, NetMbps: 2500},
		"b": {DiskIOPS: 7500, NetMbps: 100},
		"c": {DiskIOPS: 300, NetMbps: 12000},
	}
	return BuildSnapshotFromUsage(hosts, vms, usage)
}

// TestRank_ScoresUnchangedByPowerRemoval pins the scores the engine produced
// with the power dimension still registered (recorded on 29abe03f). Removing a
// dimension whose capacity was always 0 must not move any score.
func TestRank_ScoresUnchangedByPowerRemoval(t *testing.T) {
	// Best-first, exactly as RankFromSnapshot returned them before the
	// removal. spread-strict omits b: the pressure cap excludes it.
	golden := map[Policy][]Candidate{
		PolicyBalance:      {{"a", 66.59375}, {"c", 57.85625}, {"d", 28.125}, {"b", 22.8125}},
		PolicyBinPack:      {{"b", 47.1875}, {"a", 23.40625}, {"d", 21.875}, {"c", 7.14375}},
		PolicySpreadStrict: {{"a", 66.59375}, {"c", 57.85625}, {"d", 28.125}},
		PolicyCostAware:    {{"a", 33.296875}, {"d", 28.125}, {"b", 22.8125}, {"c", 16.530357142857}},
	}
	for pol, want := range golden {
		r := Request{CPUNeeded: 2, MemMiBNeeded: 4096, Policy: pol}
		got, err := RankFromSnapshot(scoreIdentityFixture(), &r)
		if err != nil {
			t.Fatalf("%s: %v", pol, err)
		}
		if len(got) != len(want) {
			t.Errorf("%s: ranked %v, want %v", pol, got, want)
			continue
		}
		for i := range want {
			if got[i].Host != want[i].Host || math.Abs(got[i].Score-want[i].Score) > 1e-9 {
				t.Errorf("%s: rank %d = %+v, want %+v", pol, i, got[i], want[i])
			}
		}
	}
}
