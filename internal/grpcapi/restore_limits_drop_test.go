package grpcapi

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// restoreWithLimits live-restores the cluster's own row of a VM whose spec
// carries cpuLimit, shares 200 and a 100 MB/s NIC rate, through gate, as vm2.
// It returns the restored row's spec (nil when no row was written), the
// defined domain and the log.
func restoreWithLimits(t *testing.T, gate ioGate, cpuLimit float64) (*pb.VMSpec, string, string, error) {
	t.Helper()
	s := testServer(t)
	s.hostName = "host-a"
	fake := libvirtfake.New()
	s.virt = fake
	gate.t = t
	s.SetReleaseFeatureGate(gate)
	logs := captureSlog(t)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 2048, Machine: "q35", Firmware: "uefi",
		CpuLimit: cpuLimit, CpuShares: 200,
		Network: []*pb.NetworkAttachment{{Name: "lo", Model: "virtio", RateMbSec: 100}}})
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "vm1", HostName: "host-a", State: "stopped", Spec: string(spec)}, nil, nil); err != nil {
		t.Fatal(err)
	}
	repoDir, ts := seedLiveRepo(t, make([]byte, pbsstore.ChunkSize), "")
	_, cancel, done := runRestoreLiveUntil(t, s, &pb.RestoreLiveRequest{
		RepoPath: repoDir, VmName: "vm1", DiskName: "root", Timestamp: ts, FromExisting: true, NewName: "vm2",
		TargetPath: filepath.Join(t.TempDir(), "live.qcow2"), AutoStart: true,
	}, pb.RestoreLiveProgress_STARTED)
	row, _ := corrosion.GetVM(context.Background(), s.db, "vm2")
	x := fake.DefinedXML("vm2")
	cancel()
	err := <-done
	if row == nil {
		return nil, x, logs.String(), err
	}
	var got pb.VMSpec
	_ = json.Unmarshal([]byte(row.Spec), &got)
	return &got, x, logs.String(), err
}

// A live restore is a recovery path main allowed, and main knows no limit
// fields: limits in the spec it restores are dropped, never refused — before
// the release latch (all of them), when a value is one a create would refuse
// (that value), and when the gate refuses after the latch (all of them) —
// each with a warning naming it. A valid limit past an open gate is kept.
//
// Mutations: refuse as before (checkCopiedSpecLimits) — the closed and invalid
// cases write no row; return the gate's refusal at the define — the refusing
// case writes no row; drop every limit on an invalid one — the shares are lost.
func TestRestoreLive_SpecLimitsAreDroppedNotRefused(t *testing.T) {
	// Open gate, valid: kept.
	got, x, _, err := restoreWithLimits(t, ioGate{on: true}, 1.5)
	if got == nil || got.CpuLimit != 1.5 || got.CpuShares != 200 || got.Network[0].RateMbSec != 100 ||
		!strings.Contains(x, "<cputune>") || !strings.Contains(x, "<bandwidth") {
		t.Fatalf("open gate, valid limits: spec %+v err=%v\n%s", got, err, x)
	}

	for name, tc := range map[string]struct {
		gate     ioGate
		cpuLimit float64
		keep     bool // the valid shares and rate survive
		key      string
	}{
		"before the latch":         {gate: ioGate{on: false}, cpuLimit: 1.5, key: "cpu_limit"},
		"invalid cpu limit":        {gate: ioGate{on: true}, cpuLimit: 99, keep: true, key: "cpu_limit"},
		"gate refuses after latch": {gate: ioGate{latchedButRefuses: true}, cpuLimit: 1.5, key: "cpu_limit"},
	} {
		got, x, logs, err := restoreWithLimits(t, tc.gate, tc.cpuLimit)
		if got == nil {
			t.Errorf("%s: the restore wrote no row (restore: %v)", name, err)
			continue
		}
		if got.CpuLimit != 0 {
			t.Errorf("%s: cpu_limit %v stored; want it dropped", name, got.CpuLimit)
		}
		if tc.keep != (got.CpuShares == 200 && got.Network[0].RateMbSec == 100) {
			t.Errorf("%s: shares %d rate %v; keep the valid ones = %v", name, got.CpuShares, got.Network[0].RateMbSec, tc.keep)
		}
		if !tc.keep && (strings.Contains(x, "<cputune>") || strings.Contains(x, "<bandwidth")) {
			t.Errorf("%s: the domain still renders limits:\n%s", name, x)
		}
		if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, tc.key) {
			t.Errorf("%s: no warning naming %s:\n%s", name, tc.key, logs)
		}
	}
}
