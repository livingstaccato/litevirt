package firewall

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// liveCounters stands in for the kernel's observe counters: replacing the
// per-NIC table zeroes them, as nft does.
type liveCounters struct{ wd []WouldDrop }

func (l *liveCounters) read(context.Context) ([]WouldDrop, error) {
	return append([]WouldDrop(nil), l.wd...), nil
}

func (l *liveCounters) zero() {
	for i := range l.wd {
		l.wd[i].Packets, l.wd[i].Bytes = 0, 0
	}
}

func tallyTotal(t *testing.T, tl *WouldDropTally, owners map[string]NICOwner, workload, rule string) uint64 {
	t.Helper()
	_, entries, err := tl.Snapshot(context.Background(), owners)
	if err != nil {
		t.Fatal(err)
	}
	var n uint64
	for _, e := range entries {
		if e.Workload == workload && e.Rule == rule {
			n += e.Packets
		}
	}
	return n
}

// TestWouldDropTally_SurvivesReplaceAndRestart (re-review I-4): the evidence
// observe mode exists to collect outlives every table replace (a resync, a VM
// start or stop on the host) and a daemon restart, and follows the workload
// rather than the tap name libvirt hands out.
func TestWouldDropTally_SurvivesReplaceAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "would-drop.json")
	live := &liveCounters{wd: []WouldDrop{{Device: "vnet1", Side: "in", Rule: "default", Packets: 5, Bytes: 500}}}
	owners := map[string]NICOwner{"vnet1": {Workload: "web", MAC: "52:54:00:00:00:01"}}
	now := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)

	tl := NewWouldDropTally(path, now)
	tl.read = live.read
	if got := tallyTotal(t, tl, owners, "web", "default"); got != 5 {
		t.Fatalf("live counters not reported: %d", got)
	}

	// A table replace: harvested first, then the kernel zeroes them.
	if err := tl.Harvest(context.Background(), owners); err != nil {
		t.Fatal(err)
	}
	live.zero()
	live.wd[0].Packets = 2
	if got := tallyTotal(t, tl, owners, "web", "default"); got != 7 {
		t.Fatalf("after a replace the total is %d, want 7", got)
	}

	// The VM restarts and gets another tap; the daemon restarts too.
	if err := tl.Harvest(context.Background(), owners); err != nil {
		t.Fatal(err)
	}
	live.wd = []WouldDrop{{Device: "vnet7", Side: "in", Rule: "default", Packets: 1}}
	owners = map[string]NICOwner{"vnet7": {Workload: "web", MAC: "52:54:00:00:00:01"}}
	tl2 := NewWouldDropTally(path, now.Add(time.Hour))
	tl2.read = live.read
	since, _, err := tl2.Snapshot(context.Background(), owners)
	if err != nil {
		t.Fatal(err)
	}
	if !since.Equal(now) {
		t.Errorf("since = %v after a restart, want the original %v", since, now)
	}
	if got := tallyTotal(t, tl2, owners, "web", "default"); got != 8 {
		t.Errorf("after a restart and a new tap the total is %d, want 8", got)
	}
}

// TestWouldDropTally_ResetOnlyByCommand: the totals restart only on Reset,
// which also discounts what the kernel counted before it.
func TestWouldDropTally_ResetOnlyByCommand(t *testing.T) {
	path := filepath.Join(t.TempDir(), "would-drop.json")
	live := &liveCounters{wd: []WouldDrop{{Device: "vnet1", Side: "out", Rule: "sg:x#0", Packets: 9}}}
	owners := map[string]NICOwner{"vnet1": {Workload: "db"}}
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	tl := NewWouldDropTally(path, t0)
	tl.read = live.read
	if err := tl.Harvest(context.Background(), owners); err != nil {
		t.Fatal(err)
	}
	live.zero()
	live.wd[0].Packets = 4

	t1 := t0.Add(24 * time.Hour)
	if err := tl.Reset(context.Background(), owners, t1); err != nil {
		t.Fatal(err)
	}
	if got := tallyTotal(t, tl, owners, "db", "sg:x#0"); got != 0 {
		t.Fatalf("after a reset the total is %d, want 0", got)
	}
	live.wd[0].Packets = 6 // two more since the reset
	if got := tallyTotal(t, tl, owners, "db", "sg:x#0"); got != 2 {
		t.Errorf("total = %d, want the 2 counted since the reset", got)
	}
	if err := tl.Harvest(context.Background(), owners); err != nil {
		t.Fatal(err)
	}
	live.zero()
	if got := tallyTotal(t, tl, owners, "db", "sg:x#0"); got != 2 {
		t.Errorf("after a replace following a reset the total is %d, want 2", got)
	}
	since, _, _ := tl.Snapshot(context.Background(), owners)
	if !since.Equal(t1) {
		t.Errorf("since = %v, want the reset time %v", since, t1)
	}
}

// TestApplier_HarvestsBeforeReplace: the applier hands the counters of the
// table it is about to replace to the tally, with the owners of THAT table.
func TestApplier_HarvestsBeforeReplace(t *testing.T) {
	f := &fakeNft{}
	a := NewApplier(f)
	live := &liveCounters{wd: []WouldDrop{{Device: "vnet1", Side: "in", Rule: "default", Packets: 3}}}
	tl := NewWouldDropTally(filepath.Join(t.TempDir(), "t.json"), time.Now())
	tl.read = live.read
	a.SetTally(tl)

	p := Plan{NICMode: NICModeObserve, DefaultDeny: true, NICs: []NICBinding{{NICDev: "vnet1", VMName: "web", MAC: "52:54:00:00:00:01"}}}
	if _, err := a.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	live.zero() // the first apply replaced the table the counters were in... after harvesting them
	p.NICs = append(p.NICs, NICBinding{NICDev: "vnet2", VMName: "db"})
	live.wd[0].Packets = 4
	if _, err := a.Apply(context.Background(), p); err != nil {
		t.Fatal(err)
	}
	live.zero()
	owners := map[string]NICOwner{"vnet1": {Workload: "web", MAC: "52:54:00:00:00:01"}}
	if got := tallyTotal(t, tl, owners, "web", "default"); got != 7 {
		t.Errorf("total after two replaces = %d, want 7", got)
	}
}
