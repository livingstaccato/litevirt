package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/storage"
)

// addPool adds a second ceph pool to the fixture, on its own rbd pool, with
// the same client and keyring.
func (f *cephPoolFixture) addPool(t *testing.T, name, rbdPool string) {
	t.Helper()
	opts := map[string]string{"id": "litevirt", "keyring": f.keyring, "mon_host": "10.78.0.22"}
	if err := corrosion.UpsertStoragePool(context.Background(), f.s.db, corrosion.StoragePoolRecord{
		HostName: "test-host", Name: name, Driver: "ceph", Source: rbdPool, Options: opts, State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	f.s.addStoragePoolRef(name, StoragePoolRef{Driver: "ceph", Source: rbdPool, Options: opts})
}

// insertPoolVM records a VM on this host with one rbd disk on the given
// litevirt pool (rbd pool rbdPool), in the given state.
func (f *cephPoolFixture) insertPoolVM(t *testing.T, name, pool, rbdPool, state string) corrosion.VMRecord {
	t.Helper()
	ref := rbdPool + "/" + name + "-root"
	f.world.mu.Lock()
	f.world.images[ref] = map[string]bool{}
	f.world.mu.Unlock()
	disk := corrosion.DiskRecord{
		VMName: name, DiskName: "root", HostName: "test-host", StorageType: "ceph", StorageVolume: pool,
		Path: "rbd:" + ref + ":id=litevirt:keyring=" + f.keyring + ":lvpool=" + pool, DeleteWithVM: true,
	}
	vm := corrosion.VMRecord{Name: name, HostName: "test-host", State: state, Spec: `{"name":"` + name + `","cpu":1,"memory_mib":256}`}
	if err := corrosion.InsertVM(context.Background(), f.s.db, vm, nil, []corrosion.DiskRecord{disk}); err != nil {
		t.Fatal(err)
	}
	return vm
}

func (f *cephPoolFixture) started(name string) bool {
	for _, e := range f.fake.EventLog() {
		if e.Domain == name && e.Op == "start" {
			return true
		}
	}
	return false
}

// I-R4-1. Two ceph pools, one whose cluster does not answer. The VM on the
// broken pool sorts first. Its probe fails (taking a probe's whole bound),
// so the healthy pool's VM behind it is deferred for time on the first pass
// — and starts on the second. Before, the broken VM held the head of every
// walk and spent the budget the healthy one needed. Two things each keep it
// from doing so, and each is tested on its own: the failure is remembered
// (the broken VM is deferred at once on the second pass), and, once that
// memory has aged out, the VM deferred for time is walked AHEAD of the one
// whose probe failed.
func TestReconciler_HealthyCephPoolStartsWhileAnotherIsDown(t *testing.T) {
	for _, tc := range []struct {
		name string
		aged bool
	}{{"failure remembered", false}, {"failure aged out", true}} {
		t.Run(tc.name, func(t *testing.T) { healthyPoolStarts(t, tc.aged) })
	}
}

func healthyPoolStarts(t *testing.T, aged bool) {
	f := newCephPoolFixture(t)
	f.addPool(t, "ceph2", "lv2")
	f.world.down = map[string]bool{"lv2": true}
	f.insertPoolVM(t, "a-db", "ceph2", "lv2", "running")
	f.insertPoolVM(t, "b-web", "ceph", "lv", "running")
	r := health.NewReconciler("test-host", t.TempDir(), f.s.db, f.fake)
	r.SetHardwareStartPreparer(f.s.PrepareHardwareForStart)
	r.SetStartDeferral(f.s.CephStartDeferral)
	ctx := context.Background()

	r.ReconcileOnce(ctx)
	if f.started("a-db") || f.started("b-web") {
		t.Fatal("fixture: a VM started on the first pass")
	}
	if aged {
		defer func(prev func() time.Time) { cephProofNow = prev }(cephProofNow)
		cephProofNow = func() time.Time { return time.Now().Add(cephKeyFailTTL + time.Second) }
	}
	r.ReconcileOnce(ctx)
	if !f.started("b-web") {
		t.Fatalf("the healthy pool's VM did not start within two passes (calls %v)", f.world.calls)
	}
	if f.started("a-db") {
		t.Fatal("the VM on the pool that does not answer started")
	}
	for _, n := range []string{"a-db", "b-web"} {
		if vm, err := corrosion.GetVM(ctx, f.s.db, n); err != nil || vm.State == "error" {
			t.Fatalf("%s: %+v %v; a deferral parked it in error", n, vm, err)
		}
	}
}

// I-R4-1. The FIRST probe a walk asks for runs even with less than a probe's
// bound left, bounded by what is left; a walk with its turn spent defers the
// next, as a call outside any walk does.
func TestPrepareHardwareForStart_FirstProbeOfAWalkRunsOnWhatIsLeft(t *testing.T) {
	f := newCephPoolFixture(t)
	f.addPool(t, "ceph2", "lv2")
	a := f.insertPoolVM(t, "pa", "ceph", "lv", "stopped")
	b := f.insertPoolVM(t, "pb", "ceph2", "lv2", "stopped")
	walk, cancel := context.WithTimeout(health.WithWalkProbeTurn(context.Background()), 5*time.Second)
	defer cancel()
	if err := f.s.CephStartDeferral(walk, &a); err != nil {
		t.Fatalf("the walk's first probe was deferred before any work: %v", err)
	}
	if _, err := f.s.PrepareHardwareForStart(walk, &a); err != nil || f.world.probes() != 1 {
		t.Fatalf("the walk's first probe with 5 s left: %v, %d probes; want it run", err, f.world.probes())
	}
	if left := f.world.probeLeft[0]; left > 5*time.Second {
		t.Fatalf("the probe ran with %v left, more than the walk has", left)
	}
	if err := f.s.CephStartDeferral(walk, &b); !errors.Is(err, health.ErrStartDeferred) {
		t.Fatalf("a second unproven key in the same walk: %v, want a deferral", err)
	}
	if _, err := f.s.PrepareHardwareForStart(walk, &b); !errors.Is(err, health.ErrStartDeferred) || f.world.probes() != 1 {
		t.Fatalf("a second unproven key in the same walk: %v, %d probes; want a deferral and no rbd", err, f.world.probes())
	}
	plain, cancel2 := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel2()
	if _, err := f.s.PrepareHardwareForStart(plain, &b); !errors.Is(err, health.ErrStartDeferred) || f.world.probes() != 1 {
		t.Fatalf("outside a walk with 5 s left: %v, %d probes; want a deferral", err, f.world.probes())
	}
}

// I-R4-1. A probe cut short by the walk's own deadline is a deferral for
// TIME: it says nothing about the storage, so it is not remembered as a
// failure, and the next walk probes again.
func TestPrepareHardwareForStart_AProbeCutShortIsNotAFailure(t *testing.T) {
	f := newCephPoolFixture(t)
	f.world.down = map[string]bool{"lv": true}
	a := f.insertPoolVM(t, "sa", "ceph", "lv", "stopped")
	walk, cancel := context.WithTimeout(health.WithWalkProbeTurn(context.Background()), 3*time.Second)
	defer cancel()
	_, err := f.s.PrepareHardwareForStart(walk, &a)
	if !errors.Is(err, health.ErrStartDeferred) || errors.Is(err, health.ErrStartProbeFailed) || errors.Is(err, health.ErrStartStorageDown) {
		t.Fatalf("a probe cut short by the walk: %v, want a deferral for time only", err)
	}
	f.world.down = nil
	if _, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &a); err != nil || f.world.probes() != 2 {
		t.Fatalf("next walk: %v, %d probes; want it probed again and started", err, f.world.probes())
	}
}

// I-R4-1. A probe the storage did not answer is remembered for about one
// pass: in a walk, the next VM on that storage is deferred at once — no
// probe — as "storage down", the failing VM itself as "probe failed". A
// call outside a walk (an operator's start) still probes. Once the memory
// ages out, the walk probes again.
func TestPrepareHardwareForStart_FailedProbeIsRememberedForAPass(t *testing.T) {
	f := newCephPoolFixture(t)
	f.world.infoExit, f.world.infoOut = 110, "rbd: couldn't connect to the cluster!"
	a := f.insertPoolVM(t, "fa", "ceph", "lv", "stopped")
	b := f.insertPoolVM(t, "fb", "ceph", "lv", "stopped")
	walk := health.WithWalkProbeTurn(context.Background())
	if _, err := f.s.PrepareHardwareForStart(walk, &a); !errors.Is(err, health.ErrStartProbeFailed) || f.world.probes() != 1 {
		t.Fatalf("a probe Ceph did not answer: %v (%d probes), want ErrStartProbeFailed", err, f.world.probes())
	}
	if err := f.s.CephStartDeferral(walk, &b); !errors.Is(err, health.ErrStartStorageDown) || errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("another VM on that storage, before any work: %v, want ErrStartStorageDown", err)
	}
	if err := f.s.CephStartDeferral(walk, &a); !errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("the failing VM itself, before any work: %v, want ErrStartProbeFailed", err)
	}
	if _, err := f.s.PrepareHardwareForStart(walk, &b); !errors.Is(err, health.ErrStartStorageDown) || f.world.probes() != 1 {
		t.Fatalf("another VM on that storage: %v (%d probes), want a deferral and no probe", err, f.world.probes())
	}
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &b); err == nil || f.world.probes() != 2 {
		t.Fatalf("an operator's start: %v (%d probes), want it probed", err, f.world.probes())
	}
	// A probe that is answered forgets the failure at once.
	f.world.infoExit = 0
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &b); err != nil || f.world.probes() != 3 {
		t.Fatalf("an operator's start once Ceph answers: %v (%d probes)", err, f.world.probes())
	}
	if err := f.s.CephStartDeferral(health.WithWalkProbeTurn(context.Background()), &a); err != nil {
		t.Fatalf("after a probe was answered: %v, want no deferral", err)
	}
	// A failure ages out after about a pass.
	f.world.infoExit = 110
	writeKeyring(t, f.keyring, []byte("another-restricted-key-bytes")) // unproven again
	if _, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &a); !errors.Is(err, health.ErrStartProbeFailed) || f.world.probes() != 4 {
		t.Fatalf("a rotated key Ceph does not answer for: %v (%d probes)", err, f.world.probes())
	}
	defer func(prev func() time.Time) { cephProofNow = prev }(cephProofNow)
	cephProofNow = func() time.Time { return time.Now().Add(cephKeyFailTTL + time.Second) }
	f.world.infoExit = 0
	if _, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &b); err != nil || f.world.probes() != 5 {
		t.Fatalf("after the memory aged out: %v (%d probes), want it probed and started", err, f.world.probes())
	}
}

// m5. A VM's rbd disks a live client still holds are waited for together,
// within one bound: N disks refuse in about one wait, not N of them in turn
// (which outlasted the 2 min owner proxy).
func TestDeleteVMDisks_InUseWaitsRunTogether(t *testing.T) {
	f := newCephPoolFixture(t)
	t.Cleanup(storage.OverrideCephBusyBudgetForTest(2 * time.Second))
	f.insertCephVMDisks(t, "busy", 3)
	f.world.watchers = map[string]bool{"lv/busy-da": true, "lv/busy-db": true, "lv/busy-dc": true}
	ctx := context.Background()
	disks, err := corrosion.GetVMDisks(ctx, f.s.db, "busy")
	if err != nil || len(disks) != 3 {
		t.Fatalf("disks %v %v", disks, err)
	}
	start := time.Now()
	err = f.s.deleteRecordedVMDiskVolumeRecords(ctx, "busy", disks)
	el := time.Since(start)
	if err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("got %v, want an in-use refusal", err)
	}
	if el > 6*time.Second {
		t.Fatalf("three in-use disks took %v to refuse: waited for one after another", el)
	}
	for _, d := range []string{"lv/busy-da", "lv/busy-db", "lv/busy-dc"} {
		if !f.world.has(d) {
			t.Fatalf("%s was removed while in use", d)
		}
	}
}

// m2/m4/m6. ceph_trash_leftover names, beside a failing purge: an entry HELD
// because a client still has it open (with `rbd trash restore`), a queue
// file set aside as unreadable, and — once seen on two scans — a litevirt
// image in a pool's trash that no purge here tracks.
func TestCephTrashLeftover_NamesHeldSetAsideAndUntracked(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ceph-trash-purges.json"), []byte("[{"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = storage.ResumeCephPurges(dir)

	vm := f.insertCephVM(t, "held", "test-host")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, vm.Name)
	if err := f.s.deleteRecordedVMDiskVolumeRecords(ctx, vm.Name, disks); err != nil {
		t.Fatal(err)
	}
	f.world.trashRmExit = 16
	storage.RunCephPurgesOnceForTest()
	var heldRef string
	for _, p := range storage.CephPendingPurges() {
		if p.State == storage.CephPurgeHeld {
			heldRef = p.TrashRef()
		}
	}
	if heldRef == "" {
		t.Fatalf("pending %+v, want the watched entry held", storage.CephPendingPurges())
	}

	f.world.mu.Lock()
	f.world.trash["lv/0dd1"] = "web-data"
	f.world.mu.Unlock()
	f.s.ScanCephTrash(ctx)
	f.s.judgeCephTrash(ctx)
	row, found, err := corrosion.GetHealthCondition(ctx, f.s.db, cephPoolEvaluator, condCephTrashLeftover, "host", "test-host")
	if err != nil || !found {
		t.Fatalf("condition %+v %v %v", row, found, err)
	}
	var ev struct {
		Leftovers []struct {
			Trash, State string
			ByHand       string `json:"by_hand"`
		} `json:"leftovers"`
		Unreadable []string `json:"unreadable_queue_files"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("evidence %s: %v", row.Evidence, err)
	}
	named := false
	for _, l := range ev.Leftovers {
		named = named || (l.Trash == heldRef && l.State == storage.CephPurgeHeld && l.ByHand == "rbd trash restore "+heldRef)
	}
	if !named || len(ev.Unreadable) != 1 || !strings.Contains(ev.Unreadable[0], ".unreadable-") {
		t.Fatalf("evidence %s, want %s held with `rbd trash restore`, and the set-aside queue file", row.Evidence, heldRef)
	}
	if strings.Contains(row.Evidence, "lv/0dd1") {
		t.Fatalf("an entry seen on one scan only was named (another host may be purging it): %s", row.Evidence)
	}
	f.s.ScanCephTrash(ctx)
	f.s.judgeCephTrash(ctx)
	row, _, _ = corrosion.GetHealthCondition(ctx, f.s.db, cephPoolEvaluator, condCephTrashLeftover, "host", "test-host")
	if !strings.Contains(row.Evidence, "lv/0dd1") || !strings.Contains(row.Evidence, "web-data") {
		t.Fatalf("evidence %s, want the untracked lv/0dd1 (web-data) named", row.Evidence)
	}
}

// Breaker R-1. A key another VM's probe proved says nothing about the image
// whose own probe got no answer (an inactive PG under it): that VM is probed
// again — never started on the other VM's proof, where qemu's open of its
// image would hang the start.
func TestPrepareHardwareForStart_AnotherVMsProofDoesNotSkipAFailedVMsProbe(t *testing.T) {
	f := newCephPoolFixture(t)
	x := f.insertPoolVM(t, "x-db", "ceph", "lv", "stopped")
	y := f.insertPoolVM(t, "y-web", "ceph", "lv", "stopped")
	f.world.downImages = map[string]bool{"lv/x-db-root": true}
	if _, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &x); !errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("x, whose image does not answer: %v, want ErrStartProbeFailed", err)
	}
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &y); err != nil {
		t.Fatalf("y, on the same key: %v", err)
	}
	before := f.world.probes()
	_, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &x)
	if f.world.probes() != before+1 || !errors.Is(err, health.ErrStartProbeFailed) {
		t.Fatalf("x after y proved the key: %v, %d new probes; want x probed itself and deferred, not started on y's proof", err, f.world.probes()-before)
	}
	// Once x's own image answers (an operator's start, which always
	// probes), x starts, and the remembered proof covers it again.
	f.world.downImages = nil
	if _, err := f.s.PrepareHardwareForStart(context.Background(), &x); err != nil {
		t.Fatalf("x once its image answers: %v", err)
	}
	before = f.world.probes()
	if _, err := f.s.PrepareHardwareForStart(health.WithWalkProbeTurn(context.Background()), &x); err != nil || f.world.probes() != before {
		t.Fatalf("x again: %v, %d probes; want the proof to cover it once its own probe succeeded", err, f.world.probes()-before)
	}
}

// Breaker R-2/R-4. ceph_trash_leftover never advises `rbd trash rm` for an
// entry this host cannot vouch for: an untracked one (another host may hold
// it for a client that has it open) gets only `rbd trash restore`, and a move
// whose outcome is not settled (the image may still be live under its name)
// gets only the check to run.
func TestCephTrashLeftover_NoRemoveAdviceForUntrackedOrUnsettled(t *testing.T) {
	f := newCephPoolFixture(t)
	ctx := context.Background()
	vm := f.insertCephVM(t, "unsettled", "test-host")
	disks, _ := corrosion.GetVMDisks(ctx, f.s.db, vm.Name)
	f.world.trashMvExit, f.world.trashLsExit = 110, 110
	if err := f.s.deleteRecordedVMDiskVolumeRecords(ctx, vm.Name, disks); err == nil {
		t.Fatal("a move that could not be settled reported success")
	}
	storage.RunCephPurgesOnceForTest() // still cannot settle it
	f.world.trashLsExit = 0
	f.world.mu.Lock()
	f.world.trash["lv/0dd1"] = "web-data"
	f.world.mu.Unlock()
	f.s.ScanCephTrash(ctx)
	f.s.ScanCephTrash(ctx)
	f.s.judgeCephTrash(ctx)
	row, found, err := corrosion.GetHealthCondition(ctx, f.s.db, cephPoolEvaluator, condCephTrashLeftover, "host", "test-host")
	if err != nil || !found {
		t.Fatalf("condition %+v %v %v", row, found, err)
	}
	var ev struct {
		Leftovers []struct {
			Trash, Image, State string
			ByHand              string `json:"by_hand"`
		} `json:"leftovers"`
	}
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, l := range ev.Leftovers {
		if strings.Contains(l.ByHand, "trash rm") {
			t.Errorf("%s (%s) is advised %q", l.Trash, l.State, l.ByHand)
		}
		got[l.State] = l.ByHand
	}
	if want := "rbd trash restore lv/0dd1"; got["untracked"] != want {
		t.Errorf("untracked by_hand %q, want %q", got["untracked"], want)
	}
	if want := "rbd trash ls --all --long lv; rbd info lv/unsettled-data"; got["settling"] != want {
		t.Errorf("settling by_hand %q, want %q (evidence %s)", got["settling"], want, row.Evidence)
	}
}
