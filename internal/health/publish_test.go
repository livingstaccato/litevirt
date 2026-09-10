package health

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestPublishVMRunning_MarksBeforeItCommits: for a NON-minting transition the
// markers must be on disk before the row says running.
//
// Observed from INSIDE commit, because the end state is identical either way —
// which is exactly why nothing local would otherwise notice the ordering.
func TestPublishVMRunning_MarksBeforeItCommits(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	var fileAtCommit, domAtCommit int64
	err := PublishVMRunning(context.Background(), fake, dir, "vm1", "running", 5,
		func(context.Context) error {
			fileAtCommit, _, _ = ReadVMOwnerEpochMarker(dir, "vm1")
			domAtCommit, _, _ = fake.GetDomainOwnerEpoch("vm1")
			return nil
		})
	if err != nil {
		t.Fatalf("PublishVMRunning: %v", err)
	}
	if fileAtCommit != 5 || domAtCommit != 5 {
		t.Errorf("markers at commit = file %d / domain %d, want 5/5 — a running row must never "+
			"exist without a marker naming its generation", fileAtCommit, domAtCommit)
	}
}

// TestPublishVMRunning_AMarkerFailureDoesNotCommit: before the commit, refusing
// costs only a retry, so the evidence is written first or not at all.
func TestPublishVMRunning_AMarkerFailureDoesNotCommit(t *testing.T) {
	fake := libvirtfake.New() // no domain, so SetDomainOwnerEpoch fails
	committed := false
	err := PublishVMRunning(context.Background(), fake, t.TempDir(), "vm1", "running", 5,
		func(context.Context) error { committed = true; return nil })
	if err == nil {
		t.Error("a marker failure must be returned, not swallowed")
	}
	if committed {
		t.Error("the state write ran with no marker written; that publishes an unprovable VM")
	}
}

// TestPublishVMRunning_APreEpochRowStillPublishes: a SUCCESSFUL read of 0 is a
// fact about a row the backfill has not graduated.
//
// Marking it would create the marker-against-an-epoch-0-row state convergence
// returns early on and never repairs. Refusing would strand every un-graduated
// VM on a fleet that has not enabled enforcement.owner_epoch, which is default.
func TestPublishVMRunning_APreEpochRowStillPublishes(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	committed := false
	if err := PublishVMRunning(context.Background(), fake, dir, "vm1", "running", 0,
		func(context.Context) error { committed = true; return nil }); err != nil {
		t.Fatalf("a pre-epoch row must still publish: %v", err)
	}
	if !committed {
		t.Error("the state write was skipped for a pre-epoch row")
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a marker was written for a pre-epoch row")
	}
}

// TestPublishVMRunning_ANilConcreteClientDoesNotPanic is the typed-nil trap.
//
// A nil *libvirtfake.Fake (or *lv.Client) passed as DomainEpochSetter is a
// NON-nil interface holding a nil pointer: a `virt != nil` guard passes and the
// method call then dereferences nil. VMChecker.virt is exactly that shape and is
// nil in ~70 tests, so this is the normal case, not a corner one.
func TestPublishVMRunning_ANilConcreteClientDoesNotPanic(t *testing.T) {
	var nilClient *libvirtfake.Fake // concrete nil; non-nil once boxed
	committed := false
	err := PublishVMRunning(context.Background(), nilClient, t.TempDir(), "vm1", "running", 5,
		func(context.Context) error { committed = true; return nil })
	if err != nil {
		t.Fatalf("a nil backend must skip the domain marker, not fail: %v", err)
	}
	if !committed {
		t.Error("a nil backend must not block the transition")
	}
}

// TestPublishVMRunning_ReturnsTheCommitError: the callback's error is the
// caller's to handle, unchanged.
func TestPublishVMRunning_ReturnsTheCommitError(t *testing.T) {
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	want := errors.New("state write refused")
	if got := PublishVMRunning(context.Background(), fake, t.TempDir(), "vm1", "running", 5,
		func(context.Context) error { return want }); !errors.Is(got, want) {
		t.Errorf("err = %v, want the commit's own error", got)
	}
}

// TestPublishVMRunning_SkipsTheFileMarkerWithoutADataDir matches readVMMarker's
// treatment of an empty dataDir, so no marker lands on a path no reader resolves.
func TestPublishVMRunning_SkipsTheFileMarkerWithoutADataDir(t *testing.T) {
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	t.Chdir(t.TempDir())
	if err := PublishVMRunning(context.Background(), fake, "", "vm1", "running", 5,
		func(context.Context) error { return nil }); err != nil {
		t.Fatalf("PublishVMRunning: %v", err)
	}
	if _, err := os.Stat(filepath.Join("vms", "vm1", "owner_epoch")); err == nil {
		t.Error("a marker was written to a relative path")
	}
}

// TestPublishVMRunningMinted_MarksTheEpochTheCommitProduced is the finding that
// forced two orderings.
//
// TransferVMOwner sets state='running' AND vm_owner_epoch = vm_owner_epoch + 1
// in one statement. Marking before it stamps the SUPERSEDED generation — the
// exact marker/row disagreement condition 7 reports. The marker must name what
// the commit produced, so it is written after.
func TestPublishVMRunningMinted_MarksTheEpochTheCommitProduced(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 6 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	if err := PublishVMRunningMinted(ctx, fake, db, dir, "node-a", "vm1", func(ctx context.Context) error {
		return corrosion.TransferVMOwner(ctx, db, "vm1", "node-a", "running", 6)
	}); err != nil {
		t.Fatalf("PublishVMRunningMinted: %v", err)
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.OwnerEpoch != 7 {
		t.Fatalf("row epoch = %d, want 7 (the transfer mints)", row.OwnerEpoch)
	}
	epoch, ok, err := ReadVMOwnerEpochMarker(dir, "vm1")
	if err != nil || !ok || epoch != 7 {
		t.Errorf("file marker = (%d,%v,%v), want (7,true,nil) — marking before a minting commit "+
			"names the generation the row just left", epoch, ok, err)
	}
	if e, ok, _ := fake.GetDomainOwnerEpoch("vm1"); !ok || e != 7 {
		t.Errorf("domain marker = (%d,%v), want (7,true)", e, ok)
	}
}

// TestPublishVMRunningMinted_AFailedCommitMarksNothing
func TestPublishVMRunningMinted_AFailedCommitMarksNothing(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	want := errors.New("mint refused")
	if got := PublishVMRunningMinted(ctx, fake, db, dir, "node-a", "vm1",
		func(context.Context) error { return want }); !errors.Is(got, want) {
		t.Errorf("err = %v, want the commit's error", got)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a marker was written although the minting commit failed")
	}
}

// TestPublishVMRunningMinted_AMarkerFailureIsNotFatal is the opposite of the
// non-minting contract, deliberately.
//
// The commit has landed and the guest is running, so refusing undoes nothing —
// and a positive epoch with a missing marker is precisely
// convergeOwnerEpochMarker's repair case, whose call site fires for any
// confirmed-running VM regardless of the enforcement flag.
func TestPublishVMRunningMinted_AMarkerFailureIsNotFatal(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node-a"); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New() // NO domain, so the domain marker write fails

	if err := PublishVMRunningMinted(ctx, fake, db, t.TempDir(), "node-a", "vm1",
		func(ctx context.Context) error {
			return corrosion.UpdateVMState(ctx, db, "vm1", "running", "test")
		}); err != nil {
		t.Errorf("a marker failure after a landed commit must not be reported as failure "+
			"(convergence repairs it): %v", err)
	}
	row, err := corrosion.GetVM(ctx, db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "running" {
		t.Errorf("state = %q, want running — the commit had already landed", row.State)
	}
}

// TestPublishVMRunningMinted_AnEpochReadFailureIsReported: after a landed
// commit, a failed read-back cannot be silently treated as "pre-epoch, skip".
func TestPublishVMRunningMinted_AnEpochReadFailureIsReported(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)
	err := PublishVMRunningMinted(ctx, fake, db, t.TempDir(), "node-a", "vm1",
		func(context.Context) error { db.Close(); return nil })
	if err == nil {
		t.Error("a read-back failure must be reported, not swallowed into a skipped marker")
	}
}

// TestPublishVMRunning_ANonRunningStateWritesNoMarkers is the state gate.
//
// Several routed sites write a state that is dynamic at the call but provably
// never "running" — classifyStop's output, a drift heal toward libvirt — and one
// is genuinely either. Without the gate a uniform wrap stamps a RUNNING marker
// (and a LIVE domain write, which libvirt rejects on an inactive domain) on an
// out-of-band STOP, and PublishVMRunning's fatal contract then drops the stop
// sync entirely: the row stays "running" for a VM that is down.
func TestPublishVMRunning_ANonRunningStateWritesNoMarkers(t *testing.T) {
	dir := t.TempDir()
	fake := libvirtfake.New() // no domain: a marker write would fail
	committed := false
	if err := PublishVMRunning(context.Background(), fake, dir, "vm1", "stopped", 5,
		func(context.Context) error { committed = true; return nil }); err != nil {
		t.Fatalf("a non-running publish must not be gated on markers: %v", err)
	}
	if !committed {
		t.Error("the stop sync was dropped because a running-marker write failed")
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Error("a running marker was written for a stopped publish")
	}
}

// TestPublishVMRunningMinted_OwnershipMovedLeavesTheMarkersAlone.
//
// A second ownership transition landing between our commit and our read-back
// hands us the NEXT owner's generation. Stamping our own runtime with it makes a
// superseded runtime look current — the one direction of this race that is not
// fail-safe, because runtimeSuperseded then sees a marker that agrees with the
// row and declines to refuse a runtime it should have refused.
func TestPublishVMRunningMinted_OwnershipMovedLeavesTheMarkersAlone(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "node-a", Spec: "{}", State: "stopped",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := corrosion.BackfillOwnerEpochs(ctx, db, "node-a"); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fake.SetState("vm1", libvirtfake.StateRunning)

	// We are node-a. Our commit lands, then node-b takes the VM before our
	// read-back — so the row we read names node-b's generation, not ours.
	err := PublishVMRunningMinted(ctx, fake, db, dir, "node-a", "vm1",
		func(ctx context.Context) error {
			if cerr := corrosion.UpdateVMState(ctx, db, "vm1", "running", "ours"); cerr != nil {
				return cerr
			}
			return corrosion.TransferVMOwnerFresh(ctx, db, "vm1", "node-b", "running")
		})
	if err != nil {
		t.Fatalf("PublishVMRunningMinted: %v", err)
	}
	row, gerr := corrosion.GetVM(ctx, db, "vm1")
	if gerr != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, gerr)
	}
	if row.HostName != "node-b" {
		t.Fatalf("owner = %q, want node-b — the test did not reproduce the race", row.HostName)
	}
	if _, ok, _ := ReadVMOwnerEpochMarker(dir, "vm1"); ok {
		t.Errorf("node-a stamped its own runtime with node-b's generation %d; a superseded "+
			"runtime must not be made to look current", row.OwnerEpoch)
	}
	if _, ok, _ := fake.GetDomainOwnerEpoch("vm1"); ok {
		t.Error("the domain marker was stamped with the new owner's generation")
	}
}

// TestEpochForPublish_RetriesATransientReadFailure.
//
// The state write persistVMState guards already retries 4 times, and its two
// running callers only log and continue. An unretried read in front of it would
// turn one transient store error into a DROPPED state write — a regression the
// old code did not have.
func TestEpochForPublish_RetriesATransientReadFailure(t *testing.T) {
	calls := 0
	epoch, err := epochForPublish(context.Background(), "vm1",
		func(context.Context) (*corrosion.VMRecord, error) {
			calls++
			if calls == 1 {
				return nil, errors.New("database is locked")
			}
			return &corrosion.VMRecord{Name: "vm1", OwnerEpoch: 4}, nil
		})
	if err != nil {
		t.Fatalf("a transient read failure must be retried, not fatal: %v", err)
	}
	if epoch != 4 {
		t.Errorf("epoch = %d, want 4", epoch)
	}
	if calls != 2 {
		t.Errorf("read attempted %d time(s), want 2 — the retry never happened", calls)
	}
}

// TestEpochForPublish_AMissingRowDoesNotRetry: a successful read finding no
// row is an answer, not a transient failure. Retrying cannot conjure a row.
func TestEpochForPublish_AMissingRowDoesNotRetry(t *testing.T) {
	calls := 0
	_, err := epochForPublish(context.Background(), "gone",
		func(context.Context) (*corrosion.VMRecord, error) { calls++; return nil, nil })
	if err == nil {
		t.Error("a missing row must refuse the publish")
	}
	if calls != 1 {
		t.Errorf("read attempted %d time(s), want 1 — a definite answer must not be retried", calls)
	}
}
