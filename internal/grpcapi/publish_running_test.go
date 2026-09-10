package grpcapi

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// publishServer is a create-capable server holding one running VM at a known
// generation, which is the precondition every routed non-minting site shares.
func publishServer(t *testing.T) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s, fake := provableCreateServer(t)
	if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	fake.SetState("vm1", libvirtfake.StateRunning)
	return s, fake
}

// TestPersistVMState_RunningMarksBeforeItCommits.
//
// persistVMState is the funnel for the snapshot restore and both StartVM
// writes, so routing it covers three sites at once. Observed from inside the
// commit: the end state is identical either way, which is exactly why nothing
// would otherwise notice the ordering.
func TestPersistVMState_RunningMarksBeforeItCommits(t *testing.T) {
	s, fake := publishServer(t)
	ctx := adminCtx()

	// Move the row off "running" so the write under test is a real transition.
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	if err := health.WriteVMOwnerEpochMarker(s.dataDir, "vm1", 1); err != nil {
		t.Fatal(err)
	}

	obs := &stateObservingVirt{Fake: fake, ctx: ctx, db: s.db}
	s.virt = obs
	if err := s.persistVMState(ctx, "vm1", "running", "test", corrosion.OpVMState); err != nil {
		t.Fatalf("persistVMState: %v", err)
	}
	if !obs.called {
		t.Fatal("the marker write was never attempted, so this test proves nothing about ordering")
	}
	if obs.stateAtMark != "stopped" {
		t.Errorf("row was %q when the marker was written, want stopped — the row must not "+
			"say running before a marker names its generation", obs.stateAtMark)
	}
}

// TestPersistVMState_AStopIsNotGatedOnMarkers.
//
// classifyStop's vocabulary and the operator-stop path both reach here with a
// non-running state. Writing a RUNNING marker for them would be wrong twice
// over: it stamps a generation onto a runtime that is going away, and
// SetDomainOwnerEpoch sends LIVE|CONFIG for running, which libvirt rejects on an
// inactive domain — so the fatal ordering would DROP the stop sync and leave the
// row saying running for a VM that is down.
func TestPersistVMState_AStopIsNotGatedOnMarkers(t *testing.T) {
	s, fake := publishServer(t)
	ctx := adminCtx()

	obs := &stateObservingVirt{Fake: fake, ctx: ctx, db: s.db, failWith: errors.New("domain is not running")}
	s.virt = obs
	if err := s.persistVMState(ctx, "vm1", "stopped", "operator-stop", corrosion.OpVMState); err != nil {
		t.Fatalf("a stop must not be gated on a running-marker write: %v", err)
	}
	if obs.called {
		t.Error("a running marker was written for a stop")
	}
	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State != "stopped" {
		t.Errorf("state = %q, want stopped — the stop sync was dropped", row.State)
	}
}

// TestPersistVMState_AMarkerFailureDoesNotCommitRunning: before the commit,
// refusing costs only the caller's retry, so the evidence lands or nothing does.
func TestPersistVMState_AMarkerFailureDoesNotCommitRunning(t *testing.T) {
	s, fake := publishServer(t)
	ctx := adminCtx()
	if err := corrosion.UpdateVMState(ctx, s.db, "vm1", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	s.virt = &stateObservingVirt{Fake: fake, ctx: ctx, db: s.db, failWith: errors.New("libvirt is down")}

	if err := s.persistVMState(ctx, "vm1", "running", "test", corrosion.OpVMState); err == nil {
		t.Error("a marker failure must be returned, not swallowed")
	}
	row, err := corrosion.GetVM(ctx, s.db, "vm1")
	if err != nil || row == nil {
		t.Fatalf("GetVM = (%v, %v), want a row", row, err)
	}
	if row.State == "running" {
		t.Error("the row says running with no marker written; that publishes an unprovable VM")
	}
}

// TestVMEpochForPublish_RetriesATransientReadFailure.
//
// The state write persistVMState guards already retries 4 times, and its two
// running callers only log and continue. An unretried read in front of it would
// turn one transient store error into a DROPPED state write — a regression the
// old code did not have.
func TestReadEpochWithRetry_RetriesATransientReadFailure(t *testing.T) {
	calls := 0
	epoch, err := readEpochWithRetry(context.Background(), "vm1",
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

// TestVMEpochForPublish_AMissingRowDoesNotRetry: a successful read finding no
// row is an answer, not a transient failure. Retrying cannot conjure a row.
func TestReadEpochWithRetry_AMissingRowDoesNotRetry(t *testing.T) {
	calls := 0
	_, err := readEpochWithRetry(context.Background(), "gone",
		func(context.Context) (*corrosion.VMRecord, error) { calls++; return nil, nil })
	if err == nil {
		t.Error("a missing row must refuse the publish")
	}
	if calls != 1 {
		t.Errorf("read attempted %d time(s), want 1 — a definite answer must not be retried", calls)
	}
}

// stateObservingVirt records the persisted VM STATE at the instant the domain
// marker is written, so mark-before-commit can be asserted rather than inferred
// from an end state that is identical either way. A wrapper, not a flag on the
// fake, so the fake keeps the real client's contract.
type stateObservingVirt struct {
	*libvirtfake.Fake
	ctx         context.Context
	db          *corrosion.Client
	failWith    error
	called      bool
	stateAtMark string
}

func (v *stateObservingVirt) SetDomainOwnerEpoch(name string, epoch int64, running bool) error {
	v.called = true
	if row, err := corrosion.GetVM(v.ctx, v.db, name); err == nil && row != nil {
		v.stateAtMark = row.State
	}
	if v.failWith != nil {
		return v.failWith
	}
	return v.Fake.SetDomainOwnerEpoch(name, epoch, running)
}
