package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// invOp seeds one reservation-bearing operation: its header at headerEpoch with
// the given created_at, and the given steps at their epochs. Test fixture data.
func invOp(t *testing.T, c *Client, id string, kind OperationKind, resourceKind, resourceID, method string,
	headerEpoch int64, rv ReservationVector, createdAt string, steps map[int64][]string) {
	t.Helper()
	ctx := context.Background()
	enc, err := rv.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := InsertOperation(ctx, c, OperationRecord{
		ID: id, Method: method, ResourceKind: resourceKind, ResourceID: resourceID,
		OperationKind: string(kind), RequestHash: "h", ReservationJSON: enc, VMOwnerEpoch: headerEpoch,
	}); err != nil {
		t.Fatalf("InsertOperation %s: %v", id, err)
	}
	if err := c.Execute(ctx, `UPDATE operations SET created_at = ? WHERE id = ?`, createdAt, id); err != nil {
		t.Fatalf("set created_at: %v", err)
	}
	for epoch, names := range steps {
		for _, n := range names {
			if err := AppendOperationStep(ctx, c, OperationStepRecord{OperationID: id, OwnerEpoch: epoch, StepName: n}); err != nil {
				t.Fatalf("append %s@%d: %v", n, epoch, err)
			}
		}
	}
}

// invVM seeds a live VM row with an explicit owner epoch, incarnation stamp and
// barrier.
func invVM(t *testing.T, c *Client, name string, epoch int64, createdAt, activeOp string) {
	t.Helper()
	ctx := context.Background()
	if err := InsertVM(ctx, c, VMRecord{Name: name, HostName: "h1", State: "running", Spec: "{}"}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	if err := c.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ?, created_at = ?, active_operation_id = ? WHERE name = ?`,
		epoch, createdAt, activeOp, name); err != nil {
		t.Fatalf("set vm fields: %v", err)
	}
}

func ago(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

func agoNano(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339Nano) }

// leakSteps is the lab's leaked resize: admission at the header's epoch 0, the
// whole workload operation — through completed — at the VM's epoch 1.
func leakSteps() map[int64][]string {
	return map[int64][]string{
		0: {OpStepReserved, OpStepAdmitted},
		1: {OpStepPlanned, OpStepDesiredPersisted, OpStepConfigApplied, OpStepLiveApplied, OpStepObserved, OpStepCompleted},
	}
}

var leakVector = ReservationVector{TargetHost: "h1", TargetMemMiB: 512, Provisional: true}

func mustClassify(t *testing.T, c *Client, opID string) *HostReservationView {
	t.Helper()
	v, err := ClassifyReservation(context.Background(), c, opID)
	if err != nil {
		t.Fatalf("ClassifyReservation(%s): %v", opID, err)
	}
	if v == nil {
		t.Fatalf("ClassifyReservation(%s): not counted, want a counted reservation", opID)
	}
	return v
}

func TestClassify_LabLeakShapeIsTerminalPastHeader(t *testing.T) {
	c := testClient(t)
	ctx := context.Background()
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	invOp(t, c, "leak", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())

	if _, mem, err := HostReserved(ctx, c, "h1"); err != nil || mem != 512 {
		t.Fatalf("precondition: HostReserved(h1) mem = %d (err %v), want the leaked 512", mem, err)
	}
	v := mustClassify(t, c, "leak")
	if v.Class != ReservationTerminalPastHeader {
		t.Fatalf("lab leak shape classified %q (%s), want %q", v.Class, v.Detail, ReservationTerminalPastHeader)
	}
	if v.HeaderEpoch != 0 || v.LatestEpoch != 1 || v.LatestState != OpStepCompleted || !v.Admitted {
		t.Errorf("view: header %d latest %d state %q admitted %v, want 0, 1, completed, true",
			v.HeaderEpoch, v.LatestEpoch, v.LatestState, v.Admitted)
	}
}

func TestClassify_LatestEpochNonterminalIsNotReleasable(t *testing.T) {
	c := testClient(t)
	invVM(t, c, "vm1", 2, agoNano(48*time.Hour), "")
	// Completed at 1, then a takeover resumed it at 2.
	invOp(t, c, "resumed", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour),
		map[int64][]string{0: {OpStepReserved}, 1: {OpStepPlanned, OpStepCompleted}, 2: {OpStepPlanned}})
	if v := mustClassify(t, c, "resumed"); v.Class != ReservationNoRunningOperation {
		t.Fatalf("terminal at 1 but resumed at 2 classified %q (%s), want %q", v.Class, v.Detail, ReservationNoRunningOperation)
	}
}

func TestClassify_StaleLowerEpochTerminalIgnored(t *testing.T) {
	c := testClient(t)
	invVM(t, c, "vm1", 2, agoNano(48*time.Hour), "")
	// A stale owner's terminal at 1, under a header at 2 with nothing at 2 yet.
	invOp(t, c, "stale", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 2, leakVector, ago(time.Hour),
		map[int64][]string{1: {OpStepReserved, OpStepCompleted}})
	// The same with the header's own reserved step at 2.
	invOp(t, c, "stale2", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 2, leakVector, ago(time.Hour),
		map[int64][]string{1: {OpStepCompleted}, 2: {OpStepReserved}})
	for _, id := range []string{"stale", "stale2"} {
		if v := mustClassify(t, c, id); v.Class == ReservationTerminalPastHeader {
			t.Fatalf("%s: a terminal below the header epoch classified %q (%s)", id, v.Class, v.Detail)
		}
	}
}

func TestClassify_BarrierHeldIsInFlight(t *testing.T) {
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "leak")
	invOp(t, c, "leak", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())
	if v := mustClassify(t, c, "leak"); v.Class != ReservationInFlight {
		t.Fatalf("barrier-held op classified %q (%s), want %q", v.Class, v.Detail, ReservationInFlight)
	}
}

func TestClassify_SupersededAloneIsNotTerminal(t *testing.T) {
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	invOp(t, c, "sup", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour),
		map[int64][]string{0: {OpStepReserved}, 1: {OpStepSuperseded}})
	if v := mustClassify(t, c, "sup"); v.Class == ReservationTerminalPastHeader {
		t.Fatalf("superseded alone at the latest epoch classified %q", v.Class)
	}
}

func TestClassify_VMGone(t *testing.T) {
	steps := map[int64][]string{1: {OpStepReserved, OpStepAdmitted}}
	t.Run("tombstoned", func(t *testing.T) {
		c := testClient(t)
		invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
		if err := c.Execute(context.Background(), `UPDATE vms SET deleted_at = ? WHERE name = 'vm1'`, ago(time.Minute)); err != nil {
			t.Fatal(err)
		}
		invOp(t, c, "op", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, ago(time.Hour), steps)
		if v := mustClassify(t, c, "op"); v.Class != ReservationVMGone {
			t.Fatalf("tombstoned VM classified %q (%s), want %q", v.Class, v.Detail, ReservationVMGone)
		}
	})
	t.Run("recreated", func(t *testing.T) {
		c := testClient(t)
		invVM(t, c, "vm1", 1, agoNano(time.Minute), "")
		invOp(t, c, "op", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, ago(time.Hour), steps)
		if v := mustClassify(t, c, "op"); v.Class != ReservationVMGone {
			t.Fatalf("VM re-created after the op classified %q (%s), want %q", v.Class, v.Detail, ReservationVMGone)
		}
	})
	t.Run("same incarnation", func(t *testing.T) {
		c := testClient(t)
		invVM(t, c, "vm1", 1, agoNano(2*time.Hour), "")
		invOp(t, c, "op", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, ago(time.Hour), steps)
		if v := mustClassify(t, c, "op"); v.Class != ReservationNoRunningOperation {
			t.Fatalf("VM older than the op, no barrier, classified %q (%s), want %q", v.Class, v.Detail, ReservationNoRunningOperation)
		}
	})
	t.Run("same incarnation, admitting", func(t *testing.T) {
		c := testClient(t)
		invVM(t, c, "vm1", 1, agoNano(2*time.Hour), "")
		invOp(t, c, "op", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, ago(time.Minute), steps)
		if v := mustClassify(t, c, "op"); v.Class != ReservationAdmitting {
			t.Fatalf("a minute-old op with no barrier classified %q (%s), want %q", v.Class, v.Detail, ReservationAdmitting)
		}
	})
}

func TestClassify_CapacityLeaseNeverReleasable(t *testing.T) {
	c := testClient(t)
	invOp(t, c, "lease", OpResourceUpdateRunning, CapacityResourceKind, "", "CreateVM", 0, leakVector, ago(2*time.Hour), leakSteps())
	v := mustClassify(t, c, "lease")
	if v.Class != ReservationCapacityLease {
		t.Fatalf("capacity lease classified %q (%s), want %q", v.Class, v.Detail, ReservationCapacityLease)
	}
	if v.Class.Releasable() {
		t.Fatal("a capacity lease reported releasable")
	}
}

func TestClassify_ManifestKindsNeverReleasable(t *testing.T) {
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	for _, kind := range []OperationKind{OpVMReplace, OpDrainColdMove} {
		id := "m-" + string(kind)
		invOp(t, c, id, kind, "vm", "vm1", "x", 0, leakVector, ago(2*time.Hour), leakSteps())
		if v := mustClassify(t, c, id); v.Class != ReservationManifest {
			t.Fatalf("%s classified %q (%s), want %q", kind, v.Class, v.Detail, ReservationManifest)
		}
	}
}

func releaseRow(t *testing.T, c *Client, opID string, epoch int64) (facts, createdAt string) {
	t.Helper()
	rows, err := c.Query(context.Background(),
		`SELECT facts, created_at FROM operation_steps
		 WHERE operation_id = ? AND owner_epoch = ? AND step_name = 'cancelled' AND deleted_at IS NULL`, opID, epoch)
	if err != nil || len(rows) != 1 {
		t.Fatalf("release row of %s@%d: rows=%d err=%v, want one", opID, epoch, len(rows), err)
	}
	return rows[0].String("facts"), rows[0].String("created_at")
}

func TestReleaseReservation_RowIsDeterministicAcrossWriters(t *testing.T) {
	ctx := context.Background()
	a, b := testClient(t), testClient(t)
	created := "2026-10-11T08:00:00Z"
	invVM(t, a, "vm1", 1, agoNano(48*time.Hour), "")
	invOp(t, a, "leak", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, created, leakSteps())
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatalf("seed b: %v", err)
	}

	for name, c := range map[string]*Client{"a": a, "b": b} {
		if already, err := ReleaseReservation(ctx, c, "leak"); err != nil || already {
			t.Fatalf("release on %s: already=%v err=%v", name, already, err)
		}
		facts, createdAt := releaseRow(t, c, "leak", 0)
		if facts != ReservationReleasedFacts || createdAt != created {
			t.Fatalf("release row on %s: facts %q created_at %q, want %q and the header's %q",
				name, facts, createdAt, ReservationReleasedFacts, created)
		}
	}
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatalf("merge a into b: %v", err)
	}
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatalf("merge b into a: %v", err)
	}
	if na, nb := a.UnresolvedTieCount(), b.UnresolvedTieCount(); na != 0 || nb != 0 {
		t.Fatalf("two writers' release rows conflict: unresolved a=%d b=%d, want 0", na, nb)
	}
}

func TestReleaseReservation_ShapeIsLedgered(t *testing.T) {
	st := reservationReleaseStatement(OperationRecord{ID: "x", VMOwnerEpoch: 3, CreatedAt: "t"}, "n")
	fp, err := FingerprintSQL(st.SQL)
	if err != nil {
		t.Fatalf("FingerprintSQL: %v", err)
	}
	e, ok := LedgerLookup(fp)
	if !ok || !CurrentLedgerHas(fp) {
		t.Fatalf("release statement shape %s is not in the current ledger", fp)
	}
	if e.Table != "operation_steps" || e.Disposition != DispCustomMerge {
		t.Fatalf("release statement ledgered as %s/%v, want operation_steps/DispCustomMerge", e.Table, e.Disposition)
	}
	if st.Guard != nil {
		t.Fatal("release statement carries a replication guard; it must keep the unguarded wire shape")
	}
}

func TestReleaseReservation_OldReaderStopsCounting(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	invOp(t, c, "leak", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())
	if _, err := ReleaseReservation(ctx, c, "leak"); err != nil {
		t.Fatalf("ReleaseReservation: %v", err)
	}
	byID, _, err := nonterminalReservationsByID(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, counted := byID["leak"]; counted {
		t.Fatal("after its release the reservation is still counted by the unchanged aggregation scan")
	}
	if cpu, mem, err := HostReserved(ctx, c, "h1"); err != nil || cpu != 0 || mem != 0 {
		t.Fatalf("HostReserved(h1) after release = %d/%d (err %v), want 0/0", cpu, mem, err)
	}
	if v, err := ClassifyReservation(ctx, c, "leak"); err != nil || v != nil {
		t.Fatalf("ClassifyReservation after release = %+v (err %v), want nil", v, err)
	}
}

func TestReleaseReservation_Idempotent(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	invOp(t, c, "leak", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())
	if already, err := ReleaseReservation(ctx, c, "leak"); err != nil || already {
		t.Fatalf("first release: already=%v err=%v", already, err)
	}
	count := func() int {
		rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM operation_steps WHERE operation_id = 'leak'`)
		if err != nil {
			t.Fatal(err)
		}
		return rows[0].Int("n")
	}
	before := count()
	already, err := ReleaseReservation(ctx, c, "leak")
	if err != nil || !already {
		t.Fatalf("second release: already=%v err=%v, want already=true", already, err)
	}
	if after := count(); after != before {
		t.Fatalf("second release wrote rows: %d -> %d", before, after)
	}
}

func TestReleaseReservation_RefusesWhatIsNeverReleased(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	invVM(t, c, "busy", 1, agoNano(48*time.Hour), "held")
	invOp(t, c, "held", OpResourceUpdateRunning, "vm", "busy", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())
	invOp(t, c, "lease", OpResourceUpdateRunning, CapacityResourceKind, "", "CreateVM", 0, leakVector, ago(time.Hour), leakSteps())
	invOp(t, c, "manifest", OpVMReplace, "vm", "x", "x", 0, leakVector, ago(time.Hour), leakSteps())
	for _, tc := range []struct {
		id   string
		want error
	}{
		{"held", ErrReservationInFlight},
		{"lease", ErrReservationNotReleasable},
		{"manifest", ErrReservationNotReleasable},
		{"absent", ErrReservationNotFound},
	} {
		if _, err := ReleaseReservation(ctx, c, tc.id); !errors.Is(err, tc.want) {
			t.Errorf("ReleaseReservation(%s) = %v, want %v", tc.id, err, tc.want)
		}
		rows, err := c.Query(ctx, `SELECT 1 FROM operation_steps WHERE operation_id = ? AND facts = ?`, tc.id, ReservationReleasedFacts)
		if err != nil || len(rows) != 0 {
			t.Errorf("ReleaseReservation(%s) wrote a release row (rows=%d err=%v)", tc.id, len(rows), err)
		}
	}
}

func TestHostReservations_SumEqualsHostReserved(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	invVM(t, c, "wc", 1, agoNano(48*time.Hour), "")
	invOp(t, c, "resize", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())
	invOp(t, c, "lease", OpResourceUpdateRunning, CapacityResourceKind, "", "CreateVM", 0,
		ReservationVector{TargetHost: "h1", TargetCPU: 1, TargetMemMiB: 256}, ago(time.Minute), map[int64][]string{0: {OpStepReserved}})
	// A create at a non-zero epoch whose VM no longer names it: not counted.
	invOp(t, c, "unowned", OpWorkloadCreate, "vm", "wc", "CreateVM", 1,
		ReservationVector{TargetHost: "h1", TargetCPU: 4, TargetMemMiB: 1024}, ago(time.Hour), map[int64][]string{1: {OpStepPlanned}})
	invOp(t, c, "manifest", OpVMReplace, "vm", "vm1", "CutoverVM", 0,
		ReservationVector{TargetHost: "h1", TargetMemMiB: 128}, ago(time.Hour), map[int64][]string{0: {OpStepPlanned}})
	invOp(t, c, "other-host", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1,
		ReservationVector{TargetHost: "h2", TargetMemMiB: 64}, ago(time.Hour), map[int64][]string{1: {OpStepReserved}})

	views, err := HostReservations(ctx, c, "h1")
	if err != nil {
		t.Fatalf("HostReservations: %v", err)
	}
	var cpu, mem int
	for _, v := range views {
		cpu += v.Vector.TargetCPU
		mem += v.Vector.TargetMemMiB
	}
	wantCPU, wantMem, err := HostReserved(ctx, c, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if cpu != wantCPU || mem != wantMem || len(views) != 3 {
		t.Fatalf("HostReservations(h1) lists %d rows summing %d/%d, HostReserved says %d/%d (want 3 rows)",
			len(views), cpu, mem, wantCPU, wantMem)
	}
	all, err := HostReservations(ctx, c, "")
	if err != nil || len(all) != 4 {
		t.Fatalf("HostReservations(all) = %d rows (err %v), want 4", len(all), err)
	}
}

// A tombstoned (reaped) operation or step is gone: it neither holds a
// reservation nor counts as evidence that one finished.
func TestHostReservations_IgnoresTombstonedRows(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	// A reaped operation: header and steps tombstoned, nonterminal at its header.
	invOp(t, c, "reaped", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, ago(time.Hour),
		map[int64][]string{1: {OpStepReserved}})
	reapedAt := ago(time.Minute)
	if err := c.Execute(ctx, `UPDATE operations SET deleted_at = ? WHERE id = 'reaped'`, reapedAt); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, `UPDATE operation_steps SET deleted_at = ? WHERE operation_id = 'reaped'`, reapedAt); err != nil {
		t.Fatal(err)
	}
	// A live operation whose only terminal past its header is a tombstoned step.
	invOp(t, c, "live", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())
	if err := c.Execute(ctx, `UPDATE operation_steps SET deleted_at = ?
		WHERE operation_id = 'live' AND owner_epoch = 1 AND step_name = 'completed'`, reapedAt); err != nil {
		t.Fatal(err)
	}

	views, err := HostReservations(ctx, c, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if len(views) != 1 || views[0].Op.ID != "live" {
		t.Fatalf("HostReservations(h1) = %d rows, want only the live operation", len(views))
	}
	if v, err := ClassifyReservation(ctx, c, "reaped"); err != nil || v != nil {
		t.Fatalf("ClassifyReservation(reaped) = %+v (err %v), want nil", v, err)
	}
	if _, err := ReleaseReservation(ctx, c, "reaped"); !errors.Is(err, ErrReservationNotFound) {
		t.Fatalf("ReleaseReservation(reaped) = %v, want ErrReservationNotFound", err)
	}
	if v := mustClassify(t, c, "live"); v.Class == ReservationTerminalPastHeader || v.LatestState == OpStepCompleted {
		t.Fatalf("a tombstoned completed step was read as the operation's finish: %q at %d (%s)", v.LatestState, v.LatestEpoch, v.Class)
	}
}

// A container reservation is never released on terminal-past-header or
// vm-gone evidence (there is no VM row to be gone), and a containers barrier
// naming it makes it in flight — to the classifier and to the release guard.
func TestClassify_ContainerReservation(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	rv := ReservationVector{TargetHost: "h1", TargetMemMiB: 256, Workload: "ct1", WorkloadKind: WorkloadContainer, WorkloadHost: "h1"}
	steps := map[int64][]string{0: {OpStepPlanned, OpStepReserved}, 1: {OpStepCompleted}}
	invOp(t, c, "ct-held", OpWorkloadCreate, "container", "ct1", "CreateContainer", 0, rv, ago(time.Hour), steps)
	invOp(t, c, "ct-free", OpWorkloadCreate, "container", "ct2", "CreateContainer", 0, rv, ago(time.Hour), steps)
	now := ago(time.Hour)
	if err := c.Execute(ctx, `INSERT INTO containers (host_name, name, image, state, created_at, updated_at)
		VALUES ('h1', 'ct1', 'img', 'running', ?, ?)`, now, now); err != nil {
		t.Fatalf("seed container: %v", err)
	}
	if err := c.Execute(ctx, `UPDATE containers SET active_operation_id = 'ct-held' WHERE name = 'ct1'`); err != nil {
		t.Fatal(err)
	}

	if v := mustClassify(t, c, "ct-held"); v.Class != ReservationInFlight {
		t.Fatalf("container op under its barrier classified %q (%s), want %q", v.Class, v.Detail, ReservationInFlight)
	}
	if _, err := ReleaseReservation(ctx, c, "ct-held"); !errors.Is(err, ErrReservationInFlight) {
		t.Fatalf("ReleaseReservation(container op under its barrier) = %v, want ErrReservationInFlight", err)
	}
	if v := mustClassify(t, c, "ct-free"); v.Class != ReservationNoRunningOperation {
		t.Fatalf("container op with no barrier classified %q (%s), want %q (never vm_gone)", v.Class, v.Detail, ReservationNoRunningOperation)
	}
}

// A VM row created in the operation header's own second is the same
// incarnation, though its nanosecond stamp sorts after the header's.
func TestClassify_VMCreatedInTheOperationsSecondIsNotGone(t *testing.T) {
	c := testClient(t)
	sec := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	invVM(t, c, "vm1", 1, sec.Add(500*time.Millisecond).Format(time.RFC3339Nano), "")
	invOp(t, c, "op", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, sec.Format(time.RFC3339),
		map[int64][]string{1: {OpStepReserved, OpStepAdmitted}})
	if v := mustClassify(t, c, "op"); v.Class != ReservationNoRunningOperation {
		t.Fatalf("VM created in the op's own second classified %q (%s), want %q", v.Class, v.Detail, ReservationNoRunningOperation)
	}
}

// A tombstoned cancelled row at the release key, under a live header, cannot be
// written again. The release fails loudly (never "already released"), and the
// reservation is still counted and flagged as blocked.
func TestReleaseReservation_TombstonedReleaseRowBlocksTheRelease(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	invOp(t, c, "leak", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 0, leakVector, ago(time.Hour), leakSteps())
	if err := AppendOperationStep(ctx, c, OperationStepRecord{OperationID: "leak", StepName: OpStepCancelled, Facts: ReservationReleasedFacts}); err != nil {
		t.Fatal(err)
	}
	if err := c.Execute(ctx, `UPDATE operation_steps SET deleted_at = ?
		WHERE operation_id = 'leak' AND owner_epoch = 0 AND step_name = 'cancelled'`, ago(time.Minute)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		already, err := ReleaseReservation(ctx, c, "leak")
		if !errors.Is(err, ErrReservationReleaseBlocked) || already {
			t.Fatalf("release %d over a tombstoned release row: already=%v err=%v, want ErrReservationReleaseBlocked", i, already, err)
		}
		if !strings.Contains(err.Error(), "leak") || !strings.Contains(err.Error(), "still counted") ||
			!strings.Contains(err.Error(), "tombstoned") {
			t.Fatalf("blocked release error %q must name the operation, that it is still counted, and the tombstoned row", err)
		}
	}
	if _, mem, err := HostReserved(ctx, c, "h1"); err != nil || mem != 512 {
		t.Fatalf("HostReserved(h1) = %d MiB (err %v), want the still-counted 512", mem, err)
	}
	v := mustClassify(t, c, "leak")
	if !v.ReleaseBlocked || !strings.Contains(v.Detail, "release blocked") {
		t.Fatalf("view: ReleaseBlocked=%v detail %q, want the blocked release flagged", v.ReleaseBlocked, v.Detail)
	}
}

// HostReservations orders by the parsed instant: a whole-second header sorts
// before a nanosecond one later in the same second, though its string sorts
// after it, and an unparseable stamp sorts last.
func TestHostReservations_OrdersByInstant(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	invVM(t, c, "vm1", 1, agoNano(48*time.Hour), "")
	sec := time.Now().Add(-time.Hour).UTC().Truncate(time.Second)
	steps := map[int64][]string{1: {OpStepReserved}}
	invOp(t, c, "a-bad", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, "not-a-time", steps)
	invOp(t, c, "b-nano", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector,
		sec.Add(500*time.Millisecond).Format(time.RFC3339Nano), steps)
	invOp(t, c, "c-sec", OpResourceUpdateRunning, "vm", "vm1", "ResizeVMLive", 1, leakVector, sec.Format(time.RFC3339), steps)
	views, err := HostReservations(ctx, c, "h1")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range views {
		got = append(got, v.Op.ID)
	}
	if strings.Join(got, ",") != "c-sec,b-nano,a-bad" {
		t.Fatalf("HostReservations order = %v, want [c-sec b-nano a-bad]", got)
	}
}
