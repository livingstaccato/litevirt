package health

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func settleAuditRows(t *testing.T, f *settleFixture) int {
	t.Helper()
	rows, err := f.db.Query(context.Background(),
		`SELECT id FROM audit_log WHERE action = 'partition.settle' AND target = 'vm-a'`)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func settleAuditDetail(t *testing.T, f *settleFixture) string {
	t.Helper()
	rows, err := f.db.Query(context.Background(),
		`SELECT detail FROM audit_log WHERE action = 'partition.settle' AND target = 'vm-a'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("partition.settle rows = %d (%v), want 1", len(rows), err)
	}
	return rows[0].String("detail")
}

func vmPending(t *testing.T, dataDir string) []settlePending {
	t.Helper()
	recs, err := newSettlePendingStore(dataDir).list(PauseKindVM)
	if err != nil {
		t.Fatal(err)
	}
	return recs
}

func settlePendingFor(t *testing.T, f *settleFixture) (settlePending, bool) {
	t.Helper()
	for _, r := range vmPending(t, f.dataDir) {
		if r.Name == "vm-a" {
			return r, true
		}
	}
	return settlePending{}, false
}

// settledRaised reports whether vm_settled was raised for proof-1. It may
// already be resolved: the leftover cleanup undefines the stopped copy, and
// resolveSettled then resolves it in the same pass.
func settledRaised(t *testing.T, f *settleFixture) bool {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(context.Background(), f.db, corrosion.PartitionPauseEvaluator,
		corrosion.CondVMSettled, "vm", "vm-a@node-a")
	if err != nil {
		t.Fatal(err)
	}
	return ok && c.ConfirmedAt != "" && strings.Contains(c.Evidence, `"proof":"proof-1"`)
}

// failFirst fails step's first n writes.
func failFirst(step string, n int) func(string) error {
	return func(s string) error {
		if s == step && n > 0 {
			n--
			return errors.New("injected " + s + " failure")
		}
		return nil
	}
}

// pendingFor is the record settleCertifiedMove would save for f's settle.
func (f *settleFixture) pendingFor(r *Reconciler) settlePending {
	local := r.localVMIdentity("vm-a")
	return r.settleRec().newPending(PauseKindVM, "vm-a", "stopped the local copy (test)", f.proof, f.cert,
		local.Incarnation, local.Epoch, local.Source)
}

// The destroy cannot be repeated, so an audit row that fails to write with it
// is written by the next pass, once.
//
// Mutations: settleCertifiedMove saves no pending record — the second pass
// writes nothing and this goes red; drop the retry call from selfFence — red.
func TestSettle_AFailedAuditRowIsWrittenOnTheNextPass(t *testing.T) {
	f := newSettleFixture(t)
	f.r.settleFault = failFirst("audit", 1)
	if st := f.run(); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-a is %s; a failed record write must not hold the destroy back", st)
	}
	if n := settleAuditRows(t, f); n != 0 {
		t.Fatalf("partition.settle rows = %d after a failed write, want 0", n)
	}
	if rec, ok := settlePendingFor(t, f); !ok || rec.Audited || !rec.Raised || rec.Phase != settlePhaseStopped {
		t.Fatalf("pending-settle record = (%+v, %v), want one stopped, raised, not audited", rec, ok)
	}

	ctx := context.Background()
	f.r.selfFence(ctx)
	if n := settleAuditRows(t, f); n != 1 {
		t.Fatalf("partition.settle rows = %d after the retry pass, want 1", n)
	}
	if strings.Contains(settleAuditDetail(t, f), "; found ") {
		t.Fatalf("a row for the settle's own destroy says the stop cause is unknown: %s", settleAuditDetail(t, f))
	}
	if _, ok := settlePendingFor(t, f); ok {
		t.Fatal("the pending-settle record outlived a complete record")
	}
	if _, ok, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a"); ok {
		t.Fatal("the pause record outlived the settled copy")
	}
	f.r.selfFence(ctx)
	if n := settleAuditRows(t, f); n != 1 {
		t.Fatalf("partition.settle rows = %d after a further pass, want still 1", n)
	}
}

// vm_settled that fails to raise is retried every pass until it is raised,
// and the audit row already written is not written again.
//
// Mutations: mark the condition raised whatever the upsert returned — red;
// rewrite the audit row on each retry under a fresh id — the row count goes red.
func TestSettle_AFailedVMSettledIsRetriedUntilRaised(t *testing.T) {
	f := newSettleFixture(t)
	f.r.settleFault = failFirst("raise", 2)
	f.run()
	ctx := context.Background()
	if settledRaised(t, f) {
		t.Fatal("vm_settled raised through an injected failure")
	}
	f.r.selfFence(ctx)
	if settledRaised(t, f) {
		t.Fatal("vm_settled raised through the second injected failure")
	}
	if _, ok := settlePendingFor(t, f); !ok {
		t.Fatal("the pending-settle record was dropped before vm_settled was raised")
	}
	f.r.selfFence(ctx)
	if !settledRaised(t, f) {
		t.Fatal("vm_settled not raised once the write succeeds")
	}
	if n := settleAuditRows(t, f); n != 1 {
		t.Fatalf("partition.settle rows = %d, want 1", n)
	}
	if _, ok := settlePendingFor(t, f); ok {
		t.Fatal("the pending-settle record outlived a complete record")
	}
}

// A daemon that dies between the destroy and the record leaves the pending
// record on disk; the next run's reconciler writes the record once — also
// when the audit row landed before the crash and only the progress save did
// not.
//
// Mutations: give the retry a fresh audit id — "audit landed" goes red with 2
// rows; drop the retry call — both go red.
func TestSettle_ARecordSurvivesACrashBetweenDestroyAndRecord(t *testing.T) {
	for _, tc := range []struct {
		name        string
		phase       string
		auditLanded bool
	}{
		{"crash before the stopped phase was saved", settlePhaseStopping, false},
		{"crash after the audit row landed", settlePhaseStopped, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			ctx := context.Background()
			rec := f.pendingFor(f.r)
			rec.Phase = tc.phase
			if err := newSettlePendingStore(f.dataDir).put(rec); err != nil {
				t.Fatal(err)
			}
			if err := f.virt.DestroyDomain("vm-a"); err != nil {
				t.Fatal(err)
			}
			f.virt.SetStateReason("vm-a", "destroyed")
			if tc.auditLanded {
				if err := auditSettle(ctx, f.db, "node-a", "vm-a", rec.Detail, rec.AuditID); err != nil {
					t.Fatal(err)
				}
			}

			// The restarted daemon's reconciler: nothing carried over but the
			// data dir and the database.
			r := NewReconciler("node-a", f.dataDir, f.db, f.virt)
			r.selfFence(ctx)
			r.selfFence(ctx)
			if n := settleAuditRows(t, f); n != 1 {
				t.Fatalf("partition.settle rows = %d after the restart, want 1", n)
			}
			if !settledRaised(t, f) {
				t.Fatal("vm_settled not raised after the restart")
			}
			if _, ok := settlePendingFor(t, f); ok {
				t.Fatal("the pending-settle record outlived a complete record")
			}
		})
	}
}

// A daemon that dies after saving the pending record but before the destroy
// leaves a live copy: the record is not a stop, so it is dropped and the
// settle decides again — one row, for the stop that did happen.
//
// Mutation: write the record of a stopping-phase entry whatever the runtime
// says — two rows, red.
func TestSettle_ARecordOfADestroyThatNeverHappenedIsDropped(t *testing.T) {
	f := newSettleFixture(t)
	stale := f.pendingFor(f.r)
	if err := newSettlePendingStore(f.dataDir).put(stale); err != nil {
		t.Fatal(err)
	}
	if st := f.run(); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-a is %s; the settle must still stop it", st)
	}
	if n := settleAuditRows(t, f); n != 1 {
		t.Fatalf("partition.settle rows = %d, want 1", n)
	}
	rows, err := f.db.Query(context.Background(), `SELECT id FROM audit_log WHERE id = ?`, stale.AuditID)
	if err != nil || len(rows) != 0 {
		t.Fatalf("the never-executed settle's row was written (%d, %v)", len(rows), err)
	}
	if _, ok := settlePendingFor(t, f); ok {
		t.Fatal("a pending-settle record remains")
	}
}

// overrideState reports a fixed runtime state for vm-a (states the fake
// cannot model: in transition, crashed with qemu kept, no state).
type overrideState struct {
	*libvirtfake.Fake
	st  lv.DomainStatus
	err error
}

func (o *overrideState) DomainStateReason(name string) (lv.DomainStatus, error) {
	if name != "vm-a" {
		return o.Fake.DomainStateReason(name)
	}
	return o.st, o.err
}

// A stopping-phase record completes only on positive proof the copy is shut
// off. A copy shutting down, crashed with its process kept, with no state,
// with a managed-save image, or whose state cannot be read keeps the record and
// writes nothing; once it is shut off (here by the guest), the record is
// written once, saying the stop cause is not known.
//
// Mutations: complete on anything not running/paused/pmsuspended — each
// unproven state writes a row early and goes red; drop the stop-cause note —
// the detail check goes red.
func TestSettle_APendingRecordWaitsForPositiveProofOfShutOff(t *testing.T) {
	for _, tc := range []struct {
		name string
		st   lv.DomainStatus
		err  error
	}{
		{"shutting down", lv.DomainStatus{State: "stopping", Reason: "shutting-down"}, nil},
		{"crashed with qemu kept", lv.DomainStatus{State: "error", Reason: "crashed"}, nil},
		{"no state", lv.DomainStatus{State: "unknown", Reason: "unknown"}, nil},
		{"managed save", lv.DomainStatus{State: "stopped", Reason: "saved"}, nil},
		{"state unreadable", lv.DomainStatus{State: "unknown", Reason: "unknown"}, errors.New("libvirt: timeout")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			ctx := context.Background()
			o := &overrideState{Fake: f.virt, st: tc.st, err: tc.err}
			r := NewReconciler("node-a", f.dataDir, f.db, o)
			rec := f.pendingFor(f.r)
			if err := newSettlePendingStore(f.dataDir).put(rec); err != nil {
				t.Fatal(err)
			}
			r.selfFence(ctx)
			r.selfFence(ctx)
			if n := settleAuditRows(t, f); n != 0 {
				t.Fatalf("partition.settle rows = %d with the copy %s/%s, want 0: nothing proves it stopped", n, tc.st.State, tc.st.Reason)
			}
			if _, ok := settlePendingFor(t, f); !ok {
				t.Fatal("the pending-settle record was dropped without proof either way")
			}
			o.st, o.err = lv.DomainStatus{State: "stopped", Reason: "guest-shutdown"}, nil
			r.selfFence(ctx)
			r.selfFence(ctx)
			if n := settleAuditRows(t, f); n != 1 {
				t.Fatalf("partition.settle rows = %d once the copy shut off, want 1", n)
			}
			if d := settleAuditDetail(t, f); !strings.Contains(d, "found shut off (reason guest-shutdown)") {
				t.Fatalf("detail %q does not say how the copy was found", d)
			}
			if _, ok := settlePendingFor(t, f); ok {
				t.Fatal("the pending-settle record outlived a complete record")
			}
		})
	}
}

// A destroy that returns an error keeps the stopping record: the destroy may
// have taken effect. If it did not (the copy is still live) the next pass
// drops the record and the settle decides again; if it did, the next pass
// writes the record.
//
// Mutations: drop the record on a destroy error — "took effect" goes red (no
// row ever); write the record of a failed destroy at once — "no effect" goes
// red.
func TestSettle_AFailedDestroyKeepsItsRecordForTheRuntimeToDecide(t *testing.T) {
	t.Run("no effect", func(t *testing.T) {
		f := newSettleFixture(t)
		f.virt.FailDestroyDomain = func(string) error { return errors.New("injected destroy failure") }
		f.run()
		if _, ok := settlePendingFor(t, f); !ok {
			t.Fatal("a failed destroy dropped its pending record")
		}
		if n := settleAuditRows(t, f); n != 0 {
			t.Fatalf("partition.settle rows = %d for a destroy that failed", n)
		}
		f.virt.FailDestroyDomain = nil
		if st := f.run(); st != libvirtfake.StateShutdown {
			t.Fatalf("vm-a is %s; the settle must stop it once the destroy works", st)
		}
		if n := settleAuditRows(t, f); n != 1 {
			t.Fatalf("partition.settle rows = %d, want 1", n)
		}
		if recs := vmPending(t, f.dataDir); len(recs) != 0 {
			t.Fatalf("pending records %+v remain", recs)
		}
	})
	t.Run("took effect", func(t *testing.T) {
		f := newSettleFixture(t)
		f.virt.FailDestroyDomain = func(name string) error {
			f.virt.SetState(name, libvirtfake.StateShutdown)
			f.virt.SetStateReason(name, "destroyed")
			return errors.New("injected: rpc timed out after the destroy")
		}
		f.run()
		if n := settleAuditRows(t, f); n != 0 {
			t.Fatalf("partition.settle rows = %d at once for a destroy that reported failure", n)
		}
		f.r.selfFence(context.Background())
		if n := settleAuditRows(t, f); n != 1 {
			t.Fatalf("partition.settle rows = %d after the next pass, want 1", n)
		}
		if recs := vmPending(t, f.dataDir); len(recs) != 0 {
			t.Fatalf("pending records %+v remain", recs)
		}
	})
}

// Records are kept per settle, not per name: two settles of one name whose
// records are both pending are both written. A record completing drops the
// pause record of the copy it settled, never a later pause of the same name.
//
// Mutations: key the file by name alone — the first record is overwritten and
// one row is written, red; drop the pause record whatever it describes — the
// later pause's record is gone, red.
func TestSettle_RecordsArePerSettleAndDropOnlyTheirOwnPause(t *testing.T) {
	f := newSettleFixture(t)
	ctx := context.Background()
	store := newSettlePendingStore(f.dataDir)
	first := f.pendingFor(f.r)
	first.Phase = settlePhaseStopped
	second := f.pendingFor(f.r)
	second.Phase = settlePhaseStopped
	second.LocalEpoch = first.LocalEpoch + 2
	for _, rec := range []settlePending{first, second} {
		if err := store.put(rec); err != nil {
			t.Fatal(err)
		}
	}
	if recs := vmPending(t, f.dataDir); len(recs) != 2 {
		t.Fatalf("pending records = %d, want 2", len(recs))
	}
	if err := f.virt.DestroyDomain("vm-a"); err != nil {
		t.Fatal(err)
	}
	f.virt.SetStateReason("vm-a", "crashed") // stays defined, not settled again
	// A later pause of the same name, at an epoch the first settle's copy
	// did not have: the first record must leave it.
	later, _, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a")
	later.OwnerEpoch = first.LocalEpoch + 1
	if err := newPauseStore(f.dataDir).put(later); err != nil {
		t.Fatal(err)
	}
	// Only the first completes this pass.
	r := NewReconciler("node-a", f.dataDir, f.db, f.virt)
	if err := store.remove(second); err != nil {
		t.Fatal(err)
	}
	r.selfFence(ctx)
	if _, ok, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a"); !ok {
		t.Fatal("a settle record dropped the pause record of a later pause")
	}
	if err := store.put(second); err != nil {
		t.Fatal(err)
	}
	later.OwnerEpoch = second.LocalEpoch
	if err := newPauseStore(f.dataDir).put(later); err != nil {
		t.Fatal(err)
	}
	r.selfFence(ctx)
	if n := settleAuditRows(t, f); n != 2 {
		t.Fatalf("partition.settle rows = %d for two settles, want 2", n)
	}
	if _, ok, _ := ReadPauseRecord(f.dataDir, PauseKindVM, "vm-a"); ok {
		t.Fatal("the settle record left the pause record of the copy it settled")
	}
}

// A record another host name wrote (this host was renamed) is not written in
// that name, and is reported at most once an hour.
//
// Mutation: report it on every pass — the logged time moves, red; write it
// anyway — a row appears, red.
func TestSettle_ARecordOfAnotherHostNameIsReportedNotWritten(t *testing.T) {
	f := newSettleFixture(t)
	ctx := context.Background()
	now := time.Unix(1_800_000_000, 0)
	r := NewReconciler("node-a", f.dataDir, f.db, f.virt)
	r.Now = func() time.Time { return now }
	rec := f.pendingFor(r)
	rec.Host, rec.Phase = "node-old", settlePhaseStopped
	if err := newSettlePendingStore(f.dataDir).put(rec); err != nil {
		t.Fatal(err)
	}
	r.selfFence(ctx)
	fn, _ := settlePendingFile(rec)
	first, ok := r.settleRec().foreignLogged.Load(fn)
	if !ok {
		t.Fatal("a record of another host name was not reported")
	}
	now = now.Add(10 * time.Minute)
	r.selfFence(ctx)
	if again, _ := r.settleRec().foreignLogged.Load(fn); again != first {
		t.Fatal("reported again within the hour")
	}
	now = now.Add(foreignRecordLogEvery)
	r.selfFence(ctx)
	if again, _ := r.settleRec().foreignLogged.Load(fn); again == first {
		t.Fatal("not reported again after the hour")
	}
	if n := settleAuditRows(t, f); n != 0 {
		t.Fatalf("partition.settle rows = %d for another host's record", n)
	}
	if _, ok := settlePendingFor(t, f); !ok {
		t.Fatal("another host's record was removed")
	}
}

// A record waiting on a copy that is neither live nor shut off says so, naming
// the copy and the state observed, once per interval rather than every pass.
//
// Mutations: never log the wait — red; log on every pass — the count goes red.
func TestSettle_AWaitingRecordIsReportedOncePerInterval(t *testing.T) {
	f := newSettleFixture(t)
	ctx := context.Background()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	now := time.Unix(1_800_000_000, 0)
	o := &overrideState{Fake: f.virt, st: lv.DomainStatus{State: "stopping", Reason: "shutting-down"}}
	r := NewReconciler("node-a", f.dataDir, f.db, o)
	r.Now = func() time.Time { return now }
	if err := newSettlePendingStore(f.dataDir).put(f.pendingFor(f.r)); err != nil {
		t.Fatal(err)
	}
	waits := func() int {
		n := 0
		for _, line := range strings.Split(buf.String(), "\n") {
			if strings.Contains(line, "wait until its copy is positively shut off") {
				if !strings.Contains(line, "name=vm-a") || !strings.Contains(line, "observed=stopping/shutting-down") {
					t.Fatalf("the wait line does not name the copy and its state: %s", line)
				}
				n++
			}
		}
		return n
	}
	r.selfFence(ctx)
	now = now.Add(time.Minute)
	r.selfFence(ctx)
	r.selfFence(ctx)
	if n := waits(); n != 1 {
		t.Fatalf("wait reported %d times within the interval, want 1", n)
	}
	now = now.Add(settleWaitLogEvery)
	r.selfFence(ctx)
	if n := waits(); n != 2 {
		t.Fatalf("wait reported %d times after the interval, want 2", n)
	}
}

// failSteps fails every write whose step fails reports true.
func failSteps(fails func(step string) bool) func(string) error {
	return func(s string) error {
		if fails(s) {
			return errors.New("injected " + s + " failure")
		}
		return nil
	}
}

// A stopping-phase record whose copy is proven shut off is a stop, whatever
// happens to the name next. Its writes fail; the copy then comes back live
// under the same name (an operator started it); the record is still written,
// once, by the next run — it is not taken for a stop that never happened.
//
// Mutations: retry no longer saves the stopped phase before the writes — the
// live copy drops the record, red; write it twice under fresh ids — the row
// count goes red.
func TestSettle_AProvenStopSurvivesFailedWritesAndALaterLiveCopy(t *testing.T) {
	f := newSettleFixture(t)
	ctx := context.Background()
	o := &overrideState{Fake: f.virt, st: lv.DomainStatus{State: "stopped", Reason: "guest-shutdown"}}
	r := NewReconciler("node-a", f.dataDir, f.db, o)
	failing := true
	r.settleFault = failSteps(func(string) bool { return failing })
	rec := f.pendingFor(f.r)
	if err := newSettlePendingStore(f.dataDir).put(rec); err != nil {
		t.Fatal(err)
	}
	r.selfFence(ctx)
	if n := settleAuditRows(t, f); n != 0 {
		t.Fatalf("partition.settle rows = %d through injected failures", n)
	}
	got, ok := settlePendingFor(t, f)
	if !ok || got.Phase != settlePhaseStopped {
		t.Fatalf("pending-settle record = (%+v, %v), want it saved in the stopped phase once its copy was proven shut off", got, ok)
	}

	// The name comes back live (the pass above may have cleaned up the
	// shut-off leftover, so it is defined again); the writes still fail.
	f.virt.SetState("vm-a", libvirtfake.StateRunning)
	o.st = lv.DomainStatus{State: RuntimeRunning, Reason: "booted"}
	r.selfFence(ctx)
	if _, ok := f.virt.RawState("vm-a"); !ok {
		t.Fatal("the live copy is not defined; the pass did not see it live")
	}
	if _, ok := settlePendingFor(t, f); !ok {
		t.Fatal("a proven stop's record was dropped because a later copy of the name is live")
	}

	// A restarted daemon whose writes succeed.
	failing = false
	r = NewReconciler("node-a", f.dataDir, f.db, o)
	r.selfFence(ctx)
	r.selfFence(ctx)
	if n := settleAuditRows(t, f); n != 1 {
		t.Fatalf("partition.settle rows = %d, want 1", n)
	}
	if d := settleAuditDetail(t, f); !strings.Contains(d, "found shut off (reason guest-shutdown)") {
		t.Fatalf("detail %q does not say how the copy was found", d)
	}
	if !settledRaised(t, f) {
		t.Fatal("vm_settled not raised")
	}
	if _, ok := settlePendingFor(t, f); ok {
		t.Fatal("the pending-settle record outlived a complete record")
	}
}

// A stopping-phase record that already wrote part of its record (an earlier
// build wrote it without saving the stopped phase) was proven stopped then: a
// live copy of the name now does not drop it. One that wrote nothing and
// whose copy is live never stopped it, and is dropped as before.
//
// Mutations: drop every stopping-phase record whose copy is live — "audited"
// goes red; complete every stopping-phase record — "never stopped" goes red.
func TestSettle_ALiveCopyDropsOnlyARecordThatNeverProvedAStop(t *testing.T) {
	for _, tc := range []struct {
		name    string
		audited bool
		kept    bool
	}{
		{"never stopped", false, false},
		{"audited", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			ctx := context.Background()
			o := &overrideState{Fake: f.virt, st: lv.DomainStatus{State: RuntimeRunning, Reason: "booted"}}
			r := NewReconciler("node-a", f.dataDir, f.db, o)
			rec := f.pendingFor(f.r)
			if tc.audited {
				if err := auditSettle(ctx, f.db, "node-a", "vm-a", rec.Detail, rec.AuditID); err != nil {
					t.Fatal(err)
				}
				rec.Audited = true
			}
			if err := newSettlePendingStore(f.dataDir).put(rec); err != nil {
				t.Fatal(err)
			}
			r.selfFence(ctx)
			want := 0
			if tc.kept {
				want = 1
			}
			if n := settleAuditRows(t, f); n != want {
				t.Fatalf("partition.settle rows = %d, want %d", n, want)
			}
			if got := settledRaised(t, f); got != tc.kept {
				t.Fatalf("vm_settled raised = %v, want %v", got, tc.kept)
			}
			if _, ok := settlePendingFor(t, f); ok {
				t.Fatal("the pending-settle record remains")
			}
		})
	}
}
