package health

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
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

func settlePendingFor(t *testing.T, f *settleFixture) (settlePending, bool) {
	t.Helper()
	recs, err := newSettlePendingStore(f.dataDir).list()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range recs {
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
			rec := f.r.newSettlePending("vm-a", f.proof, f.cert, f.r.localVMIdentity("vm-a"))
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
	stale := f.r.newSettlePending("vm-a", f.proof, f.cert, f.r.localVMIdentity("vm-a"))
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

// A destroy that fails leaves no pending record: nothing was stopped.
//
// Mutation: keep the record on a failed destroy — red.
func TestSettle_AFailedDestroyLeavesNoPendingRecord(t *testing.T) {
	f := newSettleFixture(t)
	f.virt.FailDestroyDomain = func(string) error { return errors.New("injected destroy failure") }
	f.run()
	if _, ok := settlePendingFor(t, f); ok {
		t.Fatal("a failed destroy left a pending-settle record")
	}
	if n := settleAuditRows(t, f); n != 0 {
		t.Fatalf("partition.settle rows = %d for a destroy that failed", n)
	}
}
