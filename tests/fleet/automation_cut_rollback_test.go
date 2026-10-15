package fleet

import (
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/corrosion"
	"testing"
)

// The callback is a tripwire that always refuses; it cannot mint completeness.
// Actual source history and standing are produced by the production engine.
func TestAutomationCutRejectsOversizedBeforeReducer(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	db := f.cluster.Nodes[0].DB
	cfg, err := corrosion.AdoptedVoterConfig(f.ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.SealVoterGeneration(f.ctx, cfg.Generation, "test"); err != nil {
		t.Fatal(err)
	}
	if err = localExec(f.ctx, db, `UPDATE local_voter_seals SET reason=CAST(zeroblob(4194304) AS TEXT)`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	_, err = db.FreezeAutomationCut(f.ctx, cfg.Generation, func(corrosion.AutomationProjection, contract.Decision) (corrosion.AutomationReduction, error) {
		calls++
		return corrosion.AutomationReduction{}, fmt.Errorf("reducer tripwire")
	})
	if err == nil || calls != 0 {
		t.Fatalf("oversized source reached reducer: calls=%d err=%v", calls, err)
	}
}

func TestAutomationCutLateFailureRollsBackReplay(t *testing.T) {
	f := NewAutomationFixture(t, 3)
	if _, err := f.Engine(0).Submit(f.ctx, f.Barrier(0, "rollback-barrier")); err != nil {
		t.Fatal(err)
	}
	db := f.cluster.Nodes[0].DB
	for _, q := range []string{`DELETE FROM local_automation_prefix`, `DELETE FROM local_automation_requests`, `UPDATE local_recovery_claims SET value_digest='corrupt' WHERE target_kind='automation' AND owner_epoch=2`} {
		if err := localExec(f.ctx, db, q); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := corrosion.AdoptedVoterConfig(f.ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.SealVoterGeneration(f.ctx, cfg.Generation, "test"); err != nil {
		t.Fatal(err)
	}
	if _, err = f.Engine(0).FreezeMembershipCut(f.ctx, cfg.Generation); err == nil {
		t.Fatal("corrupt acceptance produced cut")
	}
	for _, table := range []string{"local_automation_prefix", "local_automation_requests", "local_automation_cuts", "local_automation_cut_records"} {
		rows, err := db.Query(f.ctx, "SELECT count(*) AS n FROM "+table)
		if err != nil || rows[0].Int64("n") != 0 {
			t.Fatal("late failure retained partial repair/cut", table, err)
		}
	}
}
