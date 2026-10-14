package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A DecisionPolicy reads the failover scope once: every quorum question of
// one decision is answered against the same policy, and the read is not
// repeated per question.
//
// Mutation: read the scope on every call — the second call sees region.
func TestDecisionPolicy_ReadsTheScopeOnce(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	pol := NewDecisionPolicy(db)
	first, err := pol.Scope(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if first.Region() {
		t.Fatal("setup: a new cluster is already region-scoped")
	}
	if err := corrosion.SetFailoverScope(ctx, db, corrosion.FailoverScopeRegion, "test"); err != nil {
		t.Fatal(err)
	}
	if again, err := pol.Scope(ctx); err != nil || again.Region() {
		t.Fatalf("the policy re-read the scope within one decision: %+v, %v", again, err)
	}
	if fresh, err := NewDecisionPolicy(db).Scope(ctx); err != nil || !fresh.Region() {
		t.Fatalf("setup: the scope change did not land: %+v, %v", fresh, err)
	}
}
