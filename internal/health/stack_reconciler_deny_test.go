package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// cr7 round 1, I1 backstop. A live stack whose file asks for the cluster
// default-deny gets it back within one reconcile pass when the cluster has
// no default row (its owner went down while this stack's deploy was in
// flight). An operator's explicit default-allow row is left alone.
//
// Mutation: drop the re-assert from reconcile — the cluster stays
// default-allow.
func TestStackReconciler_ReassertsADenyALiveStackAsksFor(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "c", State: "active",
		ComposeYAML: "name: c\nfirewall:\n  default-deny: true\n"}); err != nil {
		t.Fatal(err)
	}
	r := NewStackReconciler("node-0", db)
	r.SetCleaner(&recordingStackCleaner{})
	r.reconcile(ctx)
	d, err := corrosion.GetFirewallDefault(ctx, db, "cluster")
	if err != nil || d == nil || !d.DefaultDeny || d.StackName != "c" {
		t.Fatalf("cluster default after a reconcile pass = %+v (%v), want deny owned by c", d, err)
	}

	if err := corrosion.SetFirewallDefault(ctx, db, "cluster", false, ""); err != nil {
		t.Fatal(err)
	}
	r.reconcile(ctx)
	if d, _ := corrosion.GetFirewallDefault(ctx, db, "cluster"); d == nil || d.DefaultDeny {
		t.Errorf("cluster default after an operator turned it off and a reconcile pass = %+v, want the operator's allow kept", d)
	}
}

// cr7 round 2. The re-assert after a removal counts only stacks recorded
// after it, never a stack being deleted, and leaves an operator's allow row
// that predates the stack alone.
//
// Mutations: ignore the removal's time (the stale stack re-sets the deny);
// count deleting stacks (the stack mid-down re-sets it).
func TestStackReconciler_ReassertRespectsTheRemoval(t *testing.T) {
	ctx := context.Background()
	newDB := func() *corrosion.Client {
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		return db
	}
	pass := func(db *corrosion.Client) *corrosion.FirewallDefault {
		r := NewStackReconciler("node-0", db)
		r.SetCleaner(&recordingStackCleaner{})
		r.reconcile(ctx)
		d, err := corrosion.GetFirewallDefault(ctx, db, "cluster")
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	denyYAML := "name: s\nfirewall:\n  default-deny: true\n"

	t.Run("stack recorded before the removal", func(t *testing.T) {
		db := newDB()
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "s", State: "active", ComposeYAML: denyYAML}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.SetFirewallDefault(ctx, db, "cluster", true, "s"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.DeleteFirewallDefault(ctx, db, "cluster"); err != nil {
			t.Fatal(err)
		}
		if d := pass(db); d != nil {
			t.Errorf("cluster default = %+v, want none: s's record predates the removal", d)
		}
		// Recorded again after the removal, it asks anew.
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "s", State: "active", ComposeYAML: denyYAML}); err != nil {
			t.Fatal(err)
		}
		if d := pass(db); d == nil || !d.DefaultDeny || d.StackName != "s" {
			t.Errorf("cluster default = %+v, want deny owned by s", d)
		}
	})
	t.Run("stack being deleted", func(t *testing.T) {
		db := newDB()
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "s", State: "deleting", ComposeYAML: denyYAML}); err != nil {
			t.Fatal(err)
		}
		// The re-assert alone: a full pass would finish the stack's teardown
		// first and prove nothing.
		if err := corrosion.ReassertStackDefaultDeny(ctx, db, compose.StoredStackWants); err != nil {
			t.Fatal(err)
		}
		if d, _ := corrosion.GetFirewallDefault(ctx, db, "cluster"); d != nil && d.DefaultDeny {
			t.Errorf("cluster default = %+v, want none for a stack being deleted", d)
		}
	})
	t.Run("operator allow predates the stack", func(t *testing.T) {
		db := newDB()
		if err := corrosion.SetFirewallDefault(ctx, db, "cluster", false, ""); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.UpsertStack(ctx, db, corrosion.StackRecord{Name: "s", State: "active", ComposeYAML: denyYAML}); err != nil {
			t.Fatal(err)
		}
		if d := pass(db); d == nil || d.DefaultDeny {
			t.Errorf("cluster default = %+v, want the operator's allow kept", d)
		}
	})
}
