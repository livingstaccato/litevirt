package health

import (
	"context"
	"testing"

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
