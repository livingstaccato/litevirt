package rolling

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/compose"
)

// Every strategy applies an update with the least destructive mechanism its
// change allows; only a recreate-class change goes through the strategy's
// replacement procedure.

var replacingStrategies = []string{"recreate", "stop-first", "rolling", "start-first", "all-at-once", "blue-green", "snapshot-and-replace"}

// A live or metadata change is applied to the VM; nothing is recreated,
// created or deleted.
func TestEveryStrategy_LiveChangeKeepsTheVM(t *testing.T) {
	for _, strategy := range replacingStrategies {
		for name, plan := range map[string]compose.ChangePlan{"live": livePlan(), "metadata": metaPlan()} {
			ops := &mockOps{}
			fn, _ := collect()
			if err := Run(context.Background(), ops, "s", []VMAction{act("web", strategy, plan)}, fn); err != nil {
				t.Fatalf("%s/%s: %v", strategy, name, err)
			}
			if len(ops.recreated)+len(ops.created)+len(ops.deleted)+len(ops.reconfigured) != 0 {
				t.Errorf("%s/%s: recreated=%v created=%v deleted=%v reconfigured=%v, want the VM kept", strategy, name,
					ops.recreated, ops.created, ops.deleted, ops.reconfigured)
			}
			if name == "live" && len(ops.resized) != 1 {
				t.Errorf("%s/live: resized=%v, want web resized live", strategy, ops.resized)
			}
			if name == "metadata" && len(ops.metadata["web"]) == 0 {
				t.Errorf("%s/metadata: no live metadata applied", strategy)
			}
		}
	}
}

// A restart-class change reconfigures and restarts the same VM.
func TestEveryStrategy_RestartChangeReconfiguresTheSameVM(t *testing.T) {
	for _, strategy := range replacingStrategies {
		ops := &mockOps{}
		fn, _ := collect()
		if err := Run(context.Background(), ops, "s", []VMAction{act("web", strategy, restartPlan())}, fn); err != nil {
			t.Fatalf("%s: %v", strategy, err)
		}
		if len(ops.reconfigured) != 1 || len(ops.recreated)+len(ops.created)+len(ops.deleted) != 0 {
			t.Errorf("%s: reconfigured=%v recreated=%v created=%v deleted=%v, want web reconfigured only", strategy,
				ops.reconfigured, ops.recreated, ops.created, ops.deleted)
		}
	}
}

// ForceRecreate sends an action through the strategy's replacement whatever
// its plan says.
func TestForceRecreate_Replaces(t *testing.T) {
	ops := &mockOps{}
	fn, _ := collect()
	a := act("web", "recreate", metaPlan())
	a.ForceRecreate = true
	if err := Run(context.Background(), ops, "s", []VMAction{a}, fn); err != nil {
		t.Fatal(err)
	}
	if len(ops.recreated) != 1 || len(ops.metadata) != 0 {
		t.Errorf("recreated=%v metadata=%v, want web recreated", ops.recreated, ops.metadata)
	}
}

// Repair sends a half-made VM through ReconfigureVM whatever its plan says,
// under every strategy that replaces VMs — never through a replacement.
func TestRepair_ReconfiguresNeverReplaces(t *testing.T) {
	for _, strategy := range replacingStrategies {
		ops := &mockOps{}
		fn, _ := collect()
		a := act("web", strategy, compose.ChangePlan{})
		a.Repair = true
		if err := Run(context.Background(), ops, "s", []VMAction{a}, fn); err != nil {
			t.Fatalf("%s: %v", strategy, err)
		}
		if len(ops.reconfigured) != 1 || len(ops.recreated)+len(ops.created)+len(ops.deleted) != 0 {
			t.Errorf("%s: reconfigured=%v recreated=%v created=%v deleted=%v, want web repaired only", strategy,
				ops.reconfigured, ops.recreated, ops.created, ops.deleted)
		}
	}
}

// in-place keeps refusing what it cannot do live, rather than restarting.
func TestInPlace_StillRefusesARestart(t *testing.T) {
	ops := &mockOps{}
	fn, _ := collect()
	if err := Run(context.Background(), ops, "s", []VMAction{act("web", "in-place", restartPlan())}, fn); err == nil {
		t.Fatal("in-place applied a restart-class change")
	}
	if len(ops.reconfigured) != 0 {
		t.Errorf("in-place reconfigured %v", ops.reconfigured)
	}
}
