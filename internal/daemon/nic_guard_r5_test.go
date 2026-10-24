package daemon

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestNICGuardLabel_TracksLiveEnforcement (re-review m5): the host's
// litevirt.nic-guards label carries this build's version only while its last
// firewall pass put the per-NIC table in force; a pass refused, failed or
// timed out clears it, and the next good pass sets it again.
func TestNICGuardLabel_TracksLiveEnforcement(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "h1", Address: "192.0.2.1", State: "active", Version: "v9"}); err != nil {
		t.Fatal(err)
	}
	label := func() string {
		t.Helper()
		h, err := corrosion.GetHost(ctx, db, "h1")
		if err != nil || h == nil {
			t.Fatalf("GetHost: %v", err)
		}
		return h.Labels[corrosion.LabelNICGuards]
	}
	hook := nicGuardLabelHook(db, "h1", "v9")
	for i, step := range []struct {
		enforcing bool
		want      string
	}{{false, ""}, {true, "v9"}, {false, ""}, {true, "v9"}} {
		hook(ctx, step.enforcing)
		if got := label(); got != step.want {
			t.Errorf("step %d (enforcing=%v): label = %q, want %q", i, step.enforcing, got, step.want)
		}
	}
	// A pass whose own context ran out (a boot pass past its budget) still
	// clears the label.
	hook(ctx, true)
	dead, cancel := context.WithCancel(ctx)
	cancel()
	hook(dead, false)
	if got := label(); got != "" {
		t.Errorf("after a timed-out pass: label = %q, want it cleared", got)
	}
}

// TestStartWaitPredicate (re-review concern 4): a start waits for the start
// guard only when its VM has a NIC guard on, or whether it has one cannot be
// read; a VM with none starts as on main.
func TestStartWaitPredicate(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	for _, vm := range []string{"plain", "guarded"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: vm, HostName: "h1", State: "stopped",
			Spec: `{"name":"` + vm + `","uuid":"u-` + vm + `"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "guarded", MAC: "52:54:00:00:05:09",
		Mode: corrosion.NICGuardOn, VMUUID: "u-guarded"}, "t"); err != nil {
		t.Fatal(err)
	}
	wait := startWaitNeeded(db, func(string) string { return "" }, func(context.Context, string) bool { return false })
	if wait("plain") {
		t.Error("an unguarded VM's start waits for the start guard")
	}
	if !wait("guarded") {
		t.Error("a guarded VM's start does not wait for the start guard")
	}
	if _, err := db.DB().ExecContext(ctx, `ALTER TABLE cluster_policies RENAME TO cluster_policies_r5`); err != nil {
		t.Fatal(err)
	}
	defer db.DB().ExecContext(ctx, `ALTER TABLE cluster_policies_r5 RENAME TO cluster_policies`) //nolint:errcheck
	if !wait("plain") {
		t.Error("a VM whose guard state cannot be read does not wait")
	}
}

// TestRun_LabelHookBeforeTheBootPass (re-review m5): the label follows every
// pass, the boot pass included, so the hook is wired before it.
func TestRun_LabelHookBeforeTheBootPass(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	first := map[string]token.Pos{}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "Run" || fd.Recv == nil {
			continue
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				var b bytes.Buffer
				_ = printer.Fprint(&b, fset, call.Fun)
				if _, seen := first[b.String()]; !seen {
					first[b.String()] = call.Pos()
				}
			}
			return true
		})
	}
	hook, ok1 := first["d.fwReconciler.SetPassHook"]
	boot, ok2 := first["bootFirewallPass"]
	if !ok1 || !ok2 || hook >= boot {
		t.Errorf("SetPassHook (%v) must be wired before bootFirewallPass (%v)", ok1, ok2)
	}
}

// TestStartWaitPredicate_CreatingIncarnation (lab 2, F-B): a start a create
// is making waits only for that create's own guards. A guard record another
// incarnation of the name left live, with no VM row, makes it wait only
// while no create names its incarnation.
func TestStartWaitPredicate_CreatingIncarnation(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.PutNICGuard(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards), corrosion.NICGuardRecord{VMName: "fc", MAC: "52:54:00:00:05:0a",
		Mode: corrosion.NICGuardOn, VMUUID: "u-old"}, "t"); err != nil {
		t.Fatal(err)
	}
	creating := ""
	wait := startWaitNeeded(db, func(string) string { return creating }, func(context.Context, string) bool { return false })
	if !wait("fc") {
		t.Error("with no create in flight, a stale record of the name is not waited for")
	}
	creating = "u-new"
	if wait("fc") {
		t.Error("a create's start waits for a record another incarnation left")
	}
}
