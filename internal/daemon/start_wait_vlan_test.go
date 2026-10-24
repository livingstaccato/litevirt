package daemon

import (
	"bytes"
	"context"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// A start of a VM with a trunk NIC waits for the start guard, NIC guard or
// not: the guard is what puts its VLANs on its taps before the guest runs,
// and an access NIC started without it runs on VLAN 1 (after a host boot, an
// onboot start can come before the guard is wired). A VM with neither a guard
// nor a trunk starts as before. The daemon's wiring of the predicate is the
// server's HasTapVLANs, or grpcapi.VMHasTapVLANs before the server is up;
// this is the latter, over the rows.
//
// Mutation: drop the vlans term from startWaitNeeded — red.
func TestStartWaitPredicate_TapVLANsWait(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatal(err)
	}
	db.SetClusterPolicyGate(func() bool { return true })
	for name, spec := range map[string]string{
		"plain":  `{"name":"plain","network":[{"name":"net0"}]}`,
		"access": `{"name":"access","network":[{"name":"net0","trunk":[30]}]}`,
		"trunk":  `{"name":"trunk","network":[{"name":"net0","trunk":[100,101]}]}`,
	} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: name, HostName: "h1", State: "stopped", Spec: spec}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	wait := startWaitNeeded(db, func(string) string { return "" }, func(ctx context.Context, name string) bool {
		return grpcapi.VMHasTapVLANs(ctx, db, name)
	})
	if wait("plain") {
		t.Error("a VM with no NIC guard and no trunk waits for the start guard")
	}
	for _, vm := range []string{"access", "trunk"} {
		if !wait(vm) {
			t.Errorf("%s: a VM with a trunk NIC starts without the start guard, so its VLANs are never put on its tap", vm)
		}
	}
	if wait("absent") {
		t.Error("a domain with no VM row waits")
	}
}

// NB-R1: the sweep that finishes starts an earlier run left paused runs after
// the start guard is wired and the first firewall pass, and before any start
// source (the health checker, the reconciler, onboot) or the gRPC server: no
// start of this run can be in its paused window while it looks.
//
// Mutation: move ResumeStrandedStarts after vmChecker.Start — red.
func TestRun_StrandedStartSweepBeforeAnyStartSource(t *testing.T) {
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
	sweep, ok := first["svc.ResumeStrandedStarts"]
	if !ok {
		t.Fatal("Run does not call svc.ResumeStrandedStarts")
	}
	for _, before := range []string{"d.virt.SetStartGuard", "bootFirewallPass"} {
		if at, ok := first[before]; !ok || at > sweep {
			t.Errorf("%s must come before the sweep", before)
		}
	}
	for _, after := range []string{"vmChecker.Start", "d.grpcSrv.Serve", "svc.RunHeldGuestResumer"} {
		if at, ok := first[after]; !ok || at < sweep {
			t.Errorf("%s (found %v) must come after the sweep", after, ok)
		}
	}
}
