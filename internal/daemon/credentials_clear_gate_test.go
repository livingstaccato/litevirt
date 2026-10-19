package daemon

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// TestWireCredentialsClearGate_TracksTheDurableLatch: the gate that empties the
// old secret columns follows the REAL durable latch of credentials_clear_v1,
// closed before and open after, and only together with the split gate. Every
// other test injects the gate directly, so this is the test that fails if the
// production wiring is deleted — an unwired gate is silent: it fails closed and
// looks exactly like a mid-roll.
//
// It also pins CredentialsClearLatchedOnDisk, the gate `lv user reset-admin`
// uses, so the CLI empties the old column exactly when the daemon would.
func TestWireCredentialsClearGate_TracksTheDurableLatch(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("init schema: %v", err)
	}
	if err := corrosion.RegisterHost(ctx, db, corrosion.HostRecord{
		Name: "host-a", Address: "10.0.0.1", State: "active", Role: "worker",
	}); err != nil {
		t.Fatalf("register host: %v", err)
	}

	dataDir := t.TempDir()
	checker := health.NewChecker("host-a", "/etc/litevirt/pki", db)
	checker.SetActivationMarker(health.ActivationMarkerBase(dataDir))
	checker.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return capabilities.Supported(), time.Time{}, nil
	})

	d := &Daemon{db: db, checker: checker, cfg: &Config{}}
	d.wireCorrosionGates() // the set the daemon wires, so a lost call fails here
	onDisk := CredentialsClearLatchedOnDisk(dataDir)

	if db.MayClearCredentialColumns() || onDisk() {
		t.Fatal("the credentials clear gate is open before credentials_clear_v1 has durably latched")
	}
	if !checker.Enforced(ctx, capabilities.CredentialsClearV1) || !checker.DurablyLatched(capabilities.CredentialsClearV1) {
		t.Fatal("credentials_clear_v1 did not latch durably with the only host advertising it; the rest is vacuous")
	}
	if db.MayClearCredentialColumns() {
		t.Error("the clear gate opened before credentials_split_v1 latched; a node must never empty " +
			"the column that is its only copy")
	}
	if !checker.Enforced(ctx, capabilities.CredentialsSplitV1) {
		t.Fatal("credentials_split_v1 did not latch; the rest is vacuous")
	}
	if !db.MayClearCredentialColumns() {
		t.Error("the daemon's credentials clear gate stayed closed after both tokens durably latched")
	}
	if !onDisk() {
		t.Error("CredentialsClearLatchedOnDisk does not see the marker the checker wrote; " +
			"`lv user reset-admin` would write the secret into the old column after the clear")
	}
}

// TestRunWiresEveryCredentialGate: the gate tests above call the wire
// functions directly, so they pass with the call deleted from Run. An unwired
// gate fails closed and looks exactly like a mid-roll. This pins the calls.
func TestRunWiresEveryCredentialGate(t *testing.T) {
	assertRunCalls(t, "wireCredentialsSplitGate", "wireCredentialsClearGate", "wireHostMembershipGate")
}

// assertRunCalls fails unless (*Daemon).Run calls each named method on d,
// directly or through another (*Daemon) method of daemon.go that Run reaches
// the same way (wireCorrosionGates wires several gates for Run and its test).
func assertRunCalls(t *testing.T, names ...string) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	bodies := map[string]*ast.BlockStmt{}
	for _, decl := range f.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Recv != nil && fn.Body != nil {
			bodies[fn.Name.Name] = fn.Body
		}
	}
	if bodies["Run"] == nil {
		t.Fatal("found no (*Daemon).Run in daemon.go")
	}
	called := map[string]bool{}
	queue := []string{"Run"}
	for len(queue) > 0 {
		body := bodies[queue[0]]
		queue = queue[1:]
		if body == nil {
			continue
		}
		ast.Inspect(body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "d" && !called[sel.Sel.Name] {
						called[sel.Sel.Name] = true
						queue = append(queue, sel.Sel.Name)
					}
				}
			}
			return true
		})
	}
	for _, n := range names {
		if !called[n] {
			t.Errorf("(*Daemon).Run does not call d.%s(); the gate it wires stays closed", n)
		}
	}
}

// TestRunNotesTheCredentialsBaselineBeforeReplication (re-review 2, N8): the
// credentials baseline is positive evidence only if it describes this node's
// database BEFORE anything replicated in. Run must record it after InitSchema
// and before the replicator and anti-entropy start; deleted, every legacy
// external user is refused after the upgrade, and moved later, a joiner could
// record rows it merely received.
func TestRunNotesTheCredentialsBaselineBeforeReplication(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	pos := map[string]token.Pos{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Run" || fn.Recv == nil || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			name := sel.Sel.Name
			switch name {
			case "InitSchema", "NoteCredentialsBaseline", "NewReplicator", "NewAntiEntropy":
				if _, seen := pos[name]; !seen {
					pos[name] = call.Pos()
				}
			}
			return true
		})
	}
	for _, n := range []string{"InitSchema", "NoteCredentialsBaseline", "NewReplicator", "NewAntiEntropy"} {
		if pos[n] == token.NoPos {
			t.Fatalf("(*Daemon).Run does not call %s", n)
		}
	}
	if !(pos["InitSchema"] < pos["NoteCredentialsBaseline"]) {
		t.Error("Run records the credentials baseline before InitSchema")
	}
	if !(pos["NoteCredentialsBaseline"] < pos["NewReplicator"] && pos["NoteCredentialsBaseline"] < pos["NewAntiEntropy"]) {
		t.Error("Run records the credentials baseline after replication or anti-entropy starts: a joiner " +
			"would record rows it merely received as its own")
	}
}
