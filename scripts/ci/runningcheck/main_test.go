package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// scanSrc runs the checker over one in-memory file.
func scanSrc(t *testing.T, src string) []violation {
	t.Helper()
	path := filepath.Join(t.TempDir(), "x.go")
	if err := os.WriteFile(path, []byte("package p\n"+src), 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := scanFile(path)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	return vs
}

func wantNone(t *testing.T, src, why string) {
	t.Helper()
	if vs := scanSrc(t, src); len(vs) != 0 {
		t.Errorf("%s: got %d violation(s), want 0:\n  %s", why, len(vs), vs[0].msg)
	}
}

func wantOne(t *testing.T, src, substr, why string) {
	t.Helper()
	vs := scanSrc(t, src)
	if len(vs) != 1 {
		t.Fatalf("%s: got %d violation(s), want 1", why, len(vs))
	}
	if !strings.Contains(vs[0].msg, substr) {
		t.Errorf("%s: message = %q, want it to mention %q", why, vs[0].msg, substr)
	}
}

// TestUnroutedRunningWriteIsFlagged is the rule the guard exists for.
func TestUnroutedRunningWriteIsFlagged(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", "running", "detail")
}`, "not routed", "a bare running write")
}

// TestRoutedRunningWriteIsAccepted: the shape the codebase actually uses.
func TestRoutedRunningWriteIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	s.publishRunning(ctx, name, state, func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", "running", "detail")
	})
}`, "an inline routed closure")
}

// TestLiteralNonRunningStateIsExempt: a write that can only ever publish a
// stopped VM has no runtime to prove.
func TestLiteralNonRunningStateIsExempt(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", "stopped", "operator-stop")
}`, "a literal stopped write")
}

// TestDynamicStateIsNotExempt: a state only known at runtime may be "running",
// so it must be routed. The helper's own state gate makes a uniform wrap correct.
func TestDynamicStateIsNotExempt(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", live, "detail")
}`, "not routed", "a runtime-determined state")
}

// TestMintingThroughThePlainHelperIsAFamilyMismatch is the bypass an earlier
// guard rule allowed: routing IS present, so a rule that only asks "is this
// inside a routed closure" passes it — while the mark-then-commit ordering
// stamps the generation the transfer is about to leave.
func TestMintingThroughThePlainHelperIsAFamilyMismatch(t *testing.T) {
	wantOne(t, `
func f() {
	s.publishRunning(ctx, name, state, func(ctx context.Context) error {
		return corrosion.TransferVMOwner(ctx, db, "vm1", "host-a", "running", 3)
	})
}`, "MINTING write routed through", "a minting write in a plain helper")
}

// TestMintingThroughTheMintedHelperIsAccepted.
func TestMintingThroughTheMintedHelperIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	s.publishRunningMinted(ctx, name, func(ctx context.Context) error {
		return corrosion.TransferVMOwner(ctx, db, "vm1", "host-a", "running", 3)
	})
}`, "a minting write in the minted helper")
}

// TestMintingHandoffOfAStoppedVMIsExempt: a transfer that hands over a stopped
// VM publishes no runtime, so there is nothing to mark.
func TestMintingHandoffOfAStoppedVMIsExempt(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.TransferVMOwnerFresh(ctx, db, "vm1", "host-b", "stopped")
}`, "a stopped handoff")
}

// TestDirectClosureInvocationIsFlagged is the second bypass an earlier rule
// allowed: the closure IS passed to a helper, so a lexical "is it routed" test
// passes — while the unconditional direct call publishes unmarked anyway.
func TestDirectClosureInvocationIsFlagged(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	commit(ctx)
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "an unconditional direct invocation")
}

// TestDirectClosureInvocationUnderAProvenBranchIsAccepted: the shape a router
// legitimately uses to skip the row read for a non-running write.
func TestDirectClosureInvocationUnderAProvenBranchIsAccepted(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state != "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "a direct invocation under a proven branch")
}

// TestBornRunningInsertNeedsGraduation is the third bypass: an earlier rule
// matched only a literal State: "running", so a dynamic state — which is what
// the clone path actually writes — sailed past it.
func TestBornRunningInsertNeedsGraduation(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.InsertVMWithHardware(ctx, db, corrosion.VMRecord{
		Name: "vm1", State: state,
	}, nil, nil, nil, nil, false)
}`, "born at", "a dynamic born-running insert")
}

// TestBornRunningInsertWithGraduationIsAccepted.
func TestBornRunningInsertWithGraduationIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.InsertVMWithHardware(ctx, db, corrosion.VMRecord{
		Name: "vm1", State: "running",
	}, nil, nil, nil, nil, false)
	s.assignOwnerEpochAtCreate(ctx, "vm1")
}`, "a graduated born-running insert")
}

// TestStoppedInsertNeedsNoGraduation: a stopped row has no runtime to prove,
// and stamping a generation it did not earn would make the row and the marker
// disagree the moment whatever starts it mints one.
func TestStoppedInsertNeedsNoGraduation(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", State: "stopped",
	}, nil, nil)
}`, "a stopped insert")
}

// TestAllowDirectiveSuppresses, in both placements: trailing on the statement,
// and as a reason block directly above it.
func TestAllowDirectiveSuppresses(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.UpdateVMState(ctx, db, "vm1", "running", "d") //runningcheck:allow handoff
}`, "a trailing directive")

	wantNone(t, `
func f() {
	//runningcheck:allow ownership handoff — the publishing host is not the running host,
	// and its domain has already been undefined by the migration.
	corrosion.UpdateVMState(ctx, db, "vm1", "running", "d")
}`, "a directive block above the statement")
}

// TestUpdateVMHostRunningIsFlagged: UpdateVMHost(ctx, c, name, host, state)
// takes its state at index 4 and writes `UPDATE vms SET host_name = ?, state = ?`.
// It was registered with index -1 under a comment claiming the state travelled
// inside a VMRecord, which made it unconditionally exempt — a hole in the guard
// exactly where a same-host re-point would publish running unmarked.
func TestUpdateVMHostRunningIsFlagged(t *testing.T) {
	wantOne(t, `
func f() {
	corrosion.UpdateVMHost(ctx, db, "vm1", "host-a", "running")
}`, "not routed", "a bare UpdateVMHost running write")
}

// TestUpdateVMHostStoppedIsExempt: the literal exemption does the work now that
// the index is real.
func TestUpdateVMHostStoppedIsExempt(t *testing.T) {
	wantNone(t, `
func f() {
	corrosion.UpdateVMHost(ctx, db, "vm1", "host-a", "stopped")
}`, "a stopped UpdateVMHost")
}

// TestClientMethodWriterIsSeen: a writer reached as a METHOD on the corrosion
// client is invisible to a selector test keyed on the package identifier.
// CommitVMCreateOperation's statement is a literal UPDATE vms SET state='running'.
func TestClientMethodWriterIsSeen(t *testing.T) {
	wantOne(t, `
func f() {
	s.db.CommitVMCreateOperation(ctx, "op1", 1, corrosion.VMRecord{
		Name: "vm1", State: "running",
	}, nil, nil, nil, nil)
}`, "born at", "a client-method born-running commit")
}

// TestDisjunctiveConditionDoesNotProveNonRunning is the bypass an OR-as-AND
// reading let through: `state != "running" || force` is entered with state ==
// "running" whenever force is true.
func TestDisjunctiveConditionDoesNotProveNonRunning(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state != "running" || force {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "a disjunctive guard")
}

// TestConjunctiveConditionStillProvesNonRunning: either conjunct proving it is
// enough, because both must hold to enter the branch.
func TestConjunctiveConditionStillProvesNonRunning(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state != "running" && ready {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "a conjunctive guard")
}

// TestStaleAllowDirectiveIsFlagged: a directive whose statement was deleted or
// moved silently exempts whatever code next occupies those lines. That is the
// self-defeating allowlist this guard exists to rule out, in the other
// direction.
func TestStaleAllowDirectiveIsFlagged(t *testing.T) {
	wantOne(t, `
func f() {
	//runningcheck:allow ownership handoff — but the call it covered is gone
	x := 1
	_ = x
}`, "suppressed nothing", "an orphaned directive")
}

// TestSecondBornRunningInsertNeedsItsOwnGraduation: the graduation evidence is
// block-scoped, because the routed code already depends on branch placement —
// promote.go graduates inside `if renamed`, templates.go inside
// `if state == "running"`. A function-wide check let a second insert on another
// branch ride on the first branch's call.
func TestSecondBornRunningInsertNeedsItsOwnGraduation(t *testing.T) {
	wantOne(t, `
func f() {
	if renamed {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "a", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "a")
	} else {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "b", State: "running"}, nil, nil)
	}
}`, "same block", "a second born-running insert with no graduation of its own")
}

// TestPerBranchGraduationIsAccepted: both branches graduating is the shape the
// routed code actually has.
func TestPerBranchGraduationIsAccepted(t *testing.T) {
	wantNone(t, `
func f() {
	if renamed {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "a", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "a")
	} else {
		corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "b", State: "running"}, nil, nil)
		s.assignOwnerEpochAtCreate(ctx, "b")
	}
}`, "per-branch graduation")
}

// TestHelperArgumentsAreNotTreatedAsClosures: registering every identifier
// argument put ctx, name and state into the routed-variable set, so an
// unrelated local of one of those names was reported as the routed closure
// invoked directly.
func TestHelperArgumentsAreNotTreatedAsClosures(t *testing.T) {
	wantNone(t, `
func f() error {
	if err := s.publishRunning(ctx, name, state, func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}); err != nil {
		return err
	}
	return name(ctx)
}`, "an unrelated call sharing an argument name")
}

// TestProofAboutAnotherStringIsNotAProof: the condition has to be about the
// value the closure will WRITE. Accepting any expression compared against
// "running" made this bypass — a proof about the detail string, of all things —
// read as a proof about the state.
func TestProofAboutAnotherStringIsNotAProof(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, detail)
	}
	if detail != "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "a proof about an unrelated string")
}

// TestPositiveStateComparisonProvesNonRunning: `state == "stopped"` is as good
// a proof as `state != "running"`, and it is how classifyStop's callers read.
// Rejecting it would have pushed a future site toward a directive instead.
func TestPositiveStateComparisonProvesNonRunning(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state == "stopped" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "a positive comparison against a non-running literal")
}

// TestPositiveRunningComparisonIsNotAProof: the same shape with the literal
// "running" proves the OPPOSITE, and must not be read as a proof.
func TestPositiveRunningComparisonIsNotAProof(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", state, "d")
	}
	if state == "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, state, commit)
}`, "invoked directly", "a positive comparison against \"running\"")
}

// TestSelectorStateExpressionIsMatched: the state at real call sites is
// `vm.State`, not a bare identifier. The proof must match it through the
// selector, or every routed site in the codebase would need a directive.
func TestSelectorStateExpressionIsMatched(t *testing.T) {
	wantNone(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.UpdateVMState(ctx, db, "vm1", vm.State, "d")
	}
	if vm.State != "running" {
		return commit(ctx)
	}
	return s.publishRunning(ctx, name, vm.State, commit)
}`, "a proof through the same selector expression")
}

// TestMintedClosureIsNeverProvenNonRunning: a minted helper takes no state
// argument because it ALWAYS publishes running. No branch can disprove that, so
// a direct invocation of its closure is unroutable by construction.
func TestMintedClosureIsNeverProvenNonRunning(t *testing.T) {
	wantOne(t, `
func f() error {
	commit := func(ctx context.Context) error {
		return corrosion.CompleteVMStartProof(ctx, db, id, "vm1", host)
	}
	if state != "running" {
		return commit(ctx)
	}
	return s.publishRunningMinted(ctx, name, commit)
}`, "invoked directly", "a minted closure under a state proof")
}

// scanCorrosionSrc runs the checker over one in-memory file placed where rule 5
// applies — the rule is corrosion-only, and the package is identified by path.
func scanCorrosionSrc(t *testing.T, src string) []violation {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "corrosion")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "x.go")
	if err := os.WriteFile(path, []byte("package corrosion\n"+src), 0o644); err != nil {
		t.Fatal(err)
	}
	vs, err := scanFile(path)
	if err != nil {
		t.Fatalf("scanFile: %v", err)
	}
	return vs
}

// TestUnregisteredStateStatementIsFlagged is rule 5's reason to exist: rules 1-4
// only police writers somebody remembered to name in a map.
func TestUnregisteredStateStatementIsFlagged(t *testing.T) {
	vs := scanCorrosionSrc(t, "const q = `UPDATE vms SET state = ?, updated_at = ? WHERE name = ?`\n")
	if len(vs) != 1 {
		t.Fatalf("got %d violation(s), want 1", len(vs))
	}
	if !strings.Contains(vs[0].msg, "stateWritingStatements") {
		t.Errorf("message = %q, want it to name the inventory", vs[0].msg)
	}
}

// TestRegisteredStateStatementIsAccepted, reflowed: the inventory is matched on
// normalized text, so re-wrapping a statement in corrosion must not fail CI.
func TestRegisteredStateStatementIsAccepted(t *testing.T) {
	vs := scanCorrosionSrc(t, "const q = `UPDATE vms\n"+
		"    SET state = ?, state_detail = ?, updated_at = ?\n"+
		"    WHERE name = ?`\n")
	if len(vs) != 0 {
		t.Errorf("a registered statement, reflowed, got %d violation(s), want 0:\n  %s", len(vs), vs[0].msg)
	}
}

// TestStateDetailIsNotAStateWrite: the near-misses a pattern match would trip
// over. Only the state column itself publishes a runtime.
func TestStateDetailIsNotAStateWrite(t *testing.T) {
	for _, sql := range []string{
		"UPDATE vms SET state_detail = ?, updated_at = ? WHERE name = ?",
		"UPDATE vms SET hardware_adoption_state = ?, updated_at = ? WHERE name = ?",
		"UPDATE vms SET updated_at = ? WHERE name = ? AND state = 'running'",
		"UPDATE vm_disks SET state = ?, updated_at = ? WHERE name = ?",
		"INSERT INTO vms (name, host_name, spec) VALUES (?, ?, ?)",
	} {
		if vs := scanCorrosionSrc(t, "const q = `"+sql+"`\n"); len(vs) != 0 {
			t.Errorf("%q was read as a vms.state write: %s", sql, vs[0].msg)
		}
	}
}

// TestStateStatementsOutsideCorrosionAreNotInventoried: rule 5 is scoped to the
// one package that holds the statements, so a fixture or a doc example elsewhere
// does not have to be registered.
func TestStateStatementsOutsideCorrosionAreNotInventoried(t *testing.T) {
	wantNone(t, "const q = `UPDATE vms SET state = ?, updated_at = ? WHERE name = ?`\n",
		"an unregistered state statement outside internal/corrosion")
}

// TestEveryInventoryEntryIsStillPresent: an entry whose statement was deleted or
// edited is the inventory's own stale-directive case. Left in place it silently
// pre-approves whatever statement later normalizes to the same text.
func TestEveryInventoryEntryIsStillPresent(t *testing.T) {
	found := map[string]bool{}
	err := filepath.WalkDir("../../../internal/corrosion", func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		for _, sql := range stateStatementsIn(t, path) {
			found[sql] = true
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk internal/corrosion: %v", err)
	}
	for _, st := range stateWritingStatements {
		if !found[normalizeSQL(st.sql)] {
			t.Errorf("inventory entry %q matches no statement in internal/corrosion any more — "+
				"remove it, or it pre-approves whatever next normalizes to the same text", st.owner)
		}
	}
}

// stateStatementsIn returns the normalized vms.state statements a file holds.
func stateStatementsIn(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		bl, ok := n.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return true
		}
		if sql := normalizeSQL(strings.Trim(bl.Value, "`\"")); writesVMState(sql) {
			out = append(out, sql)
		}
		return true
	})
	return out
}
