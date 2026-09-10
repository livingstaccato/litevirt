package main

import (
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
