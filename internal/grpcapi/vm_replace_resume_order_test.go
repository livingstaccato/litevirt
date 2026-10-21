package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Lab 2 N-2. A crash after a cutover commits, before its runtime handoff:
// at the restart the cutover resume runs in the background (it may be
// deferred while storage does not answer), and the hardware backfill can
// audit the contested name first, while no domain is defined there. Its
// verdict ("no inactive domain definition", blocked) used to stand until the
// next daemon start, so the replacement would not start.
//
// In this order — crash, backfill, a start, then the resume — the backfill
// defers its verdict on the VM, a start before the resume is refused as
// retryable, and the audit runs once the handoff completes.
//
// Mutations: "the backfill audits a VM whose handoff is owed" — the VM is
// recorded blocked: red. "a start does not wait for the handoff" — the start
// is not refused as retryable: red.
func TestCutoverRestart_TheBackfillBeforeTheResumeDoesNotBlockTheVM(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()
	crashAt(s, "before-runtime")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon before the runtime handoff")
	}
	s.SetCutoverCrashHook(nil)
	if _, err := s.virt.DumpXMLInactive("app"); err == nil {
		t.Fatal("setup: the handoff already ran")
	}

	// The restart: the backfill gets to the VM before the resume.
	if err := s.BackfillHardwareTables(context.Background()); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if state, reason, err := corrosion.GetHardwareAdoptionState(ctx, s.db, "app"); err != nil || state == "blocked" {
		t.Fatalf("after the backfill, app's adoption is %q (%s, %v); want no verdict on a name whose handoff is owed", state, reason, err)
	}
	vm := vmRecord(t, s, "app")
	_, err := s.PrepareHardwareForStart(ctx, vm)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "cutover") {
		t.Fatalf("a start before the resume: %v; want Unavailable naming the owed cutover", err)
	}

	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("resume: %v", err)
	}
	if state, reason, err := corrosion.GetHardwareAdoptionState(ctx, s.db, "app"); err != nil || state != "adopted" {
		t.Fatalf("after the resume, app's adoption is %q (%s, %v); want adopted on its new definition", state, reason, err)
	}
	if _, err := s.PrepareHardwareForStart(ctx, vmRecord(t, s, "app")); status.Code(err) == codes.Unavailable {
		t.Fatalf("a start after the resume: %v", err)
	}
}

// ccguard I3: a cutover that returns with its committed phases journaled
// wakes the daemon's retry loop, so the owed handoff is finished without a
// daemon restart; the loop's attempt is ResumeVMReplaceCleanups.
//
// Mutation: no kick on that return — nothing wakes the loop, red.
func TestCutoverVM_AJournaledFailureKicksTheCleanupRetry(t *testing.T) {
	s, _, _, _ := restartFixture(t)
	ctx := adminCtx()
	crashAt(s, "before-runtime")
	if _, err := s.CutoverVM(ctx, &pb.CutoverVMRequest{VmName: "app"}); err == nil {
		t.Fatal("the cutover did not abandon before the runtime handoff")
	}
	s.SetCutoverCrashHook(nil)
	select {
	case <-s.VMReplaceCleanupKick():
	default:
		t.Fatal("a cutover that left its handoff journaled did not wake the cleanup retry")
	}
	if err := s.ResumeVMReplaceCleanups(ctx); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if _, err := s.virt.DumpXMLInactive("app"); err != nil {
		t.Fatalf("after the retry the handoff has not run: %v", err)
	}
}
