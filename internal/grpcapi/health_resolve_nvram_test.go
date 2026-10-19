package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
)

func staleVarsServer(t *testing.T) *Server {
	t.Helper()
	s := dualRunTestServer(t, 2)
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: libvirt.NvramFlushEvaluator, Code: libvirt.CondNvramFlushFailed,
		SubjectKind: "host", SubjectID: "h1", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityCritical, Reporter: "h1", LastSeen: backdated,
		Evidence: `{"files":[{"path":"/var/lib/libvirt/qemu/nvram/web-1_VARS.fd","vm":"web-1","ino":4242,"episode":"9f3a1c"}]}`,
	}); err != nil {
		t.Fatal(err)
	}
	return s
}

func staleVarsLifecycle(t *testing.T, s *Server) string {
	t.Helper()
	row, _, err := corrosion.GetHealthCondition(context.Background(), s.db,
		libvirt.NvramFlushEvaluator, libvirt.CondNvramFlushFailed, "host", "h1")
	if err != nil {
		t.Fatal(err)
	}
	return row.Lifecycle
}

// TestResolveHealthCondition_StaleUEFIVarsAcknowledged: a plain UEFI VM's
// failed vars flush has no exit that replaces the file. An admin may resolve
// nvram_flush_failed by acknowledging that the store may be stale, with a
// reason; it is audited, naming the files. Without a reason it is refused and
// nothing is written.
func TestResolveHealthCondition_StaleUEFIVarsAcknowledged(t *testing.T) {
	s := staleVarsServer(t)
	ctx := boundCtx(t, s, "alice", "admin", "Admin")
	req := &pb.ResolveHealthConditionRequest{Code: libvirt.CondNvramFlushFailed, SubjectKind: "host", SubjectId: "h1", AcceptStaleUefiVars: true}

	if _, err := s.ResolveHealthCondition(ctx, req); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("no reason: err = %v, want InvalidArgument", err)
	}
	if got := staleVarsLifecycle(t, s); got != corrosion.ConditionConfirmed {
		t.Fatalf("a refused acknowledgement left the row %q", got)
	}
	if len(healthResolveAudits(t, s)) != 0 {
		t.Fatal("a refused acknowledgement was audited")
	}

	req.Reason = "disk replaced; guest re-enrolled its keys"
	req.AcceptStaleUefiVars = true
	if _, err := s.ResolveHealthCondition(ctx, req); err != nil {
		t.Fatalf("acknowledge: %v", err)
	}
	if got := staleVarsLifecycle(t, s); got != corrosion.ConditionResolved {
		t.Fatalf("after the acknowledgement the row is %q", got)
	}
	audits := healthResolveAudits(t, s)
	if len(audits) != 1 || !strings.Contains(audits[0][1], "may be stale") ||
		!strings.Contains(audits[0][1], "web-1_VARS.fd") || !strings.Contains(audits[0][1], req.Reason) ||
		!strings.Contains(audits[0][1], "inode 4242") || !strings.Contains(audits[0][1], "episode 9f3a1c") {
		t.Fatalf("audit = %v; want one row acknowledging the stale store, naming the file, its inode and episode, and the reason", audits)
	}
}

// An operator (not admin) cannot acknowledge it.
func TestResolveHealthCondition_StaleUEFIVarsNeedsAdmin(t *testing.T) {
	s := staleVarsServer(t)
	ctx := boundCtx(t, s, "bob", "operator", "Operator")
	_, err := s.ResolveHealthCondition(ctx, &pb.ResolveHealthConditionRequest{
		Code: libvirt.CondNvramFlushFailed, SubjectKind: "host", SubjectId: "h1", Reason: "x", AcceptStaleUefiVars: true})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator: err = %v, want PermissionDenied", err)
	}
	if got := staleVarsLifecycle(t, s); got != corrosion.ConditionConfirmed {
		t.Fatalf("operator call left the row %q", got)
	}
}

// TestResolveHealthCondition_StaleUEFIVarsNeedsExplicitIntent: a request
// with a reason but without accept_stale_uefi_vars (an older lv, a script
// resolving open conditions, a direct gRPC call) is refused, naming the flag;
// the row is untouched and nothing is audited.
func TestResolveHealthCondition_StaleUEFIVarsNeedsExplicitIntent(t *testing.T) {
	s := staleVarsServer(t)
	ctx := boundCtx(t, s, "alice", "admin", "Admin")
	_, err := s.ResolveHealthCondition(ctx, &pb.ResolveHealthConditionRequest{
		Code: libvirt.CondNvramFlushFailed, SubjectKind: "host", SubjectId: "h1", Reason: "cleanup script"})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "--accept-stale-uefi-vars") {
		t.Fatalf("reason without intent: err = %v, want FailedPrecondition naming --accept-stale-uefi-vars", err)
	}
	if got := staleVarsLifecycle(t, s); got != corrosion.ConditionConfirmed {
		t.Fatalf("a refused acknowledgement left the row %q", got)
	}
	if len(healthResolveAudits(t, s)) != 0 {
		t.Fatal("a refused acknowledgement was audited")
	}
}

// Evidence that cannot be parsed is said so in the audit.
func TestResolveHealthCondition_StaleUEFIVarsUnreadableEvidenceIsAudited(t *testing.T) {
	s := dualRunTestServer(t, 2)
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
		Evaluator: libvirt.NvramFlushEvaluator, Code: libvirt.CondNvramFlushFailed,
		SubjectKind: "host", SubjectID: "h1", Lifecycle: corrosion.ConditionConfirmed,
		Severity: corrosion.SeverityCritical, Reporter: "h1", LastSeen: backdated, Evidence: "not json",
	}); err != nil {
		t.Fatal(err)
	}
	ctx := boundCtx(t, s, "alice", "admin", "Admin")
	if _, err := s.ResolveHealthCondition(ctx, &pb.ResolveHealthConditionRequest{
		Code: libvirt.CondNvramFlushFailed, SubjectKind: "host", SubjectId: "h1", Reason: "r", AcceptStaleUefiVars: true}); err != nil {
		t.Fatal(err)
	}
	audits := healthResolveAudits(t, s)
	if len(audits) != 1 || !strings.Contains(audits[0][1], "evidence unreadable") {
		t.Fatalf("audit = %v; want it to say the evidence was unreadable", audits)
	}
}

// --accept and --force are vm.move_unresolved's: sent with an acknowledgement
// of nvram_flush_failed, complete with its own flag and a reason, each is
// refused, not ignored, and nothing is written or audited.
func TestResolveHealthCondition_MoveFlagsRefusedOnStaleUEFIVars(t *testing.T) {
	for name, ctx := range map[string]context.Context{
		"--accept": acceptCtx("/var/lib/libvirt/qemu/nvram/web-1_VARS.fd"),
		"--force":  forceCtx(),
	} {
		t.Run(name, func(t *testing.T) {
			s := staleVarsServer(t)
			_, err := s.ResolveHealthCondition(ctx, &pb.ResolveHealthConditionRequest{
				Code: libvirt.CondNvramFlushFailed, SubjectKind: "host", SubjectId: "h1",
				Reason: "disk replaced", AcceptStaleUefiVars: true})
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "applies only to vm.move_unresolved") {
				t.Fatalf("err = %v, want InvalidArgument naming vm.move_unresolved", err)
			}
			if got := staleVarsLifecycle(t, s); got != corrosion.ConditionConfirmed {
				t.Fatalf("a refused acknowledgement left the row %q", got)
			}
			if len(healthResolveAudits(t, s)) != 0 {
				t.Fatal("a refused acknowledgement was audited")
			}
		})
	}
}
