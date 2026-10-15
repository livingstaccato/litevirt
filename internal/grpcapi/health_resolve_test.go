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

// confirmedMismatchServer is a dual-run fixture holding a confirmed
// runtime_owner_mismatch on vmA (DB owner h1, runtime on h2), with the gather
// still seeing it.
func confirmedMismatchServer(t *testing.T) *Server {
	t.Helper()
	s := dualRunTestServer(t, 2)
	seedVM(t, s, "vmA", "h1", "running")
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {}, "h2": {diskHolderVMs: []string{"vmA"}},
	})
	s.detectDualRunPass(context.Background())
	s.detectDualRunPass(context.Background())
	if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionConfirmed {
		t.Fatalf("setup: owner mismatch = %q, want confirmed", got)
	}
	return s
}

func resolveReq() *pb.ResolveHealthConditionRequest {
	return &pb.ResolveHealthConditionRequest{
		Code: "runtime_owner_mismatch", SubjectKind: "vm", SubjectId: "vmA", Reason: "VM deleted; no domain anywhere",
	}
}

func healthResolveAudits(t *testing.T, s *Server) [][2]string {
	t.Helper()
	rows, err := s.db.Query(context.Background(),
		`SELECT target, detail FROM audit_log WHERE action = 'health.condition.resolve' ORDER BY timestamp, id`)
	if err != nil {
		t.Fatalf("read audit log: %v", err)
	}
	out := make([][2]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, [2]string{r.String("target"), r.String("detail")})
	}
	return out
}

// TestResolveHealthCondition_AdminResolvesAudited: an admin resolves an open
// dual-run condition. The row is resolved, one audit row names the condition
// and the operator's reason, and an event is published.
//
// Mutations: skip the upsert — the row stays confirmed; skip the audit — no
// row; skip the publish — no event.
func TestResolveHealthCondition_AdminResolvesAudited(t *testing.T) {
	s := confirmedMismatchServer(t)
	ctx := boundCtx(t, s, "alice", "admin", "Admin")
	ch, unsub := s.events.Subscribe()
	defer unsub()

	resp, err := s.ResolveHealthCondition(ctx, resolveReq())
	if err != nil {
		t.Fatalf("ResolveHealthCondition: %v", err)
	}
	if got := resp.GetCondition().GetLifecycle(); got != corrosion.ConditionResolved {
		t.Errorf("response lifecycle = %q, want resolved", got)
	}
	if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionResolved {
		t.Fatalf("row lifecycle = %q, want resolved", got)
	}
	audits := healthResolveAudits(t, s)
	if len(audits) != 1 {
		t.Fatalf("audit rows = %d, want 1", len(audits))
	}
	if got := audits[0][0]; got != "dual_run/runtime_owner_mismatch/vm/vmA" {
		t.Errorf("audit target = %q", got)
	}
	if !strings.Contains(audits[0][1], "VM deleted; no domain anywhere") || !strings.Contains(audits[0][1], "confirmed") {
		t.Errorf("audit detail %q names neither the reason nor the prior lifecycle", audits[0][1])
	}
	published := false
	for !published {
		select {
		case e := <-ch:
			published = e.Action == "ha.condition.resolved" && e.Target == "runtime_owner_mismatch:vm/vmA"
		default:
			t.Fatalf("no ha.condition.resolved event for vm/vmA")
		}
	}
}

// TestResolveHealthCondition_StillTrueIsRaisedAgain: resolving is an
// operator's statement, not proof. The detector re-derives every finding each
// pass, so a mismatch that still holds is raised again — observed, and so
// admission-gating again — on the very next pass.
func TestResolveHealthCondition_StillTrueIsRaisedAgain(t *testing.T) {
	s := confirmedMismatchServer(t)
	ctx := boundCtx(t, s, "alice", "admin", "Admin")
	if _, err := s.ResolveHealthCondition(ctx, resolveReq()); err != nil {
		t.Fatalf("ResolveHealthCondition: %v", err)
	}
	s.detectDualRunPass(context.Background())
	if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionObserved {
		t.Fatalf("lifecycle after a pass that still sees the mismatch = %q, want observed", got)
	}
}

// TestResolveHealthCondition_Refusals: only an admin, never a peer, and only
// the dual-run detector's conditions — the ones re-derived every pass, which
// are also the only ones that gate admission.
//
// Mutations: drop the peer check, the RBAC check, or the evaluator check —
// the matching case resolves the row and goes red.
func TestResolveHealthCondition_Refusals(t *testing.T) {
	t.Run("operator", func(t *testing.T) {
		s := confirmedMismatchServer(t)
		ctx := boundCtx(t, s, "bob", "operator", "Operator")
		_, err := s.ResolveHealthCondition(ctx, resolveReq())
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("operator: err = %v, want PermissionDenied", err)
		}
		if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionConfirmed {
			t.Errorf("operator call left the row %q", got)
		}
	})
	t.Run("peer", func(t *testing.T) {
		s := confirmedMismatchServer(t)
		ctx := context.WithValue(context.Background(), ctxKeyPrincipalKind, principalKindPeer)
		ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
		ctx = context.WithValue(ctx, ctxKeyRole, "admin")
		_, err := s.ResolveHealthCondition(ctx, resolveReq())
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("peer: err = %v, want PermissionDenied", err)
		}
		if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionConfirmed {
			t.Errorf("peer call left the row %q", got)
		}
	})
	t.Run("another evaluator", func(t *testing.T) {
		s := confirmedMismatchServer(t)
		ctx := boundCtx(t, s, "alice", "admin", "Admin")
		if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{
			Evaluator: corrosion.PartitionPauseEvaluator, Code: corrosion.CondPartitionPaused,
			SubjectKind: "host", SubjectID: "h1", Lifecycle: corrosion.ConditionConfirmed,
			Severity: corrosion.SeverityWarning, Reporter: "h1",
		}); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(ctx, &pb.ResolveHealthConditionRequest{
			Code: corrosion.CondPartitionPaused, SubjectKind: "host", SubjectId: "h1",
		})
		if status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("partition_paused: err = %v, want FailedPrecondition", err)
		}
		row, _, _ := corrosion.GetHealthCondition(context.Background(), s.db,
			corrosion.PartitionPauseEvaluator, corrosion.CondPartitionPaused, "host", "h1")
		if row.Lifecycle != corrosion.ConditionConfirmed {
			t.Errorf("partition_paused left %q", row.Lifecycle)
		}
	})
	t.Run("no such open condition", func(t *testing.T) {
		s := confirmedMismatchServer(t)
		ctx := boundCtx(t, s, "alice", "admin", "Admin")
		_, err := s.ResolveHealthCondition(ctx, &pb.ResolveHealthConditionRequest{
			Code: "runtime_owner_mismatch", SubjectKind: "vm", SubjectId: "nope",
		})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("err = %v, want NotFound", err)
		}
		if len(healthResolveAudits(t, s)) != 0 {
			t.Errorf("a refused call wrote an audit row")
		}
	})
}
