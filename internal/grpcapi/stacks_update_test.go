package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A compose update applies a hooks change as a spec patch now, not through
// CreateVM — and defining a hook still needs admin (hooks run as root on the
// host), so an operator's deploy cannot change one.
func TestApplyLiveMetadata_HooksNeedAdmin(t *testing.T) {
	s := testServerWithLocks(t)
	insertTestVM(t, context.Background(), s.db, "web", "test-host", "running")
	desired := &pb.VMSpec{Hooks: &pb.HooksSpec{PreStart: "touch /tmp/x"}}

	operator := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "op"), ctxKeyRole, "operator")
	err := s.applyLiveMetadata(operator, "web", desired, []string{"hooks"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator changing hooks: err=%v, want PermissionDenied", err)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "web"); vm != nil && vmHooks(vm) != nil {
		t.Errorf("hooks were written despite the refusal")
	}

	if err := s.applyLiveMetadata(adminCtx(), "web", desired, []string{"hooks"}); err != nil {
		t.Fatalf("admin changing hooks: %v", err)
	}
	vm, _ := corrosion.GetVM(context.Background(), s.db, "web")
	if vm == nil || vmHooks(vm).GetPreStart() != "touch /tmp/x" {
		t.Errorf("admin's hooks change was not applied: %+v", vm)
	}
}
