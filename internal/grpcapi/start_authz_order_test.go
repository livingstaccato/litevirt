package grpcapi

import (
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// StartVM ran its linked-clone guard BEFORE RequirePerm, so a caller who clears
// only the coarse role floor — an operator bound to one project — got back the
// NAMES of another project's linked clones in the refusal for a VM they are not
// allowed to start. Every sibling in this file authorizes first.
func TestStartVM_AuthorizesBeforeNamingOtherProjectsClones(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	base := corrosion.VMRecord{Name: "base", HostName: "test-host", State: "stopped", Project: "secret"}
	if err := corrosion.InsertVM(ctx, s.db, base, nil,
		[]corrosion.DiskRecord{{VMName: "base", DiskName: "root", HostName: "test-host",
			Path: s.images.DiskPath("base", "root"), StorageType: "local"}}); err != nil {
		t.Fatalf("InsertVM base: %v", err)
	}
	if err := corrosion.InsertVM(ctx,
		s.db, corrosion.VMRecord{Name: "topsecret-clone", HostName: "test-host", State: "stopped", Project: "secret"},
		nil,
		[]corrosion.DiskRecord{{VMName: "topsecret-clone", DiskName: "root", HostName: "test-host",
			Path: s.images.DiskPath("topsecret-clone", "root"), StorageType: "local",
			BackingDisk: s.images.DiskPath("base", "root")}}); err != nil {
		t.Fatalf("InsertVM clone: %v", err)
	}

	// An operator scoped to a DIFFERENT project: clears the role floor, fails the
	// per-resource check.
	callerCtx := boundAtCtx(t, s, "mallory", "operator", "Operator", "/projects/other")

	_, err := s.StartVM(callerCtx, &pb.StartVMRequest{Name: "base"})

	if err == nil {
		t.Fatal("StartVM succeeded for a caller with no permission on that project")
	}
	if strings.Contains(err.Error(), "topsecret-clone") {
		t.Fatalf("the refusal named another project's linked clone: %v — the clone guard "+
			"runs before authorization, so an unauthorized caller learns what exists", err)
	}
	if got := status.Code(err); got != codes.PermissionDenied {
		t.Errorf("code = %s, want PermissionDenied (authorize first, then check the guard)", got)
	}
}
