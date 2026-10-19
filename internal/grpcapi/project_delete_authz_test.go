package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A user bound only inside project P must lose that access when P is deleted
// WITHOUT falling back to their legacy role, which applies cluster-wide.
// RequirePerm treats "no bindings at all" as "use the legacy role", so retiring
// the last binding of a confined principal would hand them every project.
func TestDeleteProject_ConfinedUserGainsNothingClusterWide(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertProject(ctx, s.db, corrosion.ProjectRecord{Name: "acme"}); err != nil {
		t.Fatal(err)
	}
	callerCtx := boundAtCtx(t, s, "mallory", "operator", "Operator", "/projects/acme")

	if err := s.RequirePerm(callerCtx, "/projects/acme/vms/web", "vm.start", "operator"); err != nil {
		t.Fatalf("setup: the bound user is denied inside their own project: %v", err)
	}

	if err := corrosion.DeleteProject(ctx, s.db, "acme"); err != nil {
		t.Fatal(err)
	}
	if err := s.authEngine.Reload(ctx); err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"/projects/acme/vms/web", "/projects/beta/vms/web", "/projects/_default/vms/web", "/"} {
		err := s.RequirePerm(callerCtx, path, "vm.start", "operator")
		if status.Code(err) != codes.PermissionDenied {
			t.Fatalf("after the project was deleted, RequirePerm(%s) = %v, want PermissionDenied: "+
				"the user fell back to their legacy role cluster-wide", path, err)
		}
	}
}
