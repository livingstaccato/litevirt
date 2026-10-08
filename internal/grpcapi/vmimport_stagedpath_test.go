package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Naming an import source outside the staging root reads a host path, so it
// takes the storage host-path verb (storage.hostpath at the root) — the verb
// every other host path in storage takes. A custom role holding that verb
// may; an Admin, and the legacy admin role, still may, as on main; an
// Operator may not.
func TestResolveStagedPath_TakesTheStorageHostPathVerb(t *testing.T) {
	s, _, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db
	if err := corrosion.InsertRole(context.Background(), s.db, corrosion.RoleRecord{
		Name: "HostPaths", Verbs: []string{verbStorageHostPath},
	}); err != nil {
		t.Fatal(err)
	}
	hp := hostPathEngineCtx(t, s, "hp", "HostPaths", "/")
	if _, err := s.resolveStagedPath(hp, hostFile); err != nil {
		t.Errorf("a holder of %s naming a host path: %v", verbStorageHostPath, err)
	}
	op := hostPathEngineCtx(t, s, "op", "Operator", "/")
	if _, err := s.resolveStagedPath(op, hostFile); status.Code(err) != codes.PermissionDenied {
		t.Errorf("an operator naming a host path: got %v, want PermissionDenied", err)
	}
	if _, err := s.resolveStagedPath(adminCtx(), hostFile); err != nil {
		t.Errorf("the admin naming a host path: %v", err)
	}
}
