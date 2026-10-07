package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An import forwarded with --target-host arrives at the target from a peer,
// and a peer authenticates as admin there whoever called the entry node. A
// host path outside the staging root is judged as that caller: by the bearer
// the entry node relays, or by forwarded identity when it is enforced. An
// operator's forwarded import never names a host file; an admin's does, as
// on main.

// forwardedPeerCtx is what the auth interceptor hands a handler for a peer
// call with no forwarded identity: the peer transport, as admin.
func forwardedPeerCtx(t *testing.T, s *Server, cn string) context.Context {
	t.Helper()
	ctx := peerCtxFor(t, s, cn)
	ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

// forwardedImportFor is a peer call relaying user's bearer: role is the
// user's role at the cluster root.
func forwardedImportFor(t *testing.T, s *Server, user, role string) context.Context {
	t.Helper()
	_ = hostPathEngineCtx(t, s, user, role, "/")
	return forwardedAs(t, s, forwardedPeerCtx(t, s, "entry-node"), user)
}

func TestApplyImportDiskMap_ForwardedImportNeverNamesAHostPath(t *testing.T) {
	s, importDir, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db
	fv := proxmoxConfNaming(t, importDir, hostFile)

	err := s.applyImportDiskMap(forwardedImportFor(t, s, "op", "Operator"), fv, &pb.ImportVMRequest{}, importDir)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator's forwarded import naming a host file: got %v, want PermissionDenied", err)
	}
}

func TestApplyImportDiskMap_ForwardedDiskMapOutsideStagingRefused(t *testing.T) {
	s, importDir, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db
	fv := proxmoxConfNaming(t, importDir, "local-lvm:vm-100-disk-0")

	meta := &pb.ImportVMRequest{DiskMap: map[string]string{"scsi0": hostFile}}
	err := s.applyImportDiskMap(forwardedImportFor(t, s, "op", "Operator"), fv, meta, importDir)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator's forwarded --disk-map outside the staging root: got %v, want PermissionDenied", err)
	}
}

func TestResolveStagedPath_ForwardedServerPathOutsideStagingRefused(t *testing.T) {
	s, _, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db

	_, err := s.resolveStagedPath(forwardedImportFor(t, s, "op", "Operator"), hostFile)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("an operator's forwarded --server-path outside the staging root: got %v, want PermissionDenied", err)
	}
	// Promoted by forwarded identity: the operator, still refused.
	promoted := context.WithValue(hostPathEngineCtx(t, s, "op2", "Operator", "/"), ctxKeyPrincipalKind, principalKindPeer)
	promoted = context.WithValue(promoted, ctxKeyAuthMethod, authMethodToken)
	if _, err := s.resolveStagedPath(promoted, hostFile); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a promoted operator's forwarded --server-path: got %v, want PermissionDenied", err)
	}
}

// I-2. An admin's forwarded --server-path import works as on main: by the
// bearer the entry node relays, promoted by forwarded identity, or with no
// bearer at all (an admin by certificate on the entry node).
func TestResolveStagedPath_AnAdminsForwardedServerPathIsTaken(t *testing.T) {
	s, _, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db

	if _, err := s.resolveStagedPath(forwardedImportFor(t, s, "ada", "Admin"), hostFile); err != nil {
		t.Errorf("an admin's forwarded --server-path (relayed bearer): %v", err)
	}
	promoted := context.WithValue(hostPathEngineCtx(t, s, "ada2", "Admin", "/"), ctxKeyPrincipalKind, principalKindPeer)
	promoted = context.WithValue(promoted, ctxKeyAuthMethod, authMethodToken)
	if _, err := s.resolveStagedPath(promoted, hostFile); err != nil {
		t.Errorf("an admin's forwarded --server-path (forwarded identity): %v", err)
	}
	if _, err := s.resolveStagedPath(forwardedPeerCtx(t, s, "entry-node-2"), hostFile); err != nil {
		t.Errorf("an admin-by-certificate's forwarded --server-path (no bearer): %v", err)
	}
}

// The entry node never forwards an import bare for a caller who is not an
// admin: forwarded with no bearer, it would reach the target as this node.
func TestImportVM_ABearerlessNonAdminIsNotForwardedBare(t *testing.T) {
	s := testServer(t)
	s.dataDir = t.TempDir()
	op := context.WithValue(context.WithValue(context.Background(), ctxKeyUsername, "op"), ctxKeyRole, "operator")
	err := s.ImportVM(&fakeImportStream{ctx: op, frames: []*pb.ImportVMRequest{{
		Name: "fwd", SourceFormat: "proxmox", TargetHost: "host-b", SourcePath: "/etc/hostname",
	}}})
	if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "no identity to carry") {
		t.Fatalf("a bearerless operator's forwarded import: got %v, want PermissionDenied before the forward", err)
	}
}
