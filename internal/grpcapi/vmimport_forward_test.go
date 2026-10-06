package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An import forwarded with --target-host arrives at the target from a peer,
// and a peer authenticates as admin there, so an operator's forwarded import
// could name any host file as a disk. A forwarded import never carries
// host-path authority: only a caller connected to the target itself may name
// a path outside the staging root.

// forwardedPeerCtx is what the auth interceptor hands a handler for a peer
// call with no forwarded identity: the peer transport, as admin.
func forwardedPeerCtx(t *testing.T, s *Server, cn string) context.Context {
	t.Helper()
	ctx := peerCtxFor(t, s, cn)
	ctx = context.WithValue(ctx, ctxKeyUsername, "admin")
	return context.WithValue(ctx, ctxKeyRole, "admin")
}

func TestApplyImportDiskMap_ForwardedImportNeverNamesAHostPath(t *testing.T) {
	s, importDir, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db
	fv := proxmoxConfNaming(t, importDir, hostFile)

	err := s.applyImportDiskMap(forwardedPeerCtx(t, s, "entry-node"), fv, &pb.ImportVMRequest{}, importDir)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forwarded import naming a host file: got %v, want PermissionDenied", err)
	}
}

func TestApplyImportDiskMap_ForwardedDiskMapOutsideStagingRefused(t *testing.T) {
	s, importDir, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db
	fv := proxmoxConfNaming(t, importDir, "local-lvm:vm-100-disk-0")

	meta := &pb.ImportVMRequest{DiskMap: map[string]string{"scsi0": hostFile}}
	err := s.applyImportDiskMap(forwardedPeerCtx(t, s, "entry-node"), fv, meta, importDir)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forwarded --disk-map outside the staging root: got %v, want PermissionDenied", err)
	}
}

func TestResolveStagedPath_ForwardedServerPathOutsideStagingRefused(t *testing.T) {
	s, _, hostFile := importDiskPathFixture(t)
	s.db = testServer(t).db

	_, err := s.resolveStagedPath(forwardedPeerCtx(t, s, "entry-node"), hostFile)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("forwarded --server-path outside the staging root: got %v, want PermissionDenied", err)
	}
}
