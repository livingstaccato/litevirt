package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func cloneTargetServer(t *testing.T) *Server {
	t.Helper()
	s := testServerWithLocks(t)
	s.virt = libvirtfake.New()
	s.images = image.NewStore(s.dataDir)
	seedCloneSource(t, s, "tpl", "", "")
	return s
}

func addDirPool(t *testing.T, s *Server, name string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), name)
	s.addStoragePoolRef(name, StoragePoolRef{Driver: "dir", Target: dir})
	return dir
}

func cloneDisk(t *testing.T, s *Server, vm string) corrosion.DiskRecord {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), s.db, vm)
	if err != nil || len(disks) != 1 {
		t.Fatalf("GetVMDisks %s: %v %v", vm, disks, err)
	}
	return disks[0]
}

// A clone into a pool puts its disk in that pool's directory, records the pool
// and its driver as MoveVolume does, and leaves the source's disk alone.
//
// Mutation: drop the `tpool != nil` branch that picks the path — the disk goes
// to the default directory and the first assertion fails.
func TestCloneVM_IntoAPoolPlacesTheDiskThere(t *testing.T) {
	s := cloneTargetServer(t)
	dir := addDirPool(t, s, "ssd")

	if _, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c1", TargetPool: "ssd"}); err != nil {
		t.Fatalf("CloneVM into a pool: %v", err)
	}
	d := cloneDisk(t, s, "c1")
	want := filepath.Join(dir, "c1-root.qcow2")
	if d.Path != want || d.StorageVolume != "ssd" || d.StorageType != "dir" || d.HostName != "test-host" {
		t.Fatalf("clone disk row = %+v, want path %s in pool ssd (dir)", d, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("the clone's file is not in the pool: %v", err)
	}
	if _, err := os.Stat(s.images.DiskPath("c1", "root")); err == nil {
		t.Errorf("a pool clone left a file in the default disk directory")
	}
	if _, err := os.Stat(s.images.DiskPath("tpl", "root")); err != nil {
		t.Errorf("the source's disk is gone: %v", err)
	}
	xml, _ := s.virt.DumpXML("c1")
	if !strings.Contains(xml, want) {
		t.Errorf("the clone's domain does not use the pool file:\n%s", xml)
	}
}

// Refusals, each before a byte is written, each leaving nothing behind.
func TestCloneVM_TargetRefusals(t *testing.T) {
	s := cloneTargetServer(t)
	addDirPool(t, s, "ssd")
	s.addStoragePoolRef("ceph1", StoragePoolRef{Driver: "ceph", Source: "rbd/pool"})
	ctx := context.Background()
	for _, h := range []corrosion.HostRecord{
		{Name: "draining", Address: "10.0.0.2", SSHUser: "root", State: "draining", CertSerial: "s1"},
		{Name: "wit", Address: "10.0.0.3", SSHUser: "root", State: "active", CertSerial: "s2", Role: "witness"},
		{Name: "h2", Address: "10.0.0.4", SSHUser: "root", State: "active", CertSerial: "s3"},
	} {
		if err := corrosion.InsertHost(ctx, s.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	// A pool another project owns.
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: "test-host", Name: "theirs", Driver: "dir", Target: t.TempDir(), Project: "other", State: "active"}); err != nil {
		t.Fatal(err)
	}
	s.addStoragePoolRef("theirs", StoragePoolRef{Driver: "dir", Target: t.TempDir()})

	for _, tc := range []struct {
		name string
		req  *pb.CloneVMRequest
		code codes.Code
		want string
	}{
		{"unknown host", &pb.CloneVMRequest{TargetHost: "nowhere"}, codes.NotFound, "not found"},
		{"draining host", &pb.CloneVMRequest{TargetHost: "draining"}, codes.FailedPrecondition, "not active"},
		{"witness host", &pb.CloneVMRequest{TargetHost: "wit"}, codes.FailedPrecondition, "witness"},
		{"linked on another host", &pb.CloneVMRequest{TargetHost: "h2", Mode: "linked"}, codes.InvalidArgument, "linked clone"},
		{"linked in a pool", &pb.CloneVMRequest{TargetPool: "ssd", Mode: "linked"}, codes.InvalidArgument, "linked clone"},
		{"unknown pool", &pb.CloneVMRequest{TargetPool: "nope"}, codes.NotFound, "not configured"},
		{"block pool", &pb.CloneVMRequest{TargetPool: "ceph1"}, codes.FailedPrecondition, "not file-based"},
		{"another project's pool", &pb.CloneVMRequest{TargetPool: "theirs"}, codes.PermissionDenied, "owned by project"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tc.req.Source, tc.req.Target = "tpl", "refused"
			_, err := s.CloneVM(adminCtx(), tc.req)
			if status.Code(err) == codes.OK || (tc.want != "" && !strings.Contains(err.Error(), tc.want)) {
				t.Fatalf("CloneVM = %v, want %v containing %q", err, tc.code, tc.want)
			}
			if tc.want != "" && status.Code(err) != tc.code {
				t.Fatalf("code = %v, want %v (%v)", status.Code(err), tc.code, err)
			}
			if vm, _ := corrosion.GetVM(ctx, s.db, "refused"); vm != nil {
				t.Fatalf("a refused clone left a VM row")
			}
		})
	}
}

// A file already at the pool path is never overwritten: in a shared pool the
// derived name can be another VM's disk.
//
// Mutation: drop the Lstat refusal — the other VM's disk is replaced.
func TestCloneVM_IntoAPoolNeverOverwritesAFile(t *testing.T) {
	s := cloneTargetServer(t)
	dir := addDirPool(t, s, "ssd")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(dir, "c2-root.qcow2")
	if err := os.WriteFile(victim, []byte("someone else's disk"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := s.CloneVM(adminCtx(), &pb.CloneVMRequest{Source: "tpl", Target: "c2", TargetPool: "ssd"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("CloneVM onto an existing file = %v, want AlreadyExists", err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "someone else's disk" {
		t.Fatalf("the existing file was overwritten: %q", b)
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, "c2"); vm != nil {
		t.Fatal("a refused clone left a VM row")
	}
}
