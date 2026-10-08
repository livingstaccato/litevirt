package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/vmimport"
)

// A Proxmox .conf names each disk by a volume reference that the parser keeps
// verbatim. When that reference happens to be an absolute path to a file that
// exists on the importing host, the disk must still go through the staging
// check: otherwise an operator can name any host file as a "disk", have it
// converted into their VM's disk, and read it from inside the guest.

func importDiskPathFixture(t *testing.T) (s *Server, importDir, hostFile string) {
	t.Helper()
	dataDir := t.TempDir()
	importDir = filepath.Join(dataDir, "imports", "vm1-123")
	if err := os.MkdirAll(importDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A file outside the data dir standing in for any host file the daemon can
	// read but the caller must not.
	hostFile = filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(hostFile, []byte("not for the caller"), 0o600); err != nil {
		t.Fatal(err)
	}
	return &Server{dataDir: dataDir}, importDir, hostFile
}

func proxmoxConfNaming(t *testing.T, dir, diskRef string) *vmimport.ForeignVM {
	t.Helper()
	conf := filepath.Join(dir, "100.conf")
	body := "name: vm1\nmemory: 512\ncores: 1\nscsi0: " + diskRef + ",size=1G\n"
	if err := os.WriteFile(conf, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	fv, err := vmimport.ParseProxmoxConf(conf)
	if err != nil {
		t.Fatalf("parse conf: %v", err)
	}
	return fv
}

func operatorCtx() context.Context {
	return context.WithValue(context.Background(), ctxKeyRole, "operator")
}

func adminCtxForImport() context.Context {
	return context.WithValue(context.Background(), ctxKeyRole, "admin")
}

func TestApplyImportDiskMap_HostPathDiskRefRefusedForOperator(t *testing.T) {
	s, importDir, hostFile := importDiskPathFixture(t)
	fv := proxmoxConfNaming(t, importDir, hostFile)

	err := s.applyImportDiskMap(operatorCtx(), fv, &pb.ImportVMRequest{}, importDir)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator naming a host file as a disk: got %v, want PermissionDenied", err)
	}
}

func TestApplyImportDiskMap_HostPathDiskRefAllowedForAdmin(t *testing.T) {
	s, importDir, hostFile := importDiskPathFixture(t)
	fv := proxmoxConfNaming(t, importDir, hostFile)

	if err := s.applyImportDiskMap(adminCtxForImport(), fv, &pb.ImportVMRequest{}, importDir); err != nil {
		t.Fatalf("admin naming a host file as a disk: %v", err)
	}
}

func TestApplyImportDiskMap_DiskInsideImportDirNeedsNoMap(t *testing.T) {
	s, importDir, _ := importDiskPathFixture(t)
	inside := filepath.Join(importDir, "disk-0.raw")
	if err := os.WriteFile(inside, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fv := proxmoxConfNaming(t, importDir, inside)

	if err := s.applyImportDiskMap(operatorCtx(), fv, &pb.ImportVMRequest{}, importDir); err != nil {
		t.Fatalf("disk unpacked inside the import dir: %v", err)
	}
}

func TestApplyImportDiskMap_SymlinkOutOfImportDirRefusedForOperator(t *testing.T) {
	s, importDir, hostFile := importDiskPathFixture(t)
	link := filepath.Join(importDir, "disk-0.raw")
	if err := os.Symlink(hostFile, link); err != nil {
		t.Fatal(err)
	}
	fv := proxmoxConfNaming(t, importDir, link)

	err := s.applyImportDiskMap(operatorCtx(), fv, &pb.ImportVMRequest{}, importDir)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("symlink in the import dir pointing out of it: got %v, want PermissionDenied", err)
	}
}

func TestApplyImportDiskMap_StagedDiskMapStillWorksForOperator(t *testing.T) {
	s, importDir, _ := importDiskPathFixture(t)
	staging := filepath.Join(s.dataDir, "imports", "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(staging, "vm-100-disk-0.raw")
	if err := os.WriteFile(staged, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	fv := proxmoxConfNaming(t, importDir, "local-lvm:vm-100-disk-0")

	meta := &pb.ImportVMRequest{DiskMap: map[string]string{"scsi0": staged}}
	if err := s.applyImportDiskMap(operatorCtx(), fv, meta, importDir); err != nil {
		t.Fatalf("operator --disk-map into the staging root: %v", err)
	}
	if got := fv.Disks[0].LocalPath; got != staged {
		t.Fatalf("disk path = %q, want %q", got, staged)
	}
}
