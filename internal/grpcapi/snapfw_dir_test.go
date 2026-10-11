package grpcapi

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func firmwareSnapshotVM(t *testing.T, name string) *Server {
	t.Helper()
	s := testServer(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	spec := `{"name":"` + name + `","secure_boot":true,"firmware":"uefi","uuid":"u-` + name + `"}`
	if err := corrosion.InsertVM(adminCtx(), s.db, corrosion.VMRecord{Name: name, HostName: s.hostName, Spec: spec, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	nv := lv.NvramPath(s.dataDir, name)
	if err := os.MkdirAll(filepath.Dir(nv), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nv, []byte("uefi vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	return s
}

// Lab 2 run b, finding 7: removing a VM's last firmware snapshot left an empty
// snapfw/<vm>/ behind. The directory goes with its last bundle — rmdir, so
// only when it is empty: while another snapshot's bundle, or anything else,
// is in it, it stays, and nothing in it is removed.
//
// Mutations: drop the rmdir — the empty directory stays, red. RemoveAll
// instead — s2's bundle and the foreign file go, red.
func TestDeleteSnapshot_TheLastFirmwareBundleTakesItsEmptyDirectory(t *testing.T) {
	ctx := adminCtx()
	s := firmwareSnapshotVM(t, "fw1")
	for _, snap := range []string{"s1", "s2"} {
		if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fw1", Name: snap}); err != nil {
			t.Fatalf("CreateSnapshot %s: %v", snap, err)
		}
	}
	dir := filepath.Dir(lv.SnapshotFirmwareBundlePath(s.dataDir, "fw1", "s1"))

	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "fw1", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot s1: %v", err)
	}
	if _, err := os.Stat(lv.SnapshotFirmwareBundlePath(s.dataDir, "fw1", "s2")); err != nil {
		t.Fatalf("s2's bundle went with s1's delete: %v", err)
	}
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "fw1", SnapshotName: "s2"}); err != nil {
		t.Fatalf("DeleteSnapshot s2: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("snapfw/fw1 is left after its last bundle went (err=%v)", err)
	}
	if _, err := os.Stat(filepath.Dir(dir)); err != nil {
		t.Errorf("snapfw/ itself went: %v", err)
	}
	// A new snapshot afterwards makes the directory again.
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fw1", Name: "s3"}); err != nil {
		t.Fatalf("CreateSnapshot after the directory went: %v", err)
	}
}

// Something in the directory that is not a bundle of a removed snapshot keeps
// it, untouched.
func TestDeleteSnapshot_AFirmwareDirectoryThatIsNotEmptyStays(t *testing.T) {
	ctx := adminCtx()
	s := firmwareSnapshotVM(t, "fw2")
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fw2", Name: "s1"}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	dir := filepath.Dir(lv.SnapshotFirmwareBundlePath(s.dataDir, "fw2", "s1"))
	foreign := filepath.Join(dir, "operator-copy.tar")
	if err := os.WriteFile(foreign, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteSnapshot(ctx, &pb.DeleteSnapshotRequest{VmName: "fw2", SnapshotName: "s1"}); err != nil {
		t.Fatalf("DeleteSnapshot: %v", err)
	}
	if b, err := os.ReadFile(foreign); err != nil || string(b) != "keep" {
		t.Errorf("a file in snapfw/fw2 that is no snapshot's bundle was touched: %q %v", b, err)
	}
}
