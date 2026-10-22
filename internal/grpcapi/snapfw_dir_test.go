package grpcapi

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
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

// Lab 2 rc1, B2: `lv rm` left snapfw/<vm>/<snap>.tar — the deleted VM's nvram
// and vTPM state — on the host. A delete that committed takes the whole
// directory; another VM's bundles and a --keep-disks delete are untouched.
//
// Mutations: drop the removeVMFirmwareBundles call in deleteVM — the leftover,
// red. Remove it before the tombstone — TestDeleteVM_FirmwareBundlesStayWhenTheDeleteFails red.
func TestDeleteVM_RemovesItsSnapshotFirmwareBundles(t *testing.T) {
	ctx := adminCtx()
	s := firmwareSnapshotVM(t, "fwrm")
	for _, snap := range []string{"s1", "s2"} {
		if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fwrm", Name: snap}); err != nil {
			t.Fatalf("CreateSnapshot %s: %v", snap, err)
		}
	}
	other := filepath.Join(s.dataDir, "snapfw", "fwrm2", "s1.tar")
	if err := os.MkdirAll(filepath.Dir(other), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, []byte("other vm"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Dir(lv.SnapshotFirmwareBundlePath(s.dataDir, "fwrm", "s1"))
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("no bundle was captured: %v", err)
	}

	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "fwrm", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("snapfw/fwrm is left after the VM was deleted (err=%v)", err)
	}
	if _, err := os.Stat(other); err != nil {
		t.Errorf("another VM's bundle went: %v", err)
	}
}

// A --keep-disks delete of a VM with snapshots is refused, here on the path
// of a VM whose domain is gone: its snapshot records and firmware bundles
// would stay keyed by the name, for a later VM of the name to list and
// remove. The VM, its snapshot record and its bundle stay.
//
// Mutation: drop keepDisksSnapshotRefusal from deleteVM: red.
func TestDeleteVM_KeepDisksOfAVMWithSnapshotsIsRefused(t *testing.T) {
	ctx := adminCtx()
	s := firmwareSnapshotVM(t, "fwkeep")
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fwkeep", Name: "s1"}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	_, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "fwkeep", Force: true, KeepDisks: true})
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv snapshot rm fwkeep") {
		t.Fatalf("DeleteVM --keep-disks of a VM with a snapshot = %v; want FailedPrecondition naming lv snapshot rm", err)
	}
	if _, err := os.Stat(lv.SnapshotFirmwareBundlePath(s.dataDir, "fwkeep", "s1")); err != nil {
		t.Errorf("the refused delete removed the firmware bundle: %v", err)
	}
	if vm, err := corrosion.GetVM(ctx, s.db, "fwkeep"); err != nil || vm == nil {
		t.Errorf("the refused delete took the VM's record: %+v, %v", vm, err)
	}
	if snaps, err := corrosion.ListSnapshots(ctx, s.db, "fwkeep"); err != nil || len(snaps) != 1 {
		t.Errorf("snapshot records after the refused delete = %+v, %v; want s1", snaps, err)
	}
}

// The bundle is kept while the VM still exists: a delete that is refused (here
// by an operation in progress) and the helper itself, called with a live row.
func TestDeleteVM_FirmwareBundlesStayWhileTheVMExists(t *testing.T) {
	ctx := adminCtx()
	s := firmwareSnapshotVM(t, "fwlive")
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fwlive", Name: "s1"}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	bundle := lv.SnapshotFirmwareBundlePath(s.dataDir, "fwlive", "s1")

	s.removeVMFirmwareBundles(ctx, "fwlive") // the row is live
	if _, err := os.Stat(bundle); err != nil {
		t.Fatalf("a live VM's bundle was removed: %v", err)
	}
}

func TestDeleteVM_FirmwareBundlesStayWhenTheDeleteFails(t *testing.T) {
	ctx := adminCtx()
	s := firmwareSnapshotVM(t, "fwfail")
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fwfail", Name: "s1"}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	bundle := lv.SnapshotFirmwareBundlePath(s.dataDir, "fwfail", "s1")
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "fwfail-nope", Force: true}); err == nil {
		t.Fatal("deleting a VM that does not exist succeeded")
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Errorf("another VM's failed delete removed this bundle: %v", err)
	}
}

// The same on the main delete path: the VM's domain is defined here, as on the
// lab, rather than gone (the stale-record path above).
func TestDeleteVM_WithADomainRemovesItsSnapshotFirmwareBundles(t *testing.T) {
	ctx := adminCtx()
	s := firmwareSnapshotVM(t, "fwdom")
	s.images = image.NewStore(s.dataDir)
	if err := s.virt.DefineDomain(`<domain><name>fwdom</name><uuid>8a1b2c3d-0000-4000-8000-0000000000cc</uuid></domain>`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fwdom", Name: "s1"}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	dir := filepath.Dir(lv.SnapshotFirmwareBundlePath(s.dataDir, "fwdom", "s1"))
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("no bundle was captured: %v", err)
	}
	if _, err := s.DeleteVM(ctx, &pb.DeleteVMRequest{Name: "fwdom", Force: true}); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	if s.virt.DomainExists("fwdom") {
		t.Fatal("the domain survived: this did not take the main delete path")
	}
	if _, err := os.Lstat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("snapfw/fwdom is left after the VM was deleted (err=%v)", err)
	}
}
