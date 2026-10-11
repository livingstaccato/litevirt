//go:build unix

package grpcapi

// A VM disk is the guest's data: every disk file the daemon writes anew is the
// owner's alone (0600), and every directory it makes to hold one is searchable
// but not listable (0711) — qemu, running as its own user once libvirt has
// labelled the FILE, must still resolve the path. A file or directory that
// already exists is never changed (no backfill), but a copy of an old 0644 disk
// — a migration's, a restore's — is a new file and gets the new mode.

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

func umask022(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
}

func wantMode(t *testing.T, p string, want os.FileMode) {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatalf("stat %s: %v", p, err)
	}
	if got := fi.Mode().Perm(); got != want {
		t.Errorf("%s is %04o, want %04o", p, got, want)
	}
}

// A cold migration's copy lands owner-only, even of a source disk that is
// 0644 (made by an older build), and the disk directory it makes on the target
// is 0711.
//
// Mutations: the receive's chmod back to 0o644 — the file goes red; its
// MkdirAll at 0o755 — the directory goes red.
func TestReceiveMigrationDisk_TheCopyIsOwnerOnly(t *testing.T) {
	umask022(t)
	f := newColdDiskFixture(t)
	f.writeSource(t, []byte("guest data"))
	if err := os.Chmod(f.src.hostDiskFile(f.path), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("streamColdDisk: %v", err)
	}
	wantMode(t, f.path, 0o600)
	wantMode(t, filepath.Dir(f.path), 0o711)
}

// The copy without qemu-img (a qcow2 move on a host that has none) writes a
// new file owner-only.
//
// Mutation: copyFileWithProgress's create at 0o644 — this goes red.
func TestCopyFileWithProgress_ANewFileIsOwnerOnly(t *testing.T) {
	umask022(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.WriteFile(src, []byte("guest data"), 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "dst")
	if err := copyFileWithProgress(context.Background(), src, dst, func(*pb.MoveVolumeProgress) error { return nil }); err != nil {
		t.Fatal(err)
	}
	wantMode(t, dst, 0o600)
}

// A restore's staging directory, when the restore makes it, is 0711; the temp
// in it is CreateTemp's 0600, as on main.
//
// Mutation: stagingTemp's MkdirAll at 0o755 — this goes red.
func TestStagingTemp_ANewDirectoryIsSearchableOnly(t *testing.T) {
	umask022(t)
	dir := filepath.Join(t.TempDir(), "pool")
	tmp, err := stagingTemp(filepath.Join(dir, "vm-root.qcow2"))
	if err != nil {
		t.Fatal(err)
	}
	wantMode(t, dir, 0o711)
	wantMode(t, tmp, 0o600)
}

// The local disks directory an import makes is 0711.
//
// Mutation: importPoolDir's MkdirAll at 0o755 — this goes red.
func TestImportPoolDir_ANewDisksDirIsSearchableOnly(t *testing.T) {
	umask022(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	dir, err := s.importPoolDir(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	wantMode(t, dir, 0o711)
}

// A replica increment's directory, when it makes it, is 0711; the replica is
// CreatePoolTemp's 0600, as on main.
//
// Mutation: forkRawAndApply's MkdirAll at 0o755 — this goes red.
func TestForkRawAndApply_ANewDirectoryIsSearchableOnly(t *testing.T) {
	umask022(t)
	dir := filepath.Join(t.TempDir(), "replicas")
	p, err := forkRawAndApply(dir, "r1.raw", "", 4096, func(*os.File) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	wantMode(t, dir, 0o711)
	wantMode(t, p, 0o600)
}

// A snapshot's firmware bundle holds the VM's UEFI variables and TPM state —
// Secure Boot keys, sealed secrets — so it is owner-only, and the snapshot
// directory made for it is 0711.
//
// Mutations: the bundle created with os.Create again — the file goes red; its
// MkdirAll at 0o755 — the directory goes red.
func TestCreateSnapshot_FirmwareBundleIsOwnerOnly(t *testing.T) {
	umask022(t)
	s := testServer(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	spec := `{"name":"fw1","secure_boot":true,"firmware":"uefi","uuid":"u-fw1"}`
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "fw1", HostName: s.hostName, Spec: spec, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	nv := lv.NvramPath(s.dataDir, "fw1")
	if err := os.MkdirAll(filepath.Dir(nv), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nv, []byte("uefi vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fw1", Name: "s1"}); err != nil {
		t.Fatalf("CreateSnapshot: %v", err)
	}
	bundle, err := lv.SafeSnapshotFirmwareBundlePath(s.dataDir, "fw1", "s1")
	if err != nil {
		t.Fatal(err)
	}
	wantMode(t, bundle, 0o600)
	wantMode(t, filepath.Dir(bundle), 0o711)
}

// A new UEFI VM's NVRAM directory, when its create makes it, is 0711: qemu
// opens the vars file (libvirt's, 0600 and labelled) through it.
//
// Mutation: the nvram MkdirAll at 0o755 — this goes red.
func TestApplyFirmwareConfig_ANewNvramDirIsSearchableOnly(t *testing.T) {
	umask022(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.firmware = lv.FirmwarePaths{Code: "/c", Vars: "/v", SecbootCode: "/sc", MsVars: "/mv"}
	cfg := &lv.VMConfig{Name: "uefi1"}
	if err := s.applyFirmwareConfig(cfg, &pb.VMSpec{Name: "uefi1", Firmware: "uefi", SecureBoot: true}); err != nil {
		t.Fatal(err)
	}
	if cfg.NvramPath == "" {
		t.Fatal("no NVRAM path was configured")
	}
	wantMode(t, filepath.Dir(cfg.NvramPath), 0o711)
}
