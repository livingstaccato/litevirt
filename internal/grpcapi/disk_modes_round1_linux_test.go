//go:build linux

package grpcapi

// Fix round 1 of fix/vm-disk-modes: a narrowing is a backstop, never a new way
// for an operation main allowed to fail (a filesystem that refuses chmod);
// real qemu-img writes into the file it is handed; every directory made for
// disks is 0711.

import (
	"bytes"
	"context"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/diskmode"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// refuseChmod stands in a filesystem that refuses every chmod, and returns
// what the operation logged.
func refuseChmod(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	t.Cleanup(diskmode.SetFchmodForTest(func(*os.File, fs.FileMode) error { return syscall.EPERM }))
	return &buf
}

func wantWarned(t *testing.T, log *bytes.Buffer, path string) {
	t.Helper()
	if !strings.Contains(log.String(), path) || !strings.Contains(log.String(), "operation not permitted") {
		t.Errorf("no warning naming %s and the error:\n%s", path, log.String())
	}
}

func diskModeInode(t *testing.T, p string) uint64 {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

// M2: a convert whose output cannot be narrowed still succeeds, and says so.
//
// Mutation: convertImageWith returns the Narrow error again — this goes red.
func TestConvertImage_ARefusedChmodNeverFailsTheCopy(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	umask022(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	log := refuseChmod(t)
	// A destination its caller made wider than its owner: convertImage makes
	// one it creates itself owner-only, so only such a file is narrowed.
	fresh := filepath.Join(dir, "fresh.qcow2")
	if err := os.WriteFile(fresh, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := convertImage(context.Background(), src, "qcow2", nil, fresh, func(*pb.MoveVolumeProgress) error { return nil }); err != nil {
		t.Fatalf("the convert failed on a refused chmod: %v", err)
	}
	wantWarned(t, log, fresh)
}

// M4: real qemu-img convert writes into the very file it is handed — same
// inode, still 0600 — with no narrowing to mask it (chmod refused).
//
// Mutation: hand qemu-img a path that does not exist yet — the inode check
// has nothing to compare and the mode is qemu-img's 0644: red.
func TestConvertImage_RealQemuImgKeepsThePreMadeInode(t *testing.T) {
	if _, err := exec.LookPath("qemu-img"); err != nil {
		t.Skip("qemu-img not installed")
	}
	umask022(t)
	dir := t.TempDir()
	src := filepath.Join(dir, "src.qcow2")
	if err := qcow2.Create(src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	refuseChmod(t)
	f, err := os.CreateTemp(dir, ".repl-*.tmp")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	before := diskModeInode(t, f.Name())
	if err := convertImage(context.Background(), src, "qcow2", nil, f.Name(), func(*pb.MoveVolumeProgress) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if diskModeInode(t, f.Name()) != before {
		t.Error("qemu-img replaced the file it was handed")
	}
	wantMode(t, f.Name(), 0o600)
}

// M2: a cold migration's copy is placed although its chmod is refused.
//
// Mutation: the receive fails on the chmod again — this goes red.
func TestReceiveMigrationDisk_ARefusedChmodNeverFailsTheCopy(t *testing.T) {
	f := newColdDiskFixture(t)
	f.writeSource(t, []byte("guest data"))
	log := refuseChmod(t)
	if err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "raw"); err != nil {
		t.Fatalf("the copy failed on a refused chmod: %v", err)
	}
	if got, _ := os.ReadFile(f.path); string(got) != "guest data" {
		t.Fatalf("target holds %q", got)
	}
	if !strings.Contains(log.String(), "operation not permitted") {
		t.Errorf("no warning:\n%s", log.String())
	}
}

// M2: an import placed by copy is placed although its chmod is refused.
//
// Mutation: copyIntoPlace fails on the chmod again — this goes red.
func TestPlaceNoReplace_ARefusedChmodNeverFailsTheImport(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, ".a.convert-x"), filepath.Join(dir, "a.qcow2")
	if err := os.WriteFile(src, []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := refuseChmod(t)
	if err := placeNoReplace(context.Background(), src, dst, nil); err != nil {
		t.Fatalf("the import failed on a refused chmod: %v", err)
	}
	if b, _ := os.ReadFile(dst); string(b) != "ours" {
		t.Fatalf("placed %q", b)
	}
	if !strings.Contains(log.String(), "operation not permitted") {
		t.Errorf("no warning:\n%s", log.String())
	}
}

// M2: a snapshot's firmware bundle is written although its chmod is refused.
//
// Mutation: the bundle write fails on the chmod — this goes red.
func TestCreateSnapshot_ARefusedChmodNeverFailsTheBundle(t *testing.T) {
	s := testServer(t)
	s.virt = libvirtfake.New()
	s.dataDir = t.TempDir()
	ctx := adminCtx()
	spec := `{"name":"fw2","secure_boot":true,"firmware":"uefi","uuid":"u-fw2"}`
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "fw2", HostName: s.hostName, Spec: spec, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	nv := lv.NvramPath(s.dataDir, "fw2")
	if err := os.MkdirAll(filepath.Dir(nv), 0o711); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nv, []byte("uefi vars"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := refuseChmod(t)
	if _, err := s.CreateSnapshot(ctx, &pb.CreateSnapshotRequest{VmName: "fw2", Name: "s1"}); err != nil {
		t.Fatalf("the snapshot failed on a refused chmod: %v", err)
	}
	bundle, _ := lv.SafeSnapshotFirmwareBundlePath(s.dataDir, "fw2", "s1")
	wantWarned(t, log, bundle)
}

// M1: hotplug's staging directory, when the attach makes it, is 0711.
//
// Mutation: stageQcow2's MkdirAll at 0o755 — this goes red.
func TestStageQcow2_ANewDirectoryIsSearchableOnly(t *testing.T) {
	umask022(t)
	dir := filepath.Join(t.TempDir(), "disks")
	tmp := filepath.Join(dir, ".vm-data.attach.tmp")
	if err := stageQcow2(tmp, 1<<20); err != nil {
		t.Fatal(err)
	}
	wantMode(t, dir, 0o711)
	wantMode(t, tmp, 0o600)
}

// M1: every site that makes a directory to hold VM disks makes it through
// diskmode.MkdirAll (0711), so docs/storage.md's "File modes" is true of all
// of them. The sites sit inside flows a unit test cannot reach one by one
// (clone into a pool, a linked clone's disk dir, the --with-storage stub, the
// live move's destination, an upload); this pins each file's source.
//
// Mutation: any of them back to os.MkdirAll(…, 0o755) — this goes red.
func TestDiskDirSites_MakeDirsThroughDiskmode(t *testing.T) {
	allowed := map[string][]string{
		// receiveFileNoClobber: replicaDirMode (0711).
		"storage_contents.go": {"os.MkdirAll(dir, dirMode)"},
		// Holds 0700 MkdirTemp dirs only.
		"vmimport.go": {`os.MkdirAll(filepath.Join(s.dataDir, "imports"), 0o755)`},
	}
	for _, f := range []string{"clone_target.go", "templates.go", "migrate.go", "hotplug_disk.go", "storage_contents.go",
		"move_live.go", "migrate_cold_disk.go", "restore_dest.go", "vmimport.go", "replica_increment.go", "snapshot.go", "firmware.go"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(b), "\n") {
			if !strings.Contains(line, "os.MkdirAll(") {
				continue
			}
			ok := false
			for _, a := range allowed[f] {
				if strings.Contains(line, a) {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s:%d makes a directory with os.MkdirAll, not diskmode.MkdirAll: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}
