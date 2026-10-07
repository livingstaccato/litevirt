package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Fix round 4, tests of the round-4 API (they do not compile on f3d45603).

// C-3: a VM's first arrival on a host where another project's pool maps its
// library's directory. The source sends the sha256 of the file it judged; the
// target admits a file with those very bytes (and records it), and nothing
// else.
func TestISORound4_AFirstArrivalIsAdmittedAsTheSameBytes(t *testing.T) {
	ctx := context.Background()
	s, _ := stubTarget(t)
	lib, here := libraryVM(t, s, "mig", "acme")
	if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
		HostName: s.hostName, Name: "o-disks", Driver: "dir", Target: lib, Project: "other", State: "active",
	}); err != nil {
		t.Fatal(err)
	}
	src := "/srv/source/acme-isos/install.iso"
	move := func(sum string, runtime bool) error {
		req := &pb.EnsureDisksRequest{VmName: "mig", InstallerIsoListed: true,
			InstallerIsoPaths: []string{src}, InstallerIsoRuntime: runtime}
		if sum != "" {
			req.InstallerIsoSha256 = map[string]string{src: sum}
		}
		_, err := s.EnsureDisks(adminCtx(), req)
		return err
	}
	for _, runtime := range []bool{true, false} {
		if err := move("", runtime); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("first arrival (runtime=%v) with no hash from the source: got %v, want FailedPrecondition", runtime, err)
		}
		if err := move(sha("another file"), runtime); status.Code(err) != codes.FailedPrecondition {
			t.Fatalf("first arrival (runtime=%v) whose bytes differ from the source's: got %v, want FailedPrecondition", runtime, err)
		}
	}
	if err := move(sha(isoBody), true); err != nil {
		t.Fatalf("first arrival of the very bytes the source judged: %v", err)
	}
	// It is recorded: the start here passes without the source.
	spec := vmSpecFor(vmRecord(t, s, "mig"))
	if _, _, err := s.resolveSpecISO(ctx, "mig", "acme", spec); err != nil {
		t.Fatalf("start after the arrival: %v", err)
	}
	// A file swapped in under the name since is refused.
	if err := os.Remove(here); err != nil {
		t.Fatal(err)
	}
	writeLibFile(t, here, isoBody+" from other")
	if _, _, err := s.resolveSpecISO(ctx, "mig", "acme", spec); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start after the file was swapped: got %v, want FailedPrecondition", err)
	}
}

// I-c: a pool directory on another network filesystem than the ISO's
// directory, per /proc/self/mountinfo, is not read: one tenant's dead NFS
// server does not refuse another tenant's starts. On the same device, or
// behind a link above its mount point, it is read and fails closed.
func TestISORound4_ADeadDirectoryOnAnotherFilesystemIsNotRead(t *testing.T) {
	s, _, _ := isoServer(t)
	lib, _ := libraryVMStopped(t, s, "v")
	root := t.TempDir()
	hung := filepath.Join(root, "nfs-target")
	linked := filepath.Join(root, "via-link")
	if err := os.Symlink(root, linked); err != nil {
		t.Fatal(err)
	}
	hung2 := filepath.Join(linked, "nfs2") // its mount point is listed below a link
	deadPool := func(name, target string) {
		if err := corrosion.UpsertStoragePool(context.Background(), s.db, corrosion.StoragePoolRecord{
			HostName: s.hostName, Name: name, Driver: "nfs", Source: "nas:/gone",
			Target: target, Project: "other", State: "active",
		}); err != nil {
			t.Fatal(err)
		}
	}
	deadPool("dead-nfs", hung)
	block := make(chan struct{})
	origP, origM, origT := isoDirProbe, isoMountInfo, isoDirProbeTimeout
	t.Cleanup(func() { close(block); isoDirProbe, isoMountInfo, isoDirProbeTimeout = origP, origM, origT })
	isoDirProbeTimeout = 200 * time.Millisecond
	var readMu sync.Mutex
	readSet := map[string]bool{}
	wasRead := func(p string) bool { readMu.Lock(); defer readMu.Unlock(); return readSet[p] }
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if p == hung || p == hung2 {
			readMu.Lock()
			readSet[p] = true
			readMu.Unlock()
			<-block
		}
		return origP(p)
	}
	real, err := origM()
	if err != nil {
		t.Skipf("no mount table: %v", err)
	}
	libMount, ok := mountOf(real, mustEval(t, lib))
	if !ok {
		t.Skip("the library's mount is not in the mount table")
	}
	mounts := func(dev string, points ...string) func() ([]mountEntry, error) {
		return func() ([]mountEntry, error) {
			out := append([]mountEntry(nil), real...)
			for _, p := range points {
				out = append(out, mountEntry{point: p, dev: dev, fstype: "nfs4"})
			}
			return out, nil
		}
	}
	isoMountInfo = mounts("0:999", hung)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "v")); err != nil || wasRead(hung) {
		t.Fatalf("start with another tenant's dead NFS directory on another filesystem: %v (read: %v)", err, wasRead(hung))
	}
	// On the library's own device it is read, and fails closed.
	isoMountInfo = mounts(libMount.dev, hung)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "v")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with a dead directory on the library's device: got %v, want FailedPrecondition", err)
	}
	// Reached through a link above its mount point: read, and fails closed.
	deadPool("dead-nfs2", hung2)
	isoMountInfo = mounts("0:999", hung, hung2)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "v")); status.Code(err) != codes.FailedPrecondition || !wasRead(hung2) {
		t.Fatalf("start with a dead directory behind a link above its mount point: got %v (read %v), want FailedPrecondition", err, wasRead(hung2))
	}
}

// N-C2: a USB stick under /run/media and an ISO in a home directory work for
// an Admin's create, a main-era VM's start and a move; a key, a key renamed
// .iso, an ISO in a dot-directory and a file swapped after the check do not.
func TestISORound4_UserDataRootsHoldISOsAndNothingElse(t *testing.T) {
	s, fake, _ := isoServer(t)
	root := t.TempDir()
	home, run := filepath.Join(root, "home"), filepath.Join(root, "run")
	t.Cleanup(storage.SetUserDataRootsForTest([]string{home, run}))
	mk := func(p, body string) string {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		writeLibFile(t, p, body)
		return p
	}
	stick := mk(filepath.Join(run, "media", "u", "STICK", "x.iso"), opticalImage("stick"))
	virtio := mk(filepath.Join(home, "u", "isos", "virtio-win.iso"), opticalImage("virtio"))
	key := mk(filepath.Join(home, "u", ".ssh", "id_rsa"), "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	renamed := mk(filepath.Join(home, "u", "isos", "id_rsa.iso"), "-----BEGIN OPENSSH PRIVATE KEY-----\n")
	dotISO := mk(filepath.Join(home, "u", ".cache", "x.iso"), opticalImage("cached"))

	if _, err := s.CreateVM(adminCtx(), isoCreate("stick", stick, "")); err != nil {
		t.Fatalf("admin create with a USB stick ISO under /run/media: %v", err)
	}
	legacyVM(t, s, fake, "old", virtio)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "old")); err != nil {
		t.Fatalf("start of a main-era VM whose ISO is in a home directory: %v", err)
	}
	if _, err := s.EnsureDisks(adminCtx(), &pb.EnsureDisksRequest{VmName: "old", InstallerIsoListed: true,
		InstallerIsoPaths: []string{virtio}, InstallerIsoRuntime: true}); err != nil {
		t.Fatalf("a live move (a drain) of that VM onto this host: %v", err)
	}
	for i, p := range []string{key, renamed, dotISO} {
		name := "bad" + string(rune('a'+i))
		if _, err := s.CreateVM(adminCtx(), isoCreate(name, p, "")); status.Code(err) != codes.InvalidArgument {
			t.Errorf("admin create with %s: got %v, want InvalidArgument", p, err)
		}
	}
	legacyVM(t, s, fake, "leak", renamed)
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "leak")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start of a main-era VM whose ISO is a key renamed .iso: got %v, want FailedPrecondition", err)
	}
	// The signature is read from the file opened, not from a name checked
	// before: a swap between the check and the open is refused.
	// (Rewritten in place, so it is the same file by every identity check.)
	t.Cleanup(func() { isoBeforeOpen = nil })
	isoBeforeOpen = func(p string) {
		if p == virtio {
			writeLibFile(t, virtio, "-----BEGIN OPENSSH PRIVATE KEY-----\n")
		}
	}
	if _, err := s.PrepareHardwareForStart(context.Background(), vmRecord(t, s, "old")); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("start with the ISO swapped for a key after the check: got %v, want FailedPrecondition", err)
	}
}

// Identity records of VMs that no longer exist, and temp files a crash left,
// are swept; a live VM's record is kept.
func TestISORound4_TheSweepRemovesOrphanRecords(t *testing.T) {
	s, _, _ := isoServer(t)
	_, _ = libraryVMStopped(t, s, "v")
	live := isoIdentityKey("v", vmSpecFor(vmRecord(t, s, "v")))
	dir := filepath.Join(s.dataDir, isoIdentityDir)
	for _, n := range []string{"uuid-0000-dead.json", "name-gone.json", ".tmp-123"} {
		writeLibFile(t, filepath.Join(dir, n), "{}")
	}
	orig := isoIdentitySweepGrace
	t.Cleanup(func() { isoIdentitySweepGrace = orig })
	if err := s.SweepISOIdentities(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := identityFiles(t, s); len(got) != 4 {
		t.Fatalf("records younger than the grace were swept: %v", got)
	}
	isoIdentitySweepGrace = 0
	if err := s.SweepISOIdentities(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := identityFiles(t, s); len(got) != 1 || got[0] != live+".json" {
		t.Fatalf("records after the sweep = %v, want only %s.json", got, live)
	}
}

// I-b: the sync loop does not hang on a global library whose directory does
// not answer.
func TestISORound4_TheSyncPassDoesNotHang(t *testing.T) {
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	lib := globalLibrary(t, s)
	if err := corrosion.SetISOLibraryMode(context.Background(), s.db, corrosion.ISOLibrarySync, "test"); err != nil {
		t.Fatal(err)
	}
	block := make(chan struct{})
	origP, origT := isoDirProbe, isoDirProbeTimeout
	t.Cleanup(func() { close(block); isoDirProbe, isoDirProbeTimeout = origP, origT })
	isoDirProbeTimeout = 200 * time.Millisecond
	isoDirProbe = func(p string) (string, os.FileInfo, error) {
		if p == lib {
			<-block
		}
		return origP(p)
	}
	done := make(chan error, 1)
	go func() { done <- s.SyncISOLibrary(context.Background()) }()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "did not answer") {
			t.Fatalf("sync pass against an unanswering library: %v, want it to say so", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the sync pass hung on an unanswering library")
	}
}

// m-6: the pin shows who pinned it, not a raw marker.
func TestISORound4_ThePinIsShownAsOne(t *testing.T) {
	s, _, _ := isoServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.pinImplicitISOLibraryMode(adminCtx())
	m, err := s.GetISOLibraryMode(adminCtx(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasPrefix(m.GetSetBy(), "pin:") || !strings.Contains(m.GetSetBy(), "pinned") {
		t.Fatalf("set_by = %q", m.GetSetBy())
	}
}
