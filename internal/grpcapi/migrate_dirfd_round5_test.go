package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// The qcow2 (flatten) source read: coldDiskSourceCheck judges the overlay by
// path, the hook swaps the disk's final component for a link to another
// tenant's image, and the flatten must refuse it (the top layer is opened
// O_NOFOLLOW and judged as the open file) instead of shipping it.
//
// Red on d0fb47b0a: the flatten opened the name with os.Open.
// Mutation: drop NoFollowSource in flattenColdDisk - the image is shipped.
func TestStreamColdDisk_FlattenSourceSwappedForALinkIsRefused(t *testing.T) {
	f := newColdDiskFixture(t)
	const size = 1 << 20
	f.recordTemplateBase(t)
	baseDir := filepath.Dir(f.src.hostDiskFile(f.path))
	if err := os.MkdirAll(baseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	base := filepath.Join(baseDir, "tpl-base.qcow2")
	if err := qcow2.Create(base, size, nil); err != nil {
		t.Fatal(err)
	}
	sp := f.src.hostDiskFile(f.path)
	if err := qcow2.CreateWithBacking(sp, base, size, nil); err != nil {
		t.Fatalf("create overlay: %v", err)
	}
	other := filepath.Join(t.TempDir(), "other-tenant.qcow2")
	if err := qcow2.Create(other, 3*size, nil); err != nil {
		t.Fatal(err)
	}
	f.src.SetColdSourceReadHookForTest(func() {
		_ = os.Remove(sp)
		if err := os.Symlink(other, sp); err != nil {
			t.Errorf("swap: %v", err)
		}
	})
	err := f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "qcow2")
	if err == nil {
		t.Errorf("streamColdDisk flattened a link swapped in as the disk")
	}
	if info, ierr := qcow2.Info(f.path); ierr == nil && info.VirtualSize == 3*size {
		t.Errorf("the source shipped the image the link pointed to (virtual size %d)", info.VirtualSize)
	}
}

// A FIFO swapped in as the disk, after the checks, is refused promptly: only a
// regular file is read.
//
// Mutation: drop the IsRegular check in streamColdDisk - the read hangs or ships
// nothing sensible and this is red.
func TestStreamColdDisk_AFifoSwappedInAsTheDiskIsRefused(t *testing.T) {
	f := newColdDiskFixture(t)
	f.writeSource(t, []byte("the disk"))
	sp := f.src.hostDiskFile(f.path)
	f.src.SetColdSourceReadHookForTest(func() {
		_ = os.Remove(sp)
		if err := syscall.Mkfifo(sp, 0o600); err != nil {
			t.Errorf("mkfifo: %v", err)
		}
	})
	done := make(chan error, 1)
	go func() { done <- f.src.streamColdDisk(adminCtx(), f.client, "os1", f.disk, "raw") }()
	select {
	case err := <-done:
		if err == nil {
			t.Errorf("a FIFO swapped in as the disk was read")
		}
	case <-time.After(20 * time.Second):
		t.Fatal("streamColdDisk hung on a FIFO")
	}
	if _, err := os.Lstat(f.path); err == nil {
		t.Errorf("a file reached the target from a FIFO")
	}
}

// The firmware discard removes a stub through the directory it judges: with the
// stub's directory swapped for a link to a directory holding a same-named file,
// that file survives.
//
// Mutation: os.Remove(s.hostDiskFile(p)) in removeDiscardedStubs - red.
func TestRemoveDiscardedStubsDoesNotFollowASwappedDirectory(t *testing.T) {
	ctx := adminCtx()
	s := testServer(t)
	s.hostName = "here"
	s.db.SetClusterPolicyGate(func() bool { return true }) // stub records are kept
	victimDir := t.TempDir()
	dir := filepath.Join(s.dataDir, "disks", "sub")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	stub := filepath.Join(dir, "stub.qcow2")
	if err := os.WriteFile(stub, []byte("stub"), 0o600); err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(victimDir, "stub.qcow2")
	if err := os.WriteFile(victim, []byte("victim"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "v", HostName: "other", State: "stopped", Spec: `{"name":"v"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	s.recordMade(ctx, &s.migrationStubs, "v", stub)
	if err := os.Rename(dir, dir+".gone"); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victimDir, dir); err != nil {
		t.Fatal(err)
	}
	s.removeDiscardedStubs(ctx, "v", []string{stub})
	if b, err := os.ReadFile(victim); err != nil || string(b) != "victim" {
		t.Errorf("the discard removed the file behind the swapped link (err %v, %q)", err, b)
	}
}

// The root is judged for what the descriptor it opened names, not for the path
// string that was resolved just before: a pool directory swapped for a link
// between the resolve and the open is refused.
//
// Mutation: hand the check the resolved path instead of the readback - the
// swapped link is accepted and this is red.
func TestDiskRootCheckJudgesWhatWasOpened(t *testing.T) {
	data, other := t.TempDir(), t.TempDir()
	s := &Server{hostName: "h", dataDir: data, pkiDir: t.TempDir()}
	root := filepath.Join(data, "mounts", "nfs1", "p")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	rootOpenHook = func() {
		_ = os.Rename(root, root+".was")
		_ = os.Symlink(other, root)
	}
	t.Cleanup(func() { rootOpenHook = nil })
	pd, err := s.openDiskDir(root, ".", false, false)
	if err == nil {
		pd.close()
		t.Errorf("a pool directory swapped for a link after it was resolved was opened")
	} else if !errors.Is(err, errBeneath) {
		t.Errorf("err = %v, want errBeneath", err)
	}
}

// A root below an area is made from the area's descriptor: with a link on the
// way (mounts/nfs1/a -> elsewhere), nothing is created through it.
//
// Mutation: MkdirAll(rootFS) by path before the walk (the old order) - the
// directories appear in the link's target and this is red.
func TestOpenDiskDirCreateDoesNotCreateThroughALinkOnTheWay(t *testing.T) {
	data, elsewhere := t.TempDir(), t.TempDir()
	s := &Server{hostName: "h", dataDir: data, pkiDir: t.TempDir()}
	if err := os.MkdirAll(filepath.Join(data, "mounts", "nfs1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(data, "mounts", "nfs1", "a")); err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(data, "mounts", "nfs1", "a", "b", "p")
	pd, err := s.openDiskDir(root, "sub", true, false)
	if err == nil {
		pd.close()
		t.Errorf("a root with a link on the way was opened")
	}
	if ents, _ := os.ReadDir(elsewhere); len(ents) != 0 {
		t.Errorf("directories were created through the link: %v", ents)
	}
}

// The root-judgement rows the re-review ran beyond TestDiskRootCheck.
func TestDiskRootCheckRows(t *testing.T) {
	data, pki, other, vol := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	s := &Server{hostName: "h", dataDir: data, pkiDir: pki}
	mk := func(p string) string {
		t.Helper()
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
		return p
	}
	link := func(target, at string) string {
		t.Helper()
		mk(filepath.Dir(at))
		if err := os.Symlink(target, at); err != nil {
			t.Fatal(err)
		}
		return at
	}
	mk(filepath.Join(data, "mounts", "nfs2", "q"))
	cases := []struct {
		name string
		root string
		ok   bool
	}{
		{"outside areas, link to /etc", link("/etc", filepath.Join(other, "p-etc")), false},
		{"outside areas, link to /etc/cron.d", link("/etc/cron.d", filepath.Join(other, "p-cron")), false},
		{"outside areas, link to /", link("/", filepath.Join(other, "p-root")), false},
		{"outside areas, link to a dir inside pki", link(mk(filepath.Join(pki, "sub")), filepath.Join(other, "p-pkisub")), false},
		{"outside areas, link to the data dir", link(data, filepath.Join(other, "p-data")), false},
		{"outside areas, plain dir", mk(filepath.Join(other, "plain")), true},
		{"outside areas, link to another volume", link(vol, filepath.Join(other, "p-vol")), true},
		{"outside areas, link to a link to another volume", link(filepath.Join(other, "p-vol"), filepath.Join(other, "p-vol2")), true},
		{"below mounts/, link to /etc", link("/etc", filepath.Join(data, "mounts", "nfs1", "e")), false},
		{"below mounts/, link to pki", link(pki, filepath.Join(data, "mounts", "nfs1", "k")), false},
		{"below pools/, link to another volume", link(vol, filepath.Join(data, "pools", "v")), false},
		{"below mounts/, link to another export inside mounts/", link(filepath.Join(data, "mounts", "nfs2", "q"), filepath.Join(data, "mounts", "nfs1", "x")), true},
		{"below mounts/, relative link escaping", link("../../../"+filepath.Base(other), filepath.Join(data, "mounts", "nfs1", "r")), false},
	}
	for _, tc := range cases {
		pd, err := s.openDiskDir(tc.root, ".", false, false)
		if pd != nil {
			pd.close()
		}
		if (err == nil) != tc.ok {
			t.Errorf("%s: openDiskDir(%s) = %v, want ok=%v", tc.name, tc.root, err, tc.ok)
		}
	}
}
