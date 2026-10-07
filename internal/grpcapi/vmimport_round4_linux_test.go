package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// deadImportInstance names a daemon process of this host that is gone.
const deadImportInstance = "a-daemon-gone"

// plantDeadLeftover writes body at p the way an import of this host left it
// when its daemon went away: recorded beside the journal in the state it was
// left in, and with the origin xattr where the pool keeps user xattrs.
func plantDeadLeftover(t *testing.T, s *Server, p, body string, scratch bool) {
	t.Helper()
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = setImportOrigin(p, s.hostName+"/"+deadImportInstance+"/imp-1")
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	rec, ok := placementOf(p, fi, "imp-1", scratch, !scratch)
	if !ok {
		t.Fatal("no file identity")
	}
	rec.Instance = deadImportInstance
	if err := s.writeImportPlacement(rec); err != nil {
		t.Fatal(err)
	}
}

// noUserXattrs takes user xattrs away, as NFS before 4.2, CIFS and most FUSE
// filesystems do.
func noUserXattrs(t *testing.T) {
	t.Helper()
	set, get := setImportOrigin, getImportOrigin
	setImportOrigin = func(string, string) error { return syscall.ENOTSUP }
	getImportOrigin = func(string) (string, bool) { return "", false }
	t.Cleanup(func() { setImportOrigin, getImportOrigin = set, get })
}

func importAs(s *Server, t *testing.T, name string) error {
	return s.ImportVM(&fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{smallImportFrame(t, name, false)}})
}

func keptAside(t *testing.T, dst, body string) {
	t.Helper()
	aside, _ := filepath.Glob(dst + ".orphan-*")
	if len(aside) != 1 {
		t.Fatalf("leftover kept as %v, want one file beside the disk", aside)
	}
	if b, _ := os.ReadFile(aside[0]); string(b) != body {
		t.Fatalf("the leftover kept aside holds %q", b)
	}
}

// I-1. A dead import's leftover that a later flow rewrote in place (qemu-img
// convert into an existing path keeps the inode, and its xattr) is no longer
// that import's leftover: while it is fresh it may still be being written, and
// it is never moved aside.
func TestImportVM_AReplicaWrittenIntoADeadLeftoverIsNeverMovedAside(t *testing.T) {
	cases := map[string]func(t *testing.T, dst string, was os.FileInfo) string{
		"rewritten in place": func(t *testing.T, dst string, was os.FileInfo) string {
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_TRUNC, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString("replica!"); err != nil {
				t.Fatal(err)
			}
			f.Close()
			later := was.ModTime().Add(time.Second)
			if err := os.Chtimes(dst, later, later); err != nil {
				t.Fatal(err)
			}
			return "replica!"
		},
		"grown in place, its time put back": func(t *testing.T, dst string, was os.FileInfo) string {
			f, err := os.OpenFile(dst, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(" and more"); err != nil {
				t.Fatal(err)
			}
			f.Close()
			if err := os.Chtimes(dst, was.ModTime(), was.ModTime()); err != nil {
				t.Fatal(err)
			}
			return "crashed! and more"
		},
		"another file, same size and time": func(t *testing.T, dst string, was os.FileInfo) string {
			other := dst + ".new"
			if err := os.WriteFile(other, []byte("replica!"), 0o600); err != nil {
				t.Fatal(err)
			}
			if o, ok := getImportOrigin(dst); ok {
				_ = setImportOrigin(other, o)
			}
			if err := os.Chtimes(other, was.ModTime(), was.ModTime()); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(other, dst); err != nil {
				t.Fatal(err)
			}
			return "replica!"
		},
	}
	for name, rewrite := range cases {
		t.Run(name, func(t *testing.T) {
			s, dst := orphanFixture(t, "web")
			plantDeadLeftover(t, s, dst, "crashed!", false)
			was, err := os.Lstat(dst)
			if err != nil {
				t.Fatal(err)
			}
			body := rewrite(t, dst, was)
			refusedAndUntouched(t, s, "web", dst, body)
		})
	}
}

// CR-3. On a pool without user xattrs the record alone shows the leftover,
// its siblings and its scratch file are a dead import's: the re-import right
// after the crash goes ahead.
func TestImportVM_APoolWithoutUserXattrsTakesAReimportRightAfterACrash(t *testing.T) {
	noUserXattrs(t)
	s, dst := orphanFixture(t, "web")
	dir := filepath.Dir(dst)
	plantDeadLeftover(t, s, dst, "crashed", false)
	plantDeadLeftover(t, s, filepath.Join(dir, "web-data.qcow2"), "crashed too", false)
	scratch := filepath.Join(dir, ".web-data.qcow2.convert-abc")
	plantDeadLeftover(t, s, scratch, "scratch", true)
	// A scratch file is recorded when it is created; qemu-img writes it after.
	f, err := os.OpenFile(scratch, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(", converted"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if err := importAs(s, t, "web"); err != nil {
		t.Fatalf("a re-import right after a crash, on a pool without user xattrs: %v", err)
	}
	keptAside(t, dst, "crashed")
}

// And there too a leftover written since it was recorded is not one.
func TestImportVM_WithoutUserXattrsALeftoverWrittenSinceIsNotOne(t *testing.T) {
	noUserXattrs(t)
	s, dst := orphanFixture(t, "web")
	plantDeadLeftover(t, s, dst, "crashed", false)
	later := time.Now().Add(time.Second)
	if err := os.Chtimes(dst, later, later); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "web", dst, "crashed")
}

// Where the pool keeps user xattrs, an origin there that names another
// import than the record does unbinds the record.
func TestImportVM_ALeftoverWhoseXattrNamesAnotherImportIsNotOne(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	plantDeadLeftover(t, s, dst, "crashed", false)
	was, err := os.Lstat(dst)
	if err != nil {
		t.Fatal(err)
	}
	setOriginForTest(t, dst, s.hostName+"/"+deadImportInstance+"/imp-2")
	if err := os.Chtimes(dst, was.ModTime(), was.ModTime()); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "web", dst, "crashed")
}

// A placed disk is recorded before it takes its name, in the state it takes
// it in: a crash right after placement leaves it recorded. A disk placed by a
// copy is recorded as the copy.
func TestImportWrites_ADiskIsRecordedBeforeAndAfterItsPlacement(t *testing.T) {
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "link", true: "copy"}[fallback], func(t *testing.T) {
			if fallback {
				noLinkNoRenameNoReplace(t)
			}
			stubQemuImg(t)
			s := concurrentImportServer(t, 10*oneDiskNeed())
			importDir, pool := t.TempDir(), t.TempDir()
			src := filepath.Join(importDir, "disk.raw")
			if err := writeFileHelper(src, make([]byte, 4096)); err != nil {
				t.Fatal(err)
			}
			dst := filepath.Join(pool, "web-root.qcow2")
			space := s.reserveImportSpace(importDir)
			defer space.release()
			w, forget := s.importWritesFor("imp-9", space)
			if !fallback {
				link := coldLink
				t.Cleanup(func() { coldLink = link })
				coldLink = func(o, n string) error {
					rec, ok := s.importPlacementOf(n)
					fi, err := os.Lstat(o)
					if !ok || err != nil || !rec.matches(fi) {
						t.Errorf("%s took its name before it was recorded as %s (%v, %v)", o, n, ok, err)
					}
					return link(o, n)
				}
			}
			if err := convertForeignDisk(context.Background(), src, "raw", dst, importDir, 1<<30, nil, w); err != nil {
				t.Fatal(err)
			}
			fi, err := os.Lstat(dst)
			if err != nil {
				t.Fatal(err)
			}
			rec, ok := s.importPlacementOf(dst)
			if !ok || !rec.matches(fi) || rec.ImportID != "imp-9" || rec.Scratch || rec.CtimeNs == 0 {
				t.Fatalf("the placed disk's record: %+v (%v)", rec, ok)
			}
			forget()
			if _, ok := s.importPlacementOf(dst); ok {
				t.Fatal("the import's record outlived it")
			}
		})
	}
}

// An import that ends, either way, leaves no record behind; a dead import's
// record whose file is gone goes too, and one whose file is there stays.
func TestImportVM_AnImportThatEndsLeavesNoRecords(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	dir := filepath.Dir(dst)
	gone, kept := filepath.Join(dir, "db-root.qcow2"), filepath.Join(dir, "db-data.qcow2")
	plantDeadLeftover(t, s, gone, "removed by hand", false)
	plantDeadLeftover(t, s, kept, "still there", false)
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	if err := importAs(s, t, "web"); err != nil {
		t.Fatal(err)
	}
	// The prune runs off the import's path.
	var left []string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		left, _ = filepath.Glob(filepath.Join(s.dataDir, importPlacementDirName, "*"))
		if len(left) == 1 {
			break
		}
	}
	if _, ok := s.importPlacementOf(kept); !ok || len(left) != 1 {
		t.Fatalf("records left: %v, want only %s's", left, kept)
	}
}

// A running import records a disk before it is placed; another import
// starting meanwhile does not take that record for a gone file's.
func TestImportWrites_ARunningImportsRecordOfADiskNotPlacedYetStays(t *testing.T) {
	s, dst := orphanFixture(t, "web")
	src := filepath.Join(t.TempDir(), "scratch")
	if err := os.WriteFile(src, []byte("converted"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordImportPlacement(dst, fi, "imp-running", false); err != nil {
		t.Fatal(err)
	}
	s.pruneImportPlacementsIn(filepath.Dir(dst), time.Now().Add(time.Minute))
	if _, ok := s.importPlacementOf(dst); !ok {
		t.Fatal("a running import's record of a disk it is about to place was dropped")
	}
}

// Another import running on this host writes only its own VM's files: its
// fresh disk beside a leftover of another name does not hold it.
func TestImportVM_AnotherRunningImportsDiskDoesNotHoldALeftover(t *testing.T) {
	s, dst := orphanFixture(t, "web-3")
	plantOld(t, dst, "leftover")
	release, err := s.claimImportNameAs("web-1", "imp-run")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	theirs := filepath.Join(filepath.Dir(dst), "web-1-root.qcow2")
	if err := os.WriteFile(theirs, []byte("being imported"), 0o600); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Lstat(theirs)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.recordImportPlacement(theirs, fi, "imp-run", false); err != nil {
		t.Fatal(err)
	}
	if err := importAs(s, t, "web-3"); err != nil {
		t.Fatalf("a re-import beside another running import's disk: %v", err)
	}
	keptAside(t, dst, "leftover")
	if b, _ := os.ReadFile(theirs); string(b) != "being imported" {
		t.Fatalf("the other import's disk now holds %q", b)
	}
}

// A fresh sibling named for the VM that dst is named for is that VM's, and
// may be its flow still writing: it holds even this host's dead leftover.
func TestImportVM_AFreshSiblingOfTheVMDstIsNamedForHoldsALeftover(t *testing.T) {
	s, dst := orphanFixture(t, "web-x")
	plantDeadLeftover(t, s, dst, "crashed", false)
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
		Name: "web", HostName: "other-host", Spec: "{}", State: "running", Project: "default",
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(filepath.Dir(dst), "web-x-data.qcow2"), []byte("writing"), 0o600); err != nil {
		t.Fatal(err)
	}
	refusedAndUntouched(t, s, "web-x", dst, "crashed")
}

// CR-1. A running VM's own disk beside a leftover is a disk something
// records, not a flow still writing: it never holds the leftover back.
func TestImportVM_ARecordedDiskBesideALeftoverDoesNotHoldIt(t *testing.T) {
	type sibling struct{ vm, file string }
	cases := []struct {
		name, imp string
		dead      bool
		vmDisk    *sibling // a VM, running, with a disk row naming file
		imageAt   string   // an image stored at this file
		vmOnly    *sibling // a VM, running, no row naming file
	}{
		{name: "web-1 running, re-import web-3", imp: "web-3", vmDisk: &sibling{"web-1", "web-1-root.qcow2"}},
		{name: "web-prod running, re-import web", imp: "web", vmDisk: &sibling{"web-prod", "web-prod-root.qcow2"}},
		{name: "a dead import's leftover beside web-1", imp: "web-3", dead: true, vmDisk: &sibling{"web-1", "web-1-root.qcow2"}},
		{name: "a disk of another VM at a custom path", imp: "web", vmDisk: &sibling{"db", "web-extra.qcow2"}},
		{name: "an image beside it", imp: "web", imageAt: "web-base.qcow2"},
		{name: "a file named for a live VM", imp: "web-3", vmOnly: &sibling{"web-1", "web-1-root-r.qcow2"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s, dst := orphanFixture(t, c.imp)
			dir := filepath.Dir(dst)
			if c.dead {
				plantDeadLeftover(t, s, dst, "leftover", false)
			} else {
				plantOld(t, dst, "leftover")
			}
			ctx := context.Background()
			if sb := c.vmDisk; sb != nil {
				p := filepath.Join(dir, sb.file)
				if err := os.WriteFile(p, []byte("running"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
					Name: sb.vm, HostName: s.hostName, Spec: "{}", State: "running", Project: "default",
				}, nil, []corrosion.DiskRecord{{VMName: sb.vm, DiskName: "root", HostName: s.hostName, Path: p, StorageType: "local"}}); err != nil {
					t.Fatal(err)
				}
			}
			if c.imageAt != "" {
				p := filepath.Join(dir, c.imageAt)
				if err := os.WriteFile(p, []byte("image"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := s.db.Execute(ctx,
					`INSERT INTO image_hosts (image_name, host_name, path, status, updated_at) VALUES ('base', 'test-host', ?, 'ready', ?)`,
					p, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			if sb := c.vmOnly; sb != nil {
				if err := os.WriteFile(filepath.Join(dir, sb.file), []byte("its replica"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{
					Name: sb.vm, HostName: s.hostName, Spec: "{}", State: "running", Project: "default",
				}, nil, nil); err != nil {
					t.Fatal(err)
				}
			}
			if err := importAs(s, t, c.imp); err != nil {
				t.Fatalf("a re-import beside a recorded disk: %v", err)
			}
			keptAside(t, dst, "leftover")
		})
	}
}

// But a fresh sibling nothing records — another host's conversion, a create
// still writing — holds it, a running VM beside it or not.
func TestImportVM_AnUnrecordedFreshSiblingStillHoldsALeftover(t *testing.T) {
	for _, sib := range []string{"web-3-data.qcow2", ".web-3-data.qcow2.convert-abc", ".web-3-data.qcow2.place-abc", "web-9-root.qcow2.tmp"} {
		t.Run(sib, func(t *testing.T) {
			s, dst := orphanFixture(t, "web-3")
			dir := filepath.Dir(dst)
			plantOld(t, dst, "leftover")
			running := filepath.Join(dir, "web-1-root.qcow2")
			if err := os.WriteFile(running, []byte("running"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
				Name: "web-1", HostName: s.hostName, Spec: "{}", State: "running", Project: "default",
			}, nil, []corrosion.DiskRecord{{VMName: "web-1", DiskName: "root", HostName: s.hostName, Path: running, StorageType: "local"}}); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, sib), []byte("writing"), 0o600); err != nil {
				t.Fatal(err)
			}
			refusedAndUntouched(t, s, "web-3", dst, "leftover")
		})
	}
}

// CR-2. A dead import's leftover, unchanged since it was left, is moved aside
// even when a VM whose name prefixes it exists: no replica or hotplug file of
// that VM can be a file nothing wrote since this host's import left it.
func TestImportVM_ADeadImportsLeftoverNamedLikeALiveVMIsMovedAside(t *testing.T) {
	for _, movedOn := range []bool{false, true} {
		t.Run(map[bool]string{false: "as left", true: "written since"}[movedOn], func(t *testing.T) {
			s, dst := orphanFixture(t, "web-x")
			plantDeadLeftover(t, s, dst, "crashed", false)
			if movedOn {
				later := time.Now().Add(time.Second)
				if err := os.Chtimes(dst, later, later); err != nil {
					t.Fatal(err)
				}
			}
			if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
				Name: "web", HostName: "other-host", Spec: "{}", State: "stopped", Project: "default",
			}, nil, nil); err != nil {
				t.Fatal(err)
			}
			if movedOn {
				refusedAndUntouched(t, s, "web-x", dst, "crashed")
				return
			}
			if err := importAs(s, t, "web-x"); err != nil {
				t.Fatalf("a re-import over this host's dead import's leftover beside VM web: %v", err)
			}
			keptAside(t, dst, "crashed")
		})
	}
}

// M-1. The copy fallback removes its source only while the source's name
// still holds the file it copied.
func TestPlaceNoReplace_ACopyNeverRemovesAFileThatTookTheSourcesName(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, ".a.convert-x"), filepath.Join(dir, "a.qcow2")
	if err := os.WriteFile(src, []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := placeCopy
	t.Cleanup(func() { placeCopy = saved })
	placeCopy = func(ctx context.Context, out, in *os.File, limit int64) error {
		err := saved(ctx, out, in, limit)
		theirs := filepath.Join(dir, "theirs")
		if werr := os.WriteFile(theirs, []byte("theirs"), 0o600); werr != nil {
			t.Fatal(werr)
		}
		if rerr := os.Rename(theirs, src); rerr != nil {
			t.Fatal(rerr)
		}
		return err
	}
	if err := placeNoReplace(context.Background(), src, dst, nil); err != nil {
		t.Fatalf("the copy was placed: %v", err)
	}
	if b, _ := os.ReadFile(src); string(b) != "theirs" {
		t.Fatalf("the file that took the source's name now holds %q", b)
	}
	if b, _ := os.ReadFile(dst); string(b) != "ours" {
		t.Fatalf("the placed copy holds %q", b)
	}
}

// A failed copy removes its temp only while it is still the file the copy
// created, and never takes the disk's name.
func TestPlaceNoReplace_AFailedCopyNeverRemovesAFileThatTookItsName(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	dir := t.TempDir()
	src, dst := filepath.Join(dir, ".a.convert-x"), filepath.Join(dir, "a.qcow2")
	if err := os.WriteFile(src, []byte("ours"), 0o600); err != nil {
		t.Fatal(err)
	}
	saved := placeCopy
	t.Cleanup(func() { placeCopy = saved })
	var temp string
	placeCopy = func(_ context.Context, out *os.File, _ *os.File, _ int64) error {
		temp = out.Name()
		theirs := filepath.Join(dir, "theirs")
		if werr := os.WriteFile(theirs, []byte("theirs"), 0o600); werr != nil {
			t.Fatal(werr)
		}
		if rerr := os.Rename(theirs, temp); rerr != nil {
			t.Fatal(rerr)
		}
		return errors.New("disk full")
	}
	if err := placeNoReplace(context.Background(), src, dst, nil); err == nil {
		t.Fatal("a failed copy reported success")
	}
	if b, _ := os.ReadFile(temp); string(b) != "theirs" {
		t.Fatalf("the file that took the copy's name now holds %q", b)
	}
	if _, err := os.Lstat(dst); !os.IsNotExist(err) {
		t.Fatalf("a failed copy left the disk's name taken: %v", err)
	}
	if b, _ := os.ReadFile(src); string(b) != "ours" {
		t.Fatalf("the source now holds %q", b)
	}
}

// M-2. The copy stops with the import, and the second write is reserved
// before it starts.
func TestPlaceNoReplace_ACopyStopsWithItsContextAndIsReservedFirst(t *testing.T) {
	noLinkNoRenameNoReplace(t)
	for _, c := range []string{"cancelled", "refused"} {
		t.Run(c, func(t *testing.T) {
			dir := t.TempDir()
			src, dst := filepath.Join(dir, ".a.convert-x"), filepath.Join(dir, "a.qcow2")
			if err := os.WriteFile(src, []byte("ours, 13 byte"), 0o600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var asked uint64
			copying := func(n uint64) error { asked = n; return nil }
			if c == "cancelled" {
				cancel()
			} else {
				copying = func(n uint64) error { asked = n; return errors.New("no room") }
			}
			if err := placeNoReplace(ctx, src, dst, &importDiskWrites{copying: copying}); err == nil {
				t.Fatal("placed")
			}
			if left, _ := filepath.Glob(filepath.Join(dir, "*a.qcow2*")); len(left) != 0 {
				t.Fatalf("the destination or its copy was left: %v", left)
			}
			if b, _ := os.ReadFile(src); string(b) != "ours, 13 byte" {
				t.Fatalf("the source holds %q", b)
			}
			if c == "refused" && asked != 13 {
				t.Fatalf("reserved %d bytes for the copy, want 13", asked)
			}
		})
	}
}

// The import reserves that second write in its pool like any other.
func TestImportVM_ACopiedPlacementIsReserved(t *testing.T) {
	// Once the conversion is done, what it reserved and did not write stops
	// counting: a copy that fits beside what was written goes ahead.
	t.Run("fits beside what was written", func(t *testing.T) {
		noLinkNoRenameNoReplace(t)
		s := concurrentImportServer(t, oneDiskNeed()+512<<10)
		stubQemuImg(t)
		if err := importAs(s, t, "imp-fits"); err != nil {
			t.Fatalf("a copy that fits: %v", err)
		}
	})
	for _, fallback := range []bool{false, true} {
		t.Run(map[bool]string{false: "link", true: "copy"}[fallback], func(t *testing.T) {
			if fallback {
				noLinkNoRenameNoReplace(t)
			}
			s := concurrentImportServer(t, 10*oneDiskNeed())
			stubQemuImg(t)
			poolDir, err := s.importPoolDir(adminCtx(), "")
			if err != nil {
				t.Fatal(err)
			}
			// Room for the conversion; once it has written its disk, room
			// for nothing more.
			const total = 100 << 30
			s.diskSpaceOverride = func(string) (uint64, uint64, error) {
				scratch, _ := filepath.Glob(filepath.Join(poolDir, ".imp-tight-root.qcow2.convert-*"))
				for _, p := range scratch {
					if fi, err := os.Stat(p); err == nil && fi.Size() > 0 {
						return coldDiskHeadroom(total), total, nil
					}
				}
				return coldDiskHeadroom(total) + 10*oneDiskNeed(), total, nil
			}
			err = importAs(s, t, "imp-tight")
			if !fallback {
				if err != nil {
					t.Fatalf("an import that fits: %v", err)
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "copying") {
				t.Fatalf("a copy past the room: %v, want a refusal for the copy", err)
			}
		})
	}
}

// M-6. Judging a file's origin never waits on the space ledger's lock, which
// a reservation holds across a free-space read of a slow pool.
func TestImportRunning_DoesNotWaitOnTheSpaceLedger(t *testing.T) {
	s := &Server{hostName: "test-host"}
	s.importSpace.mu.Lock()
	defer s.importSpace.mu.Unlock()
	done := make(chan bool, 1)
	go func() { done <- s.importRunning("x") }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("importRunning waited on the space ledger's lock")
	}
}

// M-3. On btrfs a file is flushed again only once it has grown, not on every
// re-measurement: an import's files are not forced to write back each second.
func TestImportSpace_OnBtrfsAFileIsFlushedOnlyWhenItGrew(t *testing.T) {
	var used int64
	s := sharedSpaceServer(20<<20, &used)
	s.fsKeyOverride = func(string) string { return "btrfs:/dev/sdb1" }
	flushes := map[string]int{}
	saved := flushForCredit
	t.Cleanup(func() { flushForCredit = saved })
	flushForCredit = func(p string) error { flushes[p]++; return nil }
	a := t.TempDir()
	ra := s.reserveImportSpace(a)
	defer ra.release()
	f := filepath.Join(a, "disk")
	writeAllocatedAs(t, f, 1<<20)
	for range 3 {
		ra.refresh()
	}
	if flushes[f] != 1 {
		t.Fatalf("an unchanged file was flushed %d times, want once", flushes[f])
	}
	writeAllocatedAs(t, f, 2<<20)
	ra.refresh()
	if flushes[f] != 2 {
		t.Fatalf("a grown file was flushed %d times in all, want twice", flushes[f])
	}
}

// M-4. A flush that fails when a phase ends keeps what the phase reserved:
// the bytes it wrote are not shown free, and are not dropped either.
func TestImportSpace_BeginAfterAFailedFlushKeepsTheReservation(t *testing.T) {
	var used int64
	s := sharedSpaceServer(20<<20, &used)
	s.fsKeyOverride = func(string) string { return "btrfs:/dev/sdb1" }
	saved := flushForCredit
	t.Cleanup(func() { flushForCredit = saved })
	flushForCredit = func(string) error { return errors.New("no flush") }
	a, b := t.TempDir(), t.TempDir()
	ra := s.reserveImportSpace(a)
	defer ra.release()
	if err := ra.reserve(a, 8<<20, "a"); err != nil {
		t.Fatal(err)
	}
	writeAllocated(t, a, 4<<20)
	used = 4 << 20
	ra.begin()
	// 16 MiB free, and a may still have written all 8 it reserved.
	rb := s.reserveImportSpace(b)
	defer rb.release()
	refusedForReservation(t, rb.reserve(b, 12<<20, "b"))
}
