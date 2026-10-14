package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// lv image rm removes the image's files: on each host, the files nothing
// uses, the current one too. Every other file is kept and the reason said.

// deletedImage imports image name on s (catalog row and file) and deletes its
// catalog row, as lv image rm does first. It returns the image's file.
func deletedImage(t *testing.T, s *Server, name string) string {
	t.Helper()
	importVersion(t, s, name, "D ")
	f := s.images.ImagePath(name)
	if !exists(f) {
		t.Fatalf("the import left no file at %s", f)
	}
	if err := corrosion.DeleteImage(context.Background(), s.db, name); err != nil {
		t.Fatal(err)
	}
	return f
}

// keptFor is the reason resp gives for keeping f ("" when it does not).
func keptFor(resp *pb.PruneImagesResponse, f string) string {
	for _, k := range resp.GetKept() {
		if k.Path == f {
			return k.Reason
		}
	}
	return ""
}

// noSeams makes the host checks that read the real host (open files, the
// store's filesystem) answer "nothing", so a test sees only what it sets up.
func noSeams(s *Server) {
	s.imagePrune.openFiles = func([]string) (map[string]string, error) { return nil, nil }
	s.imagePrune.storeFS = func(string) (string, error) { return "", nil }
}

// A deleted image's current file is removed by a prune; a live image's
// current file, and the file of an image the catalog does not know, are not.
func TestPruneImages_RemovesADeletedImagesCurrentFile(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	gone := deletedImage(t, s, "ubuntu")
	importVersion(t, s, "debian", "L ")
	live := s.images.ImagePath("debian")
	unknown := publishVersion(t, s, "legacy", "U ", "")

	dry, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(dry.Removed, []string{gone}) || !exists(gone) {
		t.Fatalf("dry run: would remove %v (file there: %v), want only %s, untouched", dry.Removed, exists(gone), gone)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.RemovesDeletedImages {
		t.Error("the response does not say this build removes a deleted image's files")
	}
	if exists(gone) || !slices.Equal(resp.Removed, []string{gone}) {
		t.Errorf("removed %v; the deleted image's file is there: %v", resp.Removed, exists(gone))
	}
	if _, err := os.Lstat(filepath.Join(s.images.ImageDir(), "ubuntu.current")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the deleted image's current-version pointer is left: %v", err)
	}
	if !exists(live) || !exists(unknown) {
		t.Errorf("a live image's file (%v) or an uncatalogued image's file (%v) was removed", exists(live), exists(unknown))
	}
}

// A deleted image's file a disk on this host is built on — through a linked
// clone, with no row naming either disk — is kept, and the disk is named.
func TestPruneImages_KeepsADeletedImageADiskChainReaches(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	// The template's disk is somewhere no scan lists; only the clone, in
	// <data_dir>/disks, says (through it) that the image is in use.
	src := filepath.Join(t.TempDir(), "tpl-root.qcow2")
	if err := qcow2.CreateWithBacking(src, f, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	clone := filepath.Join(s.dataDir, "disks", "web-root.qcow2")
	if err := qcow2.CreateWithBacking(clone, src, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) {
		t.Fatal("the deleted image's file was removed: a disk chain reaches it")
	}
	if r := keptFor(resp, f); !strings.Contains(r, "disks") {
		t.Errorf("kept with reason %q, want the disk that is built on it named", r)
	}
	if got := guestView(t, clone); len(got) == 0 || got[0] != 'D' {
		t.Error("the clone no longer reads its base")
	}
}

// A deleted image any VM in the cluster records — a disk on another host
// built on it, or a VM created from it — keeps its files on every host.
func TestPruneImages_KeepsADeletedImageAVMAnywhereRecords(t *testing.T) {
	cases := map[string]func(t *testing.T, s *Server){
		"disk-row": func(t *testing.T, s *Server) {
			if err := corrosion.InsertVM(context.Background(), s.db,
				corrosion.VMRecord{Name: "far", HostName: "other-host", State: "stopped", Spec: `{}`}, nil,
				[]corrosion.DiskRecord{{VMName: "far", DiskName: "root", HostName: "other-host",
					Path: "/var/lib/litevirt/disks/far-root.qcow2", BackingImage: "ubuntu"}}); err != nil {
				t.Fatal(err)
			}
		},
		"vm-spec": func(t *testing.T, s *Server) {
			if err := corrosion.InsertVM(context.Background(), s.db,
				corrosion.VMRecord{Name: "far", HostName: "other-host", State: "creating", Spec: `{"name":"far","image":"ubuntu"}`}, nil, nil); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			s := pruneServer(t)
			noSeams(s)
			f := deletedImage(t, s, "ubuntu")
			setup(t, s)
			resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
			if err != nil {
				t.Fatal(err)
			}
			if !exists(f) {
				t.Fatal("the deleted image's file was removed while a VM records the image")
			}
			if r := keptFor(resp, f); !strings.Contains(r, "far") || !strings.Contains(r, "other-host") {
				t.Errorf("kept with reason %q, want VM far on other-host named", r)
			}
		})
	}
}

// A deleted image's file a process holds open (a running qemu) is kept.
func TestPruneImages_KeepsADeletedImageAProcessHoldsOpen(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	s.imagePrune.openFiles = func(paths []string) (map[string]string, error) {
		return map[string]string{f: "process 4242 (qemu-system-x86)"}, nil
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "4242") {
		t.Fatalf("file there: %v, reason %q; want it kept, naming the process", exists(f), keptFor(resp, f))
	}
	// Open files that cannot be told keep it too.
	s.imagePrune.openFiles = func([]string) (map[string]string, error) { return nil, errors.New("no /proc") }
	resp, err = s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "no /proc") {
		t.Fatalf("file there: %v, reason %q; want it kept when open files cannot be read", exists(f), keptFor(resp, f))
	}
}

// An image store on a network filesystem may be another host's too: its
// disks, which this host cannot see, may be built on the files. Kept.
func TestPruneImages_KeepsADeletedImageOnANetworkStore(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	s.imagePrune.storeFS = func(string) (string, error) { return "nfs", nil }
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "nfs") {
		t.Fatalf("file there: %v, reason %q; want it kept, naming the filesystem", exists(f), keptFor(resp, f))
	}
}

// A disk this host's rows record whose file it cannot see might be built on
// any image: every deleted image's file is kept.
func TestPruneImages_KeepsDeletedImagesWhileALocalDiskFileIsMissing(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "lost", HostName: s.hostName, State: "stopped", Spec: `{}`}, nil,
		[]corrosion.DiskRecord{{VMName: "lost", DiskName: "data", HostName: s.hostName,
			Path: filepath.Join(t.TempDir(), "gone", "lost-data.qcow2")}}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "lost") {
		t.Fatalf("file there: %v, reason %q; want it kept, naming the disk", exists(f), keptFor(resp, f))
	}
}

// A qcow2 in a staging directory (a restore, an import, a replica scratch)
// built on a deleted image keeps it.
func TestPruneImages_KeepsADeletedImageAStagedOverlayIsBuiltOn(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	staged := filepath.Join(s.dataDir, "restore-staging", "job-1", "web-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(staged), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.CreateWithBacking(staged, f, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "restore-staging") {
		t.Fatalf("file there: %v, reason %q; want it kept, naming the staged overlay", exists(f), keptFor(resp, f))
	}
}

// A pinned file (a backup was taken on it) of a deleted image is kept.
func TestPruneImages_KeepsAPinnedFileOfADeletedImage(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	if err := s.images.Pin(f); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "pinned") {
		t.Fatalf("file there: %v, reason %q; want it kept as pinned", exists(f), keptFor(resp, f))
	}
}

// The check and the delete are one step against a create: a create on the
// image that starts — and finishes — while the scan runs keeps the file,
// though the scan did not see its disk.
func TestPruneImages_ACreateDuringTheScanKeepsADeletedImage(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	var disk string
	s.imagePrune.afterScan = func() {
		release := s.holdImage("ubuntu")
		defer release()
		p, err := s.images.CreateOverlayDisk("late", "root", "ubuntu", "1M")
		if err != nil {
			t.Error(err)
		}
		disk = p
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) {
		t.Fatal("the deleted image's file was removed under a disk created during the scan")
	}
	if r := keptFor(resp, f); !strings.Contains(r, "started during") {
		t.Errorf("kept with reason %q, want the create named", r)
	}
	if got := guestView(t, disk); len(got) == 0 || got[0] != 'D' {
		t.Error("the disk created during the scan lost its base")
	}
	// The next prune sees the disk and keeps the file for it.
	s.imagePrune.afterScan = nil
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(f) {
		t.Fatal("removed once the scan could see the disk built on it")
	}
}

// A create, pull or import already in flight when the scan begins keeps the
// file, though it finishes — and its hold is gone — before the removal.
func TestPruneImages_ACreateInFlightAtTheScanKeepsADeletedImage(t *testing.T) {
	for name, hold := range map[string]func(*Server) func(){
		"create": func(s *Server) func() { return s.holdImage("ubuntu") },
		"pull":   func(s *Server) func() { return s.holdImagePublish("ubuntu") },
	} {
		t.Run(name, func(t *testing.T) {
			s := pruneServer(t)
			noSeams(s)
			f := deletedImage(t, s, "ubuntu")
			release := hold(s)
			s.imagePrune.afterScan = release
			resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
			if err != nil {
				t.Fatal(err)
			}
			if !exists(f) || !strings.Contains(keptFor(resp, f), "in flight") {
				t.Fatalf("file there: %v, reason %q; want it kept for the %s in flight", exists(f), keptFor(resp, f), name)
			}
		})
	}
}

// The image imported again while a removal's scan runs (the catalog row is
// live again, the same content current): the file stays.
func TestPruneImages_AnImportDuringTheScanKeepsTheImage(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	s.imagePrune.afterScan = func() { importVersion(t, s, "ubuntu", "D ") }
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if img, _ := corrosion.GetImage(context.Background(), s.db, "ubuntu"); img == nil {
		t.Fatal("the import did not make the image live again")
	}
	if !exists(f) || s.images.ImagePath("ubuntu") != f {
		t.Fatalf("the re-imported image's file is gone (%v) or no longer current (%s)", exists(f), s.images.ImagePath("ubuntu"))
	}
}

// An import that completes after the prune read the catalog — so the prune
// still holds the image as deleted — keeps the file it published.
func TestPruneImages_AnImportAfterTheCatalogReadKeepsTheImage(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	s.imagePrune.afterCatalog = func() { importVersion(t, s, "ubuntu", "D ") }
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(f) || s.images.ImagePath("ubuntu") != f {
		t.Fatalf("the re-imported image's file is gone (%v) or no longer current (%s)", exists(f), s.images.ImagePath("ubuntu"))
	}
}

// deleted_image waits for this host's catalog to show the delete, and keeps
// the file when it never does (the image was pulled again, or the delete
// has not replicated here).
func TestPruneImages_ADeletedImageRequestWaitsForTheCatalog(t *testing.T) {
	t.Run("arrives", func(t *testing.T) {
		s := pruneServer(t)
		noSeams(s)
		importVersion(t, s, "ubuntu", "D ")
		f := s.images.ImagePath("ubuntu")
		s.imagePrune.deleteWait.Store(int64(10 * time.Second))
		go func() {
			time.Sleep(300 * time.Millisecond)
			_ = corrosion.DeleteImage(context.Background(), s.db, "ubuntu")
		}()
		resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu", DeletedImage: true})
		if err != nil {
			t.Fatal(err)
		}
		if exists(f) || !slices.Equal(resp.Removed, []string{f}) {
			t.Fatalf("removed %v; file there: %v; want it removed once the delete arrived", resp.Removed, exists(f))
		}
	})
	t.Run("never", func(t *testing.T) {
		s := pruneServer(t)
		noSeams(s)
		importVersion(t, s, "ubuntu", "D ")
		f := s.images.ImagePath("ubuntu")
		s.imagePrune.deleteWait.Store(int64(200 * time.Millisecond))
		resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu", DeletedImage: true})
		if err != nil {
			t.Fatal(err)
		}
		if !exists(f) || !strings.Contains(keptFor(resp, f), "catalog") {
			t.Fatalf("file there: %v, reason %q; want it kept, naming the catalog", exists(f), keptFor(resp, f))
		}
	})
}

// DeleteImage (the REST and web UI delete, and an older CLI) removes the
// files too, in the background.
func TestDeleteImage_RemovesTheImagesFiles(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "ubuntu", "D ")
	f := s.images.ImagePath("ubuntu")
	if _, err := s.DeleteImage(adminCtx(), &pb.DeleteImageRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	s.waitImagePrunes()
	if exists(f) {
		t.Fatal("DeleteImage left the image's file")
	}
}

// RemoveImage deletes the row and reports this host's removal.
func TestRemoveImage_DeletesTheRowAndReportsEachHost(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "ubuntu", "D ")
	f := s.images.ImagePath("ubuntu")
	resp, err := s.RemoveImage(adminCtx(), &pb.RemoveImageRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if img, _ := corrosion.GetImage(context.Background(), s.db, "ubuntu"); img != nil {
		t.Error("the catalog row is live")
	}
	if len(resp.Hosts) != 1 || resp.Hosts[0].HostName != s.hostName || !slices.Equal(resp.Hosts[0].Removed, []string{f}) {
		t.Fatalf("hosts %v, want %s reporting %s removed", resp.Hosts, s.hostName, f)
	}
	if exists(f) {
		t.Error("the file is there")
	}
}

// A create on a live image that starts after a prune's scan and finishes
// before its removals keeps the superseded version it may be built on: the
// scan did not see its disk, and its hold is gone by the removal.
func TestPruneImages_ACreateDuringTheScanKeepsALiveImagesVersion(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "ubuntu", "A ")
	older := s.images.ImagePath("ubuntu")
	publishVersion(t, s, "ubuntu", "B ", "")
	if s.images.ImagePath("ubuntu") == older {
		t.Fatal("the second version is not current")
	}
	disk := s.images.DiskPath("late", "root")
	s.imagePrune.afterScan = func() {
		release := s.holdImage("ubuntu")
		defer release()
		if err := os.MkdirAll(filepath.Dir(disk), 0o755); err != nil {
			t.Error(err)
		}
		// It resolved the version current a moment before.
		if err := qcow2.CreateWithBacking(disk, older, 0, nil); err != nil {
			t.Error(err)
		}
	}
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(older) {
		t.Fatal("the superseded version was removed under a disk created during the scan")
	}
	if got := guestView(t, disk); len(got) == 0 || got[0] != 'A' {
		t.Error("the disk created during the scan lost its base")
	}
	// The next prune sees the disk and keeps the version for it.
	s.imagePrune.afterScan = nil
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
		t.Fatal(err)
	}
	if !exists(older) {
		t.Fatal("removed once the scan could see the disk built on it")
	}
}
