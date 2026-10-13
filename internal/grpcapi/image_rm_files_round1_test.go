package grpcapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// Review round 1 of lv image rm's file removal.

// I1: lv image rm is gated as DeleteImage is, so an operator whose RBAC
// bindings carry no image.import on "/" (a project-scoped operator) deletes
// the image, files and all, as main let them — and a viewer is refused both.
func TestRemoveImage_IsGatedAsDeleteImage(t *testing.T) {
	s := delegationServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	t.Cleanup(s.waitImagePrunes)
	noSeams(s)
	// Removed moments after its import: no clock-skew margin.
	s.SetImageDeleteMarginForTest(time.Nanosecond)
	carol := userCtx("carol", "operator") // bound VMOperator on one VM only
	if err := s.RequirePerm(carol, "/", "image.import", "operator"); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the test needs an operator without image.import on /: %v", err)
	}
	importVersion(t, s, "ubuntu", "D ")
	f := s.images.ImagePath("ubuntu")
	resp, err := s.RemoveImage(carol, &pb.RemoveImageRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatalf("lv image rm by a project-scoped operator: %v (DeleteImage lets them)", err)
	}
	if exists(f) || len(resp.Hosts) != 1 || len(resp.Hosts[0].Removed) != 1 {
		t.Errorf("file there: %v, hosts %v; want it removed", exists(f), resp.Hosts)
	}
	if _, err := s.DeleteImage(patCtx(), &pb.DeleteImageRequest{Name: "ubuntu"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("DeleteImage by a viewer: %v", err)
	}
	if _, err := s.RemoveImage(patCtx(), &pb.RemoveImageRequest{Name: "ubuntu"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("RemoveImage by a viewer: %v, want PermissionDenied as DeleteImage", err)
	}
}

// I2, across hosts: a rebuild or rolling recreate tombstones the VM, then its
// create may land on another host, which holds the image only once its create
// begins. Until then the deleted row still records the image there.
func TestPruneImages_ARecentlyDeletedVMStillRecordsTheImage(t *testing.T) {
	for _, tc := range []struct {
		name string
		rows func(t *testing.T, s *Server)
	}{
		{"vm-spec", func(t *testing.T, s *Server) {
			if err := corrosion.InsertVM(context.Background(), s.db,
				corrosion.VMRecord{Name: "web", HostName: "other-host", State: "stopped", Spec: `{"name":"web","image":"ubuntu"}`}, nil, nil); err != nil {
				t.Fatal(err)
			}
		}},
		{"disk-row", func(t *testing.T, s *Server) {
			if err := corrosion.InsertVM(context.Background(), s.db,
				corrosion.VMRecord{Name: "web", HostName: "other-host", State: "stopped", Spec: `{}`}, nil,
				[]corrosion.DiskRecord{{VMName: "web", DiskName: "root", HostName: "other-host",
					Path: "/var/lib/litevirt/disks/web-root.qcow2", BackingImage: "ubuntu"}}); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := pruneServer(t)
			noSeams(s)
			f := deletedImage(t, s, "ubuntu")
			tc.rows(t, s)
			if err := corrosion.DeleteVM(context.Background(), s.db, "web"); err != nil {
				t.Fatal(err)
			}
			resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
			if err != nil {
				t.Fatal(err)
			}
			if !exists(f) || !strings.Contains(keptFor(resp, f), "deleted at") {
				t.Fatalf("file there: %v, reason %q; want it kept for the VM deleted moments ago", exists(f), keptFor(resp, f))
			}
			// Past the grace, the deleted row records nothing.
			s.imagePrune.recentGrace.Store(int64(time.Nanosecond))
			if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"}); err != nil {
				t.Fatal(err)
			}
			if exists(f) {
				t.Error("kept past the grace")
			}
		})
	}
}

// A deleted row whose deleted_at cannot be read counts as deleted just now:
// how long ago it went is unknown, so its image is kept.
func TestPruneImages_AnUnreadableDeletedAtCountsAsRecent(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "web", HostName: "other-host", State: "stopped", Spec: `{"name":"web","image":"ubuntu"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET deleted_at = 'garbage' WHERE name = 'web'`); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "deleted at garbage") {
		t.Fatalf("file there: %v, reason %q; want it kept for the row deleted at an unreadable time", exists(f), keptFor(resp, f))
	}
}

// M8: a disk row naming the image by one of its store files keeps it.
func TestPruneImages_ADiskRowNamingAStoreFileRecordsTheImage(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	if err := corrosion.InsertVM(context.Background(), s.db,
		corrosion.VMRecord{Name: "cl", HostName: "other-host", State: "stopped", Spec: `{}`}, nil,
		[]corrosion.DiskRecord{{VMName: "cl", DiskName: "root", HostName: "other-host",
			Path: "/var/lib/litevirt/disks/cl-root.qcow2", BackingImage: "/var/lib/litevirt/images/" + filepath.Base(f)}}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "cl/root") {
		t.Fatalf("file there: %v, reason %q; want it kept for disk cl/root", exists(f), keptFor(resp, f))
	}
}

// M1: a deleted image kept for a reason the chain walk does not see (a VM
// records it) keeps what it is built on: another image's older version.
func TestPruneImages_KeepsWhatAKeptDeletedImageIsBuiltOn(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	importVersion(t, s, "lower", "X ")
	x := s.images.ImagePath("lower")
	publishVersion(t, s, "upper", "U", x)
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "upper", Format: "qcow2"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteImage(ctx, s.db, "upper"); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "far", HostName: "other-host", State: "stopped",
		Spec: `{"name":"far","image":"upper"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	importVersion(t, s, "lower", "Y ")
	s.waitImagePrunes()
	if _, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{}); err != nil {
		t.Fatal(err)
	}
	if !exists(s.images.ImagePath("upper")) {
		t.Fatal("the deleted image a VM records was removed")
	}
	if !exists(x) {
		t.Fatal("the version the kept deleted image is built on was pruned")
	}
}

// M4, M8: another host's disk row whose file is not here, and a device path
// on this host, never hold a deleted image's files.
func TestPruneImages_MissingDiskIgnoresOtherHostsAndDevices(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	ctx := context.Background()
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "far", HostName: "other-host", State: "stopped", Spec: `{}`}, nil,
		[]corrosion.DiskRecord{{VMName: "far", DiskName: "data", HostName: "other-host", Path: "/nonexistent/far-data.qcow2"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "lun", HostName: s.hostName, State: "stopped", Spec: `{}`}, nil,
		[]corrosion.DiskRecord{{VMName: "lun", DiskName: "data", HostName: s.hostName, StorageType: "iscsi",
			Path: "/dev/disk/by-path/ip-10.0.0.9:3260-iscsi-iqn.2026-10.lab:t-lun-1"}}); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if exists(f) {
		t.Fatalf("kept: %q; another host's missing file and a logged-out LUN say nothing of this host's disks", keptFor(resp, f))
	}
}

// M5: a backup repo's chunks under a staging directory are guest data: one
// that begins with the qcow2 magic is neither parsed nor a reason to keep.
func TestPruneImages_StagedChunksAreNotDiskFiles(t *testing.T) {
	for _, layout := range []string{"chunks", "repo"} {
		t.Run(layout, func(t *testing.T) {
			s := pruneServer(t)
			noSeams(s)
			f := deletedImage(t, s, "ubuntu")
			root := filepath.Join(s.dataDir, "restore-staging", "tok")
			chunk := filepath.Join(root, "chunks", "ab", "abcdef")
			if layout == "repo" {
				chunk = filepath.Join(root, "data", "abcdef")
				if err := os.MkdirAll(root, 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(root, "repo.json"), []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.MkdirAll(filepath.Dir(chunk), 0o755); err != nil {
				t.Fatal(err)
			}
			// The qcow2 magic, then a header that does not parse.
			if err := os.WriteFile(chunk, append([]byte{'Q', 'F', 'I', 0xfb}, bytes.Repeat([]byte{0xff}, 600)...), 0o600); err != nil {
				t.Fatal(err)
			}
			resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
			if err != nil {
				t.Fatalf("a chunk was read as a disk header: %v", err)
			}
			if exists(f) {
				t.Errorf("kept: %q", keptFor(resp, f))
			}
		})
	}
}

// M8: a staging directory nested deeper than the scan reads keeps every
// deleted image's files: what is down there is unseen.
func TestPruneImages_ATooDeepStagingDirKeepsDeletedImages(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	deep := filepath.Join(s.dataDir, "imports", "a", "b", "c", "d", "e")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !exists(f) || !strings.Contains(keptFor(resp, f), "deeper") {
		t.Fatalf("file there: %v, reason %q; want it kept for the unread directory", exists(f), keptFor(resp, f))
	}
}

// blockingSource serves body once released: started closes when a download
// begins, and release lets it finish.
func blockingSource(t *testing.T, body []byte) (url string, started <-chan struct{}, release func()) {
	t.Helper()
	st, rel := make(chan struct{}), make(chan struct{})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(st)
		<-rel
		_, _ = w.Write(body)
	}))
	var once bool
	t.Cleanup(func() {
		if !once {
			close(rel)
		}
		ts.Close()
	})
	return ts.URL + "/img.qcow2", st, func() { once = true; close(rel) }
}

func standaloneQcow2(t *testing.T) []byte {
	t.Helper()
	p := filepath.Join(t.TempDir(), "s.qcow2")
	if err := qcow2.Create(p, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// I3: an operator's import of the deleted image that runs after the prune
// read the catalog — reviving the row the prune holds as deleted — keeps the
// file. (A pull no longer revives a deleted name: review round 1 of the F-1
// fix, I-1.)
func TestPruneImages_AnImportDuringThePruneKeepsTheImage(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	f := deletedImage(t, s, "ubuntu")
	s.imagePrune.afterCatalog = func() {
		src := filepath.Join(t.TempDir(), "n.qcow2")
		filledQcow2(t, src, "N ")
		b, _ := os.ReadFile(src)
		if err := s.ImportImage(&mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: b}}}); err != nil {
			t.Errorf("import: %v", err)
		}
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if r := keptFor(resp, f); len(resp.Removed) != 0 || !strings.Contains(r, "import") {
		t.Fatalf("removed %v, reason %q; want the file kept for the import", resp.Removed, keptFor(resp, f))
	}
}

// I3, as review round 1 of the F-1 fix changed it: a compose deploy's
// download never brings a deleted image back (I-1), so it is refused before
// anything is downloaded and holds nothing; the prune removes the deleted
// image's older version.
func TestPruneImages_AComposeDownloadOfADeletedImageIsRefusedAndHoldsNothing(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	older := publishVersion(t, s, "ubuntu", "O ", "")
	if err := os.Remove(filepath.Join(s.images.ImageDir(), "ubuntu.current")); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "ubuntu", Format: "qcow2"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.DeleteImage(ctx, s.db, "ubuntu"); err != nil {
		t.Fatal(err)
	}
	url, started, _ := blockingSource(t, standaloneQcow2(t))
	cf := &compose.File{
		Images: map[string]compose.ImageDef{"ubuntu": {Source: url, Format: "qcow2"}},
		VMs:    map[string]compose.VMDef{"web": {Image: "ubuntu"}},
	}
	if err := s.autoPullImages(ctx, cf, &mockDeployStream{ctx: ctx}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("a compose download of a deleted image: %v, want FailedPrecondition", err)
	}
	select {
	case <-started:
		t.Fatal("a compose deploy downloaded a deleted image")
	default:
	}
	resp, err := s.PruneImages(adminCtx(), &pb.PruneImagesRequest{Name: "ubuntu"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(resp.Removed, older) {
		t.Fatalf("removed %v, kept %v; want the deleted image's older version removed", resp.Removed, resp.Kept)
	}
}

// I3: a build of the image takes the publish hold: its generation moves, so
// a prune whose scan it overlaps removes nothing of the image.
func TestBuildImage_HoldsTheImageItPublishes(t *testing.T) {
	s := pruneServer(t)
	noSeams(s)
	src, err := s.images.CreateEmptyDisk("vm1", "root", "1M")
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "vm1", HostName: s.hostName, State: "stopped", Spec: `{}`}, nil,
		[]corrosion.DiskRecord{{VMName: "vm1", DiskName: "root", HostName: s.hostName, Path: src, StorageType: "local"}}); err != nil {
		t.Fatal(err)
	}
	before := s.imagePrune.snapshot()["golden"]
	if _, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "vm1", ImageName: "golden"}); err != nil {
		t.Fatalf("build: %v", err)
	}
	if after := s.imagePrune.snapshot()["golden"]; after.gen == before.gen {
		t.Fatal("the build took no hold on the image it published")
	}
}
