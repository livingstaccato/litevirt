package grpcapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pbsstore"
)

// Fix round 4: an image refresh never replaces the base existing disks are
// built on (IMP-4, m1), a damaged base is healed only with byte-identical
// content (concern 1), and a legacy backup restores in place onto an image
// whose records prove it unchanged (IMP-5).

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// imageServer is a server with an image store, image "ubuntu" (OLD content,
// published before identities were recorded) and VM "v" on another host
// built on it by name. It also returns an overlay on this host built on the
// image, and the guest view of the old image.
func imageServer(t *testing.T) (s *Server, old string, overlay string, oldView []byte) {
	t.Helper()
	needQemuImg(t)
	s = testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	old = s.images.ImagePath("ubuntu")
	oldView = filledQcow2(t, old, "OLD ")
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "v", HostName: "other-host", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "v", DiskName: "root", HostName: "other-host", Path: "/x/v-root.qcow2", BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	var err error
	overlay, err = s.images.CreateOverlayDisk("here", "root", "ubuntu", "1M")
	if err != nil {
		t.Fatal(err)
	}
	return s, old, overlay, oldView
}

// newContent is a qcow2 of NEW content, its bytes and guest view.
func newContent(t *testing.T) (file []byte, view []byte) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "new.qcow2")
	view = filledQcow2(t, p, "NEW ")
	file, _ = os.ReadFile(p)
	return file, view
}

// requireRefreshed checks a refresh of "ubuntu": new disks get the new
// content, the old file is untouched and the existing overlay still reads it.
func requireRefreshed(t *testing.T, s *Server, old, overlay string, oldBytes, oldView, newFile, newView []byte) {
	t.Helper()
	cur := s.images.ImagePath("ubuntu")
	if cur == old {
		t.Fatal("the refresh did not publish a new version")
	}
	if got, _ := os.ReadFile(cur); !bytes.Equal(got, newFile) {
		t.Error("the current version does not hold the new content")
	}
	if got, _ := os.ReadFile(old); !bytes.Equal(got, oldBytes) {
		t.Fatal("the base an existing disk is built on was written over")
	}
	if got := guestView(t, overlay); !bytes.Equal(got, oldView) {
		t.Error("the existing disk no longer reads its old base")
	}
	fresh, err := s.images.CreateOverlayDisk("fresh", "root", "ubuntu", "1M")
	if err != nil {
		t.Fatal(err)
	}
	if got := guestView(t, fresh); !bytes.Equal(got, newView) {
		t.Error("a new disk is not built on the refreshed image")
	}
	img, _ := corrosion.GetImage(context.Background(), s.db, "ubuntu")
	if img == nil || normalizeChecksum(img.Checksum) != sha256Hex(newFile) {
		t.Errorf("image record %+v, want the new content's sha256 %s", img, sha256Hex(newFile))
	}
}

// IMP-4: re-pulling an image disks are built on refreshes it.
func TestPullImage_RefreshOfAnImageDisksAreBuiltOn(t *testing.T) {
	s, old, overlay, oldView := imageServer(t)
	oldBytes, _ := os.ReadFile(old)
	newFile, newView := newContent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newFile) }))
	defer srv.Close()
	if err := s.PullImage(&pb.PullImageRequest{Name: "ubuntu", SourceUrl: srv.URL + "/u.qcow2"}, &streamRecorder[pb.PullProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("re-pull of an image disks are built on: %v", err)
	}
	requireRefreshed(t, s, old, overlay, oldBytes, oldView, newFile, newView)
}

// IMP-4: ... and re-importing it.
func TestImportImage_RefreshOfAnImageDisksAreBuiltOn(t *testing.T) {
	s, old, overlay, oldView := imageServer(t)
	oldBytes, _ := os.ReadFile(old)
	newFile, newView := newContent(t)
	stream := &mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: newFile}}}
	if err := s.ImportImage(stream); err != nil {
		t.Fatalf("re-import of an image disks are built on: %v", err)
	}
	requireRefreshed(t, s, old, overlay, oldBytes, oldView, newFile, newView)
}

// m1: a disk created on the image WHILE a re-pull downloads keeps its base.
func TestPullImage_ADiskCreatedDuringThePullKeepsItsBase(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	old := s.images.ImagePath("ubuntu")
	oldView := filledQcow2(t, old, "OLD ")
	newFile, _ := newContent(t)
	var during string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Unused when the pull starts; a VM is created on it mid-download.
		p, err := s.images.CreateOverlayDisk("during", "root", "ubuntu", "1M")
		if err != nil {
			t.Error(err)
		}
		during = p
		_, _ = w.Write(newFile)
	}))
	defer srv.Close()
	if err := s.PullImage(&pb.PullImageRequest{Name: "ubuntu", SourceUrl: srv.URL + "/u.qcow2"}, &streamRecorder[pb.PullProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("re-pull: %v", err)
	}
	if got := guestView(t, during); !bytes.Equal(got, oldView) {
		t.Error("a disk created during the pull had its base replaced under it")
	}
}

// Concern 1: a damaged copy of an image disks are built on is healed in
// place only with content byte-identical to its recorded identity; any other
// content is a new version and the damaged file is left for repair.
func TestImportImage_HealsADamagedBaseOnlyWithItsRecordedIdentity(t *testing.T) {
	needQemuImg(t)
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	src := filepath.Join(t.TempDir(), "good.qcow2")
	goodView := filledQcow2(t, src, "GOOD ")
	good, _ := os.ReadFile(src)
	importBytes := func(b []byte) error {
		return s.ImportImage(&mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{{Name: "ubuntu", Format: "qcow2", Chunk: b}}})
	}
	if err := importBytes(good); err != nil {
		t.Fatal(err)
	}
	base := s.images.ImagePath("ubuntu")
	overlay, err := s.images.CreateOverlayDisk("v", "root", "ubuntu", "1M")
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "v", HostName: s.hostName, State: "stopped"}, nil,
		[]corrosion.DiskRecord{{VMName: "v", DiskName: "root", HostName: s.hostName, Path: overlay, BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	// Damaged on disk: truncated.
	if err := os.Truncate(base, int64(len(good)/2)); err != nil {
		t.Fatal(err)
	}
	// Different content does not replace it.
	other, _ := newContent(t)
	if err := importBytes(other); err != nil {
		t.Fatalf("import of other content: %v", err)
	}
	if fi, _ := os.Stat(base); fi.Size() != int64(len(good)/2) {
		t.Fatal("content other than the recorded identity was written over a base a disk is built on")
	}
	// The recorded identity heals it in place.
	if err := importBytes(good); err != nil {
		t.Fatalf("import of the recorded identity: %v", err)
	}
	if got, _ := os.ReadFile(base); !bytes.Equal(got, good) {
		t.Fatal("the damaged base was not healed with its recorded identity")
	}
	if got := guestView(t, overlay); !bytes.Equal(got, goodView) {
		t.Error("the disk does not read its healed base")
	}
}

// deliveringPeer is a peer that answers PushImage by importing content into
// the asking server, as a real peer's push does.
type deliveringPeer struct {
	pb.LiteVirtClient
	to      *Server
	content []byte
	pushes  int
}

type donePushStream struct {
	grpc.ClientStream
	sent bool
}

func (d *donePushStream) Recv() (*pb.PushImageProgress, error) {
	if d.sent {
		return nil, io.EOF
	}
	d.sent = true
	return &pb.PushImageProgress{Status: "complete", ProgressPct: 100}, nil
}

func (p *deliveringPeer) PushImage(_ context.Context, req *pb.PushImageRequest, _ ...grpc.CallOption) (grpc.ServerStreamingClient[pb.PushImageProgress], error) {
	p.pushes++
	if err := p.to.ImportImage(&mockImportImageStream{ctx: adminCtx(), msgs: []*pb.ImportImageRequest{{Name: req.Name, Format: "qcow2", Chunk: p.content}}}); err != nil {
		return nil, err
	}
	return &donePushStream{}, nil
}

// autoPullServer is a server whose local copy of "ubuntu" (the base of a disk
// on another host) has the wrong size for its record, and a peer that holds
// it and pushes content when asked.
func autoPullServer(t *testing.T, local []byte, published bool, content []byte) (*Server, *deliveringPeer, string) {
	t.Helper()
	s := testServer(t)
	s.dataDir = t.TempDir()
	s.images = image.NewStore(s.dataDir)
	_ = s.images.Init()
	ctx := context.Background()
	img := s.images.ImagePath("ubuntu")
	if published {
		tmp := filepath.Join(s.images.ImageDir(), "import-seed.tmp")
		if err := os.WriteFile(tmp, content, 0o600); err != nil {
			t.Fatal(err)
		}
		pub, err := s.images.Publish("ubuntu", tmp, sha256Hex(content))
		if err != nil {
			t.Fatal(err)
		}
		img = pub.Path
	}
	if err := os.WriteFile(img, local, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertImage(ctx, s.db, corrosion.ImageRecord{Name: "ubuntu", Format: "qcow2", SizeBytes: int64(len(content))}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertImageHost(ctx, s.db, corrosion.ImageHostRecord{ImageName: "ubuntu", HostName: "peer-host", Path: img, Status: "ready"}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "v", HostName: "other-host", State: "running"}, nil,
		[]corrosion.DiskRecord{{VMName: "v", DiskName: "root", HostName: "other-host", Path: "/x/v-root.qcow2", BackingImage: "ubuntu"}}); err != nil {
		t.Fatal(err)
	}
	peer := &deliveringPeer{to: s, content: content}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	return s, peer, img
}

// Concern 1: the reconciler's heal fetches from a peer; a damaged copy with
// no recorded identity is never replaced — the fetched content becomes a new
// version for new disks.
func TestAutoPullImage_NeverReplacesAnUnverifiedBase(t *testing.T) {
	damaged := []byte("short, damaged-looking local copy")
	good := bytes.Repeat([]byte("GOOD"), 1024)
	s, peer, img := autoPullServer(t, damaged, false, good)
	if err := s.autoPullImage(context.Background(), "ubuntu"); err != nil {
		t.Fatalf("auto-pull: %v", err)
	}
	if peer.pushes != 1 {
		t.Errorf("a peer was asked %d time(s), want 1", peer.pushes)
	}
	if got, _ := os.ReadFile(img); !bytes.Equal(got, damaged) {
		t.Fatal("a base with no recorded identity was replaced")
	}
	if cur := s.images.ImagePath("ubuntu"); cur == img {
		t.Error("the fetched content was not published for new disks")
	} else if got, _ := os.ReadFile(cur); !bytes.Equal(got, good) {
		t.Error("the new version does not hold the fetched content")
	}
}

// ... and a damaged copy whose recorded identity the fetched content has is
// healed in place.
func TestAutoPullImage_HealsABaseWithItsRecordedIdentity(t *testing.T) {
	good := bytes.Repeat([]byte("GOOD"), 1024)
	s, peer, img := autoPullServer(t, []byte("damaged"), true, good)
	if err := s.autoPullImage(context.Background(), "ubuntu"); err != nil {
		t.Fatalf("auto-pull: %v", err)
	}
	if peer.pushes != 1 {
		t.Errorf("a peer was asked %d time(s), want 1", peer.pushes)
	}
	if got, _ := os.ReadFile(img); !bytes.Equal(got, good) {
		t.Fatal("the damaged base was not healed with its recorded identity")
	}
	if s.images.ImagePath("ubuntu") != img {
		t.Error("a heal published a new version")
	}
}

// legacyImageBackup is project a's VM "im" on image "ubuntu", written here
// and recorded as pulled here at pulledAt (an earlier build's file: no
// provenance record), the image record carrying checksum, and a disk-file
// backup at ts that records no base identity (taken before manifests did).
func legacyImageBackup(t *testing.T, f *restoreFixture, checksum bool, pulledAt, ts string) (disk, img string, want []byte) {
	t.Helper()
	ctx := context.Background()
	img = filepath.Join(f.s.dataDir, "images", "ubuntu.qcow2")
	base := filledQcow2(t, img, "UBUNTU ")
	raw, _ := os.ReadFile(img)
	at, err := time.Parse(time.RFC3339, pulledAt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(img, at, at); err != nil {
		t.Fatal(err)
	}
	rec := corrosion.ImageRecord{Name: "ubuntu", Format: "qcow2", SizeBytes: int64(len(raw))}
	if checksum {
		rec.Checksum = "sha256:" + sha256Hex(raw)
	}
	if err := corrosion.InsertImage(ctx, f.s.db, rec); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertImageHost(ctx, f.s.db, corrosion.ImageHostRecord{ImageName: "ubuntu", HostName: f.s.hostName, Path: img, Status: "ready", PulledAt: pulledAt}); err != nil {
		t.Fatal(err)
	}
	disk = filepath.Join(f.s.dataDir, "disks", "im-root.qcow2")
	want = append(bytes.Repeat([]byte("DELTA"), 65536/5+1)[:65536], base[65536:]...)
	overlayWithData(t, disk, img, "qcow2", want)
	backedVM(t, f, "im", disk, corrosion.DiskRecord{StorageType: "local", BackingImage: "ubuntu"})
	pushVMWithIdentity(t, f, "im", disk, ts, pbsstore.ContentDiskFile, "", nil)
	return disk, img, want
}

const (
	legacyPulled = "2020-01-01T00:00:00Z"
	legacyBackup = "2020-06-01T00:00:00Z"
)

// IMP-5 / C-1: a legacy backup restores in place onto the image file the disk
// is built on when that file's provenance shows it unchanged since — with or
// without a recorded image checksum (main recorded none for a pull without
// --checksum, a BuildImage, or a compose pull without one).
func TestRestoreInPlace_LegacyBackupOnAnImageUnchangedSince(t *testing.T) {
	for _, checksum := range []bool{true, false} {
		t.Run(map[bool]string{true: "checksum-recorded", false: "no-checksum"}[checksum], func(t *testing.T) {
			needQemuImg(t)
			f := newRestoreFixture(t)
			f.s.virt = libvirtfake.New()
			disk, img, want := legacyImageBackup(t, f, checksum, legacyPulled, legacyBackup)
			if err := inPlace(f, "im", legacyBackup); err != nil {
				t.Fatalf("in-place restore of a legacy backup onto an unchanged image: %v", err)
			}
			requireRestoredOnto(t, disk, img, want)
		})
	}
}

// C-1b: the image name refreshed on ANOTHER host since: its record names the
// other content, but this host's file is untouched.
func TestRestoreInPlace_LegacyBackupAfterARefreshOnAnotherHost(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	ctx := context.Background()
	disk, img, want := legacyImageBackup(t, f, true, legacyPulled, legacyBackup)
	if err := corrosion.InsertImage(ctx, f.s.db, corrosion.ImageRecord{Name: "ubuntu", Format: "qcow2", Checksum: "sha256:" + sha256Hex([]byte("other")), SizeBytes: 5}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertImageHost(ctx, f.s.db, corrosion.ImageHostRecord{ImageName: "ubuntu", HostName: "host-b", Path: img, Status: "ready", PulledAt: "2021-01-01T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	if err := inPlace(f, "im", legacyBackup); err != nil {
		t.Fatalf("in-place restore after a refresh on another host: %v", err)
	}
	requireRestoredOnto(t, disk, img, want)
}

// C-1c: the image name refreshed on THIS host since (after the upgrade): a new
// version is published, the file the disk is built on is untouched, and the
// restore onto it works.
func TestRestoreInPlace_LegacyBackupAfterARefreshOnThisHost(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	f.s.images = image.NewStore(f.s.dataDir)
	disk, img, want := legacyImageBackup(t, f, false, legacyPulled, legacyBackup)
	// No startup pass here: the pull itself records the file's provenance
	// before it moves this host's pulled_at.
	newFile, _ := newContent(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(newFile) }))
	defer srv.Close()
	if err := f.s.PullImage(&pb.PullImageRequest{Name: "ubuntu", SourceUrl: srv.URL + "/u.qcow2"}, &streamRecorder[pb.PullProgress]{ctx: adminCtx()}); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if err := inPlace(f, "im", legacyBackup); err != nil {
		t.Fatalf("in-place restore after a refresh on this host: %v", err)
	}
	requireRestoredOnto(t, disk, img, want)
}

// IMP-5: ... and refused, saying why and that a new file works, when the
// image was pulled here after the backup.
func TestRestoreInPlace_LegacyBackupOnAnImagePulledSinceIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	disk, _, _ := legacyImageBackup(t, f, true, "2020-12-01T00:00:00Z", legacyBackup)
	before, _ := os.ReadFile(disk)
	err := inPlace(f, "im", legacyBackup)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "after the backup") || !strings.Contains(err.Error(), "new file") {
		t.Errorf("legacy backup onto an image pulled since: got %v, want FailedPrecondition naming why and the new-file route", err)
	}
	if after, _ := os.ReadFile(disk); !bytes.Equal(before, after) {
		t.Error("the disk was replaced")
	}
}

// IMP-5: ... refused when an earlier build wrote over the file after the
// backup (its mtime moved) ...
func TestRestoreInPlace_LegacyBackupOnAnImageWrittenOverSinceIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	_, img, _ := legacyImageBackup(t, f, true, legacyPulled, legacyBackup)
	if err := os.Remove(img); err != nil {
		t.Fatal(err)
	}
	filledQcow2(t, img, "REPLACED ")
	err := inPlace(f, "im", legacyBackup)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "after the backup") {
		t.Errorf("legacy backup onto an image written over since: got %v, want FailedPrecondition naming it", err)
	}
}

// ... and refused when the file's bytes no longer have the sha256 recorded
// for it.
func TestRestoreInPlace_LegacyBackupOnAnImageWhoseBytesChangedIsRefused(t *testing.T) {
	needQemuImg(t)
	f := newRestoreFixture(t)
	f.s.virt = libvirtfake.New()
	_, img, _ := legacyImageBackup(t, f, true, legacyPulled, legacyBackup)
	f.s.RecordLegacyImageProvenance(context.Background())
	fh, err := os.OpenFile(img, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fh.WriteAt([]byte("flipped"), 1<<19)
	fh.Close()
	at, _ := time.Parse(time.RFC3339, legacyPulled)
	_ = os.Chtimes(img, at, at)
	err = inPlace(f, "im", legacyBackup)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "no longer matches") {
		t.Errorf("legacy backup onto an image whose bytes changed: got %v, want FailedPrecondition naming it", err)
	}
}
