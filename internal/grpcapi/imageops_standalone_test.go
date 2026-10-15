package grpcapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/events"
	"github.com/litevirt/litevirt/internal/image"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// An imported image becomes the base of every VM created from it. If its qcow2
// header names a backing file, qemu opens that file on the host and the guest
// reads it. ImportImage must refuse such an image and keep nothing.
func TestImportImage_RefusesImageThatNamesAHostFile(t *testing.T) {
	dataDir := t.TempDir()
	db := corrosion.NewTestClientT(t)
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	imgStore := image.NewStore(dataDir)
	imgStore.Init()
	s := &Server{hostName: "test-host", dataDir: dataDir, db: db, images: imgStore, events: events.NewBus()}

	work := t.TempDir()
	hostFile := filepath.Join(work, "host-only")
	if err := os.WriteFile(hostFile, []byte("not for the guest"), 0o600); err != nil {
		t.Fatal(err)
	}
	crafted := filepath.Join(work, "crafted.qcow2")
	if err := qcow2.CreateWithBacking(crafted, hostFile, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(crafted)
	if err != nil {
		t.Fatal(err)
	}

	stream := &mockImportImageStream{ctx: ctx, msgs: []*pb.ImportImageRequest{
		{Name: "crafted", Format: "qcow2", Chunk: body},
	}}
	err = s.ImportImage(stream)
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("import of an image naming a host file: got %v, want InvalidArgument", err)
	}
	if _, statErr := os.Stat(imgStore.ImagePath("crafted")); !os.IsNotExist(statErr) {
		t.Fatalf("refused image left in the store: stat err = %v", statErr)
	}
	if rec, _ := corrosion.GetImage(ctx, db, "crafted"); rec != nil {
		t.Fatalf("refused image recorded: %+v", rec)
	}
}

// An image qemu would refuse as corrupt — an lv image build of a disk over
// 512 MiB from before that was fixed — is refused on import (lv image
// import, lv image push, a peer's heal), naming the image and the remedy,
// and nothing is published or recorded.
func TestImportImage_RefusesMisalignedImage(t *testing.T) {
	dataDir := t.TempDir()
	db := corrosion.NewTestClientT(t)
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	imgStore := image.NewStore(dataDir)
	imgStore.Init()
	s := &Server{hostName: "test-host", dataDir: dataDir, db: db, images: imgStore, events: events.NewBus()}

	p := filepath.Join(t.TempDir(), "built.qcow2")
	if err := qcow2.Create(p, 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	l1 := binary.BigEndian.Uint64(body[40:48])
	binary.BigEndian.PutUint64(body[l1:l1+8], 0x10200|1<<63) // off a 64 KiB boundary

	stream := &mockImportImageStream{ctx: ctx, msgs: []*pb.ImportImageRequest{
		{Name: "built", Format: "qcow2", Chunk: body},
	}}
	err = s.ImportImage(stream)
	if status.Code(err) != codes.InvalidArgument || !qcow2.IsMisaligned(err) {
		t.Fatalf("import of a misaligned image: got %v, want InvalidArgument naming the misalignment", err)
	}
	for _, want := range []string{`"built"`, "lv image build"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %s", err, want)
		}
	}
	if _, statErr := os.Stat(imgStore.ImagePath("built")); !os.IsNotExist(statErr) {
		t.Fatalf("refused image left in the store: stat err = %v", statErr)
	}
	if rec, _ := corrosion.GetImage(ctx, db, "built"); rec != nil {
		t.Fatalf("refused image recorded: %+v", rec)
	}
}

// A refused re-import of a name that already exists changes nothing: the
// stored file keeps its bytes, and the image's record and host row stay as
// they were. The refusal comes before anything is published.
//
// Mutation: run the alignment check after the publish — the stored file is
// replaced by a new version and the record follows it.
func TestImportImage_RefusedMisalignedReimportLeavesTheStoredImage(t *testing.T) {
	dataDir := t.TempDir()
	db := corrosion.NewTestClientT(t)
	ctx := adminCtx()
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	imgStore := image.NewStore(dataDir)
	imgStore.Init()
	s := &Server{hostName: "test-host", dataDir: dataDir, db: db, images: imgStore, events: events.NewBus()}

	p := filepath.Join(t.TempDir(), "base.qcow2")
	if err := qcow2.Create(p, 1<<30, nil); err != nil {
		t.Fatal(err)
	}
	good, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ImportImage(&mockImportImageStream{ctx: ctx, msgs: []*pb.ImportImageRequest{
		{Name: "base", Format: "qcow2", Chunk: good},
	}}); err != nil {
		t.Fatalf("first import: %v", err)
	}

	type snapshot struct {
		bytes    []byte
		resolved string
		rec      string
		hosts    string
		files    []string
	}
	take := func() snapshot {
		t.Helper()
		var sn snapshot
		sn.bytes, err = os.ReadFile(imgStore.ImagePath("base"))
		if err != nil {
			t.Fatalf("read stored image: %v", err)
		}
		sn.resolved, _ = filepath.EvalSymlinks(imgStore.ImagePath("base"))
		rec, err := corrosion.GetImage(ctx, db, "base")
		if err != nil || rec == nil {
			t.Fatalf("GetImage: %v %v", rec, err)
		}
		sn.rec = fmt.Sprintf("%+v", *rec)
		hosts, err := corrosion.GetImageHosts(ctx, db, "base")
		if err != nil {
			t.Fatalf("GetImageHosts: %v", err)
		}
		sn.hosts = fmt.Sprintf("%+v", hosts)
		filepath.WalkDir(dataDir, func(path string, d os.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				sn.files = append(sn.files, path)
			}
			return nil
		})
		return sn
	}
	before := take()

	bad := append([]byte(nil), good...)
	l1 := binary.BigEndian.Uint64(bad[40:48])
	binary.BigEndian.PutUint64(bad[l1:l1+8], 0x10200|1<<63) // off a 64 KiB boundary
	err = s.ImportImage(&mockImportImageStream{ctx: ctx, msgs: []*pb.ImportImageRequest{
		{Name: "base", Format: "qcow2", Chunk: bad},
	}})
	if status.Code(err) != codes.InvalidArgument || !qcow2.IsMisaligned(err) {
		t.Fatalf("misaligned re-import: got %v, want InvalidArgument naming the misalignment", err)
	}

	after := take()
	if !bytes.Equal(after.bytes, before.bytes) || after.resolved != before.resolved {
		t.Errorf("stored image changed: %s (%d bytes) -> %s (%d bytes)", before.resolved, len(before.bytes), after.resolved, len(after.bytes))
	}
	if after.rec != before.rec {
		t.Errorf("image record changed:\n before %s\n after  %s", before.rec, after.rec)
	}
	if after.hosts != before.hosts {
		t.Errorf("image host rows changed:\n before %s\n after  %s", before.hosts, after.hosts)
	}
	if fmt.Sprint(after.files) != fmt.Sprint(before.files) {
		t.Errorf("files under the data dir changed:\n before %v\n after  %v", before.files, after.files)
	}
}
