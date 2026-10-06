package grpcapi

import (
	"os"
	"path/filepath"
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
