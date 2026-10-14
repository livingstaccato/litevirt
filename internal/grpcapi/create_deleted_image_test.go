package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func imageCreateRequest(name, img string) *pb.CreateVMRequest {
	req := disklessCreateRequest(name)
	req.Spec.Image = img
	return req
}

// lv image rm deletes the catalog row first and the files after; a host keeps
// a deleted image's file a while (the delete margin, a VM that records it).
// A create naming the image on such a host found the file and built a disk
// on it, with no pull: a deleted image was usable by name (lab 2). It is
// refused, naming the image as deleted and how to have it again; nothing of
// the VM is left behind.
//
// Mutation: drop the deleted-image check in createVM — the create succeeds
// on the kept file.
func TestCreateVM_ADeletedImageIsRefusedWhileItsFileIsKept(t *testing.T) {
	needQemuImg(t)
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	importVersion(t, s, "ubuntu", "A ")
	f := s.images.ImagePath("ubuntu")
	if err := corrosion.DeleteImage(context.Background(), s.db, "ubuntu"); err != nil {
		t.Fatal(err)
	}
	if !exists(f) {
		t.Fatal("the setup lost the kept file")
	}

	_, err := s.CreateVM(ctx, imageCreateRequest("web", "ubuntu"))
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("create on a deleted image: %v, want FailedPrecondition", err)
	}
	for _, want := range []string{`"ubuntu"`, "deleted", "lv image import", "lv image pull"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}
	if vm, _ := corrosion.GetVM(ctx, s.db, "web"); vm != nil {
		t.Error("the refused create left a VM row")
	}
	if exists(s.images.DiskPath("web", "root")) {
		t.Error("the refused create built a disk on the deleted image")
	}
	if !exists(f) {
		t.Error("the refusal removed the kept file")
	}

	// A re-import revives the name, by design: the create goes ahead.
	importVersion(t, s, "ubuntu", "B ")
	if _, err := s.CreateVM(ctx, imageCreateRequest("web", "ubuntu")); err != nil {
		t.Fatalf("create after a re-import: %v", err)
	}
}

// An image the catalog has never recorded (a file placed in the store by
// hand, an older build's) is not a deleted one: the create goes ahead, as
// on main.
func TestCreateVM_AnImageWithNoCatalogRowIsNotRefused(t *testing.T) {
	needQemuImg(t)
	s, _ := provableCreateServer(t)
	ctx := adminCtx()
	publishVersion(t, s, "ubuntu", "A ", "") // the store only: no catalog row
	if _, err := s.CreateVM(ctx, imageCreateRequest("web", "ubuntu")); err != nil {
		t.Fatalf("create on an image with no catalog row: %v", err)
	}
}
