package grpcapi

import (
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Review F3: a claim whose daemon dies once the new image is in place,
// before anything after it runs, leaves the image owned by the claim's
// project, not by the project that owned the item before: the owner is
// published with the content, in the one rename.
func TestPullOCI_AClaimCutShortAfterTheSwapLeavesNoStaleOwner(t *testing.T) {
	s, rt := ctPathServer(t)
	rt.pullUnpack = true
	dir := mkBundle(t, s, "base", "g1")
	if err := s.writeOCIOwner("base", "acme"); err != nil {
		t.Fatal(err)
	}
	rt.pullCrashBeforePublish = true
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "img-other", Dest: "base", Project: "other"}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got := itemImage(t, dir); got != "img-other" {
		t.Fatalf("the item holds %q", got)
	}
	if owner, err := s.readOCIOwner("base"); err != nil || owner != "other" {
		t.Fatalf("the claimed image is owned by %q (%v), want the claim's project", owner, err)
	}
	_, err := s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{
		Name: "web", Template: filepath.Join(dir, "rootfs"), Project: "acme", Arch: "amd64"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the old owner's create from the claimed image: %v, want PermissionDenied", err)
	}
}
