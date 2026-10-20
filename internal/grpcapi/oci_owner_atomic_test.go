package grpcapi

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
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

func compatOwner(t *testing.T, s *Server, item string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.dataDir, ociOwnersDir, item))
	if err != nil {
		return "<" + err.Error() + ">"
	}
	return strings.TrimSpace(string(b))
}

// Review r2 M6: the owner record an earlier build reads holds no project
// while a claim is under way, so a binary rolled back to after a claim cut
// short refuses the item to every project, not only to the claim's; a
// claim that fails before the swap puts the record back.
func TestPullOCI_TheEarlierBuildsOwnerRecordIsPendingDuringAClaim(t *testing.T) {
	s, rt := ctPathServer(t)
	rt.pullUnpack = true
	mkBundle(t, s, "base", "g1")
	if err := s.writeOCIOwner("base", "acme"); err != nil {
		t.Fatal(err)
	}
	rt.pullCrashBeforePublish = true
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "img-other", Dest: "base", Project: "other"}); err != nil {
		t.Fatalf("claim: %v", err)
	}
	if got := compatOwner(t, s, "base"); got != ociOwnerPending {
		t.Fatalf("after a claim cut short the earlier build's record says %q, want %q", got, ociOwnerPending)
	}

	s2, rt2 := ctPathServer(t)
	mkBundle(t, s2, "base", "g1")
	if err := s2.writeOCIOwner("base", "acme"); err != nil {
		t.Fatal(err)
	}
	rt2.pullErr = errors.New("registry unreachable")
	if _, err := s2.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "img-other", Dest: "base", Project: "other"}); err == nil {
		t.Fatal("the failing claim succeeded")
	}
	if got := compatOwner(t, s2, "base"); got != "acme" {
		t.Fatalf("after a failed claim the earlier build's record says %q, want it put back", got)
	}
}
