package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func itemImage(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, "rootfs", "etc", "image"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Two Admin claims of one item: whichever content the item ends with, its
// owner is the project of the claim that put it there. A claim records the
// owner with its content, under the item's lock, so the other claim cannot
// replace the content between them.
func TestPullOCI_ConcurrentClaimsLeaveContentAndOwnerOfOneClaim(t *testing.T) {
	s, rt := ctPathServer(t)
	rt.pullUnpack = true
	dir := mkBundle(t, s, "base", "g1")
	if err := os.WriteFile(filepath.Join(dir, "rootfs", "etc", "image"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	bDone := make(chan error, 1)
	prev := ociOwnerWriteHook
	t.Cleanup(func() { ociOwnerWriteHook = prev })
	var once bool
	ociOwnerWriteHook = func(item, project string) {
		if once || project != "pa" {
			return
		}
		once = true
		// A's content is in place; B's claim runs now, and is given the
		// time to finish if nothing holds it off.
		go func() {
			_, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "img-b", Dest: "base", Project: "pb"})
			bDone <- err
		}()
		select {
		case err := <-bDone:
			bDone <- err
		case <-time.After(500 * time.Millisecond):
		}
	}
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "img-a", Dest: "base", Project: "pa"}); err != nil {
		t.Fatalf("claim A: %v", err)
	}
	if err := <-bDone; err != nil {
		t.Fatalf("claim B: %v", err)
	}
	owner, err := s.readOCIOwner("base")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"img-a": "pa", "img-b": "pb"}[itemImage(t, dir)]
	if owner != want {
		t.Fatalf("the item holds %s and is owned by %q, want %q", itemImage(t, dir), owner, want)
	}
}

// A create that passed the owner check before a claim moved the item to
// another project does not copy the claimed content: the owner is judged
// again where the create copies, under the item's lock.
func TestCreateContainer_AClaimAfterTheOwnerCheckIsJudgedAtTheCopy(t *testing.T) {
	s, rt := ctPathServer(t)
	rt.pullUnpack = true
	dir := mkBundle(t, s, "base", "g1")
	if err := s.writeOCIOwner("base", "acme"); err != nil {
		t.Fatal(err)
	}
	rt.beforeCopy = func() {
		rt.beforeCopy = nil
		if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "img-other", Dest: "base", Project: "other"}); err != nil {
			t.Errorf("the Admin's claim: %v", err)
		}
	}
	_, err := s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{
		Name: "web", Template: filepath.Join(dir, "rootfs"), Project: "acme", Arch: "amd64"})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("create after the claim: %v (copied %q), want PermissionDenied", err, rt.copied["web"])
	}
	if got, ok := rt.copied["web"]; ok {
		t.Fatalf("the create copied %q", got)
	}
}

// A privileged member's recreate by a deployer without ContainerRoot is
// judged against the generation it was built from; an Admin's claim of the
// item between that judgment and the create's copy is refused while the
// recreate is under way, and the member is rebuilt from the image it was
// judged on.
func TestComposeRecreate_AClaimAfterTheJudgmentDoesNotReachTheCopy(t *testing.T) {
	s, rt := secServer(t)
	rt.pullUnpack = true
	carl := carlCtx(t, s)
	item := mkBundle(t, s, "build", "g1")
	if err := os.WriteFile(filepath.Join(item, "rootfs", "etc", "image"), []byte("judged"), 0o644); err != nil {
		t.Fatal(err)
	}
	tmpl := filepath.Join(item, "rootfs")
	seedSecCT(t, s, rt, "web", "running", corrosion.ContainerCreateSpec{})
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "running", Project: "acme", Image: tmpl,
		Labels:     map[string]string{corrosion.LabelStack: "st"},
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: tmpl, TemplateGen: "g1", Arch: "amd64"}),
	}); err != nil {
		t.Fatal(err)
	}
	var claimErr error
	s.recreateDeleted = func(string) {
		_, claimErr = s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "replaced", Dest: "build", Project: "acme"})
	}
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindOCI, Image: tmpl, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if status.Code(claimErr) != codes.FailedPrecondition || !strings.Contains(claimErr.Error(), "web") {
		t.Fatalf("the claim during the recreate: %v, want FailedPrecondition naming the member", claimErr)
	}
	if got := rt.copied["web"]; got != "judged" {
		t.Fatalf("the member was rebuilt from %q, want the image it was judged on", got)
	}
	// The recreate is over: the item is the Admin's to claim again.
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "replaced", Dest: "build", Project: "acme"}); err != nil {
		t.Fatalf("the claim after the recreate: %v", err)
	}
}
