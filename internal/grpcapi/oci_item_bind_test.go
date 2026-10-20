package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
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
// judged against the generation it was built from, and the member's host
// copies that generation aside before the delete: an Admin's claim of the
// item between the delete and the create goes ahead, and the member is
// rebuilt from the image it was judged on.
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
	if claimErr != nil {
		t.Fatalf("the Admin's claim during the recreate: %v", claimErr)
	}
	if got := rt.copied["web"]; got != "judged" {
		t.Fatalf("the member was rebuilt from %q, want the image it was judged on", got)
	}
	if got := itemImage(t, item); got != "replaced" {
		t.Fatalf("the item holds %q, want the Admin's claim", got)
	}
}

// Review F1: however long the delete-to-create window, and whatever the
// item becomes in it, a recreate does not delete a member it cannot then
// rebuild: the member is rebuilt from the copy taken before the delete.
// (The probe lapsed the pin earlier builds held; there is no pin to lapse
// now, and the claim simply lands.)
func TestRV14C_PinLapseAfterDeleteLosesTheMember(t *testing.T) {
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
		_, claimErr = s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "replaced", Dest: "build", Project: "_default"})
	}
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindOCI, Image: tmpl, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	err := recreateMember(carl, s, upd, f)
	row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "web")
	if claimErr != nil || err != nil || row == nil || rt.copied["web"] != "judged" {
		t.Fatalf("claim=%v recreate=%v rowPresent=%v copied=%q: want the member rebuilt from the judged image",
			claimErr, err, row != nil, rt.copied["web"])
	}
	if got := specOf(t, s, "host-a", "web").TemplateGen; got != "" && got != "g1" {
		t.Errorf("the member records generation %q, want g1", got)
	}
}

// Review F5: a recreate judgment that goes no further leaves nothing that
// holds an Admin's claim of the item off.
func TestRV14C_AbandonedJudgmentLeavesAPinThatRefusesTheAdmin(t *testing.T) {
	s, rt := secServer(t)
	rt.pullUnpack = true
	carl := carlCtx(t, s)
	item := mkBundle(t, s, "build", "g1")
	tmpl := filepath.Join(item, "rootfs")
	seedSecCT(t, s, rt, "web", "running", corrosion.ContainerCreateSpec{})
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "running", Project: "acme", Image: tmpl,
		Labels:     map[string]string{corrosion.LabelStack: "st"},
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: tmpl, TemplateGen: "g1", Arch: "amd64"}),
	}); err != nil {
		t.Fatal(err)
	}
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindOCI, Image: tmpl, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if _, _, err := s.judgeContainerRecreate(carl, upd, f); err != nil {
		t.Fatalf("judge: %v", err)
	}
	if _, err := s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "replaced", Dest: "build", Project: "acme"}); err != nil {
		t.Fatalf("the Admin's claim after an abandoned judgment: %v", err)
	}
}

// A recreate never deletes a member it cannot then rebuild: an unprivileged
// member's item claimed for another project between the delete and the
// create does not refuse the create; the member is rebuilt from the copy
// its host took, and judged, before the delete.
func TestComposeRecreate_AClaimForAnotherProjectAfterTheDeleteKeepsTheMember(t *testing.T) {
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
		Labels: map[string]string{corrosion.LabelStack: "st"},
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: tmpl, TemplateGen: "g1", Arch: "amd64",
			IDMapBase: 100000, Confinement: lxc.ConfinementDefault}),
	}); err != nil {
		t.Fatal(err)
	}
	var claimErr error
	s.recreateDeleted = func(string) {
		_, claimErr = s.PullOCIImage(adminCtx(), &pb.PullOCIImageRequest{Image: "theirs", Dest: "build", Project: "other"})
	}
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindOCI, Image: tmpl, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	err := recreateMember(carl, s, upd, f)
	if claimErr != nil || err != nil || rt.copied["web"] != "judged" {
		t.Fatalf("claim=%v recreate=%v copied=%q: want the member rebuilt from the judged copy", claimErr, err, rt.copied["web"])
	}
}
