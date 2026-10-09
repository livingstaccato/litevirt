package grpcapi

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// seedRecreateCT records container name on host with the given image and spec.
func seedRecreateCT(t *testing.T, s *Server, host, name, image string, spec corrosion.ContainerCreateSpec) {
	t.Helper()
	seedStackCT(t, s, "st", host, name, image, spec)
}

// seedStackCT records container name on host as a member of stack.
func seedStackCT(t *testing.T, s *Server, stack, host, name, image string, spec corrosion.ContainerCreateSpec) {
	t.Helper()
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: host, Name: name, State: "stopped", Project: "acme", Image: image,
		Labels: map[string]string{corrosion.LabelStack: stack}, CreateSpec: corrosion.EncodeCreateSpec(spec),
	}); err != nil {
		t.Fatal(err)
	}
}

func unprivilegedSpec(s *Server, release string) corrosion.ContainerCreateSpec {
	return corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", Release: release, Arch: "amd64",
		IDMapBase: s.idmapSlotBase(s.idmapStartSlot()), Confinement: lxc.ConfinementDefault}
}

// Review C1: two recreates of one container name — here on two hosts, as two
// stacks may hold — are judged one after the other before either creates.
// The judgment of one must never reach the other's create: host-a's
// unprivileged member, recreated with a new image, comes back unprivileged
// even though host-b's privileged member was judged in between.
func TestComposeRecreate_AJudgmentNeverReachesAnotherRecreate(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	seedStackCT(t, s, "a", "host-a", "web", "alpine:3.22", unprivilegedSpec(s, "3.22"))
	seedStackCT(t, s, "b", "host-b", "web", "alpine:3.22", corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"})
	fA := &compose.File{Name: "a", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.23"}}}
	fB := &compose.File{Name: "b", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	updA := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	updB := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-b", IsContainer: true}

	decA, _, err := s.judgeContainerRecreate(carl, updA, fA)
	if err != nil {
		t.Fatalf("judge A: %v", err)
	}
	if _, _, err := s.judgeContainerRecreate(carl, updB, fB); err != nil {
		t.Fatalf("judge B: %v", err)
	}
	if err := s.deleteWorkload(carl, updA); err != nil {
		t.Fatal(err)
	}
	if err := s.deployCreatePlanned(withRecreateDecision(carl, decA), updA, fA); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase == 0 || last.Confinement != lxc.ConfinementDefault {
		t.Fatalf("host-a's unprivileged member came back as %+v: it took host-b's privilege", last)
	}
	if row := lastAuditRow(t, s, "ct.recreate-security"); row.found {
		t.Errorf("a carry-over was recorded for host-a's member: %+v", row)
	}
}

// Review C1, scenario C: a recreate whose delete fails leaves nothing behind
// that a later create of the same name could pick up. A create with no
// judgment of its own carries nothing over.
func TestComposeRecreate_AFailedDeleteLeavesNoCarryOver(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedMember(t, s, rt, "3.22")
	rt.deleteErr = errors.New("lxc-destroy failed")
	same := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, same); err == nil {
		t.Fatal("the recreate succeeded with a failing delete")
	}
	// The member goes another way; a later deploy creates the name afresh
	// with a new image.
	rt.deleteErr = nil
	if err := corrosion.DeleteContainer(context.Background(), s.db, "host-a", "web"); err != nil {
		t.Fatal(err)
	}
	changed := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.23"}}}
	if err := s.deployCreatePlanned(carl, upd, changed); err != nil {
		t.Fatalf("create: %v", err)
	}
	if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase == 0 {
		t.Fatalf("the new container was created privileged (%+v) from a failed recreate's judgment", last)
	}
}

// Review M2: an equal image reference over a different rootfs source is a
// changed image, refused before the delete for a deployer without ct.exec.
func TestComposeRecreate_TheSameImageNameOverAnotherSourceIsAChange(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	seedRecreateCT(t, s, "host-a", "web", "alpine:3.22", corrosion.ContainerCreateSpec{Template: "rootfs:/srv/other", Arch: "amd64"})
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("recreate over another source by a deployer without ct.exec: %v, want PermissionDenied", err)
	}
	memberExists(t, s, rt)
}

// Review I1: a member whose image is a rootfs path outside the OCI library
// (main had no host-path check: any operator deployed it) is redeployed with
// a cpu bump by a non-admin as on main — the create's host-path authority is
// judged with the recreate, before the delete, and the unchanged source is
// the member's own. A CHANGED path still needs the authority, and is refused
// before the delete.
func TestComposeRecreate_ARootfsPathMemberIsJudgedBeforeTheDelete(t *testing.T) {
	root := filepath.Join(t.TempDir(), "rootfs")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "rootfs2")
	if err := os.MkdirAll(other, 0o755); err != nil {
		t.Fatal(err)
	}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}

	t.Run("unchanged path, cpu bump", func(t *testing.T) {
		s, rt := secServer(t)
		carl := carlCtx(t, s)
		seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
		seedRecreateCT(t, s, "host-a", "web", root, corrosion.ContainerCreateSpec{Template: root, Arch: "amd64"})
		f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: root, CPU: 4}}}
		if err := recreateMember(carl, s, upd, f); err != nil {
			t.Fatalf("a plain redeploy of a rootfs-path member: %v", err)
		}
		if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "web"); row == nil {
			t.Fatal("the member is gone after its redeploy")
		}
	})
	t.Run("changed path", func(t *testing.T) {
		s, rt := secServer(t)
		carl := carlCtx(t, s)
		seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
		seedRecreateCT(t, s, "host-a", "web", root, unprivilegedSpec(s, ""))
		f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: other}}}
		if err := recreateMember(carl, s, upd, f); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("a recreate onto a new host path by a non-admin: %v, want PermissionDenied", err)
		}
		memberExists(t, s, rt)
	})
}

// A new opt-out stays the Admin's even for a ct.exec holder (review M2).
func TestComposeRecreate_ANewOptOutNeedsAdminEvenWithExec(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	ctx := context.Background()
	if err := corrosion.InsertRole(ctx, s.db, corrosion.RoleRecord{Name: "Shell", Verbs: []string{"ct.exec"}}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: "carl-shell", Path: "/projects/acme/containers/web", Role: "Shell", Principal: "user:carl@local", Propagate: true}); err != nil {
		t.Fatal(err)
	}
	engine := auth.NewEngine(s.db)
	if err := engine.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(engine)
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	seedRecreateCT(t, s, "host-a", "web", "alpine:3.22", unprivilegedSpec(s, "3.22"))
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", Privileged: true}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("privileged recreate of an unprivileged member by a ct.exec holder: %v, want PermissionDenied", err)
	}
	memberExists(t, s, rt)
}

// mainEraSpec is a main-era member's create spec: privileged, legacy.
func mainEraSpec() corrosion.ContainerCreateSpec {
	return corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine", Release: "3.22", Arch: "amd64"}
}

// Review C1-R: a recreate on host-a is judged by host-a's member alone. A
// same-named privileged member on host-b — even of this stack — never donates
// its mode: with no member on host-a the container is created afresh,
// unprivileged, as the stack file states.
func TestComposeRecreate_AnotherHostsMemberNeverDonates(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedStackCT(t, s, "st", "host-b", "web", "alpine:3.22", mainEraSpec())
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	dec, _, err := s.judgeContainerRecreate(carl, upd, f)
	if err != nil {
		t.Fatalf("judge: %v", err)
	}
	if dec != nil {
		t.Fatalf("host-a's recreate was judged from host-b's member: %+v", dec)
	}
	if err := recreateMember(carl, s, upd, f); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase == 0 || last.Confinement != lxc.ConfinementDefault {
		t.Fatalf("host-a's container was created as %+v: it took host-b's privilege", last)
	}
}

// The create applies a decision only when it judged the member on the host
// the create targets: a decision about host-b's member carries nothing to a
// create on host-a.
func TestComposeRecreate_ADecisionForAnotherHostCarriesNothing(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedStackCT(t, s, "st", "host-b", "web", "alpine:3.22", mainEraSpec())
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	updB := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-b", IsContainer: true}
	decB, _, err := s.judgeContainerRecreate(carl, updB, f)
	if err != nil || decB == nil {
		t.Fatalf("judge B: %+v %v", decB, err)
	}
	updA := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := s.deployCreatePlanned(withRecreateDecision(carl, decB), updA, f); err != nil {
		t.Fatalf("create on host-a: %v", err)
	}
	if last := rt.createCalls[len(rt.createCalls)-1]; last.IDMapBase == 0 {
		t.Fatalf("host-a's container was created as %+v from host-b's decision", last)
	}
}

// A container on the target host that is not this stack's member (another
// stack's, by the label compose down deletes by) never donates its mode, and
// is not deleted by this stack's recreate: refused before the delete.
func TestComposeRecreate_AnotherStacksContainerIsNotRecreated(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	seedStackCT(t, s, "other", "host-a", "web", "alpine:3.22", mainEraSpec())
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22"}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("recreate of another stack's container: %v, want FailedPrecondition", err)
	}
	memberExists(t, s, rt)
	if len(rt.createCalls) != 0 {
		t.Fatalf("a container was created: %+v", rt.createCalls)
	}
}

// Review M3: the reading host's own template check (protected places, the
// daemon's state) runs with the recreate's judgment when this host is the
// one that reads it, so a member whose recorded path is now refused is
// refused before its delete, never after.
func TestComposeRecreate_AProtectedTemplateIsRefusedBeforeTheDelete(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	path := filepath.Join(s.dataDir, "images", "ct-root")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	seedStackCT(t, s, "st", "host-a", "web", path, corrosion.ContainerCreateSpec{Template: path, Arch: "amd64"})
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: path, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("recreate from a template in the daemon's state: %v, want InvalidArgument", err)
	}
	memberExists(t, s, rt)
}
