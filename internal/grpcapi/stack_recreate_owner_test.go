package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Review I3: a member that runs from an OCI library item keeps running from
// it when the item is later claimed by another project (an Admin's claim):
// the member's own recorded template is its own for ownership too, so a
// non-admin's unchanged redeploy is not deleted and then refused. A NEW
// container from the item by another project is still refused.
func TestComposeRecreate_AClaimedItemStillBacksItsMember(t *testing.T) {
	s, rt := ctPathServer(t)
	root := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "web-img", "rootfs"))
	image := "rootfs:" + root
	carl := carlCtx(t, s)
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	seedStackCT(t, s, "st", "host-a", "web", image, corrosion.ContainerCreateSpec{Template: image, Arch: "amd64"})
	// An Admin claims the item for project x.
	if err := s.writeOCIOwner("web-img", "x"); err != nil {
		t.Fatal(err)
	}
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: image, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); err != nil {
		t.Fatalf("unchanged redeploy of a member whose item was claimed: %v", err)
	}
	if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "web"); row == nil {
		t.Fatal("the member is gone after its redeploy")
	}
	// A new container from x's item, in another project, by a non-admin.
	if _, err := s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{Name: "newbie", Template: image, Project: "beta"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a new container from another project's item: %v, want PermissionDenied", err)
	}
	// The grant is the member's template only: another item's path is not
	// covered by it.
	other := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "other-img", "rootfs"))
	if err := s.writeOCIOwner("other-img", "x"); err != nil {
		t.Fatal(err)
	}
	granted := context.WithValue(ctOperatorCtx(), recreateTemplateKey{}, image)
	if _, err := s.CreateContainer(granted, &pb.CreateContainerRequest{Name: "sneak", Template: "rootfs:" + other, Project: "beta"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a create naming another item under a grant for %s: %v, want PermissionDenied", image, err)
	}
}

// A create forwarded to the member's host for a granted (unchanged) template
// does not ask that host to apply the owner rule; any other create from a
// non-admin still does.
func TestComposeRecreate_AGrantedTemplateIsForwardedWithoutTheOwnerRule(t *testing.T) {
	s, _ := ctPathServer(t)
	peer := &fakeOwnerPeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	tpl := "rootfs:" + filepath.Join(s.dataDir, "oci", "web-img", "rootfs")
	granted := context.WithValue(ctOperatorCtx(), recreateTemplateKey{}, tpl)
	_, _ = s.CreateContainer(granted, &pb.CreateContainerRequest{Name: "web", HostName: "host-b", Template: tpl})
	_, _ = s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{Name: "web2", HostName: "host-b", Template: tpl})
	if len(peer.strict) != 2 || peer.strict[0] || !peer.strict[1] {
		t.Fatalf("owner-strict on the forwards = %v, want [false true]", peer.strict)
	}
}

// Review M6: a member that cannot be read is not "no member": the recreate
// fails before its delete (the deploy retries), so a privileged member never
// comes back unprivileged for want of a read.
func TestComposeRecreate_AnUnreadableMemberFailsBeforeTheDelete(t *testing.T) {
	s, rt := secServer(t)
	carl := carlCtx(t, s)
	seedMember(t, s, rt, "3.22")
	prev := recreateMemberRead
	recreateMemberRead = func(context.Context, *corrosion.Client, string, string) (*corrosion.ContainerRecord, error) {
		return nil, errors.New("database is locked")
	}
	t.Cleanup(func() { recreateMemberRead = prev })
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: "alpine:3.22", CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	if err := recreateMember(carl, s, upd, f); err == nil {
		t.Fatal("the recreate went ahead without reading its member")
	}
	if len(rt.deleteCalls) != 0 || len(rt.createCalls) != 0 {
		t.Fatalf("runtime touched: deletes %v creates %+v", rt.deleteCalls, rt.createCalls)
	}
}
