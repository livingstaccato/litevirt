package grpcapi

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedOCIMember records stack st's member web on host-a as compose creates
// it (project _default, the stack label), built from OCI library item
// web-img, and returns the image: the member names.
func seedOCIMember(t *testing.T, s *Server, rt *fakeCTRuntime) string {
	t.Helper()
	root := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "web-img", "rootfs"))
	image := "rootfs:" + root
	seedSecCT(t, s, rt, "web", "stopped", corrosion.ContainerCreateSpec{})
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{
		HostName: "host-a", Name: "web", State: "stopped", Project: "", Image: image,
		Labels:     map[string]string{corrosion.LabelStack: "st"},
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: image, Arch: "amd64"}),
	}); err != nil {
		t.Fatal(err)
	}
	return image
}

func unchangedOCIRedeploy(image string) (*compose.File, planner.VMAction) {
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: image, CPU: 4}}}
	return f, planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
}

// Reviews I3 and I4: the image-owner check of a recreate's create runs in
// the recreate's judgment, before the delete, on the member's own host. An
// item another project owns there refuses a non-admin's unchanged redeploy
// with the member left as it is — never deleted and then refused:
//   - I3: an Admin claimed the member's (ownerless) item for project x;
//   - I4: the member was moved (migrate, relocation) onto a host whose
//     same-named item is x's own pull; items and owner records are per host,
//     so the template string the member recorded does not make that item its.
func TestComposeRecreate_AnotherProjectsItemIsRefusedBeforeTheDelete(t *testing.T) {
	for _, tc := range []struct{ name, why string }{
		{"admin-claim", "an Admin claimed the item for x"},
		{"moved-member", "the member was moved onto a host where x pulled its own web-img"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rt := ctPathServer(t)
			carl := carlCtx(t, s)
			image := seedOCIMember(t, s, rt)
			if err := s.writeOCIOwner("web-img", "x"); err != nil {
				t.Fatal(err)
			}
			f, upd := unchangedOCIRedeploy(image)
			err := recreateMember(carl, s, upd, f)
			if status.Code(err) != codes.PermissionDenied {
				t.Fatalf("%s: unchanged redeploy by a non-admin: %v, want PermissionDenied", tc.why, err)
			}
			msg := status.Convert(err).Message()
			for _, want := range []string{`project "x"`, "Admin", "left as it is"} {
				if !strings.Contains(msg, want) {
					t.Errorf("refusal %q does not say %q", msg, want)
				}
			}
			memberExists(t, s, rt)
			if len(rt.createCalls) != 0 {
				t.Fatalf("created: %+v", rt.createCalls)
			}
		})
	}
}

// An item with no owner record (pulled by an earlier build, or without
// --project), or owned by the member's own project, still backs the member's
// unchanged redeploy, as on main.
func TestComposeRecreate_AnOwnerlessOrOwnItemStillBacksItsMember(t *testing.T) {
	for _, owner := range []string{"", "_default"} {
		t.Run("owner="+owner, func(t *testing.T) {
			s, rt := ctPathServer(t)
			carl := carlCtx(t, s)
			image := seedOCIMember(t, s, rt)
			if owner != "" {
				if err := s.writeOCIOwner("web-img", owner); err != nil {
					t.Fatal(err)
				}
			}
			f, upd := unchangedOCIRedeploy(image)
			if err := recreateMember(carl, s, upd, f); err != nil {
				t.Fatalf("unchanged redeploy from an item owned by %q: %v", owner, err)
			}
			if row, _ := corrosion.GetContainer(context.Background(), s.db, "host-a", "web"); row == nil {
				t.Fatal("the member is gone after its redeploy")
			}
			if len(rt.createCalls) != 1 {
				t.Fatalf("creates = %d, want 1", len(rt.createCalls))
			}
		})
	}
}

// The member's recorded template grants its host-path authority, never the
// item's ownership: a create carrying the grant is still refused another
// project's item, on this host and, forwarded, on the target (the owner rule
// is asked for whether or not the template is granted).
func TestComposeRecreate_TheMembersTemplateIsNoOwnerGrant(t *testing.T) {
	s, _ := ctPathServer(t)
	root := mkCTRootfs(t, filepath.Join(s.dataDir, "oci", "web-img", "rootfs"))
	image := "rootfs:" + root
	if err := s.writeOCIOwner("web-img", "x"); err != nil {
		t.Fatal(err)
	}
	granted := context.WithValue(ctOperatorCtx(), recreateTemplateKey{}, image)
	if _, err := s.CreateContainer(granted, &pb.CreateContainerRequest{Name: "web", Template: image, Project: "beta"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a granted create from another project's item: %v, want PermissionDenied", err)
	}

	peer := &fakeOwnerPeer{}
	s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) { return peer, func() {}, nil }
	_, _ = s.CreateContainer(granted, &pb.CreateContainerRequest{Name: "web", HostName: "host-b", Template: image})
	_, _ = s.CreateContainer(ctOperatorCtx(), &pb.CreateContainerRequest{Name: "web2", HostName: "host-b", Template: image})
	if len(peer.strict) != 2 || !peer.strict[0] || !peer.strict[1] {
		t.Fatalf("owner-strict on the forwards = %v, want [true true]", peer.strict)
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
