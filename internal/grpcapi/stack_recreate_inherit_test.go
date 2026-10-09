package grpcapi

import (
	"context"
	"encoding/json"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/lxc"
)

// carlPeerCtx is a call from the peer host-b, promoted by
// auth.forwarded_identity to the deployer carl (a non-admin).
func carlPeerCtx() context.Context {
	return context.WithValue(context.WithValue(mtlsCtx("host-b"), ctxKeyUsername, "carl"), ctxKeyRole, "viewer")
}

// inheritMarker is the recreate decision a forwarding peer sends with a
// recreate's create, in its wire form.
func inheritMarker(t *testing.T, fields map[string]any) metadata.MD {
	t.Helper()
	b, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return metadata.Pairs("x-litevirt-recreate-inherit-bin", string(b))
}

func webMarker() map[string]any {
	return map[string]any{"name": "web", "host": "host-a", "image": "alpine:3.22", "template": "download",
		"privileged": true, "confinement": lxc.ConfinementLegacy, "inherited": true}
}

func webPrivilegedCreate() *pb.CreateContainerRequest {
	return &pb.CreateContainerRequest{Name: "web", Image: "alpine:3.22", Template: "download", Distro: "alpine", Release: "3.22",
		Arch: "amd64", Privileged: true, Confinement: lxc.ConfinementLegacy}
}

func redeployMainEraFromEntry(entry *Server, carl context.Context, image string) error {
	f := &compose.File{Name: "st", VMs: map[string]compose.VMDef{"web": {Kind: compose.WorkloadKindLXC, Image: image, CPU: 4}}}
	upd := planner.VMAction{Kind: planner.OpUpdate, VMName: "web", TargetHost: "host-a", IsContainer: true}
	return recreateMember(carl, entry, upd, f)
}

// Post-breaker fix: with auth.forwarded_identity on, a non-admin's unchanged
// redeploy of a main-era (privileged, legacy) member, entering on another
// host, keeps the member's mode on the member's host — it is not deleted and
// then refused "requires the admin role".
func TestComposeRecreate_ForwardedIdentity_APrivilegedMemberKeepsItsMode(t *testing.T) {
	entry, tgt, rt, carl := remoteEntryAs(t, true)
	seedMember(t, tgt, rt, "3.22")
	if err := redeployMainEraFromEntry(entry, carl, "alpine:3.22"); err != nil {
		t.Fatalf("unchanged redeploy of a privileged member from another entry host: %v", err)
	}
	spec := specOf(t, tgt, "host-a", "web")
	if spec.IDMapBase != 0 || spec.Confinement != lxc.ConfinementLegacy {
		t.Fatalf("recreated member idmap base %d confinement %q, want privileged and legacy", spec.IDMapBase, spec.Confinement)
	}
}

// A changed image of such a member still needs the Admin role or ct.exec,
// and is refused before the delete.
func TestComposeRecreate_ForwardedIdentity_AChangedImageIsRefusedBeforeTheDelete(t *testing.T) {
	entry, tgt, rt, carl := remoteEntryAs(t, true)
	seedMember(t, tgt, rt, "3.22")
	err := redeployMainEraFromEntry(entry, carl, "alpine:3.23")
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("changed image of a privileged member: %v, want PermissionDenied", err)
	}
	memberExists(t, tgt, rt)
}

// A client cannot send the decision: on a call that is not an authenticated
// peer's, the marker is ignored and the opt-outs stay the Admin's.
func TestComposeRecreate_AClientCannotSendTheRecreateDecision(t *testing.T) {
	_, tgt, _, carl := remoteEntryAs(t, true)
	ctx := metadata.NewIncomingContext(carl, inheritMarker(t, webMarker()))
	if _, err := tgt.CreateContainer(ctx, webPrivilegedCreate()); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a client's privileged create carrying a recreate decision: %v, want PermissionDenied", err)
	}
}

// The decision grants only the create it was judged for: another name,
// another host, another image or template, or a broader mode than the one
// it records, gets nothing from it. The same create with the matching
// decision passes.
func TestComposeRecreate_ARecreateDecisionGrantsOnlyItsCreate(t *testing.T) {
	_, tgt, _, _ := remoteEntryAs(t, true)
	for _, tc := range []struct {
		field string
		value any
	}{
		{"name", "other"},
		{"host", "host-b"},
		{"image", "alpine:3.23"},
		{"template", "rootfs:/srv/x"},
		{"privileged", false},
	} {
		m := webMarker()
		m[tc.field] = tc.value
		ctx := metadata.NewIncomingContext(carlPeerCtx(), inheritMarker(t, m))
		if _, err := tgt.CreateContainer(ctx, webPrivilegedCreate()); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("decision with %s=%v: %v, want PermissionDenied", tc.field, tc.value, err)
		}
	}
	ctx := metadata.NewIncomingContext(carlPeerCtx(), inheritMarker(t, webMarker()))
	if _, err := tgt.CreateContainer(ctx, webPrivilegedCreate()); err != nil {
		t.Fatalf("the create the decision was judged for: %v", err)
	}
}
