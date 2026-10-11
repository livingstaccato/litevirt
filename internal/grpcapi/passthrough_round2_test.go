package grpcapi

import (
	"context"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/auth"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/lxc"
)

// N5. A USB mapping's devices are what every VM granted resourcemap.use on
// it receives: changing them hands out host USB, which is the admin role's.
// Operator's resourcemap.write changes PCI mappings as before, never a USB
// one — not adding a device, not removing one, not deleting the mapping.
func TestMappingDevices_USBEditsAreAdminOnly(t *testing.T) {
	s := reconfigServer(t)
	addUSBMapping(t, s, "dongle", "test-host", "usb:1a86:7523")
	op := userCtx("op", "operator")
	if _, err := s.AddMappingDevice(op, &pb.AddMappingDeviceRequest{Mapping: "dongle", Host: "test-host", Address: "usb:20a0:4108"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator add of a USB device = %v; want PermissionDenied", err)
	}
	if _, err := s.AddMappingDevice(op, &pb.AddMappingDeviceRequest{Mapping: "fresh", Host: "test-host", Address: "usb:20a0:4108"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator add of a USB device to a new mapping = %v; want PermissionDenied", err)
	}
	if _, err := s.RemoveMappingDevice(op, &pb.RemoveMappingDeviceRequest{Mapping: "dongle", Host: "test-host", Address: "usb:1a86:7523"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator removal from a USB mapping = %v; want PermissionDenied", err)
	}
	if _, err := s.DeleteResourceMapping(op, &pb.DeleteResourceMappingRequest{Name: "dongle"}); status.Code(err) != codes.PermissionDenied {
		t.Errorf("operator delete of a USB mapping = %v; want PermissionDenied", err)
	}
	if m, _ := corrosion.GetResourceMapping(context.Background(), s.db, "dongle"); m == nil || len(m.Devices) != 1 || m.Devices[0].Address != "usb:1a86:7523" {
		t.Fatalf("a refused edit changed the mapping: %+v", m)
	}
	// PCI mappings keep resourcemap.write.
	if _, err := s.AddMappingDevice(op, &pb.AddMappingDeviceRequest{Mapping: "gpu", Host: "test-host", Address: "0000:03:00.0"}); err != nil {
		t.Errorf("operator add of a PCI device: %v", err)
	}
	if _, err := s.RemoveMappingDevice(op, &pb.RemoveMappingDeviceRequest{Mapping: "gpu", Host: "test-host", Address: "0000:03:00.0"}); err != nil {
		t.Errorf("operator removal of a PCI device: %v", err)
	}
	// An admin edits a USB mapping.
	if _, err := s.AddMappingDevice(adminCtx(), &pb.AddMappingDeviceRequest{Mapping: "dongle", Host: "test-host", Address: "usb:20a0:4108"}); err != nil {
		t.Errorf("admin add of a USB device: %v", err)
	}
}

// m-f. An unprivileging an earlier attempt left unfinished is finished into
// the range its marker recorded — the files already partly there — never a
// newly allocated one; an already unprivileged container keeps its range.
func TestUnprivilegeContainer_ReusesTheMarkersRange(t *testing.T) {
	s, rt := secServer(t)
	const marked = int64(1_000_131_072)
	rt.security = map[string]lxc.Security{
		"half":   {Confinement: lxc.ConfinementLegacy, Converting: true, ConvertTo: &lxc.ConvertOpts{IDMap: &lxc.IDMap{Base: marked, Size: lxc.IDMapSize}}},
		"unpriv": {Confinement: lxc.ConfinementLegacy, IDMap: &lxc.IDMap{Base: 1_000_196_608, Size: lxc.IDMapSize}},
	}
	base, err := s.unprivilegeContainer(context.Background(), rt, "half")
	if err != nil {
		t.Fatal(err)
	}
	if base != marked || len(rt.converts) != 1 || rt.converts[0].to.IDMap.Base != marked {
		t.Fatalf("resumed unprivileging used %d (converts %+v); want the marker's %d", base, rt.converts, marked)
	}
	if base, err := s.unprivilegeContainer(context.Background(), rt, "unpriv"); err != nil || base != 1_000_196_608 {
		t.Fatalf("an unprivileged container moved to %d (%v); want its own range", base, err)
	}
	base, err = s.unprivilegeContainer(context.Background(), rt, "fresh")
	if err != nil || base == 0 || base == marked || base == 1_000_196_608 {
		t.Fatalf("a privileged container was given %d (%v); want a fresh range", base, err)
	}
	if last := rt.converts[len(rt.converts)-1]; last.to.Confinement != lxc.ConfinementDefault {
		t.Fatalf("unprivileging left confinement %q", last.to.Confinement)
	}
}

// N2. A non-admin's clone of a privileged container is never refused: it
// lands unprivileged with default confinement, and says so. The ruling made
// on the entry node (Unprivileged) is honoured by the source's host, where
// the caller is the peer.
func TestCloneContainer_NonAdminCloneLandsUnprivileged(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "p", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	if _, err := s.CloneContainer(ctOperatorCtx(), &pb.CloneContainerRequest{Source: "p", Target: "p2", HostName: "host-a"}); err != nil {
		t.Fatalf("operator clone of a privileged container: %v", err)
	}
	if spec := specOf(t, s, "host-a", "p2"); spec.IDMapBase == 0 || spec.Confinement != lxc.ConfinementDefault {
		t.Fatalf("operator clone recorded %+v; want an id range and default confinement", spec)
	}
	// The peer (an admin) carrying the entry node's ruling.
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "p", Target: "p3", HostName: "host-a", Unprivileged: true}); err != nil {
		t.Fatal(err)
	}
	if spec := specOf(t, s, "host-a", "p3"); spec.IDMapBase == 0 {
		t.Fatalf("a forwarded non-admin clone kept the privileged mode: %+v", spec)
	}
	if _, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "p", Target: "p4", HostName: "host-a"}); err != nil {
		t.Fatal(err)
	}
	if spec := specOf(t, s, "host-a", "p4"); spec.IDMapBase != 0 {
		t.Fatalf("an admin's clone lost the privileged mode: %+v", spec)
	}
}

// m-e, R4-I1. A peer move's source row authorizes its NICs, host access and
// privilege: one that cannot be read fails the restore Unavailable (retried);
// one this replica does not hold yet refuses before anything is written —
// FailedPrecondition for a cold migrate (its source rolls back), Unavailable
// for a relocation (its coordinator defers); the row the moving peer sends is
// used as sent. Never "no source", which would strip the container.
func TestPeerMoveSource(t *testing.T) {
	s := testServer(t)
	s.hostName = "self"
	s.sourceRowWait = 50 * time.Millisecond
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(relocateTokenMDKey, "tok"))
	req := &pb.RestoreContainerRequest{Name: "ct1"}
	if _, err := s.peerMoveSource(ctx, req, "src"); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("a migrate whose source row is not here = %v; want FailedPrecondition", err)
	}
	// A relocation with no row and none sent is an earlier coordinator's: it
	// restores as main did (P1, TestPeerMoveSource_OlderCoordinatorWithNoRowRestoresAsMain).
	sent := corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{{Name: "eth0", Bridge: "br0"}}})
	if src, err := s.peerMoveSource(ctx, &pb.RestoreContainerRequest{Name: "ct1", SourceCreateSpec: sent}, "src"); err != nil || src == nil || src.CreateSpec != sent {
		t.Errorf("the row the peer sent = %+v (%v); want it as sent", src, err)
	}
	if err := corrosion.UpsertContainer(context.Background(), s.db, corrosion.ContainerRecord{HostName: "src", Name: "ct1", State: "stopped", CreateSpec: sent}); err != nil {
		t.Fatal(err)
	}
	if src, err := s.peerMoveSource(ctx, req, "src"); err != nil || src == nil || src.CreateSpec != sent {
		t.Errorf("the migrate source row here = %+v (%v); want it", src, err)
	}
	_ = s.db.Close()
	for _, from := range []string{"src", ""} {
		if _, err := s.peerMoveSource(ctx, req, from); status.Code(err) != codes.Unavailable {
			t.Errorf("an unreadable source row (migrate from %q) = %v; want Unavailable", from, err)
		}
	}
}

// m-1. A source with an unfinished conversion is refused for cloning: its
// copied marker names the SOURCE's target range, so the clone would share it
// (and never start). Finish the conversion first.
func TestCloneContainer_RefusesAConvertingSource(t *testing.T) {
	s, rt := secServer(t)
	seedSecCT(t, s, rt, "half", "stopped", corrosion.ContainerCreateSpec{Template: "download"})
	rt.security = map[string]lxc.Security{"half": {Confinement: lxc.ConfinementLegacy, Converting: true,
		ConvertTo: &lxc.ConvertOpts{IDMap: &lxc.IDMap{Base: 1_000_131_072, Size: lxc.IDMapSize}}}}
	_, err := s.CloneContainer(adminCtx(), &pb.CloneContainerRequest{Source: "half", Target: "h2", HostName: "host-a"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("clone of a converting source = %v; want FailedPrecondition", err)
	}
	if len(rt.cloneCalls) != 0 {
		t.Fatalf("the refused clone copied the source: %+v", rt.cloneCalls)
	}
}

// projectBoundCtx is a caller bound as Operator on /projects/<project> only,
// with the auth engine loaded, so RBAC (not the legacy role) decides.
func projectBoundCtx(t *testing.T, s *Server, user, project string) context.Context {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertUser(ctx, s.db, user, "operator", "x"); err != nil {
		t.Fatal(err)
	}
	if err := auth.SeedBuiltinRoles(ctx, s.db); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertRoleBinding(ctx, s.db, corrosion.RoleBindingRecord{
		ID: user + "-p", Path: "/projects/" + project, Role: "Operator", Principal: "user:" + user + "@local", Propagate: true,
	}); err != nil {
		t.Fatal(err)
	}
	e := auth.NewEngine(s.db)
	if err := e.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	s.SetAuthEngine(e)
	return userCtx(user, "operator")
}

// R2-I1. A restore renders a managed NIC on its network's own bridge, never
// the archive spec's; a raw NIC is kept only for a caller with raw-bridge
// authority or a peer move whose source row carries it — otherwise it is
// dropped (and said), and the restore proceeds.
func TestAuthorizeRestoredNICs(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.UpsertNetwork(ctx, s.db, corrosion.NetworkRecord{Name: "ctnet", Type: "bridge",
		Config: `{"type":"bridge","interface":"br-ctnet"}`}); err != nil {
		t.Fatal(err)
	}
	forged := corrosion.ContainerCreateSpec{Template: "download", Networks: []corrosion.ContainerNetwork{
		{Name: "eth0", NetworkName: "ctnet", Bridge: "br-victim", MAC: "02:00:00:00:00:01"},
		{Name: "eth1", Bridge: "br-mgmt"},
	}}
	scoped := projectBoundCtx(t, s, "carol", "acme")
	out, dropped, _ := s.authorizeRestoredNICs(scoped, "acme", forged, nil, false)
	if len(out.Networks) != 1 || out.Networks[0].Bridge != "br-ctnet" || out.Networks[0].NetworkName != "ctnet" || out.Networks[0].MAC != "02:00:00:00:00:01" {
		t.Fatalf("a scoped operator's restore NICs = %+v; want only eth0 on br-ctnet", out.Networks)
	}
	if !strings.Contains(strings.Join(dropped, " "), "br-mgmt") {
		t.Errorf("the dropped raw NIC was not reported: %v", dropped)
	}
	// Raw-bridge authority (an admin) keeps the raw NIC; the managed bridge
	// is still the network's.
	out, _, _ = s.authorizeRestoredNICs(adminCtx(), "acme", forged, nil, false)
	if len(out.Networks) != 2 || out.Networks[0].Bridge != "br-ctnet" || out.Networks[1].Bridge != "br-mgmt" {
		t.Fatalf("an admin's restore NICs = %+v", out.Networks)
	}
	// A peer move keeps exactly the NICs its source row records (R4-I1): the
	// raw NIC the row records, and not the archive's eth0 it does not.
	src := &corrosion.ContainerRecord{CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download",
		Networks: []corrosion.ContainerNetwork{{Name: "eth1", Bridge: "br-mgmt"}}})}
	if out, _, _ = s.authorizeRestoredNICs(adminCtx(), "acme", forged, src, true); len(out.Networks) != 1 || out.Networks[0].Bridge != "br-mgmt" {
		t.Errorf("a peer move's NICs = %+v; want only the raw NIC its source row records", out.Networks)
	}
	// With no source row (an earlier coordinator, P1) it restores as main:
	// the managed NIC on its network's bridge, the raw one dropped.
	if out, _, err := s.authorizeRestoredNICs(adminCtx(), "acme", forged, nil, true); err != nil || len(out.Networks) != 1 || out.Networks[0].Bridge != "br-ctnet" {
		t.Errorf("a peer move with no source row = %+v (%v); want only eth0 on br-ctnet", out.Networks, err)
	}
}
