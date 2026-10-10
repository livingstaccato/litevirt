package grpcapi

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
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

// m-e. A peer move's source row authorizes its host access: one that cannot
// be read fails the restore Unavailable (retried), and removes what was
// imported — never reads as "no source" and strips the container.
func TestRestoreContainer_SourceRowReadErrorIsUnavailable(t *testing.T) {
	s, rt, repo, ts, token, proofID := setupProofRestore(t)
	rt.importHook = func() { _ = s.db.Execute(context.Background(), `DROP TABLE containers`) }
	rs := &progressStream[pb.RestoreContainerProgress]{ctx: proofRestoreCtx(token)}
	err := s.RestoreContainer(&pb.RestoreContainerRequest{
		Name: "ct1", RepoPath: repo, Timestamp: ts, Proof: relocProof(proofID, token),
	}, rs)
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("restore with an unreadable source row = %v; want Unavailable", err)
	}
	deleted := false
	for _, n := range rt.deleteCalls {
		deleted = deleted || n == "ct1"
	}
	if !deleted {
		t.Fatalf("the imported container was left behind: deleteCalls=%v", rt.deleteCalls)
	}
}
