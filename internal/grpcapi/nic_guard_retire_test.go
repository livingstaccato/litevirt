package grpcapi

import (
	"errors"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

const retireMAC = "52:54:00:ab:10:01"

// guardHotplugServer is a hot-plug server with guard records writable and a
// VM vm1 in state.
func guardHotplugServer(t *testing.T, state string) (*Server, *libvirtfake.Fake) {
	t.Helper()
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	openGuardRecords(t, s)
	seedNICVM(t, s, "vm1", state)
	fake := s.virt.(*libvirtfake.Fake)
	if state == "running" {
		fake.SetState("vm1", libvirtfake.StateRunning)
	}
	return s, fake
}

func attachGuardedNIC(t *testing.T, s *Server, mac string) {
	t.Helper()
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "vm1",
		Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac}}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if !guardRecordsOf(t, s, "vm1")[mac] {
		t.Fatalf("fixture: the attached NIC has no guard record")
	}
}

// TestDetachNIC_RetiresItsGuardRecord: the detach of a NIC, running or
// stopped, retires the NIC's guard record in the same operation (lab 2, C3).
func TestDetachNIC_RetiresItsGuardRecord(t *testing.T) {
	for _, state := range []string{"running", "stopped"} {
		t.Run(state, func(t *testing.T) {
			s, _ := guardHotplugServer(t, state)
			attachGuardedNIC(t, s, retireMAC)
			if _, err := s.DetachDevice(adminCtx(), &pb.DetachDeviceRequest{VmName: "vm1", NicMac: retireMAC}); err != nil {
				t.Fatalf("detach: %v", err)
			}
			if guardRecordsOf(t, s, "vm1")[retireMAC] {
				t.Error("the detached NIC's guard record is still live")
			}
		})
	}
}

// TestAttachNIC_FailedAttachRetiresItsGuardRecord: an attach that fails after
// writing the NIC's guard record retires it with the rollback.
func TestAttachNIC_FailedAttachRetiresItsGuardRecord(t *testing.T) {
	s, fake := guardHotplugServer(t, "running")
	fake.FailAttachNIC = func(string, string, string, string) error { return errors.New("injected") }
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{VmName: "vm1",
		Nic: &pb.NetworkAttachment{Name: "lan", Mac: retireMAC}}); err == nil {
		t.Fatal("the injected failure did not fail the attach")
	}
	if guardRecordsOf(t, s, "vm1")[retireMAC] {
		t.Error("the failed attach left its guard record live")
	}
}

// TestAttachNIC_IncompleteRollbackKeepsTheGuardRecord: when the rollback
// cannot take the NIC out of the domain, the NIC may still be live, and it
// keeps its guard record.
func TestAttachNIC_IncompleteRollbackKeepsTheGuardRecord(t *testing.T) {
	s, fake := guardHotplugServer(t, "running")
	ctx := adminCtx()
	if err := s.db.Execute(ctx,
		`CREATE TRIGGER nic_insert_fail BEFORE INSERT ON vm_nics BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	fake.FailDetachNIC = func(string, string) error { return errors.New("injected: detach refused") }
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "vm1",
		Nic: &pb.NetworkAttachment{Name: "lan", Mac: retireMAC}}); err == nil {
		t.Fatal("the attach did not fail")
	}
	if live, _ := fake.DumpXML("vm1"); !nicMacInXML(live, retireMAC) {
		t.Fatal("fixture: the NIC is not left in the live domain")
	}
	if !guardRecordsOf(t, s, "vm1")[retireMAC] {
		t.Error("a NIC still in the live domain lost its guard record")
	}
}

// TestRecoverNICDetach_RetiresTheGuardRecord: a detach recovered after a
// crash retires the NIC's guard record before it completes.
func TestRecoverNICDetach_RetiresTheGuardRecord(t *testing.T) {
	s, _ := guardHotplugServer(t, "running")
	ctx := adminCtx()
	attachGuardedNIC(t, s, retireMAC)
	beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach, detachNICRequestHash("vm1", retireMAC),
		[]string{corrosion.OpStepReserved}, map[string]string{"mac": retireMAC})
	s.RecoverHardwareOperations(ctx)
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("fixture: the detach was not recovered: %q", vm.ActiveOperationID)
	}
	if guardRecordsOf(t, s, "vm1")[retireMAC] {
		t.Error("the recovered detach left the NIC's guard record live")
	}
}

// leakGuardRecord writes a guard record for vm1's MAC mac, as an earlier
// build's detach or failed attach left it.
func leakGuardRecord(t *testing.T, s *Server, mac string) {
	t.Helper()
	if err := corrosion.PutNICGuard(adminCtx(), s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		corrosion.NICGuardRecord{VMName: "vm1", MAC: mac, Mode: corrosion.NICGuardOn, Network: "lan"}, "old-build"); err != nil {
		t.Fatal(err)
	}
}

// TestRetireOrphanNICGuards_OnlyWhatNoNICCarries: on the VM's owner, with no
// operation in flight, a record whose MAC has no live NIC row and is in
// neither definition of the domain is retired; a record whose NIC is still in
// the domain, or has a live row, is kept.
func TestRetireOrphanNICGuards_OnlyWhatNoNICCarries(t *testing.T) {
	s, fake := guardHotplugServer(t, "running")
	ctx := adminCtx()
	attachGuardedNIC(t, s, retireMAC)
	const orphan = "52:54:00:ab:10:99"
	leakGuardRecord(t, s, orphan)
	// A NIC with a live row the domain does not have yet (its definition is
	// rebuilt from the rows at the next start): kept.
	const rowOnly = "52:54:00:ab:10:98"
	if err := corrosion.UpsertNIC(ctx, s.db, corrosion.NICRecord{VMName: "vm1", ID: corrosion.DeterministicNICID("vm1", rowOnly),
		NetworkName: "lan", MAC: rowOnly, Ordinal: 5}); err != nil {
		t.Fatal(err)
	}
	leakGuardRecord(t, s, rowOnly)

	// The NIC's row is gone but it is still in the domain: kept.
	if err := corrosion.TombstoneNIC(ctx, s.db, "vm1", corrosion.DeterministicNICID("vm1", retireMAC)); err != nil {
		t.Fatal(err)
	}
	s.retireOrphanNICGuards(ctx, "vm1", "")
	got := guardRecordsOf(t, s, "vm1")
	if !got[retireMAC] {
		t.Error("the record of a NIC still in the domain was retired")
	}
	if got[orphan] {
		t.Error("the record of a NIC that exists nowhere was not retired")
	}
	if !got[rowOnly] {
		t.Error("the record of a NIC with a live row was retired")
	}

	// Once it is out of the domain too, it goes.
	if err := fake.DetachNIC("vm1", retireMAC); err != nil {
		t.Fatal(err)
	}
	s.retireOrphanNICGuards(ctx, "vm1", "")
	if guardRecordsOf(t, s, "vm1")[retireMAC] {
		t.Error("the record of a NIC gone from its row and its domain was not retired")
	}
}

// TestRetireOrphanNICGuards_NotUnderAnotherOperationOrOffOwner: nothing is
// retired while another operation holds the VM (an attach writes its record
// before its row), or on a host that does not own the VM.
func TestRetireOrphanNICGuards_NotUnderAnotherOperationOrOffOwner(t *testing.T) {
	s, _ := guardHotplugServer(t, "running")
	ctx := adminCtx()
	const orphan = "52:54:00:ab:10:99"
	leakGuardRecord(t, s, orphan)

	beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceAttach, "h", []string{corrosion.OpStepReserved},
		map[string]string{"mac": orphan})
	s.retireOrphanNICGuards(ctx, "vm1", "")
	if !guardRecordsOf(t, s, "vm1")[orphan] {
		t.Error("a record was retired while another operation holds the VM")
	}
	op := mustGetVM(t, s, "vm1").ActiveOperationID
	s.retireOrphanNICGuards(ctx, "vm1", op)
	if guardRecordsOf(t, s, "vm1")[orphan] {
		t.Error("the operation's own repair did not retire the record")
	}

	leakGuardRecord(t, s, orphan)
	s.hostName = "elsewhere"
	s.retireOrphanNICGuards(ctx, "vm1", op)
	if !guardRecordsOf(t, s, "vm1")[orphan] {
		t.Error("a host that does not own the VM retired its record")
	}
}
