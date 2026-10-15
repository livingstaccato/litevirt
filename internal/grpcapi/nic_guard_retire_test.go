package grpcapi

import (
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A NIC detach that recovery rolls forward retires the NIC's guard record, as
// the detach itself does: a record left for a NIC in no row and no domain can
// never be in force, and every later start of the VM refuses for want of it.
// Mutation: drop the retire in recoverNICDetach, and the record survives.
func TestRecoverHardwareOperations_NICDetachRetiresTheGuardRecord(t *testing.T) {
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	s.db.SetClusterPolicyGate(func() bool { return true })
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	s.virt.(*libvirtfake.Fake).SetState("vm1", libvirtfake.StateRunning)

	const mac = "52:54:00:aa:bb:03"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	if err := corrosion.PutNICGuard(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureNICGuards),
		corrosion.NICGuardRecord{VMName: "vm1", MAC: mac, Mode: corrosion.NICGuardOn, Network: "lan"}, "admin"); err != nil {
		t.Fatal(err)
	}
	beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachNICRequestHash("vm1", mac),
		[]string{corrosion.OpStepReserved},
		map[string]string{"mac": mac, "nic_id": corrosion.DeterministicNICID("vm1", mac)})

	s.RecoverHardwareOperations(ctx)

	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
		t.Fatalf("barrier not cleared: %q", vm.ActiveOperationID)
	}
	if rec, err := corrosion.GetNICGuard(ctx, s.db, "vm1", mac); err != nil || rec != nil {
		t.Fatalf("the detached NIC's guard record after recovery = %+v (err %v), want it retired", rec, err)
	}
}
