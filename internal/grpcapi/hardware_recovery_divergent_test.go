package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/vfio"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// Lab finding N1 (lab1-c713, TestVM_AttachDetachNIC): a NIC detach issued while the
// guest was still booting was left recoverable, and then NEVER recovered. The first
// LIVE|CONFIG detach removed the NIC from the persistent definition at once, but the
// guest dropped the eject, so the live copy stayed. Every later detach — the
// verifier's re-requests and recovery's 60 s retries alike — sent LIVE|CONFIG again,
// and libvirt failed each one on the config half ("device not found: no device found
// ... matching MAC address") without re-issuing the live unplug. The VM's operation
// barrier was held for as long as anyone watched (>9 min); `virsh detach-interface
// --live` cleared it at once.
//
// libvirtfake used to succeed on any detach, which defined this away. It now models
// libvirt's all-or-nothing flag semantics (detachFlagsLocked), so these tests fail
// against a detach that always sends LIVE|CONFIG.
//
// The two directions:
//   - persistent copy gone, live copy present: the N1 state, made by one detach
//     whose eject the guest drops;
//   - live copy gone, persistent copy present: made by a live-only detach
//     (SkipConfigOn*Mutation); recovery used to skip the detach because the LIVE
//     domain no longer held the device, then fail its persistent-definition check
//     forever.

// leaveOnlyLiveCopy runs one detach whose eject the guest drops: the persistent copy
// goes, the live one stays. The guest answers the NEXT request.
func leaveOnlyLiveCopy(t *testing.T, fake *libvirtfake.Fake, detach func() error) {
	t.Helper()
	fake.DeferLiveUnplug = true
	fake.HonorUnplugOnRequest = 2
	if err := detach(); err != nil {
		t.Fatalf("first detach: %v", err)
	}
	if got := fake.PendingUnplugs("vm1"); got != 1 {
		t.Fatalf("the first eject must go unanswered, pending=%d", got)
	}
}

// leaveOnlyPersistentCopy removes the device from the live domain only.
func leaveOnlyPersistentCopy(t *testing.T, skip *bool, detach func() error) {
	t.Helper()
	*skip = true
	if err := detach(); err != nil {
		t.Fatalf("live-only detach: %v", err)
	}
	*skip = false
}

func assertDetachRecovered(t *testing.T, ctx context.Context, s *Server, opID string, epoch int64) {
	t.Helper()
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID != "" {
		t.Fatalf("operation barrier still held after recovery: %q", vm.ActiveOperationID)
	}
	state, _, err := corrosion.OperationCurrentState(ctx, s.db, opID, epoch, corrosion.OpDeviceDetach)
	if err != nil {
		t.Fatalf("read op state: %v", err)
	}
	if state != corrosion.OpStepCompleted {
		t.Fatalf("detach recovery state = %q, want completed", state)
	}
}

// ── NIC ──────────────────────────────────────────────────────────────────────

func seedAttachedNIC(t *testing.T) (*Server, *libvirtfake.Fake, context.Context, string) {
	t.Helper()
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateRunning)
	const mac = "52:54:00:aa:bb:03"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Nic: &pb.NetworkAttachment{Name: "lan", Mac: mac},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	fastUnplugWait(t, 2*time.Second)
	return s, fake, ctx, mac
}

func wedgeNICDetach(t *testing.T, ctx context.Context, s *Server, mac string) (string, int64) {
	t.Helper()
	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachNICRequestHash("vm1", mac), []string{corrosion.OpStepReserved},
		map[string]string{"mac": mac, "nic_id": corrosion.DeterministicNICID("vm1", mac)})
	return opID, epoch
}

func assertNICGone(t *testing.T, fake *libvirtfake.Fake, mac string) {
	t.Helper()
	if live, _ := fake.DumpXML("vm1"); nicMacInXML(live, mac) {
		t.Fatalf("nic %s still in the live domain", mac)
	}
	if inactive, _ := fake.DumpXMLInactive("vm1"); nicMacInXML(inactive, mac) {
		t.Fatalf("nic %s still in the persistent definition", mac)
	}
}

func TestRecoverNICDetach_PersistentCopyAlreadyGone(t *testing.T) {
	s, fake, ctx, mac := seedAttachedNIC(t)
	leaveOnlyLiveCopy(t, fake, func() error { return s.virt.DetachNIC("vm1", mac) })
	opID, epoch := wedgeNICDetach(t, ctx, s, mac)

	s.RecoverHardwareOperations(ctx)

	assertDetachRecovered(t, ctx, s, opID, epoch)
	assertNICGone(t, fake, mac)
	if got := fake.UnplugRequests("vm1"); got < 2 {
		t.Fatalf("recovery never re-requested the live unplug (requests=%d)", got)
	}
}

func TestRecoverNICDetach_LiveCopyAlreadyGone(t *testing.T) {
	s, fake, ctx, mac := seedAttachedNIC(t)
	leaveOnlyPersistentCopy(t, &fake.SkipConfigOnNICMutation, func() error { return s.virt.DetachNIC("vm1", mac) })
	if inactive, _ := fake.DumpXMLInactive("vm1"); !nicMacInXML(inactive, mac) {
		t.Fatal("setup: the persistent copy must remain")
	}
	opID, epoch := wedgeNICDetach(t, ctx, s, mac)

	s.RecoverHardwareOperations(ctx)

	assertDetachRecovered(t, ctx, s, opID, epoch)
	assertNICGone(t, fake, mac)
}

// The verifier's own re-requests hit the same wall, before recovery is ever
// involved: this is the "could not be verified; left recoverable ... after 5
// reissues over 30 s" the lab test saw. A guest that drops the first eject and
// answers the second must verify.
func TestVerifyNICDetached_ReissueAfterPersistentCopyGone(t *testing.T) {
	s, fake, _, mac := seedAttachedNIC(t)
	leaveOnlyLiveCopy(t, fake, func() error { return s.virt.DetachNIC("vm1", mac) })

	if err := s.verifyNICDetached(context.Background(), "vm1", mac, true); err != nil {
		t.Fatalf("a guest that answers the re-request must verify, got: %v (requests=%d)", err, fake.UnplugRequests("vm1"))
	}
	assertNICGone(t, fake, mac)
}

// ── disk ─────────────────────────────────────────────────────────────────────

func seedAttachedDisk(t *testing.T) (*Server, *libvirtfake.Fake, context.Context, string) {
	t.Helper()
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	ctx := adminCtx()
	seedDiskVM(t, s, "vm1", "running")
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateRunning)
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", Disk: &pb.DiskSpec{Name: "data1", Size: "5G", Bus: "virtio"},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	fastUnplugWait(t, 2*time.Second)
	return s, fake, ctx, diskTargetDev(t, ctx, s, "vm1", "data1")
}

func wedgeDiskDetach(t *testing.T, ctx context.Context, s *Server, td string) (string, int64) {
	t.Helper()
	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachDiskRequestHash("vm1", "data1"), []string{corrosion.OpStepReserved},
		map[string]string{"disk_name": "data1", "target_dev": td})
	return opID, epoch
}

func assertDiskGone(t *testing.T, fake *libvirtfake.Fake, td string) {
	t.Helper()
	if srcs, _ := fake.DomainDiskSources("vm1"); srcs[td] != "" {
		t.Fatalf("disk %s still in the live domain", td)
	}
	if inactive, _ := fake.DumpXMLInactive("vm1"); diskDevInXML(inactive, td) {
		t.Fatalf("disk %s still in the persistent definition", td)
	}
}

func TestRecoverDiskDetach_PersistentCopyAlreadyGone(t *testing.T) {
	s, fake, ctx, td := seedAttachedDisk(t)
	leaveOnlyLiveCopy(t, fake, func() error { return s.virt.DetachDisk("vm1", td) })
	opID, epoch := wedgeDiskDetach(t, ctx, s, td)

	s.RecoverHardwareOperations(ctx)

	assertDetachRecovered(t, ctx, s, opID, epoch)
	assertDiskGone(t, fake, td)
}

func TestRecoverDiskDetach_LiveCopyAlreadyGone(t *testing.T) {
	s, fake, ctx, td := seedAttachedDisk(t)
	leaveOnlyPersistentCopy(t, &fake.SkipConfigOnDiskMutation, func() error { return s.virt.DetachDisk("vm1", td) })
	if inactive, _ := fake.DumpXMLInactive("vm1"); !diskDevInXML(inactive, td) {
		t.Fatal("setup: the persistent copy must remain")
	}
	opID, epoch := wedgeDiskDetach(t, ctx, s, td)

	s.RecoverHardwareOperations(ctx)

	assertDetachRecovered(t, ctx, s, opID, epoch)
	assertDiskGone(t, fake, td)
}

// An unreadable live view is not an absent one (review M1): recovery must leave
// the op recoverable before it touches the disk row, not fall through to the
// persistent read and soft-delete the row first.
func TestRecoverDiskDetach_LiveReadFails_LeavesRecoverable(t *testing.T) {
	s, fake, ctx, td := seedAttachedDisk(t)
	opID, _ := wedgeDiskDetach(t, ctx, s, td)
	fake.SetFailDomainDiskSources(func(string) error { return errors.New("libvirt connection lost") })

	s.RecoverHardwareOperations(ctx)

	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != opID {
		t.Fatalf("operation barrier = %q, want %q still held", vm.ActiveOperationID, opID)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	if !hasDiskName(disks, "data1") {
		t.Fatal("the disk row was soft-deleted although the live membership could not be read")
	}
}

// ── PCI ──────────────────────────────────────────────────────────────────────

func seedAttachedPCI(t *testing.T) (*Server, *libvirtfake.Fake, context.Context, string, string) {
	s, fake, ctx, addr, deviceID, _ := seedAttachedPCIWithFS(t)
	return s, fake, ctx, addr, deviceID
}

func seedAttachedPCIWithFS(t *testing.T) (*Server, *libvirtfake.Fake, context.Context, string, string, *pciUnbindRecordingFS) {
	t.Helper()
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	vfs := newPCIUnbindRecordingFS()
	restore := vfio.SetFS(vfs)
	t.Cleanup(restore)
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, "0000:41:00.0", -1)
	fake := s.virt.(*libvirtfake.Fake)
	fake.SetState("vm1", libvirtfake.StateRunning)
	const addr = "0000:41:00.0"
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Address: addr},
	}); err != nil {
		t.Fatalf("seed attach: %v", err)
	}
	fastUnplugWait(t, 2*time.Second)
	deviceID := liveIntents(t, ctx, s, "vm1")[0].DeviceID
	return s, fake, ctx, addr, deviceID, vfs
}

// assertPCIStillHeld: nothing was released while the hostdev may still be in the
// guest — no vfio unbind, the realization rows and the ownership still stand, and
// the operation is still in flight for a later pass.
func assertPCIStillHeld(t *testing.T, ctx context.Context, s *Server, vfs *pciUnbindRecordingFS, addr, opID string) {
	t.Helper()
	if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != opID {
		t.Fatalf("operation barrier = %q, want %q still held (left recoverable)", vm.ActiveOperationID, opID)
	}
	if n := vfs.unbindCount(addr); n != 0 {
		t.Fatalf("vfio unbind of %s ran %d time(s) while the hostdev was still in the live domain", addr, n)
	}
	if rs := liveRealizations(t, ctx, s, "vm1"); len(rs) == 0 {
		t.Fatal("realizations tombstoned while the hostdev was still in the live domain")
	}
	owned := false
	devs, _ := corrosion.ListPCIDevices(ctx, s.db, "test-host", "")
	for _, d := range devs {
		if d.Address == addr && d.VMName == "vm1" {
			owned = true
		}
	}
	if !owned {
		t.Fatalf("%s released while the hostdev was still in the live domain", addr)
	}
}

// Review I1: once DetachLiveAndConfig re-requests the live unplug, libvirt answers
// nil after its own short wait even when the guest has not let go. Releasing then
// — vfio unbind while QEMU still holds the device, tombstoning the realizations —
// blocks in the kernel and, on the next pass, leaves recovery with no members to
// verify. A guest that keeps dropping the eject must leave everything held and
// the op recoverable; once it answers, the next pass converges.
func TestRecoverPCIDetach_GuestKeepsDroppingEject_ReleasesNothing(t *testing.T) {
	s, fake, ctx, addr, deviceID, vfs := seedAttachedPCIWithFS(t)
	fake.DeferLiveUnplug = true // HonorUnplugOnRequest 0: the guest answers no request on its own
	if err := s.virt.DetachHostdev("vm1", addr); err != nil {
		t.Fatalf("first detach: %v", err)
	}
	opID, epoch := wedgePCIDetach(t, ctx, s, addr, deviceID)

	s.RecoverHardwareOperations(ctx)

	assertPCIStillHeld(t, ctx, s, vfs, addr, opID)
	if got := fake.UnplugRequests("vm1"); got < 2 {
		t.Fatalf("recovery never re-requested the live unplug (requests=%d)", got)
	}

	fake.AckLiveUnplug("vm1")
	s.RecoverHardwareOperations(ctx)

	assertDetachRecovered(t, ctx, s, opID, epoch)
	assertHostdevGone(t, fake, pciMemberAlias(deviceID, "m0"))
	if n := vfs.unbindCount(addr); n == 0 {
		t.Fatal("the converged detach never released the device")
	}
}

// The same ordering on the live path: executePCIDetach must not release the device
// while the guest still holds the hostdev.
func TestDetachPCI_GuestKeepsDroppingEject_ReleasesNothing(t *testing.T) {
	s, fake, ctx, addr, _, vfs := seedAttachedPCIWithFS(t)
	fake.DeferLiveUnplug = true

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if err == nil {
		t.Fatal("a detach the guest never answered must not report success")
	}
	vm := mustGetVM(t, s, "vm1")
	if vm.ActiveOperationID == "" {
		t.Fatalf("detach failed (%v) but cleared the barrier: it must be left recoverable", err)
	}
	assertPCIStillHeld(t, ctx, s, vfs, addr, vm.ActiveOperationID)
}

func wedgePCIDetach(t *testing.T, ctx context.Context, s *Server, addr, deviceID string) (string, int64) {
	t.Helper()
	opID, epoch, _ := beginWedgedDeviceOp(t, ctx, s, "vm1", corrosion.OpDeviceDetach,
		detachPCIRequestHash("vm1", addr), []string{corrosion.OpStepReserved},
		map[string]string{"device_id": deviceID, "pci_address": addr, "member_addresses": addr})
	return opID, epoch
}

func assertHostdevGone(t *testing.T, fake *libvirtfake.Fake, alias string) {
	t.Helper()
	if live, _ := fake.DumpXML("vm1"); hostdevAliasInXML(live, alias) {
		t.Fatalf("hostdev %s still in the live domain", alias)
	}
	if inactive, _ := fake.DumpXMLInactive("vm1"); hostdevAliasInXML(inactive, alias) {
		t.Fatalf("hostdev %s still in the persistent definition", alias)
	}
}

func TestRecoverPCIDetach_PersistentCopyAlreadyGone(t *testing.T) {
	s, fake, ctx, addr, deviceID := seedAttachedPCI(t)
	leaveOnlyLiveCopy(t, fake, func() error { return s.virt.DetachHostdev("vm1", addr) })
	opID, epoch := wedgePCIDetach(t, ctx, s, addr, deviceID)

	s.RecoverHardwareOperations(ctx)

	assertDetachRecovered(t, ctx, s, opID, epoch)
	assertHostdevGone(t, fake, pciMemberAlias(deviceID, "m0"))
}

func TestRecoverPCIDetach_LiveCopyAlreadyGone(t *testing.T) {
	s, fake, ctx, addr, deviceID := seedAttachedPCI(t)
	alias := pciMemberAlias(deviceID, "m0")
	leaveOnlyPersistentCopy(t, &fake.SkipConfigOnHostdevMutation, func() error { return s.virt.DetachHostdev("vm1", addr) })
	if inactive, _ := fake.DumpXMLInactive("vm1"); !hostdevAliasInXML(inactive, alias) {
		t.Fatal("setup: the persistent copy must remain")
	}
	opID, epoch := wedgePCIDetach(t, ctx, s, addr, deviceID)

	s.RecoverHardwareOperations(ctx)

	assertDetachRecovered(t, ctx, s, opID, epoch)
	assertHostdevGone(t, fake, alias)
}
