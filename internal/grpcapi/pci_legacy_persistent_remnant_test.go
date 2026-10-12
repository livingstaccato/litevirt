package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// persistentHasHostdev reports whether vmName's PERSISTENT definition — what a
// cold boot loads — still carries a PCI hostdev whose source BDF is addr.
func persistentHasHostdev(t *testing.T, s *Server, vmName, addr string) bool {
	t.Helper()
	x, err := s.virt.DumpXMLInactive(vmName)
	if err != nil {
		t.Fatalf("DumpXMLInactive(%s): %v", vmName, err)
	}
	want, _ := pci.CanonicalBDF(addr)
	for _, raw := range libvirt.HostdevSourcePCIAddresses(x) {
		if got, ok := pci.CanonicalBDF(raw); ok && got == want {
			return true
		}
	}
	return false
}

// legacyAttachThenDropLiveCopy attaches addr to running vm1 on the legacy path and
// then removes the hostdev from the LIVE domain only, leaving it in the persistent
// definition: lab "pci B", live 0 / inactive 1.
func legacyAttachThenDropLiveCopy(t *testing.T, s *Server, fake *libvirtfake.Fake, addr string) {
	t.Helper()
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("legacy type attach: %v", err)
	}
	fake.SkipConfigOnHostdevMutation = true
	if err := fake.DetachHostdev("vm1", addr); err != nil {
		t.Fatalf("drop the live copy: %v", err)
	}
	fake.SkipConfigOnHostdevMutation = false
	if guestHasHostdev(t, s, "vm1", addr) || !persistentHasHostdev(t, s, "vm1", addr) {
		t.Fatal("precondition: the hostdev must be in the persistent definition only")
	}
}

// TestDetachPCI_LegacyPersistentOnlyRemnant_IsDetachedBeforeRelease is review I2
// (lab V2): on the legacy path a hostdev left in the persistent definition alone
// was skipped — the membership check read the live copy only — and with the vfio
// release now working, the detach reported success and released the device while
// a cold boot of vm1 would take it back from whoever claimed it next. The detach
// must clear the persistent copy before ownership is released.
func TestDetachPCI_LegacyPersistentOnlyRemnant_IsDetachedBeforeRelease(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1)
	legacyAttachThenDropLiveCopy(t, s, fake, addr)

	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	remnant := persistentHasHostdev(t, s, "vm1", addr)
	owner := pciOwnerOf(t, ctx, s, addr)
	if remnant && owner == "" {
		t.Fatalf("the device was released (detach err=%v) while vm1's persistent definition still holds its hostdev", err)
	}
	if err != nil {
		t.Fatalf("detach of a persistent-only remnant: %v", err)
	}
	if remnant {
		t.Fatal("the detach left the hostdev in the persistent definition")
	}
	if owner != "" || fs.isBound(addr) {
		t.Fatalf("after the detach: owner=%q bound=%v, want released and unbound", owner, fs.isBound(addr))
	}
}

// TestDetachPCI_LegacyPersistentCopyThatWillNotClear_KeepsOwnership: when libvirt
// accepts the detach but the persistent copy keeps the hostdev, the release must
// not happen: the RPC fails and the device stays owned and bound.
func TestDetachPCI_LegacyPersistentCopyThatWillNotClear_KeepsOwnership(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1)
	legacyAttachThenDropLiveCopy(t, s, fake, addr)

	fake.SkipConfigOnHostdevMutation = true // config detaches are accepted and do nothing
	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if err == nil {
		t.Fatal("the detach reported success with the hostdev still in the persistent definition")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" {
		t.Fatalf("owner = %q, want vm1 kept while the persistent copy holds the hostdev", o)
	}
	if !fs.isBound(addr) {
		t.Fatal("the device was unbound while the persistent copy still holds its hostdev")
	}
}

// legacyAttach attaches addr to running vm1 on the legacy path.
func legacyAttach(t *testing.T, s *Server, addr string) {
	t.Helper()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1)
	if _, err := s.AttachDevice(adminCtx(), &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("legacy type attach: %v", err)
	}
}

// TestDetachPCI_LegacyLiveUnplugNeverAcked_KeepsOwnership: the live half of a
// detach only REQUESTS the unplug. A guest that never acknowledges it keeps the
// hostdev in its live domain, so the legacy detach must fail and keep the device
// owned and bound, not release it from under a guest still using it.
func TestDetachPCI_LegacyLiveUnplugNeverAcked_KeepsOwnership(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)
	legacyAttach(t, s, addr)
	fake.DeferLiveUnplug = true // never acknowledged
	fastUnplugWait(t, 200*time.Millisecond)

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr}); err == nil {
		t.Fatal("the detach reported success while the hostdev is still in the live domain")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" || !fs.isBound(addr) {
		t.Fatalf("owner=%q bound=%v, want kept by vm1 and bound while the guest holds it", o, fs.isBound(addr))
	}
}

// TestDetachPCI_LegacyDroppedEject_IsReRequested: a guest that drops the first
// eject and honours the second (HonorUnplugOnRequest) must still converge: the
// wait re-requests the unplug, then the device is released.
func TestDetachPCI_LegacyDroppedEject_IsReRequested(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)
	legacyAttach(t, s, addr)
	fake.DeferLiveUnplug = true
	fake.HonorUnplugOnRequest = 2
	fastUnplugWait(t, 5*time.Second)

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if guestHasHostdev(t, s, "vm1", addr) || persistentHasHostdev(t, s, "vm1", addr) {
		t.Fatal("the hostdev is still in a copy of vm1")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" || fs.isBound(addr) {
		t.Fatalf("owner=%q bound=%v, want released and unbound", o, fs.isBound(addr))
	}
}

// TestDetachPCI_LegacyWaitHonoursTheCallersContext (re-review R1-M2): the live
// wait runs under the caller's context. A cancelled or expired RPC stops it
// instead of holding the VM lock for the full unplug budget.
func TestDetachPCI_LegacyWaitHonoursTheCallersContext(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	defer vfio.SetFS(fs)()
	fake := s.virt.(*libvirtfake.Fake)
	legacyAttach(t, s, addr)
	fake.DeferLiveUnplug = true // never acknowledged
	fastUnplugWait(t, 20*time.Second)

	ctx, cancel := context.WithTimeout(adminCtx(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr})
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the detach waited %v after its context expired at 500ms", took)
	}
	if err == nil {
		t.Fatal("the detach reported success while the hostdev is still in the live domain")
	}
	if o := pciOwnerOf(t, adminCtx(), s, addr); o != "vm1" || !fs.isBound(addr) {
		t.Fatalf("owner=%q bound=%v, want kept by vm1 and bound", o, fs.isBound(addr))
	}
}

// TestReclaimLive_APausedGuestIsLeftForTheRetry (re-review R1-M2): a paused guest
// cannot acknowledge an unplug, so waiting for it only stalls the caller — and
// device-lease recovery runs inside the startup barrier, where that was up to the
// full unplug budget per device. The detach must refuse at once and leave the
// device owned and bound for the retry.
func TestReclaimLive_APausedGuestIsLeftForTheRetry(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	fake := s.virt.(*libvirtfake.Fake)
	legacyAttach(t, s, addr)
	fake.SetState("vm1", libvirtfake.StatePaused)
	fake.DeferLiveUnplug = true
	fastUnplugWait(t, 20*time.Second)

	start := time.Now()
	err := s.reclaimLeasedDevices(ctx, "vm1", []string{addr}, reclaimLive)
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("the reclaim waited %v on a paused guest", took)
	}
	if err == nil {
		t.Fatal("the reclaim succeeded although the paused guest still holds the hostdev")
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "vm1" || !fs.isBound(addr) {
		t.Fatalf("owner=%q bound=%v, want kept by vm1 and bound for the retry", o, fs.isBound(addr))
	}
}
