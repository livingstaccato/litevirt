package grpcapi

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/vfio"
)

func hostDriverRecord(t *testing.T, s *Server) map[string]string {
	t.Helper()
	m := map[string]string{}
	b, err := os.ReadFile(filepath.Join(s.dataDir, vfio.HostDriversFileName))
	if os.IsNotExist(err) {
		return m
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("host-driver record: %v (%s)", err, b)
	}
	return m
}

// TestPCI_AttachRecordsTheHostDriverAndDetachReturnsTheDeviceToIt (review I1, M3):
// the attach records, in this host's data directory, the driver the device was on
// (igbvf). A rescan then overwrites the inventory's driver with "vfio-pci", as it
// does on every host. The detach must still return the device to igbvf — through
// the named-driver path, whose verification no grpcapi test reached before — and
// drop the record.
func TestPCI_AttachRecordsTheHostDriverAndDetachReturnsTheDeviceToIt(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	fs.setHostDriver(addr, "igbvf")
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1)

	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if got := hostDriverRecord(t, s); got[addr] != "igbvf" {
		t.Fatalf("host-driver record after attach = %v, want %s → igbvf", got, addr)
	}
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: addr, Type: "gpu", VendorID: "10de", IOMMUGroup: soloIOMMUGroup(addr), Driver: "vfio-pci",
	}); err != nil {
		t.Fatalf("rescan: %v", err)
	}

	if _, err := s.DetachDevice(ctx, &pb.DetachDeviceRequest{VmName: "vm1", PciAddress: addr}); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if fs.isBound(addr) || fs.hostDriver(addr) != "igbvf" {
		t.Fatalf("after detach: bound=%v host driver=%q, want igbvf", fs.isBound(addr), fs.hostDriver(addr))
	}
	if got := hostDriverRecord(t, s); len(got) != 0 {
		t.Fatalf("host-driver record after detach = %v, want empty", got)
	}
}

// TestReleaseDevices_ClearsAStaleOverrideOnAnUnboundDevice (review M2): a device
// owned by the VM, NOT bound, but still carrying driver_override=vfio-pci (an
// older build's failed Bind). The release skips Unbind for it, and used to release
// it with the override intact, so the next probe handed an unowned device to
// vfio-pci. The override must be cleared before ownership goes.
func TestReleaseDevices_ClearsAStaleOverrideOnAnUnboundDevice(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	fs.native[addr] = "igbvf"
	fs.setStaleOverride(addr)
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("assign: %v", err)
	}

	if err := s.releaseDevices(ctx, "vm1"); err != nil {
		t.Fatalf("releaseDevices: %v", err)
	}
	if fs.overrideSet(addr) {
		t.Fatal("the device was released with driver_override=vfio-pci still set")
	}
	if fs.isBound(addr) || fs.hostDriver(addr) != "igbvf" {
		t.Fatalf("bound=%v host driver=%q, want reprobed onto igbvf", fs.isBound(addr), fs.hostDriver(addr))
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("owner = %q, want released", o)
	}
}

// TestReleaseDevices_LogsTheDriverTheDeviceLandedOn (lab note N1): the release's
// log line printed the inventory's driver as "restored_driver", which after a
// rescan of a bound device is "vfio-pci", while the device had gone to igbvf. It
// must name the driver the device is on after the release.
func TestReleaseDevices_LogsTheDriverTheDeviceLandedOn(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	enableHardwareV2(t, s)
	fs := newPCIUnbindRecordingFS()
	fs.setHostDriver(addr, "igbvf")
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	seedNICVM(t, s, "vm1", "running")
	seedPCIGPU(t, s, addr, -1)
	if _, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{
		VmName: "vm1", PciDevice: &pb.DeviceSpec{Type: "gpu"},
	}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
		HostName: "test-host", Address: addr, Type: "gpu", VendorID: "10de", IOMMUGroup: soloIOMMUGroup(addr), Driver: "vfio-pci",
	}); err != nil {
		t.Fatalf("rescan: %v", err)
	}

	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	err := s.releaseDevices(ctx, "vm1")
	slog.SetDefault(prev)
	if err != nil {
		t.Fatalf("releaseDevices: %v", err)
	}
	var line string
	for _, l := range strings.Split(buf.String(), "\n") {
		if strings.Contains(l, `msg="device unbound from vfio-pci"`) && strings.Contains(l, addr) {
			line = l
		}
	}
	if !strings.Contains(line, "driver=igbvf") {
		t.Fatalf("release log line = %q, want it to name igbvf, the driver the device is on", line)
	}
}

// TestReleaseDevices_AVanishedDeviceIsReleased (re-review R1-I1): a stopped VM
// keeps its VF, the host reboots, and the VF does not come back (sriov_numvfs is
// not persistent). Its sysfs directory is gone. `lv rm` reaches releaseDevices,
// and the vanished device must be released, not fail the delete on every retry
// with "read driver_override: no such file".
func TestReleaseDevices_AVanishedDeviceIsReleased(t *testing.T) {
	const addr = "0000:50:00.0"
	s := hotplugDiskServer(t)
	fs := newPCIUnbindRecordingFS()
	fs.setAbsent(addr)
	defer vfio.SetFS(fs)()
	ctx := adminCtx()
	seedPCIGPU(t, s, addr, -1)
	if err := corrosion.AssignPCIDevice(ctx, s.db, "test-host", addr, "vm1"); err != nil {
		t.Fatalf("assign: %v", err)
	}

	if err := s.releaseDevices(ctx, "vm1"); err != nil {
		t.Fatalf("releaseDevices with a vanished device: %v", err)
	}
	if o := pciOwnerOf(t, ctx, s, addr); o != "" {
		t.Fatalf("owner = %q, want released", o)
	}
}
