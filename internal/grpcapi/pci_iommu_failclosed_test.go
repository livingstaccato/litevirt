package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pci"
)

// fakeIOMMUSysfs installs a fake sysfs root for the IOMMU probe: an
// iommu_groups directory holding `groups` (none → the IOMMU is off) and a PCI
// devices directory. It returns the devices root.
func fakeIOMMUSysfs(t *testing.T, groups ...string) (devices, groupsDir string) {
	t.Helper()
	root := t.TempDir()
	devices = filepath.Join(root, "bus", "pci", "devices")
	groupsDir = filepath.Join(root, "kernel", "iommu_groups")
	for _, d := range []string{devices, groupsDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, g := range groups {
		if err := os.MkdirAll(filepath.Join(groupsDir, g, "devices"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(pci.SetSysDevices(devices))
	t.Cleanup(pci.SetSysIOMMUGroups(groupsDir))
	return devices, groupsDir
}

func seedNoGroupDevice(t *testing.T, s *Server, addr string) {
	t.Helper()
	if err := corrosion.UpsertPCIDevice(context.Background(), s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: addr, Type: "gpu", VendorID: "10de", IOMMUGroup: -1,
	}); err != nil {
		t.Fatalf("UpsertPCIDevice: %v", err)
	}
}

func wantRefusal(t *testing.T, err error, code codes.Code, needles ...string) {
	t.Helper()
	if err == nil {
		t.Fatalf("checkIOMMUConflict allowed the device; want a %v refusal", code)
	}
	if got := status.Code(err); got != code {
		t.Errorf("code = %v, want %v (%v)", got, code, err)
	}
	for _, n := range needles {
		if !strings.Contains(err.Error(), n) {
			t.Errorf("refusal %q does not name %q", err.Error(), n)
		}
	}
}

// Exit 1: the inventory cannot be read. The device was let through with no
// group check at all.
func TestCheckIOMMUConflict_InventoryReadErrorRefuses(t *testing.T) {
	s := testServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	cancel()
	err := s.checkIOMMUConflict(ctx, "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.Unavailable, "0000:41:00.0", "host_pci_devices", "retry")
}

// Exit 2: the device is not in this host's inventory, so its group is unknown.
func TestCheckIOMMUConflict_NotInInventoryRefuses(t *testing.T) {
	s := testServer(t)
	err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition, "0000:41:00.0", "not in host test-host's PCI inventory", "lv host rescan test-host")
}

// Exit 3, IOMMU off: the inventory records no group because the kernel has the
// IOMMU off. Passthrough there isolates nothing.
func TestCheckIOMMUConflict_IOMMUOffRefuses(t *testing.T) {
	s := testServer(t)
	_, groups := fakeIOMMUSysfs(t) // no groups: IOMMU off
	seedNoGroupDevice(t, s, "0000:41:00.0")
	err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition, "IOMMU is off", groups, "intel_iommu=on", "amd_iommu=off", "iommu=off", "lv host rescan test-host")
}

// Exit 3, IOMMU off, the groups directory absent altogether (no IOMMU driver).
func TestCheckIOMMUConflict_IOMMUGroupsDirMissingRefuses(t *testing.T) {
	s := testServer(t)
	_, groups := fakeIOMMUSysfs(t)
	if err := os.Remove(groups); err != nil {
		t.Fatal(err)
	}
	seedNoGroupDevice(t, s, "0000:41:00.0")
	err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition, "IOMMU is off", groups, "intel_iommu=on")
}

// Exit 3, IOMMU groups unreadable: name the path and refuse.
func TestCheckIOMMUConflict_IOMMUGroupsUnreadableRefuses(t *testing.T) {
	s := testServer(t)
	_, groups := fakeIOMMUSysfs(t)
	if err := os.Remove(groups); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groups, nil, 0o644); err != nil { // a file, not a directory
		t.Fatal(err)
	}
	seedNoGroupDevice(t, s, "0000:41:00.0")
	err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition, "cannot read "+groups)
}

// Exit 3, IOMMU on but this device has no group link.
func TestCheckIOMMUConflict_DeviceWithoutGroupRefuses(t *testing.T) {
	s := testServer(t)
	devices, _ := fakeIOMMUSysfs(t, "0", "1")
	if err := os.MkdirAll(filepath.Join(devices, "0000:41:00.0"), 0o755); err != nil {
		t.Fatal(err)
	}
	seedNoGroupDevice(t, s, "0000:41:00.0")
	err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition,
		"has no IOMMU group", filepath.Join(devices, "0000:41:00.0", "iommu_group"), "dmesg")
}

// Exit 3, IOMMU on and the device now has a group: the inventory predates the
// IOMMU being turned on. Refuse and say to rescan.
func TestCheckIOMMUConflict_StaleInventoryRefuses(t *testing.T) {
	s := testServer(t)
	devices, _ := fakeIOMMUSysfs(t, "0", "12")
	dev := filepath.Join(devices, "0000:41:00.0")
	if err := os.MkdirAll(dev, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../../kernel/iommu_groups/12", filepath.Join(dev, "iommu_group")); err != nil {
		t.Fatal(err)
	}
	seedNoGroupDevice(t, s, "0000:41:00.0")
	err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition, "group 12", "stale", "lv host rescan test-host")
}

// Exit 3, IOMMU on and the device is gone from sysfs.
func TestCheckIOMMUConflict_DeviceGoneFromSysfsRefuses(t *testing.T) {
	s := testServer(t)
	devices, _ := fakeIOMMUSysfs(t, "0")
	seedNoGroupDevice(t, s, "0000:41:00.0")
	err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition, filepath.Join(devices, "0000:41:00.0"), "lv host rescan test-host")
}

// Exit 4: the group's members were read with a second query whose failure let
// the device through. They now come from the one inventory read, so a sibling
// owned by another VM is found from it — there is no second read to fail.
func TestCheckIOMMUConflict_GroupMembersFromTheOneRead(t *testing.T) {
	s := testServer(t)
	ctx := adminCtx()
	for _, d := range []corrosion.PCIDeviceRecord{
		{HostName: s.hostName, Address: "0000:41:00.0", IOMMUGroup: 7},
		{HostName: s.hostName, Address: "0000:41:00.1", IOMMUGroup: 7, VMName: "vm-b"},
		{HostName: s.hostName, Address: "0000:42:00.0", IOMMUGroup: 8, VMName: "vm-c"},
		{HostName: "other-host", Address: "0000:41:00.2", IOMMUGroup: 7, VMName: "vm-d"},
	} {
		if err := corrosion.UpsertPCIDevice(ctx, s.db, d); err != nil {
			t.Fatal(err)
		}
	}
	err := s.checkIOMMUConflict(ctx, "0000:41:00.0", "vm-a")
	wantRefusal(t, err, codes.FailedPrecondition, "IOMMU group 7 conflict", "0000:41:00.1", `"vm-b"`)

	// A group-8 or other-host owner is not a conflict for a group-7 device.
	if err := corrosion.ReleasePCIDevice(ctx, s.db, s.hostName, "0000:41:00.1", "vm-b"); err != nil {
		t.Fatal(err)
	}
	if err := s.checkIOMMUConflict(ctx, "0000:41:00.0", "vm-a"); err != nil {
		t.Fatalf("no same-group other-VM owner on this host: got %v, want nil", err)
	}
}

// A correctly configured host is unaffected: a device with a group and no
// conflicting owner passes, without consulting sysfs at all.
func TestCheckIOMMUConflict_GroupedDevicePasses(t *testing.T) {
	s := testServer(t)
	fakeIOMMUSysfs(t) // IOMMU "off" in sysfs: must not matter when the inventory has a group
	if err := corrosion.UpsertPCIDevice(adminCtx(), s.db, corrosion.PCIDeviceRecord{
		HostName: s.hostName, Address: "0000:41:00.0", IOMMUGroup: 0,
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.checkIOMMUConflict(adminCtx(), "0000:41:00.0", "vm-a"); err != nil {
		t.Fatalf("grouped device: got %v, want nil", err)
	}
}

// iommuGroupSiblings dropped its inventory read error and returned the device
// alone, so a resolve under a read error never saw the siblings.
func TestIOMMUGroupSiblings_InventoryReadErrorFails(t *testing.T) {
	s := testServer(t)
	ctx, cancel := context.WithCancel(adminCtx())
	cancel()
	if addrs, err := s.iommuGroupSiblings(ctx, "0000:41:00.0"); err == nil {
		t.Fatalf("iommuGroupSiblings under a read error returned %v, nil; want an error", addrs)
	}
}
