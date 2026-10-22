package pci

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
)

var sysIOMMUGroups = "/sys/kernel/iommu_groups"

// SetSysIOMMUGroups overrides the sysfs IOMMU-groups root and returns a restore
// func. Test seam: production never calls it (the default points at real sysfs).
func SetSysIOMMUGroups(path string) func() {
	old := sysIOMMUGroups
	sysIOMMUGroups = path
	return func() { sysIOMMUGroups = old }
}

// IOMMUGroupsPath is the directory the kernel lists IOMMU groups under.
func IOMMUGroupsPath() string { return sysIOMMUGroups }

// IOMMUEnabled reports whether the kernel has the IOMMU on: it lists at least
// one group under IOMMUGroupsPath. A missing directory means the IOMMU is off
// (false, nil); any other read failure is returned, because it says nothing
// either way.
func IOMMUEnabled() (bool, error) {
	entries, err := os.ReadDir(sysIOMMUGroups)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		return false, err
	}
	return len(entries) > 0, nil
}

// DeviceIOMMUGroupLink is the sysfs link naming a device's IOMMU group.
func DeviceIOMMUGroupLink(address string) string {
	return filepath.Join(sysDevices, address, "iommu_group")
}

// DeviceIOMMUGroup reads the IOMMU group a device is in from its sysfs link.
// The error wraps fs.ErrNotExist when the device has no group (or is not in
// sysfs at all).
func DeviceIOMMUGroup(address string) (int, error) {
	link := DeviceIOMMUGroupLink(address)
	target, err := os.Readlink(link)
	if err != nil {
		return -1, err
	}
	n, err := strconv.Atoi(filepath.Base(target))
	if err != nil {
		return -1, fmt.Errorf("%s points at %q, not a group number", link, target)
	}
	return n, nil
}

// DeviceInSysfs reports whether a device directory exists under the PCI
// devices root.
func DeviceInSysfs(address string) bool {
	_, err := os.Stat(filepath.Join(sysDevices, address))
	return err == nil
}

// SysDevicesPath is the PCI devices root (/sys/bus/pci/devices).
func SysDevicesPath() string { return sysDevices }
