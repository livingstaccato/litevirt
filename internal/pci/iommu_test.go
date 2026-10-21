package pci

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestIOMMUEnabled(t *testing.T) {
	root := t.TempDir()
	groups := filepath.Join(root, "iommu_groups")
	t.Cleanup(SetSysIOMMUGroups(groups))

	if on, err := IOMMUEnabled(); on || err != nil {
		t.Fatalf("missing groups dir: got (%v, %v), want (false, nil)", on, err)
	}
	if err := os.MkdirAll(groups, 0o755); err != nil {
		t.Fatal(err)
	}
	if on, err := IOMMUEnabled(); on || err != nil {
		t.Fatalf("empty groups dir: got (%v, %v), want (false, nil)", on, err)
	}
	if err := os.MkdirAll(filepath.Join(groups, "0"), 0o755); err != nil {
		t.Fatal(err)
	}
	if on, err := IOMMUEnabled(); !on || err != nil {
		t.Fatalf("one group: got (%v, %v), want (true, nil)", on, err)
	}

	// A path that is not a directory is a read error, not "off".
	file := filepath.Join(root, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(SetSysIOMMUGroups(file))
	if _, err := IOMMUEnabled(); err == nil {
		t.Fatal("unreadable groups dir: want an error")
	}
}

func TestDeviceIOMMUGroup(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(SetSysDevices(root))
	const addr = "0000:41:00.0"
	if err := os.MkdirAll(filepath.Join(root, addr), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := DeviceIOMMUGroup(addr); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("no link: got %v, want fs.ErrNotExist", err)
	}
	if err := os.Symlink("../../../kernel/iommu_groups/12", DeviceIOMMUGroupLink(addr)); err != nil {
		t.Fatal(err)
	}
	if g, err := DeviceIOMMUGroup(addr); g != 12 || err != nil {
		t.Fatalf("got (%d, %v), want (12, nil)", g, err)
	}
	if !DeviceInSysfs(addr) || DeviceInSysfs("0000:99:00.0") {
		t.Fatal("DeviceInSysfs wrong")
	}
}
