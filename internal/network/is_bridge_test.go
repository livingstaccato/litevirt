package network

import (
	"os"
	"path/filepath"
	"testing"
)

// IsBridge is true only for a bridge: a link that exists but is not a bridge
// (lo), a name no link has, and a name that is not a link name at all are
// all false.
//
// Mutation: IsBridge returns BridgeExists — "lo" goes red.
func TestIsBridge_OnlyABridge(t *testing.T) {
	if !BridgeExists("lo") {
		t.Skip("no lo on this host")
	}
	for _, name := range []string{"lo", "lv-no-such-br", "../lo", ""} {
		if IsBridge(name) {
			t.Errorf("IsBridge(%q) = true, want false", name)
		}
	}
}

// A link whose sysfs entry has a bridge directory is a bridge; one without is
// not, whatever else it has.
//
// Mutation: IsBridge always false — "br0" goes red.
func TestIsBridge_ABridgeInSysfs(t *testing.T) {
	root := t.TempDir()
	for _, p := range []string{"br0/bridge", "eth1/device"} {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := sysfsNet
	sysfsNet = root
	t.Cleanup(func() { sysfsNet = old })
	if !IsBridge("br0") {
		t.Error("IsBridge(br0) = false, want true: it has a bridge dir")
	}
	if IsBridge("eth1") {
		t.Error("IsBridge(eth1) = true, want false: it is a NIC")
	}
}
