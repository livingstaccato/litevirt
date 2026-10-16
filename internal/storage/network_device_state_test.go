package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDaemonStatePath_NetworkDeviceRecord(t *testing.T) {
	data, pki := filepath.Join(t.TempDir(), "data"), filepath.Join(t.TempDir(), "pki")
	alias := filepath.Join(t.TempDir(), "runtime")
	if err := os.Symlink("/run", alias); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/run/litevirt/network-devices.json", "/run/litevirt/network-devices.json.tmp", filepath.Join(alias, "litevirt", "network-devices.json"), filepath.Join(alias, "litevirt", "network-devices.json.tmp")} {
		if err := CheckDaemonStatePath(p, data, pki); err == nil {
			t.Errorf("daemon network record accepted: %s", p)
		}
	}
	for _, p := range []string{"/run/litevirt/network-devices.json.user", "/run/litevirt/ordinary.img", filepath.Join(t.TempDir(), "network-devices.json")} {
		if err := CheckDaemonStatePath(p, data, pki); err != nil {
			t.Errorf("ordinary neighboring file rejected: %s: %v", p, err)
		}
	}
}
