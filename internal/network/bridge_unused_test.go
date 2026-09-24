package network

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRemoveBridgeIfUnused(t *testing.T) {
	root := t.TempDir()
	sysClassNet = root
	defer func() { sysClassNet = "/sys/class/net" }()
	withIP := map[string]bool{"hc_ip": true}
	origIPv4 := bridgeIPv4
	bridgeIPv4 = func(name string) bool { return withIP[name] }
	defer func() { bridgeIPv4 = origIPv4 }()
	var deleted []string
	execCommand = func(name string, args ...string) ([]byte, error) {
		deleted = append(deleted, args[len(args)-1])
		return nil, nil
	}
	defer func() { execCommand = defaultExec }()

	mk := func(name string, bridge bool, ports ...string) {
		t.Helper()
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if bridge {
			if err := os.MkdirAll(filepath.Join(dir, "bridge"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.MkdirAll(filepath.Join(dir, "brif"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, p := range ports {
				if err := os.WriteFile(filepath.Join(dir, "brif", p), nil, 0o644); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	mk("hc_hc", true)
	mk("hc_busy", true, "vnet3")
	mk("hc_ip", true)
	mk("hc_nic", false)

	for _, tc := range []struct {
		name string
		want bool
	}{
		{"hc_hc", true},      // empty bridge
		{"hc_busy", false},   // a port is attached
		{"hc_ip", false},     // carries an address
		{"hc_nic", false},    // not a bridge
		{"hc_absent", false}, // not there
	} {
		got, err := RemoveBridgeIfUnused(tc.name)
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("RemoveBridgeIfUnused(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
	if len(deleted) != 1 || deleted[0] != "hc_hc" {
		t.Errorf("ip link del ran for %v, want only hc_hc", deleted)
	}
}
