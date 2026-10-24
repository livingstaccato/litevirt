package network

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An access-port NIC (trunk: with one VLAN) is refused on a Linux bridge whose
// vlan_filtering is off, and passes on one where it is on. A device that is
// missing or is not a Linux bridge, and a NIC with no access VLAN, are not
// judged.
//
// Mutations: accept any vlan_filtering value — red; judge a NIC with no
// access VLAN — red; refuse a device with no bridge/ directory — red.
func TestRunPreFlight_AccessVLANNeedsAFilteringBridge(t *testing.T) {
	root := t.TempDir()
	old := sysClassNet
	sysClassNet = root
	t.Cleanup(func() { sysClassNet = old })
	bridge := func(name, filtering string) {
		t.Helper()
		dir := filepath.Join(root, name, "bridge")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "vlan_filtering"), []byte(filtering+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	bridge("brf", "1")
	bridge("brn", "0")
	if err := os.MkdirAll(filepath.Join(root, "eth0"), 0o755); err != nil { // a device, not a bridge
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name  string
		check PreFlightCheck
		want  string // "" = passes
	}{
		{"filtering bridge", PreFlightCheck{Bridge: "brf", AccessVLAN: 30}, ""},
		{"non-filtering bridge", PreFlightCheck{Bridge: "brn", AccessVLAN: 30}, `bridge "brn" does not filter VLANs`},
		{"no access VLAN", PreFlightCheck{Bridge: "brn"}, ""},
		{"missing device", PreFlightCheck{Bridge: "nosuch", AccessVLAN: 30}, ""},
		{"not a bridge", PreFlightCheck{Bridge: "eth0", AccessVLAN: 30}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := RunPreFlight([]PreFlightCheck{tc.check})
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("RunPreFlight: %v, want nil", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("RunPreFlight: %v, want %q", err, tc.want)
			}
		})
	}

	// The first failing NIC refuses the lot.
	if err := RunPreFlight([]PreFlightCheck{{Bridge: "brf", AccessVLAN: 30}, {Bridge: "brn", AccessVLAN: 31}}); err == nil ||
		!strings.Contains(err.Error(), "VLAN 31") {
		t.Fatalf("RunPreFlight over two NICs: %v, want the second refused", err)
	}
}
