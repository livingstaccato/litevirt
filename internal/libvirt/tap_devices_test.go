package libvirt

import "testing"

// Every interface with a target dev is mapped by its lower-cased MAC; one
// without (not started yet) is left out.
func TestParseTapDevices(t *testing.T) {
	got, err := parseTapDevices(`<domain><devices>
  <interface type='bridge'><mac address='52:54:00:AA:00:01'/><target dev='vnet2'/></interface>
  <interface type='bridge'><mac address='52:54:00:aa:00:02'/><target dev='vnet3'/></interface>
  <interface type='bridge'><mac address='52:54:00:aa:00:03'/></interface>
</devices></domain>`)
	if err != nil {
		t.Fatalf("parseTapDevices: %v", err)
	}
	want := map[string]string{"52:54:00:aa:00:01": "vnet2", "52:54:00:aa:00:02": "vnet3"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for mac, tap := range want {
		if got[mac] != tap {
			t.Errorf("%s → %q, want %q", mac, got[mac], tap)
		}
	}
	if _, err := parseTapDevices("<domain"); err == nil {
		t.Error("malformed XML must be an error, not an empty map")
	}
}
