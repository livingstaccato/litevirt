package daemon

import "testing"

// enforcement.vrrp_unicast defaults ON: unset means on, and only an explicit
// false turns it off (docs/configuration.md). Nothing changes until
// vrrp_unicast_v1 has latched, so the default changes nothing mid-roll.
//
// Mutation "drop VRRPUnicast from LoadConfig's preset" — red on every unset
// case.
func TestLoadConfig_VRRPUnicastDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"no enforcement block", "", true},
		{"empty enforcement block", "enforcement:\n", true},
		{"enforcement block without the key", "enforcement:\n  partition_pause: true\n", true},
		{"explicitly on", "enforcement:\n  vrrp_unicast: true\n", true},
		{"explicitly off", "enforcement:\n  vrrp_unicast: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustLoadConfigText(t, tc.text).Enforcement.VRRPUnicast; got != tc.want {
				t.Fatalf("Enforcement.VRRPUnicast = %v, want %v", got, tc.want)
			}
		})
	}
}
