package daemon

import "testing"

// enforcement.console_password defaults ON: unset means on, and only an
// explicit false turns it off (docs/configuration.md). Nothing is set until
// console_password_v1 has latched, so the default changes nothing mid-roll.
//
// Mutation "drop ConsolePassword from LoadConfig's preset" — red on every
// unset case.
func TestLoadConfig_ConsolePasswordDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"no enforcement block", "", true},
		{"empty enforcement block", "enforcement:\n", true},
		{"enforcement block without the key", "enforcement:\n  partition_pause: true\n", true},
		{"explicitly on", "enforcement:\n  console_password: true\n", true},
		{"explicitly off", "enforcement:\n  console_password: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustLoadConfigText(t, tc.text).Enforcement.ConsolePassword; got != tc.want {
				t.Fatalf("Enforcement.ConsolePassword = %v, want %v", got, tc.want)
			}
		})
	}
}
