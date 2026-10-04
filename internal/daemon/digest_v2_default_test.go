package daemon

import "testing"

// digest_v2 is ON unless a host's config says otherwise. With it off, a
// replica founded at an older schema and one founded fresh — identical rows,
// different physical column order — compare positionally and disagree on
// every pass, so `lv cluster converge` reports DIVERGENT and anti-entropy
// pulls the table each cycle. It is not a capability token: two peers compare
// v2 only when BOTH emitted it, so a default that differs across builds never
// pits a v1 hash against a v2 one. An explicit false is the kill switch.
//
// Mutation: drop DigestV2 from LoadConfig's preset — every default case goes
// red; preset it in a way an explicit false cannot override — the last case
// goes red.
func TestLoadConfig_DigestV2DefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"no enforcement block", "", true},
		{"empty enforcement block", "enforcement:\n", true},
		{"enforcement block without the key", "enforcement:\n  recovery_claim: true\n", true},
		{"explicitly on", "enforcement:\n  digest_v2: true\n", true},
		{"explicitly off", "enforcement:\n  digest_v2: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustLoadConfigText(t, tc.text).Enforcement.DigestV2; got != tc.want {
				t.Fatalf("Enforcement.DigestV2 = %v, want %v", got, tc.want)
			}
		})
	}
}
