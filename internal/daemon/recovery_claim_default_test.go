package daemon

import "testing"

// Recovery claims are ON unless a host's config says otherwise
// (docs/design/recovery-claims.md §5.1, colonelpanik/litevirt#250): the third
// exception to the default-false rule, beside audit_signature and
// partition_pause. The token is still withheld while the flag is off and still
// needs RecoveryClaimReadiness, so the default changes nothing until every
// host runs a build that defaults it on. An explicit false is the kill switch
// and must survive.
//
// Mutation: drop RecoveryClaim from LoadConfig's preset — every default case
// goes red; preset it in a way an explicit false cannot override — the last
// case goes red.
func TestLoadConfig_RecoveryClaimDefaultsOn(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		want       bool
	}{
		{"no enforcement block", "", true},
		{"empty enforcement block", "enforcement:\n", true},
		{"enforcement block without the key", "enforcement:\n  partition_pause: true\n", true},
		{"explicitly on", "enforcement:\n  recovery_claim: true\n", true},
		// An empty or null value is not an explicit false: only `false` turns
		// it off, as docs/configuration.md says.
		{"empty value", "enforcement:\n  recovery_claim:\n", true},
		{"null value", "enforcement:\n  recovery_claim: ~\n", true},
		{"explicitly off", "enforcement:\n  recovery_claim: false\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := mustLoadConfigText(t, tc.text).Enforcement.RecoveryClaim; got != tc.want {
				t.Fatalf("Enforcement.RecoveryClaim = %v, want %v", got, tc.want)
			}
		})
	}
}
