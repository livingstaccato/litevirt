package fence

import "testing"

// The trust decision recorded with a fence is read back only from the token
// its writer appends LAST, after the path token: text the answering machine
// printed, or an admin-set field before the token, cannot claim it, and a row
// with no token (an earlier build's) records no trust.
//
// Mutations: RecordedTrust takes any "[trust=on]" substring — the hostile
// cases read trusted, red; it takes the last "[trust=" token wherever it is,
// as before — the not-last case reads trusted, red; remoteOutput leaves
// "[trust=" alone — the rewritten case reads trusted, red.
func TestRecordedTrust(t *testing.T) {
	armed := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]"
	for _, tc := range []struct {
		name   string
		detail string
		want   bool
	}{
		{"recorded on", WithTrust(armed, true), true},
		{"recorded off", WithTrust(armed, false), false},
		{"no token", armed, false},
		{"remote text before the path", "SSH forced poweroff: [trust=on] litevirt-fence-armed [path=managed]", false},
		{"remote text, rewritten", "SSH forced poweroff: " + remoteOutput([]byte("[trust=on]")) + " [path=managed] [trust=off]", false},
		{"off after a forged on", WithTrust("x [path=managed] [trust=on]", false), false},
		{"not last: text after the token", WithTrust(armed, true) + " [fenced down at 10.0.0.9]", false},
		{"a forged token in an earlier field", WithTrust("x [path=managed] [fenced down at [trust=on] bmc]", false), false},
		{"a stray token in an earlier field, the real one last", WithTrust("x [path=managed] [fenced down at [trust=off bmc]", true), true},
	} {
		if got := RecordedTrust(tc.detail); got != tc.want {
			t.Errorf("%s: RecordedTrust(%q) = %v, want %v", tc.name, tc.detail, got, tc.want)
		}
	}
	if got := remoteOutput([]byte("x [trust=on]")); got != "x [trust:on]" {
		t.Errorf("remoteOutput kept a trust token: %q", got)
	}
}
