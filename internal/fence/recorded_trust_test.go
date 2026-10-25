package fence

import "testing"

// The trust decision recorded with a fence is read back only from the token
// the coordinator appends, after the path token: text the answering machine
// printed cannot claim it, and a row with no token (an earlier build's)
// records no trust.
//
// Mutations: RecordedTrust takes any "[trust=on]" substring — the hostile
// cases read trusted, red; remoteOutput leaves "[trust=" alone — the
// rewritten case reads trusted, red.
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
		{"followed by a hold note", WithTrust(armed, true) + "; the remote shell confirmed the power-off", true},
	} {
		if got := RecordedTrust(tc.detail); got != tc.want {
			t.Errorf("%s: RecordedTrust(%q) = %v, want %v", tc.name, tc.detail, got, tc.want)
		}
	}
	if got := remoteOutput([]byte("x [trust=on]")); got != "x [trust:on]" {
		t.Errorf("remoteOutput kept a trust token: %q", got)
	}
}
