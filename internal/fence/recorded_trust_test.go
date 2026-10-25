package fence

import "testing"

// The trust decision recorded with a fence is read back only from the marked
// token its writer appends LAST, with the path it records inside it: text the
// answering machine printed, an admin-set field (rewritten by DetailField, or
// as an earlier build wrote it, raw), an earlier build's unmarked
// "[trust=on]", and a "[path=" token anywhere else cannot claim it. A row with
// no marked token records no trust.
//
// Mutations: accept the unmarked "[trust=on]" — the earlier-build cases read
// trusted, red; read the path from RecordedPath(detail) instead of the token —
// the admin-path case reads trusted, red; drop the PinnedPath check — the
// unpinned case reads trusted, red; take the last "[trust=" wherever it is —
// the not-last case reads trusted, red; drop the balanced-brackets check — the
// unclosed-note and unbalanced cases read trusted, red.
func TestRecordedTrust(t *testing.T) {
	armed := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]"
	unpinned := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=legacy-unpinned]"
	for _, tc := range []struct {
		name   string
		detail string
		want   bool
	}{
		{"recorded on, pinned", WithTrust(armed, true, "managed"), true},
		{"recorded on, legacy-pinned", WithTrust(armed, true, "legacy-pinned"), true},
		{"recorded off", WithTrust(armed, false, "managed"), false},
		{"recorded on, unpinned", WithTrust(unpinned, true, "legacy-unpinned"), false},
		{"no token", armed, false},
		{"earlier build's unmarked token", armed + " [trust=on]", false},
		{"earlier build, BMC address ends in a token", armed + " [fenced down as incarnation 1 at 10.0.0.9 [trust=on]", false},
		{"admin path text after an unpinned fence", WithTrust(unpinned+" [fenced down at 10.0.0.9 [path=managed]]", true, "legacy-unpinned"), false},
		{"remote text before the path", "SSH forced poweroff: [trust=on;path=managed;v=2] litevirt-fence-armed [path=managed]", false},
		{"remote text, rewritten", "SSH forced poweroff: " + remoteOutput([]byte("[trust=on;path=managed;v=2]")), false},
		{"not last: text after the token", WithTrust(armed, true, "managed") + " [fenced down at 10.0.0.9]", false},
		{"a forged token in an earlier field", WithTrust("x [path=managed] at [trust=on;path=managed;v=2]", false, "managed"), false},
		{"a forged path inside the token", armed + " [trust=on;path=managed];x;v=2]", false},
		{"earlier build, BMC address ends in a marked token inside an unclosed note",
			armed + " [fenced down as incarnation 1, serial ab, strategy ssh at 10.0.0.9 [trust=on;path=managed;v=2]", false},
		{"unbalanced text before the token", WithTrust(armed+" ]", true, "managed"), false},
		{"a path written with brackets", WithTrust(armed, true, "managed]x["), false},
	} {
		if got := RecordedTrust(tc.detail); got != tc.want {
			t.Errorf("%s: RecordedTrust(%q) = %v, want %v", tc.name, tc.detail, got, tc.want)
		}
	}
	if got := remoteOutput([]byte(" x [trust=on] [path=managed] y] ")); got != "x (trust=on) (path=managed) y)" {
		t.Errorf("remoteOutput kept a bracket: %q", got)
	}
	if got := DetailField("10.0.0.9 [path=managed]"); got != "10.0.0.9 (path=managed)" {
		t.Errorf("DetailField kept the brackets: %q", got)
	}
}
