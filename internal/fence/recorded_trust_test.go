package fence

import "testing"

// The trust decision recorded with a fence is read back only from the marked
// token its writer appends LAST, naming its own row's id, with the path it
// records inside it: text the answering machine printed, an admin-set field
// (rewritten by DetailField, or as an earlier build wrote it, raw), an
// earlier form ("[trust=on]", the unreleased v=2), a token naming another
// row, and a "[path=" token anywhere else cannot claim it. A row with no such
// token records no trust.
//
// Mutations: ignore the id — the wrong-id and guessed-id cases read trusted,
// red; accept the v=2 form — the earlier-form cases read trusted, red; read
// the path from RecordedPath(detail) — the admin-path case reads trusted,
// red; drop the PinnedPath check — the unpinned case reads trusted, red; drop
// the balanced-brackets check — the unclosed-note case reads trusted, red.
func TestRecordedTrust(t *testing.T) {
	const id = "row-1"
	armed := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=managed]"
	unpinned := "SSH forced poweroff to root@10.0.0.40: litevirt-fence-armed [path=legacy-unpinned]"
	for _, tc := range []struct {
		name   string
		detail string
		want   bool
	}{
		{"recorded on, pinned", WithTrust(armed, true, "managed", id), true},
		{"recorded on, legacy-pinned", WithTrust(armed, true, "legacy-pinned", id), true},
		{"recorded off", WithTrust(armed, false, "managed", id), false},
		{"recorded on, unpinned", WithTrust(unpinned, true, "legacy-unpinned", id), false},
		{"another row's id", WithTrust(armed, true, "managed", "row-2"), false},
		{"no token", armed, false},
		{"earlier build's unmarked token", armed + " [trust=on]", false},
		{"the unreleased v=2 form", armed + " [trust=on;path=managed;v=2]", false},
		{"earlier build, BMC address closes the note and forges v=2", armed + " [fenced down at x] [trust=on;path=managed;v=2]", false},
		{"earlier build, BMC address closes the note and guesses an id", armed + " [fenced down at x] [trust=on;path=managed;id=guess;v=3]", false},
		{"earlier build, BMC address ends in a token inside an unclosed note",
			armed + " [fenced down as incarnation 1 at 10.0.0.9 [trust=on;path=managed;id=" + id + ";v=3]", false},
		{"unbalanced text before the token", WithTrust(armed+" ]", true, "managed", id), false},
		{"admin path text after an unpinned fence", WithTrust(unpinned+" [fenced down at 10.0.0.9 [path=managed]]", true, "legacy-unpinned", id), false},
		{"remote text before the path", "SSH forced poweroff: [trust=on;path=managed;id=" + id + ";v=3] litevirt-fence-armed [path=managed]", false},
		{"remote text, rewritten", "SSH forced poweroff: " + remoteOutput([]byte("[trust=on;path=managed;id="+id+";v=3]")), false},
		{"not last: text after the token", WithTrust(armed, true, "managed", id) + " [fenced down at 10.0.0.9]", false},
		{"a path written with brackets or separators", WithTrust(armed, true, "managed;id=row-1", id), false},
		{"an empty id never matches", WithTrust(armed, true, "managed", ""), false},
	} {
		want := id
		if tc.name == "an empty id never matches" {
			want = ""
		}
		if got := RecordedTrust(tc.detail, want); got != tc.want {
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
