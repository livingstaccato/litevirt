package libvirt

import "testing"

// The mark is evidence only with its token: an element without one, or
// another element under the namespace, is corrupt, never a match.
func TestParsePartitionPauseMark(t *testing.T) {
	for _, tc := range []struct {
		raw   string
		token string
		ok    bool
		err   bool
	}{
		{raw: `<pause token="0123abcd"/>`, token: "0123abcd", ok: true},
		{raw: `<lv:pause xmlns:lv="https://litevirt.dev/xmlns/partition-pause/1" token="t1"/>`, token: "t1", ok: true},
		{raw: `<pause/>`, err: true},
		{raw: `<managed token="t1"/>`, err: true},
		{raw: `<pause token=`, err: true},
	} {
		token, ok, err := parsePartitionPauseMark("vm", tc.raw)
		if (err != nil) != tc.err || ok != tc.ok || token != tc.token {
			t.Errorf("parsePartitionPauseMark(%q) = %q, %v, %v; want %q, %v, err=%v", tc.raw, token, ok, err, tc.token, tc.ok, tc.err)
		}
	}
}
