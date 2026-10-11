package main

import "testing"

// A name from a backup is guest data: control characters must not reach the
// terminal raw.
func TestPrintable_EscapesControlCharacters(t *testing.T) {
	for in, want := range map[string]string{
		"hosts":              "hosts",
		"résumé.txt":         "résumé.txt",
		"evil\x1b]0;pwn\x07": `evil\x1b]0;pwn\x07`,
		"two\nlines":         `two\x0alines`,
		"bidi\u202egnp.exe":  `bidi\u202egnp.exe`,
		"c1\u009bcsi":        `c1\u009bcsi`,
	} {
		if got := printable(in); got != want {
			t.Errorf("printable(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBackupFileTarget(t *testing.T) {
	for _, tc := range []struct {
		t        backupFileTarget
		name     string
		disk     string
		wantFail bool
	}{
		{t: backupFileTarget{repo: "r", ts: "x", vm: "web"}, name: "web", disk: "root"},
		{t: backupFileTarget{repo: "r", ts: "x", ct: "box"}, name: "box", disk: "rootfs"},
		{t: backupFileTarget{repo: "r", ts: "x", vm: "web", disk: "data"}, name: "web", disk: "data"},
		{t: backupFileTarget{repo: "r", ts: "x", vm: "web", ct: "box"}, wantFail: true},
		{t: backupFileTarget{repo: "r", ts: "x"}, wantFail: true},
		{t: backupFileTarget{ts: "x", vm: "web"}, wantFail: true},
	} {
		name, disk, err := tc.t.resolve()
		if (err != nil) != tc.wantFail || name != tc.name || disk != tc.disk {
			t.Errorf("%+v: got %q %q %v", tc.t, name, disk, err)
		}
	}
}
