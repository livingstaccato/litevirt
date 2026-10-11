package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSSH puts an `ssh` on PATH that echoes its remote command on stdout and
// stderr and fails, the way a refused remote command does. The lab helpers'
// errors quote that command, which is where a token or a password rides.
func fakeSSH(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\nfor last; do :; done\necho \"out: $last\"\necho \"err: $last\" >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func fakeLab(t *testing.T) *lab {
	t.Helper()
	return &lab{t: t, lvPath: "/usr/local/bin/litevirt", key: "k", cmDir: t.TempDir(), portBase: 2230, num: map[string]int{"node-2": 2}}
}

// A failing delegated call must not put the user's token in the test's output.
// Needs no lab (it fakes ssh): LITEVIRT_E2E=1 LV_BIN=/bin/true LV_HOST=x
// go test ./tests/e2e -run TestRedaction
func TestRedaction_LvAsKeepsTheTokenOutOfFailures(t *testing.T) {
	fakeSSH(t)
	l := fakeLab(t)
	const tok = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	out, err := l.lvAs("node-2", tok, "role", "grant", "Admin")
	if err == nil {
		t.Fatal("the fake ssh fails, so lvAs must")
	}
	if strings.Contains(out+err.Error(), tok) {
		t.Fatalf("the token reached lvAs's output or error:\n%s\n%v", out, err)
	}
	if !strings.Contains(err.Error(), "role grant Admin") {
		t.Fatalf("redaction must keep the rest of the message: %v", err)
	}
}

func TestRedaction_QuietFailureKeepsThePasswordOut(t *testing.T) {
	fakeSSH(t)
	l := fakeLab(t)
	args := []string{"user", "create", "bob", "--password", e2eUserPassword}
	_, err := l.lv("node-2", args...)
	if err == nil || !strings.Contains(err.Error(), e2eUserPassword) {
		t.Fatalf("premise: the raw ssh error quotes the command and so the password: %v", err)
	}
	msg := quietFailure("node-2", args, err, []string{e2eUserPassword})
	if strings.Contains(msg, e2eUserPassword) {
		t.Fatalf("the password reached the failure message: %s", msg)
	}
	if !strings.Contains(msg, "user create bob") {
		t.Fatalf("redaction must keep the rest of the message: %s", msg)
	}
}
