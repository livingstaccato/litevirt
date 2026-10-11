package labsecret

import (
	"fmt"
	"strings"
	"testing"
)

// The CHAP credentials reach the node only on stdin, never on the command
// line (argv, ps), and a failed step's error never carries them — even when
// the runner's error quotes the command, its stdin and its output, as the lab
// harness's ssh does with the command.
//
// Mutations: put the password back in the command — the argv check goes red;
// drop the redaction — the error check goes red.
func TestSetTPGCHAP_TheSecretNeverReachesArgvOrErrors(t *testing.T) {
	const user, pass = "chap-user-x", "s3cr3t-Pa55,'\"$(x)"
	var gotCmd, gotStdin string
	failing := func(cmd, stdin string) (string, error) {
		gotCmd, gotStdin = cmd, stdin
		return "echoed " + stdin, fmt.Errorf("ssh node-1 %q: exit status 1: %s", cmd, stdin)
	}
	err := SetTPGCHAP(failing, "iqn.2026-10.io.litevirt:e2e-a", user, pass)
	if err == nil {
		t.Fatal("a failing step reported success")
	}
	for _, sec := range []string{pass, user} {
		if strings.Contains(err.Error(), sec) {
			t.Errorf("the error carries a secret: %v", err)
		}
		if strings.Contains(gotCmd, sec) {
			t.Errorf("the command line carries a secret: %q", gotCmd)
		}
	}
	if gotStdin != user+"\n"+pass+"\n" {
		t.Errorf("stdin = %q, want the user and password lines", gotStdin)
	}
	if !strings.Contains(err.Error(), "iqn.2026-10.io.litevirt:e2e-a") || !strings.Contains(err.Error(), Redacted) {
		t.Errorf("the error should name the target and show the redaction: %v", err)
	}
	ok := func(cmd, stdin string) (string, error) { return "", nil }
	if err := SetTPGCHAP(ok, "iqn.x", user, pass); err != nil {
		t.Fatalf("a succeeding step: %v", err)
	}
	if err := SetTPGCHAP(ok, "iqn.x", user, "two\nlines"); err == nil || strings.Contains(err.Error(), "two") {
		t.Fatalf("a multi-line password: %v", err)
	}
}
