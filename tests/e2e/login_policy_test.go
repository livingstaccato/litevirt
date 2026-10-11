package e2e

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/tests/e2e/e2ehelp"
	"github.com/litevirt/litevirt/tests/e2e/labsecret"
)

// Login rules on the live lab: an account disabled on one node stops
// authenticating on the others, and a delegated project admin cannot grant
// beyond its project or its own holdings. The fleet tests prove the logic in
// one process; this proves it through the real binary, the real CLI and the
// real replication between lab nodes, and checks every replica's
// user_lifecycle rows directly.
//
// Needs release_2026_11_v1 latched on the lab (every node on this build), so
// the login_policy feature can open.

var tokenLine = regexp.MustCompile(`(?m)^Token:\s+([0-9a-f]{64})\s*$`)

// e2eUserPassword is the throwaway password of the test users. It is a
// credential like any other: it never reaches a failure message or a log.
const e2eUserPassword = "e2e-password-0123456789"

// lvAs runs the CLI on host with an API token, so the call authenticates as
// that token's user rather than as the host. The token rides on the remote
// command line, which an ssh error quotes, so the output and the error are
// redacted of it before they leave this function.
func (l *lab) lvAs(host, token string, args ...string) (string, error) {
	q := []string{"LV_TOKEN=" + shellQuote(token), shellQuote(l.lvPath)}
	for _, a := range args {
		q = append(q, shellQuote(a))
	}
	out, err := l.ssh(host, 2*time.Minute, strings.Join(q, " "))
	return labsecret.Redact(out, token), e2ehelp.RedactError(err, token)
}

// quietFailure is the message for a failed command that carried a credential:
// the command and the error with every secret redacted.
func quietFailure(host string, args []string, err error, secrets []string) string {
	return fmt.Sprintf("lv %s on %s: %v", labsecret.Redact(strings.Join(args, " "), secrets...), host, e2ehelp.RedactError(err, secrets...))
}

// mustLVQuiet is mustLV for a command that carries a credential.
func (l *lab) mustLVQuiet(secrets []string, host string, args ...string) string {
	l.t.Helper()
	out, err := l.lv(host, args...)
	if err != nil {
		l.t.Fatal(quietFailure(host, args, err, secrets))
	}
	return out
}

func (l *lab) mintToken(host, user string) string {
	l.t.Helper()
	out := l.mustLV(host, "user", "token-create", user, "e2e-"+user)
	m := tokenLine.FindStringSubmatch(out)
	if m == nil {
		// The output may hold a token in a shape the pattern missed: say how
		// much there was, not what.
		l.t.Fatalf("no token line in `lv user token-create` output (%d bytes, not shown: it may hold a credential)", len(out))
	}
	return m[1]
}

func TestLab_DisabledAccountRefusedOnEveryNode(t *testing.T) {
	l := newLab(t)
	a, b, c := l.hosts[0], l.hosts[1], l.hosts[2]
	user := fmt.Sprintf("e2e-bob-%d", time.Now().Unix())
	l.mustLVQuiet([]string{e2eUserPassword}, a, "user", "create", user, "--role", "operator", "--password", e2eUserPassword)
	l.onRestore(func() { _, _ = l.lv(a, "user", "delete", user) })
	tok := l.mintToken(a, user)

	waitUntil := func(what string, cond func() bool) {
		t.Helper()
		deadline := time.Now().Add(90 * time.Second)
		for !cond() {
			if time.Now().After(deadline) {
				t.Fatalf("timed out waiting for %s", what)
			}
			time.Sleep(2 * time.Second)
		}
	}
	waitUntil("the token to work on "+c, func() bool {
		_, err := l.lvAs(c, tok, "session", "ls")
		return err == nil
	})

	l.mark("disable %s on %s", user, a)
	l.mustLV(a, "user", "disable", user)
	for _, h := range []string{b, c} {
		h := h
		waitUntil("the token to be refused on "+h, func() bool {
			_, err := l.lvAs(h, tok, "session", "ls")
			return err != nil && strings.Contains(err.Error(), "account disabled")
		})
		rows := l.mustSQL(h, fmt.Sprintf(
			`SELECT value FROM user_lifecycle WHERE username = '%s' AND attribute = 'disabled' AND deleted_at IS NULL`, user))
		if len(rows) != 1 || rows[0][0] != "true" {
			t.Fatalf("%s: user_lifecycle disabled row = %v, want [[true]]", h, rows)
		}
	}
	if out := l.mustLV(c, "user", "ls"); !regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(user) + `\s.*\sdisabled\s`).MatchString(out) {
		t.Fatalf("`lv user ls` on %s does not show %s disabled:\n%s", c, user, out)
	}

	l.mark("enable %s on %s", user, b)
	l.mustLV(b, "user", "enable", user)
	waitUntil("the token to work again on "+a, func() bool {
		_, err := l.lvAs(a, tok, "session", "ls")
		return err == nil
	})
}

func TestLab_DelegatedAdminStaysInItsProject(t *testing.T) {
	l := newLab(t)
	a, b := l.hosts[0], l.hosts[1]
	sfx := time.Now().Unix()
	pat, bob := fmt.Sprintf("e2e-pat-%d", sfx), fmt.Sprintf("e2e-bob-%d", sfx)
	proj := fmt.Sprintf("/projects/e2e-acme-%d", sfx)
	for _, u := range []string{pat, bob} {
		l.mustLVQuiet([]string{e2eUserPassword}, a, "user", "create", u, "--role", "viewer", "--password", e2eUserPassword)
		u := u
		l.onRestore(func() { _, _ = l.lv(a, "user", "delete", u) })
	}
	l.mustLV(a, "role", "grant", "Operator", "user:"+pat+"@local", "--path", proj, "--propagate")
	l.mustLV(a, "role", "grant", "PermissionAdmin", "user:"+pat+"@local", "--path", proj, "--propagate")
	l.mustLV(a, "role", "grant", "VMOperator", "user:"+bob+"@local", "--path", proj+"/vms/seed", "--propagate")
	tok := l.mintToken(a, pat)

	// The delegated grant is judged against the engine snapshot of b, which
	// reloads on its own schedule (about 30 s; 16 s was measured): until it
	// has, b still sees pat as a viewer and refuses. So wait for the in-project
	// grant to WORK, bounded (a hard 60 s: a hung ssh attempt is abandoned at
	// the deadline), and only then check what must stay refused: a
	// refusal before the snapshot loads would pass those checks for the wrong
	// reason.
	inProject := []string{"role", "grant", "VMOperator", "user:" + bob + "@local", "--path", proj, "--propagate"}
	start := time.Now()
	if err := e2ehelp.Eventually(60*time.Second, 2*time.Second, func() error {
		out, err := l.lvAs(b, tok, inProject...)
		if err != nil {
			return fmt.Errorf("%v: %s", err, out)
		}
		return nil
	}); err != nil {
		t.Fatalf("delegated grant inside the project on %s never worked in 60s: %v", b, err)
	}
	l.mark("the delegated grant on %s worked after %v", b, time.Since(start).Round(time.Second))

	for _, bad := range [][]string{
		{"role", "grant", "Admin", "user:" + bob + "@local", "--path", proj, "--propagate"},
		{"role", "grant", "VMOperator", "user:" + bob + "@local", "--path", "/projects/other", "--propagate"},
		{"role", "grant", "VMOperator", "user:" + bob + "@local", "--path", "/", "--propagate"},
		{"role", "grant", "VMOperator", "user:" + bob + "@local", "--path", proj + "/../other", "--propagate"},
	} {
		if out, err := l.lvAs(b, tok, bad...); err == nil {
			t.Fatalf("delegated `lv %s` on %s succeeded:\n%s", strings.Join(bad, " "), b, out)
		}
	}
	rows := l.mustSQL(a, fmt.Sprintf(
		`SELECT role, path FROM role_bindings WHERE principal = 'user:%s@local' AND path != '%s'
		   AND path NOT LIKE '%s/%%' AND deleted_at IS NULL`, bob, proj, proj))
	if len(rows) != 0 {
		t.Fatalf("bob holds bindings outside %s: %v", proj, rows)
	}
}
