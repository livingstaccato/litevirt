// Package labsecret hands a secret to a lab node without it ever reaching a
// command line or test output: the secret travels on the remote command's
// stdin, and any error from that step has it redacted. tests/e2e uses it for
// the iSCSI test target's CHAP credentials.
package labsecret

import (
	"errors"
	"strings"
)

// Runner runs cmd on a lab node with stdin as its standard input. Its error
// may quote cmd, its output and anything else; Run redacts it.
type Runner func(cmd, stdin string) (string, error)

// Redacted is what a secret is replaced with in an error.
const Redacted = "<redacted>"

// Redact replaces every non-empty secret in s.
func Redact(s string, secrets ...string) string {
	for _, sec := range secrets {
		if sec != "" {
			s = strings.ReplaceAll(s, sec, Redacted)
		}
	}
	return s
}

// SetTPGCHAPCommand is the remote command that sets the CHAP credentials of
// tpg 1 of LIO iSCSI target iqn — the tpg-level auth a target with
// generate_node_acls=1 uses (what `targetcli … tpg1 set auth` writes) — from
// two lines on its stdin: the user name, then the password. They are read and
// written by shell builtins only, so neither is in any process's argv.
func SetTPGCHAPCommand(iqn string) string {
	dir := "/sys/kernel/config/target/iscsi/" + iqn + "/tpgt_1/auth"
	return "set -e; IFS= read -r u; IFS= read -r p; d=" + shellQuote(dir) +
		`; printf %s "$u" > "$d/userid"; printf %s "$p" > "$d/password"`
}

// SetTPGCHAP sets tpg 1's CHAP credentials of target iqn through run. The
// credentials are only on stdin; a failure's error names the target, never
// the user or the password.
func SetTPGCHAP(run Runner, iqn, user, password string) error {
	if user == "" || password == "" || strings.ContainsAny(user+password, "\n\r") {
		return errors.New("set CHAP on target " + iqn + ": the user and password must be non-empty single lines")
	}
	if _, err := run(SetTPGCHAPCommand(iqn), user+"\n"+password+"\n"); err != nil {
		return errors.New("set CHAP on target " + iqn + ": " + Redact(err.Error(), password, user))
	}
	return nil
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
