package cli

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// shellWords is cmd as sh splits it, evaluated in dir (a command
// substitution or a ; there would show up as a file or extra words).
func shellWords(t *testing.T, dir, cmd string) []string {
	t.Helper()
	c := exec.Command("sh", "-c", `eval "set -- $1"; for a in "$@"; do printf '%s\n' "$a"; done`, "_", cmd)
	c.Dir = dir
	out, err := c.CombinedOutput()
	if err != nil {
		t.Fatalf("sh on %q: %v (%s)", cmd, err, out)
	}
	return strings.Split(strings.TrimRight(string(out), "\n"), "\n")
}

// Our review m2: the commands an add's refusal and a removal print are one
// shell word per argument whatever the name, and running them runs nothing
// else. Pinned on the commands sh evaluates.
//
// Mutation: shellWord returns its input — every name but the plain one
// splits, and two run commands.
func TestSettleCommands_AreShellSafe(t *testing.T) {
	for _, n := range []string{"node-9", "x;touch${IFS}pwned", "a b", "$(touch pwned2)", "it's", "`touch pwned3`", "n|sh", "x&&y", "a\"b"} {
		dir := t.TempDir()
		for _, cmd := range []string{
			settleCmd(hostAddPlan{hostName: n, hostAddr: "10.0.0.9"}, "abc"),
			settleRmCmd(n, "00ABC", "10.0.0.9"),
		} {
			got := shellWords(t, dir, cmd)
			want := []string{"lv", "host", "rm", n, "--serial", "abc", "--address", "10.0.0.9"}
			if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
				t.Errorf("%q splits as %q, want %q", cmd, got, want)
			}
		}
		if ents, _ := os.ReadDir(dir); len(ents) != 0 {
			t.Errorf("evaluating the commands for %q ran something: %v", n, ents)
		}
	}
}
