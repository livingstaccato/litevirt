package fencessh_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An sshd that is installed but will not start fails the real-sshd tests; it
// is not a missing prerequisite they skip on. Otherwise an OpenSSH upgrade
// that rejects the harness's configuration, or an sshd that dies on start,
// turns every real-sshd fence test into a skip.
func TestHarness_SSHDThatCannotStartIsNotASkip(t *testing.T) {
	if err := sshdPrereqs(); err != nil {
		requireOrSkip(t, "%v", err)
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, n *node)
		want  string
	}{
		{
			name:  "configuration sshd rejects",
			setup: func(t *testing.T, n *node) { n.extraConfig = "NoSuchHarnessOption yes\n" },
			want:  "NoSuchHarnessOption",
		},
		{
			name: "sshd that exits 1",
			setup: func(t *testing.T, n *node) {
				bin := t.TempDir()
				writeFile(t, filepath.Join(bin, "sshd"), "#!/bin/sh\necho fake sshd refusing to start >&2\nexit 1\n", 0o755)
				t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
			},
			want: "fake sshd refusing to start",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			n := w.node("node-x", "127.0.0.3")
			tc.setup(t, n)
			err := n.launch(false)
			if err == nil {
				t.Fatal("launch succeeded: want sshd not to listen")
			}
			var p *prereqError
			if errors.As(err, &p) {
				t.Fatalf("an sshd that is there but will not start is reported as a missing prerequisite, so start skips: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error does not carry sshd's output %q: %v", tc.want, err)
			}
		})
	}
}
