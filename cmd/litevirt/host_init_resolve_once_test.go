package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// `lv host init <alias>` reads the ssh config once: the cluster-member check
// and the init take the same resolved target. A Match exec in the config
// counts how often ssh -G ran.
func TestHostInitCmd_ResolvesTheSSHConfigOnce(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LV_CONFIG_DIR", filepath.Join(home, "lvcfg"))
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	counter := filepath.Join(home, "runs")
	cfg := "Match exec \"echo x >> " + counter + "\"\n  Port 1\nHost labnode\n  HostName 127.0.0.1\n  User deploy\n  Port 1\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := newHostInitCmd()
	cmd.SetArgs([]string{"labnode", "--name", "node-9"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	_ = cmd.Execute() // fails later (no key, no CA); only the ssh -G count matters
	b, _ := os.ReadFile(counter)
	if n := strings.Count(string(b), "x"); n != 1 {
		t.Fatalf("ssh -G ran %d times for one `host init`, want 1", n)
	}
}
