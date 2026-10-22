package ssh

import (
	"os"
	"path/filepath"
	"testing"
)

// TestMain points the global known_hosts files into a directory of the test
// binary's own, so no test reads this machine's /etc/ssh/ssh_known_hosts{,2}:
// on a host whose global file x/crypto cannot parse, or that covers 127.0.0.1
// or *, every dial test would fail or change meaning.
func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "lv-ssh-global-")
	if err != nil {
		panic(err)
	}
	defaultGlobalKnownHosts = []string{filepath.Join(dir, "ssh_known_hosts"), filepath.Join(dir, "ssh_known_hosts2")}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}
