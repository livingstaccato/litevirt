package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRemoteAddSetupCommand_NoInjectionFromJoinPeers pins shellEnvPrefix at the
// `lv host add` call site. The setup_env_quoting tests prove the helper; only
// running the exact line HostAdd hands to sshd shows the helper is still the
// thing building it.
//
// The command is run as sshd runs it: through a shell, with the setup script
// on stdin for `bash -s`. Here the "script" just reports what JOIN_PEERS
// arrived as.
func TestRemoteAddSetupCommand_NoInjectionFromJoinPeers(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not on PATH; the remote line runs `bash -s`")
	}
	canary := filepath.Join(t.TempDir(), "pwned")
	// A peer address from hosts.address, rendered the way HostAdd renders it.
	peersYAML := `["$(touch ` + canary + `):7946","10.0.0.2:7946"]`

	line := remoteAddSetupCommand("node-9", "10.0.0.9", peersYAML, "enforcement:\n  audit_signature: true\n")
	if !strings.HasSuffix(line, " bash -s") {
		t.Fatalf("the add setup line no longer runs `bash -s` off stdin: %q", line)
	}

	cmd := exec.Command("/bin/sh", "-c", line)
	cmd.Stdin = strings.NewReader(`printf '%s|%s|%s' "$HOST_NAME" "$ADVERTISE_ADDRESS" "$JOIN_PEERS"`)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("the shell rejected the add setup line %q: %v", line, err)
	}

	if _, err := os.Stat(canary); err == nil {
		t.Fatalf("the shell EXECUTED a payload carried in a peer address: %s exists", canary)
	}
	if got, want := string(out), "node-9|10.0.0.9|"+peersYAML; got != want {
		t.Fatalf("setup env arrived as %q, want %q", got, want)
	}
}
