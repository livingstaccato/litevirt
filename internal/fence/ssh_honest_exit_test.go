package fence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fakeSSH puts an `ssh` on PATH that behaves like a real one: it runs the
// remote command string — the last argument — through a shell whose
// `systemctl` and `poweroff` exit with poweroffExit, and returns that shell's
// status.
//
// The remote command is executed rather than matched, because the property
// under test lives inside the command string itself. `systemctl poweroff ||
// poweroff || true` collapses any remote failure to exit 0, and a fake that
// merely returned a chosen exit code would assert the fake's arithmetic instead
// of the command's.
func fakeSSH(t *testing.T, poweroffExit int) {
	t.Helper()
	dir := t.TempDir()
	remote := filepath.Join(dir, "remote")
	if err := os.MkdirAll(remote, 0o755); err != nil {
		t.Fatalf("mkdir remote: %v", err)
	}
	for _, name := range []string{"systemctl", "poweroff"} {
		script := fmt.Sprintf("#!/bin/sh\necho \"%s: exiting %d\"\nexit %d\n", name, poweroffExit, poweroffExit)
		if err := os.WriteFile(filepath.Join(remote, name), []byte(script), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", name, err)
		}
	}

	sshScript := fmt.Sprintf(`#!/bin/sh
for last; do :; done
PATH=%q:/usr/bin:/bin sh -c "$last"
exit $?
`, remote)
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(sshScript), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func sshHost() HostConfig {
	return HostConfig{Name: "node-4", Address: "10.0.0.4", SSHUser: "root", SSHPort: 22, FenceStrategy: "ssh"}
}

// A reachable host whose poweroff commands both failed has not been fenced.
//
// The remote command ended in `|| true`, so the shell exited 0 whatever
// happened and the fence reported Success. That success is load-bearing:
// fenceProvedOff writes hosts.state = "fenced" from it, and a later coordinator
// resumes the reschedule from that record alone. A host that is still running
// then has its VMs started somewhere else.
func TestFenceSSH_ReportsFailureWhenThePoweroffFailed(t *testing.T) {
	fakeSSH(t, 1)

	r := Execute(context.Background(), sshHost())

	if r.Success {
		t.Errorf("Success=true after both poweroff commands failed; detail=%q", r.Detail)
	}
}

// A poweroff that worked is still a success. Without this, reporting every SSH
// fence as failed would pass the test above — and would strand the VMs of every
// host that was genuinely powered off.
func TestFenceSSH_ReportsSuccessWhenThePoweroffWorked(t *testing.T) {
	fakeSSH(t, 0)

	r := Execute(context.Background(), sshHost())

	if !r.Success {
		t.Errorf("Success=false after the poweroff succeeded; detail=%q", r.Detail)
	}
}

// Best-effort is unchanged: it proceeds on a failure by design, which is why
// the safe-fence policy demands an operator confirmation for it separately.
func TestFenceSSH_BestEffortStillProceedsOnFailure(t *testing.T) {
	fakeSSH(t, 1)
	h := sshHost()
	h.FenceStrategy = "best-effort"

	r := Execute(context.Background(), h)

	if !r.Success {
		t.Errorf("best-effort reported Success=false; it is fire-and-forget by design. detail=%q", r.Detail)
	}
}
