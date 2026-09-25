package fence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeRemote models the host at the far end of an SSH fence.
type fakeRemote struct {
	// forceWorks: `systemctl poweroff --force --force` powers the host off.
	// When false it fails, as it does on a host without systemd.
	forceWorks bool
	// sysrqWritable: /proc/sysrq-trigger accepts a write.
	sysrqWritable bool
	// unreachable: ssh never gets a session (no route, refused, auth failed).
	unreachable bool
	// forcedCommand: the key is pinned to an authorized_keys command="..."
	// that ignores what was asked for and exits 0.
	forcedCommand bool
}

// remoteHost is a running fake host; its state file reads "running",
// "shutting-down-gracefully" or "off".
type remoteHost struct {
	dir   string
	sysrq string
}

func (h remoteHost) state(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(h.dir, "state"))
	if err != nil {
		t.Fatalf("read host state: %v", err)
	}
	return strings.TrimSpace(string(b))
}

func (h remoteHost) sysrqWrites() string {
	b, _ := os.ReadFile(h.sysrq)
	return strings.TrimSpace(string(b))
}

// fakeSSH puts an `ssh` on PATH that behaves like a real one against a fake
// host: it runs the remote command string — the last argument — through a
// shell whose `systemctl` and `poweroff` act on the host's state, and whose
// /proc/sysrq-trigger is a file under the test's temp dir.
//
// The remote command is executed rather than matched, because the properties
// under test live inside the command string itself: a trailing `|| true`
// collapses any remote failure to exit 0, and a graceful poweroff "succeeds"
// while the host keeps running its guests for minutes.
//
// Two behaviours of the real ssh client are modelled because the fence's
// classification depends on them:
//
//   - When the host powers off mid-session no exit status ever arrives. Real
//     ssh then exits 255 — but only if ServerAliveInterval is set; without it
//     the client waits on a TCP connection to a machine that no longer exists
//     until something kills it. The fake hangs in that case.
//   - An unreachable host makes ssh exit 255 without running anything.
func fakeSSH(t *testing.T, r fakeRemote) remoteHost {
	t.Helper()
	dir := t.TempDir()
	remote := filepath.Join(dir, "remote")
	if err := os.MkdirAll(remote, 0o755); err != nil {
		t.Fatalf("mkdir remote: %v", err)
	}
	h := remoteHost{dir: dir, sysrq: filepath.Join(dir, "proc", "sysrq-trigger")}
	if r.sysrqWritable {
		if err := os.MkdirAll(filepath.Dir(h.sysrq), 0o755); err != nil {
			t.Fatalf("mkdir proc: %v", err)
		}
	} // else: the parent directory is missing, so the redirect fails even as root.
	state := filepath.Join(dir, "state")
	if err := os.WriteFile(state, []byte("running\n"), 0o644); err != nil {
		t.Fatalf("write state: %v", err)
	}

	forced := "echo 'System has not been booted with systemd' >&2; exit 1"
	if r.forceWorks {
		// The real call never returns; the ssh wrapper below sees the host is
		// off and reports what a real client would.
		forced = fmt.Sprintf("echo off > %q; exit 0", state)
	}
	systemctl := fmt.Sprintf(`#!/bin/sh
case "$*" in
  "poweroff --force --force"|"poweroff -ff"|"-ff poweroff"|"--force --force poweroff")
    %s ;;
  "poweroff")
    # Real systemctl queues the shutdown job and returns 0 at once; the host
    # then spends minutes in libvirt-guests waiting for its VMs.
    echo shutting-down-gracefully > %q; exit 0 ;;
  *) echo "systemctl: unexpected args: $*" >&2; exit 1 ;;
esac
`, forced, state)
	if err := os.WriteFile(filepath.Join(remote, "systemctl"), []byte(systemctl), 0o755); err != nil {
		t.Fatalf("write fake systemctl: %v", err)
	}
	poweroff := fmt.Sprintf(`#!/bin/sh
[ "$*" = "" ] && { echo shutting-down-gracefully > %q; exit 0; }
echo "poweroff: unexpected args: $*" >&2; exit 1
`, state)
	if err := os.WriteFile(filepath.Join(remote, "poweroff"), []byte(poweroff), 0o755); err != nil {
		t.Fatalf("write fake poweroff: %v", err)
	}

	preamble := ""
	if r.unreachable {
		preamble = `echo "ssh: connect to host 10.0.0.4 port 22: No route to host" >&2; exit 255`
	}
	if r.forcedCommand {
		preamble = `echo "backup-only key"; exit 0`
	}
	sshScript := fmt.Sprintf(`#!/bin/sh
%s
alive=no
case "$*" in *ServerAliveInterval=*) alive=yes ;; esac
for last; do :; done
cmd=$(printf '%%s' "$last" | sed "s#/proc/sysrq-trigger#%s#g")
PATH=%q:/usr/bin:/bin sh -c "$cmd"
rc=$?
grep -qx o %q 2>/dev/null && echo off > %q
if [ "$(cat %q)" = off ]; then
  if [ $alive = yes ]; then
    echo "Timeout, server 10.0.0.4 not responding." >&2
    exit 255
  fi
  exec sleep 60
fi
exit $rc
`, preamble, h.sysrq, remote, h.sysrq, state, state)
	if err := os.WriteFile(filepath.Join(dir, "ssh"), []byte(sshScript), 0o755); err != nil {
		t.Fatalf("write fake ssh: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return h
}

func sshHost() HostConfig {
	return HostConfig{Name: "node-4", Address: "10.0.0.4", SSHUser: "root", SSHPort: 22, FenceStrategy: "ssh"}
}

// fenceCtx bounds a fence the way the coordinator does, well above what a
// forced power-off needs and well below the fake's hang.
func fenceCtx(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// A fence must stop the machine now. A graceful `systemctl poweroff` returns 0
// the moment the job is queued, and the host then waits in libvirt-guests for
// its VMs to shut down cleanly — on the lab, ~2m40s during which the fence
// already read "fenced" and a coordinator could start a second copy of a VM
// that was still running.
//
// A forced power-off never returns, so the session dies under the fence and ssh
// exits 255. That must still be reported as a success, or every SSH fence that
// worked would strand its host's VMs.
func TestFenceSSH_PowersTheHostOffImmediately(t *testing.T) {
	h := fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true})

	r := Execute(fenceCtx(t), sshHost())

	if got := h.state(t); got != "off" {
		t.Errorf("host state = %q after the fence, want off: a graceful shutdown leaves guests running", got)
	}
	if !r.Success {
		t.Errorf("Success=false for a host that was powered off; detail=%q", r.Detail)
	}
}

// A host where systemctl cannot force a power-off (no systemd) is powered off
// through the kernel directly.
func TestFenceSSH_FallsBackToSysrqWhenSystemctlCannotForce(t *testing.T) {
	h := fakeSSH(t, fakeRemote{forceWorks: false, sysrqWritable: true})

	r := Execute(fenceCtx(t), sshHost())

	if got := h.sysrqWrites(); got != "o" {
		t.Errorf("/proc/sysrq-trigger received %q, want \"o\" (immediate power-off)", got)
	}
	if !r.Success {
		t.Errorf("Success=false after a sysrq power-off; detail=%q", r.Detail)
	}
}

// A reachable host whose power-off commands both failed has not been fenced.
//
// The remote command once ended in `|| true`, so the shell exited 0 whatever
// happened and the fence reported Success. That success is load-bearing:
// fenceProvedOff writes hosts.state = "fenced" from it, and a later coordinator
// resumes the reschedule from that record alone. A host that is still running
// then has its VMs started somewhere else.
func TestFenceSSH_ReportsFailureWhenThePoweroffFailed(t *testing.T) {
	h := fakeSSH(t, fakeRemote{forceWorks: false, sysrqWritable: false})

	r := Execute(fenceCtx(t), sshHost())

	if r.Success {
		t.Errorf("Success=true after both power-off commands failed; detail=%q", r.Detail)
	}
	if got := h.state(t); got != "running" {
		t.Fatalf("fake host state = %q, want running (test setup)", got)
	}
}

// ssh exits 255 both when a forced power-off kills the session and when the
// host was never reached. Only the first is a fence; reading every 255 as one
// would declare a partitioned, still-running host fenced.
func TestFenceSSH_UnreachableHostIsNotFenced(t *testing.T) {
	fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true, unreachable: true})

	r := Execute(fenceCtx(t), sshHost())

	if r.Success {
		t.Errorf("Success=true for a host ssh never reached; detail=%q", r.Detail)
	}
	if r.Method != "ssh" {
		t.Errorf("Method = %q, want ssh", r.Method)
	}
}

// An exit 0 is not proof the power-off ran. A key pinned to an authorized_keys
// forced command exits 0 without running the fence at all; only the marker the
// fence command prints shows that OUR command reached the target.
func TestFenceSSH_ExitZeroWithoutTheFenceRunningIsNotFenced(t *testing.T) {
	h := fakeSSH(t, fakeRemote{forceWorks: true, sysrqWritable: true, forcedCommand: true})

	r := Execute(fenceCtx(t), sshHost())

	if r.Success {
		t.Errorf("Success=true although the fence command never ran; detail=%q", r.Detail)
	}
	if got := h.state(t); got != "running" {
		t.Fatalf("fake host state = %q, want running (test setup)", got)
	}
}

// Best-effort is unchanged: it proceeds on a failure by design, which is why
// the safe-fence policy demands an operator confirmation for it separately.
func TestFenceSSH_BestEffortStillProceedsOnFailure(t *testing.T) {
	fakeSSH(t, fakeRemote{forceWorks: false, sysrqWritable: false})
	h := sshHost()
	h.FenceStrategy = "best-effort"

	r := Execute(fenceCtx(t), h)

	if !r.Success {
		t.Errorf("best-effort reported Success=false; it is fire-and-forget by design. detail=%q", r.Detail)
	}
}
