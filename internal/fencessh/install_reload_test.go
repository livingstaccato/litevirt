package fencessh

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeSystemctl is a systemctl on PATH that answers is-active from the units
// in active (sockets and services by full name; a bare name is a .service),
// records every call, and reloads a running service unless reloadFails.
func fakeSystemctl(t *testing.T, active string, reloadFails bool) (bin, log string) {
	t.Helper()
	bin = t.TempDir()
	log = filepath.Join(bin, "calls")
	fail := "0"
	if reloadFails {
		fail = "1"
	}
	script := fmt.Sprintf(`#!/bin/sh
echo "$*" >> %q
u=
for a; do case "$a" in -*) ;; *) u="$a" ;; esac; done
case "$u" in *.*) ;; *) u="$u.service" ;; esac
on=0
for x in %s; do [ "$x" = "$u" ] && on=1; done
case "$1" in
is-active) if [ $on = 1 ]; then echo active; exit 0; fi; echo inactive; exit 3 ;;
reload) if [ $on = 1 ] && [ %s = 0 ]; then exit 0; fi; echo "reload of $u failed" >&2; exit 1 ;;
esac
exit 1
`, log, active, fail)
	if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

// runReload runs lv_fence_ssh_reload with bin first on PATH and no
// FENCE_SSH_RELOAD override: the production path. Its sshd -t gate runs
// `true` unless env names an sshd and a config.
func runReload(t *testing.T, bin string, env ...string) (string, error) {
	t.Helper()
	ok, err := exec.LookPath("true")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", InstallScript+"\nlv_fence_ssh_reload")
	cmd.Env = append(append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "FENCE_SSH_RELOAD=", "FENCE_SSH_SSHD="+ok), env...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func calls(t *testing.T, log string) string {
	t.Helper()
	raw, _ := os.ReadFile(log)
	return string(raw)
}

// TestReload_UnitStates: which unit is reloaded for each way systemd runs
// sshd. A running service is reloaded whether or not a socket starts it
// (Ubuntu 22.10+ ssh.socket starts ONE persistent sshd, whose children take
// its configuration: bug B3); a socket alone needs no reload; neither is a
// refusal that says why.
func TestReload_UnitStates(t *testing.T) {
	for _, tc := range []struct {
		name, active string
		reloadFails  bool
		wantErr      bool
		reloaded     string // the unit reloaded, or "" for none
		say          string
	}{
		{name: "socket and service (Ubuntu 22.10+)", active: "ssh.socket ssh.service", reloaded: "ssh.service"},
		{name: "classic ssh.service", active: "ssh.service", reloaded: "ssh.service"},
		{name: "classic sshd.service", active: "sshd.service", reloaded: "sshd.service"},
		{name: "ssh.socket, no service yet", active: "ssh.socket", say: "the next connection starts sshd"},
		{name: "sshd.socket, no service yet", active: "sshd.socket", say: "the next connection starts sshd"},
		{name: "neither", active: "", wantErr: true, say: "cannot reload sshd"},
		{name: "service whose reload fails", active: "ssh.socket ssh.service", reloadFails: true, wantErr: true,
			say: "systemctl reload ssh.service failed: reload of ssh.service failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bin, log := fakeSystemctl(t, tc.active, tc.reloadFails)
			out, err := runReload(t, bin)
			if (err != nil) != tc.wantErr {
				t.Fatalf("reload error = %v, want error %v\noutput %q\ncalls:\n%s", err, tc.wantErr, out, calls(t, log))
			}
			c := calls(t, log)
			if tc.reloaded != "" && !strings.Contains(c, "reload "+tc.reloaded+"\n") {
				t.Fatalf("%s was not reloaded; calls:\n%s", tc.reloaded, c)
			}
			if tc.reloaded == "" && !tc.reloadFails && strings.Contains(c, "reload ") {
				t.Fatalf("reloaded with no service running; calls:\n%s", c)
			}
			if !strings.Contains(out, tc.say) {
				t.Fatalf("output %q, want %q", out, tc.say)
			}
		})
	}
}

// TestInstallScript_ReloadsSocketActivatedSSHD: the whole install, on a host
// whose ssh.socket started ssh.service, reloads it and does not warn; with no
// sshd unit at all it warns, and says why.
func TestInstallScript_ReloadsSocketActivatedSSHD(t *testing.T) {
	w := newInstallWorld(t, "")
	bin, log := fakeSystemctl(t, "ssh.socket ssh.service", false)
	out := w.run(t, "FENCE_SSH_PEERS=10.77.0.3", "FENCE_SSH_RELOAD=", "PATH="+bin+":"+os.Getenv("PATH"))
	if !strings.Contains(calls(t, log), "reload ssh.service\n") || strings.Contains(out, "WARNING") || !strings.Contains(out, "installed") {
		t.Fatalf("output %q\ncalls:\n%s", out, calls(t, log))
	}

	w = newInstallWorld(t, "")
	bin, _ = fakeSystemctl(t, "", false)
	out = w.run(t, "FENCE_SSH_PEERS=10.77.0.3", "FENCE_SSH_RELOAD=", "PATH="+bin+":"+os.Getenv("PATH"))
	if !strings.Contains(out, "cannot reload sshd") || !strings.Contains(out, "WARNING: sshd could not be reloaded") {
		t.Fatalf("output %q", out)
	}
}

// TestInstallScript_NeverReloadsAConfigSSHDRefuses: both callers of the
// reload, install and FENCE_SSH_REMOVE, go through its sshd -t gate. A config
// broken when the drop-in is removed (an operator's edit in progress) is not
// reloaded: on an sshd.service whose ExecReload is a bare SIGHUP, that would
// stop the listener and lock out new logins.
func TestInstallScript_NeverReloadsAConfigSSHDRefuses(t *testing.T) {
	w := newInstallWorld(t, "")
	w.run(t, "FENCE_SSH_PEERS=10.77.0.3")
	if w.dropIn(t) == "" {
		t.Fatal("no drop-in")
	}
	f, err := os.OpenFile(w.cfg, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString("NotAnSSHDKeyword yes\n"); err != nil {
		t.Fatal(err)
	}
	f.Close()
	bin, log := fakeSystemctl(t, "sshd.service", false)
	out := w.run(t, "FENCE_SSH_REMOVE=1", "FENCE_SSH_RELOAD=", "PATH="+bin+":"+os.Getenv("PATH"))
	if c := calls(t, log); strings.Contains(c, "reload") || !strings.Contains(out, "sshd -t -f "+w.cfg+" fails, so sshd was not reloaded") ||
		!strings.Contains(out, "NotAnSSHDKeyword") || !strings.Contains(out, "WARNING") {
		t.Fatalf("output %q\ncalls:\n%s", out, c)
	}
	if w.dropIn(t) != "" {
		t.Fatal("the drop-in is still there")
	}
}

// TestReload_RealSocketActivatedSSHD runs a REAL sshd under real socket
// activation with Accept=no (systemd-socket-activate hands it the listening
// socket, as ssh.socket does on Ubuntu 22.10+), unprivileged. Only the unit
// bookkeeping is a stand-in: a systemctl that reports ssh.socket active while
// the activator runs, ssh.service active once sshd has taken over, and
// reloads it with SIGHUP as ssh.service's ExecReload does.
//
//   - Listener running: a configuration change is not read by it (the B3
//     failure, reproduced), and after lv_fence_ssh_reload it is.
//   - Listener not started yet: no reload, and the first connection reads the
//     new configuration.
func TestReload_RealSocketActivatedSSHD(t *testing.T) {
	need := func(format string, args ...any) {
		t.Helper()
		if os.Getenv("LITEVIRT_REQUIRE_SSHD") == "1" {
			t.Fatalf("LITEVIRT_REQUIRE_SSHD=1: "+format, args...)
		}
		t.Skipf(format+" (set LITEVIRT_REQUIRE_SSHD=1 to fail instead)", args...)
	}
	if _, err := os.Stat(SSHDPath()); err != nil {
		need("no sshd at %s", SSHDPath())
	}
	activate, err := exec.LookPath("systemd-socket-activate")
	if err != nil {
		need("no systemd-socket-activate on PATH")
	}
	for _, b := range []string{"ssh", "ssh-keygen"} {
		if _, err := exec.LookPath(b); err != nil {
			need("no %s on PATH", b)
		}
	}

	for _, started := range []bool{true, false} {
		name := "listener not started"
		if started {
			name = "listener running"
		}
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for _, k := range []string{"hk", "uk"} {
				if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", filepath.Join(dir, k)).CombinedOutput(); err != nil {
					t.Fatalf("ssh-keygen: %v %s", err, out)
				}
			}
			inc := filepath.Join(dir, "inc")
			if err := os.MkdirAll(inc, 0o755); err != nil {
				t.Fatal(err)
			}
			l, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			port := l.Addr().(*net.TCPAddr).Port
			l.Close()
			cfg := filepath.Join(dir, "sshd_config")
			if err := os.WriteFile(cfg, []byte(fmt.Sprintf(`Include %s/*.conf
HostKey %s
PidFile none
UsePAM no
StrictModes no
AuthorizedKeysFile none
PasswordAuthentication no
KbdInteractiveAuthentication no
LogLevel VERBOSE
`, inc, filepath.Join(dir, "hk"))), 0o600); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "sshd.log")
			logf, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			act := exec.Command(activate, "-l", fmt.Sprintf("127.0.0.1:%d", port), SSHDPath(), "-D", "-e", "-f", cfg)
			act.Stdout, act.Stderr = logf, logf
			if err := act.Start(); err != nil {
				need("systemd-socket-activate will not start: %v", err)
			}
			t.Cleanup(func() {
				_ = act.Process.Kill()
				_ = act.Wait()
				logf.Close()
				if t.Failed() {
					raw, _ := os.ReadFile(logPath)
					t.Logf("sshd log:\n%s", raw)
				}
			})
			pid := act.Process.Pid

			bin := t.TempDir()
			calls := filepath.Join(bin, "calls")
			if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(fmt.Sprintf(`#!/bin/sh
echo "$*" >> %q
u=
for a; do case "$a" in -*) ;; *) u="$a" ;; esac; done
comm="$(cat /proc/%d/comm 2>/dev/null)"
case "$1:$u" in
is-active:ssh.socket) if [ -n "$comm" ]; then echo active; exit 0; fi ;;
is-active:ssh.service|is-active:ssh) if [ "$comm" = sshd ]; then echo active; exit 0; fi ;;
reload:ssh.service|reload:ssh) if [ "$comm" = sshd ]; then kill -HUP %d; exit $?; fi; exit 1 ;;
esac
echo inactive
exit 3
`, calls, pid, pid)), 0o755); err != nil {
				t.Fatal(err)
			}

			login := func() error {
				out, err := exec.Command("ssh", "-F", "/dev/null", "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
					"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10",
					"-i", filepath.Join(dir, "uk"), "-p", fmt.Sprint(port), "127.0.0.1", "echo", "logged-in").CombinedOutput()
				if err == nil && !strings.Contains(string(out), "logged-in") {
					err = fmt.Errorf("no output")
				}
				if err != nil {
					return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
				}
				return nil
			}

			if started {
				// The first connection starts the listener, on a
				// configuration that accepts no key.
				if err := login(); err == nil {
					t.Fatal("logged in before any key was configured")
				}
				waitComm(t, pid, "sshd")
			}
			if err := os.WriteFile(filepath.Join(inc, "60-test.conf"),
				[]byte("AuthorizedKeysFile "+filepath.Join(dir, "uk.pub")+"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if started {
				if err := login(); err == nil {
					t.Fatal("the running socket-activated sshd read a configuration change without a reload: " +
						"this test no longer reproduces bug B3")
				}
			}

			out, err := runReload(t, bin, "FENCE_SSH_SSHD="+SSHDPath(), "FENCE_SSH_SSHD_CONFIG="+cfg)
			if err != nil {
				raw, _ := os.ReadFile(calls)
				t.Fatalf("reload: %v\noutput %q\ncalls:\n%s", err, out, raw)
			}
			raw, _ := os.ReadFile(calls)
			if reloaded := strings.Contains(string(raw), "reload "); reloaded != started {
				t.Fatalf("reloaded = %v with the listener running = %v; calls:\n%s", reloaded, started, raw)
			}
			// sshd re-executes itself on SIGHUP; the listening socket is the
			// activator's and stays open, so a connection waits for it.
			if err := login(); err != nil {
				t.Fatalf("the managed key is not accepted after lv_fence_ssh_reload: %v", err)
			}
		})
	}
}

// waitComm waits for pid's command name to become comm (the activator execs
// sshd on the first connection).
func waitComm(t *testing.T, pid int, comm string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
		if strings.TrimSpace(string(raw)) == comm {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("pid %d is %q, not %s", pid, strings.TrimSpace(string(raw)), comm)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
