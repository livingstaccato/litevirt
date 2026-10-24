package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Restoring the old subshell leaves a capable parent holding fd9 after the
// helper yields. Both PID replacement and actual independent flock detect it.
func TestEnrollmentOwningShellExecHasNoParentCustodian(t *testing.T) {
	root := filepath.Join(t.TempDir(), "root ' quoted")
	r := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "pki")}
	marker := "node-1 12 1700000000 abcdef installing"
	m := machineClaim{r: r, mine: marker, settle: "/etc/litevirt/.settle-test"}
	if err := os.MkdirAll(filepath.Dir(r.Path(addInstalledMarker)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(r.Path(addInstalledMarker), []byte(marker+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	helper := "/var/tmp/litevirt-enrollment.0123456789/litevirt"
	if err := os.MkdirAll(filepath.Dir(r.Path(helper)), 0700); err != nil {
		t.Fatal(err)
	}
	script := "#!/bin/sh\n[ \"$1\" = host-enroll ] || exit 2\nprintf '%s\\n' \"$$\"\nexec 9>&-\nprintf 'CLOSED\\n'\nread -r done\n"
	if err := os.WriteFile(r.Path(helper), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	command, err := m.enrollmentExecCmd(helper)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, "/bin/sh", "-c", command)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	child.Stderr = &stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		stdin.Close()
		if !waited {
			err := child.Wait()
			t.Logf("launcher pid=%d cleanup Wait=%v stderr=%s", child.Process.Pid, err, stderr.String())
		}
	})
	scan := bufio.NewScanner(stdout)
	if !scan.Scan() {
		t.Fatal("helper did not report pid")
	}
	pid, err := strconv.Atoi(scan.Text())
	if err != nil {
		t.Fatal(err)
	}
	if !scan.Scan() || scan.Text() != "CLOSED" {
		t.Fatal("helper did not acknowledge yield")
	}
	contender := exec.CommandContext(ctx, "flock", "-n", r.Path(addLock), "true")
	out, contendErr := contender.CombinedOutput()
	t.Logf("shell pid=%d helper pid=%d contender pid=%d Wait=%v output=%s", child.Process.Pid, pid, contender.Process.Pid, contendErr, out)
	if contendErr == nil {
		// A real successor takes the yielded claim while the original helper is
		// still alive. Reusing this original guarded command must not execute it.
		successor := machineClaim{r: r, mine: "node-1 12 1700000001 successor installing", settle: m.settle}
		if err := successor.take(m.mine); err != nil {
			t.Fatal("successor could not reacquire yielded claim", err)
		}
		stale := exec.CommandContext(ctx, "/bin/sh", "-c", command)
		out, err := stale.CombinedOutput()
		t.Logf("stale launcher pid=%d Wait=%v output=%s", stale.Process.Pid, err, out)
		if exitStatus(err) != notOurMachine {
			t.Fatalf("stale launch crossed actual yield/reacquisition: %v %s", err, out)
		}
	}
	fmt.Fprintln(stdin, "done")
	err = child.Wait()
	waited = true
	if err != nil {
		t.Fatalf("launcher Wait=%v stderr=%s", err, stderr.String())
	}
	if pid != child.Process.Pid {
		t.Errorf("helper pid=%d leaves parent custodian pid=%d", pid, child.Process.Pid)
	}
	if contendErr != nil {
		t.Errorf("yielded helper still has parent-held claim: %v %s", contendErr, strings.TrimSpace(string(out)))
	}
}

func TestEnrollmentOwningShellExecRechecksClaim(t *testing.T) {
	root := t.TempDir()
	r := &LocalAddTarget{Root: root, PKIDir: filepath.Join(root, "pki")}
	m := machineClaim{r: r, mine: "node-1 12 1700000000 abcdef installing", settle: "/etc/litevirt/.settle-test"}
	helper := "/var/tmp/litevirt-enrollment.0123456789/litevirt"
	for _, bad := range []string{"", "/bin/true", helper + ";touch /tmp/escape", helper + "/..", "/var/tmp/litevirt-enrollment.x/litevirt", "/var/tmp/litevirt-enrollment.012345678'/litevirt"} {
		if _, err := m.enrollmentExecCmd(bad); err == nil {
			t.Fatalf("accepted executable outside staged family: %q", bad)
		}
	}
	if err := os.MkdirAll(filepath.Dir(r.Path(addInstalledMarker)), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(r.Path(helper)), 0700); err != nil {
		t.Fatal(err)
	}
	effect := filepath.Join(root, "effect")
	script := "#!/bin/sh\n[ \"$1\" = host-enroll ] || exit 2\nprintf yes > \"$ENROLLMENT_EFFECT\"\n"
	if err := os.WriteFile(r.Path(helper), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	command, err := m.enrollmentExecCmd(helper)
	if err != nil {
		t.Fatal(err)
	}
	run := func(want int) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "/bin/sh", "-c", command)
		cmd.Env = append(os.Environ(), "ENROLLMENT_EFFECT="+effect)
		out, err := cmd.CombinedOutput()
		got := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				got = e.ExitCode()
			} else {
				t.Fatal(err)
			}
		}
		t.Logf("claim shell pid=%d Wait=%v", cmd.Process.Pid, err)
		if got != want {
			t.Fatalf("exit=%d want=%d: %s", got, want, out)
		}
	}
	for _, state := range []string{"missing", "different", "settled", "reacquired-different", "owned"} {
		t.Run(state, func(t *testing.T) {
			os.Remove(effect)
			os.Remove(r.Path(m.settle))
			os.Remove(r.Path(addInstalledMarker))
			marker := m.mine
			if state == "different" || state == "reacquired-different" {
				marker = "node-1 12 1700000000 successor installing"
			}
			if state != "missing" {
				if err := os.WriteFile(r.Path(addInstalledMarker), []byte(marker+"\n"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if state == "settled" {
				if err := os.WriteFile(r.Path(m.settle), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if state == "owned" {
				run(0)
				if b, err := os.ReadFile(effect); err != nil || string(b) != "yes" {
					t.Fatal("owned helper not executed", err)
				}
			} else {
				run(notOurMachine)
				if _, err := os.Stat(effect); !os.IsNotExist(err) {
					t.Fatal("stale claim executed capable helper")
				}
			}
		})
	}
}
