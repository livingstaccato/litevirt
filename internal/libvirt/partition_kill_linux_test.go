package libvirt

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const killTestUUID = "6f1c0d2e-3b4a-4c5d-8e9f-0a1b2c3d4e5f"

// fakeQEMU starts a real process whose command line carries a QEMU's
// identifying arguments for domain name, and writes its pid where libvirt
// would. The process is reaped in cleanup whatever happens to it.
func fakeQEMU(t *testing.T, runDir, name, uuid string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sh", "-c", "sleep 600; :", "qemu-system-x86_64",
		"-name", "guest="+name+",debug-threads=on", "-uuid", uuid)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _, _ = cmd.Process.Wait() })
	if err := os.WriteFile(filepath.Join(runDir, name+".pid"), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return cmd
}

// exitedBySIGKILL waits for cmd and reports whether SIGKILL ended it.
func exitedBySIGKILL(t *testing.T, cmd *exec.Cmd) bool {
	t.Helper()
	done := make(chan *os.ProcessState, 1)
	go func() { st, _ := cmd.Process.Wait(); done <- st }()
	select {
	case st := <-done:
		ws, ok := st.Sys().(syscall.WaitStatus)
		return ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL
	case <-time.After(5 * time.Second):
		return false
	}
}

// The partition pauser's kill reaches the domain's QEMU by libvirt's pid
// file and its own command line, with no libvirt call, and kills it.
func TestKillQEMU_KillsTheDomainsQEMU(t *testing.T) {
	for _, tc := range []struct{ name, uuid string }{
		{"by uuid", killTestUUID},
		{"by name, no recorded uuid", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runDir := t.TempDir()
			cmd := fakeQEMU(t, runDir, "vm-a", killTestUUID)
			if err := killQEMU(runDir, "/proc", "vm-a", tc.uuid); err != nil {
				t.Fatalf("killQEMU: %v", err)
			}
			if !exitedBySIGKILL(t, cmd) {
				t.Fatal("the domain's QEMU was not killed")
			}
			// Gone now: a second kill finds nothing to land on, which is success.
			if err := killQEMU(runDir, "/proc", "vm-a", tc.uuid); err != nil {
				t.Fatalf("killQEMU of an exited QEMU: %v", err)
			}
		})
	}
}

// A pid file that names another domain's process (stale, or a reused pid),
// or no pid file at all, kills nothing and is an error: the pauser then
// reports the pause failed rather than trusting it.
func TestKillQEMU_RefusesAnyOtherProcess(t *testing.T) {
	runDir := t.TempDir()
	cmd := fakeQEMU(t, runDir, "vm-b", killTestUUID)
	// vm-a's pid file names vm-b's process.
	b, _ := os.ReadFile(filepath.Join(runDir, "vm-b.pid"))
	if err := os.WriteFile(filepath.Join(runDir, "vm-a.pid"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := killQEMU(runDir, "/proc", "vm-a", "00000000-0000-4000-8000-000000000000"); err == nil || !strings.Contains(err.Error(), "not its QEMU") {
		t.Fatalf("kill by another uuid: err = %v, want a refusal", err)
	}
	if err := killQEMU(runDir, "/proc", "vm-a", ""); err == nil || !strings.Contains(err.Error(), "not its QEMU") {
		t.Fatalf("kill by another name: err = %v, want a refusal", err)
	}
	if err := killQEMU(runDir, "/proc", "vm-c", killTestUUID); err == nil {
		t.Fatal("kill with no pid file succeeded")
	}
	if err := cmd.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatalf("vm-b's process was hit: %v", err)
	}
}

// A QEMU killed while its disks' writeback pages cannot be flushed (its
// storage cut along with the voters) does not exit: it sits in an
// uninterruptible wait with those pages in this host's page cache, and they
// land on the replacement's disk once the storage returns. A queued SIGKILL
// is therefore not a stop: the kill succeeds only once the process has
// exited, and is an error otherwise, so the pauser falls back to reporting
// the pause failed and self-fencing (re-review 5, finding 1). A process
// that will not exit cannot be made in a test, so the wait stands in for
// one that never sees the exit.
//
// Red on 9850aa45a (success once the signal was queued). Mutation: return
// nil once the signal is queued — red.
func TestKillQEMU_FailsUntilTheQEMUHasExited(t *testing.T) {
	old := waitPidfdExit
	var waited time.Duration
	waitPidfdExit = func(_ int, d time.Duration) (bool, error) { waited = d; return false, nil }
	t.Cleanup(func() { waitPidfdExit = old })

	runDir := t.TempDir()
	cmd := fakeQEMU(t, runDir, "vm-a", killTestUUID)
	err := killQEMU(runDir, "/proc", "vm-a", killTestUUID)
	if err == nil || !strings.Contains(err.Error(), "has not exited") {
		t.Fatalf("kill of a QEMU that has not exited: err = %v, want an error", err)
	}
	if waited <= 0 || waited >= 2*time.Second {
		t.Fatalf("waited %s for the exit, want inside the pauser's 2s call timeout", waited)
	}
	// The signal was still sent: the process dies when it can.
	if !exitedBySIGKILL(t, cmd) {
		t.Fatal("the domain's QEMU was not sent SIGKILL")
	}
}

// The real wait sees a real exit: once the kill returns, the process has
// exited (a zombie, since this test is its unreaped parent).
func TestKillQEMU_ReturnsOnceTheQEMUHasExited(t *testing.T) {
	runDir := t.TempDir()
	cmd := fakeQEMU(t, runDir, "vm-a", killTestUUID)
	if err := killQEMU(runDir, "/proc", "vm-a", killTestUUID); err != nil {
		t.Fatalf("killQEMU: %v", err)
	}
	stat, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "stat"))
	if err != nil {
		t.Fatal(err)
	}
	if i := strings.LastIndexByte(string(stat), ')'); i < 0 || i+2 >= len(stat) || stat[i+2] != 'Z' {
		t.Fatalf("the QEMU has not exited when the kill returned: stat %q", stat)
	}
}
