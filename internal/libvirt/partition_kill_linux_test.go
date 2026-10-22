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
