package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/cli"
	"golang.org/x/sys/unix"
)

var diagnosticCLIBinary = flag.String("diagnostics-cli", "", "sealed CLI binary for actual private relay dispatch")

// An unknown-command exit or loss of fd4 data fails this test. This executes
// the built CLI main, not the test binary's helper fixture.
func TestEnrollmentDiagnosticsActualCLI(t *testing.T) {
	if *diagnosticCLIBinary == "" {
		t.Skip("requires sealed actual CLI binary")
	}
	for _, malformed := range []bool{false, true} {
		t.Run(map[bool]string{false: "relay", true: "malformed"}[malformed], func(t *testing.T) {
			output, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
			if err != nil {
				t.Fatal(err)
			}
			defer output.Close()
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			writer := os.NewFile(uintptr(pair[0]), "producer")
			defer writer.Close()
			reader := os.NewFile(uintptr(pair[1]), "consumer")
			defer reader.Close()
			args := []string{cli.EnrollmentDiagnosticsRelayArg}
			if malformed {
				args = append(args, "unexpected")
			}
			cmd := exec.Command(*diagnosticCLIBinary, args...)
			cmd.ExtraFiles = []*os.File{output, reader}
			cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			reader.Close()
			if !malformed {
				want, err := os.Stat(*diagnosticCLIBinary)
				if err != nil {
					t.Fatal(err)
				}
				actual, err := os.Stat(fmt.Sprintf("/proc/%d/exe", cmd.Process.Pid))
				if err != nil || !os.SameFile(want, actual) {
					t.Fatalf("actual CLI image changed: %v", err)
				}
			}
			if !malformed {
				if _, err := writer.Write([]byte("actual-cli-tail")); err != nil {
					t.Fatal(err)
				}
			}
			writer.Close()
			waited := make(chan error, 1)
			go func() { waited <- cmd.Wait() }()
			select {
			case err := <-waited:
				if !malformed && err != nil {
					t.Fatalf("private CLI relay failed: %v", err)
				}
				if malformed && err == nil {
					t.Fatal("malformed invocation succeeded")
				}
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				<-waited
				t.Fatal("actual CLI relay did not join")
			}
			body, err := os.ReadFile(output.Name())
			if err != nil {
				t.Fatal(err)
			}
			want := []byte("actual-cli-tail")
			if malformed {
				want = nil
			}
			if !bytes.Equal(body, want) {
				t.Fatalf("actual CLI output %q, want %q", body, want)
			}
		})
	}
}
