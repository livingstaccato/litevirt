package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	enrollmentssh "github.com/litevirt/litevirt/internal/ssh"
	cryptossh "golang.org/x/crypto/ssh"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEnrollmentDiagnosticsRelayProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_TEST_DIAGNOSTIC_RELAY") != "1" {
		return
	}
	os.Exit(RunEnrollmentDiagnosticsRelay())
}

func startDiagnosticTest(t *testing.T, ctx context.Context, destination *os.File) *enrollmentCLIDiagnostics {
	t.Helper()
	t.Setenv("LITEVIRT_TEST_DIAGNOSTIC_RELAY", "1")
	d, err := newEnrollmentCLIDiagnosticsArgs(ctx, destination, []string{"-test.run=^TestEnrollmentDiagnosticsRelayProcess$"})
	if err != nil {
		t.Fatalf("admit actual stderr: %v", err)
	}
	t.Cleanup(func() { _ = d.Finish(context.Canceled, time.Now().Add(5*time.Second)) })
	return d
}

// Reopening the destination, seeking it, losing queued bytes or closing the
// borrowed handle breaks these exact offset and append observations.
func TestEnrollmentDiagnosticsRegularFile(t *testing.T) {
	for _, appendMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "offset", true: "append"}[appendMode], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "stderr")
			if err := os.WriteFile(path, []byte("prefix-0123456789"), 0600); err != nil {
				t.Fatal(err)
			}
			flags := os.O_RDWR
			if appendMode {
				flags |= os.O_APPEND
			}
			f, err := os.OpenFile(path, flags, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			if _, err := f.Seek(7, 0); err != nil {
				t.Fatal(err)
			}
			d := startDiagnosticTest(t, context.Background(), f)
			if _, err := d.Diagnostics().Write([]byte("relay-tail")); err != nil {
				t.Fatal(err)
			}
			if err := d.Finish(nil, time.Now().Add(5*time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write([]byte("!")); err != nil {
				t.Fatalf("borrowed stderr closed: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := "prefix-relay-tail!"
			if appendMode {
				want = "prefix-0123456789relay-tail!"
			}
			if string(got) != want {
				t.Fatalf("output %q, want %q", got, want)
			}
			pos, err := f.Seek(0, 1)
			if err != nil || pos != int64(len(want)) {
				t.Fatalf("shared offset %d: %v", pos, err)
			}
		})
	}
}

func diagnosticRaw(t *testing.T, f *os.File) int {
	t.Helper()
	raw, err := f.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	fd := -1
	if err := raw.Control(func(n uintptr) { fd = int(n) }); err != nil {
		t.Fatal(err)
	}
	return fd
}
func diagnosticFlags(t *testing.T, f *os.File) int {
	t.Helper()
	flags, err := unix.FcntlInt(uintptr(diagnosticRaw(t, f)), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	return flags
}

func diagnosticOutput(t *testing.T, kind string, nonblock bool) (*os.File, io.ReadCloser) {
	t.Helper()
	var f *os.File
	var peer io.ReadCloser
	switch kind {
	case "pipe":
		pair := make([]int, 2)
		if err := unix.Pipe2(pair, unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		peer = os.NewFile(uintptr(pair[0]), "reader")
		f = os.NewFile(uintptr(pair[1]), "stderr")
		if _, err := unix.FcntlInt(uintptr(pair[1]), unix.F_SETPIPE_SZ, 4096); err != nil {
			t.Fatal(err)
		}
	case "unix":
		pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
			t.Fatal(err)
		}
		f = os.NewFile(uintptr(pair[0]), "stderr")
		peer = os.NewFile(uintptr(pair[1]), "reader")
	case "tcp":
		listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		client, err := net.DialTCP("tcp4", nil, listener.Addr().(*net.TCPAddr))
		if err != nil {
			t.Fatal(err)
		}
		receiver, err := listener.AcceptTCP()
		if err != nil {
			client.Close()
			t.Fatal(err)
		}
		peer = receiver
		if err := client.SetWriteBuffer(4096); err != nil {
			t.Fatal(err)
		}
		if err := receiver.SetReadBuffer(4096); err != nil {
			t.Fatal(err)
		}
		f, err = client.File()
		client.Close()
		if err != nil {
			t.Fatal(err)
		}
	case "pty", "stopped-pty", "foreground-pty":
		master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		peer = os.NewFile(uintptr(master), "pty-master")
		if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
			peer.Close()
			t.Fatal(err)
		}
		number, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
		if err != nil {
			peer.Close()
			t.Fatal(err)
		}
		access := unix.O_WRONLY
		if kind == "foreground-pty" {
			access = unix.O_RDWR
		}
		slave, err := unix.Open(fmt.Sprintf("/dev/pts/%d", number), access|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			peer.Close()
			t.Fatal(err)
		}
		f = os.NewFile(uintptr(slave), "pty-stderr")
		if kind == "stopped-pty" {
			if err := unix.IoctlSetInt(slave, unix.TCXONC, unix.TCOOFF); err != nil {
				f.Close()
				peer.Close()
				t.Fatal(err)
			}
		}
	default:
		t.Fatal("unknown fixture")
	}
	if err := unix.SetNonblock(diagnosticRaw(t, f), nonblock); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close(); peer.Close() })
	return f, peer
}

// Observe the actual helper write/poll syscall, not elapsed time or a fake
// started message. Go can execute the copier on any runtime thread.
func waitDiagnosticBlocked(t *testing.T, pid int, nonblock bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var last string
	for time.Now().Before(deadline) {
		threads, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/syscall", pid))
		for _, p := range threads {
			b, readErr := os.ReadFile(p)
			last = fmt.Sprintf("%s: %q error=%v", p, b, readErr)
			fields := strings.Fields(string(b))
			if len(fields) < 2 {
				continue
			}
			number, _ := strconv.Atoi(fields[0])
			if (!nonblock && number == unix.SYS_WRITE && fields[1] == "0x3") || (nonblock && number == unix.SYS_PPOLL) {
				t.Logf("actual relay PID%d blocked syscall: %s", pid, strings.TrimSpace(string(b)))
				return
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("relay never reached actual blocked output syscall; last observation %s", last)
}

func finishDiagnosticBounded(t *testing.T, d *enrollmentCLIDiagnostics, err error, deadline time.Time) error {
	t.Helper()
	result := make(chan error, 1)
	go func() { result <- d.Finish(err, deadline) }()
	select {
	case err := <-result:
		if killErr := unix.Kill(d.pid, 0); !errors.Is(killErr, unix.ESRCH) {
			t.Errorf("relay not physically reaped: %v", killErr)
		}
		return err
	case <-time.After(4 * time.Second):
		// Rescue belongs only to the failing fixture. It cannot make cancellation
		// pass, and we still join the original Finish and writer before returning.
		t.Error("relay failed actual cancellation/drain deadline")
		_ = unix.Kill(d.pid, unix.SIGKILL)
		return <-result
	}
}

func TestEnrollmentDiagnosticsBlockedOutput(t *testing.T) {
	for _, kind := range []string{"pipe", "unix", "tcp", "pty", "stopped-pty"} {
		for _, nonblock := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nonblock=%v", kind, nonblock), func(t *testing.T) {
				destination, _ := diagnosticOutput(t, kind, nonblock)
				flags := diagnosticFlags(t, destination)
				var descriptor unix.Stat_t
				if err := unix.Fstat(diagnosticRaw(t, destination), &descriptor); err != nil {
					t.Fatal(err)
				}
				t.Logf("destination inode=%d pid=%d fd=%d", descriptor.Ino, os.Getpid(), diagnosticRaw(t, destination))
				closeExec, err := unix.FcntlInt(uintptr(diagnosticRaw(t, destination)), unix.F_GETFD, 0)
				if err != nil {
					t.Fatal(err)
				}
				var termios *unix.Termios
				if strings.Contains(kind, "pty") {
					termios, _ = unix.IoctlGetTermios(diagnosticRaw(t, destination), unix.TCGETS)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				d := startDiagnosticTest(t, ctx, destination)
				written := make(chan error, 1)
				go func() { _, err := d.Diagnostics().Write(bytes.Repeat([]byte("x"), 4<<20)); written <- err }()
				t.Cleanup(func() { cancel(); _ = d.Finish(context.Canceled, time.Now().Add(5*time.Second)); <-written })
				waitDiagnosticBlocked(t, d.pid, nonblock)
				if got := diagnosticFlags(t, destination); got != flags {
					t.Fatalf("caller flags changed while blocked: %x -> %x", flags, got)
				}
				cancel()
				if err := finishDiagnosticBounded(t, d, nil, time.Now().Add(5*time.Second)); err == nil {
					t.Fatal("cancellation claimed success")
				}
				if got := diagnosticFlags(t, destination); got != flags {
					t.Errorf("caller flags changed after cancellation: %x -> %x", flags, got)
				}
				if termios != nil {
					after, err := unix.IoctlGetTermios(diagnosticRaw(t, destination), unix.TCGETS)
					if err != nil || *after != *termios {
						t.Errorf("terminal state changed: %v", err)
					}
				}
				afterCloseExec, err := unix.FcntlInt(uintptr(diagnosticRaw(t, destination)), unix.F_GETFD, 0)
				if err != nil || afterCloseExec != closeExec {
					t.Errorf("borrowed CLOEXEC changed: %v", err)
				}
				if _, err := destination.Stat(); err != nil {
					t.Errorf("borrowed descriptor lost: %v", err)
				}
			})
		}
	}
}

func TestEnrollmentDiagnosticsDrainAndLateError(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken=%v", broken), func(t *testing.T) {
			destination, peer := diagnosticOutput(t, "pipe", false)
			d := startDiagnosticTest(t, context.Background(), destination)
			payload := append(bytes.Repeat([]byte("d"), 64<<10), []byte("last-diagnostic-byte")...)
			if _, err := d.Diagnostics().Write(payload); err != nil {
				t.Fatal(err)
			}
			waitDiagnosticBlocked(t, d.pid, false)
			finished := make(chan error, 1)
			go func() { finished <- d.Finish(nil, time.Now().Add(5*time.Second)) }()
			select {
			case err := <-finished:
				t.Fatalf("returned before output drain: %v", err)
			case <-time.After(30 * time.Millisecond):
			}
			if broken {
				peer.Close()
				if err := <-finished; err == nil {
					t.Fatal("late diagnostic failure became local success")
				}
			} else {
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(peer, got); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, payload) {
					t.Fatal("diagnostic tail lost")
				}
				if err := <-finished; err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestEnrollmentDiagnosticsOriginalAndCleanupBudgets(t *testing.T) {
	for _, mode := range []string{"original", "cleanup"} {
		t.Run(mode, func(t *testing.T) {
			destination, _ := diagnosticOutput(t, "pipe", false)
			ctx := context.Background()
			cancel := func() {}
			if mode == "original" {
				ctx, cancel = context.WithTimeout(ctx, 800*time.Millisecond)
			}
			defer cancel()
			original, _ := ctx.Deadline()
			d := startDiagnosticTest(t, ctx, destination)
			if mode == "original" {
				actual, _ := d.Context().Deadline()
				if !actual.Equal(original) {
					t.Fatal("original attempt deadline renewed")
				}
			}
			if _, err := d.Diagnostics().Write(bytes.Repeat([]byte("x"), 64<<10)); err != nil {
				t.Fatal(err)
			}
			waitDiagnosticBlocked(t, d.pid, false)
			end := time.Now().Add(5 * time.Second)
			if mode == "cleanup" {
				end = time.Now().Add(1200 * time.Millisecond)
			}
			start := time.Now()
			if err := finishDiagnosticBounded(t, d, nil, end); err == nil {
				t.Fatal("incomplete diagnostics succeeded")
			}
			if time.Since(start) > 1500*time.Millisecond {
				t.Fatal("remaining budget was renewed")
			}
		})
	}
}

func TestEnrollmentDiagnosticsAdmissionAndUnlinkedFile(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	if d, err := newEnrollmentCLIDiagnostics(ctx, null); err == nil || d != nil {
		t.Fatal("cancelled constructor launched")
	}
	if d, err := newEnrollmentCLIDiagnostics(nil, null); err == nil || d != nil {
		t.Fatal("nil context admitted")
	}
	if d, err := newEnrollmentCLIDiagnostics(context.Background(), nil); err == nil || d != nil {
		t.Fatal("nil stderr admitted")
	}
	readonly, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	if d, err := newEnrollmentCLIDiagnostics(context.Background(), readonly); err == nil || d != nil {
		t.Fatal("read-only stderr admitted")
	}
	d := startDiagnosticTest(t, context.Background(), null)
	if _, err := d.Diagnostics().Write([]byte("discard")); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish(nil, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "unlinked")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	d = startDiagnosticTest(t, context.Background(), f)
	if _, err := d.Diagnostics().Write([]byte("kept-open")); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish(nil, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil || string(got) != "kept-open" {
		t.Fatalf("unlinked output %q: %v", got, err)
	}
}

func TestEnrollmentDiagnosticsParentProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_TEST_DIAGNOSTIC_PARENT") != "1" {
		return
	}
	destination := os.NewFile(3, "parent-stderr")
	link, _ := os.Readlink("/proc/self/fd/3")
	fmt.Fprintf(os.Stderr, "OWNER fd3=%s\n", link)
	report := os.NewFile(4, "parent-report")
	gate := os.NewFile(5, "parent-gate")
	unix.CloseOnExec(4)
	unix.CloseOnExec(5) // fixture-owned control FDs, not relay rights
	defer destination.Close()
	defer report.Close()
	defer gate.Close()
	if _, err := fmt.Fprintln(report, os.Getpid()); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if _, err := io.ReadFull(gate, one[:]); err != nil {
		t.Fatal(err)
	}
	d := startDiagnosticTest(t, context.Background(), destination)
	// Queue acceptance does not mean destination drain: this host may have a
	// 64 MiB socket send buffer. Keep the owner alive after a finite producer write.
	wrote := make(chan error, 1)
	go func() { _, err := d.Diagnostics().Write(bytes.Repeat([]byte("orphan"), 1<<20)); wrote <- err }()
	defer func() { _ = d.Finish(context.Canceled, time.Now().Add(5*time.Second)); <-wrote }()
	for i := 0; i < 5; i++ {
		runtime.GC()
		runtime.Gosched()
	}
	waitDiagnosticBlocked(t, d.pid, false)
	flags := diagnosticFlags(t, destination)
	if flags&unix.O_ACCMODE != unix.O_WRONLY {
		t.Fatalf("owner destination mode %x", flags)
	}
	if _, err := fmt.Fprintln(report, d.pid); err != nil {
		t.Fatal(err)
	}
	select {} // observer must kill this actual owner, not manufacture an EOF

}

func TestEnrollmentDiagnosticsOrphanObserver(t *testing.T) {
	if os.Getenv("LITEVIRT_TEST_DIAGNOSTIC_OBSERVER") != "1" {
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
		t.Fatal(err)
	}
	destination, retainedReader := diagnosticOutput(t, "pipe", false)
	defer runtime.KeepAlive(retainedReader)
	reportR, reportW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reportR.Close()
	defer reportW.Close()
	gateR, gateW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer gateR.Close()
	defer gateW.Close()
	image := filepath.Join(t.TempDir(), "copied-owner")
	original, err := os.Open("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	copy, err := os.OpenFile(image, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0700)
	if err != nil {
		original.Close()
		t.Fatal(err)
	}
	_, err = io.Copy(copy, original)
	original.Close()
	copy.Close()
	if err != nil {
		t.Fatal(err)
	}
	identity, err := os.Stat(image)
	if err != nil {
		t.Fatal(err)
	}
	owner := exec.Command(image, "-test.run=^TestEnrollmentDiagnosticsParentProcess$")
	owner.Env = append(os.Environ(), "LITEVIRT_TEST_DIAGNOSTIC_PARENT=1")
	owner.Stdout = os.Stdout
	owner.Stderr = os.Stderr
	owner.ExtraFiles = []*os.File{destination, reportW, gateR}
	owner.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := owner.Start(); err != nil {
		t.Fatal(err)
	}
	relayPID := 0
	reaped := false
	defer func() {
		if !reaped {
			_ = owner.Process.Kill()
			_ = owner.Wait()
			if relayPID > 0 {
				_ = unix.Kill(relayPID, unix.SIGKILL)
				_, _ = unix.Wait4(relayPID, nil, 0, nil)
			}
		}
	}()
	reportW.Close()
	gateR.Close()
	var ownerPID int
	if _, err := fmt.Fscanln(reportR, &ownerPID); err != nil {
		t.Fatal(err)
	}
	if ownerPID != owner.Process.Pid {
		t.Fatal("wrong owner identity")
	}
	// Move its installed path before the owner creates the relay. Reopening the
	// old executable path fails; /proc/self/exe must still execute the same image.
	if err := os.Rename(image, image+".renamed"); err != nil {
		t.Fatal(err)
	}
	if _, err := gateW.Write([]byte{1}); err != nil {
		t.Fatal(err)
	}
	gateW.Close()
	if _, err := fmt.Fscanln(reportR, &relayPID); err != nil {
		t.Fatal(err)
	}
	destLink, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/3", relayPID))
	ownLink, _ := os.Readlink(fmt.Sprintf("/proc/%d/fd/3", ownerPID))
	t.Logf("ownerfd3=%s relayfd3=%s", ownLink, destLink)
	for _, pid := range []int{ownerPID, relayPID} {
		info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/3", pid))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("PID%d actual fd3 info: %s", pid, info)
	}
	relayImage, err := os.Stat(fmt.Sprintf("/proc/%d/exe", relayPID))
	if err != nil || !os.SameFile(identity, relayImage) {
		t.Fatalf("relay changed image identity: %v", err)
	}
	waitDiagnosticBlocked(t, relayPID, false)
	for _, path := range mustDiagnosticGlob(t, fmt.Sprintf("/proc/%d/fd/*", relayPID)) {
		fd, err := strconv.Atoi(filepath.Base(path))
		if err != nil {
			t.Fatal(err)
		}
		target, err := os.Readlink(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("relay explicit/runtime fd%d=%s", fd, target)
		if fd <= 2 && target != "/dev/null" {
			t.Fatalf("relay standard FD leak %d=%s", fd, target)
		}
		if fd > 4 && target != "anon_inode:[eventpoll]" && target != "anon_inode:[eventfd]" {
			// Go1.26 internal/runtime/cgroup.OpenCPU opens this exact own-cgroup
			// quota file O_RDONLY|O_CLOEXEC during runtime startup.
			group, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", relayPID))
			if err != nil {
				t.Fatal(err)
			}
			cpuPath := ""
			for _, line := range strings.Split(string(group), "\n") {
				if strings.HasPrefix(line, "0::") {
					cpuPath = filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(line, "0::"), "cpu.max")
				}
			}
			info, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", relayPID, fd))
			if err != nil {
				t.Fatal(err)
			}
			flags := uint64(0)
			for _, line := range strings.Split(string(info), "\n") {
				if strings.HasPrefix(line, "flags:") {
					flags, err = strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "flags:")), 8, 64)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			if target != cpuPath || flags&uint64(unix.O_ACCMODE|unix.O_CLOEXEC) != uint64(unix.O_CLOEXEC) {
				t.Fatalf("unexpected inherited relay right fd%d=%s flags=%o", fd, target, flags)
			}
		}
	}

	for _, p := range mustDiagnosticGlob(t, fmt.Sprintf("/proc/%d/task/*/children", relayPID)) {
		b, err := os.ReadFile(p)
		if err != nil || len(bytes.TrimSpace(b)) != 0 {
			t.Fatalf("relay has application descendant: %q %v", b, err)
		}
	}
	if err := owner.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Wait(); err == nil {
		t.Fatal("killed owner exited successfully")
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		var status unix.WaitStatus
		pid, err := unix.Wait4(relayPID, &status, unix.WNOHANG, nil)
		if err != nil {
			t.Fatal(err)
		}
		if pid == relayPID {
			reaped = true
			if !status.Signaled() || status.Signal() != unix.SIGKILL {
				t.Fatalf("relay exit was not parent-death SIGKILL: %v", status)
			}
			t.Logf("actual Wait owner%d and adopted relay%d SIGKILL; same renamed image", ownerPID, relayPID)
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("parent death did not physically terminate relay")
}

func mustDiagnosticGlob(t *testing.T, pattern string) []string {
	t.Helper()
	paths, err := filepath.Glob(pattern)
	if err != nil || len(paths) == 0 {
		t.Fatalf("inspect actual process: %v", err)
	}
	return paths
}

func TestEnrollmentDiagnosticsParentDeath(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestEnrollmentDiagnosticsOrphanObserver$", "-test.v")
	cmd.Env = append(os.Environ(), "LITEVIRT_TEST_DIAGNOSTIC_OBSERVER=1")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("actual orphan observer: %v\n%s", err, output)
	}
	if !bytes.Contains(output, []byte("actual Wait owner")) {
		t.Fatalf("observer did not reap actual children: %s", output)
	}
	t.Log(string(output))
}

func TestEnrollmentDiagnosticsUnsupportedDescriptors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"closed", "path", "direct", "packet", "datagram", "seqpacket", "listener", "unconnected", "device"} {
		t.Run(kind, func(t *testing.T) {
			fd := -1
			var err error
			switch kind {
			case "closed", "path", "direct":
				flags := unix.O_WRONLY | unix.O_CLOEXEC
				if kind == "path" {
					flags = unix.O_PATH | unix.O_CLOEXEC
				}
				if kind == "direct" {
					flags |= unix.O_DIRECT
				}
				fd, err = unix.Open(path, flags, 0)
			case "packet":
				pair := make([]int, 2)
				err = unix.Pipe2(pair, unix.O_DIRECT|unix.O_CLOEXEC)
				if err == nil {
					defer unix.Close(pair[0])
					fd = pair[1]
				}
			case "datagram", "seqpacket":
				typ := unix.SOCK_DGRAM
				if kind == "seqpacket" {
					typ = unix.SOCK_SEQPACKET
				}
				var pair [2]int
				pair, err = unix.Socketpair(unix.AF_UNIX, typ|unix.SOCK_CLOEXEC, 0)
				if err == nil {
					defer unix.Close(pair[1])
					fd = pair[0]
				}
			case "listener", "unconnected":
				fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
				if err == nil && kind == "listener" {
					err = unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
					if err == nil {
						err = unix.Listen(fd, 1)
					}
				}
			case "device":
				fd, err = unix.Open("/dev/zero", unix.O_WRONLY|unix.O_CLOEXEC, 0)
			}
			if err != nil {
				if fd >= 0 {
					unix.Close(fd)
				}
				t.Fatalf("actual admission fixture: %v", err)
			}
			f := os.NewFile(uintptr(fd), kind)
			defer f.Close()
			if kind == "closed" {
				f.Close()
			}
			if d, err := newEnrollmentCLIDiagnostics(context.Background(), f); err == nil || d != nil {
				if d != nil {
					d.Finish(context.Canceled, time.Now().Add(5*time.Second))
				}
				t.Fatal("unsupported stderr admitted")
			}
		})
	}
}

func TestEnrollmentDiagnosticsExecFailureReleasesFDs(t *testing.T) {
	f, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	// Prime the runtime poller so its process-global descriptors are not mistaken
	// for per-attempt leaks; the first successful owner must be joined.
	d := startDiagnosticTest(t, context.Background(), f)
	if err := d.Finish(nil, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_TEST_EXEC_SIZE", strings.Repeat("x", 256<<10))
	for i := 0; i < 3; i++ {
		if d, err := newEnrollmentCLIDiagnostics(context.Background(), f); err == nil || d != nil {
			t.Fatal("oversized actual exec environment admitted")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("exec failure leaked descriptors: %d -> %d", len(before), len(after))
	}
	if _, err := f.Stat(); err != nil {
		t.Fatal("borrowed stderr closed on exec error")
	}
}

func TestEnrollmentDiagnosticsForegroundProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_TEST_DIAGNOSTIC_FOREGROUND") != "1" {
		return
	}
	f := os.NewFile(3, "controlling-tty")
	defer f.Close()
	d := startDiagnosticTest(t, context.Background(), f)
	if _, err := d.Diagnostics().Write([]byte("foreground")); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish(nil, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
}

func TestEnrollmentDiagnosticsForegroundTOSTOP(t *testing.T) {
	destination, peer := diagnosticOutput(t, "foreground-pty", false)
	attrs, err := unix.IoctlGetTermios(diagnosticRaw(t, destination), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	attrs.Lflag |= unix.TOSTOP
	if err := unix.IoctlSetTermios(diagnosticRaw(t, destination), unix.TCSETS, attrs); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 7*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/proc/self/exe", "-test.run=^TestEnrollmentDiagnosticsForegroundProcess$")
	cmd.Env = append(os.Environ(), "LITEVIRT_TEST_DIAGNOSTIC_FOREGROUND=1")
	cmd.ExtraFiles = []*os.File{destination}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 3, Pdeathsig: syscall.SIGKILL}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("foreground relay: %v: %s", err, output)
	}
	actual := make([]byte, len("foreground"))
	if _, err := io.ReadFull(peer, actual); err != nil {
		t.Fatal(err)
	}
	if string(actual) != "foreground" {
		t.Fatalf("foreground output %q", actual)
	}
}

func TestEnrollmentDiagnosticsExistingSSHRoute(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := cryptossh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemKey), 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	config := fmt.Sprintf("Host diagnostic-fixture\n HostName 127.0.0.1\n Port %d\n User diagnostic\n IdentityFile %s\n IdentitiesOnly yes\n IdentityAgent none\n UserKnownHostsFile %s/missing-pins\n GlobalKnownHostsFile none\n", port, keyPath, home)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	done := make(chan error, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		accepted <- raw
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(8 * time.Second))
		serverConfig := &cryptossh.ServerConfig{PublicKeyCallback: func(cryptossh.ConnMetadata, cryptossh.PublicKey) (*cryptossh.Permissions, error) { return nil, nil }}
		serverConfig.AddHostKey(signer)
		connection, channels, requests, err := cryptossh.NewServerConn(raw, serverConfig)
		if err != nil {
			done <- err
			return
		}
		requestDone := make(chan struct{})
		go func() { cryptossh.DiscardRequests(requests); close(requestDone) }()
		for pending := range channels {
			if pending.ChannelType() != "session" {
				pending.Reject(cryptossh.UnknownChannelType, "fixture")
				continue
			}
			ch, reqs, err := pending.Accept()
			if err != nil {
				connection.Close()
				<-requestDone
				done <- err
				return
			}
			for request := range reqs {
				if request.Type != "exec" {
					request.Reply(false, nil)
					continue
				}
				request.Reply(true, nil)
				_, err = io.WriteString(ch.Stderr(), "native-diagnostic-tail")
				if err == nil {
					_, err = ch.SendRequest("exit-status", false, cryptossh.Marshal(struct{ Status uint32 }{0}))
				}
				ch.Close()
				break
			}
			ch.Close()
		}
		connection.Close()
		<-requestDone
		done <- nil
	}()
	var client *enrollmentssh.EnrollmentClient
	t.Cleanup(func() {
		listener.Close()
		if client != nil {
			client.Close()
		}
		select {
		case raw := <-accepted:
			raw.Close()
		default:
		}
		if err := <-done; err != nil {
			t.Errorf("owned SSH fixture: %v", err)
		}
	})
	destination, err := os.Create(filepath.Join(t.TempDir(), "stderr"))
	if err != nil {
		t.Fatal(err)
	}
	defer destination.Close()
	d := startDiagnosticTest(t, context.Background(), destination)
	target, err := enrollmentssh.ResolveContext(d.Context(), "diagnostic-fixture", d.Diagnostics())
	if err != nil {
		t.Fatal(err)
	}
	client, err = enrollmentssh.NewEnrollmentClient(d.Context(), target, d.Diagnostics())
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Run(d.Context(), "fixture-command"); err != nil {
		t.Fatal(err)
	}
	cleanupDeadline := time.Now().Add(5 * time.Second)
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish(nil, cleanupDeadline); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(destination.Name())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"missing-pins", "host key not verified", "native-diagnostic-tail"} {
		if !bytes.Contains(body, []byte(want)) {
			t.Fatalf("existing warning/diagnostic missing %q: %s", want, body)
		}
	}
}

func TestEnrollmentDiagnosticsInheritedPipeWithoutReopenPermission(t *testing.T) {
	destination, peer := diagnosticOutput(t, "pipe", false)
	fd := diagnosticRaw(t, destination)
	if err := unix.Fchmod(fd, 0); err != nil {
		t.Fatal(err)
	}
	reopened, err := unix.Open(fmt.Sprintf("/proc/self/fd/%d", fd), unix.O_WRONLY|unix.O_NONBLOCK, 0)
	if err == nil {
		unix.Close(reopened)
		t.Fatal("fixture unexpectedly allows pipe reopen")
	}
	if !errors.Is(err, unix.EACCES) {
		t.Fatalf("reopen fixture: %v", err)
	}
	d := startDiagnosticTest(t, context.Background(), destination)
	if _, err := d.Diagnostics().Write([]byte("inherited")); err != nil {
		t.Fatal(err)
	}
	if err := d.Finish(nil, time.Now().Add(5*time.Second)); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("inherited"))
	if _, err := io.ReadFull(peer, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "inherited" {
		t.Fatalf("inherited pipe output %q", got)
	}
}

// This fixture changes only the newly owned producer socket's buffer size. It
// never changes the borrowed stderr or relies on this host's default buffers.
// Kernel EAGAIN and actual writer stacks below establish pressure independently
// of any chosen byte count. Removing cancellation/joins must break these tests.
func diagnosticFDInventory(t *testing.T) map[int]bool {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	fds := make(map[int]bool)
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err == nil {
			// ReadDir's own transient descriptor is already closed.
			if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err == nil {
				fds[fd] = true
			}
		}
	}
	return fds
}

func diagnosticProducerFD(t *testing.T, before map[int]bool) int {
	t.Helper()
	found := -1
	for fd := range diagnosticFDInventory(t) {
		if before[fd] {
			continue
		}
		domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
		if err != nil || domain != unix.AF_UNIX {
			continue
		}
		kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || kind != unix.SOCK_STREAM {
			continue
		}
		if _, err := unix.Getpeername(fd); err != nil {
			continue
		}
		if found >= 0 {
			t.Fatal("more than one newly owned Unix stream")
		}
		found = fd
	}
	if found < 0 {
		t.Fatal("adapter producer socket absent")
	}
	if err := unix.SetsockoptInt(found, unix.SOL_SOCKET, unix.SO_SNDBUF, 4096); err != nil {
		t.Fatal(err)
	}
	size, err := unix.GetsockoptInt(found, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil || size > 16384 {
		t.Fatalf("private producer buffer %d: %v", size, err)
	}
	flags, err := unix.FcntlInt(uintptr(found), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatalf("producer must be pollable: %x %v", flags, err)
	}
	t.Logf("actual owned producer fd=%d SO_SNDBUF=%d", found, size)
	return found
}

func fillDiagnosticProducer(t *testing.T, d *enrollmentCLIDiagnostics, fd int) {
	t.Helper()
	// Only precondition an idle private stream; no transport writer is active.
	// Its receiver is the real relay, whose destination remains unread.
	chunk := bytes.Repeat([]byte("p"), 32<<10)
	fill := func() {
		for n := 0; n < 64; n++ {
			_, err := unix.Write(fd, chunk)
			if errors.Is(err, unix.EAGAIN) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
		}
		t.Fatal("private stream did not reach actual EAGAIN")
	}
	fill()
	waitDiagnosticBlocked(t, d.pid, false)
	fill() // no further relay reads are possible after the fd3 write barrier
	if _, err := unix.Write(fd, []byte("x")); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("producer is not actually full: %v", err)
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	if _, err := unix.Poll(poll, 0); err != nil || poll[0].Revents != 0 {
		t.Fatalf("producer unexpectedly writable: %+v %v", poll, err)
	}
	t.Log("actual producer EAGAIN and no POLLOUT while relay is blocked on retained unread pipe")
}

func diagnosticStacks() []string {
	buf := make([]byte, 2<<20)
	n := runtime.Stack(buf, true)
	return strings.Split(string(buf[:n]), "\n\n")
}

func waitDiagnosticStack(t *testing.T, deadline time.Time, fragments ...string) string {
	t.Helper()
	for time.Now().Before(deadline) {
		for _, stack := range diagnosticStacks() {
			matches := true
			for _, fragment := range fragments {
				matches = matches && strings.Contains(stack, fragment)
			}
			if matches {
				t.Logf("actual blocked transport stage:\n%s", stack)
				return strings.Fields(stack)[1]
			}
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("actual transport stage absent: %q\n%s", fragments, strings.Join(diagnosticStacks(), "\n\n"))
	return ""
}

func joinDiagnosticSignal(t *testing.T, done <-chan struct{}, deadline time.Time, name string) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(time.Until(deadline)):
		t.Fatalf("%s did not join within original common cleanup deadline", name)
	}
}

// The server is an actual authenticated loopback SSH peer. A handshake gate
// lets the client finish its first-contact setup warning before we saturate
// diagnostics; its later key-exchange warning must then block in the callback.
func startDiagnosticTransportServer(t *testing.T, originalDeadline time.Time, gate <-chan struct{}, effect string) (string, <-chan struct{}) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_AUTH_SOCK", "")
	if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pemKey, err := cryptossh.MarshalPrivateKey(key, "")
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(home, ".ssh", "id_ed25519")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(pemKey), 0600); err != nil {
		t.Fatal(err)
	}
	signer, err := cryptossh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	config := fmt.Sprintf("Host blocked-diagnostic\n HostName 127.0.0.1\n Port %d\n User diagnostic\n IdentityFile %s\n IdentitiesOnly yes\n IdentityAgent none\n UserKnownHostsFile none\n GlobalKnownHostsFile none\n", listener.Addr().(*net.TCPAddr).Port, keyPath)
	if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	accepted := make(chan net.Conn, 1)
	rescue := make(chan struct{})
	t.Cleanup(func() {
		close(rescue)
		listener.Close()
		select {
		case raw := <-accepted:
			raw.Close()
		default:
		}
		joinDiagnosticSignal(t, done, time.Now().Add(3*time.Second), "rescued SSH fixture")
	})
	go func() {
		defer close(done)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		accepted <- raw
		defer raw.Close()
		_ = raw.SetDeadline(originalDeadline)
		if gate != nil {
			select {
			case <-gate:
			case <-rescue:
				return
			}
		}
		cfg := &cryptossh.ServerConfig{PublicKeyCallback: func(cryptossh.ConnMetadata, cryptossh.PublicKey) (*cryptossh.Permissions, error) { return nil, nil }}
		cfg.AddHostKey(signer)
		conn, channels, requests, err := cryptossh.NewServerConn(raw, cfg)
		if err != nil {
			return
		} // cancellation during key exchange is expected
		defer conn.Close()
		requestsDone := make(chan struct{})
		go func() { cryptossh.DiscardRequests(requests); close(requestsDone) }()
		defer func() { conn.Close(); <-requestsDone; conn.Wait() }()
		for pending := range channels {
			if pending.ChannelType() != "session" {
				pending.Reject(cryptossh.UnknownChannelType, "fixture")
				continue
			}
			ch, reqs, err := pending.Accept()
			if err != nil {
				return
			}
			defer ch.Close()
			for req := range reqs {
				if req.Type != "exec" {
					req.Reply(false, nil)
					continue
				}
				if err := os.WriteFile(effect, []byte("remote effect already occurred"), 0600); err != nil {
					t.Error(err)
					return
				}
				if err := req.Reply(true, nil); err != nil {
					return
				}
				chunk := bytes.Repeat([]byte("remote diagnostic"), 2048)
				for {
					// The peer's actual SSH channel window eventually blocks this
					// writer; its stack is observed before cancellation below.
					if _, err := ch.Stderr().Write(chunk); err != nil {
						return
					}
				}
			}
		}
	}()
	return "blocked-diagnostic", done
}

func TestEnrollmentDiagnosticsBlockedTransportComposition(t *testing.T) {
	for _, stage := range []string{"resolver", "handshake", "command"} {
		for _, failOutput := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/output-failure=%v", stage, failOutput), func(t *testing.T) {
				originalDeadline := time.Now().Add(20 * time.Second)
				ctx, cancel := context.WithDeadline(context.Background(), originalDeadline)
				defer cancel()
				destination, peer := diagnosticOutput(t, "pipe", false)
				effect := filepath.Join(t.TempDir(), "remote-effect")
				var gate chan struct{}
				var fixtureDone <-chan struct{}
				var host string
				if stage != "resolver" {
					if stage == "handshake" {
						gate = make(chan struct{})
					}
					host, fixtureDone = startDiagnosticTransportServer(t, originalDeadline, gate, effect)
				} else {
					home := t.TempDir()
					t.Setenv("HOME", home)
					if err := os.Mkdir(filepath.Join(home, ".ssh"), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(home, ".ssh", "config"), []byte("Host blocked-diagnostic\n HostName 127.0.0.1\n ProxyJump diagnostic-proxy.invalid\n"), 0600); err != nil {
						t.Fatal(err)
					}
					host = "blocked-diagnostic"
				}
				before := diagnosticFDInventory(t)
				d := startDiagnosticTest(t, ctx, destination)
				producerFD := diagnosticProducerFD(t, before)
				if deadline, ok := d.Context().Deadline(); !ok || !deadline.Equal(originalDeadline) {
					t.Fatal("attempt deadline was renewed")
				}
				var target *enrollmentssh.Target
				var client *enrollmentssh.EnrollmentClient
				var err error
				if stage != "resolver" {
					target, err = enrollmentssh.ResolveContext(d.Context(), host, d.Diagnostics())
					if err != nil {
						t.Fatal(err)
					}
				}
				if stage == "command" {
					client, err = enrollmentssh.NewEnrollmentClient(d.Context(), target, d.Diagnostics())
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { client.Close() })
				}
				if stage == "resolver" {
					fillDiagnosticProducer(t, d, producerFD)
				}
				operationDone := make(chan struct{})
				var operationErr error
				var unexpectedSuccess bool
				go func() {
					defer close(operationDone)
					switch stage {
					case "resolver":
						var resolved *enrollmentssh.Target
						resolved, operationErr = enrollmentssh.ResolveContext(d.Context(), host, d.Diagnostics())
						if resolved != nil {
							unexpectedSuccess = true
						}
					case "handshake":
						var connected *enrollmentssh.EnrollmentClient
						connected, operationErr = enrollmentssh.NewEnrollmentClient(d.Context(), target, d.Diagnostics())
						if connected != nil {
							connected.Close()
							unexpectedSuccess = true
						}
					case "command":
						operationErr = client.Run(d.Context(), "effect-before-diagnostics")
					}
				}()
				// Failure-only cleanup rescues the exact original operation and
				// retains the pipe reader until after cancellation and actual joins.
				t.Cleanup(func() {
					cancel()
					if t.Failed() {
						select {
						case <-d.done:
						default:
							// Failure-only rescue cannot satisfy the original oracle.
							_ = unix.Kill(d.pid, unix.SIGKILL)
						}
					}
					_ = d.Finish(context.Canceled, time.Now().Add(5*time.Second))
					joinDiagnosticSignal(t, operationDone, time.Now().Add(3*time.Second), "rescued transport operation")
				})
				barrierDeadline := time.Now().Add(4 * time.Second)
				if stage == "handshake" {
					waitDiagnosticStack(t, barrierDeadline, "exchangeVersions", "NewEnrollmentClient", "[IO wait]")
					fillDiagnosticProducer(t, d, producerFD)
					close(gate)
				}
				fragments := []string{"(*EnrollmentDiagnostics).Write", "[IO wait]"}
				switch stage {
				case "resolver":
					fragments = append(fragments, "ResolveContext", "resolveConfigUsing")
				case "handshake":
					fragments = append(fragments, "clientConfigWithWarning.func", "handshakeTransport")
				case "command":
					fragments = append(fragments, "(*EnrollmentClient).run.func")
				}
				writerID := waitDiagnosticStack(t, barrierDeadline, fragments...)
				waitDiagnosticBlocked(t, d.pid, false)
				writerIDs := []string{writerID}
				if stage == "command" {
					writerIDs = append(writerIDs, waitDiagnosticStack(t, barrierDeadline, "(*window).reserve", "startDiagnosticTransportServer"))
					if body, err := os.ReadFile(effect); err != nil || string(body) != "remote effect already occurred" {
						t.Fatalf("command stage/effect absent: %q %v", body, err)
					}
				}
				select {
				case <-operationDone:
					t.Fatal("transport completed before cancellation/failure oracle")
				default:
				}
				cleanupDeadline := time.Now().Add(5 * time.Second)
				if !cleanupDeadline.Before(originalDeadline) {
					t.Fatal("fixture exhausted original budget before oracle")
				}
				if failOutput {
					peer.Close()
				} else {
					cancel()
				}
				joinDiagnosticSignal(t, operationDone, cleanupDeadline, "actual transport operation and writers")
				if operationErr == nil || unexpectedSuccess {
					t.Fatal("blocked transport failure claimed success")
				}
				if stage == "command" && !strings.Contains(operationErr.Error(), "unknown") {
					t.Fatalf("remote effect lost UNKNOWN: %v", operationErr)
				}
				closed := make(chan struct{})
				var finishErr error
				go func() {
					defer close(closed)
					if client != nil {
						client.Close()
					}
					finishErr = d.Finish(operationErr, cleanupDeadline)
				}()
				joinDiagnosticSignal(t, closed, cleanupDeadline, "transport Close and adapter owner actual Wait")
				if fixtureDone != nil {
					joinDiagnosticSignal(t, fixtureDone, cleanupDeadline, "actual SSH fixture and writer")
				}
				if finishErr == nil || !strings.Contains(finishErr.Error(), "unknown") {
					t.Fatalf("adapter failed to preserve UNKNOWN: %v", finishErr)
				}
				if err := unix.Kill(d.pid, 0); !errors.Is(err, unix.ESRCH) {
					t.Fatalf("relay not actually reaped: %v", err)
				}
				// A done-channel send can precede the goroutine's final return;
				// observe disappearance within the same budget, never a new one.
				for _, id := range writerIDs {
					for {
						present := false
						for _, stack := range diagnosticStacks() {
							present = present || strings.HasPrefix(stack, "goroutine "+id+" ")
						}
						if !present {
							break
						}
						if !time.Now().Before(cleanupDeadline) {
							t.Fatalf("transport-owned writer %s survived joined operation", id)
						}
						time.Sleep(time.Millisecond)
					}
				}
				if stage == "command" {
					if body, err := os.ReadFile(effect); err != nil || string(body) != "remote effect already occurred" {
						t.Fatal("unknown result erased existing remote effect")
					}
				}
				if time.Now().After(cleanupDeadline) {
					t.Fatal("common cleanup deadline was renewed")
				}
				runtime.KeepAlive(peer)
				t.Logf("%s joined within original/common deadlines; operation=%v; adapter=%v", stage, operationErr, finishErr)
			})
		}
	}
}
