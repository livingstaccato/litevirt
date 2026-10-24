package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/ssh"
	"golang.org/x/sys/unix"
)

// EnrollmentDiagnosticsRelayArg selects only local descriptor copying, never an
// enrollment operation. The public enrollment caller remains unchanged.
const EnrollmentDiagnosticsRelayArg = "--internal-enrollment-diagnostics-relay"

const diagnosticCleanupLimit = 5 * time.Second
const diagnosticReapReserve = time.Second

type diagnosticFinish struct {
	err      error
	deadline time.Time
}

type enrollmentCLIDiagnostics struct {
	ctx         context.Context
	cancel      context.CancelFunc
	diagnostics *ssh.EnrollmentDiagnostics
	finish      chan diagnosticFinish
	done        chan struct{}
	pid         int   // published by the constructor's startup channel
	relayErr    error // published by done
	finishOnce  sync.Once
	finishErr   error
}

func newEnrollmentCLIDiagnostics(parent context.Context, stderr *os.File) (*enrollmentCLIDiagnostics, error) {
	return newEnrollmentCLIDiagnosticsArgs(parent, stderr, []string{EnrollmentDiagnosticsRelayArg})
}

// args is a private same-image test seam, never an executable or writer seam.
func newEnrollmentCLIDiagnosticsArgs(parent context.Context, stderr *os.File, args []string) (*enrollmentCLIDiagnostics, error) {
	if parent == nil || stderr == nil {
		return nil, errors.New("nil enrollment diagnostics context or stderr")
	}
	ctx, cancel := context.WithTimeout(parent, 10*time.Minute)
	ready := false
	defer func() {
		if !ready {
			cancel()
		}
	}()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	raw, err := stderr.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var admissionErr error
	err = raw.Control(func(original uintptr) {
		if admissionErr = admitDiagnosticDestination(int(original)); admissionErr == nil {
			fd, admissionErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 3)
		}
	})
	if err != nil || admissionErr != nil {
		return nil, errors.Join(err, admissionErr)
	}
	destination := os.NewFile(uintptr(fd), "enrollment-stderr-owned")
	defer destination.Close()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	producerFile := os.NewFile(uintptr(pair[0]), "enrollment-diagnostics-producer")
	reader := os.NewFile(uintptr(pair[1]), "enrollment-diagnostics-reader")
	defer reader.Close()
	conn, err := net.FileConn(producerFile)
	producerFile.Close()
	if err != nil {
		return nil, err
	}
	stream, ok := conn.(*net.UnixConn)
	if !ok {
		conn.Close()
		return nil, errors.New("diagnostics socketpair is not a Unix stream")
	}
	diagnostics, err := ssh.NewEnrollmentDiagnostics(ctx, stream)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ready {
			diagnostics.Close()
		}
	}()
	null, err := os.OpenFile(os.DevNull, os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}
	defer null.Close()
	cmd := exec.Command("/proc/self/exe", args...)
	cmd.Stdin = null
	cmd.Stdout = null
	cmd.Stderr = null
	cmd.ExtraFiles = []*os.File{destination, reader}
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	d := &enrollmentCLIDiagnostics{ctx: ctx, cancel: cancel, diagnostics: diagnostics, finish: make(chan diagnosticFinish, 1), done: make(chan struct{})}
	started := make(chan error, 1)
	go d.own(cmd, started)
	if err := <-started; err != nil {
		<-d.done
		return nil, err
	}
	// Parent copies must close before admission, so EOF cannot be held by us.
	destination.Close()
	reader.Close()
	null.Close()
	if err := ctx.Err(); err != nil {
		return nil, d.Finish(err, time.Now().Add(diagnosticCleanupLimit))
	}
	ready = true
	return d, nil
}

func (d *enrollmentCLIDiagnostics) Context() context.Context                { return d.ctx }
func (d *enrollmentCLIDiagnostics) Diagnostics() *ssh.EnrollmentDiagnostics { return d.diagnostics }

// Finish joins the actual relay. Caller cleanupDeadline includes time already
// spent closing/joining the existing transport; it must not be renewed here.
func (d *enrollmentCLIDiagnostics) Finish(operationErr error, cleanupDeadline time.Time) error {
	d.finishOnce.Do(func() {
		limit := time.Now().Add(diagnosticCleanupLimit)
		if cleanupDeadline.IsZero() || limit.Before(cleanupDeadline) {
			cleanupDeadline = limit
		}
		request := diagnosticFinish{operationErr, cleanupDeadline}
		// Publish cutoff before close: even concurrent writes must not defer it.
		select {
		case d.finish <- request:
		case <-d.done:
		}
		d.diagnostics.Close()
		<-d.done
		d.finishErr = errors.Join(operationErr, d.relayErr, d.ctx.Err())
		d.cancel()
		if d.finishErr != nil {
			d.finishErr = fmt.Errorf("enrollment diagnostics result unknown: %w", d.finishErr)
		}
	})
	return d.finishErr
}

func (d *enrollmentCLIDiagnostics) own(cmd *exec.Cmd, started chan<- error) {
	defer close(d.done)
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := cmd.Start(); err != nil {
		d.relayErr = err
		started <- err
		return
	}
	d.pid = cmd.Process.Pid
	started <- nil
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	var cutoff <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	killAndWait := func(reason error) {
		killErr := cmd.Process.Kill()
		if errors.Is(killErr, os.ErrProcessDone) {
			killErr = nil
		}
		d.diagnostics.Close()
		d.relayErr = errors.Join(reason, killErr, <-waited)
		d.cancel()
	}
	for {
		select {
		case err := <-waited:
			d.relayErr = err
			if err != nil {
				d.cancel()
				d.diagnostics.Close()
			}
			return
		case <-d.ctx.Done():
			killAndWait(d.ctx.Err())
			return
		case request := <-d.finish:
			if request.err != nil {
				killAndWait(request.err)
				return
			}
			end := request.deadline.Add(-diagnosticReapReserve)
			if original, ok := d.ctx.Deadline(); ok && original.Before(end) {
				end = original
			}
			if !time.Now().Before(end) {
				killAndWait(errors.New("diagnostic drain cleanup budget exhausted"))
				return
			}
			timer = time.NewTimer(time.Until(end))
			cutoff = timer.C
		case <-cutoff:
			killAndWait(errors.New("diagnostic drain cleanup budget exhausted"))
			return
		}
	}
}

func admitDiagnosticDestination(fd int) error {
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil {
		return err
	}
	if flags&unix.O_PATH != 0 || flags&unix.O_ACCMODE == unix.O_RDONLY {
		return errors.New("stderr is not writable")
	}
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG, unix.S_IFIFO:
		if flags&unix.O_DIRECT != 0 {
			return errors.New("direct/packet stderr is not a diagnostic byte stream")
		}
		return nil
	case unix.S_IFSOCK:
		return admitDiagnosticSocket(fd, false)
	case unix.S_IFCHR:
		if unix.Major(st.Rdev) == 1 && unix.Minor(st.Rdev) == 3 {
			return nil
		}
		if _, err := unix.IoctlGetTermios(fd, unix.TCGETS); err != nil {
			return errors.New("stderr is not a supported terminal")
		}
		discipline, err := unix.IoctlGetInt(fd, unix.TIOCGETD)
		if err != nil || discipline != 0 /* Linux N_TTY, include/uapi/linux/tty.h */ {
			return errors.New("stderr requires N_TTY terminal discipline")
		}
		return nil
	default:
		return errors.New("unsupported stderr descriptor kind")
	}
}

func admitDiagnosticSocket(fd int, unixOnly bool) error {
	kind, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_TYPE)
	if err != nil || kind != unix.SOCK_STREAM {
		return errors.New("diagnostics requires a stream socket")
	}
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil || (domain != unix.AF_UNIX && (unixOnly || (domain != unix.AF_INET && domain != unix.AF_INET6))) {
		return errors.New("unsupported diagnostic socket domain")
	}
	_, err = unix.Getpeername(fd)
	return err
}

// RunEnrollmentDiagnosticsRelay copies only inherited fd4 to fd3. It creates
// no application children or goroutines, changes no destination flags or termios,
// and exits successfully only after EOF, complete writes and owned closes.
// Ordinary healthy kernel/driver/local-filesystem assumptions apply to reaping.
func RunEnrollmentDiagnosticsRelay() int {
	err := admitDiagnosticDestination(3)
	if err == nil {
		err = admitDiagnosticSocket(4, true)
	}
	if err == nil {
		err = copyDiagnosticDescriptors(3, 4)
	}
	err = errors.Join(err, unix.Close(3), unix.Close(4))
	if err != nil {
		return 1
	}
	return 0
}

func waitDiagnosticFD(fd int, events int16) error {
	for {
		poll := []unix.PollFd{{Fd: int32(fd), Events: events}}
		_, err := unix.Poll(poll, -1)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		if poll[0].Revents&unix.POLLNVAL != 0 {
			return unix.EBADF
		}
		return nil
	}
}

func copyDiagnosticDescriptors(destination, source int) error {
	var buffer [32 << 10]byte
	for {
		n, err := unix.Read(source, buffer[:])
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			if err = waitDiagnosticFD(source, unix.POLLIN); err != nil {
				return err
			}
			continue
		}
		if err != nil {
			return err
		}
		if n == 0 {
			return nil
		}
		for offset := 0; offset < n; {
			written, err := unix.Write(destination, buffer[offset:n])
			if written > 0 {
				offset += written
			}
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if errors.Is(err, unix.EAGAIN) {
				if err = waitDiagnosticFD(destination, unix.POLLOUT); err != nil {
					return err
				}
				continue
			}
			if err != nil {
				return err
			}
			if written == 0 {
				return io.ErrShortWrite
			}
		}
	}
}
