package pki

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHostDomainEnrollmentWorkerBorrowUsesActualAdmission(t *testing.T) {
	dir := t.TempDir()
	lease, err := AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	borrowed, err := lease.BorrowForEnrollmentWorker()
	if err != nil {
		t.Fatalf("RED_ENROLLMENT_WORKER_BORROW: actual exclusive admission refused: %v", err)
	}
	defer borrowed.Close()
	flags, _, errno := syscall.Syscall(syscall.SYS_FCNTL, borrowed.Fd(), syscall.F_GETFD, 0)
	if errno != 0 || flags&syscall.FD_CLOEXEC == 0 {
		t.Fatal("actual borrow is not CLOEXEC")
	}
	lease.Release()
	if got := borrowContender(t, dir); !strings.HasPrefix(got, "BLOCKED\n") {
		t.Fatalf("live borrowed OFD did not retain exclusion: %s", got)
	}
	_ = borrowed.Close()
	if got := borrowContender(t, dir); !strings.HasPrefix(got, "ACQUIRED\n") {
		t.Fatalf("last borrow close did not release exclusion: %s", got)
	}
	if _, err := lease.BorrowForEnrollmentWorker(); err == nil {
		t.Fatal("released lease borrowed again")
	}
	var zero HostDomainLease
	if _, err := zero.BorrowForEnrollmentWorker(); err == nil {
		t.Fatal("zero lease borrowed")
	}
}

// This subprocess uses the actual inherited OFD, not a reopened lock pathname.
func TestHostDomainBorrowProcess(t *testing.T) {
	mode := os.Getenv("LITEVIRT_BORROW_CHILD")
	if mode == "" {
		t.Skip("subprocess only; exercised by owned parent controls")
	}
	if mode == "registry" {
		dir := os.Getenv("LITEVIRT_BORROW_DIR")
		if err := RegisterDaemonHostDomain(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
		if err := RegisterDaemonHostDomain(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
		fmt.Println("READY")
		var b [1]byte
		os.Stdin.Read(b[:])
		return
	}
	if mode == "send" {
		lease, err := AcquireHostReinitialization(context.Background(), os.Getenv("LITEVIRT_BORROW_DIR"))
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Release()
		borrowed, err := lease.duplicateForProcess()
		if err != nil {
			t.Fatal(err)
		}
		err = syscall.Sendmsg(3, []byte("x"), syscall.UnixRights(int(borrowed.Fd())), nil, 0)
		borrowed.Close()
		if err != nil {
			t.Fatal(err)
		}
		fmt.Println("SENT")
		var b [1]byte
		os.Stdin.Read(b[:])
		return
	}
	if mode == "hold" {
		f := os.NewFile(3, "inherited-domain")
		if err := syscall.Flock(3, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		fmt.Println("READY")
		var b [1]byte
		if _, err := os.Stdin.Read(b[:]); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
		fmt.Println("CLOSED")
		return
	}
	f, err := os.OpenFile(os.Getenv("LITEVIRT_BORROW_LOCK"), os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if err == nil {
		fmt.Println("ACQUIRED")
		return
	}
	if err == syscall.EWOULDBLOCK || err == syscall.EAGAIN {
		fmt.Println("BLOCKED")
		return
	}
	t.Fatal(err)
}

func borrowContender(t *testing.T, dir string) string {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestHostDomainBorrowProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "LITEVIRT_BORROW_CHILD=contend", "LITEVIRT_BORROW_LOCK="+filepath.Join(dir, activeDomainLockName))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("contender pid/Wait: %v %s", err, out)
	}
	t.Logf("contender pid=%d Wait=0 result=%s", cmd.Process.Pid, out)
	return string(out)
}

// Removing close-only Release (restoring LOCK_UN) must let a contender cross
// the real surviving child's admission, which this test rejects.
func TestHostDomainBorrowedProcessRetainsExclusion(t *testing.T) {
	dir := setupPKI(t)
	lease, err := AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	borrowed, err := lease.duplicateForProcess()
	if err != nil {
		t.Fatal(err)
	}
	defer borrowed.Close()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestHostDomainBorrowProcess$", "-test.count=1")
	child.Env = append(os.Environ(), "LITEVIRT_BORROW_CHILD=hold")
	child.ExtraFiles = []*os.File{borrowed}
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	t.Cleanup(func() {
		stdin.Close()
		if !waited {
			err := child.Wait()
			t.Logf("holder pid=%d cleanup Wait=%v", child.Process.Pid, err)
		}
	})
	scan := bufio.NewScanner(stdout)
	if !scan.Scan() || scan.Text() != "READY" {
		t.Fatalf("child failed ready: %s %v", scan.Text(), scan.Err())
	}
	borrowed.Close()
	lease.Release()
	before := borrowContender(t, dir)
	if _, err := stdin.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if !scan.Scan() || scan.Text() != "CLOSED" {
		t.Fatal("child did not acknowledge descriptor close")
	}
	after := borrowContender(t, dir)
	err = child.Wait()
	waited = true
	t.Logf("holder pid=%d Wait=%v", child.Process.Pid, err)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(before, "BLOCKED") {
		t.Errorf("parent Release unlocked surviving child OFD: %s", before)
	}
	if !strings.Contains(after, "ACQUIRED") {
		t.Errorf("last reference did not release exclusion: %s", after)
	}
}

func TestHostDomainBorrowRejectsReleasedAndReplaced(t *testing.T) {
	t.Run("registry-shared-custody", func(t *testing.T) {
		dir := setupPKI(t)
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, executable, "-test.run=^TestHostDomainBorrowProcess$", "-test.count=1")
		child.Env = append(os.Environ(), "LITEVIRT_BORROW_CHILD=registry", "LITEVIRT_BORROW_DIR="+dir)
		stdin, err := child.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := child.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		waited := false
		t.Cleanup(func() {
			stdin.Close()
			if !waited {
				child.Process.Kill()
				err := child.Wait()
				t.Logf("registry pid=%d cleanupWait=%v", child.Process.Pid, err)
			}
		})
		scan := bufio.NewScanner(stdout)
		if !scan.Scan() || scan.Text() != "READY" {
			t.Fatal("registry did not retain actual SH")
		}
		if !strings.Contains(borrowContender(t, dir), "BLOCKED") {
			t.Fatal("registry strong SH did not exclude EX")
		}
		if _, err := stdin.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		err = child.Wait()
		waited = true
		t.Logf("registry pid=%d Wait=%v", child.Process.Pid, err)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(borrowContender(t, dir), "ACQUIRED") {
			t.Fatal("registry SH survived process exit")
		}
	})

	ctx := context.Background()
	dir := setupPKI(t)
	for _, l := range []*HostDomainLease{nil, {}} {
		if f, err := l.duplicateForProcess(); err == nil {
			f.Close()
			t.Fatal("borrow accepted zero admission")
		}
	}
	shared, err := AcquireHostDomain(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := shared.duplicateForProcess(); err == nil {
		f.Close()
		t.Fatal("borrow accepted shared admission")
	}
	shared.Release()
	l, err := AcquireHostReinitialization(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	copied := &HostDomainLease{self: l.self, dir: l.dir, file: l.file, exclusive: true}
	if f, err := copied.duplicateForProcess(); err == nil {
		f.Close()
		t.Fatal("borrow accepted copied admission")
	}
	if err := os.Rename(filepath.Join(dir, activeDomainLockName), filepath.Join(dir, "saved-lock")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, activeDomainLockName), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if f, err := l.duplicateForProcess(); err == nil {
		f.Close()
		t.Fatal("borrow accepted replaced inode")
	}
	l.Release()
	l.Release()
	if f, err := l.duplicateForProcess(); err == nil {
		f.Close()
		t.Fatal("borrow accepted released admission")
	}
	fresh, err := AcquireHostReinitialization(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	fresh.Release()
	if !strings.Contains(borrowContender(t, dir), "ACQUIRED") {
		t.Fatal("unborrowed Release retained lock")
	}
}

func TestHostDomainBorrowSurvivesOriginProcessDeath(t *testing.T) {
	dir := setupPKI(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	sockets, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(sockets[0]), "custody-receiver")
	defer receiver.Close()
	sender := os.NewFile(uintptr(sockets[1]), "custody-sender")
	defer sender.Close()
	if err := syscall.SetsockoptTimeval(sockets[0], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	origin := exec.CommandContext(ctx, executable, "-test.run=^TestHostDomainBorrowProcess$", "-test.count=1")
	origin.Env = append(os.Environ(), "LITEVIRT_BORROW_CHILD=send", "LITEVIRT_BORROW_DIR="+dir)
	origin.ExtraFiles = []*os.File{sender}
	originIn, err := origin.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	var originOut bytes.Buffer
	origin.Stdout = &originOut
	origin.Stderr = &originOut
	if err := origin.Start(); err != nil {
		t.Fatal(err)
	}
	originWaited := false
	t.Cleanup(func() {
		originIn.Close()
		if !originWaited {
			origin.Process.Kill()
			err := origin.Wait()
			t.Logf("origin pid=%d cleanupWait=%v output=%s", origin.Process.Pid, err, originOut.String())
		}
	})
	sender.Close()
	var message [1]byte
	control := make([]byte, syscall.CmsgSpace(4))
	_, n, _, _, err := syscall.Recvmsg(sockets[0], message[:], control, 0)
	if err != nil {
		t.Fatal(err)
	}
	headers, err := syscall.ParseSocketControlMessage(control[:n])
	if err != nil || len(headers) != 1 {
		t.Fatal("actual FD handoff", err)
	}
	fds, err := syscall.ParseUnixRights(&headers[0])
	if err != nil || len(fds) != 1 {
		t.Fatal("actual borrowed descriptor", err)
	}
	syscall.CloseOnExec(fds[0])
	borrowed := os.NewFile(uintptr(fds[0]), "received-same-OFD")
	defer borrowed.Close()
	holder := exec.CommandContext(ctx, executable, "-test.run=^TestHostDomainBorrowProcess$", "-test.count=1")
	holder.Env = append(os.Environ(), "LITEVIRT_BORROW_CHILD=hold")
	holder.ExtraFiles = []*os.File{borrowed}
	holderIn, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	holderOut, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	holder.Stderr = os.Stderr
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	holderWaited := false
	t.Cleanup(func() {
		holderIn.Close()
		if !holderWaited {
			holder.Process.Kill()
			err := holder.Wait()
			t.Logf("holder pid=%d cleanupWait=%v", holder.Process.Pid, err)
		}
	})
	scan := bufio.NewScanner(holderOut)
	if !scan.Scan() || scan.Text() != "READY" {
		t.Fatal("holder did not acquire inherited custody")
	}
	borrowed.Close()
	receiver.Close()
	if err := origin.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = origin.Wait()
	originWaited = true
	t.Logf("origin pid=%d killed Wait=%v output=%s", origin.Process.Pid, err, originOut.String())
	if err == nil {
		t.Fatal("killed origin reported clean Wait")
	}
	if !strings.Contains(borrowContender(t, dir), "BLOCKED") {
		t.Fatal("origin death released surviving OFD")
	}
	if err := holder.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	err = holder.Wait()
	holderWaited = true
	t.Logf("last holder pid=%d killed Wait=%v", holder.Process.Pid, err)
	if err == nil {
		t.Fatal("killed holder reported clean Wait")
	}
	if !strings.Contains(borrowContender(t, dir), "ACQUIRED") {
		t.Fatal("last holder death retained exclusion")
	}
}
