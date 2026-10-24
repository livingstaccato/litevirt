package pki

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

const activeDomainLockName = ".active-domain.lock"

var daemonDomains = struct {
	sync.Mutex
	leases map[string]*HostDomainLease
}{leases: make(map[string]*HostDomainLease)}

// RegisterDaemonHostDomain holds shared admission until process exit or exec.
// A constructor/Run error does not prove that all started consumers stopped.
// The registry deliberately owns a strong file reference, independent of the
// Daemon object and the os.File finalizer. No public release handle escapes.
func RegisterDaemonHostDomain(ctx context.Context, dir string) error {
	lease, err := AcquireHostDomain(ctx, dir)
	if err != nil {
		return err
	}
	daemonDomains.Lock()
	defer daemonDomains.Unlock()
	if existing := daemonDomains.leases[lease.dir]; existing != nil {
		lease.Release()
		info, err := existing.file.Stat()
		if err != nil {
			return err
		}
		actual, err := os.Lstat(filepath.Join(existing.dir, activeDomainLockName))
		if err != nil || !os.SameFile(info, actual) {
			return errors.New("registered daemon domain inode changed")
		}
		return nil
	}
	daemonDomains.leases[lease.dir] = lease
	return nil
}

// HostDomainLease excludes quiescent enrollment from a running daemon. It is
// independent of trust revisions and grants no certificate or storage authority.
// Acquire lifetime admission before any owner lease; ordinary trust writers do
// not acquire lifetime admission. Its inode must never be removed by setup.
type HostDomainLease struct {
	mu        sync.Mutex
	self      *HostDomainLease
	directory os.FileInfo
	dir       string
	file      *os.File
	exclusive bool
}

// AcquireHostDomain admits a daemon for its entire constructed/running lifetime.
func AcquireHostDomain(ctx context.Context, dir string) (*HostDomainLease, error) {
	return acquireHostDomain(ctx, dir, false)
}

// AcquireHostReinitialization excludes every cooperating daemon. The caller
// must stop the supported service before waiting here and release admission
// before restarting it. Possessing this lease does not authorize a root change.
func AcquireHostReinitialization(ctx context.Context, dir string) (*HostDomainLease, error) {
	return acquireHostDomain(ctx, dir, true)
}

func acquireHostDomain(ctx context.Context, dir string, exclusive bool) (*HostDomainLease, error) {
	if dir == "" {
		return nil, errors.New("no active PKI directory")
	}
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return nil, err
	}
	directory, err := os.Stat(canonical)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(canonical, activeDomainLockName)
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func(err error) (*HostDomainLease, error) { _ = f.Close(); return nil, err }
	info, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(errors.New("active domain lock is not regular"))
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		err = syscall.Flock(fd, mode|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
			return fail(err)
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return fail(ctx.Err())
		case <-timer.C:
		}
	}
	actual, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, actual) {
		return fail(errors.New("active domain lock inode changed"))
	}
	if err := f.Sync(); err != nil {
		return fail(err)
	}
	if err := syncTrustDirectory(canonical); err != nil {
		return fail(err)
	}
	actualDirectory, err := os.Stat(canonical)
	if err != nil || !os.SameFile(directory, actualDirectory) {
		return fail(errors.New("active domain directory changed"))
	}
	l := &HostDomainLease{dir: canonical, directory: directory, file: f, exclusive: exclusive}
	l.self = l
	return l, nil
}

func (l *HostDomainLease) Release() {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.self != l || l.file == nil {
		return
	}
	// Closing this reference must not unlock any surviving duplicate OFD.
	_ = l.file.Close()
	l.file = nil
}

// checkLocked is called while retaining mu through the corresponding local
// enrollment operation, so a concurrent Release cannot invalidate admission.
func (l *HostDomainLease) checkLocked(dir string) error {
	if l == nil || l.self != l || l.file == nil || !l.exclusive {
		return errors.New("exclusive host domain admission required")
	}
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return err
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return err
	}
	if canonical != l.dir {
		return errors.New("host domain admission belongs to another directory")
	}
	actualDirectory, err := os.Stat(canonical)
	if err != nil || l.directory == nil || !os.SameFile(l.directory, actualDirectory) {
		return errors.New("host domain admission directory changed")
	}
	info, err := l.file.Stat()
	if err != nil {
		return err
	}
	actual, err := os.Lstat(filepath.Join(l.dir, activeDomainLockName))
	if err != nil || !os.SameFile(info, actual) {
		return fmt.Errorf("host domain admission inode changed")
	}
	return nil
}

// duplicateForProcess retains the actual admission OFD. The parent copy is
// CLOEXEC; an explicit ExtraFiles transfer is required to give it to a child.
func (l *HostDomainLease) duplicateForProcess() (*os.File, error) {
	if l == nil {
		return nil, errors.New("exclusive host domain admission required")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if err := l.checkLocked(l.dir); err != nil {
		return nil, err
	}
	fd, _, errno := syscall.Syscall(syscall.SYS_FCNTL, l.file.Fd(), syscall.F_DUPFD_CLOEXEC, 0)
	if errno != 0 {
		return nil, errno
	}
	return os.NewFile(fd, l.file.Name()), nil
}
