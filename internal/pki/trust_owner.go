package pki

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

const trustLockName = ".trust.lock"

// The directory owner always precedes the stable advisory lock and component
// locks. Owner internals never invoke DB/network callbacks. A caller-owned
// read lease may precede that caller's DB transaction; writers never dial peers
// or fetch keys while holding this barrier.
type trustOwner struct {
	successorFloor    map[[32]byte][]byte
	dir               string
	gate              chan struct{}
	nonce             [32]byte
	revision          uint64
	root              []byte
	digest            [32]byte
	servedFingerprint [32]byte
	revokedFloor      map[string]bool
	capabilities      map[*HostCertificateValidation]bool
	policy            bool
	policyCell        *atomic.Bool
	pendingPolicy     atomic.Pointer[atomic.Bool]
	dirty             error
	crlEstablished    bool
	retired           bool
}

var trustOwners sync.Map

func trustOwnerFor(dir string) (*trustOwner, error) {
	if dir == "" {
		return nil, errors.New("no active PKI directory")
	}
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, fmt.Errorf("resolve PKI directory: %w", err)
	}
	canonical, err = filepath.Abs(canonical)
	if err != nil {
		return nil, err
	}
	if actual, ok := trustOwners.Load(canonical); ok {
		owner := actual.(*trustOwner)
		if err := rememberTrustOwnerPath(dir, owner); err != nil {
			return nil, err
		}
		return owner, nil
	}
	owner := &trustOwner{dir: canonical, gate: make(chan struct{}, 1)}
	if _, err := rand.Read(owner.nonce[:]); err != nil {
		return nil, err
	}
	owner.revision = 1
	owner.capabilities = make(map[*HostCertificateValidation]bool)
	owner.revokedFloor = make(map[string]bool)
	actual, _ := trustOwners.LoadOrStore(canonical, owner)
	owner = actual.(*trustOwner)
	if err := rememberTrustOwnerPath(dir, owner); err != nil {
		return nil, err
	}
	return owner, nil
}

type trustLock struct {
	owner *trustOwner
	file  *os.File
}

func (o *trustOwner) lock(ctx context.Context) (*trustLock, error) {
	select {
	case o.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	unlock := func() { <-o.gate }
	path := filepath.Join(o.dir, trustLockName)
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		unlock()
		return nil, fmt.Errorf("open PKI lock: %w", err)
	}
	f := os.NewFile(uintptr(fd), path)
	fail := func(err error) (*trustLock, error) { _ = f.Close(); unlock(); return nil, err }
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fail(errors.New("PKI lock is not a regular file"))
	}
	for {
		if err := ctx.Err(); err != nil {
			return fail(err)
		}
		err = syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			actual, statErr := os.Lstat(path)
			if statErr != nil || !os.SameFile(info, actual) {
				return fail(errors.New("PKI lock inode changed"))
			}
			if err := o.reconcilePolicyLocked(); err != nil {
				return fail(err)
			}
			return &trustLock{owner: o, file: f}, nil
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
}

func (l *trustLock) release() {
	_ = syscall.Flock(int(l.file.Fd()), syscall.LOCK_UN)
	_ = l.file.Close()
	<-l.owner.gate
}

func lockTrustWriter(dir string) (*trustLock, error) {
	o, err := trustOwnerFor(dir)
	if err != nil {
		return nil, err
	}
	return o.lock(context.Background())
}
