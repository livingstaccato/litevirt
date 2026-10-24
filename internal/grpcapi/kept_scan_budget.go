package grpcapi

import (
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

// What one keptCollisionScan may cost before it gives up and refuses: the
// files it looks at (each directory entry and each chain layer), the bytes
// it reads of their headers, and the time it takes. A symlink below a root
// can name a tree as large as the host's (a link to /, or a large network
// mount), and a scan that read all of it would hold the write for as long;
// one past any of these refuses instead, naming it. Variables for tests.
var (
	keptScanMaxFiles int64 = 250_000
	keptScanMaxBytes int64 = 4 << 30
	keptScanMaxTime        = 2 * time.Minute
)

// errKeptScanBudget marks a keptCollisionScan that ran past its budget.
var errKeptScanBudget = errors.New("the scan of this host's disk files ran past its budget")

// keptScanOpenHook, when set (tests), sees every path keptScanBudget.open
// is about to open.
var keptScanOpenHook func(path string)

// keptScanBudget is what is left of one keptCollisionScan's budget. Its
// counters are atomic: a walk outlives a bounded call that gave up on it.
type keptScanBudget struct {
	files, bytes atomic.Int64
	deadline     time.Time
}

func newKeptScanBudget() *keptScanBudget {
	return &keptScanBudget{deadline: time.Now().Add(keptScanMaxTime)}
}

// look charges one file looked at, and checks the time.
func (b *keptScanBudget) look() error {
	if n := b.files.Add(1); n > keptScanMaxFiles {
		return fmt.Errorf("%w: more than %d files (narrow what the pool directories hold, or fix what cannot be read)",
			errKeptScanBudget, keptScanMaxFiles)
	}
	if time.Now().After(b.deadline) {
		return fmt.Errorf("%w: more than %s (narrow what the pool directories hold, or fix what cannot be read)",
			errKeptScanBudget, keptScanMaxTime)
	}
	return nil
}

// charge charges n bytes read.
func (b *keptScanBudget) charge(n int64) error {
	if t := b.bytes.Add(n); t > keptScanMaxBytes {
		return fmt.Errorf("%w: more than %d bytes read (narrow what the pool directories hold, or fix what cannot be read)",
			errKeptScanBudget, keptScanMaxBytes)
	}
	return nil
}

// open opens the layer at path for reading its header: only a regular file
// (judged by stat first, so a FIFO or a device is never opened at all) on no
// pseudo-filesystem (keptScanPseudoFS: /proc/kmsg is a regular file whose
// read blocks), opened O_NONBLOCK and judged again through the open file, so
// one swapped in at the name since the stat neither blocks the open nor is
// read. It is charged as a file looked at.
func (b *keptScanBudget) open(path string) (*os.File, error) {
	if err := b.look(); err != nil {
		return nil, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", path)
	}
	if fs, pseudo, err := keptScanPseudoFS(path); err != nil {
		return nil, err
	} else if pseudo {
		return nil, fmt.Errorf("%s is on %s, a pseudo-filesystem, which holds no disk", path, fs)
	}
	if keptScanOpenHook != nil {
		keptScanOpenHook(path)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	fi, err = f.Stat()
	if err == nil && !fi.Mode().IsRegular() {
		err = fmt.Errorf("%s is not a regular file", path)
	}
	if err == nil {
		var fs string
		var pseudo bool
		if fs, pseudo, err = keptScanPseudoFSOf(f); err == nil && pseudo {
			err = fmt.Errorf("%s is on %s, a pseudo-filesystem, which holds no disk", path, fs)
		}
	}
	if err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
