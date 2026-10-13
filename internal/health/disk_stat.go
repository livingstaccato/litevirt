package health

import (
	"fmt"
	"os"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// The reconcile pass looks at disk files: a start checks each disk is there
// (and a transfer sets aside an old copy at its path), the define of a
// re-keyed stopped VM checks its disks are visible, and the stranded-disk
// tend looks at a disk a failover left here. A disk can be on a hard NFS
// mount whose server does not answer, and a stat there blocks in the kernel
// for as long as the server is gone (lab 2 F-3: the pass sat 2m41s in one
// newfstatat). One pass serves every VM on the host, so each look runs under
// storage.Bounded: a disk that does not answer costs the pass one bound per
// mount (the mount latch refuses later calls at once), and is never read as
// a disk that is not there — the caller waits for a later pass instead.

// statDisk is os.Stat of a disk file, under the storage bound. A no-answer
// is an *storage.FSNoAnswerError (storage.IsFSNoAnswer).
func (r *Reconciler) statDisk(p string) (os.FileInfo, error) {
	// Read here, not inside the bounded call: a call the bound gave up on
	// may still be running when a test restores the seam.
	stat := r.diskStat
	if stat == nil {
		stat = os.Stat
	}
	return storage.Bounded("stat", p, func() (os.FileInfo, error) { return stat(p) })
}

// lstatDisk is os.Lstat of a disk file, under the storage bound.
func (r *Reconciler) lstatDisk(p string) (os.FileInfo, error) {
	lstat := r.diskLstat
	if lstat == nil {
		lstat = os.Lstat
	}
	return storage.Bounded("lstat", p, func() (os.FileInfo, error) { return lstat(p) })
}

// diskNoAnswer is the deferral of a start whose disk d did not answer err.
func diskNoAnswer(d corrosion.DiskRecord, err error) error {
	return fmt.Errorf("%w: disk %s: whether its file %s is there cannot be told: its storage does not answer: %v",
		ErrStartProbeFailed, d.DiskName, d.Path, err)
}
