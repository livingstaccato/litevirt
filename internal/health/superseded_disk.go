package health

import (
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A failover start never boots a superseded copy of a host-local disk.
//
// A host-local disk lives on its VM's host. An ownership transfer — a pending
// row the coordinator re-pointed at this host when the VM's host failed —
// therefore never finds the VM's CURRENT disk here: that died, or is stranded,
// with the failed host. A file at the disk's path on this host can only be
// left from an earlier stay: the leftover cleanup removes the old domain and
// keeps its disk. The pending start rebuilt the overlay only when the file was
// missing, so it booted that copy — a silent rollback to old data, at the old
// size (drills 2 and 3 on main-b3368d7c: pp5 and pp2 came up on 112 MiB disks
// instead of their 20 GiB ones).
//
// So on a transfer the file is set aside (renamed, never deleted: it may hold
// the only copy of data an operator wants back) and the start treats the disk
// as missing — rebuilding the overlay at its recorded size, or failing if
// there is nothing to rebuild from. The one file a transfer keeps is a disk it
// rebuilt itself, for this same proof, on an earlier attempt that then failed
// and was re-armed.
//
// The identity is decided here, at the start, rather than in the leftover
// cleanup. That cleanup acts on a row that may itself be wrong (an
// equal-updated_at LWW tie converges host_name to the wrong host), so it keeps
// the disk in place on purpose; a transfer is a positive decision that the VM
// moves here, which the cleanup's row is not.

// isHostLocalDisk reports whether a disk is a plain host-local file, so the
// same path on two hosts is two distinct files (internal/grpcapi's
// isHostLocalDiskDriver). A row with no storage type is left as it was.
func isHostLocalDisk(d corrosion.DiskRecord) bool {
	return d.StorageType == "local" || d.StorageType == "dir"
}

// transferDisks is what this host rebuilt for a pending transfer, path →
// proof ID, so a re-armed attempt of the same proof keeps it. In memory: a
// restart forgets it, which costs only one more set-aside of a disk that held
// nothing yet.
type transferDisks struct {
	mu sync.Mutex
	m  map[string]string
}

func (t *transferDisks) note(path, proofID string) {
	if proofID == "" {
		return // a proof-less transfer is never re-armed
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.m == nil {
		t.m = map[string]string{}
	}
	t.m[path] = proofID
}

func (t *transferDisks) builtFor(path, proofID string) bool {
	if proofID == "" {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.m[path] == proofID
}

// setAsideSupersededDisk renames a file found at a host-local disk's path at
// the start of an ownership transfer onto this host, and returns where it went
// ("" when nothing was there or it was kept).
func (r *Reconciler) setAsideSupersededDisk(vmName, proofID string, d corrosion.DiskRecord) (string, error) {
	if !isHostLocalDisk(d) || d.Path == "" {
		return "", nil
	}
	if _, err := os.Lstat(d.Path); err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	if r.transferDisks.builtFor(d.Path, proofID) {
		return "", nil
	}
	aside := fmt.Sprintf("%s.superseded-%s", d.Path, time.Now().UTC().Format("20060102T150405.000000000Z"))
	if err := os.Rename(d.Path, aside); err != nil {
		return "", err
	}
	slog.Warn("reconciler: a failover onto this host found an old copy of the VM's disk; set it aside and will not boot it",
		"vm", vmName, "disk", d.DiskName, "path", d.Path, "set_aside_to", aside,
		"fix", "remove "+aside+" once nothing in it is needed")
	return aside, nil
}
