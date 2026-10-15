package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A deleted VM's disks on a host a failover moved it off.
//
// A VM restarted elsewhere by a failover leaves its real disk on the failed
// host, which sets it aside once it is back (stranded_disk.go), and its
// cloud-init seed (<data_dir>/cloudinit/<name>.iso). `lv rm` runs on the VM's
// owner and frees what is there; nothing freed these. On lab 1 (hdv-1,
// 2026-10-15) the copy and the seed stayed on the old host, with
// vm_disk_stranded raised, until they were removed by hand.
//
// So the delete records its decision on every open vm_disk_stranded record of
// the VM, BEFORE its tombstone (NoteStrandedDisksDeleted): the incarnation it
// deletes, and whether it keeps the disks. The host the record names acts on
// it on its own reconciler pass, from its own replica, whenever it next runs —
// a host that was down during the delete does it once it is back. It removes
// the files the record names, and the seed, only when all of these hold:
//
//   - its replica holds the VM's tombstone and no live row, and that tombstone
//     is of the incarnation the decision names (created_at): a VM created
//     again under the name is never touched, and while it exists nothing of
//     the name is removed;
//   - the decision was written within strandedDeletionWindow before that
//     tombstone, so a decision left by a delete that failed is not taken for
//     a later one. A --keep-disks delete writes its own decision, and a
//     delete with no decision (an older release) removes nothing;
//   - each file's entry was recorded for that same incarnation, at one of the
//     disk paths the VM's rows record, and a copy is named as one of that
//     path (<path>.superseded-<time>);
//   - no domain of the name is defined here, or the one that is is shut off
//     with nothing to resume — the leftover a fenced host comes back with
//     (domainAbsentOrDeadLeftover). Nothing here starts, stops or undefines a
//     domain;
//   - the file is a regular file last written no later than the tombstone
//     (within the second it names), and no live disk row references it.
//
// An entry that fails a check of the file itself, or of another incarnation,
// is dropped from the record and its file is kept: a copy then follows the
// retention for a deleted VM's (superseded_retention.go). One the host cannot
// act on yet — a live domain, storage that does not answer, a file written
// after the tombstone — keeps the record open, and the next pass tries again.
//
// The record is the only replicated thing written; its evidence is JSON, and
// a host on an older release reads none of the new fields and removes nothing.

// StrandedDeletion is what a VM's delete decided for its stranded disks.
type StrandedDeletion struct {
	Incarnation string `json:"incarnation"` // the deleted VM's created_at
	KeepDisks   bool   `json:"keep_disks,omitempty"`
	At          string `json:"at"` // RFC3339Nano, the deleting host's clock, before its tombstone
}

// strandedDeletionWindow is how long after its decision a delete's tombstone
// may land for the decision to apply, and how long a host whose replica holds
// the tombstone waits for a decision that has not reached it.
const strandedDeletionWindow = 10 * time.Minute

// tombstonePrecision is how coarse a tombstone's deleted_at can be: a wall
// key may carry whole seconds only, so a file last written within the second
// a tombstone names is not taken as written after it.
const tombstonePrecision = time.Second

// strandedDeletionSlack lets a tombstone read a little before its decision:
// both are stamped by the deleting host, but the tombstone by its LWW clock.
const strandedDeletionSlack = time.Minute

// NoteStrandedDisksDeleted records, on every open vm_disk_stranded record of
// vmName, that the delete of its incarnation createdAt is under way and
// whether it keeps the disks. The caller writes it before the tombstone.
func NoteStrandedDisksDeleted(ctx context.Context, db *corrosion.Client, reporter, vmName, createdAt string, keepDisks bool, now time.Time) error {
	open, err := corrosion.ListHealthConditions(ctx, db, false)
	if err != nil {
		return err
	}
	var errs []error
	for _, row := range open {
		if row.Evaluator != DiskMissingEvaluator || row.Code != CondVMDiskStranded || row.SubjectKind != "vm" ||
			!strings.HasPrefix(row.SubjectID, vmName+"@") {
			continue
		}
		var ev StrandedDisks
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM != vmName {
			continue // an unreadable record is left alone by its host too
		}
		ev.Deleted = &StrandedDeletion{Incarnation: createdAt, KeepDisks: keepDisks, At: now.UTC().Format(time.RFC3339Nano)}
		if err := writeStranded(ctx, db, reporter, row, true, ev, now); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", row.SubjectID, err))
		}
	}
	return errors.Join(errs...)
}

// decisionBefore reports whether a decision stamped at preceded deleted by no
// more than strandedDeletionWindow.
func decisionBefore(at string, deleted time.Time) bool {
	t, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		return false
	}
	return !deleted.Before(t.Add(-strandedDeletionSlack)) && !deleted.After(t.Add(strandedDeletionWindow))
}

// tendDeletedVMStranded decides this host's record of name's disks once no
// live row of name exists, and returns the entries the record keeps: nil
// resolves it.
func (r *Reconciler) tendDeletedVMStranded(ctx context.Context, name string, ev StrandedDisks) []StrandedDisk {
	createdAt, deletedAt, err := corrosion.GetTombstonedVMDeletion(ctx, r.db, name)
	if err != nil {
		return ev.Disks
	}
	deleted, okDeleted := corrosion.ParseUpdatedAt(deletedAt)
	dec := ev.Deleted
	if createdAt == "" || !okDeleted || dec == nil || dec.Incarnation != createdAt || !decisionBefore(dec.At, deleted) {
		if createdAt != "" && okDeleted && r.now().Sub(deleted) < strandedDeletionWindow {
			return ev.Disks // the delete's decision may still be on its way
		}
		slog.Info("reconciler: vm_disk_stranded resolved — the VM was deleted; its disk copies here follow the retention for a deleted VM's",
			"vm", name)
		return nil
	}
	if dec.KeepDisks {
		slog.Info("reconciler: vm_disk_stranded resolved — the VM was deleted with --keep-disks; its disk copies here are kept, and follow the retention for a deleted VM's",
			"vm", name)
		return nil
	}
	if r.virt == nil || !r.domainAbsentOrDeadLeftover(name) {
		slog.Debug("reconciler: a deleted VM's disks here wait: a domain of its name is live here, or cannot be read", "vm", name)
		return ev.Disks
	}
	rows, err := corrosion.VMIncarnationDisks(ctx, r.db, name, createdAt)
	if err != nil {
		return ev.Disks
	}
	recorded := map[string]bool{}
	for _, d := range rows {
		recorded[d.Path] = true
	}
	lastWrite := deleted.Add(tombstonePrecision) // the latest write the deleted VM can have made
	var kept []StrandedDisk
	for _, d := range ev.Disks {
		if d.Incarnation != createdAt || !recorded[d.Path] {
			slog.Warn("reconciler: keeping a disk of a deleted VM's name that is not the deleted VM's; it follows the retention for a deleted VM's",
				"vm", name, "path", d.Path, "copy", d.Copy, "recorded_for", d.Incarnation, "deleted", createdAt)
			continue
		}
		if !r.removeDeletedVMDisk(ctx, name, d, lastWrite) {
			kept = append(kept, d)
		}
	}
	r.removeDeletedVMSeed(name, lastWrite)
	return kept
}

// removeDeletedVMDisk removes the file of d, an entry of name's deleted
// incarnation, and reports whether the record is done with the entry: it is
// removed, gone, or kept for good. false keeps the entry for the next pass.
func (r *Reconciler) removeDeletedVMDisk(ctx context.Context, name string, d StrandedDisk, deleted time.Time) bool {
	p := d.Path
	if d.Copy != "" {
		if from, _, ok := parseSupersededName(d.Copy); !ok || from != d.Path {
			slog.Warn("reconciler: keeping a recorded copy that is not named as a copy of its disk", "vm", name, "path", d.Path, "copy", d.Copy)
			return true
		}
		p = d.Copy
	}
	fi, err := lstatSetAside(p)
	if os.IsNotExist(err) {
		return true
	}
	if err != nil {
		return false
	}
	if !fi.Mode().IsRegular() {
		slog.Warn("reconciler: keeping a deleted VM's disk path that is not a regular file", "vm", name, "path", p)
		return true
	}
	if fi.ModTime().After(deleted) {
		// Not the deleted VM's last write: a VM of the name being created
		// here again writes its disk before its row.
		return false
	}
	refs, err := corrosion.DisksReferencingPath(ctx, r.db, p)
	if err != nil {
		return false
	}
	if len(refs) > 0 {
		slog.Warn("reconciler: keeping a deleted VM's disk that a live disk record references", "vm", name, "path", p, "referenced_by", refs[0].VMName)
		return true
	}
	if err := removeSetAside(p); err != nil && !os.IsNotExist(err) {
		slog.Warn("reconciler: could not remove a deleted VM's disk left here by a failover", "vm", name, "path", p, "error", err)
		return false
	}
	slog.Warn("reconciler: removed a deleted VM's disk left here by a failover; its delete freed its disks",
		"vm", name, "path", p, "disk", d.Disk)
	return true
}

// removeDeletedVMSeed removes name's cloud-init seed here, unless it was
// written after the VM's tombstone (a VM of the name being created again).
func (r *Reconciler) removeDeletedVMSeed(name string, deleted time.Time) {
	if r.dataDir == "" {
		return
	}
	iso, err := lv.SafeCloudInitISOPath(r.dataDir, name)
	if err != nil {
		return
	}
	fi, err := os.Lstat(iso)
	if err != nil || !fi.Mode().IsRegular() || fi.ModTime().After(deleted) {
		return
	}
	if err := os.Remove(iso); err != nil && !os.IsNotExist(err) {
		slog.Warn("reconciler: could not remove a deleted VM's cloud-init seed", "vm", name, "path", iso, "error", err)
		return
	}
	slog.Info("reconciler: removed a deleted VM's cloud-init seed left here by a failover", "vm", name, "path", iso)
}
