package health

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/storage"
)

// A deleted VM's leftovers on a host a failover moved it off.
//
// A VM restarted elsewhere by a failover leaves its real disk on the failed
// host, which sets it aside once it is back (stranded_disk.go), and its
// cloud-init seed (<data_dir>/cloudinit/<name>.iso). `lv rm` runs on the VM's
// owner and frees what is there. On lab 1 (hdv-1, 2026-10-15) the old host
// kept both, with vm_disk_stranded raised, until they were removed by hand.
//
// Once its replica holds the VM's tombstone and no live row, the host the
// record names, on its own reconciler pass — a host that was down during the
// delete, once it is back:
//
//   - keeps every copy already set aside. A copy is the only line of the
//     VM's data from before a failover, and the retention for a deleted VM's
//     copies (superseded_retention.go, superseded_disk_retention_days) is the
//     undo for `lv rm`: the hourly sweep removes it when it is old enough;
//   - leaves a disk the delete kept at its path, notes it (NoteKeptDisks),
//     and drops its entry: every disk after `lv rm --keep-disks` (the record
//     says so, written by the deleting host before its tombstone:
//     MarkStrandedForDelete), one its tombstoned row records
//     delete_with_vm=0, and one whose record does not say what the deleted
//     incarnation's delete decided (DeleteDecided: a delete by an earlier
//     release, a mark lost to a later write, a replica without the record);
//   - sets aside any other disk of that VM still at its path (the host was
//     down when the VM was deleted), by the rule the host sets one aside by while the
//     VM exists (setAsideStrandedFile), so it enters the same retention.
//     Nothing is deleted. Only an entry recorded for the incarnation the
//     tombstone names (created_at), at one of the disk paths the VM's rows
//     record, is set aside; any other file stays where it is. The replica is
//     read again for a live row of the name, and the domain's state again,
//     immediately before the rename: a VM created again under the name is
//     never touched (noLiveRow). A path that reads as missing keeps its entry
//     while its directory is absent or empty, as a volume not mounted yet
//     reads (mayBeUnmounted); missing from a directory that lists other files,
//     it is gone, and its entry goes;
//   - removes the VM's own cloud-init seed: one stamped with the deleted VM's
//     spec uuid (cloudinit/seed_owner.go), and only while no domain of the
//     name is live here, and only when the delete kept no disk here: after
//     `lv rm --keep-disks`, or with a disk left at its path as one the delete
//     kept, the seed is kept with them. An unstamped seed (written before seeds were
//     stamped), or one of another VM of the name, is left alone, and is never
//     reused by another VM;
//   - resolves the record. It stays open while the disk at its path cannot be
//     set aside yet: a domain of the name is live here, the storage does not
//     answer, or the path reads as missing on what may be a volume not
//     mounted yet.
//
// Nothing here starts, stops, undefines or adopts a domain, and nothing is
// written to a replicated table but the record itself.

// tendDeletedVMStranded decides this host's record of name's disks once no
// live row of name exists, and returns the entries the record keeps: nil
// resolves it.
func (r *Reconciler) tendDeletedVMStranded(ctx context.Context, name string, ev StrandedDisks) []StrandedDisk {
	createdAt, spec, err := corrosion.GetTombstonedVM(ctx, r.db, name)
	if err != nil {
		return ev.Disks
	}
	if createdAt == "" || r.virt == nil {
		// No tombstone (a replica reseeded, or a name never seen), or no way
		// to tell whether a domain of the name is live: nothing is acted on.
		slog.Info("reconciler: vm_disk_stranded resolved — the VM was deleted; its disk copies here follow the retention for a deleted VM's",
			"vm", name)
		return nil
	}
	var recorded, keptByDelete map[string]bool
	var kept []StrandedDisk
	// deleteKept: the delete kept the VM's disks here (--keep-disks), or a
	// disk is left at its path as one it may have kept. The seed is then
	// kept too.
	deleteKept := ev.KeptByDelete
	for _, d := range ev.Disks {
		if d.Copy != "" {
			continue // the retention sweep's
		}
		if recorded == nil {
			rows, err := corrosion.VMIncarnationDisks(ctx, r.db, name, createdAt)
			if err != nil {
				return ev.Disks
			}
			recorded, keptByDelete = map[string]bool{}, map[string]bool{}
			for _, row := range rows {
				recorded[row.Path] = true
				if !row.DeleteWithVM {
					keptByDelete[row.Path] = true
				}
			}
		}
		// leave leaves the disk at its path and notes it here, so a create
		// of the name on this host moves it rather than clear it
		// (SetAsideBeforeCreate).
		leave := func(why string) {
			deleteKept = true
			if err := NoteKeptDisks(r.dataDir, name, []string{filepath.Clean(d.Path)}); err != nil {
				slog.Warn("reconciler: could not note a disk a delete kept; its record stays open", "vm", name, "path", d.Path, "error", err)
				kept = append(kept, d)
				return
			}
			slog.Info("reconciler: leaving a deleted VM's disk at its path: "+why, "vm", name, "path", d.Path)
		}
		if ev.KeptByDelete || keptByDelete[d.Path] {
			leave("the delete kept it (--keep-disks, or delete_with_vm=false)")
			continue
		}
		if d.Incarnation != createdAt || !recorded[d.Path] {
			slog.Warn("reconciler: leaving a file at a deleted VM's disk path that was not recorded for that VM",
				"vm", name, "path", d.Path, "recorded_for", d.Incarnation, "deleted", createdAt)
			continue
		}
		if !deleteKeptNothing(ev, createdAt) {
			leave("the record does not say whether the delete kept it (a delete by an earlier release, or its record lost or not here yet), so it is kept")
			continue
		}
		set, outcome := r.setAsideStrandedFile(ctx, name, d, func() bool { return r.noLiveRow(ctx, name) && r.domainAbsentOrDeadLeftover(name) })
		switch outcome {
		case setAsideMissing:
			if mayBeUnmounted(d.Path) {
				// Missing is not deleted: a volume not mounted (yet)
				// reads the same, and the disk comes back with it.
				kept = append(kept, d)
			}
		case setAsideBlocked:
			kept = append(kept, d)
		case setAsideDone:
			slog.Warn("reconciler: set aside the real disk of a deleted VM a failover left here; it follows the retention for a deleted VM's",
				"vm", name, "disk", d.Disk, "path", d.Path, "set_aside_to", set.Copy)
		}
	}
	if !deleteKept && r.domainAbsentOrDeadLeftover(name) {
		r.removeDeletedVMSeed(name, cloudinit.SpecUUID(spec))
	}
	if len(kept) == 0 {
		slog.Info("reconciler: vm_disk_stranded resolved — the VM was deleted; its disk copies here follow the retention for a deleted VM's",
			"vm", name)
	}
	return kept
}

// mayBeUnmounted reports whether a missing file at p may be on a volume not
// mounted (yet): its directory is absent, empty — an unmounted mount point is
// an empty directory — or cannot be listed. A directory that lists other
// files is mounted, and the file is gone.
func mayBeUnmounted(p string) bool {
	dir := filepath.Dir(p)
	ents, err := storage.Bounded("list", dir, func() ([]os.DirEntry, error) { return os.ReadDir(dir) })
	return err != nil || len(ents) == 0
}

// noLiveRow reports whether this host's replica holds no live row of name,
// read now. A VM of the name created again — on this host, its disk written
// before its row — is never set aside: once its row is here, the deleted-VM
// pass leaves the path alone. An unreadable row answers no.
func (r *Reconciler) noLiveRow(ctx context.Context, name string) bool {
	vm, err := corrosion.GetVM(ctx, r.db, name)
	return err == nil && vm == nil
}

// removeDeletedVMSeed removes name's cloud-init seed here when it is stamped
// as the deleted VM's, whose spec uuid is owner.
func (r *Reconciler) removeDeletedVMSeed(name, owner string) {
	if r.dataDir == "" || owner == "" {
		return
	}
	iso, err := lv.SafeCloudInitISOPath(r.dataDir, name)
	if err != nil {
		return
	}
	stamp, stamped, err := cloudinit.SeedOwner(iso)
	if err != nil || !stamped || stamp != owner {
		return
	}
	if err := cloudinit.RemoveSeed(iso); err != nil {
		slog.Warn("reconciler: could not remove a deleted VM's cloud-init seed", "vm", name, "path", iso, "error", err)
		return
	}
	slog.Info("reconciler: removed a deleted VM's cloud-init seed", "vm", name, "path", iso)
}

// keptInfix marks a disk an earlier VM of a name was deleted with and the
// operator kept (`lv rm --keep-disks`, or a disk recorded
// delete_with_vm=false), which a create of the name moved off the path its
// new disk takes: <path>.kept-<time>. Nothing removes it but an operator: it
// is neither a sweep candidate nor a set-aside copy for the retention.
const keptInfix = ".kept-"

// keptName is where a create moves the kept disk at path, at time at.
func keptName(path string, at time.Time) string {
	return path + keptInfix + at.UTC().Format(supersededTimeLayout)
}

// MovedBeforeCreate is a file a create of a VM moved off a path its debris
// sweep clears: To is where it is now.
type MovedBeforeCreate struct {
	Path, To string
	// Kept: the operator kept it with the deleted VM (To is a .kept- name,
	// never removed by the host); otherwise it is the real disk a failover
	// left here, set aside for the retention (.superseded-).
	Kept bool
}

// BeforeCreate is what SetAsideBeforeCreate did: Moved, the files it moved;
// MayBeUnmounted, the paths of the deleted VM's disks this host's record
// still lists that read as missing while their directory is absent, empty or
// cannot be listed (mayBeUnmounted). Their entries stay, and the create goes
// ahead: once such a directory is mounted, what it holds hides a file the
// create writes there.
type BeforeCreate struct {
	Moved          []MovedBeforeCreate
	MayBeUnmounted []string
}

// SetAsideBeforeCreate runs before a create of VM name on this host clears
// the files unlink, the debris sweep's candidates that no live disk row
// protects (grpcapi's protectedDiskPathsFrom; the sweep unlinks them next).
// Of those, it moves:
//
//   - a disk an earlier VM of the name was deleted with and that its delete
//     kept, to <path>.kept-<time>, which no sweep removes: one this host
//     noted (NoteKeptDisks: `lv rm --keep-disks`, a disk recorded
//     delete_with_vm=false); one the deleted VM's rows record
//     delete_with_vm=false, or record on this host, whose delete here did not
//     remove it; one this host's vm_disk_stranded record of the name lists
//     after `lv rm --keep-disks` (KeptByDelete), or without the deleted
//     incarnation's decision (DeleteDecided);
//   - the real disk a failover left here, which this host's open record still
//     lists at its path for the deleted incarnation (its created_at, at a path
//     its rows record), never set aside because the host was down when the VM
//     was deleted, to <path>.superseded-<time>, which follows the retention
//     for a deleted VM's copies: only once that incarnation's delete recorded
//     that it keeps nothing.
//
// Anything else in unlink is left to the sweep, as before. The record is
// updated: an entry moved, or one the delete kept (noted here, and left where
// it is), goes; one missing from a directory that lists other files goes; one
// missing while its directory may be a volume not mounted yet stays
// (mayBeUnmounted, returned in MayBeUnmounted), as does one at a path the
// sweep does not clear. hostPath maps a recorded path to this host's file.
//
// It refuses — and the sweep must not run — when a file in unlink is there
// but this host's replica is not trusted (it may not hold the delete's record
// yet), when what is at a path, or what this host knows of it, cannot be
// read, or when a move fails. A path that reads as missing (ENOENT, ENOTDIR),
// including one the reconciler's own pass moved first, is not there and
// refuses nothing.
func SetAsideBeforeCreate(ctx context.Context, db *corrosion.Client, dataDir, hostName, name string, unlink []string,
	hostPath func(string) string, trusted func() (bool, string), now time.Time) (BeforeCreate, error) {
	var present []string
	for _, p := range unlink {
		fi, err := lstatSetAside(p)
		if notThere(err) {
			continue
		}
		if err != nil {
			return BeforeCreate{}, fmt.Errorf("the create clears %s, left by an earlier VM %s, and what is there cannot be read (%v); "+
				"retry once that storage answers, or place the VM on another host", p, name, err)
		}
		if fi.Mode().IsRegular() {
			present = append(present, p)
		}
	}
	cannotTell := func(what string, err error) error {
		return fmt.Errorf("the create clears %s, left by an earlier VM %s, and %s cannot be read (%v); "+
			"retry, or place the VM on another host", strings.Join(present, ", "), name, what, err)
	}
	row, ev, had, err := readStranded(ctx, db, name, hostName)
	if err != nil {
		if len(present) == 0 {
			return BeforeCreate{}, nil
		}
		return BeforeCreate{}, cannotTell("this host's record of what a failover left of "+name, err)
	}
	open := had && row.Lifecycle != corrosion.ConditionResolved
	if len(present) == 0 && !open {
		return BeforeCreate{}, nil
	}
	if ok, why := trusted(); !ok {
		if len(present) == 0 {
			return BeforeCreate{}, nil // the record waits for the reconciler's pass
		}
		return BeforeCreate{}, fmt.Errorf("the create clears %s, left by an earlier VM %s, and this host's replica has not caught up "+
			"with the cluster (%s), so it cannot tell whether one is a disk the delete kept or a failover left here; "+
			"retry once the replica has caught up (shortly), or place the VM on another host", strings.Join(present, ", "), name, why)
	}
	clean := func(p string) string { return filepath.Clean(hostPath(p)) }
	note, err := keptNoteOf(dataDir, name)
	noted := note.Paths
	if err != nil {
		if len(present) == 0 {
			return BeforeCreate{}, nil
		}
		f, _ := keptDisksFile(dataDir, name)
		var ne *KeptDisksNoteError
		if errors.As(err, &ne) {
			err = ne.Err
		}
		return BeforeCreate{}, fmt.Errorf("the create clears %s, left by an earlier VM %s, and this host's note of the disks its "+
			"delete kept, %s, cannot be read (%v); repair or remove that file, then retry, or place the VM on another host",
			strings.Join(present, ", "), name, f, err)
	}
	createdAt, _, err := corrosion.GetTombstonedVM(ctx, db, name)
	var rows []corrosion.DiskRecord
	if err == nil && createdAt != "" {
		rows, err = corrosion.VMIncarnationDisks(ctx, db, name, createdAt)
	}
	if err != nil {
		if len(present) == 0 {
			return BeforeCreate{}, nil
		}
		return BeforeCreate{}, cannotTell("the deleted VM's disk records", err)
	}
	// kept: the delete kept it; here: recorded on this host, whose delete
	// did not remove it; recorded: a path the incarnation records.
	kept, here, recorded := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, p := range noted {
		kept[filepath.Clean(p)] = true
	}
	for _, d := range rows {
		recorded[d.Path] = true
		if !d.DeleteWithVM {
			kept[clean(d.Path)] = true
		}
		if d.HostName == hostName {
			here[clean(d.Path)] = true
		}
	}
	stranded := map[string]bool{}
	if had { // a resolved record still says what the delete kept
		for _, d := range ev.Disks {
			if d.Copy != "" || d.Path == "" {
				continue
			}
			switch {
			case ev.KeptByDelete:
				kept[clean(d.Path)] = true
			case open && createdAt != "" && d.Incarnation == createdAt && recorded[d.Path]:
				if deleteKeptNothing(ev, createdAt) {
					stranded[clean(d.Path)] = true
				} else {
					kept[clean(d.Path)] = true // the delete's decision is not here
				}
			}
		}
	}
	// A file a kept disk backs on is not moved: that breaks the kept disk's
	// chain, whose overlay names it by its path. The create refuses while
	// one is at a path it clears, before anything is moved.
	for _, u := range note.Under {
		for _, p := range present {
			if filepath.Clean(p) == u {
				f, _ := keptDisksFile(dataDir, name)
				return BeforeCreate{}, fmt.Errorf("the create clears %s, which a disk the deleted VM %s was kept with backs on (%s): "+
					"moving it would break that disk's backing chain, and the sweep would remove it; nothing was moved. "+
					"Move the kept disk and the files under it off that path yourself (then `qemu-img rebase -u -b <new path>` "+
					"the overlay above it), or place the VM on another host", p, name, f)
			}
		}
	}
	var moved []MovedBeforeCreate
	var movedKept []string
	movedFrom := map[string]bool{}
	for _, p := range present {
		cp := filepath.Clean(p)
		var to string
		isKept := kept[cp] || (!stranded[cp] && here[cp])
		switch {
		case isKept:
			to = keptName(p, now)
		case stranded[cp]:
			to = supersededName(p, now)
		default:
			continue
		}
		if err := renameSetAside(p, to); err != nil {
			if notThere(err) {
				continue // moved first, by the reconciler's pass
			}
			return BeforeCreate{Moved: moved}, fmt.Errorf("the create clears %s, a disk an earlier VM %s left, and moving it to %s failed (%v); "+
				"retry once that storage answers, or place the VM on another host", p, name, to, err)
		}
		movedFrom[cp] = true
		moved = append(moved, MovedBeforeCreate{Path: p, To: to, Kept: isKept})
		if isKept {
			movedKept = append(movedKept, cp)
			slog.Info("create: moved a disk an earlier VM of this name was deleted with and the operator kept off the path the create clears; nothing removes it",
				"vm", name, "path", p, "moved_to", to)
		} else {
			slog.Warn("create: set aside the real disk of a deleted VM of this name a failover left here; it follows the retention for a deleted VM's",
				"vm", name, "path", p, "set_aside_to", to)
		}
	}
	if err := forgetKeptDisks(dataDir, name, movedKept); err != nil {
		slog.Warn("create: could not update this host's note of the disks a delete kept", "vm", name, "error", err)
	}
	if !open {
		return BeforeCreate{Moved: moved}, nil
	}
	var keep, leftKept []StrandedDisk
	var unmounted []string
	for _, d := range ev.Disks {
		if d.Copy != "" {
			continue // the retention sweep's, as on the reconciler's pass
		}
		p := clean(d.Path)
		if movedFrom[p] {
			continue
		}
		if kept[p] {
			leftKept = append(leftKept, d) // stays where it is, noted below
			continue
		}
		if _, err := lstatSetAside(p); notThere(err) {
			if mayBeUnmounted(p) {
				keep = append(keep, d)
				unmounted = append(unmounted, p)
				slog.Warn("create: a deleted VM's disk path reads as missing and its directory is absent, empty or cannot be listed, as a volume not mounted yet reads; its record stays, and the create goes ahead",
					"vm", name, "path", p)
			}
			continue
		}
		keep = append(keep, d)
	}
	var notes []string
	for _, d := range leftKept {
		notes = append(notes, clean(d.Path))
	}
	if err := NoteKeptDisks(dataDir, name, notes); err != nil {
		slog.Warn("create: could not note the disks a delete kept here; their record stays open", "vm", name, "error", err)
		keep = append(keep, leftKept...)
	}
	done := BeforeCreate{Moved: moved, MayBeUnmounted: unmounted}
	if len(keep) == len(ev.Disks) {
		return done, nil
	}
	ev.Disks = keep
	if err := writeStranded(ctx, db, hostName, row, true, ev, now); err != nil {
		slog.Warn("create: could not update vm_disk_stranded", "vm", name, "error", err)
	}
	return done, nil
}

// notThere reports whether err says nothing is at a path: ENOENT, or ENOTDIR
// (a component of it is not a directory).
func notThere(err error) bool {
	return err != nil && (errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ENOTDIR))
}
