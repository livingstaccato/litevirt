package health

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/storage"
)

// Retention of superseded disk copies.
//
// A failover start sets an old copy of a host-local disk aside as
// <path>.superseded-<time> (superseded_disk.go) rather than deleting it, and
// a host that comes back after a failover moved its VM elsewhere sets the
// VM's real disk aside the same way (stranded_disk.go), also once the VM is
// deleted (deleted_vm_residue.go). Each copy is an
// independent line of the VM's data — every failover rebuilds the disk from
// its image — so any one of them can be the only copy of what the VM held
// before a failover.
//
// The rule, chosen as the simplest that never removes a copy someone may
// still need:
//
//   - while the VM whose disk it was set aside from exists, in any state, the
//     copy is retained: the hourly sweep never removes it, and neither does a
//     bare `--purge`. Only an operator removes it, by naming it
//     (`lv host superseded-disks <host> --remove <copy>`), or puts it back
//     (`--restore <copy>`);
//   - while that VM is in error, pending or starting the copy is also held: a
//     failover start that failed, or one still under way, may need it put
//     back, so not even a named removal takes it;
//   - once the VM is gone, the copy is removed when it is older than the
//     retention (superseded_disk_retention_days, default 7; 0 keeps every
//     copy), by the host that holds it, on the hourly sweep.
//
// Before this rule a copy was held only while its VM was in error, pending or
// starting, so seven days after the VM was running again on a disk rebuilt
// blank the sweep deleted the only copy of its data from before the failover.
//
// Its age is the time in its name, which is when it was set aside, not the
// file's mtime (a rename keeps the old disk's last write). Rejected
// alternatives: keeping the newest K per disk can delete a copy minutes old
// when a VM fails over back and forth, and the newest is not a superset of
// the older ones.
//
// The rule is read from the VM rows at the time of the sweep: nothing is
// written to mark a copy retained, so a host on an older release, which holds
// copies only by the old rule, is not told to delete anything by this one.
//
// `lv host superseded-disks <host>` lists them; --purge removes the ones
// neither retained nor held, whatever their age.

// supersededTimeLayout is the time in a set-aside copy's name.
const supersededTimeLayout = "20060102T150405.000000000Z"

const supersededInfix = ".superseded-"

// supersededName is where a transfer sets the file at path aside, at time at.
func supersededName(path string, at time.Time) string {
	return path + supersededInfix + at.UTC().Format(supersededTimeLayout)
}

// SupersededName is where an operator moves the file at path aside, now, so
// that `lv host superseded-disks` lists and keeps it.
func SupersededName(path string, now time.Time) string { return supersededName(path, now) }

// parseSupersededName splits a set-aside copy's name into the disk path it
// came from and when; ok=false for any other name.
func parseSupersededName(name string) (diskPath string, at time.Time, ok bool) {
	i := strings.LastIndex(name, supersededInfix)
	if i <= 0 {
		return "", time.Time{}, false
	}
	at, err := time.Parse(supersededTimeLayout, name[i+len(supersededInfix):])
	if err != nil {
		return "", time.Time{}, false
	}
	return name[:i], at, true
}

// SupersededCopy is one disk copy a failover start set aside on this host.
type SupersededCopy struct {
	Path       string    // the copy
	DiskPath   string    // the disk path it was set aside from
	SetAsideAt time.Time // when
	SizeBytes  int64
	VM         string // the VM whose disk is at DiskPath now; "" when none is
	VMState    string
	Held       string // why it is kept even from a named removal; "" when it is not held
	// Retained says why the sweep and a bare purge keep it whatever its age:
	// its VM still exists. "" when nothing retains it.
	Retained string
	// DeletedVM is the deleted VM whose disk it was set aside from, when no
	// VM has a disk at that path now; "" otherwise. Never a VM to restore to.
	DeletedVM string
}

// supersededHoldStates are the VM states that hold a copy: a failover start
// that failed (error) or is still under way (pending, starting). A start an
// operator cancelled holds them too (start_cancelled.go).
var supersededHoldStates = map[string]bool{"error": true, "pending": true, "starting": true}

// supersededDirs is where set-aside copies can be: next to every host-local
// disk path recorded anywhere (the same path names a file on every host), and
// the image store's disk directory, which holds the disks of deleted VMs too.
// A directory only a deleted VM's disks used (a pool directory, say) is
// scanned too: a copy there is a deleted VM's like any other, listed and
// swept by the same retention (lab2-drain anomaly 7).
func supersededDirs(ctx context.Context, db *corrosion.Client, dataDir string) ([]string, error) {
	seen := map[string]bool{filepath.Join(dataDir, "disks"): true}
	rows, err := db.Query(ctx, `SELECT DISTINCT path FROM vm_disks
		WHERE path != '' AND storage_type IN ('', 'local', 'dir')`)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		seen[filepath.Dir(r.String("path"))] = true
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs, nil
}

// deletedVMOfPath is the VM a deleted disk row at path belonged to, "" when
// none does.
func deletedVMOfPath(ctx context.Context, db *corrosion.Client, path string) (string, error) {
	rows, err := db.Query(ctx, `SELECT vm_name FROM vm_disks WHERE path = ? AND deleted_at IS NOT NULL
		ORDER BY deleted_at DESC LIMIT 1`, path)
	if err != nil || len(rows) == 0 {
		return "", err
	}
	return rows[0].String("vm_name"), nil
}

// ListSupersededDisks lists the set-aside disk copies on this host, oldest
// first. A directory or copy whose storage does not answer
// (superseded_bound.go) fails the listing with that no-answer: a list
// missing the copies there would read as complete (replica pruning keeps
// every listed copy's backing file).
func ListSupersededDisks(ctx context.Context, db *corrosion.Client, dataDir string) ([]SupersededCopy, error) {
	out, noAnswer, err := listSupersededDisks(ctx, db, dataDir)
	if err != nil {
		return nil, err
	}
	if noAnswer != nil {
		return nil, fmt.Errorf("list superseded disk copies: %w", noAnswer)
	}
	return out, nil
}

// listSupersededDisks is ListSupersededDisks that goes on past storage that
// does not answer: it lists the copies it could see, and returns the first
// no-answer separately.
func listSupersededDisks(ctx context.Context, db *corrosion.Client, dataDir string) (out []SupersededCopy, noAnswer, err error) {
	dirs, err := supersededDirs(ctx, db, dataDir)
	if err != nil {
		return nil, nil, fmt.Errorf("list disk directories: %w", err)
	}
	recorded, err := strandedCopies(ctx, db)
	if err != nil {
		return nil, nil, fmt.Errorf("read the recorded stranded disks: %w", err)
	}
	cancelled, err := cancelledStarts(ctx, db)
	if err != nil {
		return nil, nil, fmt.Errorf("read the cancelled starts: %w", err)
	}
	unanswered := func(err error) {
		slog.Warn("superseded disk copies: storage does not answer; what is there is not looked at", "error", err)
		if noAnswer == nil {
			noAnswer = err
		}
	}
	for _, dir := range dirs {
		matches, err := globSetAside(dir)
		if err != nil {
			if storage.IsFSNoAnswer(err) {
				unanswered(err)
				continue
			}
			return nil, nil, err
		}
		for _, p := range matches {
			diskPath, at, ok := parseSupersededName(p)
			if !ok {
				continue
			}
			fi, err := lstatSetAside(p)
			if storage.IsFSNoAnswer(err) {
				unanswered(err)
				continue
			}
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			c := SupersededCopy{Path: p, DiskPath: diskPath, SetAsideAt: at, SizeBytes: fi.Size()}
			refs, err := corrosion.DisksReferencingPath(ctx, db, diskPath)
			if err != nil {
				return nil, nil, fmt.Errorf("read the disks at %s: %w", diskPath, err)
			}
			for _, d := range refs {
				if d.Path != diskPath {
					continue
				}
				vm, err := corrosion.GetVM(ctx, db, d.VMName)
				if err != nil {
					return nil, nil, fmt.Errorf("read VM %s: %w", d.VMName, err)
				}
				if vm == nil {
					continue
				}
				c.VM, c.VMState = vm.Name, vm.State
				if supersededHoldStates[vm.State] {
					c.Held = fmt.Sprintf("VM %s is %s on %s", vm.Name, vm.State, vm.HostName)
				} else {
					c.Held = startCancelledHeld(cancelled, vm)
				}
				break
			}
			if c.VM == "" {
				// A copy recorded for a VM whose disk has since moved to
				// another path (stranded_disk.go) is still that VM's.
				if vm := recorded[p]; vm != "" {
					if row, err := corrosion.GetVM(ctx, db, vm); err != nil {
						return nil, nil, fmt.Errorf("read VM %s: %w", vm, err)
					} else if row != nil {
						c.VM, c.VMState = row.Name, row.State
					}
				}
			}
			if c.VM != "" {
				c.Retained = fmt.Sprintf("VM %s exists; only an operator removes this copy", c.VM)
			} else {
				// Its VM was deleted: shown as such, and swept by the
				// retention.
				gone, err := deletedVMOfPath(ctx, db, diskPath)
				if err != nil {
					return nil, nil, fmt.Errorf("read the deleted disks at %s: %w", diskPath, err)
				}
				c.DeletedVM = gone
			}
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].SetAsideAt.Equal(out[j].SetAsideAt) {
			return out[i].SetAsideAt.Before(out[j].SetAsideAt)
		}
		return out[i].Path < out[j].Path
	})
	return out, noAnswer, nil
}

// KeptCopy is a disk an earlier VM of a name was deleted with and its delete
// kept, which a create of the name moved off its path (<path>.kept-<time>,
// SetAsideBeforeCreate), or that VM's cloud-init seed, moved the same way
// (Seed). Nothing on the host removes it, and no purge, removal or restore
// of set-aside copies takes it.
type KeptCopy struct {
	Path      string    // the file
	DiskPath  string    // the path it was moved from
	MovedAt   time.Time // when
	SizeBytes int64
	Seed      bool // a cloud-init seed (it can hold user-data), not a disk
}

// ListKeptDisks lists the .kept- files on this host, where set-aside copies
// can be (supersededDirs), the .kept- seeds in <data_dir>/cloudinit, and the
// seeds of deleted VMs kept where they were (keptSeedsInPlace), oldest
// first. Storage that does not answer fails the listing, as it fails
// ListSupersededDisks.
func ListKeptDisks(ctx context.Context, db *corrosion.Client, dataDir string) ([]KeptCopy, error) {
	dirs, err := supersededDirs(ctx, db, dataDir)
	if err != nil {
		return nil, fmt.Errorf("list disk directories: %w", err)
	}
	seedDir := filepath.Join(dataDir, "cloudinit")
	dirs = append(dirs, seedDir)
	glob := supersededGlob
	var out []KeptCopy
	for _, dir := range dirs {
		pattern := filepath.Join(dir, "*"+keptInfix+"*")
		matches, err := storage.Bounded("list the kept disks in", dir, func() ([]string, error) { return glob(pattern) })
		if err != nil {
			return nil, fmt.Errorf("list kept disks: %w", err)
		}
		for _, p := range matches {
			i := strings.LastIndex(p, keptInfix)
			at, perr := time.Parse(supersededTimeLayout, p[i+len(keptInfix):])
			if i <= 0 || perr != nil {
				continue
			}
			fi, err := lstatSetAside(p)
			if storage.IsFSNoAnswer(err) {
				return nil, fmt.Errorf("list kept disks: %w", err)
			}
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			out = append(out, KeptCopy{Path: p, DiskPath: p[:i], MovedAt: at, SizeBytes: fi.Size(), Seed: dir == seedDir})
		}
	}
	inPlace, err := keptSeedsInPlace(ctx, db, seedDir)
	if err != nil {
		return nil, fmt.Errorf("list kept seeds: %w", err)
	}
	out = append(out, inPlace...)
	sort.Slice(out, func(i, j int) bool {
		if !out[i].MovedAt.Equal(out[j].MovedAt) {
			return out[i].MovedAt.Before(out[j].MovedAt)
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// keptHint is what a refusal adds for a .kept- file named as a copy.
func keptHint(p string) string {
	if !strings.Contains(filepath.Base(p), keptInfix) {
		return ""
	}
	return "; it is a disk a deleted VM was kept with, which only an operator removes, by hand"
}

// PurgeSupersededDisks removes the set-aside copies on this host that are
// older than olderThan at now and neither retained nor held, and returns
// them. olderThan 0 removes every such copy. It is both the hourly sweep and
// a bare `--purge`. Storage that does not answer holds none of it: the copies
// under it are left alone, the others are swept, and the no-answer is
// returned once they are. A copy keptHold (when not nil) reports held — a
// disk a delete kept backs on it — is never removed (re-review P5).
func PurgeSupersededDisks(ctx context.Context, db *corrosion.Client, dataDir string, olderThan time.Duration, now time.Time,
	keptHold func(context.Context, string) (bool, string)) ([]SupersededCopy, error) {
	copies, noAnswer, err := listSupersededDisks(ctx, db, dataDir)
	if err != nil {
		return nil, err
	}
	if keptHold != nil {
		var keep []SupersededCopy
		for _, c := range copies {
			if held, why := keptHold(ctx, c.Path); held {
				slog.Info("superseded disk copy kept: a disk a delete kept backs on it", "path", c.Path, "why", why)
				continue
			}
			keep = append(keep, c)
		}
		copies = keep
	}
	removed, err := purgeSuperseded(copies, olderThan, now)
	if err == nil && noAnswer != nil {
		err = fmt.Errorf("the copies under storage that does not answer were not looked at: %w", noAnswer)
	}
	return removed, err
}

// purgeSuperseded removes the copies of copies the purge may remove. A
// removal that does not answer is skipped, not waited on and not counted,
// and the first such no-answer is returned once the rest are done.
func purgeSuperseded(copies []SupersededCopy, olderThan time.Duration, now time.Time) (removed []SupersededCopy, noAnswer error) {
	for _, c := range copies {
		if c.Held != "" || c.Retained != "" || now.Sub(c.SetAsideAt) < olderThan {
			continue
		}
		if err := removeSetAside(c.Path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			if storage.IsFSNoAnswer(err) {
				// Nothing is removed on a no-answer; the copies after it,
				// in directories that answer, are still swept this pass.
				if noAnswer == nil {
					noAnswer = fmt.Errorf("remove %s: %w", c.Path, err)
				}
				continue
			}
			return removed, fmt.Errorf("remove %s: %w", c.Path, err)
		}
		slog.Info("removed a superseded disk copy", "path", c.Path, "disk", c.DiskPath, "vm", c.VM,
			"set_aside_at", c.SetAsideAt.Format(time.RFC3339), "bytes", c.SizeBytes)
		removed = append(removed, c)
	}
	return removed, noAnswer
}

// RemoveSupersededDisks removes the set-aside copies on this host named by
// paths, retained or not: it is the operator's explicit removal
// (`lv host superseded-disks <host> --remove <copy>`). A name that is not a
// set-aside copy on this host, or a copy held by a failed or unfinished
// start, is refused, and nothing named after it is removed.
func RemoveSupersededDisks(ctx context.Context, db *corrosion.Client, dataDir string, paths []string) ([]SupersededCopy, error) {
	copies, err := ListSupersededDisks(ctx, db, dataDir)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]SupersededCopy, len(copies))
	for _, c := range copies {
		byPath[c.Path] = c
	}
	var removed []SupersededCopy
	for _, p := range paths {
		c, ok := byPath[filepath.Clean(p)]
		if !ok {
			return removed, fmt.Errorf("%s is not a superseded disk copy on this host (lv host superseded-disks lists them)%s", p, keptHint(p))
		}
		if c.Held != "" {
			return removed, fmt.Errorf("%s is held (%s): a failed or unfinished start may need it", p, c.Held)
		}
		if err := removeSetAside(c.Path); err != nil && !os.IsNotExist(err) {
			return removed, fmt.Errorf("remove %s: %w", c.Path, err)
		}
		slog.Warn("removed a superseded disk copy by operator request", "path", c.Path, "disk", c.DiskPath, "vm", c.VM,
			"retained", c.Retained, "set_aside_at", c.SetAsideAt.Format(time.RFC3339), "bytes", c.SizeBytes)
		dropStrandedCopy(ctx, db, "", c.Path, time.Now())
		removed = append(removed, c)
	}
	return removed, nil
}

// keptSeedsInPlace lists the seeds in seedDir (<data_dir>/cloudinit/<vm>.iso)
// of VMs that no longer exist: no live row of the name here, and a tombstone
// of it. A seed stamped for another VM of the name is not the deleted VM's
// and is left out; an unstamped one (written before seeds were stamped), one
// whose stamp is empty or cannot be read, and one stamped for the deleted
// incarnation are listed. Such a seed is one a
// delete kept (`lv rm --keep-disks`, or a disk left at its path on a
// failover's old host), or one an earlier release left; it can hold
// user-data, and nothing on the host removes it. MovedAt is its mtime.
func keptSeedsInPlace(ctx context.Context, db *corrosion.Client, seedDir string) ([]KeptCopy, error) {
	matches, err := storage.Bounded("list the seeds in", seedDir, func() ([]string, error) {
		return supersededGlob(filepath.Join(seedDir, "*.iso"))
	})
	if err != nil {
		return nil, err
	}
	var out []KeptCopy
	for _, iso := range matches {
		name := strings.TrimSuffix(filepath.Base(iso), ".iso")
		if name == "" || strings.HasPrefix(name, ".") {
			continue
		}
		fi, err := lstatSetAside(iso)
		if storage.IsFSNoAnswer(err) {
			return nil, err
		}
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		live, err := corrosion.GetVM(ctx, db, name)
		if err != nil {
			return nil, err
		}
		if live != nil {
			continue
		}
		createdAt, spec, err := corrosion.GetTombstonedVM(ctx, db, name)
		if err != nil {
			return nil, err
		}
		if createdAt == "" {
			continue
		}
		// Left out only when the stamp names another VM: an empty or
		// unreadable stamp (a power cut while it was written) is an owner
		// not known, and the seed stays listed (lab 2, abort proof).
		stamp, stamped, err := cloudinit.SeedOwner(iso)
		if err == nil && stamped && stamp != "" && stamp != cloudinit.SpecUUID(spec) {
			continue
		}
		out = append(out, KeptCopy{Path: iso, DiskPath: iso, MovedAt: fi.ModTime(), SizeBytes: fi.Size(), Seed: true})
	}
	return out, nil
}
