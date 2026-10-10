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

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Retention of superseded disk copies.
//
// A failover start sets an old copy of a host-local disk aside as
// <path>.superseded-<time> (superseded_disk.go) rather than deleting it, and
// a host that comes back after a failover moved its VM elsewhere sets the
// VM's real disk aside the same way (stranded_disk.go). Each copy is an
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
}

// supersededHoldStates are the VM states that hold a copy: a failover start
// that failed (error) or is still under way (pending, starting).
var supersededHoldStates = map[string]bool{"error": true, "pending": true, "starting": true}

// supersededDirs is where set-aside copies can be: next to every host-local
// disk path recorded anywhere (the same path names a file on every host), and
// the image store's disk directory, which holds the disks of deleted VMs too.
func supersededDirs(ctx context.Context, db *corrosion.Client, dataDir string) ([]string, error) {
	seen := map[string]bool{filepath.Join(dataDir, "disks"): true}
	rows, err := db.Query(ctx, `SELECT DISTINCT path FROM vm_disks
		WHERE deleted_at IS NULL AND path != '' AND storage_type IN ('', 'local', 'dir')`)
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

// ListSupersededDisks lists the set-aside disk copies on this host, oldest
// first.
func ListSupersededDisks(ctx context.Context, db *corrosion.Client, dataDir string) ([]SupersededCopy, error) {
	dirs, err := supersededDirs(ctx, db, dataDir)
	if err != nil {
		return nil, fmt.Errorf("list disk directories: %w", err)
	}
	recorded, err := strandedCopies(ctx, db)
	if err != nil {
		return nil, fmt.Errorf("read the recorded stranded disks: %w", err)
	}
	var out []SupersededCopy
	for _, dir := range dirs {
		matches, err := filepath.Glob(filepath.Join(dir, "*"+supersededInfix+"*"))
		if err != nil {
			return nil, err
		}
		for _, p := range matches {
			diskPath, at, ok := parseSupersededName(p)
			if !ok {
				continue
			}
			fi, err := os.Lstat(p)
			if err != nil || !fi.Mode().IsRegular() {
				continue
			}
			c := SupersededCopy{Path: p, DiskPath: diskPath, SetAsideAt: at, SizeBytes: fi.Size()}
			refs, err := corrosion.DisksReferencingPath(ctx, db, diskPath)
			if err != nil {
				return nil, fmt.Errorf("read the disks at %s: %w", diskPath, err)
			}
			for _, d := range refs {
				if d.Path != diskPath {
					continue
				}
				vm, err := corrosion.GetVM(ctx, db, d.VMName)
				if err != nil {
					return nil, fmt.Errorf("read VM %s: %w", d.VMName, err)
				}
				if vm == nil {
					continue
				}
				c.VM, c.VMState = vm.Name, vm.State
				if supersededHoldStates[vm.State] {
					c.Held = fmt.Sprintf("VM %s is %s on %s", vm.Name, vm.State, vm.HostName)
				}
				break
			}
			if c.VM == "" {
				// A copy recorded for a VM whose disk has since moved to
				// another path (stranded_disk.go) is still that VM's.
				if vm := recorded[p]; vm != "" {
					if row, err := corrosion.GetVM(ctx, db, vm); err != nil {
						return nil, fmt.Errorf("read VM %s: %w", vm, err)
					} else if row != nil {
						c.VM, c.VMState = row.Name, row.State
					}
				}
			}
			if c.VM != "" {
				c.Retained = fmt.Sprintf("VM %s exists; only an operator removes this copy", c.VM)
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
	return out, nil
}

// PurgeSupersededDisks removes the set-aside copies on this host that are
// older than olderThan at now and neither retained nor held, and returns
// them. olderThan 0 removes every such copy. It is both the hourly sweep and
// a bare `--purge`.
func PurgeSupersededDisks(ctx context.Context, db *corrosion.Client, dataDir string, olderThan time.Duration, now time.Time) ([]SupersededCopy, error) {
	copies, err := ListSupersededDisks(ctx, db, dataDir)
	if err != nil {
		return nil, err
	}
	var removed []SupersededCopy
	for _, c := range copies {
		if c.Held != "" || c.Retained != "" || now.Sub(c.SetAsideAt) < olderThan {
			continue
		}
		if err := os.Remove(c.Path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return removed, fmt.Errorf("remove %s: %w", c.Path, err)
		}
		slog.Info("removed a superseded disk copy", "path", c.Path, "disk", c.DiskPath, "vm", c.VM,
			"set_aside_at", c.SetAsideAt.Format(time.RFC3339), "bytes", c.SizeBytes)
		removed = append(removed, c)
	}
	return removed, nil
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
			return removed, fmt.Errorf("%s is not a superseded disk copy on this host (lv host superseded-disks lists them)", p)
		}
		if c.Held != "" {
			return removed, fmt.Errorf("%s is held (%s): a failed or unfinished start may need it", p, c.Held)
		}
		if err := os.Remove(c.Path); err != nil && !os.IsNotExist(err) {
			return removed, fmt.Errorf("remove %s: %w", c.Path, err)
		}
		slog.Warn("removed a superseded disk copy by operator request", "path", c.Path, "disk", c.DiskPath, "vm", c.VM,
			"retained", c.Retained, "set_aside_at", c.SetAsideAt.Format(time.RFC3339), "bytes", c.SizeBytes)
		dropStrandedCopy(ctx, db, "", c.Path, time.Now())
		removed = append(removed, c)
	}
	return removed, nil
}
