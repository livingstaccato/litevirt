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
// <path>.superseded-<time> (superseded_disk.go) rather than deleting it: it
// may hold the only copy of data an operator wants back. Kept forever, they
// pile up, one full disk per failover onto a host that once ran the VM.
//
// The rule, chosen as the simplest that never removes a copy someone may
// still need:
//
//   - a copy is removed once it is older than the retention
//     (superseded_disk_retention_days, default 7; 0 keeps every copy), by the
//     host that holds it, on an hourly sweep;
//   - except while the VM whose disk it was set aside from is in error,
//     pending or starting: a failover start that failed, or one still under
//     way, may need the copy put back. It is removed on the first sweep after
//     the VM leaves that state.
//
// Its age is the time in its name, which is when it was set aside, not the
// file's mtime (a rename keeps the old disk's last write). Rejected
// alternatives: keeping the newest K per disk can delete a copy minutes old
// when a VM fails over back and forth, and each copy is an independent line
// of the VM's data (every failover rebuilds the disk from its image), so the
// newest is not a superset of the older ones.
//
// `lv host superseded-disks <host>` lists them and, with --purge, removes the
// ones not held, whatever their age.

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
	Held       string // why it is kept whatever its age; "" when it is not held
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
// older than olderThan at now and not held, and returns them. olderThan 0
// removes every copy that is not held.
func PurgeSupersededDisks(ctx context.Context, db *corrosion.Client, dataDir string, olderThan time.Duration, now time.Time) ([]SupersededCopy, error) {
	copies, err := ListSupersededDisks(ctx, db, dataDir)
	if err != nil {
		return nil, err
	}
	var removed []SupersededCopy
	for _, c := range copies {
		if c.Held != "" || now.Sub(c.SetAsideAt) < olderThan {
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
