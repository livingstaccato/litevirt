package health

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
)

// Retention of the reconciler's firmware quarantines.
//
// The reconciler's leftover cleanup moves the NVRAM and swtpm tree of a
// shut-off leftover whose row names another host into
// <data_dir>/fwmig-quarantine/<vm>-reconciled-<unix>/ instead of wiping them
// (reconciler.go, quarantineLeftoverFirmware). Like a superseded disk copy
// (superseded_retention.go) it is a copy a cleanup set aside, and it may be
// the only copy of what the VM held, so it follows the same rule:
//
//   - while a VM of its name exists, in any state, it is retained: the hourly
//     sweep never removes it, and neither does a bare `--purge`. Only an
//     operator removes it, by naming it
//     (`lv host superseded-disks <host> --remove <dir>`);
//   - while a firmware move record on this host names the VM (marker, hold,
//     leftover, owed DISCARD), or the cluster has an open
//     firmware_migration_discard_owed for it, it is also held: the move's
//     owed state is unresolved, so not even a named removal takes it;
//   - once the VM is gone it is removed when older than the retention
//     (superseded_disk_retention_days; 0 keeps every one), by the host that
//     holds it, on the hourly sweep. TPM state holds sealed secrets, so it is
//     not kept forever once nothing can use it.
//
// Its age is the time in its name. A <vm>-reconciling-<uuid> directory is a
// quarantine the reconciler has not finished, and a <vm>-restoring-<uuid> one
// an interrupted restore (fwmig/staged.go). Both are listed and held: never
// removed by the sweep, a purge or --remove, since either may hold the VM's
// only firmware state while its own paths are empty (the guard refuses the
// VM's start meanwhile). The reconciler finishes a reconciling stage on a
// later pass: as the leftover's quarantine while the leftover domain is
// defined, and, once no domain of the name with that uuid is defined here, as
// an orphaned stage renamed to <vm>-reconciled-<unix>, which then takes the
// rule above (and --remove). While the VM's own domain is defined here with
// that uuid, `--restore <dir>` puts the state back; so does a rerun of an
// interrupted restore.
//
// The doctor's own quarantines (<vm>-<attempt>/) are not covered: they raise
// firmware_migration_quarantine and are removed by hand.

// reconciledInfix names a finished reconciler quarantine.
const reconciledInfix = "-reconciled-"

// reconcilingName is the directory the reconciler gathers vm's state in
// before it takes its final name.
func reconcilingName(vm, uuid string) string {
	return fwmig.StageName(vm, fwmig.StageReconciling, uuid)
}

var reconciledNameRe = regexp.MustCompile(`^(.+)-reconciled-([0-9]+)$`)

// ReconciledQuarantine is one reconciler firmware quarantine on this host.
type ReconciledQuarantine struct {
	Path       string
	VM         string
	SetAsideAt time.Time
	SizeBytes  int64
	VMState    string // "" when no VM of the name exists
	// Held says why even a named removal is refused; "" when it is not held.
	Held string
	// Retained says why the sweep and a bare purge keep it (its VM exists).
	Retained string
}

// ListReconciledQuarantines lists the reconciler's firmware quarantines on
// this host, oldest first.
func ListReconciledQuarantines(ctx context.Context, db *corrosion.Client, dataDir string) ([]ReconciledQuarantine, error) {
	dir := filepath.Join(dataDir, fwmig.QuarantineDir)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("list %s: %w", dir, err)
	}
	recs := fwmig.New(dataDir)
	var out []ReconciledQuarantine
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		q := ReconciledQuarantine{Path: filepath.Join(dir, e.Name())}
		if m := reconciledNameRe.FindStringSubmatch(e.Name()); m != nil {
			sec, err := strconv.ParseInt(m[2], 10, 64)
			if err != nil {
				continue
			}
			q.VM, q.SetAsideAt = m[1], time.Unix(sec, 0).UTC()
		} else if vm, kind, _, ok := fwmig.ParseStageName(e.Name()); ok {
			q.VM = vm
			if fi, err := e.Info(); err == nil {
				q.SetAsideAt = fi.ModTime().UTC()
			}
			if kind == fwmig.StageRestoring {
				q.Held = fmt.Sprintf("an interrupted restore of VM %s's firmware state; run --restore %s again (the VM's start is refused until it finishes)", vm, q.Path)
			} else {
				q.Held = fmt.Sprintf("an unfinished quarantine of VM %s's firmware state: the reconciler finishes it (as the leftover's, or, once no domain of it is defined here, as an orphaned stage that --remove then takes); while the VM's own domain is defined here its start is refused until --restore %s puts the state back", vm, q.Path)
			}
		} else {
			continue
		}
		q.SizeBytes = treeSize(q.Path)
		vm, err := corrosion.GetVM(ctx, db, q.VM)
		if err != nil {
			// That one entry is held, named with its error; the rest are
			// listed (fail closed for it alone).
			q.Held = fmt.Sprintf("VM %s's row cannot be read (%v); kept until it can", q.VM, err)
			out = append(out, q)
			continue
		}
		if vm != nil {
			q.VMState = vm.State
			q.Retained = fmt.Sprintf("VM %s exists; only an operator removes this quarantine", vm.Name)
		}
		if q.Held == "" {
			held, err := reconciledHeld(ctx, db, recs, q.VM)
			if err != nil {
				return nil, err
			}
			q.Held = held
		}
		out = append(out, q)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].SetAsideAt.Equal(out[j].SetAsideAt) {
			return out[i].SetAsideAt.Before(out[j].SetAsideAt)
		}
		return out[i].Path < out[j].Path
	})
	return out, nil
}

// reconciledHeld says why vm's firmware move state is unresolved: a record on
// this host that names it, or an open owed DISCARD anywhere. A record that
// cannot be read holds it too.
func reconciledHeld(ctx context.Context, db *corrosion.Client, recs *fwmig.Records, vm string) (string, error) {
	for _, r := range []struct {
		what string
		get  func(string) (bool, error)
	}{
		{"live firmware move marker", func(n string) (bool, error) { _, ok, err := recs.GetMarker(n); return ok, err }},
		{"live firmware move hold", func(n string) (bool, error) { _, ok, err := recs.GetHold(n); return ok, err }},
		{"firmware move leftover record", func(n string) (bool, error) { _, ok, err := recs.GetLeftover(n); return ok, err }},
	} {
		ok, err := r.get(vm)
		if err != nil {
			return fmt.Sprintf("the %s of VM %s on this host cannot be read (%v)", r.what, vm, err), nil
		}
		if ok {
			return fmt.Sprintf("a %s of VM %s is on this host", r.what, vm), nil
		}
	}
	owed, err := recs.ListOwedDiscards()
	if err != nil {
		return fmt.Sprintf("the owed DISCARD records on this host cannot be read (%v)", err), nil
	}
	for _, o := range owed {
		if o.VM == vm {
			return fmt.Sprintf("this host owes %s a DISCARD of VM %s (attempt %s)", o.Target, vm, o.Attempt), nil
		}
	}
	c, found, err := corrosion.GetHealthCondition(ctx, db, "firmware_migration", "firmware_migration_discard_owed", "vm", vm)
	if err != nil {
		return "", fmt.Errorf("read firmware_migration_discard_owed of VM %s: %w", vm, err)
	}
	if found && c.Lifecycle != corrosion.ConditionResolved {
		return fmt.Sprintf("an owed DISCARD of VM %s is open (firmware_migration_discard_owed)", vm), nil
	}
	return "", nil
}

// treeSize is the bytes of the regular files under p.
func treeSize(p string) int64 {
	var n int64
	_ = filepath.WalkDir(p, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if fi, err := d.Info(); err == nil {
				n += fi.Size()
			}
		}
		return nil
	})
	return n
}

// PurgeReconciledQuarantines removes the reconciler's firmware quarantines on
// this host that are older than olderThan at now and neither retained nor
// held, and returns them. olderThan 0 removes every such one. It is the
// hourly sweep and a bare `lv host superseded-disks --purge`.
func PurgeReconciledQuarantines(ctx context.Context, db *corrosion.Client, dataDir string, olderThan time.Duration, now time.Time) ([]ReconciledQuarantine, error) {
	qs, err := ListReconciledQuarantines(ctx, db, dataDir)
	if err != nil {
		return nil, err
	}
	var removed []ReconciledQuarantine
	for _, q := range qs {
		if q.Held != "" || q.Retained != "" || now.Sub(q.SetAsideAt) < olderThan {
			continue
		}
		if err := removeReconciled(q.Path); err != nil {
			return removed, fmt.Errorf("remove %s: %w", q.Path, err)
		}
		slog.Info("removed a reconciled firmware quarantine", "path", q.Path, "vm", q.VM,
			"set_aside_at", q.SetAsideAt.Format(time.RFC3339), "bytes", q.SizeBytes)
		removed = append(removed, q)
	}
	return removed, nil
}

// SweepSetAside is the hourly sweep of what a cleanup set aside on this host:
// the superseded disk copies and the reconciler's firmware quarantines, each
// by its retention rule, with retention as superseded_disk_retention_days.
// keptHold (nil: none) keeps a copy a disk a delete kept backs on.
func SweepSetAside(ctx context.Context, db *corrosion.Client, dataDir string, retention time.Duration, now time.Time,
	keptHold func(context.Context, string) (bool, string)) {
	if _, err := PurgeSupersededDisks(ctx, db, dataDir, retention, now, keptHold); err != nil {
		slog.Warn("superseded disk sweep", "error", err)
	}
	if _, err := PurgeReconciledQuarantines(ctx, db, dataDir, retention, now); err != nil {
		slog.Warn("reconciled firmware quarantine sweep", "error", err)
	}
}

// RemoveReconciledQuarantines removes the reconciler's firmware quarantines
// named by paths, retained or not: the operator's explicit removal. A name
// that is not one on this host, or one held, is refused, and nothing named
// after it is removed.
func RemoveReconciledQuarantines(ctx context.Context, db *corrosion.Client, dataDir string, paths []string) ([]ReconciledQuarantine, error) {
	qs, err := ListReconciledQuarantines(ctx, db, dataDir)
	if err != nil {
		return nil, err
	}
	byPath := make(map[string]ReconciledQuarantine, len(qs))
	for _, q := range qs {
		byPath[q.Path] = q
	}
	var removed []ReconciledQuarantine
	for _, p := range paths {
		q, ok := byPath[filepath.Clean(p)]
		if !ok {
			return removed, fmt.Errorf("%s is not a reconciled firmware quarantine on this host (lv host superseded-disks lists them)", p)
		}
		if q.Held != "" {
			return removed, fmt.Errorf("%s is held (%s)", p, q.Held)
		}
		if err := removeReconciled(q.Path); err != nil {
			return removed, fmt.Errorf("remove %s: %w", q.Path, err)
		}
		slog.Warn("removed a reconciled firmware quarantine by operator request", "path", q.Path, "vm", q.VM,
			"retained", q.Retained, "set_aside_at", q.SetAsideAt.Format(time.RFC3339), "bytes", q.SizeBytes)
		removed = append(removed, q)
	}
	return removed, nil
}

// IsReconciledQuarantinePath reports whether p names a reconciler firmware
// quarantine (finished or not) under dataDir.
func IsReconciledQuarantinePath(dataDir, p string) bool {
	p = filepath.Clean(p)
	if filepath.Dir(p) != filepath.Join(dataDir, fwmig.QuarantineDir) {
		return false
	}
	b := filepath.Base(p)
	_, _, _, staged := fwmig.ParseStageName(b)
	return reconciledNameRe.MatchString(b) || staged
}

// removeReconciled removes a quarantine directory; a test can fail it.
var removeReconciled = os.RemoveAll
