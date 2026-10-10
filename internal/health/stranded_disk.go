package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/randid"
)

// Stranded disks: the real disk a failover left behind.
//
// A RUNNING VM with a host-local disk whose host fails is restarted on
// another host under its failure policy (`on-host-failure: restart-any`).
// That host cannot reach the disk, so it starts the VM on a disk rebuilt from
// its image (reconciler.go, startPendingVM). That is the policy's documented
// cost, and keeps the VM available, but the VM's real data is still on the
// failed host. Before this record nothing said so: the restart looked like
// any other, the disk on the failed host was no longer recorded anywhere, a
// later failover back onto that host set it aside as .superseded-<time>, and
// the retention sweep deleted it seven days after the VM was running again.
//
// So the data left behind is recorded, retained and surfaced:
//
//   - the coordinator that reschedules the VM records the host-local disks it
//     leaves on the failed host (RecordStrandedDisks): condition
//     vm_disk_stranded (evaluator vm_disk, subject vm/<name>@<host>, a
//     warning), a vm.failover.disk_stranded event, an audit row and a
//     vm.disk.stranded notification. `lv inspect <vm>` shows it;
//   - when that host comes back it sets each such disk aside as
//     <path>.superseded-<time> (tendStrandedDisks) and records where. Under
//     that name no later move or restart onto the host can collide with it
//     or take its place: a migration refuses a path that is occupied, and a
//     failover start sets an occupied path aside;
//   - a failover start that sets aside an old copy it finds on its target
//     records it the same way (setAsideSupersededDisk);
//   - every such copy is retained while its VM exists, whatever the VM's state
//     (superseded_retention.go): only an operator removes it
//     (`lv host superseded-disks <host> --remove <copy>`) or puts it back
//     (`--restore <copy>`, RestoreSupersededDisk), which sets the disk it
//     replaces aside in turn, so nothing is ever deleted by the swap.
//
// The record is a health condition, one row per VM and host, written by the
// coordinator while the host is down and by the host itself afterwards. It
// adds no column and no VM state: a host on an older release reads none of
// it, and still holds copies by the old rule, exactly as before.
//
// The host is set aside on positive proof only: a record that a failover
// moved the VM off THIS host, the VM's row naming another host, and no
// domain of that name running here. A host whose row converged wrongly to
// another host (an LWW tie) has no such record, so its disk stays in place.

// CondVMDiskStranded is the condition code, filed under DiskMissingEvaluator.
const CondVMDiskStranded = "vm_disk_stranded"

// StrandedDisk is one host-local disk of a VM left on a host by a failover.
type StrandedDisk struct {
	Disk string `json:"disk"`
	Path string `json:"path"` // the disk's path on the host
	// Copy is where the host set it aside (<path>.superseded-<time>); "" while
	// the file is still at Path, which is while the host is down.
	Copy  string `json:"copy,omitempty"`
	Since string `json:"since"` // RFC3339: when it was left behind or set aside
}

// StrandedDisks is the evidence of one vm_disk_stranded condition: the
// disks of VM left on Host.
type StrandedDisks struct {
	VM      string         `json:"vm"`
	Host    string         `json:"host"`
	MovedTo string         `json:"moved_to,omitempty"` // where the failover restarted the VM
	Disks   []StrandedDisk `json:"disks"`
	Detail  string         `json:"detail"`
	Fix     string         `json:"fix"`
}

func strandedSubject(vm, host string) string { return vm + "@" + host }

// strandedFix is what an operator can do about the disks of vm left on host.
func strandedFix(vm, host string) string {
	return fmt.Sprintf("%[2]s keeps them as <path>.superseded-<time> while %[1]s exists; `lv host superseded-disks %[2]s` lists them. "+
		"To run %[1]s on its real disk again once %[2]s is back: `lv host undrain %[2]s` (it comes back fenced), "+
		"`lv stop %[1]s`, `lv migrate %[1]s %[2]s --cold`, "+
		"`lv host superseded-disks %[2]s --restore <copy>` (the disk it replaces is kept the same way), then `lv start %[1]s`. "+
		"To give the data up: `lv host superseded-disks %[2]s --remove <copy>`", vm, host)
}

// strandedDetail says what happened, in words.
func strandedDetail(ev StrandedDisks) string {
	var parts []string
	for _, d := range ev.Disks {
		if d.Copy != "" {
			parts = append(parts, fmt.Sprintf("%s (set aside as %s)", d.Disk, d.Copy))
		} else {
			parts = append(parts, fmt.Sprintf("%s at %s", d.Disk, d.Path))
		}
	}
	where := ""
	if ev.MovedTo != "" {
		where = " runs on " + ev.MovedTo + " and"
	}
	return fmt.Sprintf("VM %s%s does not have its real data: its host-local disk(s) %s are on %s",
		ev.VM, where, strings.Join(parts, ", "), ev.Host)
}

// readStranded returns the vm_disk_stranded row for vm on host, open or not.
func readStranded(ctx context.Context, db *corrosion.Client, vm, host string) (corrosion.HealthCondition, StrandedDisks, bool, error) {
	row, had, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMDiskStranded, "vm", strandedSubject(vm, host))
	if err != nil || !had {
		return row, StrandedDisks{}, false, err
	}
	var ev StrandedDisks
	if row.Evidence != "" {
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			return row, StrandedDisks{}, true, fmt.Errorf("vm_disk_stranded evidence for %s: %w", row.SubjectID, err)
		}
	}
	return row, ev, true, nil
}

// writeStranded upserts the condition for ev, open (confirmed), or resolved
// when ev lists nothing.
func writeStranded(ctx context.Context, db *corrosion.Client, reporter string, row corrosion.HealthCondition, had bool, ev StrandedDisks, now time.Time) error {
	ts := now.UTC().Format(time.RFC3339)
	if !had || row.Lifecycle == corrosion.ConditionResolved {
		if len(ev.Disks) == 0 {
			return nil
		}
		row = corrosion.HealthCondition{
			Evaluator: DiskMissingEvaluator, Code: CondVMDiskStranded, SubjectKind: "vm",
			SubjectID: strandedSubject(ev.VM, ev.Host), FirstSeen: ts, ConfirmedAt: ts,
		}
	}
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{ev.Host}
	row.LastSeen = ts
	row.Reporter = reporter
	if len(ev.Disks) == 0 {
		row.Lifecycle = corrosion.ConditionResolved
		row.ResolvedAt = ts
		row.ObserveCount = 0
		row.CleanCount = 1
	} else {
		ev.Detail, ev.Fix = strandedDetail(ev), strandedFix(ev.VM, ev.Host)
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		row.Evidence = string(b)
		row.Lifecycle = corrosion.ConditionConfirmed
		row.ResolvedAt = ""
		row.ObserveCount++
		row.CleanCount = 0
	}
	return corrosion.UpsertHealthCondition(ctx, db, row)
}

// RecordStrandedDisks records that a failover restarted vmName on movedTo,
// leaving its host-local disks on host, and returns the detail for the
// caller's event, audit row and notification. It returns "" when every disk
// moved with the VM (shared storage) and records nothing. Recording the same
// stranding again lists no disk twice.
func RecordStrandedDisks(ctx context.Context, db *corrosion.Client, reporter, vmName, host, movedTo string, disks []corrosion.DiskRecord, now time.Time) (string, error) {
	var local []corrosion.DiskRecord
	for _, d := range disks {
		if d.Path != "" && !corrosion.DiskIsShared(d) {
			local = append(local, d)
		}
	}
	if len(local) == 0 {
		return "", nil
	}
	row, ev, had, err := readStranded(ctx, db, vmName, host)
	if err != nil {
		return "", err
	}
	if !had || row.Lifecycle == corrosion.ConditionResolved {
		ev = StrandedDisks{}
	}
	ev.VM, ev.Host, ev.MovedTo = vmName, host, movedTo
	since := now.UTC().Format(time.RFC3339)
	for _, d := range local {
		listed := false
		for _, e := range ev.Disks {
			if e.Path == d.Path && e.Copy == "" {
				listed = true
				break
			}
		}
		if !listed {
			ev.Disks = append(ev.Disks, StrandedDisk{Disk: d.DiskName, Path: d.Path, Since: since})
		}
	}
	if err := writeStranded(ctx, db, reporter, row, had, ev, now); err != nil {
		return "", err
	}
	return strandedDetail(ev), nil
}

// noteStrandedCopy records that host set the disk of vmName at path aside to
// copyPath: the entry for the file still at path takes the copy, or, when
// there is none (an old copy a failover start found), a new entry is added.
func noteStrandedCopy(ctx context.Context, db *corrosion.Client, reporter, vmName, host, disk, path, copyPath string, now time.Time) (string, error) {
	row, ev, had, err := readStranded(ctx, db, vmName, host)
	if err != nil {
		return "", err
	}
	if !had || row.Lifecycle == corrosion.ConditionResolved {
		ev = StrandedDisks{}
	}
	ev.VM, ev.Host = vmName, host
	since := now.UTC().Format(time.RFC3339)
	noted := false
	for i := range ev.Disks {
		if ev.Disks[i].Path == path && ev.Disks[i].Copy == "" {
			ev.Disks[i].Copy, ev.Disks[i].Since, noted = copyPath, since, true
			break
		}
	}
	if !noted {
		ev.Disks = append(ev.Disks, StrandedDisk{Disk: disk, Path: path, Copy: copyPath, Since: since})
	}
	if err := writeStranded(ctx, db, reporter, row, had, ev, now); err != nil {
		return "", err
	}
	return strandedDetail(ev), nil
}

// StrandedDisksOf returns the open vm_disk_stranded records of vmName, one
// per host holding its data, for `lv inspect`.
func StrandedDisksOf(ctx context.Context, db *corrosion.Client, vmName string) ([]StrandedDisks, error) {
	open, err := corrosion.ListHealthConditions(ctx, db, false)
	if err != nil {
		return nil, err
	}
	var out []StrandedDisks
	for _, row := range open {
		if row.Evaluator != DiskMissingEvaluator || row.Code != CondVMDiskStranded || row.SubjectKind != "vm" ||
			!strings.HasPrefix(row.SubjectID, vmName+"@") {
			continue
		}
		var ev StrandedDisks
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM != vmName {
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

// strandedCopies maps every set-aside copy an open record names to its VM.
func strandedCopies(ctx context.Context, db *corrosion.Client) (map[string]string, error) {
	open, err := corrosion.ListHealthConditions(ctx, db, false)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, row := range open {
		if row.Evaluator != DiskMissingEvaluator || row.Code != CondVMDiskStranded {
			continue
		}
		var ev StrandedDisks
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			continue
		}
		for _, d := range ev.Disks {
			if d.Copy != "" {
				out[d.Copy] = ev.VM
			}
		}
	}
	return out, nil
}

// SetDiskStrandedObserver wires a callback for each disk this host sets
// aside — on return from a failover, or at a failover start — so the daemon
// can raise the vm.disk.stranded notification.
func (r *Reconciler) SetDiskStrandedObserver(fn func(vm, host, detail string)) { r.onDiskStranded = fn }

// surfaceSetAside records the copy, the VM event and the notification for a
// disk of vmName this host set aside.
func (r *Reconciler) surfaceSetAside(ctx context.Context, vmName, disk, path, copyPath, why string) {
	detail, err := noteStrandedCopy(ctx, r.db, r.hostName, vmName, r.hostName, disk, path, copyPath, r.now())
	if err != nil {
		slog.Error("reconciler: could not record a set-aside disk copy; it is kept, but not listed on the VM",
			"vm", vmName, "copy", copyPath, "error", err)
		detail = fmt.Sprintf("VM %s: disk %s set aside on %s as %s", vmName, disk, r.hostName, copyPath)
	}
	detail = why + ": " + detail
	if err := corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vmName, HostName: r.hostName, Type: "vm.disk.set_aside",
		Result: "ok", Severity: "warn", Detail: detail, Username: "reconciler",
	}); err != nil {
		slog.Warn("reconciler: record the set-aside disk's event", "vm", vmName, "error", err)
	}
	if r.onDiskStranded != nil {
		r.onDiskStranded(vmName, r.hostName, detail)
	}
}

// tendStrandedDisks acts on this host's vm_disk_stranded records: it sets
// aside each disk a failover left here, once this host is back and the VM is
// elsewhere, and clears a record once nothing is left to keep — the VM was
// deleted, or every copy was removed or restored by an operator. Not while
// the replica is catching up: a row it has not received yet would read as a
// VM elsewhere, or gone.
func (r *Reconciler) tendStrandedDisks(ctx context.Context) {
	if ok, _ := r.replicaTrusted(ctx); !ok {
		return
	}
	open, err := corrosion.ListHealthConditions(ctx, r.db, false)
	if err != nil {
		return
	}
	suffix := "@" + r.hostName
	for _, row := range open {
		if row.Evaluator == DiskMissingEvaluator && row.Code == CondVMFailoverHeld {
			r.resolveHeldForHost(ctx, row)
			continue
		}
		if row.Evaluator != DiskMissingEvaluator || row.Code != CondVMDiskStranded {
			continue
		}
		if !strings.HasSuffix(row.SubjectID, suffix) {
			r.resolveStrandedOnRemovedHost(ctx, row)
			continue
		}
		var ev StrandedDisks
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
			slog.Warn("reconciler: unreadable vm_disk_stranded evidence; leaving it", "subject", row.SubjectID, "error", err)
			continue
		}
		name := strings.TrimSuffix(row.SubjectID, suffix)
		vm, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil {
			continue
		}
		before := len(ev.Disks)
		changed := false
		var kept []StrandedDisk
		if vm == nil {
			slog.Info("reconciler: vm_disk_stranded resolved — the VM was deleted; its disk copies here follow the retention for a deleted VM's",
				"vm", name)
		} else {
			for _, d := range ev.Disks {
				keep, set := r.tendStrandedDisk(ctx, vm, d)
				if set != d {
					changed = true
				}
				if keep {
					kept = append(kept, set)
				}
			}
		}
		if !changed && len(kept) == before {
			continue
		}
		ev.Disks = kept
		if err := writeStranded(ctx, r.db, r.hostName, row, true, ev, r.now()); err != nil {
			slog.Warn("reconciler: could not update vm_disk_stranded", "vm", name, "error", err)
		}
	}
}

// resolveStrandedOnRemovedHost clears another host's record once nothing can
// ever act on it: that host was removed from the cluster (or never was in
// it) and the VM was deleted. The host itself clears its records otherwise.
func (r *Reconciler) resolveStrandedOnRemovedHost(ctx context.Context, row corrosion.HealthCondition) {
	var ev StrandedDisks
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM == "" || ev.Host == "" {
		return
	}
	if vm, err := corrosion.GetVM(ctx, r.db, ev.VM); err != nil || vm != nil {
		return
	}
	if h, err := corrosion.GetHost(ctx, r.db, ev.Host); err != nil || (h != nil && h.State != "removed") {
		return
	}
	ev.Disks = nil
	if err := writeStranded(ctx, r.db, r.hostName, row, true, ev, r.now()); err != nil {
		slog.Warn("reconciler: could not resolve a removed host's vm_disk_stranded", "subject", row.SubjectID, "error", err)
	}
}

// tendStrandedDisk decides one recorded disk of vm on this host: whether the
// record keeps it, and its entry afterwards (with the copy, when this pass set
// the file aside).
func (r *Reconciler) tendStrandedDisk(ctx context.Context, vm *corrosion.VMRecord, d StrandedDisk) (bool, StrandedDisk) {
	if d.Copy != "" {
		if _, err := os.Lstat(d.Copy); err != nil && os.IsNotExist(err) {
			slog.Info("reconciler: a stranded disk copy is gone (removed or restored by an operator)", "vm", vm.Name, "copy", d.Copy)
			return false, d
		}
		return true, d
	}
	if vm.HostName == r.hostName {
		if vm.State == "pending" || vm.State == "starting" {
			// A failover back onto this host is starting the VM: it sets
			// the file aside itself and records it (setAsideSupersededDisk).
			return true, d
		}
		// The VM runs here again on the disk at that path.
		return false, d
	}
	fi, err := os.Lstat(d.Path)
	if err != nil {
		// Missing is not deleted: a volume not mounted (yet) — its mount
		// point absent, or present and empty — reads exactly like a file
		// gone. Nothing confirms a deletion, so the entry is kept and looked
		// at again next pass; it clears with its VM.
		return true, d
	}
	if !fi.Mode().IsRegular() {
		return true, d
	}
	// Never under a domain that is live here, or holds resumable state: the
	// disk is open, or a resume would need it, and the ownership repair
	// decides that case, not this. Only a domain shut off with nothing to
	// resume — the leftover a fenced host comes back with — or none at all.
	if r.virt != nil && r.virt.DomainExists(vm.Name) {
		st, serr := r.virt.DomainStateReason(vm.Name)
		if serr != nil {
			return true, d
		}
		if !cleanableLeftover(st) {
			if !unknownShutoff(st) {
				return true, d
			}
			if saved, merr := r.virt.HasManagedSaveImage(vm.Name); merr != nil || saved {
				return true, d
			}
		}
	}
	// Never a file a workload on this host still uses: a linked clone's base
	// or another VM's disk at the same path.
	refs, err := corrosion.DisksReferencingPath(ctx, r.db, d.Path)
	if err != nil {
		return true, d
	}
	for _, ref := range refs {
		other, gerr := corrosion.GetVM(ctx, r.db, ref.VMName)
		if gerr != nil || (other != nil && other.HostName == r.hostName) {
			return true, d
		}
	}
	aside := supersededName(d.Path, r.now())
	if err := os.Rename(d.Path, aside); err != nil {
		slog.Error("reconciler: could not set aside a disk a failover left on this host; it stays at its path",
			"vm", vm.Name, "path", d.Path, "error", err)
		return true, d
	}
	slog.Warn("reconciler: set aside the real disk of a VM a failover restarted elsewhere; it is kept while the VM exists",
		"vm", vm.Name, "disk", d.Disk, "path", d.Path, "set_aside_to", aside, "vm_host", vm.HostName)
	d.Copy, d.Since = aside, r.now().UTC().Format(time.RFC3339)
	r.surfaceSetAsideEventOnly(ctx, vm.Name, d)
	return true, d
}

// surfaceSetAsideEventOnly is surfaceSetAside for a copy whose record the
// caller writes itself (tendStrandedDisks updates the row once per pass).
func (r *Reconciler) surfaceSetAsideEventOnly(ctx context.Context, vmName string, d StrandedDisk) {
	detail := fmt.Sprintf("%s is back: the real disk %s of VM %s, left here by a failover, is set aside as %s and kept while the VM exists",
		r.hostName, d.Disk, vmName, d.Copy)
	if err := corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: vmName, HostName: r.hostName, Type: "vm.disk.set_aside",
		Result: "ok", Severity: "warn", Detail: detail, Username: "reconciler",
	}); err != nil {
		slog.Warn("reconciler: record the set-aside disk's event", "vm", vmName, "error", err)
	}
	if r.onDiskStranded != nil {
		r.onDiskStranded(vmName, r.hostName, detail)
	}
}

// RestoredCopy is what RestoreSupersededDisk did.
type RestoredCopy struct {
	VM       string
	Disk     string
	DiskPath string // where the copy now is: the VM's disk
	Restored string // the copy that was put back
	SetAside string // where the file it replaced was set aside; "" when there was none
}

// linkFile is os.Link; a test replaces it to make the link fail.
var linkFile = os.Link

// ErrRestoreRefused marks a restore refused for the VM's state or place, as
// opposed to a failure.
var ErrRestoreRefused = errors.New("restore refused")

// RestoreSupersededDisk puts a set-aside copy on this host back at its disk's
// path: the operator's reattach (`lv host superseded-disks <host> --restore
// <copy>`). The VM must exist, its row name this host, be stopped, and have
// no domain running here (domainRunning). Nothing is deleted: the file at the
// disk's path, if any, is set aside first and recorded like any other copy,
// and the copy is linked into place, which fails rather than overwrite a file
// that appeared there meanwhile.
func RestoreSupersededDisk(ctx context.Context, db *corrosion.Client, dataDir, hostName, copyPath string, domainRunning func(string) bool, now time.Time) (RestoredCopy, error) {
	copies, err := ListSupersededDisks(ctx, db, dataDir)
	if err != nil {
		return RestoredCopy{}, err
	}
	var c *SupersededCopy
	for i := range copies {
		if copies[i].Path == filepath.Clean(copyPath) {
			c = &copies[i]
			break
		}
	}
	if c == nil {
		return RestoredCopy{}, fmt.Errorf("%w: %s is not a superseded disk copy on %s (lv host superseded-disks lists them)", ErrRestoreRefused, copyPath, hostName)
	}
	if c.VM == "" {
		return RestoredCopy{}, fmt.Errorf("%w: no VM has a disk at %s any more", ErrRestoreRefused, c.DiskPath)
	}
	vm, err := corrosion.GetVM(ctx, db, c.VM)
	if err != nil {
		return RestoredCopy{}, err
	}
	if vm == nil {
		return RestoredCopy{}, fmt.Errorf("%w: VM %s no longer exists", ErrRestoreRefused, c.VM)
	}
	if vm.HostName != hostName {
		return RestoredCopy{}, fmt.Errorf("%w: VM %s is on %s, not %s; stop it and move it here first (`lv migrate %s %s --cold`)",
			ErrRestoreRefused, vm.Name, vm.HostName, hostName, vm.Name, hostName)
	}
	if vm.State != "stopped" || (domainRunning != nil && domainRunning(vm.Name)) {
		return RestoredCopy{}, fmt.Errorf("%w: VM %s is %s; stop it first (`lv stop %s`)", ErrRestoreRefused, vm.Name, vm.State, vm.Name)
	}
	var disk *corrosion.DiskRecord
	disks, err := corrosion.GetVMDisks(ctx, db, vm.Name)
	if err != nil {
		return RestoredCopy{}, err
	}
	for i := range disks {
		if disks[i].Path == c.DiskPath && !corrosion.DiskIsShared(disks[i]) {
			disk = &disks[i]
			break
		}
	}
	if disk == nil {
		return RestoredCopy{}, fmt.Errorf("%w: %s is not a host-local disk of VM %s", ErrRestoreRefused, c.DiskPath, vm.Name)
	}
	out := RestoredCopy{VM: vm.Name, Disk: disk.DiskName, DiskPath: c.DiskPath, Restored: c.Path}
	if _, err := os.Lstat(c.DiskPath); err == nil {
		out.SetAside = supersededName(c.DiskPath, now)
		if err := os.Rename(c.DiskPath, out.SetAside); err != nil {
			return RestoredCopy{}, fmt.Errorf("set aside the disk at %s: %w", c.DiskPath, err)
		}
		if _, err := noteStrandedCopy(ctx, db, hostName, vm.Name, hostName, disk.DiskName, c.DiskPath, out.SetAside, now); err != nil {
			slog.Warn("restore: could not record the copy it set aside; it is kept and listed", "copy", out.SetAside, "error", err)
		}
	} else if !os.IsNotExist(err) {
		return RestoredCopy{}, err
	}
	// Link, then unlink: a link never replaces an existing file.
	if err := linkFile(c.Path, c.DiskPath); err != nil {
		// Never leave the VM with no disk at its path: put back the one set
		// aside above.
		if out.SetAside != "" {
			if rerr := os.Rename(out.SetAside, c.DiskPath); rerr != nil {
				return out, fmt.Errorf("put %s back at %s: %w; the disk that was there is kept at %s (moving it back failed: %v)",
					c.Path, c.DiskPath, err, out.SetAside, rerr)
			}
		}
		return out, fmt.Errorf("put %s back at %s: %w; nothing was changed", c.Path, c.DiskPath, err)
	}
	if err := os.Remove(c.Path); err != nil {
		slog.Warn("restore: the copy is in place, but its old name could not be removed", "copy", c.Path, "error", err)
	}
	slog.Warn("restored a superseded disk copy as the VM's disk", "vm", vm.Name, "disk", disk.DiskName,
		"path", c.DiskPath, "restored", c.Path, "set_aside", out.SetAside)
	return out, nil
}

// A restart-same VM with a host-local disk waits for its host.
//
// `on-host-failure: restart-same` asks for the VM to come back on its own
// host. A restart anywhere else would start it on a disk rebuilt blank from
// its image, so a VM with any host-local disk is left on its fenced host and
// recorded (internal/failover/restart_same.go): condition vm_failover_held
// (evaluator vm_disk, subject vm/<name>@<host>, warning), naming the host and
// what the operator can do. Its host, once back, starts it there on its real
// disk as for any VM its row says runs there, and resolves the record. A
// restart-same VM whose disks are all shared is still restarted elsewhere, as
// before: nothing is lost.

// CondVMFailoverHeld is filed under DiskMissingEvaluator.
const CondVMFailoverHeld = "vm_failover_held"

// HeldForHost is the evidence of vm_failover_held.
type HeldForHost struct {
	VM     string         `json:"vm"`
	Host   string         `json:"host"`
	Disks  []StrandedDisk `json:"disks"`
	Detail string         `json:"detail"`
	Fix    string         `json:"fix"`
}

// heldFix is what an operator can do about a restart-same VM held on host.
func heldFix(vm, host string) string {
	return fmt.Sprintf("bring %[2]s back: once it is active it starts %[1]s there on its real disk (if it stays fenced, "+
		"because failover moved other workloads off it, run `lv host undrain %[2]s`). If %[2]s was removed "+
		"(`lv host rm --dead`), adding the machine back under that name (`lv host add`) brings %[1]s back with it. "+
		"If %[2]s is gone for good, its data is gone with it: promote a replica if there is one "+
		"(`lv replication promote %[1]s`), or remove the host first (`lv host rm --dead %[2]s`, try `--dry-run`) and then "+
		"the VM (`lv rm %[1]s`), and create it again. Disk copies a failover set aside are listed by "+
		"`lv host superseded-disks <host>`", vm, host)
}

// RecordHeldForHost records that vmName is held on host to wait for it, and
// returns the detail for the caller's event, audit row and notification.
func RecordHeldForHost(ctx context.Context, db *corrosion.Client, reporter, vmName, host string, disks []corrosion.DiskRecord, now time.Time) (string, error) {
	ts := now.UTC().Format(time.RFC3339)
	ev := HeldForHost{VM: vmName, Host: host}
	var paths []string
	for _, d := range disks {
		if d.Path != "" && !corrosion.DiskIsShared(d) {
			ev.Disks = append(ev.Disks, StrandedDisk{Disk: d.DiskName, Path: d.Path, Since: ts})
			paths = append(paths, d.DiskName+" at "+d.Path)
		}
	}
	ev.Detail = fmt.Sprintf("held on %s, not restarted elsewhere: on-host-failure is restart-same and its host-local disk(s) %s "+
		"are on %s; a restart on another host would rebuild them blank from its image", host, strings.Join(paths, ", "), host)
	ev.Fix = heldFix(vmName, host)
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	row, had, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMFailoverHeld, "vm", strandedSubject(vmName, host))
	if err != nil {
		return "", err
	}
	open := had && row.Lifecycle != corrosion.ConditionResolved
	if open {
		// Keep when the hold began; an unchanged hold is not rewritten (the
		// removed-host pass re-decides it every few seconds).
		var prev HeldForHost
		if json.Unmarshal([]byte(row.Evidence), &prev) == nil {
			since := map[string]string{}
			for _, d := range prev.Disks {
				since[d.Path] = d.Since
			}
			for i := range ev.Disks {
				if s := since[ev.Disks[i].Path]; s != "" {
					ev.Disks[i].Since = s
				}
			}
		}
		if nb, merr := json.Marshal(ev); merr == nil && string(nb) == row.Evidence {
			return ev.Detail + ". " + ev.Fix, nil
		}
		b, _ = json.Marshal(ev)
	}
	if !open {
		row = corrosion.HealthCondition{
			Evaluator: DiskMissingEvaluator, Code: CondVMFailoverHeld, SubjectKind: "vm",
			SubjectID: strandedSubject(vmName, host), FirstSeen: ts, ConfirmedAt: ts,
		}
	}
	row.Lifecycle, row.Severity, row.Hosts = corrosion.ConditionConfirmed, corrosion.SeverityWarning, []string{host}
	row.Evidence, row.LastSeen, row.Reporter, row.ResolvedAt = string(b), ts, reporter, ""
	row.ObserveCount++
	row.CleanCount = 0
	if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
		return "", err
	}
	return ev.Detail + ". " + ev.Fix, nil
}

// HeldForHostOf returns the open vm_failover_held record of vmName, or nil.
func HeldForHostOf(ctx context.Context, db *corrosion.Client, vmName string) (*HeldForHost, error) {
	open, err := corrosion.ListHealthConditions(ctx, db, false)
	if err != nil {
		return nil, err
	}
	for _, row := range open {
		if row.Evaluator != DiskMissingEvaluator || row.Code != CondVMFailoverHeld || !strings.HasPrefix(row.SubjectID, vmName+"@") {
			continue
		}
		var ev HeldForHost
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM != vmName {
			continue
		}
		return &ev, nil
	}
	return nil, nil
}

// resolveHeldForHost clears vm_failover_held records nothing holds any more:
// on this host, once the VM runs here again, or is elsewhere, or is gone; on a
// host removed from the cluster, once the VM is gone or elsewhere.
func (r *Reconciler) resolveHeldForHost(ctx context.Context, row corrosion.HealthCondition) {
	var ev HeldForHost
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM == "" || ev.Host == "" {
		return
	}
	vm, err := corrosion.GetVM(ctx, r.db, ev.VM)
	if err != nil {
		return
	}
	held := vm != nil && vm.HostName == ev.Host
	if ev.Host == r.hostName {
		// A held VM's row says running all along: only its domain running
		// here says this host has started it.
		if held && (vm.State != "running" || !r.domainRunningHere(vm.Name)) {
			return // still waiting for this host to start it
		}
	} else {
		if held {
			return
		}
		if h, herr := corrosion.GetHost(ctx, r.db, ev.Host); herr != nil || (h != nil && h.State != "removed") {
			return // that host clears its own
		}
	}
	ts := r.now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, r.hostName
	row.ObserveCount, row.CleanCount = 0, 1
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Warn("reconciler: could not resolve vm_failover_held", "vm", ev.VM, "error", err)
	}
}

// startHeldVM starts a restart-same VM that failover held for this host, now
// that the host is back, instead of letting the out-of-band stop sync record
// it stopped (which the restart engine never restarts, and which left the
// hold open for good). It reports whether it handled the VM: true means do
// not sync.
//
// It acts only on positive proof, and every gate of a local start still
// applies:
//   - an open vm_failover_held record names this host — failover decided the
//     VM stays here, and no copy of it was started anywhere (the hold mints
//     no claim and moves no row);
//   - the row names this host and says running (the caller's walk), and the
//     domain here is genuinely down with nothing to resume: shut off for a
//     reason a power loss or a kill leaves (unknown, destroyed, crashed,
//     failed). A guest shutdown, a saved or suspended domain, or anything
//     still live is left to the usual sync;
//   - the replica is trusted, the owner epoch (when enforced) does not say
//     this runtime is superseded, and startPendingVM's own gates hold:
//     self-fence, the ExecutionGate (quorum, and this host ACTIVE — a fenced
//     host starts it once undrained), the ownership-dispute refusal and the
//     VM lock.
func (r *Reconciler) startHeldVM(ctx context.Context, vm corrosion.VMRecord, st lv.DomainStatus) bool {
	held, err := HeldForHostOf(ctx, r.db, vm.Name)
	if err != nil || held == nil || held.Host != r.hostName {
		return false
	}
	switch st.Reason {
	case "unknown", "destroyed", "crashed", "failed":
	default:
		return false
	}
	if st.State != "stopped" {
		return false
	}
	if ok, why := r.replicaTrusted(ctx); !ok {
		slog.Info("reconciler: a held VM's start waits for the replica to catch up", "vm", vm.Name, "why", why)
		return true
	}
	if r.ownerEpochEnforced(ctx) && r.runtimeSuperseded(ctx, vm.Name) {
		slog.Warn("reconciler: not starting a held VM — this host's runtime belongs to a superseded ownership generation", "vm", vm.Name)
		r.noteGateRefused(corrosion.ActionReschedule, ReasonStaleEpoch)
		return true
	}
	// Saved state is never discarded by a cold boot: the VM stays held, and
	// the operator resumes it (`lv start` restores a managed-save image).
	if r.virt != nil {
		if saved, merr := r.virt.HasManagedSaveImage(vm.Name); merr != nil || saved {
			r.noteHeldSavedState(ctx, vm.Name, merr)
			return true
		}
	}
	slog.Warn("reconciler: starting a restart-same VM failover held for this host, on its real disk", "vm", vm.Name)
	r.startPendingVM(ctx, vm)
	// Once per hold: a start that took clears it, so a crash afterwards
	// follows the VM's restart policy, never another held start.
	if r.domainRunningHere(vm.Name) {
		r.resolveHeld(ctx, vm.Name)
	}
	return true
}

// noteHeldSavedState records, once per VM in this process, that a held VM has
// saved state and is left for the operator to resume.
func (r *Reconciler) noteHeldSavedState(ctx context.Context, name string, merr error) {
	r.heldSavedMu.Lock()
	if r.heldSavedNoted == nil {
		r.heldSavedNoted = map[string]bool{}
	}
	first := !r.heldSavedNoted[name]
	r.heldSavedNoted[name] = true
	r.heldSavedMu.Unlock()
	if !first {
		return
	}
	detail := fmt.Sprintf("%s is back, but held VM %s has saved state (a managed-save image) and is not cold-booted, "+
		"which would discard it: resume it with `lv start %s`", r.hostName, name, name)
	if merr != nil {
		detail = fmt.Sprintf("%s is back, but whether held VM %s has saved state cannot be read (%v), so it is not "+
			"started: check it, then `lv start %s`", r.hostName, name, merr, name)
	}
	slog.Warn("reconciler: not starting a held VM with saved state", "vm", name, "detail", detail)
	if err := corrosion.InsertVMEvent(ctx, r.db, corrosion.VMEventRecord{
		ID: randid.New(), VMName: name, HostName: r.hostName, Type: "vm.failover.held_saved_state",
		Result: "ok", Severity: "warn", Detail: detail, Username: "reconciler",
	}); err != nil {
		slog.Warn("reconciler: record the held VM's saved-state event", "vm", name, "error", err)
	}
}

// resolveHeld clears this host's vm_failover_held record for name.
func (r *Reconciler) resolveHeld(ctx context.Context, name string) {
	row, had, err := corrosion.GetHealthCondition(ctx, r.db, DiskMissingEvaluator, CondVMFailoverHeld, "vm", strandedSubject(name, r.hostName))
	if err != nil || !had || row.Lifecycle == corrosion.ConditionResolved {
		return
	}
	ts := r.now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, r.hostName
	row.ObserveCount, row.CleanCount = 0, 1
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Warn("reconciler: could not resolve vm_failover_held after the start", "vm", name, "error", err)
	}
}

// domainRunningHere reports whether name's domain runs on this host.
func (r *Reconciler) domainRunningHere(name string) bool {
	if r.virt == nil || !r.virt.DomainExists(name) {
		return false
	}
	st, err := r.virt.DomainStateReason(name)
	return err == nil && st.State == "running"
}
