package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A local start never boots a VM from a disk rebuilt blank.
//
// startPendingVM rebuilds a missing disk as a fresh overlay of its backing
// image. On an ownership transfer onto this host (a pending row, or its proof
// after a crash or re-arm) that is the recovery itself: a host-local disk
// stayed on the failed host, and the VM's failure policy chose to restart it
// from its image elsewhere. A LOCAL start is a different thing. The onboot
// autostart, the "running in the database but not in libvirt" self-heal and a
// re-driven markerless "starting" row all start a VM that this host's row
// says already runs, or ran, HERE, on the disk at its path. If that file is
// gone, the VM's data is gone with it, and a fresh overlay would start the VM
// as if nothing had happened: a silent reset of its disk, reported as a
// successful start. That is finding N5 (a re-added host took over a removed
// host's rows, then "VM marked running but not in libvirt — attempting
// restart" and "recreated overlay disk"), now blocked at admission by
// f9f33583; this refuses whatever the route.
//
// So a local start that finds a disk missing refuses, puts the VM in error,
// and raises vm_disk_missing (critical, subject vm/<name>@<host>) naming the
// disk and the two ways out: put the file back and `lv start`, or accept a
// blank disk with `lv rebuild`. The condition resolves once the VM has left
// that error on this host. Nothing is rebuilt automatically: only an operator
// can say the data is not coming back.

const (
	DiskMissingEvaluator = "vm_disk"
	CondVMDiskMissing    = "vm_disk_missing"
)

type diskMissingEvidence struct {
	Disk         string `json:"disk"`
	Path         string `json:"path"`
	BackingImage string `json:"backing_image,omitempty"`
	Detail       string `json:"detail"`
	Fix          string `json:"fix"`
}

func diskMissingSubject(vmName, host string) string { return vmName + "@" + host }

// refuseLocalStartWithoutDisk is a local start's answer to a missing disk:
// the VM goes to error, and vm_disk_missing names it.
func (r *Reconciler) refuseLocalStartWithoutDisk(ctx context.Context, vmName string, d corrosion.DiskRecord) {
	detail := fmt.Sprintf("disk %s is missing at %s on %s; a start that is not an ownership transfer never rebuilds it blank",
		d.DiskName, d.Path, r.hostName)
	if d.BackingImage != "" {
		detail += fmt.Sprintf(" from its image %s, which would silently reset the VM's data", d.BackingImage)
	}
	fix := fmt.Sprintf("put the disk back at %s and run `lv start %s`; or, if its data is lost for good, "+
		"run `lv rebuild %s` to recreate the VM with blank disks", d.Path, vmName, vmName)
	slog.Error("reconciler: refusing to start a VM whose disk is missing on this host",
		"vm", vmName, "disk", d.DiskName, "path", d.Path, "backing_image", d.BackingImage, "fix", fix)
	r.clearOnbootPending(vmName)
	r.failPendingStart(ctx, vmName, "", false, detail)

	b, err := json.Marshal(diskMissingEvidence{Disk: d.DiskName, Path: d.Path, BackingImage: d.BackingImage, Detail: detail, Fix: fix})
	if err != nil {
		return
	}
	ts := r.now().UTC().Format(time.RFC3339)
	subject := diskMissingSubject(vmName, r.hostName)
	row, had, err := corrosion.GetHealthCondition(ctx, r.db, DiskMissingEvaluator, CondVMDiskMissing, "vm", subject)
	if err != nil {
		slog.Warn("reconciler: cannot read vm_disk_missing; raising it afresh", "vm", vmName, "error", err)
	}
	if !had || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{
			Evaluator: DiskMissingEvaluator, Code: CondVMDiskMissing, SubjectKind: "vm", SubjectID: subject,
			FirstSeen: ts, ConfirmedAt: ts,
		}
	}
	row.Lifecycle = corrosion.ConditionConfirmed
	row.Severity = corrosion.SeverityCritical
	row.Hosts = []string{r.hostName}
	row.Evidence = string(b)
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen = ts
	row.ResolvedAt = ""
	row.Reporter = r.hostName
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Error("reconciler: could not record vm_disk_missing", "vm", vmName, "error", err)
	}
}

// resolveDiskMissing resolves this host's vm_disk_missing rows whose VM has
// left the refused state here: it is gone, on another host, or no longer in
// error (restored and started, rebuilt, or stopped by an operator).
func (r *Reconciler) resolveDiskMissing(ctx context.Context) {
	open, err := corrosion.ListHealthConditions(ctx, r.db, false)
	if err != nil {
		return
	}
	suffix := "@" + r.hostName
	for _, row := range open {
		if row.Evaluator != DiskMissingEvaluator || row.Code != CondVMDiskMissing || !strings.HasSuffix(row.SubjectID, suffix) {
			continue
		}
		name := strings.TrimSuffix(row.SubjectID, suffix)
		vm, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil {
			continue
		}
		if vm != nil && vm.HostName == r.hostName && vm.State == "error" {
			continue
		}
		ts := r.now().UTC().Format(time.RFC3339)
		row.Lifecycle = corrosion.ConditionResolved
		row.ResolvedAt = ts
		row.LastSeen = ts
		row.ObserveCount = 0
		row.CleanCount = 1
		row.Reporter = r.hostName
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			slog.Warn("reconciler: could not resolve vm_disk_missing", "vm", name, "error", err)
			continue
		}
		slog.Info("reconciler: vm_disk_missing resolved — the VM left the refused state on this host", "vm", name)
	}
}

// deferredTransfers is the set of proof-less transfers this host parked in
// "starting" while their backing image transferred (deferPendingStart): a
// markerless "starting" row is otherwise a local start, which never rebuilds a
// disk. In memory: a restart forgets it, and the parked transfer is then
// refused as a local start and raises vm_disk_missing. Only a proof-less
// transfer is parked this way, so only a cluster without the split-brain gate
// enforced can reach it (with it, a markerless pending row is refused as
// proof_missing); a transfer with a proof stays pending and keeps its proof.
type deferredTransfers struct {
	mu sync.Mutex
	m  map[string]bool
}

func (d *deferredTransfers) add(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.m == nil {
		d.m = map[string]bool{}
	}
	d.m[name] = true
}

func (d *deferredTransfers) has(name string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.m[name]
}

func (d *deferredTransfers) drop(name string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.m, name)
}
