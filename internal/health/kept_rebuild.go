package health

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A failover rebuild is refused at a kept overlay's missing base.
//
// An ownership transfer onto this host rebuilds a disk missing here as a
// fresh overlay of its image, at <disks>/<vm>-<disk>.qcow2 (the daemon's
// Server.RecreateOverlayDisk). A delete on this host may have kept an overlay
// of an earlier VM of the name whose missing backing file is that very path;
// the rebuilt disk would become its base, and the kept overlay a mix of two
// VMs' data. The rebuild gets the kept-create check (grpcapi's
// keptMissingBaseRefusal; while kept state cannot be read, the disk files on
// the host decide, as for a create), and a
// refusal fails the pending start as any failed rebuild does: a start with a
// transfer proof is re-armed pending and retried (the coordinator may place
// the VM elsewhere), and one without goes to error. It raises
// vm_disk_kept_base (evaluator vm_disk, subject vm/<name>@<host>, warning)
// naming the file and the cause, and resolves once the VM has left a
// pending, starting or error state on this host: started, stopped, moved,
// or gone.

// CondVMDiskKeptBase is filed under DiskMissingEvaluator.
const CondVMDiskKeptBase = "vm_disk_kept_base"

// Why a rebuild was refused (KeptRebuildRefusedError.Cause).
const (
	// KeptRebuildOverlay: a kept overlay names the disk's path as its
	// missing base (or whether one does cannot be told for a reason that
	// stands, such as a directory that does not resolve).
	KeptRebuildOverlay = "kept_overlay"
	// KeptRebuildUnreadable: kept-disks.json, or the backing chain of a
	// disk it names, cannot be read.
	KeptRebuildUnreadable = "kept_state_unreadable"
	// KeptRebuildNoAnswer: storage or the database did not answer in time.
	KeptRebuildNoAnswer = "no_answer"
)

// KeptRebuildRefusedError is a rebuild of the disk at Path refused by the
// kept-create check: Err says why and names the kept overlay or the file
// that cannot be read; Cause is which (KeptRebuild*).
type KeptRebuildRefusedError struct {
	Path  string
	Cause string
	Err   error
}

func (e *KeptRebuildRefusedError) Error() string { return e.Err.Error() }
func (e *KeptRebuildRefusedError) Unwrap() error { return e.Err }

// keptRebuildFix is what an operator can do about a rebuild refused for
// cause on host.
func keptRebuildFix(cause, host string) string {
	retry := "A start with a transfer proof is retried each pass (and the VM may be placed on another host); one without " +
		"is left in error, as any failed rebuild is. "
	switch cause {
	case KeptRebuildUnreadable:
		return retry + fmt.Sprintf("The record of disks deletes kept, or a kept disk's backing chain, cannot be read on %s "+
			"(named above): repair that file, or, once nothing needs that disk, move it away or remove its entry from "+
			"kept-disks.json (`lv health` names it under disk_leftover)", host)
	case KeptRebuildNoAnswer:
		return retry + fmt.Sprintf("Storage or the database on %s did not answer while the kept disks were checked: once it "+
			"answers, the next attempt checks again", host)
	default:
		return retry + fmt.Sprintf("A disk a delete kept on %s backs on this path although it is missing (the overlay is named "+
			"above): move that overlay off this host (or `qemu-img rebase -u -b <new path>` it onto a copy of its base), or "+
			"remove its entry from kept-disks.json once nothing needs it; kept disks are listed under disk_leftover in `lv health`", host)
	}
}

type keptBaseEvidence struct {
	Disk   string `json:"disk"`
	Path   string `json:"path"`
	Cause  string `json:"cause"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`
}

// keptRebuildRefused reports whether err is a rebuild the kept-create check
// refused, and if so raises vm_disk_kept_base for vmName's disk on this host.
func (r *Reconciler) keptRebuildRefused(ctx context.Context, vmName, diskName string, err error) bool {
	var kr *KeptRebuildRefusedError
	if !errors.As(err, &kr) {
		return false
	}
	ev := keptBaseEvidence{
		Disk: diskName, Path: kr.Path, Cause: kr.Cause,
		Detail: fmt.Sprintf("disk %s of %s was not rebuilt at %s on %s: %v", diskName, vmName, kr.Path, r.hostName, kr.Err),
		Fix:    keptRebuildFix(kr.Cause, r.hostName),
	}
	slog.Warn("reconciler: the rebuild of a missing disk is refused by the kept-disk check",
		"vm", vmName, "disk", diskName, "path", kr.Path, "cause", kr.Cause, "error", kr.Err)
	b, merr := json.Marshal(ev)
	if merr != nil {
		return true
	}
	ts := r.now().UTC().Format(time.RFC3339)
	subject := diskMissingSubject(vmName, r.hostName)
	row, had, gerr := corrosion.GetHealthCondition(ctx, r.db, DiskMissingEvaluator, CondVMDiskKeptBase, "vm", subject)
	if gerr != nil {
		slog.Warn("reconciler: cannot read vm_disk_kept_base; raising it afresh", "vm", vmName, "error", gerr)
	}
	open := gerr == nil && had && row.Lifecycle != corrosion.ConditionResolved
	if open && row.Evidence == string(b) {
		// Unchanged: a retried start refused the same way is not written
		// again (every pass would otherwise replicate a new row).
		return true
	}
	if !open {
		row = corrosion.HealthCondition{
			Evaluator: DiskMissingEvaluator, Code: CondVMDiskKeptBase, SubjectKind: "vm", SubjectID: subject,
			FirstSeen: ts, ConfirmedAt: ts,
		}
	}
	row.Lifecycle = corrosion.ConditionConfirmed
	row.Severity = corrosion.SeverityWarning
	row.Hosts = []string{r.hostName}
	row.Evidence = string(b)
	row.ObserveCount++
	row.CleanCount = 0
	row.LastSeen = ts
	row.ResolvedAt = ""
	row.Reporter = r.hostName
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Error("reconciler: could not record vm_disk_kept_base", "vm", vmName, "error", err)
	}
	return true
}

// resolveKeptRebuildRefused resolves this host's vm_disk_kept_base rows
// whose VM has left a pending, starting or error state here. Not while the
// replica is catching up.
func (r *Reconciler) resolveKeptRebuildRefused(ctx context.Context) {
	if ok, _ := r.replicaTrusted(ctx); !ok {
		return
	}
	open, err := corrosion.ListHealthConditions(ctx, r.db, false)
	if err != nil {
		return
	}
	suffix := "@" + r.hostName
	for _, row := range open {
		if row.Evaluator != DiskMissingEvaluator || row.Code != CondVMDiskKeptBase || !strings.HasSuffix(row.SubjectID, suffix) {
			continue
		}
		name := strings.TrimSuffix(row.SubjectID, suffix)
		vm, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil {
			continue
		}
		if vm != nil && vm.HostName == r.hostName && (vm.State == "pending" || vm.State == "starting" || vm.State == "error") {
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
			slog.Warn("reconciler: could not resolve vm_disk_kept_base", "vm", name, "error", err)
			continue
		}
		slog.Info("reconciler: vm_disk_kept_base resolved — the VM left the refused rebuild on this host", "vm", name)
	}
}
