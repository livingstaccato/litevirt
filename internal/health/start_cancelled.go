package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A start an operator cancelled keeps its set-aside disk copies held.
//
// A VM in pending or starting holds the copies a failover start set aside
// (supersededHoldStates): the start is unfinished and may need one put back.
// `lv stop --force` of such a VM whose domain was never defined cancels the
// start, and writes stopped/operator-stop, a state that holds nothing. So the
// cancel first records vm_start_cancelled (evaluator vm_disk, subject
// vm/<name>@<host>, info), and the copies of that VM stay held while it is
// open. It clears once the VM runs (the start it cancelled has then been
// made), is on another host, or is deleted.

// CondVMStartCancelled is filed under DiskMissingEvaluator.
const CondVMStartCancelled = "vm_start_cancelled"

// StartCancelled is the evidence of vm_start_cancelled.
type StartCancelled struct {
	VM    string `json:"vm"`
	Host  string `json:"host"`
	State string `json:"state"` // the state the start was cancelled in
	// Transfer: the start cancelled was a proof-less transfer onto Host
	// (deferredTransfers), whose start sets aside an old copy found at the
	// disk path. A start of the VM made again is the same transfer.
	Transfer bool   `json:"transfer,omitempty"`
	At       string `json:"at"`
	Detail   string `json:"detail"`
}

// CancelStartLockHolder is the per-VM start lease identity of an operator's
// cancel of a start (`lv stop --force`): held while the cancel is written, so
// no start path starts the VM in the middle of it.
func CancelStartLockHolder(hostName string) string { return hostName + "/cancel-start" }

// RecordStartCancelled records that the start of vmName on host, in state,
// was cancelled, and returns the detail for the caller's event.
func RecordStartCancelled(ctx context.Context, db *corrosion.Client, host, vmName, state string, transfer bool, now time.Time) (string, error) {
	ts := now.UTC().Format(time.RFC3339)
	ev := StartCancelled{VM: vmName, Host: host, State: state, Transfer: transfer, At: ts}
	ev.Detail = fmt.Sprintf("start cancelled: %s was %s on %s with no domain defined, and an operator's forced stop cancelled the start; "+
		"it stays stopped until `lv start %s` makes the start again, and the disk copies a failover set aside for it stay held until it runs", vmName, state, host, vmName)
	b, err := json.Marshal(ev)
	if err != nil {
		return "", err
	}
	row, had, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMStartCancelled, "vm", strandedSubject(vmName, host))
	if err != nil {
		return "", err
	}
	if had && row.Lifecycle != corrosion.ConditionResolved {
		// A start cancelled again is still the transfer it was.
		var prev StartCancelled
		if json.Unmarshal([]byte(row.Evidence), &prev) == nil && prev.Transfer && !ev.Transfer {
			ev.Transfer = true
			if b, err = json.Marshal(ev); err != nil {
				return "", err
			}
		}
	}
	if !had || row.Lifecycle == corrosion.ConditionResolved {
		row = corrosion.HealthCondition{
			Evaluator: DiskMissingEvaluator, Code: CondVMStartCancelled, SubjectKind: "vm",
			SubjectID: strandedSubject(vmName, host), FirstSeen: ts, ConfirmedAt: ts,
		}
	}
	row.Lifecycle, row.Severity, row.Hosts = corrosion.ConditionConfirmed, corrosion.SeverityInfo, []string{host}
	row.Evidence, row.LastSeen, row.Reporter, row.ResolvedAt = string(b), ts, host, ""
	row.ObserveCount++
	row.CleanCount = 0
	if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
		return "", err
	}
	return ev.Detail, nil
}

// StartCancelledOf returns the open vm_start_cancelled record of vmName on
// host, or nil.
func StartCancelledOf(ctx context.Context, db *corrosion.Client, vmName, host string) (*StartCancelled, error) {
	row, had, err := corrosion.GetHealthCondition(ctx, db, DiskMissingEvaluator, CondVMStartCancelled, "vm", strandedSubject(vmName, host))
	if err != nil || !had || row.Lifecycle == corrosion.ConditionResolved {
		return nil, err
	}
	var ev StartCancelled
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM != vmName || ev.Host != host {
		return nil, err
	}
	return &ev, nil
}

// IsDeferredTransfer reports whether vmName's start, parked in "starting",
// is a proof-less transfer onto this host (deferredTransfers), for a cancel
// of it to record.
func (r *Reconciler) IsDeferredTransfer(vmName string) bool { return r.deferredTransfers.has(vmName) }

// cancelledTransfer reports whether a start of vmName in "starting" makes
// again a proof-less transfer an operator cancelled on this host: its open
// vm_start_cancelled says so. Durable, unlike deferredTransfers.
func (r *Reconciler) cancelledTransfer(ctx context.Context, vmName string) bool {
	ev, err := StartCancelledOf(ctx, r.db, vmName, r.hostName)
	return err == nil && ev != nil && ev.Transfer
}

// cancelledSinceStart reports whether vmName's row, re-read now, says its
// operator stopped it: once startPendingVM has written "starting", that is a
// stop made while the start was under way, which the start must not
// override. The read is local and not cut short by the walk budget.
func (r *Reconciler) cancelledSinceStart(ctx context.Context, vmName string) bool {
	fresh, err := corrosion.GetVM(context.WithoutCancel(ctx), r.db, vmName)
	return err == nil && fresh != nil && fresh.State == "stopped" && IsOperatorStop(fresh.StateDetail)
}

// cancelledStarts is the open vm_start_cancelled records, by VM: the host
// each start was cancelled on.
func cancelledStarts(ctx context.Context, db *corrosion.Client) (map[string]string, error) {
	rows, err := corrosion.ListOpenHealthConditionsByCode(ctx, db, DiskMissingEvaluator, CondVMStartCancelled)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, row := range rows {
		var ev StartCancelled
		if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM == "" || ev.Host == "" ||
			row.SubjectID != strandedSubject(ev.VM, ev.Host) {
			continue
		}
		out[ev.VM] = ev.Host
	}
	return out, nil
}

// resolveStartCancelled clears a vm_start_cancelled record once it holds
// nothing: the VM runs on the host it names, is on another host, or is gone.
// Only that host clears it while the VM is there; any host once it is gone.
func (r *Reconciler) resolveStartCancelled(ctx context.Context, row corrosion.HealthCondition) {
	var ev StartCancelled
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil || ev.VM == "" || ev.Host == "" {
		return
	}
	vm, err := corrosion.GetVM(ctx, r.db, ev.VM)
	if err != nil {
		return
	}
	if vm != nil && vm.HostName == ev.Host {
		if ev.Host != r.hostName || vm.State != "running" || !r.domainRunningHere(vm.Name) {
			return
		}
	}
	ts := r.now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, ts, ts, r.hostName
	row.ObserveCount, row.CleanCount = 0, 1
	if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
		slog.Warn("reconciler: could not resolve vm_start_cancelled", "vm", ev.VM, "error", err)
	}
}

// startCancelledHeld is why a copy of vm is held by a cancelled start, or "".
func startCancelledHeld(cancelled map[string]string, vm *corrosion.VMRecord) string {
	if host, ok := cancelled[vm.Name]; ok && host == vm.HostName && !strings.EqualFold(vm.State, "running") {
		return fmt.Sprintf("VM %s's start on %s was cancelled before it finished (vm_start_cancelled)", vm.Name, host)
	}
	return ""
}
