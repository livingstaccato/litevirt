package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A guest disk write that fails with ENOSPC — a full storage pool, a thin
// volume out of backing space — pauses the guest's QEMU under QEMU's default
// write-error policy (werror=enospc; litevirt sets no error_policy). Other
// write errors (EIO) and read errors are reported to the guest instead and
// do not pause it. libvirt
// reports the domain paused, as it does an operator's pause, and every
// caller that reads Reason "paused" as "active, not executing" is right to:
// the guest holds its RAM and its disks, and is not a stop. What it was
// missing is any sign the guest is frozen. The owner raises vm_io_paused
// about the VM, warning severity, while its domain here is paused on an I/O
// error, and resolves it once the domain is anything else.
//
// The pause is not undone here: whether and when to resume a guest whose
// pool filled is the operator's call (the space has to be freed first, and
// a resume into a still-full pool pauses it again).
const (
	// VMIOPausedEvaluator is the evaluator of vm_io_paused.
	VMIOPausedEvaluator = "vm_io_pause"
	// CondVMIOPaused is the condition code of a VM whose guest QEMU paused
	// on a disk I/O error.
	CondVMIOPaused = "vm_io_paused"
)

// ioPausedWarnEvery is how often the sweep repeats a warning about one VM
// whose condition it cannot write: a host in write quarantine refuses every
// pass's attempt, and one line per VM per pass would bury the log.
const ioPausedWarnEvery = 10 * time.Minute

// ioPausedWarnings rate-limits those warnings, per VM.
type ioPausedWarnings struct {
	mu   sync.Mutex
	last map[string]time.Time
}

// due reports whether a warning about vm may be logged at now, and if so
// records it.
func (w *ioPausedWarnings) due(vm string, now time.Time) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	if t, ok := w.last[vm]; ok && now.Sub(t) < ioPausedWarnEvery {
		return false
	}
	if w.last == nil {
		w.last = map[string]time.Time{}
	}
	w.last[vm] = now
	return true
}

// clear forgets vm once its condition was written.
func (w *ioPausedWarnings) clear(vm string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.last, vm)
}

// vmIOPausedEvidence is the evidence JSON of a vm_io_paused row.
type vmIOPausedEvidence struct {
	PausedReason string `json:"paused_reason"`
	Host         string `json:"host"`
	Remedy       string `json:"remedy"`
}

// vmIOPausedRemedy is what the condition tells an operator about vm.
func vmIOPausedRemedy(vm string) string {
	return "the guest is frozen, not stopped: free space in the storage pool its disks live on (or fix the " +
		"failing disk), then resume it on its host (virsh resume " + vm + "); litevirt does not resume it on its own"
}

// reportIOPausedVMs raises vm_io_paused for every VM this host owns whose
// domain here is paused on an I/O error, and resolves every open one this
// host reported whose domain it has since seen not so paused (or gone). A
// domain libvirt does not answer for is neither raised nor resolved.
func (r *Reconciler) reportIOPausedVMs(ctx context.Context) {
	if r.virt == nil {
		return
	}
	domains, err := r.listDomainsBounded("io-paused: report")
	if err != nil {
		return
	}
	ioPaused := map[string]bool{}
	unanswered := map[string]bool{}
	for _, name := range domains {
		if !r.domainAnswers(name) {
			unanswered[name] = true
			continue
		}
		st, err := r.virt.DomainStateReason(name)
		if err != nil {
			unanswered[name] = true
			continue
		}
		if st.Reason == "paused" && st.PausedReason == lv.PausedReasonIOError {
			ioPaused[name] = true
		}
	}
	open, err := corrosion.ListOpenHealthConditionsByCode(ctx, r.db, VMIOPausedEvaluator, CondVMIOPaused)
	if err != nil {
		slog.Warn("io-paused: cannot read open conditions; not reporting this pass", "error", err)
		return
	}
	openHere := map[string]corrosion.HealthCondition{}
	for _, row := range open {
		if row.SubjectKind == "vm" && row.Reporter == r.hostName {
			openHere[row.SubjectID] = row
		}
	}
	at := r.now()
	now := at.UTC().Format(time.RFC3339)
	for name := range ioPaused {
		if _, ok := openHere[name]; ok {
			continue
		}
		vm, err := corrosion.GetVM(ctx, r.db, name)
		if err != nil || vm == nil || vm.HostName != r.hostName {
			continue // not a VM this host owns: the owner reports its own
		}
		ev, _ := json.Marshal(vmIOPausedEvidence{PausedReason: lv.PausedReasonIOError, Host: r.hostName, Remedy: vmIOPausedRemedy(name)})
		row := corrosion.HealthCondition{
			Evaluator: VMIOPausedEvaluator, Code: CondVMIOPaused,
			SubjectKind: "vm", SubjectID: name,
			Lifecycle: corrosion.ConditionConfirmed, Severity: corrosion.SeverityWarning,
			Hosts: []string{r.hostName}, Evidence: string(ev), ObserveCount: 1,
			FirstSeen: now, LastSeen: now, ConfirmedAt: now, Reporter: r.hostName,
		}
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			if r.ioPausedWarn.due(name, at) {
				slog.Warn("io-paused: VM's guest is paused on a disk write error, and raising vm_io_paused failed (repeated at most every 10m)",
					"vm", name, "error", err)
			}
			continue
		}
		r.ioPausedWarn.clear(name)
		slog.Warn("io-paused: VM's guest is paused on a disk write error (a full storage pool?)", "vm", name)
	}
	for name, row := range openHere {
		if ioPaused[name] || unanswered[name] {
			continue
		}
		row.Lifecycle, row.ResolvedAt, row.LastSeen, row.Reporter = corrosion.ConditionResolved, now, now, r.hostName
		if err := corrosion.UpsertHealthCondition(ctx, r.db, row); err != nil {
			if r.ioPausedWarn.due(name, at) {
				slog.Warn("io-paused: resolving vm_io_paused failed (repeated at most every 10m)", "vm", name, "error", err)
			}
			continue
		}
		r.ioPausedWarn.clear(name)
		slog.Info("io-paused: VM's guest is no longer paused on an I/O error", "vm", name)
	}
}
