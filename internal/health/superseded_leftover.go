package health

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// A deleted VM's shut-off definition on a host a failover moved it off.
//
// The reconciler's leftover cleanup (selfFence) undefines a shut-off domain
// whose LIVE row names another host. A VM deleted before its old host's first
// pass after a rejoin has no live row there, so that cleanup skips it, the
// delete's leftover request declines while the domain is defined, and the
// orphan report only reports it.
//
// Such a domain is undefined here, by the reconciler (on the second
// consecutive sighting, as the orphan report) and by the delete's leftover
// request, only when every one of these holds:
//
//   - no live row of the name on this host's replica, and the replica is
//     trusted (the caller checks);
//   - the name's row is tombstoned and names ANOTHER host;
//   - the domain carries litevirt's owner-epoch element, and the row's owner
//     epoch is STRICTLY greater than it: the record moved past this copy
//     before it was deleted;
//   - the host-local owner-epoch marker is absent or below the row's epoch;
//     an unreadable one keeps the domain;
//   - the domain is shut off: cleanableLeftover, or a shut-off with an unknown
//     reason and no managed-save image.
//
// Undefine only: no destroy, no disk touched, and the UEFI vars and TPM state
// kept (UndefineDomainPreservingState), since no replicated record says
// whether the delete was `lv rm --keep-disks`. Then the owner-epoch marker
// goes, once the domain is gone and the name still has no live row. A running
// or paused domain, an equal or older row epoch, a managed-stamp-only domain
// and anything unreadable stay report-only.

// SupersededLeftoverVirt is the libvirt surface the rule needs.
type SupersededLeftoverVirt interface {
	DomainExists(name string) bool
	DomainStateReason(name string) (lv.DomainStatus, error)
	HasManagedSaveImage(name string) (bool, error)
	GetDomainOwnerEpoch(name string) (int64, bool, error)
	UndefineDomainPreservingState(name string) error
}

// SupersededLeftover is a shut-off domain the rule admits.
type SupersededLeftover struct {
	Name          string
	RowHost       string
	RowOwnerEpoch int64
	MarkerEpoch   int64
	Reason        string // the shut-off reason
}

// supersededStoppedLeftover applies the rule to name. ok=false carries why.
func supersededStoppedLeftover(ctx context.Context, db *corrosion.Client, virt SupersededLeftoverVirt,
	dataDir, self, name string) (SupersededLeftover, bool, string) {
	lo := SupersededLeftover{Name: name}
	if vm, err := corrosion.GetVM(ctx, db, name); err != nil {
		return lo, false, "the record cannot be read: " + err.Error()
	} else if vm != nil {
		return lo, false, "the name has a live record"
	}
	trace, err := corrosion.LookupVMRowAnyState(ctx, db, name)
	if err != nil {
		return lo, false, "the deleted record cannot be read: " + err.Error()
	}
	if trace == nil || trace.DeletedAt == "" {
		return lo, false, "no deleted record of the name"
	}
	lo.RowHost, lo.RowOwnerEpoch = trace.HostName, trace.OwnerEpoch
	if trace.HostName == "" || trace.HostName == self {
		return lo, false, "the deleted record names this host"
	}
	epoch, marked, err := virt.GetDomainOwnerEpoch(name)
	if err != nil {
		return lo, false, "the domain's owner epoch cannot be read: " + err.Error()
	}
	if !marked || epoch < 1 {
		return lo, false, "the domain carries no owner epoch"
	}
	lo.MarkerEpoch = epoch
	if trace.OwnerEpoch <= epoch {
		return lo, false, fmt.Sprintf("the deleted record's owner epoch %d is not newer than the domain's %d", trace.OwnerEpoch, epoch)
	}
	if fileEpoch, has, err := ReadVMOwnerEpochMarker(dataDir, name); err != nil {
		return lo, false, "the owner-epoch marker cannot be read: " + err.Error()
	} else if has && fileEpoch >= trace.OwnerEpoch {
		return lo, false, fmt.Sprintf("the owner-epoch marker %d is not older than the deleted record's %d", fileEpoch, trace.OwnerEpoch)
	}
	st, err := virt.DomainStateReason(name)
	if err != nil {
		return lo, false, "the domain's state cannot be read: " + err.Error()
	}
	lo.Reason = st.Reason
	if cleanableLeftover(st) {
		return lo, true, ""
	}
	if !unknownShutoff(st) {
		return lo, false, fmt.Sprintf("the domain is not shut off (state %s, reason %s)", st.State, st.Reason)
	}
	saved, err := virt.HasManagedSaveImage(name)
	if err != nil {
		return lo, false, "whether the domain has a managed-save image cannot be read: " + err.Error()
	}
	if saved {
		return lo, false, "the domain has a managed-save image (saved RAM)"
	}
	return lo, true, ""
}

// ReapSupersededStoppedLeftover undefines name here when the rule above
// admits it, then removes its owner-epoch marker, and records a VM event. by
// names the caller for the log. It returns whether it undefined the domain,
// and otherwise why not. The caller has checked the replica is trusted.
func ReapSupersededStoppedLeftover(ctx context.Context, db *corrosion.Client, virt SupersededLeftoverVirt,
	dataDir, self, name, by string) (bool, string) {
	lo, ok, why := supersededStoppedLeftover(ctx, db, virt, dataDir, self, name)
	if !ok {
		return false, why
	}
	if err := virt.UndefineDomainPreservingState(name); err != nil {
		if !virt.DomainExists(name) {
			return false, "the domain is already gone"
		}
		slog.Warn(by+": could not undefine a deleted VM's superseded shut-off domain; kept",
			"vm", name, "error", err)
		return false, "undefine failed: " + err.Error()
	}
	if virt.DomainExists(name) {
		// It started between the check and the undefine: it survives as a
		// transient domain, running, and is left to the orphan report.
		slog.Warn(by+": a deleted VM's superseded domain was running at its undefine; left to the orphan report",
			"vm", name)
		return false, "the domain was running at its undefine"
	}
	marker := "removed"
	if vm, err := corrosion.GetVM(ctx, db, name); err != nil || vm != nil {
		marker = "kept (the name has a live record again, or it cannot be read)"
	} else if err := RemoveVMOwnerEpochMarker(dataDir, name); err != nil {
		marker = "not removed: " + err.Error()
	}
	detail := fmt.Sprintf("%s undefined its shut-off definition of deleted VM %s: the deleted record names %s at owner epoch %d, "+
		"newer than this copy's %d; disks, UEFI vars and TPM state kept; owner-epoch marker %s",
		self, name, lo.RowHost, lo.RowOwnerEpoch, lo.MarkerEpoch, marker)
	slog.Warn(by+": undefined a deleted VM's superseded shut-off domain",
		"vm", name, "host", self, "row_host", lo.RowHost, "row_owner_epoch", lo.RowOwnerEpoch,
		"marker_epoch", lo.MarkerEpoch, "reason", lo.Reason, "owner_epoch_marker", marker)
	if err := corrosion.InsertVMEvent(ctx, db, corrosion.VMEventRecord{
		VMName: name, HostName: self, Type: "vm.leftover.undefined", Result: "ok", Severity: "info",
		Detail: detail, Username: by,
	}); err != nil && !errors.Is(err, context.Canceled) {
		slog.Warn(by+": record the undefine's event", "vm", name, "error", err)
	}
	return true, ""
}
