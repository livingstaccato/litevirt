package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

// deviceLeaseStageMigrationDetached marks a device lease MigrateVM writes before
// it takes an SR-IOV VF out of the guest for a move. Between that detach and the
// migration's outcome the VF is owned by the VM, vfio-bound, and in no guest —
// the one state no other record explains. The lease is what a restart reads to
// finish the job (recoverMigrationVFLease): back into the guest if it stayed,
// released if it left.
//
// It is the existing device_lease entry (same ID, same kind), so a binary that
// predates this stage reads it as a completed allocation and clears it without
// touching a device — the VF is then left owned + bound, never unowned + bound.
const deviceLeaseStageMigrationDetached = "migration_detached"

// beginMigrationVFLease durably records, before the first VF leaves the guest,
// the VFs MigrateVM is about to detach. A write error stops the migration with
// nothing touched: a detach with no crash anchor is the loss this prevents.
//
// Unlike beginDeviceLease it is not gated on operation_protocol. The lease is
// host-local, nothing on a peer relies on it, and MigrateVM detaches VFs
// whether the protocol is on or not.
//
// The lease ID is one per VM, so it refuses to overwrite a lease an attach left
// recovery-required (in_progress / rollback_incomplete): that entry is the only
// record of devices still owned + bound, and replacing it would lose them. A
// leftover bound lease (a completed allocation) or an earlier migration's lease
// carries nothing a new one does not, and is overwritten.
func (s *Server) beginMigrationVFLease(vmName string, addrs []string) error {
	if s.opJournal == nil || len(addrs) == 0 {
		return nil
	}
	existing, found, err := s.opJournal.Read(deviceLeaseOpID(vmName))
	if err != nil {
		return fmt.Errorf("read the VM's device lease: %w", err)
	}
	if found && (existing.Stage == deviceLeaseStageInProgress || existing.Stage == deviceLeaseStageRollbackIncomplete) {
		return fmt.Errorf("a device allocation for %q awaits recovery (lease stage %s)", vmName, existing.Stage)
	}
	return s.opJournal.Write(opjournal.Entry{
		OperationID: deviceLeaseOpID(vmName),
		ResourceID:  vmName,
		Kind:        deviceLeaseKind,
		Stage:       deviceLeaseStageMigrationDetached,
		Artifacts:   map[string]string{"addresses": strings.Join(addrs, ",")},
		CreatedAt:   time.Now().UTC().Format(time.RFC3339),
	})
}

// endMigrationVFLease removes the migration's lease once every VF it names is
// settled. Only a migration_detached lease: anything else under the ID is not
// this migration's to clear.
func (s *Server) endMigrationVFLease(vmName string) {
	if s.opJournal == nil {
		return
	}
	e, found, err := s.opJournal.Read(deviceLeaseOpID(vmName))
	if err != nil || !found || e.Stage != deviceLeaseStageMigrationDetached {
		return
	}
	if err := s.opJournal.Remove(deviceLeaseOpID(vmName)); err != nil {
		slog.Warn("migrate: clear the VF lease", "vm", vmName, "error", err)
	}
}

// releaseSourceVFsAfterCutover gives up the source's VFs once the cutover has
// committed: the guest runs on the target, which allocates its own. Until here
// the VM owned them, so nothing could take one mid-move.
//
// Through the strict primitive: a VF whose unbind cannot be confirmed stays
// owned + bound and the lease stays, so a restart retries the release. Never
// fails the migration — the guest has moved.
func (s *Server) releaseSourceVFsAfterCutover(ctx context.Context, vmName string, vfs []corrosion.PCIDeviceRecord) {
	if len(vfs) == 0 {
		return
	}
	if err := s.unbindAndReleaseOwnership(ctx, vmName, pciAddresses(vfs)); err != nil {
		slog.Error("migrate: the source's VFs could not be released after the cutover — left owned and bound",
			"vm", vmName, "error", err)
		s.recordVMEvent(ctx, vmName, "device.detached", "error",
			"VFs left on "+s.hostName+" by the migration are still owned and bound; a daemon restart retries the release: "+err.Error())
		return
	}
	s.endMigrationVFLease(vmName)
}

// recoverMigrationVFLease is RecoverDeviceLeases for a migration_detached
// lease: a daemon that died with VFs out of the guest for a move. It reports
// whether the lease is settled and may be removed; false keeps it for a later
// start.
//
//   - The row names another host: the cutover committed. The VFs are this
//     host's leftovers and are released, unless a domain of the VM still runs
//     here, which nothing can safely decide about.
//   - The row names this host and the domain is running: the guest stayed. Each
//     VF goes back in, as a failed migration does (reattachVFOnSource).
//   - The row names this host and the domain is positively shut off: there is
//     nothing to put them into. Released, as reattachVFsOnSource does.
//   - Anything else (state unreadable, paused, no domain while the row still
//     says here): nothing is touched and the lease is kept.
func (s *Server) recoverMigrationVFLease(ctx context.Context, vm *corrosion.VMRecord, addrs []string) bool {
	if s.virt == nil {
		return false
	}
	release := func() bool {
		if err := s.unbindAndReleaseOwnership(ctx, vm.Name, addrs); err != nil {
			slog.Error("device-lease recovery: releasing VFs left by a migration — retaining lease", "vm", vm.Name, "error", err)
			return false
		}
		return true
	}
	if vm.HostName != s.hostName {
		if s.virt.DomainExists(vm.Name) && s.recoveryDomainDisposition(vm.Name) != dispShutoff {
			slog.Warn("device-lease recovery: VM moved away but a domain of it is still here and not shut off — retaining lease",
				"vm", vm.Name, "host", vm.HostName, "devices", addrs)
			return false
		}
		slog.Info("device-lease recovery: migration cut over; releasing the source's VFs", "vm", vm.Name, "to", vm.HostName, "devices", addrs)
		return release()
	}
	switch s.recoveryDomainDisposition(vm.Name) {
	case dispRunning:
		settled := true
		for _, addr := range addrs {
			if err := s.reattachVFOnSource(ctx, vm.Name, addr); err != nil {
				settled = false
				slog.Error("device-lease recovery: could not reattach a VF detached for a migration — retaining lease",
					"vm", vm.Name, "address", addr, "error", err)
				s.recordVMEvent(ctx, vm.Name, "device.attached", "error",
					"VF "+addr+" detached for a migration interrupted by a restart could not be reattached: "+err.Error())
				continue
			}
			slog.Info("device-lease recovery: VF reattached after an interrupted migration", "vm", vm.Name, "address", addr)
		}
		return settled
	case dispShutoff:
		return release()
	default:
		return false
	}
}

func pciAddresses(devs []corrosion.PCIDeviceRecord) []string {
	out := make([]string, 0, len(devs))
	for _, d := range devs {
		out = append(out, d.Address)
	}
	return out
}
