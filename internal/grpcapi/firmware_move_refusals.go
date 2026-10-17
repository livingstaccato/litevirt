package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Entry refusals of a live firmware move (spec §6.9). While a record of the
// move names a VM on this host — its source marker or its target hold — the
// operations that could run, stop, redefine, undefine or overwrite either copy
// of its TPM or NVRAM state are refused at their entry, naming the host, the
// attempt, the peer and the phase. The guard (internal/libvirt, spec §5.1)
// refuses the libvirt calls beneath them as well; the entry refusal is what
// stops an operation that would go on past a refused best-effort call (K-7),
// and what names the move to the caller.
//
// A VM no record names goes on exactly as before: the check reads the
// records, finds none, and changes nothing.

// firmwareMoveRefusal is the entry refusal for an operation on vm: a
// FailedPrecondition when a record names it here by its name or by its spec
// uuid, or a record cannot be read; nil otherwise.
func (s *Server) firmwareMoveRefusal(op string, vm *corrosion.VMRecord) error {
	return s.firmwareMoveRecordsRefusal(op, vm.Name, specUUID(vm.Spec))
}

// firmwareMoveNameRefusal is the entry refusal for an operation that would
// take name for a new domain (create, import, restore-as, promote, a clone's
// target): the NVRAM is keyed by name, so a record of that name refuses.
func (s *Server) firmwareMoveNameRefusal(op, name string) error {
	return s.firmwareMoveRecordsRefusal(op, name, "")
}

// firmwareMoveRecordsRefusal is firmwareMoveRecordRefusal for a server that
// may have no data directory. A server without one cannot have written a
// record (the daemon never runs without one: fwmig.Wire refuses to install
// the guard), so it has none to refuse on.
func (s *Server) firmwareMoveRecordsRefusal(op, name, uuid string) error {
	if s.fw().DataDir == "" {
		return nil
	}
	return s.firmwareMoveRecordRefusal(op, name, uuid)
}

// firmwareMoveStopRefusal is StopVM's entry refusal (spec §6.9): the stop of
// a VM in a live firmware move is refused, with what resolves it. Scoped to
// the move's records: any other VM, one in `migrating` included, stops as
// before.
func (s *Server) firmwareMoveStopRefusal(vm *corrosion.VMRecord) error {
	err := s.firmwareMoveRefusal("stop", vm)
	if err == nil {
		return nil
	}
	return status.Errorf(codes.FailedPrecondition,
		"%s; it is left running until the move ends, or, if the move is parked, until the action its "+
			"firmware_migration condition names resolves it (the D-5 firmware-move doctor). A host drain or "+
			"shutdown-workloads reports this VM and goes on with the others", status.Convert(err).Message())
}

// errFirmwareMoveSkipped: a scheduled job left a VM in a live firmware move
// alone this run (spec §6.9: scheduled backups and replication skip it with a
// log line). Not a failure of the job.
var errFirmwareMoveSkipped = errors.New("skipped: a live firmware migration names the VM on this host")

// firmwareMoveSkip is the scheduled-job form of the entry refusal: nil when
// no record names vm here, else errFirmwareMoveSkipped wrapping the refusal,
// logged once per call.
func (s *Server) firmwareMoveSkip(job string, vm *corrosion.VMRecord) error {
	err := s.firmwareMoveRefusal(job, vm)
	if err == nil {
		return nil
	}
	slog.Info("firmware move: scheduled job skipped", "job", job, "vm", vm.Name, "host", s.hostName,
		"reason", status.Convert(err).Message())
	return fmt.Errorf("%w: %s", errFirmwareMoveSkipped, status.Convert(err).Message())
}

// firmwareMoverRefusal is the refusal of a mover that live-migrates without
// the live firmware move (spec §1, §12: the health-check migrate action, the
// rebalancer, CrossRegionMigrate's live move). A Secure Boot / vTPM VM is
// moved by `lv migrate` only. "" for any other VM.
func firmwareMoverRefusal(mover string, vm *corrosion.VMRecord) string {
	if vm == nil || !usesFirmwareState(vm.Spec) {
		return ""
	}
	return fmt.Sprintf("%s does not live-migrate Secure Boot / vTPM VM %q; move it with `lv migrate`", mover, vm.Name)
}

// migrateVMForHealthCheckRefusal is MigrateVMForHealthCheck's mover refusal.
func (s *Server) migrateVMForHealthCheckRefusal(ctx context.Context, vmName string) error {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil {
		return status.Errorf(codes.Unavailable, "health-check migrate of %q: read its row: %v", vmName, err)
	}
	if why := firmwareMoverRefusal("the health-check migrate action", vm); why != "" {
		return status.Error(codes.FailedPrecondition, why)
	}
	return nil
}
