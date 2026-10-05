package grpcapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// firmwareTargetLedger is a cold firmware migration target's own record of
// the domains EnsureFirmwareState defined here, keyed by VM name, with the
// attempt that defined each.
//
// A cold firmware migration defines the domain on the target before the
// ownership handoff commits, so an attempt that fails in between — a cancelled
// request, a failed commit — has to take that domain back, or the retry is
// refused over "already-defined domain". Only what the attempt created may be
// taken back: EnsureFirmwareState refuses a domain that is already defined, so
// a domain present on the target after a failed attempt may be one it found
// there, and a source whose request was cancelled mid-call cannot tell which.
// The target can. RollbackFirmwareState removes a domain only when this ledger
// says the same attempt defined it.
//
// It is in memory, like migrationStubLedger, and a restart forgets it in the
// safe direction: a domain defined before the restart is no longer
// recognised, the rollback leaves it, and the source names it as a leftover.
// An entry expires after stubLedgerTTL for the same reason a stub does.
//
// op serialises EnsureFirmwareState's check-materialize-define with
// RollbackFirmwareState's undefine-wipe, so a rollback can never wipe
// firmware a concurrent attempt has just materialized for its own domain.
type firmwareTargetLedger struct {
	op sync.Mutex

	mu sync.Mutex
	m  map[string]firmwareTargetEntry
}

type firmwareTargetEntry struct {
	attempt string
	uuid    string
	at      time.Time
}

func (l *firmwareTargetLedger) add(vm, attempt, uuid string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil {
		l.m = map[string]firmwareTargetEntry{}
	}
	l.m[vm] = firmwareTargetEntry{attempt: attempt, uuid: uuid, at: time.Now()}
}

// owns reports whether attempt defined vm's domain here (with firmware uuid)
// and the entry has not outlived its TTL. An empty attempt owns nothing.
func (l *firmwareTargetLedger) owns(vm, attempt, uuid string) bool {
	if attempt == "" {
		return false
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[vm]
	if !ok {
		return false
	}
	if time.Since(e.at) > stubLedgerTTL() {
		delete(l.m, vm)
		return false
	}
	return e.attempt == attempt && strings.EqualFold(e.uuid, uuid)
}

func (l *firmwareTargetLedger) forget(vm string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.m, vm)
}

// RollbackFirmwareState undefines the domain and wipes the firmware state that
// EnsureFirmwareState created here for req.AttemptId, after that cold firmware
// migration failed before its handoff committed. Anything else is left: a
// domain this host did not define for that attempt, and any VM whose row names
// this host (the handoff did commit, so it is the live VM now).
func (s *Server) RollbackFirmwareState(ctx context.Context, req *pb.RollbackFirmwareStateRequest) (*pb.RollbackFirmwareStateResponse, error) {
	vm, err := s.authorizeMigrationHelper(ctx, req.VmName)
	if err != nil {
		return nil, err
	}
	if req.AttemptId == "" {
		return nil, status.Error(codes.InvalidArgument, "attempt_id is required")
	}
	// The same binding EnsureFirmwareState and CleanupMigrationArtifacts make:
	// the uuid keys a RemoveAll under the swtpm root, and the permission was
	// checked on vm_name alone.
	if req.Uuid != "" && (!lv.ValidFirmwareUUID(req.Uuid) ||
		!strings.EqualFold(parseFirmwareSpec(vm.Spec).UUID, req.Uuid)) {
		return nil, status.Errorf(codes.InvalidArgument,
			"firmware uuid %q is not the recorded uuid of VM %q", req.Uuid, req.VmName)
	}

	s.firmwareTargets.op.Lock()
	defer s.firmwareTargets.op.Unlock()
	if !s.firmwareTargets.owns(req.VmName, req.AttemptId, req.Uuid) {
		slog.Info("rollback firmware state: this host holds nothing of that attempt; leaving the domain",
			"vm", req.VmName, "attempt", req.AttemptId)
		return &pb.RollbackFirmwareStateResponse{}, nil
	}
	if vm.HostName == s.hostName {
		slog.Warn("rollback firmware state: VM lives on this host; leaving its domain and firmware",
			"vm", req.VmName, "attempt", req.AttemptId)
		s.firmwareTargets.forget(req.VmName)
		return &pb.RollbackFirmwareStateResponse{}, nil
	}
	// Undefine BEFORE wiping, and keep the firmware if the undefine fails: a
	// defined domain whose firmware was erased is worse than a leftover.
	if s.virt != nil && s.virt.DomainExists(req.VmName) {
		if err := s.virt.UndefineDomainPreservingState(req.VmName); err != nil {
			return nil, status.Errorf(codes.Internal,
				"undefine domain %q failed; left firmware in place (recoverable): %v", req.VmName, err)
		}
	}
	// A VM without firmware state was defined with no bundle: there is no
	// firmware of this attempt's to wipe, and the name-keyed files here may be
	// another VM's.
	if usesFirmwareState(vm.Spec) {
		lv.WipeFirmwareState(s.dataDir, req.VmName, req.Uuid)
	}
	s.firmwareTargets.forget(req.VmName)
	slog.Info("rollback firmware state: removed the domain and firmware this attempt defined",
		"vm", req.VmName, "attempt", req.AttemptId)
	return &pb.RollbackFirmwareStateResponse{Removed: true}, nil
}

// firmwareTargetOutcome is what a cold firmware migration's source knows about
// what its EnsureFirmwareState call left on the target.
type firmwareTargetOutcome int

const (
	// fwTargetUntouched: the call was never sent.
	fwTargetUntouched firmwareTargetOutcome = iota
	// fwTargetDefined: the target said it defined the domain for this attempt.
	fwTargetDefined
	// fwTargetUnreported: the call succeeded, but the target did not say what
	// it created — a build from before EnsureFirmwareStateResponse.
	fwTargetUnreported
	// fwTargetUnknown: the call failed, possibly after the target defined the
	// domain (a cancelled request loses the answer).
	fwTargetUnknown
)

// abandonFirmwareTarget is a cold firmware migration's rollback of the target
// after a failure before the handoff committed: it asks the target to remove
// what THIS attempt created there, and nothing else. It runs detached from the
// request — a cancelled request is one of the failures it cleans up after.
//
// When the target cannot confirm it removed a domain this attempt may have
// defined — it is too old to say, or unreachable — the domain is left, and the
// returned error names it, because the retry will be refused over it.
func (s *Server) abandonFirmwareTarget(ctx context.Context, targetHost, vmName, uuid, attempt string, outcome firmwareTargetOutcome, cause error) error {
	switch outcome {
	case fwTargetUntouched:
		return cause
	case fwTargetUnreported:
		return firmwareLeftoverError(cause, targetHost, vmName, "it is too old to report what it created")
	}
	rctx, cancel := detachedMigrateCleanupCtx(ctx)
	defer cancel()
	client, closeConn, err := s.dialPeer(rctx, targetHost)
	if err != nil {
		slog.Warn("cold firmware migration: cannot reach the target to roll it back", "host", targetHost, "vm", vmName, "error", err)
		return firmwareLeftoverError(cause, targetHost, vmName, "it could not be reached")
	}
	defer closeConn()
	resp, err := client.RollbackFirmwareState(rctx, &pb.RollbackFirmwareStateRequest{
		VmName: vmName, Uuid: uuid, AttemptId: attempt,
	})
	switch {
	case status.Code(err) == codes.Unimplemented:
		return firmwareLeftoverError(cause, targetHost, vmName, "it is too old to roll back an attempt")
	case err != nil:
		slog.Warn("cold firmware migration: target rollback failed", "host", targetHost, "vm", vmName, "error", err)
		return firmwareLeftoverError(cause, targetHost, vmName, "its rollback failed: "+err.Error())
	case resp.GetRemoved():
		slog.Info("cold firmware migration: rolled back the target", "host", targetHost, "vm", vmName)
		return cause
	case outcome == fwTargetDefined:
		// It said it defined the domain and now holds no record of it — a
		// restart in between forgets the record.
		return firmwareLeftoverError(cause, targetHost, vmName, "it no longer recognises the domain as this attempt's")
	default:
		// The target holds nothing of this attempt's: the call failed before
		// it defined anything.
		return cause
	}
}

// firmwareLeftoverError keeps cause's code and adds the domain this attempt
// may have left defined on targetHost, and what to do about it.
func firmwareLeftoverError(cause error, targetHost, vmName, why string) error {
	st := status.Convert(cause)
	return status.Error(st.Code(), fmt.Sprintf(
		"%s; domain %q may still be defined on %s, with its firmware state, by this attempt — "+
			"the source left it because %s. Check it is not a VM that lives on %s, then undefine it "+
			"and remove its firmware state there before migrating again",
		st.Message(), vmName, targetHost, why, targetHost))
}
