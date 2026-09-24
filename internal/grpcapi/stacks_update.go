package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// An update is applied with the least destructive mechanism the change allows
// (planner.VMAction.Apply): in place on the running VM, a reconfigure +
// restart of the same VM, or — only for a change of identity — a recreate,
// which replaces the disks. The update strategy decides how a change that
// needs a new VM is rolled out; it never turns a change that can keep the VM
// into a recreate.

// applyUpdateKeepingVM applies an update whose mechanism keeps the VM:
// in place (ActionLive / ActionNoChange) or reconfigure + restart
// (ActionRestart). It never deletes anything.
func (s *Server) applyUpdateKeepingVM(ctx context.Context, name string, desired *pb.VMSpec, plan compose.ChangePlan, apply compose.Action) error {
	if apply == compose.ActionRestart {
		return s.reconfigureWithRestart(ctx, name, desired, plan)
	}
	return s.applyLiveUpdate(ctx, name, desired, plan)
}

// applyLiveUpdate applies a plan's live changes to the running VM: a cpu grow
// within the hotplug ceiling or a balloon within the band, and the
// spec-persisted metadata. No stop, no redefine.
func (s *Server) applyLiveUpdate(ctx context.Context, name string, desired *pb.VMSpec, plan compose.ChangePlan) error {
	if len(plan.ResourceChanges) > 0 {
		vm, err := corrosion.GetVM(ctx, s.db, name)
		if err != nil || vm == nil {
			return status.Errorf(codes.NotFound, "VM %q not found", name)
		}
		if vm.State != "running" {
			// Nothing to resize live: a stopped VM's size is its definition,
			// which UpdateVM rewrites without starting it.
			return s.reconfigureWithRestart(ctx, name, desired, plan)
		}
		if err := (&serverOps{s: s}).ResizeVMLive(ctx, name, desired); err != nil {
			return fmt.Errorf("live resize: %w", err)
		}
		// The compose file's size is the VM's size from now on — its next
		// boot included. (A live resize under the operation protocol already
		// records it; a pre-protocol balloon only records the live actual.)
		if err := s.persistResourceSize(ctx, name, desired, plan); err != nil {
			return err
		}
	}
	if fields := planMetadataFields(plan); len(fields) > 0 {
		if err := s.applyLiveMetadata(ctx, name, desired, fields); err != nil {
			return fmt.Errorf("live metadata: %w", err)
		}
	}
	return nil
}

// reconfigureWithRestart applies a restart-class plan to the same VM through
// UpdateVM with allow_restart: stop → redefine → start under the VM lock,
// keeping its disks, MACs and incarnation (a stopped VM is redefined and left
// stopped). The plan's metadata changes are applied after.
func (s *Server) reconfigureWithRestart(ctx context.Context, name string, desired *pb.VMSpec, plan compose.ChangePlan) error {
	if len(plan.NotReconfigurable) > 0 {
		// The planner turns these into a recreate; reaching here is a bug, and
		// UpdateVM would silently drop the change.
		return fmt.Errorf("%s cannot be applied by a reconfigure", strings.Join(plan.NotReconfigurable, "; "))
	}
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil || vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", name)
	}
	stored := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), stored); err != nil {
			return status.Errorf(codes.Internal, "parse stored spec for %q: %v", name, err)
		}
	}
	allow := true
	req := &pb.UpdateVMRequest{Name: name, AllowRestart: &allow, DisableVnc: desired.DisableVnc}
	if compose.IsTransientOrErrorState(vm.State) {
		// A VM a previous deploy left half-made: repair it — redefine the
		// domain from the spec over its existing disks, and start it — even
		// when nothing in the spec changed. Naming the cpu makes UpdateVM take
		// its redefine path.
		req.Cpu = stored.Cpu
		if desired.Cpu != 0 {
			req.Cpu = desired.Cpu
		}
	}
	if desired.Cpu != 0 && desired.Cpu != stored.Cpu {
		req.Cpu = desired.Cpu
	}
	if desired.MemoryMib != 0 && desired.MemoryMib != stored.MemoryMib {
		req.MemoryMib = desired.MemoryMib
	}
	if desired.CpuMode != "" && desired.CpuMode != stored.CpuMode {
		req.CpuMode = desired.CpuMode
	}
	if desired.CpuModel != "" && desired.CpuModel != stored.CpuModel {
		req.CpuModel = desired.CpuModel
		if req.CpuMode == "" {
			req.CpuMode = desired.CpuMode
		}
	}
	if hasReason(plan.RestartReasons, "machine-type") {
		req.Machine = desired.Machine
	}
	if desired.Firmware != "" && desired.Firmware != stored.Firmware {
		req.Firmware = desired.Firmware
	}
	if desired.GuestAgent != stored.GuestAgent {
		v := desired.GuestAgent
		req.GuestAgent = &v
	}
	if desired.MinMemoryMib != 0 && desired.MinMemoryMib != stored.MinMemoryMib {
		v := desired.MinMemoryMib
		req.MinMemoryMib = &v
	}
	if desired.MaxMemoryMib != 0 && desired.MaxMemoryMib != stored.MaxMemoryMib {
		v := desired.MaxMemoryMib
		req.MaxMemoryMib = &v
	}
	if desired.MaxCpu != 0 && desired.MaxCpu != stored.MaxCpu {
		v := desired.MaxCpu
		req.MaxCpu = &v
	}
	if desired.SecureBoot != stored.SecureBoot {
		v := desired.SecureBoot
		req.SecureBoot = &v
	}
	if desired.Tpm != stored.Tpm {
		v := desired.Tpm
		req.Tpm = &v
	}
	if _, err := s.UpdateVM(ctx, req); err != nil {
		return fmt.Errorf("reconfigure with restart: %w", err)
	}
	if fields := planMetadataFields(plan); len(fields) > 0 {
		if err := s.applyLiveMetadata(ctx, name, desired, fields); err != nil {
			return fmt.Errorf("metadata after reconfigure: %w", err)
		}
	}
	return nil
}

// persistResourceSize records the plan's live-resized cpu/memory in the VM's
// stored spec.
func (s *Server) persistResourceSize(ctx context.Context, name string, desired *pb.VMSpec, plan compose.ChangePlan) error {
	applied, _, err := corrosion.MutateDesiredSpec(ctx, s.db, name, func(old string) (string, error) {
		spec := &pb.VMSpec{}
		if old != "" {
			if err := json.Unmarshal([]byte(old), spec); err != nil {
				return "", err
			}
		}
		for _, d := range plan.ResourceChanges {
			switch d.Field {
			case "cpu":
				spec.Cpu = desired.Cpu
			case "memory":
				spec.MemoryMib = desired.MemoryMib
			}
		}
		b, err := json.Marshal(spec)
		return string(b), err
	})
	if err != nil {
		return status.Errorf(codes.Internal, "record the new size of %q: %v", name, err)
	}
	if !applied {
		return status.Errorf(codes.FailedPrecondition, "cannot record the new size of %q: an operation is in progress", name)
	}
	return nil
}

func planMetadataFields(p compose.ChangePlan) []string {
	fields := make([]string, 0, len(p.MetadataChanges))
	for _, d := range p.MetadataChanges {
		fields = append(fields, d.Field)
	}
	return fields
}

func hasReason(reasons []string, prefix string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, prefix) {
			return true
		}
	}
	return false
}

// applyPlannedUpdate carries out one inline OpUpdate by its planned mechanism.
// A repair that fails is the action's failure — the VM stays as it is, never
// replaced. It returns the failed-action error.
func (s *Server) applyPlannedUpdate(ctx context.Context, action planner.VMAction, f *compose.File, gate *dependsOnGate) error {
	if action.IsContainer || action.Apply == compose.ActionRecreate {
		return s.recreateInline(ctx, action, f, gate)
	}
	if err := s.applyUpdateKeepingVM(ctx, action.VMName, action.Spec, action.Plan, action.Apply); err != nil {
		gate.markUnmet(action.VMName, err)
		return err
	}
	if action.Apply == compose.ActionRestart {
		// A restarted VM is waited on for its dependents like a new one.
		return gate.waitCreated(ctx, action)
	}
	return nil
}
