package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// A stack deployed before undeclared NIC networks resolved to the cluster
// network (compose.File.ResolveNetworkName) has NICs recorded on
// "<stack>_<name>": a name with no network record, which CreateVM turned into
// a flat bridge of that name with no gateway and no DHCP. Re-applying the same
// file asks for "<name>". This file moves such a NIC in place — same device,
// same MAC, disks untouched — instead of letting the deploy recreate the VM,
// which every update path does by deleting it and its disks.
//
// The move has two halves. The deploy node checks the move is the legacy case
// and records it in the VM's desired spec. The VM's own host then does the
// host work (provision the cluster network, re-plug the NIC, rewrite the NIC
// rows): at once when the deploy ran there, otherwise on its next network
// reconcile pass.

// errNICRetargetRefused is a move that is not the legacy flat-bridge case. It
// is refused, never turned into a recreate.
var errNICRetargetRefused = errors.New("NIC network change refused")

// checkNICRetarget verifies a classified retarget is the legacy case: the old
// name has no network record (so the NIC sits on a record-less flat bridge)
// and the new name is a real cluster network.
func (s *Server) checkNICRetarget(ctx context.Context, vmName string, rt compose.NICRetarget) error {
	oldDef, err := lookupNetworkDef(ctx, s.db, rt.From)
	if err != nil {
		return err
	}
	if oldDef != nil {
		return fmt.Errorf("%w: vm %q nic %d would move from network %q to %q, and %q is a real network, not "+
			"the record-less flat bridge left by a stack deployed before undeclared NIC networks resolved to "+
			"the cluster network. That is a network change, and a deploy does not recreate a VM (and its "+
			"disks) for it. Declare %q under networks: again to keep the NIC where it is, or move it with "+
			"`lv detach-nic` and `lv attach-nic`",
			errNICRetargetRefused, vmName, rt.Ordinal, rt.From, rt.To, rt.From, rt.To)
	}
	newDef, err := lookupNetworkDef(ctx, s.db, rt.To)
	if err != nil {
		return err
	}
	if newDef == nil {
		return fmt.Errorf("%w: vm %q nic %d: network %q does not exist", errNICRetargetRefused, vmName, rt.Ordinal, rt.To)
	}
	return nil
}

// applyNICRetargets handles every planned update whose plan moves NICs off a
// legacy stack-scoped flat bridge, BEFORE the executors run: they apply any
// update by recreating the VM. A move that succeeds is taken out of the plan,
// and an update left with nothing else to do becomes a no-change. A move that
// is refused fails that VM's action and the VM is not touched at all.
func (s *Server) applyNICRetargets(ctx context.Context, resolved *planner.ResolvedPlan,
	stream grpc.ServerStreamingServer[pb.DeployProgress], failures *deployFailures) error {
	for i := range resolved.VMs {
		a := &resolved.VMs[i]
		if a.Kind != planner.OpUpdate || a.IsContainer || len(a.Plan.NICRetargets) == 0 {
			continue
		}
		detail, err := s.retargetVMNICs(ctx, a.VMName, a.Plan.NICRetargets)
		if err != nil {
			slog.Warn("deploy: NIC move refused", "vm", a.VMName, "error", err)
			a.Kind = planner.OpNoChange // never fall through to a recreate
			if sendErr := failures.fail(a.VMName, err); sendErr != nil {
				return sendErr
			}
			continue
		}
		a.Plan.NICRetargets = nil
		if a.Plan.Max() == compose.ActionNoChange {
			a.Kind = planner.OpNoChange
		}
		if err := stream.Send(&pb.DeployProgress{Phase: "done", VmName: a.VMName, Detail: detail, ProgressPct: 100}); err != nil {
			return err
		}
	}
	return nil
}

// retargetVMNICs checks every move, records them in the VM's desired spec, and
// does the host half at once when the VM lives here.
func (s *Server) retargetVMNICs(ctx context.Context, vmName string, rts []compose.NICRetarget) (string, error) {
	for _, rt := range rts {
		if err := s.checkNICRetarget(ctx, vmName, rt); err != nil {
			return "", err
		}
	}
	applied, _, err := corrosion.MutateDesiredSpec(ctx, s.db, vmName, func(old string) (string, error) {
		spec := &pb.VMSpec{}
		if old != "" {
			if err := json.Unmarshal([]byte(old), spec); err != nil {
				return "", err
			}
		}
		for _, rt := range rts {
			if rt.Ordinal < len(spec.Network) && spec.Network[rt.Ordinal].GetName() == rt.From {
				spec.Network[rt.Ordinal].Name = rt.To
			}
		}
		b, err := json.Marshal(spec)
		return string(b), err
	})
	if err != nil {
		return "", fmt.Errorf("record NIC move for %q: %w", vmName, err)
	}
	if !applied {
		return "", fmt.Errorf("cannot move %q's NICs: an operation is in progress", vmName)
	}

	var moves []string
	for _, rt := range rts {
		moves = append(moves, fmt.Sprintf("nic %d %s→%s", rt.Ordinal, rt.From, rt.To))
	}
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil || vm == nil {
		return "", fmt.Errorf("read %q after recording its NIC move: %v", vmName, err)
	}
	if vm.HostName != s.hostName {
		return fmt.Sprintf("%s: recorded; %s re-plugs it in place (same MAC, disks kept) on its next network pass",
			strings.Join(moves, ", "), vm.HostName), nil
	}
	if err := s.retargetLocalVMNICs(ctx, *vm); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s: re-plugged in place (same MAC, disks kept)", strings.Join(moves, ", ")), nil
}

// pendingNICRetargets derives, from a VM's desired spec and its NIC rows, the
// NICs still on a legacy "<stack>_<name>" network whose spec now names
// "<name>".
func pendingNICRetargets(spec *pb.VMSpec, nics []corrosion.NICRecord) []compose.NICRetarget {
	if spec.GetStackName() == "" {
		return nil
	}
	var out []compose.NICRetarget
	for _, n := range nics {
		if n.Ordinal < 0 || n.Ordinal >= len(spec.Network) {
			continue
		}
		want := spec.Network[n.Ordinal].GetName()
		if n.NetworkName != want && n.NetworkName == compose.ScopedNetworkName(spec.StackName, want) {
			out = append(out, compose.NICRetarget{Ordinal: n.Ordinal, From: n.NetworkName, To: want})
		}
	}
	return out
}

// retargetLocalVMNICs does the host half for a VM that lives on this host:
// for each NIC the spec has moved, provision the cluster network here,
// re-plug the NIC onto its bridge, and rewrite the NIC rows. The rows change
// last, so a failed re-plug leaves the move pending for the next pass.
func (s *Server) retargetLocalVMNICs(ctx context.Context, vm corrosion.VMRecord) error {
	if vm.HostName != s.hostName {
		return nil
	}
	fresh, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil || fresh == nil {
		return err
	}
	if fresh.ActiveOperationID != "" {
		return fmt.Errorf("cannot move %q's NICs: an operation is in progress", vm.Name)
	}
	spec := &pb.VMSpec{}
	if fresh.Spec != "" {
		if err := json.Unmarshal([]byte(fresh.Spec), spec); err != nil {
			return fmt.Errorf("parse spec for %q: %w", vm.Name, err)
		}
	}
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
	if err != nil {
		return fmt.Errorf("read NICs for %q: %w", vm.Name, err)
	}
	legacy, err := corrosion.GetVMInterfaces(ctx, s.db, vm.Name)
	if err != nil {
		return fmt.Errorf("read interfaces for %q: %w", vm.Name, err)
	}
	for _, rt := range pendingNICRetargets(spec, nics) {
		if err := s.checkNICRetarget(ctx, vm.Name, rt); err != nil {
			return err
		}
		var nic corrosion.NICRecord
		for _, n := range nics {
			if n.Ordinal == rt.Ordinal {
				nic = n
			}
		}
		bridge, err := s.provisionForVM(ctx, rt.To)
		if err != nil {
			return fmt.Errorf("provision network %q for %q: %w", rt.To, vm.Name, err)
		}
		if bridge == "" || strings.HasPrefix(bridge, "direct:") {
			return fmt.Errorf("%w: network %q is not a bridge network", errNICRetargetRefused, rt.To)
		}
		if err := s.reconcileFirewallRequired(ctx); err != nil {
			return fmt.Errorf("apply firewall for network %q: %w", rt.To, err)
		}
		if s.virt != nil && s.virt.DomainExists(vm.Name) {
			if err := s.virt.SetNICBridge(vm.Name, nic.MAC, bridge); err != nil {
				return fmt.Errorf("re-plug %q nic %d onto %s: %w", vm.Name, rt.Ordinal, bridge, err)
			}
		}
		if err := s.rewriteNICNetwork(ctx, nic, legacy, rt); err != nil {
			return err
		}
		s.removeStackBridgeIfUnused(ctx, rt.From)
		slog.Info("moved a legacy stack NIC onto its cluster network in place",
			"vm", vm.Name, "nic", rt.Ordinal, "from", rt.From, "to", rt.To, "bridge", bridge, "mac", nic.MAC)
		s.recordVMEvent(ctx, vm.Name, "vm.nic_moved", "ok",
			fmt.Sprintf("nic %d %s→%s (bridge %s, mac %s)", rt.Ordinal, rt.From, rt.To, bridge, nic.MAC))
	}
	return nil
}

// rewriteNICNetwork moves a NIC's rows from rt.From to rt.To. vm_interfaces is
// keyed by (vm, network), so its row is tombstoned and re-inserted, and only
// when the VM has one; vm_nics keeps its id and is written last so it wins
// the overlay.
func (s *Server) rewriteNICNetwork(ctx context.Context, nic corrosion.NICRecord, legacy []corrosion.InterfaceRecord, rt compose.NICRetarget) error {
	for _, li := range legacy {
		if li.NetworkName != rt.From || !strings.EqualFold(li.MAC, nic.MAC) {
			continue
		}
		if err := corrosion.SoftDeleteInterfaceByMAC(ctx, s.db, nic.VMName, nic.MAC); err != nil {
			return fmt.Errorf("retire %q's interface row on %q: %w", nic.VMName, rt.From, err)
		}
		li.NetworkName = rt.To
		if err := corrosion.InsertInterface(ctx, s.db, li); err != nil {
			return fmt.Errorf("write %q's interface row on %q: %w", nic.VMName, rt.To, err)
		}
		if len(li.SecurityGroups) > 0 {
			if err := corrosion.SetInterfaceSecurityGroups(ctx, s.db, nic.VMName, rt.To, li.SecurityGroups); err != nil {
				return fmt.Errorf("carry %q's security groups to %q: %w", nic.VMName, rt.To, err)
			}
		}
	}
	nic.NetworkName = rt.To
	if err := corrosion.UpsertNIC(ctx, s.db, nic); err != nil {
		return fmt.Errorf("write %q's NIC row on %q: %w", nic.VMName, rt.To, err)
	}
	return nil
}

// reconcileLegacyNICs is the network reconcile pass's half of a NIC move: any
// VM on this host whose spec has moved a NIC the rows do not yet show.
func (s *Server) reconcileLegacyNICs(ctx context.Context) {
	vms, err := corrosion.ListVMs(ctx, s.db, "", s.hostName)
	if err != nil {
		slog.Warn("network reconcile: list local VMs for NIC moves", "error", err)
		return
	}
	for _, vm := range vms {
		if vm.StackName == "" || vm.Spec == "" {
			continue
		}
		// Cheap filter first: most VMs have nothing pending.
		spec := &pb.VMSpec{}
		if json.Unmarshal([]byte(vm.Spec), spec) != nil {
			continue
		}
		nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
		if err != nil || len(pendingNICRetargets(spec, nics)) == 0 {
			continue
		}
		if err := s.retargetLocalVMNICs(ctx, vm); err != nil {
			slog.Warn("network reconcile: NIC move not done (will retry)", "vm", vm.Name, "error", err)
		}
	}
}
