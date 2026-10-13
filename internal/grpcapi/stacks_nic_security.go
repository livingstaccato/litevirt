package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/compose/planner"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// loadNICSecurityPlanState adds to a plan's cluster state what a compose
// plan needs to compare and restore NIC security for the caller: the stack's
// live NIC security, and the gate (nicSecurityGate).
func (s *Server) loadNICSecurityPlanState(ctx context.Context, state *planner.ClusterState, stack string, allowWeaken bool) error {
	if err := planner.LoadStackNICSecurity(ctx, s.db, state, stack); err != nil {
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	state.NICSecurityGate = s.nicSecurityGate(ctx, allowWeaken)
	return nil
}

// nicSecurityGate is what the caller's deploy may restore of a NIC's security
// (compose.ApplyNICSecurityGate), decided when the plan is made so that a
// restore the deploy cannot make is reported in the plan rather than failing
// the deploy: the release gate guard records need, and the authority
// BindSecurityGroups and a weakening SetNICGuard check.
func (s *Server) nicSecurityGate(ctx context.Context, allowWeaken bool) compose.NICSecurityGate {
	g := compose.NICSecurityGate{AllowWeaken: allowWeaken}
	if !s.firewallReleaseActive() || !s.db.MayWriteClusterPolicy() {
		g.GuardsUnwritable = "a guard record cannot be written until the cluster upgrade finishes " +
			"(nic_guards needs release_2026_11_v1; lv cluster upgrade-status)"
	}
	g.CheckBind = func(vm string) error {
		if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
			return fmt.Errorf("rebinding needs network.update on vm %q: %v", vm, status.Convert(err).Message())
		}
		rec, err := corrosion.GetVM(ctx, s.db, vm)
		if err != nil {
			return fmt.Errorf("look up vm %q: %v", vm, err)
		}
		path := ""
		if rec != nil {
			path = vmRBACPath(rec)
		}
		if err := s.requirePermResolved(ctx, rec != nil, path, vmRBACPathFor("", vm),
			"network.update", "operator", "vm "+strconv.Quote(vm)); err != nil {
			return fmt.Errorf("rebinding needs network.update on vm %q, which the caller lacks", vm)
		}
		return nil
	}
	g.CheckWeakenGuard = func(network string) error {
		if err := s.requireGuardAuthority(ctx, network, "restoring the declared NIC guard"); err != nil {
			return fmt.Errorf("%s", status.Convert(err).Message())
		}
		return nil
	}
	return g
}

// nicSecurityField splits a plan's per-NIC security field ("nic_sg_0",
// "nic_guard_1") into its kind prefix and NIC position.
func nicSecurityField(f string) (prefix string, i int, ok bool) {
	for _, p := range []string{compose.NICSecurityGroupsFieldPrefix, compose.NICGuardFieldPrefix} {
		if rest, found := strings.CutPrefix(f, p); found {
			n, err := strconv.Atoi(rest)
			return p, n, err == nil && n >= 0
		}
	}
	return "", 0, false
}

// nicSecurityWrite is one restore applyDesiredNICSecurity makes.
type nicSecurityWrite struct {
	prefix string
	nic    *compose.LiveNIC
	want   *pb.NetworkAttachment
}

// applyDesiredNICSecurity puts the security-group binding and guard a compose
// file declares back on the NICs the plan names. The plan has already
// withheld what the deploy may not do (compose.ApplyNICSecurityGate); this
// re-checks against the rows as they are now, and checks every field before
// it writes any, so a refusal leaves nothing half-restored.
//
// A binding is written through BindSecurityGroups, with the deploying
// caller's authority. A guard that loosens what a default guard allows goes
// through SetNICGuard's authority check; one that does not needs none, as at
// create (putNICGuard). Both are audited like their CLI forms. The stored
// spec is not rewritten: nothing enforces from it.
//
// The plan's position i is the stored spec's NIC i, matched to its live NIC
// the way the plan matched it (compose.MatchLiveNIC).
func (s *Server) applyDesiredNICSecurity(ctx context.Context, name string, desired *pb.VMSpec, fields []string) error {
	vm, err := corrosion.GetVM(ctx, s.db, name)
	if err != nil {
		return status.Errorf(codes.Unavailable, "look up vm %q: %v", name, err)
	}
	if vm == nil {
		return status.Errorf(codes.NotFound, "VM %q not found", name)
	}
	stored := &pb.VMSpec{}
	if vm.Spec != "" {
		if err := json.Unmarshal([]byte(vm.Spec), stored); err != nil {
			return status.Errorf(codes.Internal, "parse stored spec for %q: %v", name, err)
		}
	}
	live, err := corrosion.LiveNICSecurity(ctx, s.db, name, stored.GetUuid())
	if err != nil {
		return status.Errorf(codes.Unavailable, "read the NICs of vm %q: %v", name, err)
	}
	var writes []nicSecurityWrite
	bound := map[string]bool{}
	for _, f := range fields {
		prefix, i, ok := nicSecurityField(f)
		if !ok {
			continue
		}
		n := compose.MatchLiveNIC(stored.Network, i, live)
		if n == nil || i >= len(desired.Network) || desired.Network[i] == nil {
			return status.Errorf(codes.FailedPrecondition,
				"vm %q has no NIC at position %d to apply the file's security groups or guard to", name, i)
		}
		if prefix == compose.NICSecurityGroupsFieldPrefix {
			if bound[n.Network] {
				continue
			}
			bound[n.Network] = true
			if why := compose.SharedNetworkConflict(i, desired, stored, live); why != "" {
				return status.Errorf(codes.FailedPrecondition, "vm %q: nic %d (%s) security groups not restored: %s", name, i, n.Network, why)
			}
		}
		writes = append(writes, nicSecurityWrite{prefix: prefix, nic: n, want: desired.Network[i]})
	}
	for _, w := range writes {
		switch w.prefix {
		case compose.NICSecurityGroupsFieldPrefix:
			if _, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
				VmName: name, NetworkName: w.nic.Network, SecurityGroups: w.want.GetSecurityGroups(),
			}); err != nil {
				return err
			}
		case compose.NICGuardFieldPrefix:
			mode := w.want.GetSpoofGuard()
			if mode == "" {
				mode = corrosion.NICGuardOn // a declared guard is on unless the file says off
			}
			mode, err := normalizeNICGuardMode(mode)
			if err != nil {
				return err
			}
			req := &pb.SetNICGuardRequest{
				VmName: name, Mac: w.nic.MAC, Mode: mode,
				AllowedAddresses:         w.want.GetAllowedAddresses(),
				AllowDhcpServer:          w.want.GetAllowDhcpServer(),
				AllowRouterAdvertisement: w.want.GetAllowRouterAdvertisement(),
				AllowVlanTags:            w.want.GetAllowVlanTags(),
			}
			if nicGuardWeakens(mode, req.AllowedAddresses, req.AllowDhcpServer, req.AllowRouterAdvertisement, req.AllowVlanTags) {
				_, err = s.SetNICGuard(ctx, req)
			} else {
				var tgt guardTarget
				if tgt, err = s.pickVMTarget(ctx, name, w.nic.MAC, ""); err == nil {
					_, err = s.putNICGuard(ctx, tgt, mode, req)
				}
			}
			if err != nil {
				return err
			}
		}
	}
	return nil
}
