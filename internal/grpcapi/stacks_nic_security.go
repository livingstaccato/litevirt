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
	g.GuardUnenforced = func(network string) string { return guardUnenforcedOnNetwork(ctx, s.db, network) }
	g.CheckGuardAuthority = func(network string) error {
		if err := s.requireGuardAuthority(ctx, network, "restoring a declared NIC guard that is off or has allowances"); err != nil {
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

// allowWeakenKey carries a deploy's --allow-weaken to its executor.
type allowWeakenKey struct{}

// withAllowWeaken marks ctx with the deploy's opt-in to weakening restores.
func withAllowWeaken(ctx context.Context, allow bool) context.Context {
	return context.WithValue(ctx, allowWeakenKey{}, allow)
}

// allowWeakenFrom is the deploy's opt-in, false when ctx carries none.
func allowWeakenFrom(ctx context.Context) bool {
	v, _ := ctx.Value(allowWeakenKey{}).(bool)
	return v
}

// nicSecurityWrite is one restore applyDesiredNICSecurity makes.
type nicSecurityWrite struct {
	prefix string
	nic    *compose.LiveNIC
	want   *pb.NetworkAttachment
	mode   string
}

// applyDesiredNICSecurity puts the security-group binding and guard a compose
// file declares back on the NICs the plan names. The plan has already
// withheld what the deploy may not do (compose.ApplyNICSecurityGate). This
// checks every write again, against the rows as they are now and with the
// same gate (nicSecurityGate) and the same authority rule
// (compose.DeclaredGuardNeedsAuthority), and refuses the whole set before the
// first write if any is refused: nothing is left half-restored. A write that
// has become a weakening since the plan (the rows changed in between) is
// refused unless the deploy opted in (allowWeakenFrom).
//
// Bindings are written through BindSecurityGroups, guards through putNICGuard
// (the direct/SR-IOV refusal, the release gate, the audit row), each once the
// authority above is settled. The stored spec is not rewritten: nothing
// enforces from it.
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
	allow := allowWeakenFrom(ctx)
	gate := s.nicSecurityGate(ctx, allow)
	refuse := func(i int, network, what, why string) error {
		return status.Errorf(codes.FailedPrecondition, "vm %q: nic %d (%s) %s not restored, and nothing else of its NIC security was: %s",
			name, i, network, what, why)
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
		want := desired.Network[i]
		w := nicSecurityWrite{prefix: prefix, nic: n, want: want}
		switch prefix {
		case compose.NICSecurityGroupsFieldPrefix:
			if bound[n.Network] {
				continue
			}
			bound[n.Network] = true
			if why := compose.SharedNetworkConflict(i, desired, stored, live); why != "" {
				return refuse(i, n.Network, "security groups", why)
			}
			if !allow {
				return refuse(i, n.Network, "security groups", "a rebind may remove protection set outside the file, and the deploy was not run with --allow-weaken")
			}
			if err := gate.CheckBind(name); err != nil {
				return refuse(i, n.Network, "security groups", err.Error())
			}
		case compose.NICGuardFieldPrefix:
			if why := compose.InvalidDeclaredGuard(want); why != "" {
				return refuse(i, n.Network, "guard", "the file's guard is invalid: "+why)
			}
			if gate.GuardsUnwritable != "" {
				return refuse(i, n.Network, "guard", gate.GuardsUnwritable)
			}
			if r := compose.GuardRestoreWeakens(n, want); len(r) > 0 && !allow {
				return refuse(i, n.Network, "guard", "it now relaxes the guard enforced ("+strings.Join(r, ", ")+
					"), and the deploy was not run with --allow-weaken")
			}
			if compose.DeclaredGuardNeedsAuthority(want) {
				if err := gate.CheckGuardAuthority(n.Network); err != nil {
					return refuse(i, n.Network, "guard", err.Error())
				}
			}
			mode := want.GetSpoofGuard()
			if mode == "" {
				mode = corrosion.NICGuardOn // a declared guard is on unless the file says off
			}
			if w.mode, err = normalizeNICGuardMode(mode); err != nil {
				return refuse(i, n.Network, "guard", status.Convert(err).Message())
			}
			if _, err := corrosion.NormalizeNICGuardAddresses(want.GetAllowedAddresses()); err != nil {
				return refuse(i, n.Network, "guard", "allowed addresses: "+err.Error())
			}
			if why := gate.GuardUnenforced(n.Network); why != "" {
				// The plan reports such a guard as not enforced and plans
				// nothing for it; this is the backstop.
				return refuse(i, n.Network, "guard", why)
			}
		}
		writes = append(writes, w)
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
			tgt, err := s.pickVMTarget(ctx, name, w.nic.MAC, "")
			if err != nil {
				return err
			}
			if _, err := s.putNICGuard(ctx, tgt, w.mode, &pb.SetNICGuardRequest{
				VmName: name, Mac: w.nic.MAC, Mode: w.mode,
				AllowedAddresses:         w.want.GetAllowedAddresses(),
				AllowDhcpServer:          w.want.GetAllowDhcpServer(),
				AllowRouterAdvertisement: w.want.GetAllowRouterAdvertisement(),
				AllowVlanTags:            w.want.GetAllowVlanTags(),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
