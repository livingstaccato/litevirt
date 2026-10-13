package grpcapi

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
)

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

// applyDesiredNICSecurity puts the security-group binding and guard a compose
// file declares back on the NICs the plan names (compose.classifyNICSecurity).
// They are written exactly as `lv sg bind` and `lv firewall nic-guard set`
// write them — through those RPCs, with the deploying caller's authority
// (network.update; a guard needs it over the NIC's network) and their audit
// rows — onto the rows the firewall enforces from. The stored spec is not
// rewritten: it records what the NIC was created with, and nothing enforces
// from it.
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
	// positionOf is the stored-spec position of a live NIC, or -1 for one the
	// spec does not describe (hot-attached).
	positionOf := func(mac string) int {
		for j := range stored.Network {
			if n := compose.MatchLiveNIC(stored.Network, j, live); n != nil && strings.EqualFold(n.MAC, mac) {
				return j
			}
		}
		return -1
	}
	nicAt := func(i int) (*compose.LiveNIC, *pb.NetworkAttachment, error) {
		n := compose.MatchLiveNIC(stored.Network, i, live)
		if n == nil || i >= len(desired.Network) || desired.Network[i] == nil {
			return nil, nil, status.Errorf(codes.FailedPrecondition,
				"vm %q has no NIC at position %d to apply the file's security groups or guard to", name, i)
		}
		return n, desired.Network[i], nil
	}
	bound := map[string]bool{}
	for _, f := range fields {
		prefix, i, ok := nicSecurityField(f)
		if !ok {
			continue
		}
		n, want, err := nicAt(i)
		if err != nil {
			return err
		}
		switch prefix {
		case compose.NICSecurityGroupsFieldPrefix:
			if bound[n.Network] {
				continue
			}
			// A binding is written for every NIC of the VM on the network
			// (BindSecurityGroups). Each other NIC there must be one the file
			// declares the same groups for, or the rebind would change a
			// binding the file does not own.
			for _, o := range live {
				if o.Network != n.Network || strings.EqualFold(o.MAC, n.MAC) {
					continue
				}
				j := positionOf(o.MAC)
				if j < 0 || j >= len(desired.Network) || !slices.Equal(desired.Network[j].GetSecurityGroups(), want.GetSecurityGroups()) {
					return status.Errorf(codes.FailedPrecondition,
						"vm %q: NIC %s and NIC %s are on the same network %q, and a security-group binding is written per network; "+
							"the file declares %v for one and not the same for the other, so it is not applied "+
							"(declare the same groups for both, or bind them with lv sg bind)",
						name, n.MAC, o.MAC, n.Network, want.GetSecurityGroups())
				}
			}
			if _, err := s.BindSecurityGroups(ctx, &pb.BindSecurityGroupsRequest{
				VmName: name, NetworkName: n.Network, SecurityGroups: want.GetSecurityGroups(),
			}); err != nil {
				return err
			}
			bound[n.Network] = true
		case compose.NICGuardFieldPrefix:
			mode := want.GetSpoofGuard()
			if mode == "" {
				mode = corrosion.NICGuardOn // a declared guard is on unless the file says off
			}
			if _, err := s.SetNICGuard(ctx, &pb.SetNICGuardRequest{
				VmName: name, Mac: n.MAC, Mode: mode,
				AllowedAddresses:         want.GetAllowedAddresses(),
				AllowDhcpServer:          want.GetAllowDhcpServer(),
				AllowRouterAdvertisement: want.GetAllowRouterAdvertisement(),
				AllowVlanTags:            want.GetAllowVlanTags(),
			}); err != nil {
				return err
			}
		}
	}
	return nil
}
