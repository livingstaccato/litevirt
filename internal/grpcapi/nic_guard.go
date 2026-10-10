package grpcapi

// NIC guards: per-NIC anti-spoofing (docs/firewall.md, "NIC guards").
//
// A NIC created or hot-attached by this build gets a guard record — "on"
// unless its request says otherwise — and the owning host's firewall renders
// it. A NIC with no record (every NIC that predates guards) is unguarded and
// keeps working exactly as before.
//
// Weakening a guard — turning it off, listing addresses beyond the ones
// litevirt assigns, or letting the guest answer DHCP or advertise itself as a
// router — lets that guest impersonate other tenants' addresses on the wire, so
// it needs cluster-root network authority, not merely authority over the VM.

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/firewall"
)

// normalizeNICGuardMode maps a request's spoof_guard to a record mode: empty
// is the default for a new NIC, which is on.
func normalizeNICGuardMode(m string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case "", corrosion.NICGuardOn:
		return corrosion.NICGuardOn, nil
	case corrosion.NICGuardOff:
		return corrosion.NICGuardOff, nil
	}
	return "", status.Errorf(codes.InvalidArgument, "spoof guard %q: want on or off", m)
}

// nicGuardExplicit reports whether a NIC request says anything about its guard.
func nicGuardExplicit(att *pb.NetworkAttachment) bool {
	return att.GetSpoofGuard() != "" || len(att.GetAllowedAddresses()) > 0 ||
		att.GetAllowDhcpServer() || att.GetAllowRouterAdvertisement()
}

// nicGuardWeakens reports whether a guard setting lets the guest do more than
// a default guard does.
func nicGuardWeakens(mode string, allowed []string, dhcp, ra bool) bool {
	return mode == corrosion.NICGuardOff || len(allowed) > 0 || dhcp || ra
}

// requireGuardAuthority is the cluster-root check every weakening needs.
func (s *Server) requireGuardAuthority(ctx context.Context, what string) error {
	if err := s.RequirePerm(ctx, "/", "network.update", "operator"); err != nil {
		return status.Errorf(codes.PermissionDenied,
			"%s weakens a NIC guard (anti-spoofing) and requires cluster-root network authority", what)
	}
	return nil
}

// admitNICGuards checks the guard settings of NICs about to be created: each
// must be well formed; an explicit one needs the record store to be writable
// (refused rather than silently dropped); and a weakening one needs
// cluster-root network authority unless carried is set — a re-create of a VM
// from the spec its original, authorized create stored.
func (s *Server) admitNICGuards(ctx context.Context, atts []*pb.NetworkAttachment, carried bool) error {
	for _, att := range atts {
		if att == nil {
			continue
		}
		mode, err := normalizeNICGuardMode(att.GetSpoofGuard())
		if err != nil {
			return err
		}
		allowed, aerr := corrosion.NormalizeNICGuardAddresses(att.GetAllowedAddresses())
		if aerr != nil {
			return status.Errorf(codes.InvalidArgument, "network %q allowed addresses: %v", att.GetName(), aerr)
		}
		if nicGuardExplicit(att) && !s.db.MayWriteClusterPolicy() {
			return status.Errorf(codes.FailedPrecondition,
				"network %q: NIC guard settings cannot be recorded until failover_scope_v1 has latched on every host; "+
					"leave them out to create the NIC (it will be unguarded until set with `lv firewall nic-guard set`)", att.GetName())
		}
		if !carried && nicGuardWeakens(mode, allowed, att.GetAllowDhcpServer(), att.GetAllowRouterAdvertisement()) {
			if err := s.requireGuardAuthority(ctx, "network "+att.GetName()); err != nil {
				return err
			}
		}
	}
	return nil
}

// newNICGuardRecord is the record a new NIC gets from its request. A static
// IPv6 address in the request is recorded as known: the NIC row carries only
// the IPv4 address.
func newNICGuardRecord(vm, mac string, att *pb.NetworkAttachment) corrosion.NICGuardRecord {
	mode, _ := normalizeNICGuardMode(att.GetSpoofGuard()) // admitted already
	rec := corrosion.NICGuardRecord{
		VMName: vm, MAC: mac, Mode: mode,
		Allowed:           att.GetAllowedAddresses(),
		AllowDHCPServer:   att.GetAllowDhcpServer(),
		AllowRouterAdvert: att.GetAllowRouterAdvertisement(),
	}
	if v6 := strings.TrimSpace(att.GetIpv6()); v6 != "" {
		if p, err := netip.ParsePrefix(v6); err == nil {
			rec.Known = []string{p.Addr().String()}
		} else if a, err := netip.ParseAddr(v6); err == nil {
			rec.Known = []string{a.String()}
		}
	}
	return rec
}

// writeNewNICGuards records the guards of NICs being created. Before
// failover_scope_v1 has latched nothing can be recorded; admitNICGuards has
// already refused an explicit setting, so these are defaults, and the NICs are
// created unguarded — what every NIC was before — with a warning.
func (s *Server) writeNewNICGuards(ctx context.Context, recs []corrosion.NICGuardRecord) error {
	if len(recs) == 0 {
		return nil
	}
	if !s.db.MayWriteClusterPolicy() {
		slog.Warn("NIC guard: creating NICs unguarded; guards cannot be recorded until failover_scope_v1 has latched",
			"vm", recs[0].VMName, "nics", len(recs))
		return nil
	}
	for _, r := range recs {
		if err := corrosion.PutNICGuard(ctx, s.db, r, callerUsername(ctx)); err != nil {
			return status.Errorf(codes.Internal, "record the guard of NIC %s: %v", r.MAC, err)
		}
	}
	return nil
}

// guardState renders a NIC's guard for an audit row.
func guardState(r *corrosion.NICGuardRecord, err error) string {
	switch {
	case err != nil:
		return corrosion.AuditUnknown(err)
	case r == nil:
		return corrosion.AuditStateUnset
	}
	return r.AuditText()
}

// SetNICGuard replaces one VM NIC's guard. It needs cluster-root network
// authority whatever it sets: the guard is what keeps the VM from
// impersonating other tenants, so its owner may not be the one to relax it.
func (s *Server) SetNICGuard(ctx context.Context, req *pb.SetNICGuardRequest) (*pb.NICGuard, error) {
	if err := s.requireGuardAuthority(ctx, "setting a NIC guard"); err != nil {
		return nil, err
	}
	if req.GetVmName() == "" || (req.GetMac() == "" && req.GetNetworkName() == "") {
		return nil, status.Error(codes.InvalidArgument, "vm_name and one of mac or network_name are required")
	}
	if req.GetMode() == "" {
		return nil, status.Error(codes.InvalidArgument, "mode is required (on or off)")
	}
	mode, err := normalizeNICGuardMode(req.GetMode())
	if err != nil {
		return nil, err
	}
	vm, err := corrosion.GetVM(ctx, s.db, req.GetVmName())
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "look up vm %q: %v", req.GetVmName(), err)
	}
	if vm == nil {
		return nil, status.Errorf(codes.NotFound, "vm %q not found", req.GetVmName())
	}
	nic, err := s.pickVMNIC(ctx, vm.Name, req.GetMac(), req.GetNetworkName())
	if err != nil {
		return nil, err
	}
	before, berr := corrosion.GetNICGuard(ctx, s.db, vm.Name, nic.MAC)
	rec := corrosion.NICGuardRecord{
		VMName: vm.Name, MAC: nic.MAC, Mode: mode,
		Allowed:           req.GetAllowedAddresses(),
		AllowDHCPServer:   req.GetAllowDhcpServer(),
		AllowRouterAdvert: req.GetAllowRouterAdvertisement(),
	}
	if berr == nil && before != nil {
		rec.Known = before.Known // a static IPv6 address recorded at create
	}
	if err := corrosion.PutNICGuard(ctx, s.db, rec, callerUsername(ctx)); err != nil {
		detail := "mac=" + nic.MAC + " " + corrosion.AuditChange(guardState(before, berr), "unchanged")
		s.audit(ctx, "nic.guard.set", vm.Name, detail, "error")
		switch {
		case errors.Is(err, corrosion.ErrClusterPolicyGateClosed):
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		default:
			return nil, status.Errorf(codes.InvalidArgument, "set NIC guard: %v", err)
		}
	}
	after, aerr := corrosion.GetNICGuard(ctx, s.db, vm.Name, nic.MAC)
	s.audit(ctx, "nic.guard.set", vm.Name,
		"mac="+nic.MAC+" "+corrosion.AuditChange(guardState(before, berr), guardState(after, aerr)), "ok")
	slog.Info("NIC guard set", "vm", vm.Name, "mac", nic.MAC, "mode", mode, "by", callerUsername(ctx))
	s.reconcileLocal(ctx)
	subnets, _ := corrosion.NetworkSubnets(ctx, s.db)
	return nicGuardToPb(vm.Name, nic, after, subnets), nil
}

// pickVMNIC resolves the NIC a request names: by MAC, or by network when the
// VM has exactly one NIC on it.
func (s *Server) pickVMNIC(ctx context.Context, vm, mac, network string) (corrosion.NICRecord, error) {
	nics, err := corrosion.MergedVMNICs(ctx, s.db, vm)
	if err != nil {
		return corrosion.NICRecord{}, status.Errorf(codes.Unavailable, "read the NICs of vm %q: %v", vm, err)
	}
	var match []corrosion.NICRecord
	for _, n := range nics {
		if (mac != "" && strings.EqualFold(n.MAC, mac)) || (mac == "" && n.NetworkName == network) {
			match = append(match, n)
		}
	}
	switch len(match) {
	case 0:
		return corrosion.NICRecord{}, status.Errorf(codes.NotFound, "vm %q has no NIC %s", vm, nicSelector(mac, network))
	case 1:
		return match[0], nil
	}
	return corrosion.NICRecord{}, status.Errorf(codes.InvalidArgument,
		"vm %q has %d NICs on network %q; name one by --mac", vm, len(match), network)
}

func nicSelector(mac, network string) string {
	if mac != "" {
		return "with MAC " + mac
	}
	return "on network " + network
}

// ListNICGuards reports the guard of every NIC of one VM, or of every VM the
// caller may read.
func (s *Server) ListNICGuards(ctx context.Context, req *pb.ListNICGuardsRequest) (*pb.ListNICGuardsResponse, error) {
	if err := s.requirePermPrecheck(ctx, "viewer"); err != nil {
		return nil, err
	}
	var vms []corrosion.VMRecord
	if req.GetVmName() != "" {
		vm, err := s.requireVMReadByName(ctx, req.GetVmName())
		if err != nil {
			return nil, err
		}
		if vm == nil {
			return nil, status.Errorf(codes.NotFound, "vm %q not found", req.GetVmName())
		}
		vms = []corrosion.VMRecord{*vm}
	} else {
		all, err := corrosion.ListVMs(ctx, s.db, "", "")
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "list VMs: %v", err)
		}
		for i := range all {
			if s.canReadVMRecord(ctx, &all[i]) {
				vms = append(vms, all[i])
			}
		}
	}
	guards, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read NIC guards: %v", err)
	}
	subnets, err := corrosion.NetworkSubnets(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read networks: %v", err)
	}
	out := &pb.ListNICGuardsResponse{}
	for _, vm := range vms {
		nics, err := corrosion.MergedVMNICs(ctx, s.db, vm.Name)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read the NICs of vm %q: %v", vm.Name, err)
		}
		sort.Slice(nics, func(i, j int) bool { return nics[i].Ordinal < nics[j].Ordinal })
		for _, n := range nics {
			var rec *corrosion.NICGuardRecord
			if r, ok := guards[corrosion.NICGuardKey(vm.Name, n.MAC)]; ok {
				rec = &r
			}
			out.Guards = append(out.Guards, nicGuardToPb(vm.Name, n, rec, subnets))
		}
	}
	return out, nil
}

// nicGuardToPb reports a NIC's guard, with the source addresses the owning
// host renders for it — the same resolution the firewall loader uses.
func nicGuardToPb(vm string, n corrosion.NICRecord, rec *corrosion.NICGuardRecord, subnets map[string]string) *pb.NICGuard {
	out := &pb.NICGuard{VmName: vm, Mac: strings.ToLower(n.MAC), NetworkName: n.NetworkName, Mode: "unset"}
	if rec == nil {
		return out
	}
	out.Mode = rec.Mode
	out.AllowedAddresses = rec.Allowed
	out.AllowDhcpServer = rec.AllowDHCPServer
	out.AllowRouterAdvertisement = rec.AllowRouterAdvert
	out.SetBy, out.UpdatedAt = rec.SetBy, rec.UpdatedAt
	if g := firewall.ResolveNICGuard(rec, n.MAC, n.IP, subnets[n.NetworkName]); g != nil {
		out.EffectiveIpv4, out.Ipv4Unrestricted = g.V4, g.V4 == nil
		out.EffectiveIpv6, out.Ipv6Unrestricted = g.V6, g.V6 == nil
	}
	return out
}
