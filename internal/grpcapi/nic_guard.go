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
	"github.com/litevirt/litevirt/internal/capabilities"
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
		att.GetAllowDhcpServer() || att.GetAllowRouterAdvertisement() || att.GetAllowVlanTags()
}

// nicGuardWeakens reports whether a guard setting lets the guest do more than
// a default guard does.
func nicGuardWeakens(mode string, allowed []string, dhcp, ra, vlan bool) bool {
	return mode == corrosion.NICGuardOff || len(allowed) > 0 || dhcp || ra || vlan
}

// requireGuardAuthority is the check every weakening needs: authority over
// the L2 segment the NIC sits on, whose other occupants the guard protects.
// For a network a project owns, network.update on that network; for a shared
// (global) network or a raw bridge, cluster-root network.update. With no RBAC
// bindings at all, the legacy role fallback applies, as for every check: any
// operator passes.
func (s *Server) requireGuardAuthority(ctx context.Context, networkName, what string) error {
	path := "/"
	if networkName != "" {
		if nr, err := corrosion.GetNetwork(ctx, s.db, networkName); err != nil {
			return status.Errorf(codes.Unavailable, "look up network %q: %v", networkName, err)
		} else if nr != nil && nr.Project != "" {
			path = networkRBACPathFor(nr.Project, nr.Name)
		}
	}
	if err := s.RequirePerm(ctx, path, "network.update", "operator"); err != nil {
		return status.Errorf(codes.PermissionDenied,
			"%s weakens a NIC guard (anti-spoofing) and requires network.update on %s", what, path)
	}
	return nil
}

// firewallReleaseActive reports whether every host runs a build that knows
// NIC guards and IPv6 rules — whose entry nodes check guard authority and
// whose renderers render IPv6 rules. One small function so the integration
// can swap it for the shared release token (feat/release-token); until then it
// reads firewall_ipv6_v1.
func (s *Server) firewallReleaseActive() bool {
	return s.gate != nil && s.gate.DurablyLatched(capabilities.FirewallIPv6V1)
}

// admitMode is how a create path came by the guard settings it carries.
type admitMode int

const (
	// admitNew: a caller asked for them; a weakening needs authority.
	admitNew admitMode = iota
	// admitRecreate: a re-create of a VM under the same name (rebuild, a
	// stack's rolling update). Settings that match a guard the VM already
	// had pass; anything else is a new request and needs authority.
	admitRecreate
	// admitPeerOwner: the owner leg of a request a peer forwarded. The entry
	// node checked authority — if it is a build that knows guards, which is
	// what firewallReleaseActive proves; before that, explicit settings are
	// refused rather than trusted.
	admitPeerOwner
)

// admitNICGuards checks the guard settings of NICs about to be created by
// vmName: each must be well formed; an explicit one needs the record store to
// be writable (refused rather than silently dropped); and a weakening one
// needs authority over its network (see admitMode).
func (s *Server) admitNICGuards(ctx context.Context, vmName string, atts []*pb.NetworkAttachment, how admitMode) error {
	var prior map[string]corrosion.NICGuardRecord
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
		if !nicGuardExplicit(att) {
			continue
		}
		if !s.db.MayWriteClusterPolicy() {
			return status.Errorf(codes.FailedPrecondition,
				"network %q: NIC guard settings cannot be recorded until failover_scope_v1 has latched on every host; "+
					"leave them out to create the NIC (it will be unguarded until set with `lv firewall nic-guard set`)", att.GetName())
		}
		if !nicGuardWeakens(mode, allowed, att.GetAllowDhcpServer(), att.GetAllowRouterAdvertisement(), att.GetAllowVlanTags()) {
			continue
		}
		switch how {
		case admitPeerOwner:
			if !s.firewallReleaseActive() {
				return status.Errorf(codes.FailedPrecondition,
					"network %q: NIC guard settings forwarded by a peer are refused until every host runs a build that checks them", att.GetName())
			}
			continue
		case admitRecreate:
			if prior == nil {
				if prior, err = s.guardsOf(ctx, vmName); err != nil {
					return err
				}
			}
			if guardMatchesAny(prior, mode, allowed, att) {
				continue
			}
		}
		if err := s.requireGuardAuthority(ctx, att.GetName(), "network "+att.GetName()); err != nil {
			return err
		}
	}
	return nil
}

// guardsOf returns every guard record of vmName, including those of an
// incarnation already deleted (records outlive their VM).
func (s *Server) guardsOf(ctx context.Context, vmName string) (map[string]corrosion.NICGuardRecord, error) {
	all, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "read NIC guards: %v", err)
	}
	out := map[string]corrosion.NICGuardRecord{}
	for k, r := range all {
		if r.VMName == vmName {
			out[k] = r
		}
	}
	return out, nil
}

// guardMatchesAny reports whether a requested guard equals one the VM already
// had.
func guardMatchesAny(prior map[string]corrosion.NICGuardRecord, mode string, allowed []string, att *pb.NetworkAttachment) bool {
	for _, r := range prior {
		if r.Mode == mode && strings.Join(r.Allowed, ",") == strings.Join(allowed, ",") &&
			r.AllowDHCPServer == att.GetAllowDhcpServer() && r.AllowRouterAdvert == att.GetAllowRouterAdvertisement() &&
			r.AllowVLANTags == att.GetAllowVlanTags() {
			return true
		}
	}
	return false
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
		AllowVLANTags:     att.GetAllowVlanTags(),
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

// guardTarget is the NIC a SetNICGuard names: a VM's or a container's.
type guardTarget struct {
	owner   string // the record's owner: the VM name, or ContainerGuardOwner
	display string // for audit and logs
	nic     corrosion.NICRecord
}

// SetNICGuard replaces one NIC's guard. It needs network.update over the
// NIC's network whatever it sets (requireGuardAuthority): the guard is what
// keeps the guest from impersonating the other tenants on that segment, so
// the guest's owner may not be the one to relax it.
func (s *Server) SetNICGuard(ctx context.Context, req *pb.SetNICGuardRequest) (*pb.NICGuard, error) {
	if err := s.requirePermPrecheck(ctx, "operator"); err != nil {
		return nil, err
	}
	ct := req.GetContainerName() != ""
	if (req.GetVmName() == "") == !ct || (req.GetMac() == "" && req.GetNetworkName() == "") {
		return nil, status.Error(codes.InvalidArgument,
			"one of vm_name or container_name (with container_host), and one of mac or network_name, are required")
	}
	if req.GetMode() == "" {
		return nil, status.Error(codes.InvalidArgument, "mode is required (on or off)")
	}
	mode, err := normalizeNICGuardMode(req.GetMode())
	if err != nil {
		return nil, err
	}
	var tgt guardTarget
	if ct {
		tgt, err = s.pickContainerNIC(ctx, req.GetContainerHost(), req.GetContainerName(), req.GetMac(), req.GetNetworkName())
	} else {
		tgt, err = s.pickVMTarget(ctx, req.GetVmName(), req.GetMac(), req.GetNetworkName())
	}
	if err != nil {
		return nil, err
	}
	if err := s.requireGuardAuthority(ctx, tgt.nic.NetworkName, "setting a NIC guard"); err != nil {
		return nil, err
	}
	if def, _ := lookupNetworkDef(ctx, s.db, tgt.nic.NetworkName); def != nil && (def.Type == "direct" || def.Type == "sriov") {
		return nil, status.Errorf(codes.FailedPrecondition,
			"NIC %s is on %s network %q, which bypasses the bridge where guards are enforced; a guard there would protect nothing",
			tgt.nic.MAC, def.Type, tgt.nic.NetworkName)
	}
	before, berr := corrosion.GetNICGuard(ctx, s.db, tgt.owner, tgt.nic.MAC)
	rec := corrosion.NICGuardRecord{
		VMName: tgt.owner, MAC: tgt.nic.MAC, Mode: mode,
		Allowed:           req.GetAllowedAddresses(),
		AllowDHCPServer:   req.GetAllowDhcpServer(),
		AllowRouterAdvert: req.GetAllowRouterAdvertisement(),
		AllowVLANTags:     req.GetAllowVlanTags(),
	}
	if berr == nil && before != nil {
		rec.Known = before.Known // a static IPv6 address recorded at create
	}
	if err := corrosion.PutNICGuard(ctx, s.db, rec, callerUsername(ctx)); err != nil {
		detail := "mac=" + tgt.nic.MAC + " " + corrosion.AuditChange(guardState(before, berr), "unchanged")
		s.audit(ctx, "nic.guard.set", tgt.display, detail, "error")
		switch {
		case errors.Is(err, corrosion.ErrClusterPolicyGateClosed):
			return nil, status.Errorf(codes.FailedPrecondition, "%v", err)
		default:
			return nil, status.Errorf(codes.InvalidArgument, "set NIC guard: %v", err)
		}
	}
	after, aerr := corrosion.GetNICGuard(ctx, s.db, tgt.owner, tgt.nic.MAC)
	s.audit(ctx, "nic.guard.set", tgt.display,
		"mac="+tgt.nic.MAC+" "+corrosion.AuditChange(guardState(before, berr), guardState(after, aerr)), "ok")
	slog.Info("NIC guard set", "nic", tgt.display, "mac", tgt.nic.MAC, "mode", mode, "by", callerUsername(ctx))
	s.reconcileLocal(ctx)
	subnets, _ := corrosion.NetworkSubnets(ctx, s.db)
	out := nicGuardToPb(tgt.owner, tgt.nic, after, subnets)
	if ct {
		out.VmName, out.ContainerHost, out.ContainerName = "", req.GetContainerHost(), req.GetContainerName()
	}
	return out, nil
}

func (s *Server) pickVMTarget(ctx context.Context, vmName, mac, network string) (guardTarget, error) {
	vm, err := corrosion.GetVM(ctx, s.db, vmName)
	if err != nil {
		return guardTarget{}, status.Errorf(codes.Unavailable, "look up vm %q: %v", vmName, err)
	}
	if vm == nil {
		return guardTarget{}, status.Errorf(codes.NotFound, "vm %q not found", vmName)
	}
	nic, err := s.pickVMNIC(ctx, vm.Name, mac, network)
	if err != nil {
		return guardTarget{}, err
	}
	return guardTarget{owner: vm.Name, display: vm.Name, nic: nic}, nil
}

// pickContainerNIC resolves a container's managed NIC.
func (s *Server) pickContainerNIC(ctx context.Context, host, name, mac, network string) (guardTarget, error) {
	if host == "" {
		return guardTarget{}, status.Error(codes.InvalidArgument, "container_host is required with container_name")
	}
	ifaces, err := corrosion.ListContainerInterfacesByHost(ctx, s.db, host)
	if err != nil {
		return guardTarget{}, status.Errorf(codes.Unavailable, "read container NICs on %s: %v", host, err)
	}
	var match []corrosion.ContainerInterfaceRecord
	for _, i := range ifaces {
		if i.CtName == name && ((mac != "" && strings.EqualFold(i.MAC, mac)) || (mac == "" && i.NetworkName == network)) {
			match = append(match, i)
		}
	}
	display := host + "/" + name
	switch len(match) {
	case 0:
		return guardTarget{}, status.Errorf(codes.NotFound, "container %s has no managed NIC %s", display, nicSelector(mac, network))
	case 1:
	default:
		return guardTarget{}, status.Errorf(codes.InvalidArgument,
			"container %s has %d NICs on network %q; name one by --mac", display, len(match), network)
	}
	m := match[0]
	return guardTarget{owner: corrosion.ContainerGuardOwner(host, name), display: "ct:" + display,
		nic: corrosion.NICRecord{MAC: m.MAC, IP: m.IP, NetworkName: m.NetworkName, Ordinal: m.Ordinal}}, nil
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
	out.AllowVlanTags = rec.AllowVLANTags
	out.SetBy, out.UpdatedAt = rec.SetBy, rec.UpdatedAt
	if g := firewall.ResolveNICGuard(rec, n.MAC, n.IP, subnets[n.NetworkName], nil); g != nil {
		out.EffectiveIpv4, out.Ipv4Unrestricted = g.V4, g.V4 == nil
		out.EffectiveIpv6, out.Ipv6Unrestricted = g.V6, g.V6 == nil
	}
	return out
}
