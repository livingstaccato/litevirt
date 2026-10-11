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
	"encoding/json"
	"errors"
	"fmt"
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
// NIC guards — whose entry nodes check guard authority and whose firewalls
// enforce them: the release token of the nic_guards feature has durably
// latched here (ReleaseFeatureAvailable, a local read). A guard record is
// written only through that feature (writeNICGuardsGranted), so before this
// is true no NIC is guarded.
func (s *Server) firewallReleaseActive() bool {
	return s.ReleaseFeatureAvailable(capabilities.FeatureNICGuards)
}

// nicGuardsRefusal is the release gate's refusal for an explicit guard
// setting made before the release token has latched.
func nicGuardsRefusal(what string) error {
	info, _ := capabilities.LookupFeature(capabilities.FeatureNICGuards)
	return status.Errorf(codes.FailedPrecondition,
		"the cluster upgrade must finish first (%s needs %s): %s; leave the guard settings out to create the NIC "+
			"unguarded, as before guards", capabilities.FeatureNICGuards, info.Token, what)
}

// writeNICGuardsGranted writes recs through the release feature nic_guards,
// its use recorded first.
func (s *Server) writeNICGuardsGranted(ctx context.Context, recs []corrosion.NICGuardRecord) error {
	return s.WithReleaseFeature(ctx, capabilities.FeatureNICGuards, func(ctx context.Context, g capabilities.FeatureGrant) error {
		for _, r := range recs {
			if err := corrosion.PutNICGuard(ctx, s.db, g, r, callerUsername(ctx)); err != nil {
				return status.Errorf(codes.Internal, "record the guard of NIC %s: %v", r.MAC, err)
			}
		}
		return nil
	})
}

// admitMode is how a create path came by the guard settings it carries.
type admitMode int

const (
	// admitNew: a caller asked for them; a weakening needs authority.
	admitNew admitMode = iota
	// admitRecreate: a re-create of a VM under the same name (rebuild, a
	// stack's rolling update), whose context carries the incarnation it
	// replaces (replacedVMFor). Each NIC that is the same NIC of that
	// incarnation — same network, and the same MAC when the request names
	// one, else the same position — carries that NIC's guard state; anything
	// else is a new request and needs authority to weaken (re-review I-7).
	admitRecreate
	// admitPeerOwner: the owner leg of a request a peer forwarded. The entry
	// node checked authority — if it is a build that knows guards, which is
	// what firewallReleaseActive proves; before that, explicit settings are
	// refused rather than trusted.
	admitPeerOwner
)

// guardDecision is what one NIC being created gets for its guard.
type guardDecision struct {
	// none: no record. The NIC is the same NIC of a re-created incarnation
	// that had no record (it predates guards, or was created before records
	// could be written), the request says nothing about its guard, and it
	// carries no trunk VLAN that incarnation did not: it stays unguarded, as
	// it ran (re-review I-11, R3-I1).
	none bool
	// carry: the record of the same NIC of the incarnation a re-create
	// replaces, carried to the new NIC unless the request says otherwise.
	carry *corrosion.NICGuardRecord
}

// guarded reports whether the NIC will be guarded once created with att.
func (d guardDecision) guarded(att *pb.NetworkAttachment) bool {
	switch {
	case nicGuardExplicit(att):
		mode, err := normalizeNICGuardMode(att.GetSpoofGuard())
		return err == nil && mode == corrosion.NICGuardOn
	case d.none:
		return false
	case d.carry != nil:
		return d.carry.Guarded()
	}
	return true
}

// record is the guard record the NIC gets, or nil for none.
func (d guardDecision) record(vm, uuid string, ordinal int, mac string, att *pb.NetworkAttachment) *corrosion.NICGuardRecord {
	switch {
	case nicGuardExplicit(att):
	case d.none:
		return nil
	case d.carry != nil:
		r := *d.carry
		r.VMName, r.MAC, r.VMUUID, r.Network, r.Ordinal = vm, mac, uuid, att.GetName(), ordinal
		r.SetBy, r.UpdatedAt, r.Deleted = "", "", false
		if k := staticIPv6Known(att); k != nil {
			r.Known = k
		}
		return &r
	}
	// A NIC on the `trunk:` feature is guarded like any other new NIC: its
	// guard holds every frame's MAC, ARP, ND, DHCP-server and RA identity,
	// and the addresses of its native VLAN; which VLANs it carries is its
	// network's to allow (re-review R2-I1).
	r := newNICGuardRecord(vm, uuid, ordinal, mac, att)
	return &r
}

// replacedNICs is the guard state of the incarnation a re-create replaces.
type replacedNICs struct {
	recs     []corrosion.NICGuardRecord // its records (VMUUID = its uuid)
	networks map[string]bool            // the networks its spec put a NIC on
	// trunks are, per network, the VLANs its NICs there carried on the
	// `trunk:` feature (two or more VLANs).
	trunks map[string]map[int32]bool
	// uuidless: the incarnation's spec carries no uuid (an import without
	// firmware state), so its records cannot be told from an earlier
	// incarnation's under the same name. Only a guard no weaker than the
	// default is carried from such a record; a relaxation is a new request.
	uuidless bool
}

// replacedIncarnation reads the guard state of the incarnation ctx says a
// re-create of vmName replaces. ok is false when there is none, or it cannot
// be identified on this replica — the create is then treated as new.
func (s *Server) replacedIncarnation(ctx context.Context, vmName string) (replacedNICs, bool, error) {
	r, ok := replacedVMFor(ctx, vmName)
	if !ok {
		return replacedNICs{}, false, nil
	}
	spec, found, err := corrosion.VMSpecOfIncarnation(ctx, s.db, vmName, r.snap.CreatedAt)
	if err != nil {
		return replacedNICs{}, false, status.Errorf(codes.Internal, "read the VM being re-created: %v", err)
	}
	var sp struct {
		UUID    string `json:"uuid"`
		Network []struct {
			Name  string  `json:"name"`
			Trunk []int32 `json:"trunk"`
		} `json:"network"`
	}
	if !found || json.Unmarshal([]byte(spec), &sp) != nil {
		slog.Warn("NIC guard: the incarnation a re-create replaces is not on this replica; its NICs are treated as new",
			"vm", vmName)
		return replacedNICs{}, false, nil
	}
	// With the tombstoned ones: the incarnation was deleted for the re-create.
	all, err := corrosion.ListNICGuardsWithDeleted(ctx, s.db)
	if err != nil {
		return replacedNICs{}, false, status.Errorf(codes.Internal, "read NIC guards: %v", err)
	}
	out := replacedNICs{networks: map[string]bool{}, trunks: map[string]map[int32]bool{}, uuidless: sp.UUID == ""}
	for _, n := range sp.Network {
		out.networks[n.Name] = true
		if len(n.Trunk) > 1 {
			if out.trunks[n.Name] == nil {
				out.trunks[n.Name] = map[int32]bool{}
			}
			for _, v := range n.Trunk {
				out.trunks[n.Name][v] = true
			}
		}
	}
	for _, rec := range all {
		if rec.VMName == vmName && rec.VMUUID == sp.UUID {
			out.recs = append(out.recs, rec)
		}
	}
	sort.Slice(out.recs, func(i, j int) bool { return out.recs[i].MAC < out.recs[j].MAC })
	return out, true, nil
}

// sameNIC finds the replaced incarnation's record of the NIC att is, at
// position ordinal: the same network, and the same MAC when att names one,
// else the same position.
func (p replacedNICs) sameNIC(att *pb.NetworkAttachment, ordinal int) (*corrosion.NICGuardRecord, bool) {
	for i := range p.recs {
		r := &p.recs[i]
		if r.Network != att.GetName() {
			continue
		}
		if m := strings.ToLower(att.GetMac()); m != "" {
			if strings.EqualFold(r.MAC, m) {
				return r, true
			}
			continue
		}
		if r.Ordinal == ordinal {
			return r, true
		}
	}
	return nil, false
}

// carriesNoNewVLAN reports whether att's trunk VLANs are all VLANs the
// replaced incarnation's NICs carried on att's network (re-review R3-I1). A
// NIC with no trunk carries none.
func (p replacedNICs) carriesNoNewVLAN(att *pb.NetworkAttachment) bool {
	if len(att.GetTrunk()) < 2 {
		return true
	}
	for _, v := range att.GetTrunk() {
		if !p.trunks[att.GetName()][v] {
			return false
		}
	}
	return true
}

// recordedOn reports whether the replaced incarnation had any record on
// network.
func (p replacedNICs) recordedOn(network string) bool {
	for _, r := range p.recs {
		if r.Network == network {
			return true
		}
	}
	return false
}

// admitNICGuards checks the guard settings of NICs about to be created by
// vmName and decides each one's record: each must be well formed; an
// explicit one needs the record store to be writable (refused rather than
// silently dropped); and a weakening one needs authority over its network
// (see admitMode). The decisions are indexed like atts.
func (s *Server) admitNICGuards(ctx context.Context, vmName string, atts []*pb.NetworkAttachment, how admitMode) ([]guardDecision, error) {
	decisions := make([]guardDecision, len(atts))
	if how == admitRecreate {
		var err error
		if decisions, err = s.guardDecisions(ctx, vmName, atts); err != nil {
			return nil, err
		}
	}
	for i, att := range atts {
		if att == nil {
			continue
		}
		mode, err := normalizeNICGuardMode(att.GetSpoofGuard())
		if err != nil {
			return nil, err
		}
		allowed, aerr := corrosion.NormalizeNICGuardAddresses(att.GetAllowedAddresses())
		if aerr != nil {
			return nil, status.Errorf(codes.InvalidArgument, "network %q allowed addresses: %v", att.GetName(), aerr)
		}
		same := decisions[i].carry
		if !nicGuardExplicit(att) {
			continue
		}
		if !s.db.MayWriteClusterPolicy() {
			return nil, status.Errorf(codes.FailedPrecondition,
				"network %q: NIC guard settings cannot be recorded until failover_scope_v1 has latched on every host; "+
					"leave them out to create the NIC (it will be unguarded until set with `lv firewall nic-guard set`)", att.GetName())
		}
		if !s.firewallReleaseActive() {
			return nil, nicGuardsRefusal(fmt.Sprintf("network %q: NIC guard settings are recorded only once every host runs this release", att.GetName()))
		}
		if !nicGuardWeakens(mode, allowed, att.GetAllowDhcpServer(), att.GetAllowRouterAdvertisement(), att.GetAllowVlanTags()) {
			continue
		}
		switch how {
		case admitPeerOwner:
			if !s.firewallReleaseActive() {
				return nil, status.Errorf(codes.FailedPrecondition,
					"network %q: NIC guard settings forwarded by a peer are refused until every host runs a build that checks them", att.GetName())
			}
			continue
		case admitRecreate:
			if same != nil && guardEquals(*same, mode, allowed, att) {
				continue
			}
		}
		if err := s.requireGuardAuthority(ctx, att.GetName(), "network "+att.GetName()); err != nil {
			return nil, err
		}
	}
	return decisions, nil
}

// guardDecisions decides each NIC's record for a create of vmName: when ctx
// carries the incarnation a re-create replaces, a NIC that is the same NIC of
// it carries its guard state (a record, or none); every other NIC is new.
// Indexed like atts.
func (s *Server) guardDecisions(ctx context.Context, vmName string, atts []*pb.NetworkAttachment) ([]guardDecision, error) {
	decisions := make([]guardDecision, len(atts))
	prior, ok, err := s.replacedIncarnation(ctx, vmName)
	if err != nil || !ok {
		return decisions, err
	}
	for i, att := range atts {
		if att == nil {
			continue
		}
		if r, same := prior.sameNIC(att, i); same {
			if !prior.uuidless || !nicGuardWeakens(r.Mode, r.Allowed, r.AllowDHCPServer, r.AllowRouterAdvert, r.AllowVLANTags) {
				decisions[i].carry = r
			}
		} else if prior.networks[att.GetName()] && !prior.recordedOn(att.GetName()) && prior.carriesNoNewVLAN(att) {
			// The same NIC of an incarnation that predates guards stays as
			// it ran — but only with at most the VLANs it ran with: a trunk
			// VLAN it never carried makes it a new NIC, with the default
			// guard and its network's VLANs (re-review R3-I1).
			decisions[i].none = true
		}
	}
	return decisions, nil
}

// guardEquals reports whether a requested guard is exactly the record r.
func guardEquals(r corrosion.NICGuardRecord, mode string, allowed []string, att *pb.NetworkAttachment) bool {
	return r.Mode == mode && strings.Join(r.Allowed, ",") == strings.Join(allowed, ",") &&
		r.AllowDHCPServer == att.GetAllowDhcpServer() && r.AllowRouterAdvert == att.GetAllowRouterAdvertisement() &&
		r.AllowVLANTags == att.GetAllowVlanTags()
}

// specUUID is the incarnation uuid of a stored VM spec (encoding/json of
// VMSpec), or "".
func specUUID(spec string) string {
	var sp struct {
		UUID string `json:"uuid"`
	}
	_ = json.Unmarshal([]byte(spec), &sp)
	return sp.UUID
}

// staticIPv6Known is a request's static IPv6 address as a record's Known
// list: the NIC row carries only the IPv4 address.
func staticIPv6Known(att *pb.NetworkAttachment) []string {
	v6 := strings.TrimSpace(att.GetIpv6())
	if v6 == "" {
		return nil
	}
	if p, err := netip.ParsePrefix(v6); err == nil {
		return []string{p.Addr().String()}
	}
	if a, err := netip.ParseAddr(v6); err == nil {
		return []string{a.String()}
	}
	return nil
}

// newNICGuardRecord is the record a new NIC gets from its request: on unless
// it says otherwise.
func newNICGuardRecord(vm, uuid string, ordinal int, mac string, att *pb.NetworkAttachment) corrosion.NICGuardRecord {
	mode, _ := normalizeNICGuardMode(att.GetSpoofGuard()) // admitted already
	return corrosion.NICGuardRecord{
		VMName: vm, MAC: mac, Mode: mode,
		Allowed:           att.GetAllowedAddresses(),
		AllowDHCPServer:   att.GetAllowDhcpServer(),
		AllowRouterAdvert: att.GetAllowRouterAdvertisement(),
		AllowVLANTags:     att.GetAllowVlanTags(),
		Known:             staticIPv6Known(att),
		VMUUID:            uuid, Network: att.GetName(), Ordinal: ordinal,
	}
}

// writeNewNICGuards records the guards of NICs being created, through the
// release feature nic_guards (merge checklist M8). Until the release token
// has latched — and before failover_scope_v1 has — nothing is recorded:
// admitNICGuards has already refused an explicit setting, so these are
// defaults, and the NICs are created unguarded, as on main, with a warning;
// a create main allowed is never refused for its guard. Once the token has
// latched the gate records the feature's use before the first record. A
// default record the gate still refuses (a host rolled back after the latch
// holds a first use off) is left out the same way; any other record, or any
// other failure, fails the create.
func (s *Server) writeNewNICGuards(ctx context.Context, recs []corrosion.NICGuardRecord) error {
	if len(recs) == 0 {
		return nil
	}
	if !s.db.MayWriteClusterPolicy() || !s.firewallReleaseActive() {
		slog.Warn("NIC guard: creating NICs unguarded; guards are recorded only once every host runs this release",
			"vm", recs[0].VMName, "nics", len(recs))
		return nil
	}
	err := s.writeNICGuardsGranted(ctx, recs)
	if err != nil && status.Code(err) == codes.FailedPrecondition && allDefaultGuards(recs) {
		slog.Warn("NIC guard: creating NICs unguarded; the release gate refused their guards",
			"vm", recs[0].VMName, "nics", len(recs), "error", err)
		return nil
	}
	return err
}

// allDefaultGuards reports whether every record is the default a new NIC
// gets: on, with no relaxation.
func allDefaultGuards(recs []corrosion.NICGuardRecord) bool {
	for _, r := range recs {
		if r.Mode != corrosion.NICGuardOn || len(r.Allowed) > 0 || r.AllowDHCPServer || r.AllowRouterAdvert || r.AllowVLANTags {
			return false
		}
	}
	return true
}

// retireNICGuards tombstones the guard records of a workload just deleted, so
// a later VM of the same name and MAC inherits nothing (re-review m1). A
// re-create still carries them (ListNICGuardsWithDeleted).
func (s *Server) retireNICGuards(ctx context.Context, owner string) {
	if err := corrosion.DeleteNICGuardsOf(ctx, s.db, owner, callerUsername(ctx)); err != nil {
		slog.Warn("NIC guard: could not retire the guard records of a deleted workload; a record of another incarnation guards nothing",
			"owner", owner, "error", err)
	}
}

// containerNICMACs is the MACs of this host's container name's NICs, read
// before its delete tombstones the rows (retireContainerGuards).
func (s *Server) containerNICMACs(ctx context.Context, name string) map[string]bool {
	nics, err := corrosion.GetContainerInterfaces(ctx, s.db, s.hostName, name)
	if err != nil {
		slog.Warn("NIC guard: could not read a container's NICs before its delete", "container", name, "error", err)
		return nil
	}
	mine := map[string]bool{}
	for _, n := range nics {
		mine[strings.ToLower(n.MAC)] = true
	}
	return mine
}

// retireContainerGuards tombstones the guard records of this host's
// container name, just deleted: its own, and those of its NICs (mine, from
// containerNICMACs) an earlier host wrote before it migrated or was
// relocated here, which the loader still renders it by (re-review m1).
// Another host's record is left alone while that host has a live container of
// the same name.
func (s *Server) retireContainerGuards(ctx context.Context, name string, mine map[string]bool) {
	s.retireNICGuards(ctx, corrosion.ContainerGuardOwner(s.hostName, name))
	if len(mine) == 0 {
		return
	}
	all, err := corrosion.ListNICGuards(ctx, s.db)
	if err != nil {
		slog.Warn("NIC guard: could not read the guard records of a deleted container's earlier hosts", "container", name, "error", err)
		return
	}
	done := map[string]bool{}
	for _, r := range all {
		h, n, ok := corrosion.ParseContainerGuardOwner(r.VMName)
		if !ok || n != name || h == s.hostName || done[r.VMName] || !mine[strings.ToLower(r.MAC)] {
			continue
		}
		if live, err := corrosion.GetContainer(ctx, s.db, h, name); err != nil || live != nil {
			continue // that host's own container, or unknown: not this one's to retire
		}
		done[r.VMName] = true
		s.retireNICGuards(ctx, r.VMName)
	}
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
	rec.Network, rec.Ordinal = tgt.nic.NetworkName, tgt.nic.Ordinal
	if !ct {
		if vm, err := corrosion.GetVM(ctx, s.db, tgt.owner); err == nil && vm != nil {
			rec.VMUUID = specUUID(vm.Spec)
		}
	}
	if berr == nil && before != nil {
		rec.Known = before.Known // a static IPv6 address recorded at create
		if rec.VMUUID == "" {
			rec.VMUUID = before.VMUUID
		}
	}
	if err := s.WithReleaseFeature(ctx, capabilities.FeatureNICGuards, func(ctx context.Context, g capabilities.FeatureGrant) error {
		return corrosion.PutNICGuard(ctx, s.db, g, rec, callerUsername(ctx))
	}); err != nil {
		detail := "mac=" + tgt.nic.MAC + " " + corrosion.AuditChange(guardState(before, berr), "unchanged")
		s.audit(ctx, "nic.guard.set", tgt.display, detail, "error")
		if st, ok := status.FromError(err); ok {
			return nil, st.Err() // the release gate's refusal, unchanged
		}
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
	nets, _ := corrosion.NetworkGuardInfos(ctx, s.db)
	out := nicGuardToPb(tgt.owner, tgt.nic, after, nets)
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
	nets, err := corrosion.NetworkGuardInfos(ctx, s.db)
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
			out.Guards = append(out.Guards, nicGuardToPb(vm.Name, n, rec, nets))
		}
	}
	if req.GetVmName() != "" {
		return out, nil
	}
	// Containers the caller may read, with the record the owning host renders
	// (firewall.containerGuard's lookup: a migrated container's follows it).
	cts, err := corrosion.ListContainers(ctx, s.db, "")
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "list containers: %v", err)
	}
	for _, ct := range cts {
		if s.RequirePerm(ctx, ctRBACPathFor(ct.Project, ct.Name), "ct.read", "viewer") != nil {
			continue
		}
		ifaces, err := corrosion.ListContainerInterfacesByHost(ctx, s.db, ct.HostName)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "read the NICs of container %s/%s: %v", ct.HostName, ct.Name, err)
		}
		for _, i := range ifaces {
			if i.CtName != ct.Name {
				continue
			}
			var rec *corrosion.NICGuardRecord
			if r, ok := firewall.ContainerGuard(guards, ct.HostName, ct.Name, i.MAC); ok {
				rec = &r
			}
			g := nicGuardToPb("", corrosion.NICRecord{MAC: i.MAC, IP: i.IP, NetworkName: i.NetworkName, Ordinal: i.Ordinal}, rec, nets)
			g.ContainerHost, g.ContainerName = ct.HostName, ct.Name
			out.Guards = append(out.Guards, g)
		}
	}
	return out, nil
}

// nicGuardToPb reports a NIC's guard, with the source addresses the owning
// host renders for it — the same resolution the firewall loader uses.
func nicGuardToPb(vm string, n corrosion.NICRecord, rec *corrosion.NICGuardRecord, nets map[string]corrosion.NetworkGuardInfo) *pb.NICGuard {
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
	info := nets[n.NetworkName]
	if g := firewall.ResolveNICGuard(rec, n.MAC, n.IP, info.Subnet, info.All(), nil); g != nil {
		out.EffectiveIpv4, out.Ipv4Unrestricted = g.V4, g.V4 == nil
		out.EffectiveIpv6, out.Ipv6Unrestricted = g.V6, g.V6 == nil
	}
	return out
}
