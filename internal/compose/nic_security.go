package compose

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"google.golang.org/protobuf/proto"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// A NIC's security is enforced from rows, not from the VM's stored spec: the
// security-group binding lives on the NIC row (`lv sg bind` rewrites it) and
// the guard in its nic_guards record (`lv firewall nic-guard set` rewrites
// it). The stored spec only says what the NIC was created with. So the
// comparison a deploy makes for these fields is against the rows, overlaid on
// the stored spec (OverlayLiveNICSecurity), the same view `lv inspect` shows.
//
// Compose owns what the file declares, and nothing else (docs/compose.md,
// "Security groups and guards a file does not declare"):
//
//   - A NIC's security groups are declared by a non-empty `security-groups:`.
//     A binding that differs from it is drift, and `up` rebinds the file's
//     list. A NIC whose file names no groups keeps whatever it is bound to.
//   - A NIC's guard is declared by naming any guard setting (nicGuardDeclared,
//     the create path's nicGuardExplicit). The whole guard is then the file's:
//     its mode is on unless the file says off. A NIC whose file names none
//     keeps the guard it has.
//
// An in-place restore that may take protection away from a NIC as it is
// enforced now is withheld unless the deploy opts in (--allow-weaken,
// NICSecurityGate.AllowWeaken), and the plan says what it withheld. That is
// every security-group rebind (per-NIC rules are first-match across the bound
// groups, so adding, removing or reordering a group can each widen access),
// and a guard restore that turns the guard off or adds an allowance. A guard
// restore that only tightens is applied without the opt-in, with the
// authority creating that guard would need (DeclaredGuardNeedsAuthority). So
// are restores the deploy can make
// only with authority it lacks, or that cannot be made per NIC, withheld and
// reported at plan time rather than failing the deploy (ApplyNICSecurityGate).
//
// A recreate creates the NICs from the file, as it always has: nothing is
// gated, and what it changes from the enforced state is a warning. A NIC
// whose file declares no groups keeps its live binding through the recreate
// (CarryUndeclaredSecurityGroups).

// NICSecurityGroupsFieldPrefix and NICGuardFieldPrefix prefix the
// MetadataChanges field of a NIC's security-group binding and guard; the
// suffix is the NIC's 0-based position ("nic_sg_0", "nic_guard_0").
const (
	NICSecurityGroupsFieldPrefix = "nic_sg_"
	NICGuardFieldPrefix          = "nic_guard_"
)

// LiveGuard is a NIC's guard record as the firewall enforces it.
type LiveGuard struct {
	Mode              string
	Allowed           []string
	AllowDHCPServer   bool
	AllowRouterAdvert bool
	AllowVLANTags     bool
}

// LiveNIC is one NIC of a VM as its rows have it now. Guard is nil when the
// NIC has no guard record for the VM's incarnation: it is unguarded.
type LiveNIC struct {
	Network        string
	MAC            string
	Ordinal        int
	SecurityGroups []string
	Guard          *LiveGuard
}

// MatchLiveNIC is the live NIC the stored spec's attachment at position i
// describes: the one with its MAC, or, for a spec that records no MAC, the
// one at that position on the same network. nil when there is none.
func MatchLiveNIC(stored []*pb.NetworkAttachment, i int, live []LiveNIC) *LiveNIC {
	if i < 0 || i >= len(stored) || stored[i] == nil {
		return nil
	}
	att := stored[i]
	for k := range live {
		n := &live[k]
		if att.GetMac() != "" {
			if strings.EqualFold(n.MAC, att.GetMac()) {
				return n
			}
			continue
		}
		if n.Ordinal == i && n.Network == att.GetName() {
			return n
		}
	}
	return nil
}

// OverlayLiveNICSecurity returns a copy of stored whose NICs carry their live
// security-group binding and guard in place of the create-time values. A NIC
// with no guard record gets no guard fields (SpoofGuard ""): unguarded. A NIC
// the rows do not have is left as stored.
func OverlayLiveNICSecurity(stored *pb.VMSpec, live []LiveNIC) *pb.VMSpec {
	if stored == nil {
		return nil
	}
	out := proto.Clone(stored).(*pb.VMSpec)
	for i, att := range out.Network {
		n := MatchLiveNIC(out.Network, i, live)
		if n == nil {
			continue
		}
		att.SecurityGroups = slices.Clone(n.SecurityGroups)
		att.SpoofGuard, att.AllowedAddresses = "", nil
		att.AllowDhcpServer, att.AllowRouterAdvertisement, att.AllowVlanTags = false, false, false
		if g := n.Guard; g != nil {
			att.SpoofGuard = g.Mode
			att.AllowedAddresses = slices.Clone(g.Allowed)
			att.AllowDhcpServer, att.AllowRouterAdvertisement, att.AllowVlanTags = g.AllowDHCPServer, g.AllowRouterAdvert, g.AllowVLANTags
		}
	}
	return out
}

// nicGuardDeclared reports whether a NIC of the file says anything about its
// guard (the create path's nicGuardExplicit).
func nicGuardDeclared(att *pb.NetworkAttachment) bool {
	return att.GetSpoofGuard() != "" || len(att.GetAllowedAddresses()) > 0 ||
		att.GetAllowDhcpServer() || att.GetAllowRouterAdvertisement() || att.GetAllowVlanTags()
}

// guardView is a guard in comparable form. mode "" is no record (unguarded).
type guardView struct {
	mode           string
	allowed        []string
	dhcp, ra, vlan bool
}

// desiredGuard is the guard a declaring NIC asks for: on unless it says off.
func desiredGuard(att *pb.NetworkAttachment) guardView {
	mode := strings.ToLower(strings.TrimSpace(att.GetSpoofGuard()))
	if mode == "" {
		mode = "on"
	}
	return guardView{mode: mode, allowed: canonicalGuardAddresses(att.GetAllowedAddresses()),
		dhcp: att.GetAllowDhcpServer(), ra: att.GetAllowRouterAdvertisement(), vlan: att.GetAllowVlanTags()}
}

// liveGuard is the guard an overlaid stored attachment carries.
func liveGuard(att *pb.NetworkAttachment) guardView {
	return guardView{mode: strings.ToLower(strings.TrimSpace(att.GetSpoofGuard())),
		allowed: canonicalGuardAddresses(att.GetAllowedAddresses()),
		dhcp:    att.GetAllowDhcpServer(), ra: att.GetAllowRouterAdvertisement(), vlan: att.GetAllowVlanTags()}
}

func (g guardView) equal(o guardView) bool {
	return g.mode == o.mode && slices.Equal(g.allowed, o.allowed) && g.dhcp == o.dhcp && g.ra == o.ra && g.vlan == o.vlan
}

func (g guardView) String() string {
	if g.mode == "" {
		return "unset"
	}
	return fmt.Sprintf("{mode=%s allowed=[%s] dhcp-server=%t router-advert=%t vlan-tags=%t}",
		g.mode, strings.Join(g.allowed, ","), g.dhcp, g.ra, g.vlan)
}

// relaxations lists what moving from the live guard to want lets the guest do
// that it cannot now. A NIC with no record, or one that is off, is unguarded:
// only turning on VLAN tags (honoured whatever the mode) relaxes it further.
func (g guardView) relaxations(want guardView) []string {
	var out []string
	guarded := g.mode == "on"
	if guarded && want.mode != "on" {
		out = append(out, "turns the guard off")
	}
	if guarded && want.mode == "on" {
		for _, a := range want.allowed {
			if !addressCovered(a, g.allowed) {
				out = append(out, "allows source "+a)
			}
		}
		if want.dhcp && !g.dhcp {
			out = append(out, "allows a DHCP server")
		}
		if want.ra && !g.ra {
			out = append(out, "allows router advertisements")
		}
	}
	if want.vlan && !g.vlan {
		out = append(out, "allows vlan tags")
	}
	return out
}

// canonicalGuardAddresses is the address list in the form a guard record
// stores it (corrosion.NormalizeNICGuardAddresses): masked prefixes,
// canonical addresses, sorted, deduplicated. An entry that does not parse is
// kept as written, so it still compares unequal; the guard write refuses it.
func canonicalGuardAddresses(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if p, err := netip.ParsePrefix(s); err == nil {
			s = p.Masked().String()
		} else if a, err := netip.ParseAddr(s); err == nil {
			s = a.String()
		}
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

// addressCovered reports whether addr (an address or prefix) lies inside one
// of the prefixes or addresses in have.
func addressCovered(addr string, have []string) bool {
	want, err := netip.ParsePrefix(addr)
	if err != nil {
		a, aerr := netip.ParseAddr(addr)
		if aerr != nil {
			return slices.Contains(have, addr)
		}
		want = netip.PrefixFrom(a, a.BitLen())
	}
	for _, h := range have {
		p, err := netip.ParsePrefix(h)
		if err != nil {
			a, aerr := netip.ParseAddr(h)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Bits() <= want.Bits() && p.Contains(want.Addr()) {
			return true
		}
	}
	return false
}

// NICSecurityChange is one NIC's security-group binding or guard that a plan
// changes from what is enforced now.
type NICSecurityChange struct {
	Field    string // the MetadataChanges field ("nic_sg_0", "nic_guard_0")
	Position int    // the NIC's position in the desired and stored specs
	Network  string
	Guard    bool // a guard change; else a security-group binding
	// Weakens is what the change may take away from the NIC as enforced
	// now; empty for a guard restore that only tightens.
	Weakens []string
}

func sgList(sgs []string) string { return "[" + strings.Join(sgs, ",") + "]" }

func groupsNotIn(a, b []string) []string {
	var out []string
	for _, g := range a {
		if !slices.Contains(b, g) {
			out = append(out, g)
		}
	}
	return out
}

// classifyNICSecurity diffs each NIC's declared security-group binding and
// guard against the live ones the stored spec carries (OverlayLiveNICSecurity),
// as live changes. A position whose network differs is a topology change,
// which the network bucket owns; later positions are still compared.
func classifyNICSecurity(desired, stored *pb.VMSpec, p *ChangePlan) {
	for i, dn := range desired.Network {
		if i >= len(stored.Network) || dn == nil || stored.Network[i] == nil ||
			dn.GetName() != stored.Network[i].GetName() {
			continue
		}
		sn := stored.Network[i]
		if want := dn.GetSecurityGroups(); len(want) > 0 && !slices.Equal(want, sn.GetSecurityGroups()) {
			field := NICSecurityGroupsFieldPrefix + fmt.Sprint(i)
			p.MetadataChanges = append(p.MetadataChanges, Delta{Field: field,
				Old: sgList(sn.GetSecurityGroups()), New: sgList(want)})
			w := fmt.Sprintf("nic %d (%s): rebinds security groups %s→%s", i, dn.GetName(), sgList(sn.GetSecurityGroups()), sgList(want))
			var parts []string
			if d := groupsNotIn(sn.GetSecurityGroups(), want); len(d) > 0 {
				parts = append(parts, "unbinds "+strings.Join(d, ", ")+", bound now")
			}
			if a := groupsNotIn(want, sn.GetSecurityGroups()); len(a) > 0 {
				parts = append(parts, "binds "+strings.Join(a, ", "))
			}
			if len(parts) == 0 {
				parts = append(parts, "reorders them, and the first matching rule wins")
			}
			p.NICSecurity = append(p.NICSecurity, NICSecurityChange{Field: field, Position: i, Network: dn.GetName(),
				Weakens: []string{w + " (" + strings.Join(parts, "; ") + ")"}})
		}
		if !nicGuardDeclared(dn) {
			continue
		}
		want, have := desiredGuard(dn), liveGuard(sn)
		if want.equal(have) {
			continue
		}
		field := NICGuardFieldPrefix + fmt.Sprint(i)
		p.MetadataChanges = append(p.MetadataChanges, Delta{Field: field, Old: have.String(), New: want.String()})
		c := NICSecurityChange{Field: field, Position: i, Network: dn.GetName(), Guard: true}
		if r := have.relaxations(want); len(r) > 0 {
			c.Weakens = []string{fmt.Sprintf("nic %d (%s): relaxes the guard enforced now: %s", i, dn.GetName(), strings.Join(r, ", "))}
		}
		p.NICSecurity = append(p.NICSecurity, c)
	}
}

// Weakens is every weakening the plan's NIC security changes carry.
func (p ChangePlan) Weakens() []string {
	var out []string
	for _, c := range p.NICSecurity {
		out = append(out, c.Weakens...)
	}
	return out
}

// DeclaredGuardNeedsAuthority reports whether the guard a NIC entry declares
// is weaker than the default one: off, or with any allowance. Writing such a
// guard needs network.update over the NIC's network, at create and at
// restore alike, whatever the guard enforced now; a plain "on" needs none.
// The plan gate (ApplyNICSecurityGate) and the deploy's executor both decide
// by this one function, so the plan withholds exactly what the executor
// would refuse.
func DeclaredGuardNeedsAuthority(att *pb.NetworkAttachment) bool {
	g := desiredGuard(att)
	return g.mode != "on" || len(g.allowed) > 0 || g.dhcp || g.ra || g.vlan
}

// GuardRestoreWeakens is what writing att's declared guard over the live
// NIC's guard would relax, now: the executor re-checks it against the rows
// as they are when it writes.
func GuardRestoreWeakens(live *LiveNIC, att *pb.NetworkAttachment) []string {
	have := guardView{}
	if live != nil && live.Guard != nil {
		have = guardView{mode: strings.ToLower(strings.TrimSpace(live.Guard.Mode)), allowed: canonicalGuardAddresses(live.Guard.Allowed),
			dhcp: live.Guard.AllowDHCPServer, ra: live.Guard.AllowRouterAdvert, vlan: live.Guard.AllowVLANTags}
	}
	return have.relaxations(desiredGuard(att))
}

// NICSecurityGate is what a deploy may restore of a NIC's security, decided
// by the server for the caller before the plan is shown. The zero value is
// the safe one: nothing that may weaken is applied.
type NICSecurityGate struct {
	// AllowWeaken: the caller opted in (--allow-weaken) to restores that may
	// weaken protection.
	AllowWeaken bool
	// GuardsUnwritable, when set, is why no guard record can be written now
	// (the nic_guards release has not latched); guard restores are withheld.
	GuardsUnwritable string
	// CheckBind reports whether the caller may rebind vm's security groups
	// (lv sg bind's authority). nil: it may.
	CheckBind func(vm string) error
	// CheckGuardAuthority reports whether the caller may write, on the
	// network, a guard weaker than the default one (lv firewall nic-guard
	// set's authority). nil: it may. It is asked exactly for the guards
	// DeclaredGuardNeedsAuthority names, by the plan and by the executor.
	CheckGuardAuthority func(network string) error
	// GuardUnenforced is why no guard can be enforced on a network's NICs
	// (GuardUnenforcedOn), or "". A guard the file declares there is no
	// drift: create writes no record for it, so nothing is restored, and the
	// plan says the guard is not enforced. nil: every network enforces.
	GuardUnenforced func(network string) string
}

// GuardUnenforcedOn is why a guard cannot be enforced on a NIC of a network of
// type netType named name, or "": a direct (macvtap) or SR-IOV NIC bypasses
// the bridge where guards are enforced. Create, the guard RPC, the plan and
// the deploy's executor all decide by this one function.
func GuardUnenforcedOn(netType, name string) string {
	switch {
	case netType == "direct" || strings.HasPrefix(name, "direct:"):
		return "a direct (macvtap) network bypasses the bridge where guards are enforced"
	case netType == "sriov":
		return "an SR-IOV network bypasses the bridge where guards are enforced"
	}
	return ""
}

// GuardNotEnforcedNote is the plan's note for a NIC whose file declares a
// guard on a network that cannot enforce one.
func GuardNotEnforcedNote(i int, network, why string) string {
	return fmt.Sprintf("nic %d (%s) declares a guard that is not enforced: %s; the NIC has no guard "+
		"(leave the guard settings out, or use a bridge network)", i, network, why)
}

// MaxGuardAddresses bounds the allowed list of one NIC's guard, so one record
// cannot bloat every host's ruleset.
const MaxGuardAddresses = 64

// NormalizeGuardAddresses validates a guard's allowed (or known) list and
// returns it in canonical form: masked prefixes, canonical addresses, sorted,
// deduplicated. An entry that is not an IP address or prefix, or carries a
// zone, and a list of more than MaxGuardAddresses distinct entries, are
// refused: they would otherwise reach every host's renderer, which refuses
// the whole ruleset on one. It is the one validator: the guard record store
// (corrosion.NormalizeNICGuardAddresses), create, the plan and the deploy's
// executor all use it.
func NormalizeGuardAddresses(in []string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, raw := range in {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		var canon string
		if p, err := netip.ParsePrefix(s); err == nil && p.Addr().Zone() == "" {
			canon = p.Masked().String()
		} else if a, err := netip.ParseAddr(s); err == nil && a.Zone() == "" {
			canon = a.String()
		} else {
			return nil, fmt.Errorf("%q is not an IP address or prefix", raw)
		}
		if !seen[canon] {
			seen[canon] = true
			out = append(out, canon)
		}
	}
	if len(out) > MaxGuardAddresses {
		return nil, fmt.Errorf("%d addresses; at most %d per NIC", len(out), MaxGuardAddresses)
	}
	sort.Strings(out)
	return out, nil
}

// InvalidDeclaredGuard is why a NIC entry's declared guard cannot be written
// (a mode other than on or off; allowed addresses NormalizeGuardAddresses
// refuses), or "": the checks create applies, by the same validator.
func InvalidDeclaredGuard(att *pb.NetworkAttachment) string {
	switch strings.ToLower(strings.TrimSpace(att.GetSpoofGuard())) {
	case "", "on", "off":
	default:
		return fmt.Sprintf("spoof-guard %q: want on or off", att.GetSpoofGuard())
	}
	if _, err := NormalizeGuardAddresses(att.GetAllowedAddresses()); err != nil {
		return "allowed addresses: " + err.Error()
	}
	return ""
}

// ApplyNICSecurityGate removes from an in-place plan each NIC security change
// the deploy will not make, and returns the plan's warnings about them: each
// withheld change with why, and each weakening that is applied. live is the
// VM's NICs as enforced now (nil: only the stored spec is known); stored is
// the overlaid stored spec Classify compared with.
func ApplyNICSecurityGate(vm string, p *ChangePlan, desired, stored *pb.VMSpec, live []LiveNIC, gate NICSecurityGate) []string {
	if len(p.NICSecurity) == 0 {
		return nil
	}
	if p.Max() == ActionRecreate || len(p.NotReconfigurable) > 0 {
		// The recreate makes the NICs from the file, as it always has.
		var out []string
		for _, w := range p.Weakens() {
			out = append(out, "the recreate applies the file's NIC security, which "+w)
		}
		return out
	}
	var warnings []string
	withheld := map[string]bool{}
	notEnforced := func(c NICSecurityChange, why string) {
		withheld[c.Field] = true
		warnings = append(warnings, GuardNotEnforcedNote(c.Position, c.Network, why))
	}
	withhold := func(c NICSecurityChange, why string) {
		withheld[c.Field] = true
		what := "security groups"
		if c.Guard {
			what = "guard"
		}
		warnings = append(warnings, fmt.Sprintf("nic %d (%s) %s not restored: %s", c.Position, c.Network, what, why))
	}
	for _, c := range p.NICSecurity {
		switch {
		case c.Guard && gate.GuardUnenforced != nil && gate.GuardUnenforced(c.Network) != "":
			notEnforced(c, gate.GuardUnenforced(c.Network))
		case c.Guard && InvalidDeclaredGuard(desired.Network[c.Position]) != "":
			withhold(c, "the file's guard is invalid: "+InvalidDeclaredGuard(desired.Network[c.Position]))
		case !c.Guard && SharedNetworkConflict(c.Position, desired, stored, live) != "":
			withhold(c, SharedNetworkConflict(c.Position, desired, stored, live))
		case c.Guard && gate.GuardsUnwritable != "":
			withhold(c, gate.GuardsUnwritable)
		case len(c.Weakens) > 0 && !gate.AllowWeaken:
			withhold(c, "it may remove protection set outside the file — "+strings.Join(c.Weakens, "; ")+
				"; re-run with --allow-weaken to apply it")
		case !c.Guard && gate.CheckBind != nil && gate.CheckBind(vm) != nil:
			withhold(c, gate.CheckBind(vm).Error())
		case c.Guard && DeclaredGuardNeedsAuthority(desired.Network[c.Position]) && gate.CheckGuardAuthority != nil &&
			gate.CheckGuardAuthority(c.Network) != nil:
			withhold(c, gate.CheckGuardAuthority(c.Network).Error())
		default:
			for _, w := range c.Weakens {
				warnings = append(warnings, "applied with --allow-weaken: "+w)
			}
		}
	}
	if len(withheld) > 0 {
		var meta []Delta
		for _, d := range p.MetadataChanges {
			if !withheld[d.Field] {
				meta = append(meta, d)
			}
		}
		p.MetadataChanges = meta
		var kept []NICSecurityChange
		for _, c := range p.NICSecurity {
			if !withheld[c.Field] {
				kept = append(kept, c)
			}
		}
		p.NICSecurity = kept
	}
	return warnings
}

// SharedNetworkConflict is why NIC i's binding cannot be restored on its own,
// or "": a binding is written per network, so every other NIC of the VM on
// that network must be one the file declares the same groups for.
func SharedNetworkConflict(i int, desired, stored *pb.VMSpec, live []LiveNIC) string {
	network := desired.Network[i].GetName()
	want := desired.Network[i].GetSecurityGroups()
	self := MatchLiveNIC(stored.GetNetwork(), i, live)
	positionOf := func(mac string) int {
		for j := range stored.GetNetwork() {
			if n := MatchLiveNIC(stored.GetNetwork(), j, live); n != nil && strings.EqualFold(n.MAC, mac) {
				return j
			}
		}
		return -1
	}
	conflict := func(j int) bool {
		return j < 0 || j >= len(desired.Network) || !slices.Equal(desired.Network[j].GetSecurityGroups(), want)
	}
	if live != nil {
		for _, o := range live {
			if o.Network != network || (self != nil && strings.EqualFold(o.MAC, self.MAC)) {
				continue
			}
			if conflict(positionOf(o.MAC)) {
				return fmt.Sprintf("a security-group binding is written per network, and NIC %s, also on %q, is not declared with the same groups "+
					"(declare %s on every NIC of the VM on %q, or bind them all with lv sg bind)", o.MAC, network, sgList(want), network)
			}
		}
		return ""
	}
	for j, sn := range stored.GetNetwork() {
		if j != i && sn.GetName() == network && conflict(j) {
			return fmt.Sprintf("a security-group binding is written per network, and NIC %d, also on %q, is not declared with the same groups "+
				"(declare %s on every NIC of the VM on %q, or bind them all with lv sg bind)", j, network, sgList(want), network)
		}
	}
	return ""
}

// CarryUndeclaredSecurityGroups gives each NIC of a recreate's desired spec
// whose file declares no security groups the binding its live NIC has (stored
// is the overlaid stored spec), so a recreate leaves an undeclared binding as
// it is, as an in-place update does. A binding is carried only to the NIC it
// is known to belong to:
//
//   - a desired NIC that names a MAC is the stored NIC with that MAC;
//   - otherwise, on a network where the file and the VM have the same number
//     of NICs that name no MAC in the file, the k-th such NIC is the k-th
//     unmatched stored NIC on that network. When the counts differ (a NIC was
//     added or removed on that network) the pairing is ambiguous, and nothing
//     is carried there: each binding is dropped, and named.
//
// It returns a note per binding carried and per binding dropped.
func CarryUndeclaredSecurityGroups(desired, stored *pb.VMSpec) []string {
	var notes []string
	pair := map[int]*pb.NetworkAttachment{} // desired position → its stored NIC
	used := map[*pb.NetworkAttachment]bool{}
	for i, dn := range desired.GetNetwork() {
		if dn == nil || dn.GetMac() == "" {
			continue
		}
		for _, sn := range stored.GetNetwork() {
			if sn != nil && !used[sn] && sn.GetName() == dn.GetName() && strings.EqualFold(sn.GetMac(), dn.GetMac()) {
				pair[i], used[sn] = sn, true
				break
			}
		}
	}
	ambiguous := map[string]bool{}
	byNet := map[string][]int{}
	for i, dn := range desired.GetNetwork() {
		if dn != nil && dn.GetMac() == "" {
			byNet[dn.GetName()] = append(byNet[dn.GetName()], i)
		}
	}
	for network, idx := range byNet {
		var free []*pb.NetworkAttachment
		for _, sn := range stored.GetNetwork() {
			if sn != nil && !used[sn] && sn.GetName() == network {
				free = append(free, sn)
			}
		}
		if len(free) != len(idx) {
			ambiguous[network] = true
			continue
		}
		for k, i := range idx {
			pair[i], used[free[k]] = free[k], true
		}
	}
	for i, dn := range desired.GetNetwork() {
		sn := pair[i]
		if dn == nil || sn == nil || sn.GetName() != dn.GetName() ||
			len(dn.GetSecurityGroups()) > 0 || len(sn.GetSecurityGroups()) == 0 {
			continue
		}
		dn.SecurityGroups = slices.Clone(sn.GetSecurityGroups())
		notes = append(notes, fmt.Sprintf("nic %d (%s) keeps the security groups %s its NIC (%s) has now through the recreate (the file declares none)",
			i, dn.GetName(), sgList(dn.SecurityGroups), nicLabel(sn)))
	}
	for _, sn := range stored.GetNetwork() {
		if sn == nil || used[sn] || len(sn.GetSecurityGroups()) == 0 {
			continue
		}
		why := "which the file no longer has"
		if ambiguous[sn.GetName()] {
			why = "because the file changes how many NICs are on " + sn.GetName() + ", so which new NIC is that NIC is unknown " +
				"(declare security-groups: on the NICs, or name their mac:, to keep a binding)"
		}
		notes = append(notes, fmt.Sprintf("the recreate drops the security groups %s bound now to the NIC (%s) on %s, %s",
			sgList(sn.GetSecurityGroups()), nicLabel(sn), sn.GetName(), why))
	}
	return notes
}

func nicLabel(n *pb.NetworkAttachment) string {
	if n.GetMac() != "" {
		return n.GetMac()
	}
	return "no MAC recorded"
}

// StripUnenforcedGuards removes the guard settings from each NIC of a create's
// spec whose network cannot enforce a guard (unenforced, GuardUnenforcedOn),
// so the create does not refuse a file that declares one, and returns the
// plan's note for each: the setting is reported, never dropped silently.
func StripUnenforcedGuards(spec *pb.VMSpec, unenforced func(network string) string) []string {
	if unenforced == nil {
		return nil
	}
	var notes []string
	for i, n := range spec.GetNetwork() {
		if n == nil || !nicGuardDeclared(n) {
			continue
		}
		if why := unenforced(n.GetName()); why != "" {
			n.SpoofGuard, n.AllowedAddresses = "", nil
			n.AllowDhcpServer, n.AllowRouterAdvertisement, n.AllowVlanTags = false, false, false
			notes = append(notes, GuardNotEnforcedNote(i, n.GetName(), why))
		}
	}
	return notes
}
