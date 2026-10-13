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
// An update that takes protection away from a NIC as it is enforced now (it
// unbinds a group bound outside the file, or relaxes or turns off a guard) is
// still applied — the file is what the operator declared — but never quietly:
// each one is in ChangePlan.Weakens, which the plan prints as a warning.

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
			if !slices.Contains(g.allowed, a) {
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

// WeakensWarning is the plan's warning for an update that takes protection
// away from a NIC as it is enforced now.
func WeakensWarning(weakens []string) string {
	return "this update removes protection set outside the file: " + strings.Join(weakens, "; ")
}

// sgList renders a binding for a delta.
func sgList(sgs []string) string { return "[" + strings.Join(sgs, ",") + "]" }

// classifyNICSecurity diffs each NIC's declared security-group binding and
// guard against the live ones the stored spec carries (OverlayLiveNICSecurity),
// as live changes; a NIC whose position holds another network is a topology
// change, which the network bucket owns.
func classifyNICSecurity(desired, stored *pb.VMSpec, p *ChangePlan) {
	for i, dn := range desired.Network {
		if i >= len(stored.Network) || dn == nil || stored.Network[i] == nil ||
			dn.GetName() != stored.Network[i].GetName() {
			break
		}
		sn := stored.Network[i]
		if want := dn.GetSecurityGroups(); len(want) > 0 && !slices.Equal(want, sn.GetSecurityGroups()) {
			p.MetadataChanges = append(p.MetadataChanges, Delta{Field: NICSecurityGroupsFieldPrefix + fmt.Sprint(i),
				Old: sgList(sn.GetSecurityGroups()), New: sgList(want)})
			var dropped []string
			for _, g := range sn.GetSecurityGroups() {
				if !slices.Contains(want, g) {
					dropped = append(dropped, g)
				}
			}
			if len(dropped) > 0 {
				p.Weakens = append(p.Weakens, fmt.Sprintf("nic %d (%s): unbinds security group(s) %s, bound outside the file",
					i, dn.GetName(), strings.Join(dropped, ", ")))
			}
		}
		if !nicGuardDeclared(dn) {
			continue
		}
		want, have := desiredGuard(dn), liveGuard(sn)
		if want.equal(have) {
			continue
		}
		p.MetadataChanges = append(p.MetadataChanges, Delta{Field: NICGuardFieldPrefix + fmt.Sprint(i),
			Old: have.String(), New: want.String()})
		if r := have.relaxations(want); len(r) > 0 {
			p.Weakens = append(p.Weakens, fmt.Sprintf("nic %d (%s): the guard as enforced now is relaxed: %s",
				i, dn.GetName(), strings.Join(r, ", ")))
		}
	}
}
