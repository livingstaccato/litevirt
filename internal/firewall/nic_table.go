package firewall

// The per-NIC bridge table (NICTableName): per-NIC rules, the default policy
// applied per NIC, the VLAN rule and the NIC guards.
//
// Layout, per hook (each base chain first lets everything not on a guest NIC
// port through untouched, so other bridges on the host are not filtered or
// tracked by these chains):
//
//	prerouting (-300)  VLAN rule for every NIC, then each guarded NIC's guard.
//	forward            guest ↔ guest / guest ↔ another port: sender nic_out_*, then receiver nic_in_*.
//	input              guest → host, or → routed: sender nic_out_*; what passes is marked judged.
//	output             host or routed → guest: receiver nic_in_*; routed → another port: routed_to_port.
//
// Modes (Plan.NICMode): enforce drops; observe replaces every drop with a
// counter carrying an "lv-wd" comment and drops nothing (WouldDrops reads
// them); guards-only renders prerouting only, because the rest needs
// nf_conntrack_bridge.

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// Packet marks the bridge table sets for the inet forward chain. Two high bits
// of skb->mark; a host that routes by fwmark must not use them.
const (
	// judgedMark: a guest's frame passed its NIC's egress rules (bridge
	// input), so inet forward need not judge it again.
	judgedMark = 0x10000000
	// deferMark: inet forward handed routed traffic toward a guest bridge to
	// that bridge's output hook to judge.
	deferMark = 0x20000000
)

// WouldDropComment prefixes the comment of every observe-mode counter:
// "lv-wd <dev> <in|out|vlan> <label>".
const WouldDropComment = "lv-wd"

// nicSet names, in the bridge table.
const (
	setNICDevs   = "lv_nic_devs"
	setVLANOK    = "lv_vlan_ok"
	setDHCPSrv   = "lv_dhcp_srv"
	setGateways4 = "lv_gw4"
	setGateways6 = "lv_gw6"
	setLB4       = "lv_lb4"
	setLBSrc4    = "lv_lb_src4"
)

func renderIfnameSet(b *strings.Builder, name string, devs []string) {
	fmt.Fprintf(b, "    set %s {\n        type ifname\n", name)
	if len(devs) > 0 {
		fmt.Fprintf(b, "        elements = { %s }\n", quoteNames(devs))
	}
	fmt.Fprintf(b, "    }\n\n")
}

func renderAddrSet(b *strings.Builder, name, typ string, elems []string) {
	fmt.Fprintf(b, "    set %s {\n        type %s\n        flags interval\n", name, typ)
	if c := collapseSetElements(elems); len(c) > 0 {
		fmt.Fprintf(b, "        elements = { %s }\n", strings.Join(c, ", "))
	}
	fmt.Fprintf(b, "    }\n\n")
}

// verdict renders what a terminal drop becomes in the plan's mode: the drop
// itself, or a named counter that lets the frame on.
func verdict(p Plan, dev, side, label string) string {
	if p.nicMode() == NICModeObserve {
		return fmt.Sprintf("counter comment %q", fmt.Sprintf("%s %s %s %s", WouldDropComment, dev, side, label))
	}
	return "drop"
}

// renderNICTable emits the bridge table that enforces every per-NIC policy.
func renderNICTable(b *strings.Builder, p Plan, sgs map[string]SecurityGroup, v6Sets map[string]bool) {
	nics := make([]NICBinding, len(p.NICs))
	copy(nics, p.NICs)
	sort.Slice(nics, func(i, j int) bool { return nics[i].NICDev < nics[j].NICDev })
	mode := p.nicMode()

	var devs, vlanOK, dhcpSrv []string
	for _, n := range nics {
		devs = append(devs, n.NICDev)
		if n.AllowVLANTags || len(n.TrunkVIDs) > 0 {
			vlanOK = append(vlanOK, n.NICDev)
		}
		if n.DHCPServer {
			dhcpSrv = append(dhcpSrv, n.NICDev)
		}
	}
	var gw4, gw6 []string
	for _, g := range p.Gateways {
		if isIPv6Literal(g) {
			gw6 = append(gw6, g)
		} else {
			gw4 = append(gw4, g)
		}
	}

	fmt.Fprintf(b, "table bridge %s {\n", NICTableName)
	renderIfnameSet(b, setNICDevs, devs)
	renderIfnameSet(b, setVLANOK, vlanOK)
	if mode != NICModeGuardsOnly {
		renderNICTableSets(b, p, dhcpSrv, gw4, gw6)
	}

	// prerouting: before anything else, conntrack included.
	fmt.Fprintf(b, "    chain prerouting {\n")
	fmt.Fprintf(b, "        type filter hook prerouting priority -300; policy accept;\n")
	fmt.Fprintf(b, "        iifname != @%s accept\n", setNICDevs)
	// A tagged frame from a guest carries its payload past every rule, which
	// matches untagged IP; a guest port is an access port. QinQ shows as
	// 802.1ad or a doubled 802.1Q, both caught here.
	fmt.Fprintf(b, "        iifname != @%s ether type { 8021q, 8021ad } %s\n", setVLANOK,
		verdictVLAN(p))
	for _, n := range nics {
		renderTrunkConfine(b, p, n, "iifname", true)
	}
	for _, n := range nics {
		if n.Guard != nil {
			fmt.Fprintf(b, "        iifname %s jump guard_%s\n", n.NICDev, sanitiseChain(n.NICDev))
		}
	}
	fmt.Fprintf(b, "    }\n\n")
	for _, n := range nics {
		if n.Guard != nil {
			renderGuardChain(b, n.NICDev, *n.Guard, n.AllowVLANTags, len(n.TrunkVIDs) > 0)
		}
	}
	if mode == NICModeGuardsOnly {
		b.WriteString("}\n")
		return
	}

	// forward: guest → guest on this bridge, guest ↔ another port.
	fmt.Fprintf(b, "    chain forward {\n")
	fmt.Fprintf(b, "        type filter hook forward priority filter; policy accept;\n")
	fmt.Fprintf(b, "        iifname != @%s oifname != @%s accept\n", setNICDevs, setNICDevs)
	renderTaggedToNIC(b, p, nics)
	bridgeCommon(b, p)
	// DHCPv4/v6 client requests broadcast or multicast to a server on the
	// link, and replies from a server that is not a guest (an upstream server
	// on the uplink) or from a guest allowed to serve DHCP.
	fmt.Fprintf(b, "        iifname @%s udp sport 68 udp dport 67 ip daddr 255.255.255.255 accept\n", setNICDevs)
	fmt.Fprintf(b, "        iifname @%s ip6 saddr fe80::/10 ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept\n", setNICDevs)
	fmt.Fprintf(b, "        iifname != @%s udp sport 67 udp dport 68 accept\n", setNICDevs)
	fmt.Fprintf(b, "        iifname != @%s ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n", setNICDevs)
	fmt.Fprintf(b, "        iifname @%s udp sport 67 udp dport 68 accept\n", setDHCPSrv)
	fmt.Fprintf(b, "        iifname @%s ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n", setDHCPSrv)
	// Router advertisements and redirects from a router that is not a guest.
	fmt.Fprintf(b, "        iifname != @%s ip6 hoplimit 255 icmpv6 type { nd-router-advert, nd-redirect } accept\n", setNICDevs)
	// The built-in load balancer's haproxy on ANOTHER host reaching a backend
	// here: bridged in from the uplink (re-review m-d).
	fmt.Fprintf(b, "        iifname != @%s ip saddr @%s ip daddr . tcp dport @%s accept\n", setNICDevs, setLBSrc4, setLB4)
	fmt.Fprintf(b, "        ct state invalid %s\n", verdict(p, "-", "state", "invalid"))
	dispatchNICs(b, nics, "iifname", "nic_out_")
	dispatchNICs(b, nics, "oifname", "nic_in_")
	fmt.Fprintf(b, "    }\n\n")

	// input: guest → host (or to be routed).
	fmt.Fprintf(b, "    chain input {\n")
	fmt.Fprintf(b, "        type filter hook input priority filter; policy accept;\n")
	fmt.Fprintf(b, "        iifname != @%s accept\n", setNICDevs)
	bridgeCommon(b, p)
	// litevirt's own services on the guest networks: dnsmasq's DHCP and DNS
	// at the network's gateway address, and nowhere else.
	fmt.Fprintf(b, "        udp sport 68 udp dport 67 ip daddr { 255.255.255.255 } accept\n")
	fmt.Fprintf(b, "        udp sport 68 udp dport 67 ip daddr @%s accept\n", setGateways4)
	fmt.Fprintf(b, "        ip6 saddr fe80::/10 ip6 daddr ff02::1:2 udp sport 546 udp dport 547 accept\n")
	fmt.Fprintf(b, "        ip daddr @%s udp dport 53 accept\n", setGateways4)
	fmt.Fprintf(b, "        ip daddr @%s tcp dport 53 accept\n", setGateways4)
	fmt.Fprintf(b, "        ip6 daddr @%s udp dport 53 accept\n", setGateways6)
	fmt.Fprintf(b, "        ip6 daddr @%s tcp dport 53 accept\n", setGateways6)
	fmt.Fprintf(b, "        ct state invalid %s\n", verdict(p, "-", "state", "invalid"))
	dispatchNICs(b, nics, "iifname", "nic_out_")
	if mode == NICModeEnforce {
		fmt.Fprintf(b, "        meta mark set meta mark | %#x\n", judgedMark)
	}
	fmt.Fprintf(b, "    }\n\n")

	// output: host or routed traffic → guest; routed → another port.
	fmt.Fprintf(b, "    chain output {\n")
	fmt.Fprintf(b, "        type filter hook output priority filter; policy accept;\n")
	if mode == NICModeEnforce {
		fmt.Fprintf(b, "        oifname != @%s meta mark & %#x == %#x jump routed_to_port\n", setNICDevs, deferMark, deferMark)
	}
	fmt.Fprintf(b, "        oifname != @%s accept\n", setNICDevs)
	renderTaggedToNIC(b, p, nics)
	bridgeCommon(b, p)
	// The host's dnsmasq answering DHCP and acting as the IPv6 router.
	fmt.Fprintf(b, "        ip saddr @%s udp sport 67 udp dport 68 accept\n", setGateways4)
	fmt.Fprintf(b, "        ip6 saddr fe80::/10 udp sport 547 udp dport 546 accept\n")
	fmt.Fprintf(b, "        ip6 saddr fe80::/10 ip6 hoplimit 255 icmpv6 type nd-router-advert accept\n")
	// The built-in load balancer's haproxy, on this host, reaching a backend.
	fmt.Fprintf(b, "        ip saddr @%s ip daddr . tcp dport @%s accept\n", setLBSrc4, setLB4)
	fmt.Fprintf(b, "        ct state invalid %s\n", verdict(p, "-", "state", "invalid"))
	dispatchNICs(b, nics, "oifname", "nic_in_")
	fmt.Fprintf(b, "    }\n\n")

	if mode == NICModeEnforce {
		// Routed traffic toward a port that is not a guest NIC (the uplink of
		// a bridge that also carries guests): the tiers and the default
		// policy, as the inet forward chain applies to every other routed
		// packet.
		fmt.Fprintf(b, "    chain routed_to_port {\n")
		for _, rules := range [][]Rule{p.ClusterRules, p.HostRules} {
			for _, r := range rules {
				if r.Action == Reject {
					r.Action = Drop
				}
				for _, line := range renderRules(r, "", v6Sets) {
					fmt.Fprintf(b, "        %s\n", line)
				}
			}
		}
		if p.DefaultDeny {
			fmt.Fprintf(b, "        drop\n")
		}
		fmt.Fprintf(b, "    }\n\n")
	}

	for _, n := range nics {
		renderNICChain(b, p, n, Egress, sgs, v6Sets)
		renderNICChain(b, p, n, Ingress, sgs, v6Sets)
	}
	b.WriteString("}\n")
}

// renderNICTableSets declares the sets the filtering chains use. Sets come
// first: a rule may reference only a set declared before it.
func renderNICTableSets(b *strings.Builder, p Plan, dhcpSrv, gw4, gw6 []string) {
	renderIfnameSet(b, setDHCPSrv, dhcpSrv)
	renderAddrSet(b, setGateways4, "ipv4_addr", gw4)
	renderAddrSet(b, setGateways6, "ipv6_addr", gw6)
	renderIPSets(b, p.IPSets) // sets are per table; the NIC rules reference them here
	var lb4, lbsrc4 []string
	for _, l := range p.LBBackends {
		if a, err := netip.ParseAddr(l.Addr); err == nil && a.Is4() && l.Port > 0 && l.Port < 65536 && lbProto(l) == "tcp" {
			lb4 = append(lb4, fmt.Sprintf("%s . %d", a, l.Port))
		}
	}
	for _, s := range p.LBSources {
		if a, err := netip.ParseAddr(s); err == nil && a.Is4() {
			lbsrc4 = append(lbsrc4, a.String())
		}
	}
	sort.Strings(lb4)
	lb4 = dedupe(lb4)
	fmt.Fprintf(b, "    set %s {\n        type ipv4_addr . inet_service\n", setLB4)
	if len(lb4) > 0 {
		fmt.Fprintf(b, "        elements = { %s }\n", strings.Join(lb4, ", "))
	}
	fmt.Fprintf(b, "    }\n\n")
	renderAddrSet(b, setLBSrc4, "ipv4_addr", lbsrc4)

}

func verdictVLAN(p Plan) string {
	return verdict(p, "-", "vlan", "tagged")
}

// renderTaggedToNIC drops a tagged frame on its way TO a guest NIC that may
// not carry tags (re-review I-1). It comes ahead of bridgeCommon's non-IP
// accept: the kernel holds a frame's outer tag outside the payload, so
// skb->protocol reads as the next header and a tag would otherwise carry the
// frame past the receiver's rules, and the receiver's guest strips it. On a
// vlan_filtering bridge the egress tagging policy has already been applied at
// these hooks, so an access port's untagged VLAN traffic does not match. A
// trunk NIC's own confinement follows (renderTrunkConfine).
func renderTaggedToNIC(b *strings.Builder, p Plan, nics []NICBinding) {
	fmt.Fprintf(b, "        oifname @%s oifname != @%s ether type { 8021q, 8021ad } %s\n", setNICDevs, setVLANOK,
		verdict(p, "-", "vlan", "tagged-to-nic"))
	for _, n := range nics {
		renderTrunkConfine(b, p, n, "oifname", false)
	}
}

// renderTrunkConfine confines a trunk NIC (NICBinding.TrunkVIDs) to single
// 802.1Q tags: no 802.1ad outer tag and no tag inside the tag, either of which
// would carry a payload no rule can see. On the way in it is also confined to
// its own VIDs (the bridge's vlan_filtering does so too; this keeps the rule
// independent of it). In observe mode each is a counter: everything a trunk
// could send before keeps working until enforcement is switched on.
func renderTrunkConfine(b *strings.Builder, p Plan, n NICBinding, word string, vids bool) {
	if n.TrunkDenied && len(n.TrunkVIDs) == 0 {
		// No VLAN of this trunk is allowed: drop its tags in either mode.
		fmt.Fprintf(b, "        %s %s ether type { 8021q, 8021ad } drop\n", word, n.NICDev)
		return
	}
	if len(n.TrunkVIDs) == 0 {
		return
	}
	v := verdict(p, n.NICDev, "vlan", "trunk")
	fmt.Fprintf(b, "        %s %s ether type 8021ad %s\n", word, n.NICDev, v)
	if vids {
		// A VLAN its network does not allow is dropped in either mode: on a
		// bridge that filters no VLANs it would leave through the uplink onto
		// a VLAN the tenant chose (re-review R2-I1).
		ids := append([]int(nil), n.TrunkVIDs...)
		sort.Ints(ids)
		strs := make([]string, 0, len(ids))
		for i, id := range ids {
			if i == 0 || id != ids[i-1] {
				strs = append(strs, fmt.Sprint(id))
			}
		}
		fmt.Fprintf(b, "        %s %s vlan id != { %s } drop\n", word, n.NICDev, strings.Join(strs, ", "))
	}
	fmt.Fprintf(b, "        %s %s vlan type { 8021q, 8021ad } %s\n", word, n.NICDev, v)
}

func lbProto(l LBBackend) string {
	if strings.EqualFold(l.Proto, "udp") {
		return "udp"
	}
	return "tcp"
}

func dedupe(in []string) []string {
	var out []string
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// bridgeCommon opens every filtering chain, after the port scoping: replies
// and related errors of known flows; non-IP frames (ARP and the rest of layer
// 2 are the guard's business, and a "drop all" rule must not cut a guest off
// from address resolution); and the neighbour discovery and MLD a link needs —
// all of it link-scoped (hop limit 255, link-local or multicast addresses), so
// none of it can carry traffic off the link.
func bridgeCommon(b *strings.Builder, p Plan) {
	fmt.Fprintf(b, "        ct state established,related accept\n")
	fmt.Fprintf(b, "        meta protocol != { ip, ip6 } accept\n")
	fmt.Fprintf(b, "        ip6 hoplimit 255 icmpv6 type { nd-router-solicit, nd-neighbor-solicit, nd-neighbor-advert } accept\n")
	fmt.Fprintf(b, "        ip6 saddr { ::, fe80::/10 } ip6 daddr ff00::/8 icmpv6 type { mld-listener-query, mld-listener-report, mld-listener-done, mld2-listener-report } accept\n")
}

func dispatchNICs(b *strings.Builder, nics []NICBinding, word, prefix string) {
	for _, n := range nics {
		fmt.Fprintf(b, "        %s %s jump %s%s\n", word, n.NICDev, prefix, sanitiseChain(n.NICDev))
	}
}

// renderNICChain emits one direction of one NIC's policy: the cluster tier,
// the host tier, each bound security group and the NIC's own rules, in that
// order, first match wins, then the default.
//
// A frame between two guests passes the sender's egress AND the receiver's
// ingress, so an egress accept RETURNS (an accept would end the forward chain
// before the receiver's rules) and an ingress accept accepts. `reject` is
// rendered as drop: the bridge family can reject only at prerouting and
// input, and one reject on the forward or output hook makes the kernel refuse
// the whole table.
func renderNICChain(b *strings.Builder, p Plan, n NICBinding, dir Direction, sgs map[string]SecurityGroup, v6Sets map[string]bool) {
	prefix, side := "nic_in_", "in"
	if dir == Egress {
		prefix, side = "nic_out_", "out"
	}
	fmt.Fprintf(b, "    chain %s%s {\n", prefix, sanitiseChain(n.NICDev))
	observe := p.nicMode() == NICModeObserve
	emit := func(label string, rules []Rule) {
		for i, r := range rules {
			if r.Direction != dir {
				continue
			}
			switch {
			case r.Action == Accept || r.Action == "":
				if dir == Egress {
					r.Action = "return"
				}
			case observe:
				// Count it as the rule that would have dropped the frame,
				// then stop judging this chain — as the drop would have.
				r.Action = "counter return"
				// One comment per rule, at its end: the counter's label.
				r.Comment = fmt.Sprintf("%s %s %s %s#%d", WouldDropComment, n.NICDev, side, label, i)
			default:
				r.Action = Drop // reject included; see above
			}
			for _, line := range renderRules(r, n.NICDev, v6Sets) {
				fmt.Fprintf(b, "        %s\n", line)
			}
		}
	}
	if len(p.ClusterRules) > 0 {
		fmt.Fprintf(b, "        # cluster tier\n")
		emit("cluster", p.ClusterRules)
	}
	if len(p.HostRules) > 0 {
		fmt.Fprintf(b, "        # host tier\n")
		emit("host", p.HostRules)
	}
	for _, name := range n.SecurityGroups {
		sg := sgs[name]
		if sg.Name == "" {
			continue
		}
		fmt.Fprintf(b, "        # security group %q\n", sg.Name)
		emit("sg:"+truncate(sg.Name, 40), sg.Rules)
	}
	emit("nic", n.ExtraRules)
	if p.DefaultDeny {
		fmt.Fprintf(b, "        %s\n", verdict(p, n.NICDev, side, "default"))
	}
	fmt.Fprintf(b, "    }\n\n")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// eui64LinkLocal is the IPv6 link-local address SLAAC derives from mac.
func eui64LinkLocal(mac string) (string, bool) {
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) != 6 {
		return "", false
	}
	var a [16]byte
	a[0], a[1] = 0xfe, 0x80
	a[8] = hw[0] ^ 0x02
	a[9], a[10] = hw[1], hw[2]
	a[11], a[12] = 0xff, 0xfe
	a[13], a[14], a[15] = hw[3], hw[4], hw[5]
	return netip.AddrFrom16(a).String(), true
}

// renderGuardChain emits one guarded NIC's chain. Order matters: the drops of
// things a guest may never send come first, so the DHCP-client accept further
// down can never let a server reply or a spoofed frame through.
//
// A trunk NIC's (or an --allow-vlan-tags NIC's) tagged frames leave the chain
// after the MAC-level checks: the addresses its guest uses on its other VLANs
// are not litevirt's to know, so the address guards hold its untagged (native
// VLAN) traffic only. A trunk's tags were confined by prerouting already
// (renderTrunkConfine); an --allow-vlan-tags NIC has no such confinement, so
// its guard drops doubled tags itself and treats VID 0 as native.
func renderGuardChain(b *strings.Builder, dev string, g NICGuard, vlanOK, trunk bool) {
	mac := strings.ToLower(g.MAC)
	hw, _ := net.ParseMAC(mac)
	macHex := fmt.Sprintf("0x%x", []byte(hw))
	fmt.Fprintf(b, "    chain guard_%s {\n", sanitiseChain(dev))
	fmt.Fprintf(b, "        ether saddr != %s drop\n", mac)
	if trunk || vlanOK {
		// Every frame of a trunk (or of a NIC allowed tags), tagged or not, is
		// held to the guest's own MAC in ARP and neighbour discovery, and may not answer DHCP or
		// advertise a router (re-review R2-I1). These match with no link-layer
		// dependency (raw @nh, meta l4proto, meta protocol), because the kernel
		// holds a single tag outside the frame and nft's ether type then reads
		// the tag. Every ICMPv6 match names `meta protocol ip6` first: in the
		// bridge family a bare `icmpv6` gets an implicit `ether type ip6`, which
		// misses every tagged frame, VID 0 included (lab 1 F3).
		fmt.Fprintf(b, "        meta protocol arp @nh,64,48 != %s drop\n", macHex)
		if !g.AllowDHCPServer {
			fmt.Fprintf(b, "        meta l4proto udp th sport 67 drop\n")
			fmt.Fprintf(b, "        meta l4proto udp th dport 68 drop\n")
			fmt.Fprintf(b, "        meta l4proto udp th sport 547 drop\n")
			fmt.Fprintf(b, "        meta l4proto udp th dport 546 drop\n")
		}
		if !g.AllowRouterAdvert {
			fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type { nd-router-advert, nd-redirect } drop\n")
		}
		fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } @nh,32,16 > 32 drop\n")
		fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type nd-router-solicit @nh,32,16 > 16 drop\n")
		renderNDOptionChecks(b, macHex)
		if trunk {
			// The addresses its guest uses on its other VLANs are not
			// litevirt's to know: the address guards below hold the native
			// VLAN only.
			fmt.Fprintf(b, "        ether type 8021q return\n")
		} else {
			// A NIC allowed tags without the trunk feature (--allow-vlan-tags)
			// is held the same way, with two differences. A doubled tag (an
			// 802.1ad outer tag, or an 802.1Q tag inside the outer one: the
			// kernel's protocol is then 0x8100) hides every header the raw
			// checks above read, so it is dropped, not waved through. And a
			// priority tag (VID 0) is native-VLAN traffic everywhere the
			// frame goes next, so it does not leave here: it falls through to
			// the native address guards, with its ARP sender address (which
			// nft's arp expression cannot read inside a tag) held by a raw match.
			fmt.Fprintf(b, "        ether type 8021ad drop\n")
			fmt.Fprintf(b, "        meta protocol { 8021q, 8021ad } drop\n")
			fmt.Fprintf(b, "        vlan id != 0 return\n")
			if len(g.ExcludeV4) > 0 {
				fmt.Fprintf(b, "        vlan id 0 meta protocol arp @nh,112,32 { %s } drop\n", strings.Join(v4IntSet(g.ExcludeV4), ", "))
			}
			if g.V4 != nil {
				fmt.Fprintf(b, "        vlan id 0 meta protocol arp @nh,112,32 != { %s } drop\n",
					strings.Join(v4IntSet(append([]string{"0.0.0.0"}, g.V4...)), ", "))
			}
		}
	} else {
		// Held here too, so a guarded NIC drops tagged frames in observe mode,
		// where the table-wide VLAN rule only counts.
		fmt.Fprintf(b, "        ether type { 8021q, 8021ad } drop\n")
	}
	fmt.Fprintf(b, "        arp saddr ether != %s drop\n", mac)
	if len(g.ExcludeV4) > 0 {
		fmt.Fprintf(b, "        arp saddr ip { %s } drop\n", strings.Join(collapseSetElements(g.ExcludeV4), ", "))
	}
	if g.V4 != nil {
		// 0.0.0.0 is an ARP probe (RFC 5227), sent before an address is used.
		fmt.Fprintf(b, "        arp saddr ip != { %s } drop\n",
			strings.Join(collapseSetElements(append([]string{"0.0.0.0"}, g.V4...)), ", "))
	}
	if !g.AllowDHCPServer {
		// A DHCP client accepts a reply from any source port, so the server
		// side is refused by where it is going (the client ports) as well as
		// where it says it is from.
		fmt.Fprintf(b, "        ether type ip udp sport 67 drop\n")
		fmt.Fprintf(b, "        ether type ip udp dport 68 drop\n")
		fmt.Fprintf(b, "        ether type ip6 udp sport 547 drop\n")
		fmt.Fprintf(b, "        ether type ip6 udp dport 546 drop\n")
	}
	if !g.AllowRouterAdvert {
		fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type { nd-router-advert, nd-redirect } drop\n")
	}
	if len(g.ExcludeV4) > 0 {
		fmt.Fprintf(b, "        ip saddr { %s } drop\n", strings.Join(collapseSetElements(g.ExcludeV4), ", "))
	}
	if g.V4 != nil {
		fmt.Fprintf(b, "        ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept\n")
		fmt.Fprintf(b, "        ip saddr != { %s } drop\n", strings.Join(collapseSetElements(g.V4), ", "))
	}

	// IPv6. Each ICMPv6 match names `meta protocol ip6` first (see above), so
	// these hold a priority-tagged (VID 0) frame as they hold an untagged one.
	// The guest's link-local addresses are always knowable — the EUI-64
	// one from its MAC, plus any it lists — so they are always held, even when
	// its global addresses are not: the default router is a link-local
	// address, and claiming it is how IPv6 traffic is hijacked.
	ll := append([]string(nil), g.LinkLocal...)
	if eui, ok := eui64LinkLocal(mac); ok {
		ll = append(ll, eui)
	}
	llSet := strings.Join(collapseSetElements(ll), ", ")
	if len(g.ExcludeV6) > 0 {
		fmt.Fprintf(b, "        ip6 saddr { %s } drop\n", strings.Join(collapseSetElements(g.ExcludeV6), ", "))
	}
	fmt.Fprintf(b, "        ip6 saddr fe80::/10 ip6 saddr != { %s } drop\n", llSet)
	fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type nd-neighbor-advert icmpv6 taddr fe80::/10 icmpv6 taddr != { %s } drop\n", llSet)
	if g.V6 != nil {
		own := append(append([]string(nil), g.V6...), ll...)
		fmt.Fprintf(b, "        ip6 saddr != { %s } drop\n",
			strings.Join(collapseSetElements(append([]string{"::"}, own...)), ", "))
		fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type nd-neighbor-advert icmpv6 taddr != { %s } drop\n",
			strings.Join(collapseSetElements(own), ", "))
	}
	// The link-layer address options of solicitations and advertisements must
	// carry the guest's own MAC: they are what a neighbour cache records. The
	// option checked is the first one, where every stack puts it; and there may
	// be no second one, where a stack that skips an unknown first option would
	// find a smuggled address (re-review m-a): a solicitation or advertisement
	// is at most its header (24 bytes) plus one 8-byte option — the link-layer
	// address, or a duplicate-address-detection nonce — and a router
	// solicitation 8 plus one.
	fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } ip6 length > 32 drop\n")
	fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type nd-router-solicit ip6 length > 16 drop\n")
	renderNDOptionChecks(b, macHex)
	fmt.Fprintf(b, "    }\n\n")
}

// renderNDOptionChecks holds the link-layer address option of a guarded
// guest's router and neighbour solicitations and advertisements to its MAC.
func renderNDOptionChecks(b *strings.Builder, macHex string) {
	fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type nd-router-solicit @th,64,16 0x0101 @th,80,48 != %s drop\n", macHex)
	fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type nd-neighbor-solicit @th,192,16 0x0101 @th,208,48 != %s drop\n", macHex)
	fmt.Fprintf(b, "        meta protocol ip6 icmpv6 type nd-neighbor-advert @th,192,16 0x0201 @th,208,48 != %s drop\n", macHex)
}

// v4IntSet renders IPv4 addresses and prefixes as the integers (and integer
// ranges) a raw 32-bit payload match compares with, e.g. 10.0.2.0/24 as
// 0x0a000200-0x0a0002ff. An element that is not IPv4 is skipped.
func v4IntSet(elems []string) []string {
	var out []string
	for _, s := range collapseSetElements(elems) {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			a, aerr := netip.ParseAddr(s)
			if aerr != nil {
				continue
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if !p.Addr().Is4() {
			continue
		}
		p = p.Masked()
		lo := p.Addr().As4()
		first := uint32(lo[0])<<24 | uint32(lo[1])<<16 | uint32(lo[2])<<8 | uint32(lo[3])
		last := first | (^uint32(0) >> uint(p.Bits()))
		if first == last {
			out = append(out, fmt.Sprintf("0x%08x", first))
		} else {
			out = append(out, fmt.Sprintf("0x%08x-0x%08x", first, last))
		}
	}
	return out
}
