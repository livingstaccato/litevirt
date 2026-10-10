// Package firewall is litevirt's distributed firewall. It compiles a
// cluster-wide rule model (security groups + cluster / host / VM tiers)
// into a single atomic nftables ruleset per host and applies it via
// `nft -f -`.
//
// The design choices:
//
//   - One nftables table per host: `inet litevirt-fw`. Replacing the
//     entire table at once keeps rule application atomic — partial
//     state is impossible, so a half-applied ruleset can never leak
//     traffic between tenants.
//   - Three policy tiers, evaluated in order:
//     cluster_default → host overrides → per-VM rules
//     Each tier is a chain attached to `forward`; later tiers can
//     short-circuit with `accept` / `drop`.
//   - Security groups are *named* rule sets. NICs reference them by
//     name; the renderer expands them into chain rules. The schema
//     already in Corrosion (security_groups + sg_rules) becomes the
//     authoritative source.
//   - Stateful conntrack: every chain starts with
//     ct state established,related accept
//     so reply traffic is automatic. Drop policy applies to *new*
//     connections only.
//   - IPsets (named address lists) become nftables `set` objects
//     rendered into the same table.
//
// The package is split:
//
//	firewall.go (this file): types + renderer (pure function).
//	applier.go: nft binary shell-out + atomic load.
//	reconciler.go: watches Corrosion sg/sg_rules tables and re-applies.
package firewall

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
)

// TableName is the single nftables table litevirt owns. Every chain we
// emit lives here so `nft list table inet litevirt-fw` shows the entire
// litevirt-managed surface.
const TableName = "litevirt-fw"

// NICTableName is the bridge-family table that enforces every per-NIC policy:
// the NIC guards (anti-spoofing) and the per-NIC rules (cluster, host and
// security-group tiers plus the default policy, applied to each NIC). It is
// replaced in the same `nft -f` transaction as TableName.
//
// WHY THE BRIDGE FAMILY. A guest's tap is a port of a Linux bridge, so two
// guests on one bridge talk at layer 2: their frames never reach the inet
// forward hook, and with br_netfilter loaded that hook sees the bridge, not
// the tap, as iif/oif. A rule matching the tap there never matches. The bridge
// family's forward, input and output hooks see every frame a port sends or
// receives, with the tap as iifname/oifname: guest to guest (forward), guest
// to the host or to anything the host routes to (input), and the host or
// routed traffic to the guest (output). It needs no br_netfilter. Replies are
// recognised by nf_conntrack_bridge (EnsureBridgeConntrack).
const NICTableName = "litevirt-nic"

// ipv6SetSuffix names the ipv6_addr companion of a named ip set that holds
// IPv6 elements: nft sets are typed, so one name cannot hold both families.
const ipv6SetSuffix = "_v6"

// Direction selects which side of a NIC a rule applies to. The
// semantics match Proxmox / AWS / GCP / OpenStack:
//
//	Ingress = traffic ARRIVING at the VM. In netfilter's forward
//	          chain a packet headed "into" a libvirt tap is matched
//	          with oifname=tap. Restrict who can CONNECT TO this VM.
//	Egress  = traffic LEAVING the VM. iifname=tap. Restrict where
//	          the VM can CONNECT TO.
//
// Note: the legacy internal/network/acl.go inverted these mappings; the
// new firewall package follows the cloud-vendor convention so a user
// writing `direction: ingress, port: 22, action: accept` gets the
// behaviour they expect: SSH from outside is accepted.
type Direction string

const (
	Ingress Direction = "ingress" // matches oifname=<tap> in forward chain
	Egress  Direction = "egress"  // matches iifname=<tap> in forward chain
)

// Action is the verdict at the end of a matched rule.
type Action string

const (
	Accept Action = "accept"
	Drop   Action = "drop"
	Reject Action = "reject" // sends an ICMP unreachable; useful for friendlier UX
)

// Tier is which of the three policy planes a rule belongs to.
// Cluster rules apply to every NIC; host rules apply to every NIC on
// one host; VM rules apply to one NIC. Higher-priority tiers may
// short-circuit lower ones with explicit accept/drop.
type Tier string

const (
	TierCluster Tier = "cluster"
	TierHost    Tier = "host"
	TierVM      Tier = "vm"
)

// Rule is a single firewall rule, normalised across the three tiers.
// SGRule (corrosion) and ACLRule (network/acl.go) both convert to this.
type Rule struct {
	Direction Direction
	Proto     string // "tcp" | "udp" | "icmp" | "all"
	PortRange string // "80" | "8000-9000" | ""
	CIDR      string // "10.0.0.0/24" | "" (any) | "@<ipset-name>"
	Action    Action
	Comment   string // human-readable; emitted as `# …` on the rule line
}

// SecurityGroup is a named set of Rules. NICs reference SGs by name;
// the renderer expands references into rule chains. Names are unique
// within a Plan: CorrosionPlanLoader leaves out every name that more than
// one live group holds and holds the NICs bound to it at drop, and the
// daemon refuses to create a second live group under a held name.
type SecurityGroup struct {
	Name  string
	Rules []Rule
}

// IPSet is a named CIDR list, rendered as an nftables `set` object.
// Rules can reference one with CIDR="@<set-name>" — typed-aliased
// CIDR lists make rule files dramatically smaller.
type IPSet struct {
	Name  string
	CIDRs []string
}

// NATRule is one postrouting NAT rule. SNATTo distinguishes the two forms:
//   - SNATTo == "" → masquerade for a managed subnet's guest egress:
//     `ip saddr <Subnet> oifname != <Bridge> masquerade`
//   - SNATTo != "" → source-NAT to a fixed address (LB VIP for an isolated net):
//     `oifname <OutIface> ip saddr <Subnet> snat to <SNATTo>`
//
// These fold in the old out-of-band paths: iptables MASQUERADE (network.EnsureNAT)
// and the nft snat chain (network.EnsureSNAT).
type NATRule struct {
	Subnet   string // ip saddr match (required)
	Bridge   string // masquerade: oifname != Bridge (egress leaves via any iface but this bridge)
	OutIface string // SNAT: oifname == OutIface
	SNATTo   string // SNAT target; empty → masquerade
}

// IsolationException lists VIP ports punched through a bridge's host-isolation
// drop so guests can still reach an HAProxy VIP (plus VRRP for keepalived).
type IsolationException struct {
	VIP   string
	Ports []int
}

// IsolationChain makes the host invisible to guests on Bridge: every packet
// arriving from the bridge at the host (input hook) is dropped, except the
// optional LB exceptions. Folds in network.EnsureHostIsolation.
type IsolationChain struct {
	Bridge     string
	Exceptions []IsolationException
}

// NICBinding attaches one VM NIC to zero or more security groups, plus
// any per-NIC rules layered on top. The NICDev string is the host-side
// device name (tap-… or veth…); it's the iifname/oifname token the
// renderer matches on.
type NICBinding struct {
	NICDev         string
	VMName         string
	SecurityGroups []string // SG names, resolved via Plan.SecurityGroups
	ExtraRules     []Rule   // per-VM rules layered after SG rules

	// Bridge is the bridge the NIC's device is a port of, when known. Routed
	// traffic to or from it is left to the bridge table's per-NIC decision
	// instead of being judged a second time in the inet forward chain.
	Bridge string

	// Guard, when non-nil, holds the NIC to its own identity on the wire:
	// see NICGuard. nil leaves the NIC unguarded, as every NIC was before
	// guards existed.
	Guard *NICGuard
}

// NICGuard is a NIC's anti-spoofing policy, enforced in the bridge family at
// prerouting so it sees every frame the guest sends — to another guest on the
// same bridge, out the uplink, or to the host — before anything else does.
//
// A guarded NIC may only send frames from MAC, may not send VLAN-tagged frames
// itself (their payload could not be checked), may not answer DHCP or send
// router advertisements and redirects unless allowed, and may only claim its
// own addresses in ARP and in neighbour advertisements.
//
// V4 and V6 restrict the source address of each family. nil means litevirt
// knows no address space for that family on this NIC, and leaves its source
// address unrestricted rather than cutting the guest off: a guest on a plain
// bridge served by an upstream DHCP server or router has addresses nobody
// told litevirt about. A restricted IPv6 family always allows link-local
// sources and the unspecified address (duplicate address detection); a
// restricted IPv4 family always lets a DHCP client ask for an address.
type NICGuard struct {
	MAC               string
	V4                []string // addresses / prefixes; nil = unrestricted
	V6                []string // addresses / prefixes; nil = unrestricted
	AllowDHCPServer   bool
	AllowRouterAdvert bool
}

// Plan is the input to the renderer — the *complete* desired state
// for one host. Apply replaces the host's table atomically with the
// renderer's output, so anything missing from a Plan is removed.
//
// Three-tier rules show up here as three slices. Within each tier,
// rules apply in array order (the first match wins, except for
// accept-then-fall-through semantics enforced by the renderer).
type Plan struct {
	// DefaultDeny, when true, drops any packet that no rule matched.
	// When false the policy is accept (a "logging-only" mode useful
	// during rollout).
	DefaultDeny bool

	ClusterRules []Rule
	HostRules    []Rule

	SecurityGroups []SecurityGroup
	IPSets         []IPSet
	NICs           []NICBinding

	// NAT (postrouting masquerade + SNAT) and HostIsolation (input drops) are
	// per-host infra rules folded in from the old out-of-band paths. They render
	// into their own hook chains in the same table, so the atomic replace keeps
	// them in lockstep with the filter rules.
	NAT           []NATRule
	HostIsolation []IsolationChain
}

// Render turns the Plan into an nftables ruleset that can be fed to
// `nft -f -`. The output is deterministic — identical Plan ⇒ identical
// bytes — so apply can short-circuit when nothing changed.
func Render(p Plan) (string, error) {
	if err := validate(p); err != nil {
		return "", err
	}
	sgByName := map[string]SecurityGroup{}
	for _, sg := range p.SecurityGroups {
		sgByName[sg.Name] = sg
	}
	for _, n := range p.NICs {
		for _, name := range n.SecurityGroups {
			if _, ok := sgByName[name]; !ok {
				return "", fmt.Errorf("NIC %q references unknown security group %q", n.NICDev, name)
			}
		}
	}

	var b strings.Builder
	b.WriteString("# Generated by litevirt firewall renderer — do not edit by hand.\n")
	b.WriteString("# `nft -f -` consumes this file as an atomic ruleset replace.\n\n")

	// We emit the table block as a self-contained unit. `nft -f -`
	// treats this as an atomic replace of the litevirt-fw table.
	//
	// IMPORTANT: do NOT close the brace via `defer` — strings.Builder.String()
	// snapshots the length at call time, and a deferred WriteString
	// happens *after* return value evaluation, so the brace would be
	// written into the underlying buffer but never appear in the
	// returned string. Always close before returning.
	fmt.Fprintf(&b, "table inet %s {\n", TableName)

	// IP sets first; chains may reference them.
	renderIPSets(&b, p.IPSets)

	nicTable := needsNICTable(p)

	// One forward chain hooks to the netfilter forward path. It filters
	// routed traffic that involves no guest NIC; a guest's traffic is
	// decided per NIC in the bridge table (NICTableName).
	defaultPolicy := "accept"
	if p.DefaultDeny {
		defaultPolicy = "drop"
	}
	fmt.Fprintf(&b, "    chain forward {\n")
	fmt.Fprintf(&b, "        type filter hook forward priority filter; policy %s;\n", defaultPolicy)
	// Stateful conntrack — reply traffic is always allowed. Putting it
	// at the head of the forward chain means we never re-evaluate per-
	// connection-state for established flows.
	fmt.Fprintf(&b, "        ct state established,related accept\n")
	// IPv6 does not work without these, and conntrack does not track
	// neighbour discovery or MLD, so they are accepted before the invalid
	// drop and before any tier can refuse them. Redirects are not essential
	// and are left to the rules. Guests are kept from SENDING router
	// advertisements by their NIC guard, which runs before this hook.
	fmt.Fprintf(&b, "        icmpv6 type { %s } accept\n", strings.Join(icmpv6Essentials, ", "))
	fmt.Fprintf(&b, "        ct state invalid drop\n")
	if nicTable {
		// Routed traffic to or from a bridge with guest NICs on it was
		// already decided per NIC in the bridge table: on its way in at the
		// bridge input hook, on its way out at the bridge output hook. Judging
		// it again here against the default policy would drop what a NIC's
		// rules allowed.
		if brs := nicBridges(p.NICs); len(brs) > 0 {
			quoted := make([]string, len(brs))
			for i, br := range brs {
				quoted[i] = `"` + br + `"`
			}
			fmt.Fprintf(&b, "        iifname { %s } accept\n", strings.Join(quoted, ", "))
			fmt.Fprintf(&b, "        oifname { %s } accept\n", strings.Join(quoted, ", "))
		}
	}
	// Jump tier-by-tier. Cluster rules run first because they describe
	// blanket policy (e.g. "block egress to RFC1918 from public VLAN").
	fmt.Fprintf(&b, "        jump cluster_default\n")
	fmt.Fprintf(&b, "        jump host_overrides\n")
	fmt.Fprintf(&b, "    }\n\n")

	v6Sets := setsWithIPv6(p.IPSets)
	renderTierChain(&b, "cluster_default", p.ClusterRules, v6Sets)
	renderTierChain(&b, "host_overrides", p.HostRules, v6Sets)

	// Infra chains on their own hooks. Emitted only when non-empty so a plan with
	// no NAT / isolation renders byte-identically to before this feature (and so
	// removing the last rule drops the whole chain on the next atomic replace).
	renderNAT(&b, p.NAT)
	renderHostIsolation(&b, p.HostIsolation)

	b.WriteString("}\n")
	if nicTable {
		renderNICTable(&b, p, sgByName, v6Sets)
	}
	return b.String(), nil
}

// needsNICTable reports whether any guest NIC has a policy to enforce. When
// none has — no guard, no rule of any tier, the default policy accept — no
// bridge table is rendered, so such a host never depends on nf_tables bridge
// support.
func needsNICTable(p Plan) bool {
	if len(p.NICs) == 0 {
		return false
	}
	if p.DefaultDeny || len(p.ClusterRules) > 0 || len(p.HostRules) > 0 {
		return true
	}
	for _, n := range p.NICs {
		if n.Guard != nil || len(n.SecurityGroups) > 0 || len(n.ExtraRules) > 0 {
			return true
		}
	}
	return false
}

// nicBridges is every bridge a guest NIC in the plan is a port of, sorted.
func nicBridges(nics []NICBinding) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range nics {
		if n.Bridge != "" && !seen[n.Bridge] {
			seen[n.Bridge] = true
			out = append(out, n.Bridge)
		}
	}
	sort.Strings(out)
	return out
}

// icmpv6Essentials are the ICMPv6 types IPv6 needs to work at all: the errors
// path-MTU discovery and diagnostics depend on, MLD, and neighbour/router
// discovery.
var icmpv6Essentials = []string{
	"destination-unreachable", "packet-too-big", "time-exceeded", "parameter-problem",
	"mld-listener-query", "mld-listener-report", "mld-listener-done",
	"nd-router-solicit", "nd-router-advert", "nd-neighbor-solicit", "nd-neighbor-advert",
	"mld2-listener-report",
}

// bridgePreamble opens every filtering chain of the bridge table.
//
// Only IP and IPv6 frames are judged by the rules: ARP and the rest of layer 2
// are the NIC guard's business (in prerouting, ahead of this), and a rule like
// "drop all ingress" must not cut a guest off from address resolution. DHCP
// and the ICMPv6 a network needs are accepted before any rule, as they always
// were for traffic to the host: a guest must be able to get an address and
// find its neighbours under a default-deny policy. A guest that is not allowed
// to ANSWER DHCP or advertise itself as a router is held to that by its guard.
func bridgePreamble(b *strings.Builder) {
	fmt.Fprintf(b, "        ct state established,related accept\n")
	fmt.Fprintf(b, "        meta protocol != { ip, ip6 } accept\n")
	fmt.Fprintf(b, "        icmpv6 type { %s } accept\n", strings.Join(icmpv6Essentials, ", "))
	fmt.Fprintf(b, "        udp sport 68 udp dport 67 accept\n")
	fmt.Fprintf(b, "        udp sport 67 udp dport 68 accept\n")
	fmt.Fprintf(b, "        udp sport 546 udp dport 547 accept\n")
	fmt.Fprintf(b, "        udp sport 547 udp dport 546 accept\n")
	fmt.Fprintf(b, "        ct state invalid drop\n")
}

// renderNICTable emits the bridge table that enforces every per-NIC policy.
//
// Each NIC has two chains. nic_out_<dev> holds what the guest may SEND (the
// egress rules of every tier) and is entered where a frame arrives from the
// tap: the forward hook (to another port) and the input hook (to the host, or
// to be routed). nic_in_<dev> holds what the guest may RECEIVE (the ingress
// rules) and is entered where a frame leaves through the tap: the forward hook
// and the output hook (from the host, or routed to it).
//
// A frame between two guests on one bridge passes the sender's egress AND the
// receiver's ingress. So an egress accept RETURNS rather than accepts — an
// accept would end the forward chain and skip the receiver's rules — and an
// ingress accept accepts. Each chain ends in drop under a default-deny policy;
// with no default-deny a frame no rule matched passes.
func renderNICTable(b *strings.Builder, p Plan, sgs map[string]SecurityGroup, v6Sets map[string]bool) {
	nics := make([]NICBinding, len(p.NICs))
	copy(nics, p.NICs)
	sort.Slice(nics, func(i, j int) bool { return nics[i].NICDev < nics[j].NICDev })

	fmt.Fprintf(b, "\ntable bridge %s {\n", NICTableName)
	renderIPSets(b, p.IPSets) // sets are per table; the NIC rules reference them here

	var guarded []NICBinding
	for _, n := range nics {
		if n.Guard != nil {
			guarded = append(guarded, n)
		}
	}
	if len(guarded) > 0 {
		fmt.Fprintf(b, "    chain prerouting {\n")
		// -300: ahead of every other bridge hook, conntrack included.
		fmt.Fprintf(b, "        type filter hook prerouting priority -300; policy accept;\n")
		for _, n := range guarded {
			fmt.Fprintf(b, "        iifname %s jump guard_%s\n", n.NICDev, sanitiseChain(n.NICDev))
		}
		fmt.Fprintf(b, "    }\n\n")
	}

	dispatch := func(word, prefix string) {
		for _, n := range nics {
			fmt.Fprintf(b, "        %s %s jump %s%s\n", word, n.NICDev, prefix, sanitiseChain(n.NICDev))
		}
	}
	for _, hook := range []string{"forward", "input", "output"} {
		fmt.Fprintf(b, "    chain %s {\n", hook)
		fmt.Fprintf(b, "        type filter hook %s priority filter; policy accept;\n", hook)
		bridgePreamble(b)
		if hook != "output" {
			dispatch("iifname", "nic_out_")
		}
		if hook != "input" {
			dispatch("oifname", "nic_in_")
		}
		fmt.Fprintf(b, "    }\n\n")
	}

	for _, n := range guarded {
		renderGuardChain(b, n.NICDev, *n.Guard)
	}
	for _, n := range nics {
		renderNICChain(b, p, n, Egress, sgs, v6Sets)
		renderNICChain(b, p, n, Ingress, sgs, v6Sets)
	}
	b.WriteString("}\n")
}

// renderNICChain emits one direction of one NIC's policy: the cluster tier,
// the host tier, each bound security group and the NIC's own rules, in that
// order, first match wins, then the default.
func renderNICChain(b *strings.Builder, p Plan, n NICBinding, dir Direction, sgs map[string]SecurityGroup, v6Sets map[string]bool) {
	prefix := "nic_in_"
	if dir == Egress {
		prefix = "nic_out_"
	}
	fmt.Fprintf(b, "    chain %s%s {\n", prefix, sanitiseChain(n.NICDev))
	emit := func(rules []Rule) {
		for _, r := range rules {
			if r.Direction != dir {
				continue
			}
			if dir == Egress && (r.Action == Accept || r.Action == "") {
				// Sending is allowed: go on to the receiver's ingress
				// rules rather than end the base chain here.
				r.Action = "return"
			}
			for _, line := range renderRules(r, n.NICDev, v6Sets) {
				fmt.Fprintf(b, "        %s\n", line)
			}
		}
	}
	if len(p.ClusterRules) > 0 {
		fmt.Fprintf(b, "        # cluster tier\n")
		emit(p.ClusterRules)
	}
	if len(p.HostRules) > 0 {
		fmt.Fprintf(b, "        # host tier\n")
		emit(p.HostRules)
	}
	for _, name := range n.SecurityGroups {
		sg := sgs[name]
		if sg.Name == "" {
			continue
		}
		fmt.Fprintf(b, "        # security group %q\n", sg.Name)
		emit(sg.Rules)
	}
	emit(n.ExtraRules)
	if p.DefaultDeny {
		fmt.Fprintf(b, "        drop\n")
	}
	fmt.Fprintf(b, "    }\n\n")
}

// renderGuardChain emits one guarded NIC's chain. Order matters: the drops of
// things a guest may never send come first, so the DHCP-client accept further
// down can never let a server reply or a spoofed frame through.
func renderGuardChain(b *strings.Builder, dev string, g NICGuard) {
	mac := strings.ToLower(g.MAC)
	fmt.Fprintf(b, "    chain guard_%s {\n", sanitiseChain(dev))
	fmt.Fprintf(b, "        ether saddr != %s drop\n", mac)
	fmt.Fprintf(b, "        ether type { 8021q, 8021ad } drop\n")
	fmt.Fprintf(b, "        arp saddr ether != %s drop\n", mac)
	if g.V4 != nil {
		// 0.0.0.0 is an ARP probe (RFC 5227), sent before an address is used.
		fmt.Fprintf(b, "        arp saddr ip != { %s } drop\n",
			strings.Join(collapseSetElements(append([]string{"0.0.0.0"}, g.V4...)), ", "))
	}
	if !g.AllowDHCPServer {
		fmt.Fprintf(b, "        ether type ip udp sport 67 drop\n")
		fmt.Fprintf(b, "        ether type ip6 udp sport 547 drop\n")
	}
	if !g.AllowRouterAdvert {
		fmt.Fprintf(b, "        icmpv6 type { nd-router-advert, nd-redirect } drop\n")
	}
	if g.V4 != nil {
		fmt.Fprintf(b, "        ip saddr 0.0.0.0 ip daddr 255.255.255.255 udp sport 68 udp dport 67 accept\n")
		fmt.Fprintf(b, "        ip saddr != { %s } drop\n", strings.Join(collapseSetElements(g.V4), ", "))
	}
	if g.V6 != nil {
		own := append(append([]string(nil), g.V6...), "fe80::/10")
		fmt.Fprintf(b, "        ip6 saddr != { %s } drop\n",
			strings.Join(collapseSetElements(append([]string{"::"}, own...)), ", "))
		fmt.Fprintf(b, "        icmpv6 type nd-neighbor-advert icmpv6 taddr != { %s } drop\n",
			strings.Join(collapseSetElements(own), ", "))
	}
	fmt.Fprintf(b, "    }\n\n")
}

// renderNAT emits a single `postrouting` nat chain covering masquerade (managed
// guest egress) and SNAT (LB VIP source rewrite). SNAT rules are emitted before
// masquerade — more specific first — and each group is sorted for byte-determinism.
func renderNAT(b *strings.Builder, rules []NATRule) {
	if len(rules) == 0 {
		return
	}
	var snat, masq []NATRule
	for _, r := range rules {
		if r.SNATTo != "" {
			snat = append(snat, r)
		} else {
			masq = append(masq, r)
		}
	}
	sort.Slice(snat, func(i, j int) bool {
		if snat[i].OutIface != snat[j].OutIface {
			return snat[i].OutIface < snat[j].OutIface
		}
		if snat[i].Subnet != snat[j].Subnet {
			return snat[i].Subnet < snat[j].Subnet
		}
		return snat[i].SNATTo < snat[j].SNATTo
	})
	sort.Slice(masq, func(i, j int) bool {
		if masq[i].Subnet != masq[j].Subnet {
			return masq[i].Subnet < masq[j].Subnet
		}
		return masq[i].Bridge < masq[j].Bridge
	})

	fmt.Fprintf(b, "    chain postrouting {\n")
	fmt.Fprintf(b, "        type nat hook postrouting priority srcnat; policy accept;\n")
	for _, r := range snat {
		fmt.Fprintf(b, "        oifname %s ip saddr %s snat to %s\n", r.OutIface, r.Subnet, r.SNATTo)
	}
	for _, r := range masq {
		fmt.Fprintf(b, "        ip saddr %s oifname != %s masquerade\n", r.Subnet, r.Bridge)
	}
	fmt.Fprintf(b, "    }\n\n")
}

// renderHostIsolation emits a single `input` filter chain that drops guest→host
// traffic per isolated bridge, punching through VRRP + declared LB VIP ports
// first. Policy is accept — only the explicit iifname-<bridge> drops bite, so
// non-isolated bridges and host-local traffic are untouched.
func renderHostIsolation(b *strings.Builder, chains []IsolationChain) {
	if len(chains) == 0 {
		return
	}
	sorted := make([]IsolationChain, len(chains))
	copy(sorted, chains)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Bridge < sorted[j].Bridge })

	fmt.Fprintf(b, "    chain input {\n")
	fmt.Fprintf(b, "        type filter hook input priority filter; policy accept;\n")
	for _, c := range sorted {
		if len(c.Exceptions) > 0 {
			// VRRP (keepalived) once per bridge, then each VIP:port.
			fmt.Fprintf(b, "        iifname %s ip protocol 112 accept\n", c.Bridge)
			for _, exc := range c.Exceptions {
				for _, port := range exc.Ports {
					fmt.Fprintf(b, "        iifname %s ip daddr %s tcp dport %d accept\n", c.Bridge, exc.VIP, port)
				}
			}
		}
		fmt.Fprintf(b, "        iifname %s drop\n", c.Bridge)
	}
	fmt.Fprintf(b, "    }\n\n")
}

// renderIPSets writes one `set <name> { … }` block per set NAME.
// nftables sets are typed; we use ipv4_addr with the `interval` flag
// so CIDRs work natively.
//
// Several live rows can share a name: ip_sets is keyed by a random id with no
// UNIQUE on name, and two stacks may each declare the same set. nft merges
// repeated declarations of one set into their union, so the union is what a
// duplicate already meant whenever the ruleset applied; rendering it as one
// block makes that explicit and independent of row order (#218).
func renderIPSets(b *strings.Builder, sets []IPSet) {
	if len(sets) == 0 {
		return
	}
	byName := mergeIPSets(sets)
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	// Stable order so the rendered output is byte-deterministic.
	sort.Strings(names)

	for _, name := range names {
		v4, v6 := splitFamilies(byName[name])
		fmt.Fprintf(b, "    set %s {\n", name)
		fmt.Fprintf(b, "        type ipv4_addr\n")
		fmt.Fprintf(b, "        flags interval\n")
		if cidrs := collapseSetElements(v4); len(cidrs) > 0 {
			fmt.Fprintf(b, "        elements = { %s }\n", strings.Join(cidrs, ", "))
		}
		fmt.Fprintf(b, "    }\n\n")
		if len(v6) == 0 {
			continue
		}
		// The IPv6 members live in a typed companion; a rule referencing the
		// set renders one line per family (renderRules).
		fmt.Fprintf(b, "    set %s%s {\n", name, ipv6SetSuffix)
		fmt.Fprintf(b, "        type ipv6_addr\n")
		fmt.Fprintf(b, "        flags interval\n")
		fmt.Fprintf(b, "        elements = { %s }\n", strings.Join(collapseSetElements(v6), ", "))
		fmt.Fprintf(b, "    }\n\n")
	}
}

// mergeIPSets unions the elements of every set row by name.
func mergeIPSets(sets []IPSet) map[string][]string {
	byName := map[string][]string{}
	for _, s := range sets {
		byName[s.Name] = append(byName[s.Name], s.CIDRs...)
	}
	return byName
}

// splitFamilies separates IPv6 elements from the rest. Anything without a
// colon stays with IPv4, as every element did before IPv6 sets existed.
func splitFamilies(elems []string) (v4, v6 []string) {
	for _, e := range elems {
		if isIPv6Literal(e) {
			v6 = append(v6, e)
		} else {
			v4 = append(v4, e)
		}
	}
	return v4, v6
}

// isIPv6Literal reports whether s is written as an IPv6 address or prefix.
// A set reference ("@name") is not.
func isIPv6Literal(s string) bool {
	return !strings.HasPrefix(s, "@") && strings.Contains(s, ":")
}

// collapseSetElements returns the elements sorted, with duplicates removed and
// with every prefix that another element already covers dropped.
//
// An interval set refuses overlapping elements ("conflicting intervals
// specified"), and since the ruleset loads as one transaction that refusal
// stops the whole firewall from applying. Two IPv4 prefixes either nest or are
// disjoint, so dropping the covered ones removes every conflict without
// changing what the set matches. An element that does not parse is kept
// verbatim and never used to drop another: the renderer does not second-guess
// input it cannot read.
func collapseSetElements(in []string) []string {
	type elem struct {
		s  string
		p  netip.Prefix
		ok bool
	}
	elems := make([]elem, 0, len(in))
	for _, s := range in {
		e := elem{s: s}
		if p, err := netip.ParsePrefix(s); err == nil {
			e.p, e.ok = p.Masked(), true
		} else if a, err := netip.ParseAddr(s); err == nil {
			e.p, e.ok = netip.PrefixFrom(a, a.BitLen()), true
		}
		elems = append(elems, e)
	}
	seen := map[string]bool{}
	var out []string
	for i, e := range elems {
		if seen[e.s] {
			continue
		}
		covered := false
		for j, o := range elems {
			if i == j || !e.ok || !o.ok || o.s == e.s {
				continue
			}
			if o.p.Bits() < e.p.Bits() && o.p.Contains(e.p.Addr()) {
				covered = true // strictly inside a wider element
				break
			}
			if o.p == e.p && o.s < e.s {
				covered = true // the same interval spelled differently; keep one
				break
			}
		}
		if covered {
			continue
		}
		seen[e.s] = true
		out = append(out, e.s)
	}
	sort.Strings(out)
	return out
}

// renderTierChain emits a chain whose rules apply to every packet
// entering it (cluster + host tiers don't filter by NIC). The chain
// name is the tier name.
func renderTierChain(b *strings.Builder, name string, rules []Rule, v6Sets map[string]bool) {
	fmt.Fprintf(b, "    chain %s {\n", name)
	for _, r := range rules {
		for _, line := range renderRules(r, "", v6Sets) {
			fmt.Fprintf(b, "        %s\n", line)
		}
	}
	fmt.Fprintf(b, "    }\n\n")
}

// setsWithIPv6 names the ip sets that hold at least one IPv6 element, so
// have an ipv6_addr companion.
func setsWithIPv6(sets []IPSet) map[string]bool {
	out := map[string]bool{}
	for name, elems := range mergeIPSets(sets) {
		if _, v6 := splitFamilies(elems); len(v6) > 0 {
			out[name] = true
		}
	}
	return out
}

// ruleFamily is the address family a rule's protocol pins it to: "ip" for
// icmp, "ip6" for icmpv6, "" for a protocol that exists in both.
func ruleFamily(proto string) string {
	switch strings.ToLower(proto) {
	case "icmp":
		return "ip"
	case "icmpv6", "ipv6-icmp":
		return "ip6"
	}
	return ""
}

// renderRules renders one rule as the nft lines that implement it. That is
// one line, except for a rule referencing a set that holds IPv6 elements: nft
// sets are typed, so it becomes one line per family, either of which matches.
// A family the rule's protocol excludes gets no line.
func renderRules(r Rule, nicDev string, v6Sets map[string]bool) []string {
	if !strings.HasPrefix(r.CIDR, "@") || !v6Sets[strings.TrimPrefix(r.CIDR, "@")] {
		return []string{renderRule(r, nicDev, "")}
	}
	var out []string
	if ruleFamily(r.Proto) != "ip6" {
		out = append(out, renderRule(r, nicDev, "ip"))
	}
	if ruleFamily(r.Proto) != "ip" {
		r6 := r
		r6.CIDR = r.CIDR + ipv6SetSuffix
		out = append(out, renderRule(r6, nicDev, "ip6"))
	}
	return out
}

// renderRule builds one nftables rule line. iifname/oifname is added
// only when nicDev is non-empty (cluster/host tiers don't filter by NIC).
// family forces the address matcher ("ip" / "ip6") for a set reference;
// empty derives it from the CIDR, and an IPv4 rule renders exactly as it did
// before IPv6 support.
func renderRule(r Rule, nicDev, family string) string {
	var parts []string

	if nicDev != "" {
		// Proxmox / cloud-vendor convention:
		//   Ingress (traffic arriving at the VM) → packet is leaving the
		//     forward chain via the VM's tap → oifname.
		//   Egress  (traffic leaving the VM) → packet entered the forward
		//     chain via the VM's tap → iifname.
		if r.Direction == Egress {
			parts = append(parts, "iifname", nicDev)
		} else {
			parts = append(parts, "oifname", nicDev)
		}
	}

	if family == "" {
		family = "ip"
		if isIPv6Literal(r.CIDR) {
			family = "ip6"
		}
	}

	switch proto := strings.ToLower(r.Proto); proto {
	case "tcp", "udp":
		parts = append(parts, proto)
		if r.PortRange != "" {
			// Port semantics flip with the direction the rule was
			// expressed in by the operator:
			//   Ingress: dport (the destination port on the VM)
			//   Egress:  dport too (the destination port at the remote)
			// Both are dport — sport is rarely what a security group
			// wants. nftables port-range syntax is N-M; pass through.
			parts = append(parts, "dport", r.PortRange)
		}
	case "icmp":
		parts = append(parts, "ip", "protocol", "icmp")
	case "icmpv6", "ipv6-icmp":
		parts = append(parts, "meta", "l4proto", "ipv6-icmp")
	case "", "all":
		// no proto filter
	default:
		if r.CIDR != "" && family == "ip6" {
			// `ip protocol` beside `ip6 saddr` names two network protocols,
			// which nft refuses; meta l4proto is family-neutral.
			parts = append(parts, "meta", "l4proto", proto)
		} else {
			parts = append(parts, "ip", "protocol", proto)
		}
	}

	if r.CIDR != "" {
		// CIDR direction:
		//   Ingress: saddr — restrict WHO can talk to the VM
		//   Egress:  daddr — restrict WHERE the VM can talk to
		addrWord := "saddr"
		if r.Direction == Egress {
			addrWord = "daddr"
		}
		// "@name" is the nftables set-reference syntax. Preserve verbatim.
		parts = append(parts, family, addrWord, r.CIDR)
	}

	action := r.Action
	if action == "" {
		action = Accept
	}
	parts = append(parts, string(action))

	out := strings.Join(parts, " ")
	if r.Comment != "" {
		out += fmt.Sprintf(" comment %q", r.Comment)
	}
	return out
}

// sanitiseChain produces a chain-name-safe variant of a NIC device
// name. nftables identifiers can be alphanumeric + underscore; tap
// names already meet that, but veth names with dashes need swapping.
func sanitiseChain(nicDev string) string {
	r := strings.NewReplacer("-", "_", ".", "_")
	return r.Replace(nicDev)
}

// validate catches the classes of misconfigurations the renderer can't
// safely round-trip.
func validate(p Plan) error {
	ipsets := map[string]bool{}
	for _, ipset := range p.IPSets {
		if ipset.Name == "" {
			return errors.New("ipset with empty name")
		}
		ipsets[ipset.Name] = true
		for _, cidr := range ipset.CIDRs {
			if isIPv6Literal(cidr) && !validAddrOrPrefix(cidr, true) {
				return fmt.Errorf("ipset %q: %q is not an IPv6 address or prefix", ipset.Name, cidr)
			}
		}
	}
	// An IPv6 companion named like a declared set would make nft refuse the
	// whole ruleset ("set exists").
	for name := range setsWithIPv6(p.IPSets) {
		if ipsets[name+ipv6SetSuffix] {
			return fmt.Errorf("ipset %q holds IPv6 elements, whose set is named %q, but a set of that name is also declared; rename one",
				name, name+ipv6SetSuffix)
		}
	}

	for i, r := range allRules(p) {
		switch r.Direction {
		case Ingress, Egress:
		default:
			return fmt.Errorf("rule %d: direction %q must be ingress or egress", i, r.Direction)
		}
		switch r.Action {
		case "", Accept, Drop, Reject:
		default:
			return fmt.Errorf("rule %d: action %q not supported (accept|drop|reject)", i, r.Action)
		}
		// An IPv6 CIDR renders with the ip6 matcher. A malformed one, or one
		// paired with IPv4's icmp (or an IPv4 CIDR with icmpv6), would emit a
		// line nft refuses, poisoning the whole atomic ruleset — so refuse it
		// here. IPv4 CIDRs are passed through as they always were.
		if isIPv6Literal(r.CIDR) {
			if !validAddrOrPrefix(r.CIDR, true) {
				return fmt.Errorf("rule %d: %q is not an IPv6 address or prefix", i, r.CIDR)
			}
			if ruleFamily(r.Proto) == "ip" {
				return fmt.Errorf("rule %d: proto %q is IPv4-only and cannot match IPv6 CIDR %q (use icmpv6)", i, r.Proto, r.CIDR)
			}
		} else if r.CIDR != "" && !strings.HasPrefix(r.CIDR, "@") && ruleFamily(r.Proto) == "ip6" {
			return fmt.Errorf("rule %d: proto %q is IPv6-only and cannot match IPv4 CIDR %q", i, r.Proto, r.CIDR)
		}
		if strings.HasPrefix(r.CIDR, "@") {
			name := strings.TrimPrefix(r.CIDR, "@")
			if name == "" || !ipsets[name] {
				return fmt.Errorf("rule %d: unknown ipset reference %q", i, r.CIDR)
			}
		}
	}
	for _, sg := range p.SecurityGroups {
		if sg.Name == "" {
			return errors.New("security group with empty name")
		}
	}
	for _, n := range p.NICs {
		if err := validateGuard(n); err != nil {
			return err
		}
		if n.Bridge != "" && !safeIfName(n.Bridge) {
			return fmt.Errorf("NIC %q: bridge name %q is not a safe interface name", n.NICDev, n.Bridge)
		}
	}
	// NAT / isolation are IPv4-only (same as the filter rules) and must be
	// complete — a blank field would emit a malformed rule that poisons the whole
	// atomic ruleset at apply time.
	for i, r := range p.NAT {
		if r.Subnet == "" || strings.Contains(r.Subnet, ":") {
			return fmt.Errorf("nat rule %d: subnet %q must be a non-empty IPv4 CIDR", i, r.Subnet)
		}
		if r.SNATTo != "" {
			if r.OutIface == "" || strings.Contains(r.SNATTo, ":") {
				return fmt.Errorf("nat rule %d: SNAT needs an out-iface and an IPv4 target (got iface=%q to=%q)", i, r.OutIface, r.SNATTo)
			}
		} else if r.Bridge == "" {
			return fmt.Errorf("nat rule %d: masquerade needs a bridge", i)
		}
	}
	for i, c := range p.HostIsolation {
		if c.Bridge == "" {
			return fmt.Errorf("isolation chain %d: empty bridge", i)
		}
		for _, exc := range c.Exceptions {
			if exc.VIP == "" || strings.Contains(exc.VIP, ":") {
				return fmt.Errorf("isolation chain %q: exception VIP %q must be a non-empty IPv4 address", c.Bridge, exc.VIP)
			}
		}
	}
	return nil
}

// validateGuard refuses a guard whose MAC or addresses would emit a line nft
// refuses, which would take the whole atomic ruleset down with it.
func validateGuard(n NICBinding) error {
	g := n.Guard
	if g == nil {
		return nil
	}
	if n.NICDev == "" {
		return errors.New("guarded NIC with empty device name")
	}
	if hw, err := net.ParseMAC(g.MAC); err != nil || len(hw) != 6 {
		return fmt.Errorf("NIC %q: guard MAC %q is not an Ethernet address", n.NICDev, g.MAC)
	}
	for _, a := range g.V4 {
		if !validAddrOrPrefix(a, false) {
			return fmt.Errorf("NIC %q: guard IPv4 entry %q is not an IPv4 address or prefix", n.NICDev, a)
		}
	}
	for _, a := range g.V6 {
		if !validAddrOrPrefix(a, true) {
			return fmt.Errorf("NIC %q: guard IPv6 entry %q is not an IPv6 address or prefix", n.NICDev, a)
		}
	}
	return nil
}

// safeIfName reports whether s is a plausible Linux interface name that is
// safe to quote into a ruleset.
func safeIfName(s string) bool {
	if s == "" || len(s) > 15 {
		return false
	}
	for _, r := range s {
		if !(r == '-' || r == '_' || r == '.' || (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z')) {
			return false
		}
	}
	return true
}

// validAddrOrPrefix reports whether s is an address or prefix of the given
// family (v6 = IPv6). An IPv4-mapped IPv6 address counts as IPv6.
func validAddrOrPrefix(s string, v6 bool) bool {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Addr().Is4() != v6 && p.Addr().Zone() == ""
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Is4() != v6 && a.Zone() == ""
	}
	return false
}

// allRules walks every Rule the Plan contains so validate can sweep
// them in one place.
func allRules(p Plan) []Rule {
	var out []Rule
	out = append(out, p.ClusterRules...)
	out = append(out, p.HostRules...)
	for _, sg := range p.SecurityGroups {
		out = append(out, sg.Rules...)
	}
	for _, n := range p.NICs {
		out = append(out, n.ExtraRules...)
	}
	return out
}

// FromCorrosionRule converts the on-disk SGRule struct into the typed
// Rule the renderer consumes. Empty / default fields collapse to the
// most permissive option — same convention the corrosion helpers use
// when persisting.
func FromCorrosionRule(direction, proto, portRange, cidr, action string) Rule {
	dir := Direction(strings.ToLower(direction))
	if dir != Egress {
		dir = Ingress
	}
	if proto == "" {
		proto = "all"
	}
	act := Action(strings.ToLower(action))
	if act == "" {
		act = Accept
	}
	return Rule{
		Direction: dir,
		Proto:     proto,
		PortRange: portRange,
		CIDR:      cidr,
		Action:    act,
	}
}
