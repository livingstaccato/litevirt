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

	"github.com/litevirt/litevirt/internal/firewall/rulefield"
)

// TableName is the single nftables table litevirt owns. Every chain we
// emit lives here so `nft list table inet litevirt-fw` shows the entire
// litevirt-managed surface.
const TableName = "litevirt-fw"

// NICTableName is the bridge-family table that enforces every per-NIC policy:
// the NIC guards (anti-spoofing) and the per-NIC rules (cluster, host and
// security-group tiers plus the default policy, applied to each NIC), and the
// VLAN rule. It is loaded in its own transaction, before TableName (see
// Applier.Apply), and its layout is described in nic_table.go.
//
// WHY THE BRIDGE FAMILY. A guest's tap is a port of a Linux bridge, so two
// guests on one bridge talk at layer 2: their frames never reach the inet
// forward hook, and with br_netfilter loaded that hook sees the bridge, not
// the tap, as iif/oif. A rule matching the tap there never matches. The bridge
// family's forward, input and output hooks see every frame a port sends or
// receives, with the tap as iifname/oifname: guest to guest (forward), guest
// to the host or to anything the host routes to (input), and the host or
// routed traffic to the guest (output). It needs no br_netfilter. Replies are
// recognised by nf_conntrack_bridge (BridgeConntrackAvailable); without it
// only the guards are rendered (NICModeGuardsOnly).
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

	// ID is the stored row's id. It names the rule in its log prefix.
	ID string
	// Log logs each packet the rule matches to the daemon (NFLOG), on a line
	// of its own ahead of the rule's verdict (spec §3.4). It renders only
	// where Plan.LogPolicy is Available.
	Log bool
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
	// traffic toward it is judged at that bridge's output hook (per NIC, or by
	// the tiers for any other port) instead of in the inet forward chain.
	Bridge string

	// MAC is the NIC's MAC address, when known. It names the NIC in the
	// observe-mode tally (WouldDropTally), which must outlive the tap name.
	MAC string

	// AllowVLANTags lets the guest send 802.1Q / 802.1ad tagged frames (an
	// explicit trunk). Every other NIC's tagged frames are dropped: rules match
	// untagged IP, so a tag would carry traffic past them.
	AllowVLANTags bool

	// TrunkVIDs are the VLANs of a NIC on litevirt's `trunk:` feature (two or
	// more VLANs, configured on a vlan_filtering bridge port). Such a NIC
	// carries single-tagged frames of exactly these VLANs, which its rules
	// still judge (they match the inner packet); an 802.1ad or doubled tag,
	// whose payload no rule can see, is refused like any other NIC's tag.
	TrunkVIDs []int

	// TrunkDenied marks a NIC on the `trunk:` feature none of whose VLANs its
	// network allows (re-review R3-I1): it has no TrunkVIDs, and every tagged
	// frame to or from it is dropped in either mode. Rendered like any other
	// NIC, its tags would meet only the plain VLAN rule, which observe mode
	// counts, and leave through the uplink on VLANs the tenant chose.
	TrunkDenied bool

	// DHCPServer marks a NIC whose guest is allowed to answer DHCP: its
	// replies reach other guests ahead of their ingress rules, as the host's
	// dnsmasq replies do.
	DHCPServer bool

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

	// ExcludeV4 / ExcludeV6 are addresses the guest may never claim even
	// inside an allowed prefix: the network's own addresses (network,
	// broadcast, gateway) and every other NIC's assigned address on it. They
	// matter when V4/V6 is a subnet rather than the NIC's exact address.
	ExcludeV4 []string
	ExcludeV6 []string

	// LinkLocal are the IPv6 link-local addresses the guest may use besides
	// the EUI-64 one derived from MAC (a guest with stable-privacy addresses
	// lists its own here).
	LinkLocal []string
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

	// NICMode is how per-NIC rules are applied: NICModeEnforce,
	// NICModeObserve (count what would be dropped, drop nothing) or
	// NICModeGuardsOnly (bridge conntrack is unavailable: only the guards and
	// the VLAN rule, which need no connection tracking). "" is enforce.
	NICMode string

	// Gateways are the addresses of litevirt's own services on the guest
	// networks — each managed network's gateway, where dnsmasq answers DHCP
	// and DNS. Guests may always reach those services there, and the host may
	// always answer from there.
	Gateways []string

	// LBBackends are the built-in load balancer's backend endpoints; the
	// host's haproxy (proxied connections and health checks) may always reach
	// them, from LBSources (the LB VIPs and the host's gateway addresses).
	LBBackends []LBBackend
	LBSources  []string

	// BlockedTrunks are the trunk VLANs the loader left out because the NIC's
	// network does not allow them (not rendered; reported as a condition).
	BlockedTrunks []BlockedTrunk

	// LogPolicy is how the host logs: whether it can, to which NFLOG group,
	// whether the default verdict is logged, and the per-NIC budget.
	LogPolicy LogPolicy

	// InvalidRows are the stored rows the loader did not render as written
	// because they fail the rule grammar (not rendered; reported as a
	// condition). See quarantineRule.
	InvalidRows []InvalidRow
}

// BlockedTrunk is a trunk NIC's VLANs its network does not allow.
type BlockedTrunk struct {
	Workload string
	Network  string
	VIDs     []int
}

// LBBackend is one load-balancer backend endpoint.
type LBBackend struct {
	Addr  string
	Port  int
	Proto string // "tcp" (default) or "udp"
}

// LogPolicy is a host's firewall logging (spec §3.4). The zero value renders
// no log line at all.
type LogPolicy struct {
	// Available says the host renders log lines: its kernel loads a named
	// limit and `log group`, and the daemon listens. When false nothing is
	// logged and no limit is declared, whatever the rules and Default say.
	Available bool
	// Group is the NFLOG group every log line sends to (firewall.log_group).
	Group uint16
	// Default logs each NIC side's default verdict (DECISION L-7: off until
	// an operator turns the policy on).
	Default bool
	// Rate and Burst are the per-NIC-side budget, records per second and
	// burst. A value outside 1..MaxLogRate (1..MaxLogBurst) renders the
	// default.
	Rate, Burst int
}

// The per-NIC-side log budget (DECISION L-4).
const (
	DefaultLogRate  = 5
	DefaultLogBurst = 10
	MaxLogRate      = 10000
	MaxLogBurst     = 10000
)

// Per-NIC enforcement modes (Plan.NICMode).
const (
	NICModeEnforce    = "enforce"
	NICModeObserve    = "observe"
	NICModeGuardsOnly = "guards-only"
)

func (p Plan) nicMode() string {
	switch p.NICMode {
	case NICModeObserve, NICModeGuardsOnly:
		return p.NICMode
	}
	return NICModeEnforce
}

// Render turns the Plan into the nftables ruleset `nft -f -` loads: the inet
// table, then the per-NIC bridge table when the plan has one. The inet table
// is rendered as it is when the bridge table is in force (RenderParts). The
// output is deterministic — identical Plan ⇒ identical bytes.
func Render(p Plan) (string, error) {
	inet, nic, err := RenderParts(p, true)
	if err != nil {
		return "", err
	}
	if nic == "" {
		return inet, nil
	}
	return inet + "\n" + nic, nil
}

// RenderParts renders the inet table and the per-NIC bridge table separately,
// so the applier can load them in two transactions and a refusal of the bridge
// table never freezes the inet table (NAT, isolation, routed filtering).
// nicActive says whether the bridge table is in force on the host: only then
// does the inet forward chain trust its per-NIC decisions (judgedMark,
// deferMark). nic is "" when the plan needs no bridge table.
func RenderParts(p Plan, nicActive bool) (inet, nic string, err error) {
	if err := validate(p); err != nil {
		return "", "", err
	}
	sgByName := map[string]SecurityGroup{}
	for _, sg := range p.SecurityGroups {
		sgByName[sg.Name] = sg
	}
	for _, n := range p.NICs {
		for _, name := range n.SecurityGroups {
			if _, ok := sgByName[name]; !ok {
				return "", "", fmt.Errorf("NIC %q references unknown security group %q", n.NICDev, name)
			}
		}
	}
	v6Sets := setsWithIPv6(p.IPSets)
	nicTable := len(p.NICs) > 0
	trust := nicTable && nicActive && p.nicMode() == NICModeEnforce

	var b strings.Builder
	b.WriteString("# Generated by litevirt firewall renderer — do not edit by hand.\n")
	b.WriteString("# `nft -f -` consumes this file as an atomic ruleset replace.\n\n")

	// IMPORTANT: do NOT close the brace via `defer` — strings.Builder.String()
	// snapshots the length at call time. Always close before returning.
	fmt.Fprintf(&b, "table inet %s {\n", TableName)
	renderIPSets(&b, p.IPSets)
	if p.LogPolicy.Available && (anyLogged(p.ClusterRules) || anyLogged(p.HostRules)) {
		renderLogLimit(&b, logLimitRouted, p.LogPolicy)
	}

	defaultPolicy := "accept"
	if p.DefaultDeny {
		defaultPolicy = "drop"
	}
	// The forward chain judges routed traffic with the cluster and host tiers
	// and the default policy, exactly as before per-NIC enforcement existed —
	// except traffic the bridge table has already judged per NIC (trust).
	fmt.Fprintf(&b, "    chain forward {\n")
	fmt.Fprintf(&b, "        type filter hook forward priority filter; policy %s;\n", defaultPolicy)
	// Stateful conntrack — reply traffic, and the ICMP(v6) errors that relate
	// to a known flow, are always allowed.
	fmt.Fprintf(&b, "        ct state established,related accept\n")
	fmt.Fprintf(&b, "        ct state invalid drop\n")
	// Neighbour and router discovery are link-local: a router never forwards
	// them (RFC 4861 requires hop limit 255), so a routed one is a guest using
	// the discovery exemptions to smuggle traffic off its link. Routing has
	// already decremented the hop limit when this hook runs; a BRIDGED
	// message, which reaches this hook too on a host with br_netfilter loaded,
	// still carries 255 and must pass, as it did before this rule existed.
	fmt.Fprintf(&b, "        ip6 hoplimit != 255 icmpv6 type { nd-router-solicit, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert, nd-redirect } drop\n")
	if trust {
		// A frame a guest sent was judged by its NIC's egress rules at the
		// bridge input hook, which marks what it lets through.
		fmt.Fprintf(&b, "        meta mark & %#x == %#x accept\n", judgedMark, judgedMark)
		// Routed traffic toward a bridge that carries guest NICs is judged at
		// that bridge's output hook: by the receiving NIC's ingress rules, or,
		// for any other port, by the tiers and default policy below
		// (routed_to_port), so nothing is let through unjudged.
		if brs := nicBridges(p.NICs); len(brs) > 0 {
			fmt.Fprintf(&b, "        oifname { %s } meta mark set meta mark | %#x accept\n", quoteNames(brs), deferMark)
		}
	}
	fmt.Fprintf(&b, "        jump cluster_default\n")
	fmt.Fprintf(&b, "        jump host_overrides\n")
	fmt.Fprintf(&b, "    }\n\n")

	renderTierChain(&b, "cluster_default", p.ClusterRules, v6Sets, p.LogPolicy)
	renderTierChain(&b, "host_overrides", p.HostRules, v6Sets, p.LogPolicy)

	// Infra chains on their own hooks. Emitted only when non-empty so a plan with
	// no NAT / isolation renders byte-identically to before this feature (and so
	// removing the last rule drops the whole chain on the next atomic replace).
	renderNAT(&b, p.NAT)
	renderHostIsolation(&b, p.HostIsolation)
	b.WriteString("}\n")
	inet = b.String()

	if nicTable {
		var nb strings.Builder
		renderNICTable(&nb, p, sgByName, v6Sets)
		nic = nb.String()
	}
	return inet, nic, nil
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

func quoteNames(names []string) string {
	q := make([]string, len(names))
	for i, n := range names {
		q[i] = `"` + n + `"`
	}
	return strings.Join(q, ", ")
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
// name is the tier name. A logged rule logs as dev `-` under
// lv_lg_routed.
func renderTierChain(b *strings.Builder, name string, rules []Rule, v6Sets map[string]bool, lp LogPolicy) {
	fmt.Fprintf(b, "    chain %s {\n", name)
	for _, r := range rules {
		for _, line := range renderRoutedLog(r, v6Sets, lp) {
			fmt.Fprintf(b, "        %s\n", line)
		}
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
//
// A negated or ==-prefixed reference (`!= @x`, `ne @x`) splits the same way:
// a negated rule must hold IPv6 traffic to the set's IPv6 elements too, not
// leave it untouched.
func renderRules(r Rule, nicDev string, v6Sets map[string]bool) []string {
	if name, ok := rulefield.SetRef(r.CIDR); !ok || !v6Sets[name] {
		return []string{renderRule(r, nicDev, "")}
	}
	var out []string
	if ruleFamily(r.Proto) != "ip6" {
		out = append(out, renderRule(r, nicDev, "ip"))
	}
	if ruleFamily(r.Proto) != "ip" {
		r6 := r
		r6.CIDR = strings.TrimRight(r.CIDR, " \t") + ipv6SetSuffix
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
			// wants. nftables port-range syntax is N-M; pass through,
			// lower case: nft resolves a service name only in lower case
			// (`dport SSH` is refused), and a peer on an older build can
			// store one as sent.
			parts = append(parts, "dport", strings.ToLower(r.PortRange))
		}
	case "icmp":
		parts = append(parts, "ip", "protocol", "icmp")
	case "icmpv6", "ipv6-icmp":
		if family == "ip6" {
			// With an IPv6 CIDR or set (a firewall_ipv6 write): ICMPv6.
			parts = append(parts, "meta", "l4proto", "ipv6-icmp")
		} else {
			// With no CIDR, or an IPv4 one: a shape main accepted, rendered
			// byte for byte as main rendered it (switch review m3).
			parts = append(parts, "ip", "protocol", proto)
		}
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
		out += " comment " + quoteComment(r.Comment)
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
		// The name and every element are written into the script as text.
		if err := rulefield.RenderSetName(ipset.Name); err != nil {
			return fmt.Errorf("ipset %q: %w", ipset.Name, err)
		}
		for _, e := range ipset.CIDRs {
			if err := rulefield.RenderSetElement(e); err != nil {
				return fmt.Errorf("ipset %q: %w", ipset.Name, err)
			}
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
		// proto, port and an IPv4 CIDR are written into the script verbatim:
		// text that is not nft words would add nft syntax of its own (finding
		// F-1). Only that is refused here, so a rule that applies today renders
		// as it did; the comment is quoted safely wherever it is written
		// (quoteComment).
		for _, err := range []error{rulefield.RenderProto(r.Proto), rulefield.RenderPort(r.Proto, r.PortRange), rulefield.RenderCIDR(r.CIDR)} {
			if err != nil {
				return fmt.Errorf("rule %d: %w", i, err)
			}
		}
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
		// paired with IPv4's icmp, would emit a line nft refuses, poisoning
		// the whole atomic ruleset — so refuse it here. IPv4 CIDRs are passed
		// through as they always were, icmpv6 with one included (main's
		// shape, rendered as main rendered it).
		if isIPv6Literal(r.CIDR) {
			if !validAddrOrPrefix(r.CIDR, true) {
				return fmt.Errorf("rule %d: %q is not an IPv6 address or prefix", i, r.CIDR)
			}
			if ruleFamily(r.Proto) == "ip" {
				return fmt.Errorf("rule %d: proto %q is IPv4-only and cannot match IPv6 CIDR %q (use icmpv6)", i, r.Proto, r.CIDR)
			}
		}
		// "!= @name" references a set too; nft refuses the whole ruleset on
		// one that is not declared.
		if name, op, ok := rulefield.SetRefOp(r.CIDR); ok {
			if name == "" || !ipsets[name] {
				return fmt.Errorf("rule %d: unknown ipset reference %q", i, r.CIDR)
			}
			if !rulefield.SetRefOpOK(op) {
				return fmt.Errorf("rule %d: %q compares a set with %s, which nft refuses", i, r.CIDR, op)
			}
		} else if strings.Contains(r.CIDR, "@") {
			return fmt.Errorf("rule %d: %q references a set other than as @name, != @name or == @name", i, r.CIDR)
		}
	}
	for _, sg := range p.SecurityGroups {
		if sg.Name == "" {
			return errors.New("security group with empty name")
		}
	}
	for _, g := range p.Gateways {
		if !validAddrOrPrefix(g, false) && !validAddrOrPrefix(g, true) {
			return fmt.Errorf("gateway %q is not an IP address", g)
		}
	}
	for _, n := range p.NICs {
		if !safeIfName(n.NICDev) {
			return fmt.Errorf("NIC device %q is not a safe interface name", n.NICDev)
		}
		if err := validateGuard(n); err != nil {
			return err
		}
		if n.Bridge != "" && !safeIfName(n.Bridge) {
			return fmt.Errorf("NIC %q: bridge name %q is not a safe interface name", n.NICDev, n.Bridge)
		}
		for _, v := range n.TrunkVIDs {
			if v < 1 || v > 4094 {
				return fmt.Errorf("NIC %q: trunk VLAN %d is outside 1-4094", n.NICDev, v)
			}
		}
	}
	// NAT / isolation are IPv4-only (same as the filter rules) and must be
	// complete — a blank field would emit a malformed rule that poisons the whole
	// atomic ruleset at apply time.
	// Every field is written into the script as text, so each must be an
	// interface name or an IPv4 address or prefix, nothing more.
	for i, r := range p.NAT {
		if !validAddrOrPrefix(r.Subnet, false) {
			return fmt.Errorf("nat rule %d: subnet %q must be a non-empty IPv4 CIDR", i, r.Subnet)
		}
		if r.SNATTo != "" {
			if !safeIfName(r.OutIface) || !validAddrOrPrefix(r.SNATTo, false) {
				return fmt.Errorf("nat rule %d: SNAT needs an out-iface and an IPv4 target (got iface=%q to=%q)", i, r.OutIface, r.SNATTo)
			}
		} else if !safeIfName(r.Bridge) {
			return fmt.Errorf("nat rule %d: masquerade needs a bridge (got %q)", i, r.Bridge)
		}
	}
	for i, c := range p.HostIsolation {
		if !safeIfName(c.Bridge) {
			return fmt.Errorf("isolation chain %d: bridge %q is not a safe interface name", i, c.Bridge)
		}
		for _, exc := range c.Exceptions {
			if !validAddrOrPrefix(exc.VIP, false) {
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
	for _, a := range g.ExcludeV4 {
		if !validAddrOrPrefix(a, false) {
			return fmt.Errorf("NIC %q: guard IPv4 exclusion %q is not an IPv4 address or prefix", n.NICDev, a)
		}
	}
	for _, a := range g.ExcludeV6 {
		if !validAddrOrPrefix(a, true) {
			return fmt.Errorf("NIC %q: guard IPv6 exclusion %q is not an IPv6 address or prefix", n.NICDev, a)
		}
	}
	for _, a := range g.LinkLocal {
		if p, err := netip.ParseAddr(a); err != nil || !p.Is6() || !p.IsLinkLocalUnicast() || p.Zone() != "" {
			return fmt.Errorf("NIC %q: guard link-local entry %q is not an IPv6 link-local address", n.NICDev, a)
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
