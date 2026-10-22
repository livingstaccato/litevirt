# Distributed firewall

litevirt ships a Proxmox-style three-tier firewall:
named security groups attached to NICs, declared in compose, persisted
in cluster state, and applied as an **atomic** nftables ruleset on
every host. The implementation lives in `internal/firewall/`.

## Architecture

```
                cluster state (Corrosion)
                  security_groups
                  sg_rules
                       │
                       ▼
                ┌──────────────┐
                │ Reconciler   │   30s poll on every host
                │  (per host)  │
                └──────┬───────┘
                       │ Plan
                       ▼
                ┌──────────────┐
                │ Renderer     │   pure Go; deterministic output
                └──────┬───────┘
                       │ ruleset (string)
                       ▼
                ┌──────────────┐
                │ Applier      │   skips when bytes unchanged
                └──────┬───────┘
                       │ nft -f -
                       ▼
                kernel (atomic table replace)
```

Each host runs its own reconciler. The renderer is pure — same input
produces the same bytes, byte-for-byte — so the applier short-circuits
when the cluster state is steady, keeping idle clusters at "one
Corrosion query per 30s" overhead.

## Three policy tiers

Rules are evaluated top-to-bottom, tier by tier, in each NIC's chains (see
"Where the rules are enforced"):

1. **Cluster default** (`cluster_default` chain) — applies to every
   NIC. Use it for blanket policy such as "block any forward to
   RFC1918 from the public VLAN".
2. **Host overrides** (`host_overrides` chain) — applies to every NIC
   on this host. Use it for host-local exceptions: "allow this NFS
   server to reach all OSDs."
3. **Per-NIC rules** (`nic_in_<dev>` / `nic_out_<dev>` chains) — security groups + per-NIC
   extras. This is the layer compose mostly cares about.

## Where the rules are enforced

A guest's NIC (a VM's tap, a container's veth) is a port of a Linux
bridge, so per-NIC policy is enforced in a **bridge-family** table,
`bridge litevirt-nic`, on the hooks every frame through a bridge port passes:

| Path | Hook | Chain run |
|---|---|---|
| guest to guest on one bridge | bridge `forward` | sender's `nic_out_<dev>`, then receiver's `nic_in_<dev>` |
| guest to the host, or to be routed out | bridge `input` | sender's `nic_out_<dev>` |
| the host, or routed traffic, to a guest | bridge `output` | receiver's `nic_in_<dev>` |
| routed traffic to a port that is not a guest NIC on such a bridge | bridge `output` | cluster and host tiers, then the default policy (`routed_to_port`) |

`nic_out_<dev>` holds every tier's **egress** rules for that NIC (cluster, then
host, then each bound security group, then the NIC's own rules) and
`nic_in_<dev>` holds the **ingress** rules, first match wins. An egress
`accept` lets the frame go on to the receiver's ingress rules rather than
ending the evaluation, so traffic between two guests must be allowed by the
sender's egress rules **and** the receiver's ingress rules. Under default-deny
each chain ends in `drop`. A `reject` rule is enforced as `drop` here: the
bridge family can reject only at prerouting and input, and one reject on the
forward or output hook would make the kernel refuse the whole table.

Each base chain first lets through, untouched, every frame that is neither from
nor to a guest NIC (other bridges on the host, the uplink's own traffic). For a
guest NIC it then accepts, ahead of the rules:

- replies and related ICMP errors of known flows (`ct state established,related`);
- frames that are not IP or IPv6 — ARP and the rest of layer 2 are the
  [NIC guard](#nic-guards)'s business;
- neighbour discovery with hop limit 255, and MLD between link-local or
  unspecified and multicast addresses — link-scoped, so none of it can be
  routed (inet forward drops a neighbour-discovery message a router forwarded,
  whose hop limit is below 255; a **bridged** one, which with `br_netfilter`
  loaded passes that hook too, keeps 255 and is not touched);
- DHCP only toward a server on the link: client requests to the broadcast
  address, to `ff02::1:2`, or to a managed network's gateway (where dnsmasq
  answers); server replies only from the host's dnsmasq, from a port that is not
  a guest NIC (an upstream server on the uplink), or from a NIC whose guard
  allows a DHCP server; router advertisements only from the host or from a
  non-guest port;
- litevirt's own services by explicit generated rules: DNS to a network's
  gateway where litevirt's dnsmasq is the router, and the built-in load
  balancer's haproxy to its backends' address and port — from a host the LB
  runs on (its address, the VIP or the gateway address), and from no other
  host: another host's address would let its masqueraded guests reach a
  backend's port past the backend's own groups.

Nothing else is accepted by protocol or port: a `udp 68 → 67` datagram to an
arbitrary address is judged by the rules like any other. DNS to the gateway is
accepted **ahead of** the tiers and security groups, so a group that isolates a
guest does not stop its DNS queries, which dnsmasq forwards upstream — as
before per-NIC enforcement existed. Block DNS for such a guest with a cluster or
host tier rule on the host's upstream resolver, or run the network
`host-isolation: true`.

**VLAN tags.** A guest NIC is an access port. Tagged frames — 802.1Q, 802.1ad
(QinQ), even a priority tag (VID 0) — are dropped both **from** it (at
prerouting) and **to** it (at the forward and output hooks, before anything
else: the kernel holds a frame's outer tag outside the payload, so the tag would
otherwise carry the frame past the receiver's rules, and its guest strips it).
On a `vlan_filtering` bridge the egress tagging policy has already been applied
at those hooks, so an access port's own VLAN traffic arrives untagged and is
not affected. In observe mode these drops are counters (`vlan tagged`,
`vlan tagged-to-nic`), except a guarded NIC's own tagged frames, which its
guard drops in both modes.

Two kinds of NIC carry tags:

- a NIC on the **`trunk:`** feature (two or more VLANs, a tagged trunk on its
  bridge port) carries single-tagged frames of the VLANs its **network allows**
  (`lv network set <net> --allowed-vlans 100,101`, compose `allowed-vlans:`,
  set with `network.update` on the network), and its rules still judge them: a
  rule matches the packet inside the tag. Any other VLAN is dropped in either
  mode — on a bridge that filters no VLANs it would leave through the uplink
  onto a VLAN the tenant chose. An 802.1ad outer tag or a tag inside the tag
  (whose payload no rule can see) is dropped in enforce mode and counted
  (`vlan trunk`) in observe mode. A trunk NIC is **guarded** like any other new
  NIC: every frame it sends, tagged or not, is held to its MAC, to its own MAC
  in ARP and neighbour discovery, and may not answer DHCP or advertise a router;
  its address guards hold its untagged (native) VLAN only, the addresses its
  guest uses on its other VLANs being no one's to know.
  - A trunk that existed when the cluster upgraded keeps its VLANs: they are
    recorded into its network's allowed list (an audited `network.update` by
    `litevirt`). The recording runs on every host whose replica has caught up,
    every 30 seconds until every host runs this release, so a trunk an older
    host creates during the rollout keeps its VLANs too; then it stops, after
    one more pass that finds nothing to write. A VLAN is recorded once: one an
    operator later takes off the list (`lv network set --allowed-vlans`) stays
    off. Each network's list is read and written under compare-and-swap, and
    every pass puts back a recorded VLAN that a concurrent write on another
    host dropped from the list without having seen it.
  - The VLANs litevirt put on a network's list stay on it when the network is
    written again from its definition — a re-deploy of the stack that declares
    it, a peer provisioning it — unless an operator took them off with
    `lv network set`.
  - A NIC on a network with no network row attaches to a **flat bridge** of
    that name (docs/networking.md). Its trunk carries the VLANs recorded for
    the bridge at upgrade and those allowed on it with
    `lv network set <bridge> --allowed-vlans 100,101`. A flat bridge belongs
    to no project, so that needs `network.update` at the cluster root; only
    `--allowed-vlans` can be set on one, and it replaces the bridge's list
    (the recorded VLANs stay). It is audited as `network.update`.
  - The VLANs of a flat bridge follow its trunks. A network row created under
    the bridge's name (`lv network create`, or a stack declaring it) takes
    over the VLANs recorded for the bridge and those allowed on it. When a
    re-deploy moves a legacy stack's NIC from the flat `<stack>_<name>` onto
    the cluster network `<name>`, that NIC's VLANs recorded under the flat
    name are added to `<name>`'s list before the NIC moves. Both are audited
    `network.update` by `litevirt`.
  - **Lacking a guard record grants nothing.** Once the recording has first
    run, every trunk — recorded or not — carries only what its network allows.
    Until that first run (the minutes after the first host upgrades, while its
    replica catches up) a trunk with no record keeps carrying its own VLANs, so
    nothing in use breaks while the lists are written.
  - A trunk none of whose VLANs its network allows drops every tagged frame,
    in either mode.
  - A tenant's **new** trunk outside its network's list is still created; its
    VLANs the network does not allow are dropped, and the host raises the
    warning condition `firewall.nic.trunk_vlans`, which names the trunk and the
    `lv network set ... --allowed-vlans` that allows them, and the authority it
    needs (`network.update` on the network, or at the cluster root for a flat
    bridge) — an operator decides once per VLAN;
- a NIC allowed tags explicitly (`lv firewall nic-guard set ...
  --allow-vlan-tags`, compose `allow-vlan-tags: true`) — a VLAN-aware guest
  outside the `trunk:` feature, a nested hypervisor — sends and receives tags
  of any kind; its rules see what the kernel parses of the frame and nothing
  beyond a second tag. Allowing it is a relaxation (see below). If the NIC is
  **guarded**, its tags are held like this:
  - a **single-tagged** frame (VID 1-4094) is held to the NIC's MAC, to its own
    MAC in ARP and neighbour discovery, and may not answer DHCP or advertise a
    router unless the guard allows it, but it is **not** checked against
    the NIC's addresses: the addresses a guest uses inside a VLAN are no one's
    to know. So an IPv4 or IPv6 source, a link-local address, a neighbour
    advertisement's target and an ARP sender address are all unchecked inside a
    VLAN tag;
  - a **priority-tagged** frame (VID 0) is native-VLAN traffic (the host and a
    `vlan_filtering` bridge treat it as untagged), so it is held to the NIC's
    addresses exactly as an untagged frame is;
  - any **802.1ad** tag, and any tag inside a tag (including 802.1Q inside
    802.1Q), is dropped: the checks above cannot see inside it. QinQ through a
    guarded NIC needs the guard off (`--mode off`).
  A guarded trunk NIC is held the same way for a single tag, and its doubled
  tags are dropped by its confinement (above; in enforce mode, observe mode
  counts them). The NIC-guard list below states
  the address rules for untagged and priority-tagged frames.

**Routed traffic.** The `inet litevirt-fw` forward chain still judges routed
traffic with the cluster and host tiers and the default policy, as before. Two
marks let it skip what the bridge table judges instead: a frame a guest NIC
sent and its egress rules passed (bridge input) is accepted, and routed traffic
toward a bridge that carries guest NICs is handed to that bridge's output hook
to be judged there — by the receiving NIC's ingress rules, or by the tiers and
the default policy for any other port. Nothing is accepted by bridge name.
The marks are bits `0x10000000` and `0x20000000` of the packet mark; a host that
routes by fwmark must not use them.

Replies are recognised by bridge connection tracking, `nf_conntrack_bridge`,
which the daemon loads (`modprobe`) at start; a kernel with it built in needs
no load. `br_netfilter` is not needed and not used. Once the per-NIC table uses
it, the kernel tracks **every** bridged frame on the host — the uplink's own
traffic and other bridges' included — not only guest NICs': the chains skip
those frames, conntrack does not. Size `nf_conntrack_max` for that. **Without
it** — the module cannot be loaded — the host renders only
prerouting (the NIC guards and the VLAN rule, which need no connection
tracking), keeps the inet table's tiers and NAT as they always were, and raises
the critical health condition `firewall.nic.unavailable`: per-NIC rules are not
enforced there, rather than enforced without stateful replies.

**This replaces an enforcement point that did not work.** Before, the per-NIC
chains lived in the `inet` forward hook and matched the tap by
`iifname`/`oifname`. Traffic between two guests on one bridge never reaches that
hook, and with `br_netfilter` loaded the hook sees the bridge, not the tap, so
security groups were not enforced on guest-to-guest traffic at all, nor on
traffic between a guest and its host. The rules were rendered and listed by
`lv firewall show`, which is why nothing caught it.

The two tables load as **two** `nft -f` transactions, the per-NIC table first.
If the kernel refuses the per-NIC table, the inet table (NAT, isolation, routed
filtering) is still applied — rendered not to trust a table that is not there —
and the host raises `firewall.nic.refused`; the previous per-NIC table stays.
A host with no guest NIC renders no bridge table at all, and one the daemon no
longer renders is deleted, because libvirt reuses `vnetN` names and a stale
chain would hold the next VM to get that name to another VM's policy.

**Tap names.** A NIC this release defines — create, rebuild, clone, import,
hot-attach — names its tap after its MAC, `lvt` and the MAC's twelve hex digits
(`lvt525400aabbcc`), in the domain definition. The name is known before the
domain runs, is the same on a migration target and is never another NIC's, so
the per-NIC table carries a guarded NIC's chains whether or not it is running
(see "When a guard takes effect"). A NIC an older release defined keeps its
`vnetN` until it is re-created.

**Rollback.** The daemon's systemd unit removes the per-NIC table when a binary
that does not own it starts (`ExecStartPre`), so a rollback to a release
without per-NIC enforcement leaves no stale rules in force. An upgrade installs
the units of the binary doing the upgrading — the old one — so the new binary,
when it starts on a host whose unit lacks the step, installs it as the drop-in
`litevirt.service.d/10-nic-table-cleanup.conf`; the main unit, and anything an
operator changed in it, is left as it is.

## Observe and enforce

A cluster that **upgrades** to this release starts in **observe** mode: every
per-NIC rule is installed, but each drop is a counter instead (named
`lv-wd <device> <in|out|vlan> <rule>`) and nothing is dropped; the inet table's
routed filtering stays exactly as it was. Every host with guest NICs raises the
health condition `firewall.nic.observe` and sends a notification. NIC guards on
new NICs enforce in either mode — they protect new NICs only — and so does the
drop of a guest's VRRP to its host (see Guest VRRP below), the one drop
observe mode makes outside the guards.

```
lv firewall enforce status          # per host: the mode in force, and what would have been dropped since <time>
lv firewall enforce on              # enforce (admin; audited as firewall.enforcement; applies to every host)
lv firewall enforce off             # back to observing
lv firewall enforce reset-counters  # restart every host's totals from now (admin; audited as firewall.would_drop.reset)
```

**The counts are totals.** Every reload of the per-NIC table — a resync every
five minutes, any VM or container starting, stopping or migrating on the host —
re-creates its counters. Each host therefore adds the kernel's counters into a
total kept per workload, MAC, side and rule just before every reload, in
`<data_dir>/firewall-would-drop.json`, so `status` shows everything observed
since the time it names — across reloads, tap changes and daemon restarts —
and a nightly or weekly flow shows as well as a constant one. Only
`reset-counters` moves that time.

**Which clusters enforce from the start.** The mode is the replicated
`cluster_policies` key `firewall_nic_enforcement`; with no row a cluster
observes. A cluster's **founder** decides at genesis — when `lv host init`
founded it and its first daemon minted the admin account — that the new
cluster enforces, and records it once `failover_scope_v1` has latched, from a
replica that has caught up with its peers (or is the cluster's only host, or
has no gossip peer and no other host but ones still `joining`). No
other host ever records a mode on its own: a host that joins, or rejoins after
an upgrade, never changes it. The seed is stamped before any real write, so an
operator's `lv firewall enforce` written anywhere, at any time, outranks it;
and the mode only ever changes through `lv firewall enforce`.

## NAT, SNAT and host isolation

The same renderer also emits the host's network-infra rules into the
`litevirt-fw` table, so a single atomic replace covers filtering **and**
NAT/isolation (there is no separate `inet litevirt` table and no out-of-band
iptables):

- **Masquerade** — a `postrouting` nat chain SNATs managed-subnet guest egress
  out the host's uplink (`ip saddr <subnet> oifname != <bridge> masquerade`).
- **SNAT** — a load balancer on a host-isolated network with `snat: true` (or
  `lv lb create --snat`) rewrites guest egress to its VIP
  (`oifname <uplink> ip saddr <subnet> snat to <vip>`), emitted before
  masquerade.
- **Host isolation** — an `input` chain drops guest→host traffic per isolated
  bridge (`iifname <bridge> drop`), punching through VRRP and declared LB VIP
  ports first so guests can still reach an HAProxy VIP, and replies to
  connections the host opened onto that bridge (so HAProxy reaches backends
  there): an `isolation_output` chain marks each connection the host opens out
  of the bridge with a per-bridge ct mark, and the input chain accepts only
  reply-direction packets carrying it. Bits 16-27 of the ct mark are
  litevirt's; each host-isolated bridge on a host gets a distinct value there.
  Connections the host opened onto a host-isolated bridge before an upgrade
  to this rule carry no mark, so their replies are dropped once: a long-lived
  connection (an HAProxy keep-alive to a backend) reconnects.
- **Guest VRRP** — VRRP (IP protocol 112) a guest on this host sends the host
  itself is dropped, in enforce and observe mode alike: the bridge table's
  `input` chain marks a guest NIC's VRRP (`meta l4proto 112 meta mark set meta
  mark | 0x40000000`), and a `guest_vrrp` chain on the inet `input` hook drops
  what is marked. VRRP between guests is untouched, on one bridge or routed
  between networks, and so is VRRP from a bridge port that is not a guest NIC
  (a peer LB host's, over the uplink). That last path is also how a guest on
  another host's side of a shared network reaches this host, so the drop alone
  does not stop a guest answering a load balancer's VRRP: the unicast VRRP
  transport does, once `vrrp_unicast_v1` has latched
  ([compose.md](compose.md#load-balancer)). Rendered while the per-NIC table is
  in force and not in guards-only mode. In guards-only mode a guest's VRRP to
  the host is not dropped; after the latch it needs a forged peer source, which
  the NIC guard's source-address check drops for a guarded NIC. Bit 30 of the
  packet mark is litevirt's, beside bits 28 and 29.
- **Isolated networks** — an `isolated_forward` chain on the `forward` hook
  drops anything routed off or onto an `isolated` network's bridge: per live
  isolated network's bridge (`iifname "<bridge>" oifname != "<bridge>" drop`
  and the reverse), and for every device in interface group 27766, which
  litevirt gives each bridge it creates for an isolated network, whether or not
  a network row names it (`iifgroup 27766 oifgroup != 27766 drop` and the
  reverse). No device is matched by name. The chain is in every ruleset. Guests on one isolated bridge still reach each other and the
  host's `dnsmasq` on it.

These decisions are made by network provisioning and the LB apply path and
recorded per host in `host_fw_intent`; the reconciler reads that table and
renders the chains. Because rules are per-host local state, the table is not
replicated. On upgrade, once a bridge's rules are live in `litevirt-fw` the
reconciler clears the pre-consolidation rules a prior binary left behind, so
there is never a window without NAT or isolation.

## Stateful conntrack baked in

Every chain begins with:

```
ct state established,related accept
ct state invalid drop
```

So reply traffic is always allowed (on bridge ports, through
`nf_conntrack_bridge`). Rules need only describe the *new connection*
direction. Default-deny mode is therefore safe: the
SSH SYN you allow keeps its reply path open without you writing a
matching egress rule.

## Direction semantics

litevirt follows the AWS / GCP / Proxmox convention:

| Direction | What it means | nftables match |
|---|---|---|
| `ingress` | traffic ARRIVING at the VM | `oifname <tap>`, `ip saddr` / `ip6 saddr` |
| `egress`  | traffic LEAVING the VM | `iifname <tap>`, `ip daddr` / `ip6 daddr` |

This holds for the cluster and host tiers too, now that they are applied per
NIC: a guest's routed traffic is judged, in enforce mode, by the **egress**
rules of every tier on its NIC (at the bridge input hook) and is then trusted by
the inet forward chain; routed traffic toward a guest by its NIC's **ingress**
rules. Before per-NIC enforcement a routed packet met the inet tiers'
rules of both directions, each matching by address only, so a tier rule
written for the other direction no longer applies to that hop: write tier rules
with the direction they mean. Observe mode keeps the inet table as it was, so
its counters cannot show this.
## IPv6

Rules take IPv6 CIDRs, and ip sets take IPv6 elements, in every tier:

```
lv firewall cluster-rule add --direction ingress --proto tcp --port 22 --cidr 2001:db8::/32 --action accept
lv firewall cluster-rule add --direction ingress --proto icmpv6 --cidr ::/0 --action accept
lv firewall ipset add admins --cidr 10.0.0.0/8 --cidr 2001:db8:1::/48
```

- An IPv6 CIDR renders as `ip6 saddr` / `ip6 daddr`. `icmp` is ICMP for IPv4;
  `icmp` with an IPv6 CIDR is refused, since it could match nothing.
- `icmpv6` (or `ipv6-icmp`) is ICMPv6 with an IPv6 CIDR, or with a reference
  to a set holding IPv6 elements — `--cidr ::/0` for any source. With no CIDR, or an IPv4 one, it is the shape
  earlier releases accepted, and it keeps their meaning: it renders as
  `ip protocol icmpv6`, matching IPv4 packets of protocol 58, which is to say
  nothing a guest sends.
- nftables sets are typed, so a set holding both families renders as the IPv4
  set `<name>` plus an IPv6 companion `<name>_v6`, and a rule referencing
  `@<name>` matches either. A set named `<name>_v6` beside a set `<name>`
  with IPv6 elements is refused; one an older build stored is left out (see
  below).
- A set with no IPv6 elements has no companion, so a rule referencing it does
  not match IPv6 at all: `!= @<name> drop` on an IPv4-only set lets every IPv6
  address through. Adding the set's first IPv6 element makes the same rule
  drop every IPv6 address not in the set; removing its last one lets every
  IPv6 address through again.
- A rule without a CIDR on `tcp`, `udp` or `all` matches both families, as it
  always did.
- Neighbour discovery, router solicitation and advertisement, MLD and the
  ICMPv6 errors are accepted ahead of every tier, so a drop-everything rule or a
  default-deny policy does not break IPv6 itself.

**Rolling upgrade.** Until every host runs a build that renders IPv6, an IPv6
rule would make an older host refuse its whole firewall plan, so an IPv6 rule
or ip-set element is the release feature `firewall_ipv6` of
`release_2026_11_v1` (docs/upgrades.md, "Release features"): nothing writes
one until the release token has latched, and the first one records the use
first. Before that, adding one fails with FailedPrecondition, "the cluster
upgrade must finish first (firewall_ipv6 needs release_2026_11_v1)", naming
the hosts still on the older build; IPv4 rules are unaffected. A malformed
IPv6 rule is refused as malformed either way. A stack deploy holding an IPv6
row takes the `firewall_ipv6` first use before it replaces the stack's old
rows, so the feature is recorded as used — and a rollback below the release
then quarantines — even if a later row of that deploy fails.

## NIC guards

A NIC guard holds a guest NIC to its own identity on the wire (Proxmox's
`ipfilter` / `macfilter`, plus DHCP, router-advertisement and NDP guards). It
runs at the bridge `prerouting` hook, ahead of everything else, and drops what a
guarded guest sends:

- from any MAC but the NIC's own;
- ARP that claims another MAC, or an IPv4 address that is not the guest's;
- IPv4 from an address that is not the guest's (a DHCP client asking for one,
  from `0.0.0.0`, still passes);
- IPv6 from an address that is not the guest's; its link-local addresses are
  always held — the EUI-64 one derived from its MAC, plus any listed — so it
  cannot claim the router's link-local address;
- neighbour advertisements for an address that is not the guest's, and
  solicitations, advertisements and router solicitations whose link-layer
  address option names another MAC — the IPv6 forms of ARP spoofing;
- DHCP and DHCPv6 server traffic — anything from the server ports or **to** the
  client ports, whatever its source port — unless the guard allows the guest to
  answer DHCP;
- router advertisements and redirects, unless the guard allows the guest to act
  as a router.

The address rules above hold untagged and priority-tagged frames; inside a VLAN
tag they are relaxed on a NIC allowed tags or on a trunk (see "VLAN tags").

**Which addresses are the guest's.** For each family:

- an address litevirt assigned the NIC — a static `ip:`, a NetBox address, a
  container's IPAM address, a static `ipv6:`, or, for a VM NIC on a network
  litevirt serves DHCP for, the **exact address reserved for it** in dnsmasq
  (`--dhcp-hostsfile`) — plus the guard's **allowed addresses**;
- with no assigned address of that family (a NIC guarded after it was created,
  an imported VM, a NIC whose DHCP no single local server answers — below), the
  network's `subnet:` — except the network and broadcast addresses, the
  network's router and reserved addresses, the gateway any NIC on it routes
  through, and every other NIC's assigned address, which are never the guest's
  — plus the allowed addresses;
- with neither and no allowed address of that family: **unrestricted**. A guest
  on a plain bridge served by a DHCP server or router litevirt does not run has
  addresses nobody told litevirt about, and cutting it off would break it. The
  MAC, ARP-sender-MAC, link-local, DHCP-server and router-advertisement guards
  still apply.

**DHCP reservations.** The exact address is reserved only where this host's
dnsmasq is the network's **only** DHCP server: an `isolated` network, or a
`bridge` network with no VLAN and no uplink (only guest ports). On a `vxlan`
network the elected gateway host serves DHCP, and on a bridge with an uplink
another server may answer first; a guest given a dynamic address there would be
dropped by an exact guard for the whole lease, so its guard is confined to the
subnet instead. A NIC re-created with its MAC (a rebuild) keeps the address
its MAC already leased.

**The network's router.** The router a NIC may not claim is the network's own:
the subnet's first host wherever litevirt runs dnsmasq or routes the network
(a managed bridge, a bridge with `dhcp`, an isolated or vxlan network) — the
address guests send DHCP and DNS to, protected whatever `gateway:` says; the
network's `gateway:` and `reserved-addresses:` (`lv network create --gateway
--reserved-address`, or later `lv network set`) — set them on an external or
VLAN bridge, whose router is someone else's and often not the first host; and
the `gateway:` / `ipv6_gateway:` every VM's NIC on the network routes through.
Whether litevirt runs dnsmasq there is judged from the network's definition,
which every host shares, not from whether a host's bridge existed before
litevirt (which only that host knows): a bridge network not marked `external`
counts as managed. On such a network whose bridge in fact pre-existed with no
`dhcp`, litevirt serves nothing, yet its first host is still protected and
refused at assignment — over-protection, never a gap. If that address belongs
to a router VM of yours, mark the network `external: true`.

Listing an allowed address of a family restricts that family: on a network
where litevirt does not know the guest's address, list that address (or its
subnet) too. A guest that uses stable-privacy IPv6 link-local addresses
(NetworkManager's default) must list its link-local address, or use EUI-64
(`ipv6.addr-gen-mode eui64`).

**Identities are unique.** An explicit MAC, IPv4 or IPv6 address in a create,
hot-attach, clone or import request that another live NIC holds is refused, as
is a subnet's network or broadcast address and the network's router or a
reserved address (above): the guard would otherwise enforce the impersonation
for the requester. A gateway other projects' NICs route through is refused too,
unless the requester has `network.update` on the network; one only its own
project's NICs route through is its own router to run.

**Defaults.** A NIC created by this release — `CreateVM`, a compose deploy, a
clone, `lv attach-nic`, a container's managed NIC — is guarded unless its
request says otherwise. An imported VM's NICs (`lv import`) are guarded,
confined to their network's subnet, on a network that has one (`--spoof-guard
off` imports them unguarded). A NIC on the `trunk:` feature is guarded like
any other, its VLANs its network's to allow (see "VLAN tags"). A NIC that
existed before has **no guard** and keeps working exactly as it did; set one
with `lv firewall nic-guard set`. A clone's NICs are new NICs: each gets the
default guard, not its source's relaxations or its source's lack of a record.
So do the NICs of a renamed promotion (`lv replication promote --new-name`) and of a live
restore under a new name: a second VM beside the original, with fresh MACs. A
promotion or restore under the VM's own name is unchanged.

**A direct or SR-IOV NIC has no guard.** A macvtap (`direct`) or SR-IOV NIC
bypasses the bridge where guards are enforced, so it never gets a guard record:
not at create, `lv attach-nic`, a clone, an import, or a renamed promotion or
restore. Guard settings asked for on such a NIC are refused rather than
accepted for a NIC that would silently have none: `lv run`, `lv attach-nic`
and `lv firewall nic-guard set` all refuse them. A compose file that declares
one is reported, not refused: every plan names the guard as not enforced, and
the create leaves it out (see [compose.md](compose.md#security-groups-and-guards-a-file-does-not-declare)).
A VM created by an earlier build may carry such settings in its stored spec;
they were never enforced. A rebuild or a stack's re-create replays that spec,
so it leaves them out instead of refusing. So does the host that runs a
create another host forwarded to it: during a rolling upgrade, an entry host
on an earlier build accepted them, as that build did. Once such a create has
succeeded, each setting left out is logged as a warning and recorded as a
`vm.nic_guard.not_enforced` warning event on the VM; a create refused for
another reason records none. A spec kept after a re-create failed past its
teardown (see [storage.md](storage.md)) is kept without them, so `lv run`
accepts it. The refusal is for new input only, `lv` run as root on the host
itself included.

A rebuild or a stack's re-create also makes, before it tears the VM down,
every admission its create will make that the teardown does not change, the
guard admission among them, judged as its create will judge it. That holds
for a stack's default `recreate` strategy as much as for a rolling one. Such
a refusal says "nothing was deleted" (or "nothing was changed") and leaves
the VM as it was. The default compose re-create creates the VM as a new one,
not as the re-create of the old one, unless the VM has a disk on an iSCSI
LUN. So a relaxed guard its file declares needs `network.update` on the NIC's
network there, even when the VM already has it. What the teardown itself
frees (the name, project quota and host capacity) is still judged by the
create, after the teardown.

**A re-create keeps each NIC's guard.** A rebuild or a stack's rolling update
re-creates a VM under a new incarnation. Each of its NICs that is the same NIC
of the incarnation it replaces — the same network, and the same MAC when the
spec names one, else the same position — carries that NIC's guard state: its
record, relaxations included, or **no record** for a NIC that had none — but
only while it carries **at most the trunk VLANs** that incarnation's NICs
carried on that network. A re-create that adds a trunk, or a VLAN to one, makes
the NIC a new NIC: it gets the default guard, and its new VLANs are its
network's to allow. So a workload that predates guards stays unguarded through
its rebuilds and rolling updates, with its IPv6 link-local addresses and its
DHCP address as they were, and a re-create is no way to put it on a VLAN it
never had; every other NIC is new and gets the default. A container keeps its NICs'
guards when it migrates or is relocated.

**When a guard takes effect.** Before the guest's first frame, on every path
that runs it:

- A guarded NIC is rendered under its tap name (`lvt<mac>`) whether or not it
  is running, and every domain start first puts the VM's per-NIC rules in force
  on its host — an API start, a restart policy, an onboot start, a failover
  reschedule, a restore, a snapshot revert. A NIC whose rows are written only
  after its domain starts (a create, a clone, a hot-attach) is rendered from
  the request until they are.
- A guarded NIC whose domain an older release defined has a `vnetN` tap that
  libvirt names only at start. Such a domain is started **paused**; its guard
  is put in force under the tap it actually got, and only then does the guest
  run. A live-snapshot restore is resumed the same way.
- A live move — `lv migrate`, `lv host drain` — asks the target to put the
  guest's rules in force before handing it over; a guest with a `vnetN` guarded
  NIC is handed over paused and runs once its target has (see "Held paused"
  below).
- A container's NICs are put in force before its runtime brings their veths up,
  at its create and at every start — a container that migrated or was
  relocated here by the guard record its first host wrote.
- After a host boots, no guarded VM starts until the daemon has wired its
  firewall and run a first pass: its nft tables are empty until then. That
  first pass is bounded at 60 seconds, so a hung `nft` does not hold the
  daemon's start. A VM with no NIC guard does not wait, and its start runs no
  firewall pass of its own: its NICs are rendered at the next pass, as before
  guards.

If a guarded workload's guards are not in force after the pass — the kernel
refuses the table — it is not started, and the move is refused, rather than run
unguarded; a pass that failed for another reason with the guards in force does
not refuse. A workload whose own guard records cannot be read is treated as
guarded: it is not started or moved. That reads only its own records, so a
VM with no guard starts and moves as before guards whatever another
workload's records say. A NIC with no guard is rendered once it runs, as before. A domain
started paused for its guard that then cannot be resumed is stopped, and the
start fails, rather than left paused.

**Held paused.** A guest handed over paused runs once its target has its
guards in force. The arming before the move tells the target, which records
on its own disk (`<data_dir>/nic-guard-held/`) that it holds the guest, so the
target owns letting it run:

- the source asks the target to resume it, retrying for up to two minutes; a
  retry never resumes a guest partition pause holds;
- whatever becomes of that — a dropped connection, a target daemon restart, an
  arm that ran out of time — the target lets the guest run itself, every ten
  seconds trying again, as soon as its guards are in force there;
- while it holds a guest the target raises the **critical** condition
  `firewall.nic.held`, naming the VM and why;
- the move does not report success: `lv host drain` reports the VM as an
  error, "migrated; held paused on <host> …", and `lv migrate` fails with the
  same, the VM already on its target;
- when the guest arrived but the source could not commit the move's
  ownership (the VM's row still names another host), the source tells the
  target, which keeps the guest paused — it resumes only a guest it owns — and
  names it in `firewall.nic.held` with `lv doctor repair-owner <vm> <host>`;
  once that records the VM on the target, the target lets it run. The
  condition stays while the guest is paused there, also when its VM row
  cannot be read.

The record belongs to that move, not to the VM's name: it resumes only a
domain of the incarnation the move carried (the domain's uuid), and it ends
when the guest runs, when the VM is started on that host, and when another
move arms the VM there. A guest that a later start or move brought to the
host, and that libvirt then pauses for another reason (an I/O error), is not
resumed by it. A record for a guest that never arrived is dropped two hours
after the move began, once its VM is no longer `migrating`.

To resume a held guest now, once its guards can be put in force (the kernel
accepts the per-NIC table, or its guard was turned off): `lv firewall nic-guard
resume <vm>`. It puts the guards in force first and refuses while it cannot,
so the guest never runs unguarded. The alternative, `lv stop` and `lv start`,
reboots the guest. A guest also paused by partition pause is left to it.

**Mixed versions.** Until every host runs this release, a guarded VM is placed,
moved and recovered only onto hosts that enforce NIC guards: on an older host
it would run unguarded while `nic-guard ls` says `on`. Each daemon of this
release sets the host label `litevirt.nic-guards` to its own version after
every firewall pass that put the per-NIC table in force, its first pass at
start included, and clears it after a pass that did not — the kernel refused
the table, or the pass failed or ran out of time — until a pass does. The
label counts only
while the host reports that version, so a host rolled back to an older build —
which reports its own version at start and does not know the label — no longer
counts, and no guarded VM is placed there.

**Relaxing a guard needs authority over its network.** Turning a guard off,
listing allowed addresses, letting the guest answer DHCP, advertise routes or
send VLAN tags lets that guest impersonate the other occupants of its segment,
so it needs `network.update` on the network: on a network a project owns, that
project's network authority; on a shared network or a raw bridge, cluster
root. That applies to `lv firewall nic-guard set` and to the same settings in a
create, attach or deploy request. A re-create (rebuild, a stack's rolling
update) may carry a relaxation the same NIC of the incarnation it replaces had,
and nothing new: not one another of its NICs had, nor one an earlier
incarnation under the same name had. A forwarded
attach whose entry host might be an older build is refused relaxations until
every host runs this release. With no RBAC bindings at all, the legacy role
fallback applies, as for every check: any operator passes.

```
# Per NIC, by MAC or by network (when the VM has one NIC on it)
lv firewall nic-guard set web-1 --network prod --mode on --allow 10.0.0.250 --allow 10.0.0.251
lv firewall nic-guard set lb-1 --mac 52:54:00:12:34:56 --mode on --allow-router-advertisement
lv firewall nic-guard set router-vm --network prod --mode off --allow-vlan-tags
lv firewall nic-guard set --container web --host node-1 --network prod --mode off
lv firewall nic-guard ls [<vm>]      # mode, the source addresses each NIC may use, and its allowances (VMs, then containers)

# At hot-attach and import
lv attach-nic web-1 prod --spoof-guard on --allow-address 10.0.0.250
lv import vm.ova --name legacy --spoof-guard off
```

`--allow` replaces the whole list. `lv firewall nic-guard ls` shows `any` for a
family that is unrestricted and `unset` for a NIC with no guard.

A guard set at runtime on a stack VM's NIC is drift for `lv compose diff` and
`lv compose up` only when the file names a guard setting for that NIC. `up`
sets the file's guard again when that only tightens the guard enforced now.
When it would loosen it, `up` does so only with `--allow-weaken`; without it,
the restore is withheld and the plan says so. A NIC whose file names no guard
setting keeps the runtime guard (docs/compose.md, "Security groups and guards
a file does not declare").

In compose, per NIC:

```yaml
vms:
  vip-holder:
    network:
      - name: prod
        ip: 10.0.0.10
        allowed-addresses: [10.0.0.250]   # the keepalived VIP this guest holds
      - name: lab
        spoof-guard: "off"                # a guest that routes for others
        allow-dhcp-server: true
        allow-router-advertisement: true
        allow-vlan-tags: true             # a trunk
```

The built-in load balancer's VIPs live on the hosts, not in guests, so a guarded
backend needs no allowed address for them; a guest that runs its own
keepalived needs its VIP listed.

Guards are stored per NIC in the replicated `cluster_policies` table under
`nic_guard/<vm>/<mac>` (`nic_guard/ct:<host>:<name>/<mac>` for a container,
under the host it was created on; a container that moved finds its record by
name and MAC), with the incarnation, network and position of the NIC they were
written for. A guard record is the release feature `nic_guards` of
`release_2026_11_v1` (docs/upgrades.md, "Release features"): nothing writes
one until the release token has latched — every host runs this release — and
the first one records the use first. Before that, a NIC is created unguarded
with a warning, as before guards; a request that sets guard options, and
`lv firewall nic-guard set`, are refused with "the cluster upgrade must finish
first (nic_guards needs release_2026_11_v1)", naming the hosts that hold the
release back, rather than silently unguarded. Once a guard exists anywhere, a
host whose own latch has not formed yet (one that just joined) asks the gate,
which forms it there. A NIC's implicit default guard — the one it gets when
the request names no guard setting — never fails a create, clone, import or
hot-attach: its gate call is bounded at three seconds, and if the gate refuses
it or does not answer in time, the NIC is created unguarded, as before guards,
with a warning. While a host does not acknowledge the first use of `nic_guards`
(one in maintenance and powered off, or in release probation), every such
operation waits those three seconds again and creates its NICs unguarded:
`lv cluster upgrade-status` names the host, and bringing it back, or removing
it with `lv cluster voter rm`, ends it. A guard the request names (`spoof_guard`
and the other guard settings, `on` included), and one a re-create carries from
the incarnation it replaces, are never dropped: if the gate refuses them, or
this host's own `failover_scope_v1` latch cannot form, the create fails. A
container whose guards cannot be written for any other reason is not created. A record is retired (tombstoned) when its
VM or container is deleted, and when the VM create that wrote it fails. A
record written for another incarnation of the same VM name guards nothing, and
a create does not wait for it to be in force: records an earlier build's failed
create left live do not block a later create of the name, and the next delete
of that name retires them. A re-create carries only the guard state of the
incarnation it replaces. A NIC's record is also retired when `lv detach-nic`
removes the NIC, once it is gone from the domain, and when an `lv attach-nic`
that wrote it fails and its NIC is verified gone. A record an earlier build
left for a NIC the VM no longer has is not demanded in force once the NIC's row
is tombstoned, and the VM's owner retires it at the VM's next `lv attach-nic`,
`lv migrate` or `lv start`, when no NIC row and neither definition of the
domain on that host has its MAC. The owner judges from its own replica, so it
can retire the record of a NIC whose row has not reached it yet. A retired
record of the running incarnation still guards, with the default guard, a NIC
whose row is live, unless its network cannot enforce a guard; `lv firewall
nic-guard ls` and the compose plan name such a NIC, and `lv firewall nic-guard
set` replaces its guard. A target judges a migration from its own replica, so
a NIC attached moments before the move can arrive before its record. A guard
write behind a stored write for that NIC stamped more than 5 minutes ahead of
this host's clock is refused, naming the stamp; check NTP on the host that
wrote it.

**Neighbour discovery.** A guarded NIC's solicitations and advertisements are
held to the header and one 8-byte option (the link-layer address, or a
duplicate-address-detection nonce), router solicitations to one option: only
the first option is checked against the guest's MAC, so a second one could
otherwise smuggle another. These checks, and the router-advertisement drop,
hold a frame inside a VLAN tag or a priority tag (VID 0) exactly as they hold
an untagged one, wherever the frame reaches them (see "VLAN tags").

## Compose

Per-NIC binding plus reusable group definitions:

```yaml
firewall:
  default-deny: true
  cluster-rules:
    - { direction: egress, proto: tcp, port: 25, action: drop, comment: "block outbound SMTP" }

ipsets:
  trusted_admins:
    cidrs:
      - 10.0.0.5/32
      - 10.0.0.6/32

security-groups:
  web:
    description: "HTTP/HTTPS from anywhere"
    rules:
      - { direction: ingress, proto: tcp, port: 80,  action: accept }
      - { direction: ingress, proto: tcp, port: 443, action: accept }
  ssh-admin:
    rules:
      - { direction: ingress, proto: tcp, port: 22, cidr: "@trusted_admins", action: accept }

vms:
  web-1:
    image: ubuntu-24.04
    network:
      - name: prod
        ip: 10.0.0.10
        security-groups: [web, ssh-admin]
```

Rules without a CIDR match `0.0.0.0/0` (any). `cidr: "@<ipset-name>"`
references a top-level `ipsets:` entry — useful for big admin lists.

## Rule fields

A rule's `proto`, `port` and IPv4 `cidr`, and an ip set's name and elements,
are written into every host's nft ruleset as text, so each is checked against
what nft accepts in that position before it is stored — by `lv sg rule-add`,
`lv firewall cluster-rule add`, `lv firewall host-rule add`,
`lv firewall ipset add`, the web UI and a stack deploy alike. A refused value is
an `InvalidArgument` error that names the field and the value; in a compose
file, the problem names the rule's place in the file.

| Field | Accepted |
|---|---|
| `proto` | `all`, a protocol name (any case) that nft knows itself (`tcp`, `udp`, `udplite`, `esp`, `ah`, `icmp`, `igmp`, `icmpv6`, `gre`, `comp`, `dccp`, `sctp`) or that is listed in lower case in the host's `/etc/protocols` (`ospf`, `ipv6-icmp`), or a number 0-255 (`0x6`; octal after a leading zero, so `08` is not a number) |
| `port` (tcp, udp) | a port 0-65535 (decimal, `0x16`, or octal after a leading zero: nft reads `010` as 8), a range `8000-9000` or `ssh - http` that does not run backwards, a service name listed in the host's `/etc/services` for tcp, udp, sctp, dccp or udplite (`ssh`; not `rtmp`, which is listed for ddp only) |
| `cidr` | an IPv4 address, prefix, range `10.0.0.1-10.0.0.9` or DNS name; one IPv6 address or prefix; `@<ipset>`; `tag:<group>`, naming a tag group that exists |
| ip set name | a letter, `_` or `.`, then letters, digits, `_`, `.`, `-` or `/`; at most 255 bytes, 252 for a set with IPv6 elements; not an nft keyword (`drop`, `ip`, `tcp`, `set`, ...); not starting with `lv_`, which is reserved for litevirt's internal sets |
| ip set element | an IPv4 address, prefix, range or DNS name; an IPv6 address or prefix. `--cidr 10.0.0.1,10.0.0.2` is stored as two elements |
| `action` | `accept`, `drop`, `reject` |
| `comment` | at most 128 bytes, no double quote |

`proto`, `port` and an IPv4 `cidr` also take a relational operator in front
(`!= 22`, `< 1024`, `eq 53`), a bitmask
(`& 255.0.0.0 == 10.0.0.0`) and a braced list (`{ 80, 443 }`; a double or
trailing comma is fine, a leading one is not). A set reference is `@name`,
`!= @name` or `== @name` (`ne`, `eq`) only: nft refuses `< @name`, a set in
braces or behind a mask. It never names an `lv_` set: a tag group is
referenced only as `tag:<group>`. A rule on a set with IPv6 elements applies to both
families, negated or not. A bare comma list (`80,443`) is
refused: nft rejects it, so it never applied — brace it. `<`, `>`, `<=`,
`>=` (`lt`, `gt`, `le`, `ge`) take a single value only, not a braced list, a
range or a prefix, which nft refuses. Anything else — a
second word, a newline, `;`, `#`, a stray brace or quote — is refused, because
it would add nft syntax of its own to every host's ruleset.

A port name resolves against the host's `/etc/services`, and a protocol name
against its `/etc/protocols`, on the host that writes the rule and again on
each host that renders it. Only those files are read: a name nft could resolve
through another NSS source (an `nss_db` database, sss, ldap) is refused at
write and left out at render.

`proto`, `port` and `action` are stored in lower case (`SSH` is stored as
`ssh`): nft resolves a service name only in lower case. A port an older build
stored in upper case is rendered in lower case.

A row written by a host on an older build is checked again when it is rendered.
A row that applied before renders exactly as it did; one that the renderer
would refuse no longer stops the host's whole firewall from applying, as it did
before, and nothing is rendered that the row did not ask for:

- a rule that carries such text, an IPv6 CIDR nft cannot read, or an action
  other than accept, drop or reject is held as this host last rendered it, or
  left out when this host never rendered a readable version of it;
- a rule that references an ip set that does not exist (deleted, or not
  replicated yet) as `@name` is rendered against an empty set of that name, so
  it matches nothing;
- a rule that references a set negated, `!= @name`, while that set is missing
  or was rendered without some of its elements, would match every address (or
  the addresses the set lists), so it is held like an unreadable rule: as this
  host last rendered it while that rendering's set is present and whole,
  otherwise left out;
- a rule whose port or protocol this host's nft cannot resolve (a name
  missing from its `/etc/services` or `/etc/protocols`, a port past 65535 or
  protocol past 255, a range nft reads backwards), whose `<`, `>`, `<=` or
  `>=` stands before a list, range or prefix, or whose IPv4 cidr nft cannot
  read (an octet past 255, a prefix past `/32`, a range that runs backwards)
  is held like an unreadable rule;
- an ip set is rendered without the elements it cannot render (the same
  IPv4 forms), and without its IPv6 elements when its companion's name would
  pass 255 bytes;
- an ip set whose name nft cannot read (a digit or `-` first other than a
  dotted quad such as `1.2.3.4`, longer than 255 bytes, an nft keyword), whose
  name is one of litevirt's internal sets (`lv_gw4`, `lv_nic_devs`, ...) or
  starts with `lv_tg_`, or named `<name>_v6` beside a set `<name>` with IPv6
  elements, is left out, and a rule referencing it is held like an unreadable
  rule. Any other `lv_` set an earlier build stored keeps rendering, with the
  rules on it.

Elements of one set that overlap (`10.0.0.0/8` with `10.0.0.1-10.0.0.5`, or
two ranges that share an address, in one row or across rows of the same name)
are rendered merged into one element; nft refuses overlapping elements.

The host raises the critical condition `firewall.rule.invalid`, which names
each row, its stored action and the command that removes it
(`lv firewall cluster-rule rm <id>`, `lv sg rule-rm <id>`, ...). A rule
rendered against an empty set is named only once that has lasted a minute, so
a rule that replicates just before its set, or a stack redeploy, raises
nothing.

## Firewall tags

A workload's firewall tags are key/value pairs kept apart from its labels.
Labels can be edited by any holder of `vm.update` and are copied by clone,
restore and import, so a label (`fw.`-prefixed or not) never counts as a
firewall tag; copy one over with `lv firewall tag set`.

- `lv firewall tag set` and `lv firewall tag rm` need `sg.write` at `/`
  (Admin or NetworkAdmin; Operator holds only `sg.read`), are refused until
  the cluster upgrade has finished (`firewall_tag_groups`), and leave a
  `firewall.tag.set` / `.rm` audit row with the tags before and after. A key
  and a value are each `[a-z0-9][a-z0-9_.-]{0,62}`, and a workload holds at
  most 64 tags.
- Tags belong to the workload's firewall identity (`fw_id`), which the first
  `tag set` gives it on its host. The identity, and with it the tags, follows
  the workload through a migrate, a relocation, a rebuild, a VM's rolling
  update or recreate in a stack, and a same-name replica promotion. A
  container a stack recreates, the green VM of a blue-green update, a clone,
  an import, a template instance, and a restore under a new name or into a
  freed name are new workloads with none; the delete of the container
  replaced, or of the blue VM, clears its tags.
- When another live workload holds the same identity (a copy), `tag set` and
  `tag rm` give the workload its own identity and clear the copied
  identity's tags from both; the output names the identity replaced and the
  tags cleared, and the clear leaves its own `firewall.tag.rm` audit row.
- Two tag sets of one workload sent to two hosts during a move's handover,
  when each host still believes it owns the workload, keep the last write;
  both are audited.
- A restore into a freed name, and a rebuild or recreate that fails after
  tearing the VM down, print the tags the deleted incarnation left and the
  `lv firewall tag set` command that sets them again.
- `lv cutover` gives the name to the `-next` VM, which keeps its own tags.
  The replaced VM's tags stay with it, and the cutover prints them with the
  command that sets them on the VM now named so.
- Deleting a workload clears its tags, unless another live workload holds
  the same identity (the other side of a move, or a copy), which keeps them.
  A row whose identity no live workload holds is cleared by the failover lease holder 24 hours after the last
  record of that identity, so a move or re-create in flight keeps its tags.
  A row is kept, at any age, while a workload has lost its identity from it
  (see "Fail closed"), or while a workload of its name and kind has a
  relocation or move in flight.
- A container created by a build before the container create spec existed
  (its row has none) cannot be tagged until it is created again.
- `lv inspect` (on stderr, beside the JSON) and `lv ct inspect` print a
  `Firewall tags:` line: the tags, `none`, `none (no firewall identity yet)`,
  `none (a row for an earlier incarnation of this name exists, fw_id <id>,
  not applied)`, or `unreadable` for a row that cannot be read. The web UI's
  VM page shows them read-only, and `lv firewall tag ls` lists unreadable
  rows too.

## Tag groups

A tag group selects workloads by their firewall tags and gives the cluster
one nft set, `lv_tg_<name>`, holding their addresses.

```
lv firewall tag-group set web --match role=web --match env=prod --network prod --sg web-in
lv firewall tag-group ls --members
lv firewall tag-group rm web
```

- A group name is `[a-z][a-z0-9_]{0,30}`. A name ending in `_v6` is refused,
  because `lv_tg_<name>_v6` is the IPv6 companion of another group's set.
- `--match k=v` needs the tag `k` to hold `v`, and `--match k` needs only
  that the workload holds `k`. Every match must hold. `--match k=` and a key
  matched twice are refused.
- A member's addresses are its allocated leases, IPv4 in `lv_tg_<name>`
  and IPv6 in `lv_tg_<name>_v6`. A member with no allocated address is in no
  set; `lv firewall tag-group ls --members` shows it as `no allocated
  address`. A change to a VM's recorded address does not change the set; the
  lease does.
- A VM has an allocated lease only on a network bound to NetBox. On any other
  network a VM adds no address to a group's set, though the group's bindings
  still apply to its NICs there: a `tag:` drop or reject never matches it, so
  bind a security group with `--sg` instead. `lv firewall tag set` warns, naming the
  networks, when the workload has no allocated address on a network a group
  it is a member of covers.
- A rule references the group as `cidr: tag:<name>` (an `lv sg rule-add`, a
  cluster or host rule, a compose security group or `firewall.cluster-rules`
  entry). It is stored as written and rendered as `@lv_tg_<name>`; it applies
  to both families. Writing a rule for a group that does not
  exist is refused.
- `--sg` and `--network` bind security groups: every NIC of every member is
  also bound to the listed security groups, on the listed networks (every
  network when none is listed), merged with the NIC's own.
- `rm` is refused while a rule references `tag:<name>`, the group binds
  security groups to a member's NICs, or the group's row cannot be read. `--force` overrides accept rules and
  the binding, never a drop or reject rule. It also asks `--force` while a
  workload whose tags cannot be read sits on a network the group binds.
- Writing a group, or a rule that references one, is refused until the
  cluster upgrade has finished (`firewall_tag_groups`). `lv` asks the daemon
  before it sends a `tag:` cidr, from a rule, a compose file or a gitops file
  that may hold one, and refuses unless the daemon shows it knows tag groups.

**Propagation.** A host reflects a tag or group change made at `t0` by
`t0 + L + T + pass`: `L` is that host's replication lag, `T` the 30 second
reconcile tick and `pass` one reconcile. The host that takes the write
reconciles at once. Hosts may disagree inside that window:

| Change | A host that has not yet seen it |
|---|---|
| A tag is added | The member's accepts apply later; drops on it apply later |
| A tag is removed, or a lease released | The member is still allowed |
| A lease is reallocated to a non-member | Treated as a removal |

**Established connections survive removal.** `ct state established,related
accept` comes before every rule (see "Stateful conntrack baked in"), and
litevirt does not flush conntrack when a member leaves a group, so a
connection that was accepted keeps passing. To cut one at once, delete it on
the host that carries it: `conntrack -D -s <address>`.

**Fail closed.** Where membership cannot be proven, the host raises a
condition:

- A workload whose tags row cannot be read is a member of no group, and its
  NICs are held at drop on the networks a tag group binds security groups
  on, or on every network while a drop or reject rule names a tag group
  (`firewall.tag_group.tags_unreadable`, critical).
- A workload whose identity another live workload holds too (a copy) is a
  member of no group, and every NIC of each is held at drop; an open move's
  own source and target are not held (`firewall.tag_group.identity_shared`,
  critical).
- A workload with no identity, while a row of an earlier incarnation of its
  name remains (a relocation, a restore or a spec write that did not carry
  the identity), is a member of no group, and its NICs are held as for a row
  that cannot be read (`firewall.tag_group.identity_lost`, critical). A
  container matches only a row recorded on its own host, or on the host a
  relocation record shows it came from; a container with no create spec
  never matches. `lv firewall tag rm`, which the condition names first,
  gives the workload a new identity with no tags and releases the hold.
  `lv firewall tag set` with the row's tags does too, and admits it to the
  groups they match: run it only for the workload the row was recorded for.

  These holds are partial. They are the per-NIC chain's own rules, so
  they come after the cluster and host tiers: traffic those tiers accept
  still passes. Observe mode counts the hold instead of dropping.
- A rule naming a tag group this host does not hold matches nothing when it
  accepts, and loses its address match when it drops or rejects
  (`firewall.tag_group.missing`, critical, named once it has lasted a
  minute). A cluster-tier drop or reject on a missing group therefore denies
  what else it names on every NIC of every host that does not hold the
  group; a `tag-group rm` and a new drop on the group sent through two hosts
  at once can leave one so.
- A group whose row cannot be read is rendered from the last definition this
  host read: its set, its bindings and its rules stay, so an edit that
  narrowed its match does not take effect here, and accepts keep admitting
  the members the old match selected, until the row reads again. When this host never
  read it (the daemon started since), every NIC here of every workload with
  tags is held at drop on every network until it reads again. A group named
  `<x>_v6` while a group `<x>` exists keeps its bindings, but its set cannot
  be declared, so its accepts match nothing and its drops lose their address.
  Each raises `firewall.tag_group.unreadable` (critical).
- A rule stored as a reference to a group's set (`@lv_tg_<name>`,
  `!= @lv_tg_<name>`) is left out, like any reference to one of litevirt's
  own sets, except that a negated drop or reject on a group this host does
  not render denies everyone it names. A user ip set named `lv_tg_*` is left
  out.
- `litevirt_firewall_tag_group_members{group}` counts each group's members
  in this host's view (0 for a group this host cannot read), and
  `lv firewall tag-group ls --members` lists them.

## SYN-flood protection

SYN-flood protection limits new TCP connections toward guest NICs: per guest
NIC and source address (an IPv6 source by its /64), at most `--rate` SYNs per second after a burst of
`--burst`. A SYN past the limit is dropped and counted (`lv-sf 4`, `lv-sf 6` in
`lv firewall show`). It is enforced in the per-NIC table (`bridge
litevirt-nic`), immediately before each guest NIC's ingress rules, so it applies
to traffic from the uplink, from the host and from another guest alike.

```
lv firewall synflood status                                       # cluster policy, then each host's
lv firewall synflood on [--rate 200] [--burst 1000] [--scope <host>]
lv firewall synflood off [--scope <host>]
lv firewall synflood inherit --scope <host>                       # clear a host's own policy
```

- A host's own policy (`--scope <host>`) wins over the cluster's; with
  neither, protection is off. `status` shows, per host, the policy, where it
  comes from (`host` or `cluster`), what the host itself has in force
  (IN FORCE: `on`; `ipv4-only` or `ipv6-only`, the kernel refused the other
  family's rules, whose drops then show `-`; `observe`, counted and not dropped; `guards-only`, no
  bridge conntrack, nothing rendered; `no-guest-nics`, no per-NIC table yet;
  `unavailable`, the kernel refused the rules, or the host's first per-NIC
  table; `off`; `predates`, the host's litevirtd does not report it), and its
  drops per address family since its last reload, asked of every active host
  at once. A per-NIC table the kernel refuses leaves the previous one, and its
  value, in force. The firewall page of the web UI shows the same under "Ask
  every host". A host
  without counts shows `-` and why in ERROR, never a 0: `unreachable` (no
  answer within 10 seconds), `not asked` (not active), `predates` (its
  litevirtd is older) or `reported by the host` (it could not read them).
- `on`, `off` and `inherit` need the operator role, are audited
  (`firewall.synflood`) and are refused until the cluster upgrade has
  finished. `--rate` and `--burst` are each 1-100000 (0 is refused); the
  defaults, 200 and 1000, are Proxmox's.
- A cluster founded by this release is created with protection on at 200/1000.
  A cluster that upgraded has it off until `lv firewall synflood on`, so the
  upgrade drops nothing that worked before.
- Only guest NICs are protected. The host's own input (gRPC, gossip) is never
  limited.
- In observe mode (see "Observe and enforce") a SYN past the limit is not
  dropped: `lv firewall enforce status` counts it as a would-drop with rule
  `synflood`. Read it before enforcing.
- Connections the load balancer's haproxy opens to its backends are accepted
  before the limit, by source, backend address and port. No source is exempt
  otherwise: SYNs from a routed network's gateway (a masqueraded guest) or
  from the host are limited like any other source's.

**The default is low for a proxy in front of backends.** 200 new connections
per second from one source to one backend NIC is reachable by a reverse-proxy
guest, and SYNs the host itself sends to a guest (a health check) count against
the host's address too. Read `lv firewall enforce status` (observe mode) or
`lv firewall synflood status` before relying on the default, and raise `--rate`
where such traffic runs.

**Limits.**

- The meters restart whenever the per-NIC table is reloaded. Any change that
  alters the rendered ruleset reloads both tables on every host: a rule, an ip
  set, a tag-group member or an address anywhere in the cluster.
- Each host keeps at most 65536 sources per address family. A flood from more
  random sources than that (IPv4 addresses, or IPv6 /64s) passes the limiter
  once the meter is full; guests keep their own SYN cookies. Rotating
  addresses within one IPv6 /64 does not escape it, but one IPv6 /48 holds
  65536 /64s, enough to fill the meter, as one IPv4 /16 is.
- The kernel needs `nft_limit`, and IPv6 an nft that keys a set by prefix. The
  daemon checks each address family at start (`nft -c`, nothing loaded); a
  family the kernel refuses is not rendered on that host, the other still is,
  and the host raises `firewall.synflood.unavailable` naming the family while
  the policy is on. Restart the daemon once it can.
- A policy row this build cannot read (not JSON, an unknown mode, `{}`, or a
  rate or burst outside 1-100000) is enforced as on at 200/1000, and the host
  raises `firewall.policy.unreadable` naming the key until it is set again.

## CLI

The CLI lives at `lv sg …` and `lv firewall …`:

```
# Per-NIC tier: CRUD on security groups (through the daemon; audited, needs sg.write)
lv sg create web
lv sg ls
lv sg rule-add <sg-id-or-name> --direction ingress --proto tcp --port 80 --action accept
lv sg rule-ls <sg-id-or-name>
lv sg rm <sg-id>
lv sg bind <vm> --network <net> --sg web        # bind SGs to a NIC at runtime

# Cluster tier: rules applied to every NIC on every host (cluster and host rules,
# ipsets and default-deny need sg.write at /, as security groups do)
lv firewall cluster-rule add --direction ingress --proto tcp --port 443 --action accept
lv firewall cluster-rule ls
lv firewall cluster-rule rm <id>

# Host tier: rules applied to every NIC on one host
lv firewall host-rule add --host node-1 --direction egress --proto tcp --port 25 --action drop
lv firewall host-rule ls [--host node-1]
lv firewall host-rule rm <id>

# Named CIDR lists (reference from a rule with --cidr @<name>)
lv firewall ipset add office --cidr 203.0.113.0/24 --cidr 198.51.100.0/24
lv firewall ipset ls
lv firewall ipset rm <id>

# Default forward policy (no --scope = cluster-wide; --scope <host> overrides one host)
lv firewall default-deny on [--scope node-1]   # --scope names a host that has joined

# Per-NIC anti-spoofing (see "NIC guards")
lv firewall nic-guard set <vm> --network <net> --mode on --allow 10.0.0.250
lv firewall nic-guard ls
lv firewall nic-guard resume <vm>   # a VM held paused for its guards (see "Held paused")

# Observe or enforce the per-NIC rules (see "Observe and enforce")
lv firewall enforce status

# Per-workload firewall tags (see "Firewall tags"); web-1 is a VM on a NetBox-bound network
lv firewall tag set web-1 role=web env=prod
lv firewall tag set cache-1 --container --host node-2 role=web
lv firewall tag rm web-1 env
lv firewall tag ls [web-1]

# Logging (see "Logging")
lv sg rule-add web --direction ingress --proto tcp --port 22 --action drop --log
lv firewall log-policy on [--scope node-1] [--rate 5] [--burst 10]
lv firewall log --workload web-1 --since 15m [--follow]

# Tag groups: rules reference one with --cidr tag:<name>
lv firewall tag-group set web --match role=web [--match env=prod] [--network prod] [--sg web-in]
lv firewall tag-group ls [--members]
lv firewall tag-group rm web [--force]

# SYN-flood protection on guest NICs (see "SYN-flood protection")
lv firewall synflood on --rate 500 --burst 2000
lv firewall synflood status

# Inspect the live rulesets on this host (litevirt-fw and litevirt-nic) / force a reconcile now
lv firewall show
lv firewall reload
```

CLI mutations propagate via Corrosion's CRDT replication; every host's
reconciler picks them up on its next poll (or immediately via
`lv firewall reload`). Per-NIC security groups bind via compose
`network[].security-groups` or `lv sg bind --network`; the cluster-tier
rules, host-tier rules, ipsets, and default-deny policy are also persisted in
cluster state and loaded by the reconciler's `CorrosionPlanLoader`.

## Rule macros

`--macro <name>` on `lv sg rule-add`, `lv firewall cluster-rule add` and
`lv firewall host-rule add` adds one ordinary rule per row of a named macro.
`lv firewall macros` lists the catalog. Names are case-insensitive. A macro row
is a tcp or udp destination port; there is no ICMP macro.

- `--macro` cannot be combined with `--proto` or `--port`.
- `--direction`, `--cidr`, `--action` and `--priority` apply to every row.
- The CLI expands the macro and makes one call per row, printing every rule id.
  Nothing records the macro name on the stored rule. If a call fails, the rows
  already created are removed.
- Cluster and host rows carry the comment `macro <NAME>` unless `--comment` is
  given. Security-group rules have no comment column.

```
lv sg rule-add web --macro SSH --cidr @admins
lv firewall cluster-rule add --macro DNS --direction egress
lv firewall host-rule add --host node-1 --macro HTTPS
```

## Logging

A rule added with `--log` (compose `log: true`) logs each packet it matches,
and `lv firewall log-policy on` logs each guest NIC's default verdict. The
records go to the daemon, never to the kernel log or the journal: every log
line is `log group <G> snaplen 96`, sending the packet's first 96 bytes to
NFLOG group `firewall.log_group` (default 27), which the daemon reads. Log
lines are rendered only while the daemon's own listener holds that group. A
stopping daemon removes them before it exits. They can outlive the listener
only after a crash (until the next start's first pass) and, after the
listener loses the group, for the length of the firewall pass that removes
them; a program that binds the group in such a window receives records.

```
lv sg rule-add web --direction ingress --proto tcp --port 22 --action drop --log
lv firewall cluster-rule add --direction ingress --proto tcp --port 25 --action reject --log
lv firewall log-policy status
lv firewall log-policy on [--scope <host>] [--rate 5] [--burst 10]
lv firewall log-policy off [--scope <host>]
lv firewall log-policy inherit --scope <host>
lv firewall log [--host <h>] [--workload <name>] [--since 15m] [--limit 200] [--follow]
```

- `--action drop+log` is refused: the action stays the verdict. Listings show
  a logged rule's action as `drop log`, and the API carries `log` beside the
  plain action.
- A logged rule and a log-policy write are refused until the cluster upgrade
  has finished (release feature `firewall_log`). `lv` asks the daemon first and
  refuses `--log` against one that predates logging.
- `lv firewall log-policy` needs role operator and is audited as
  `firewall.log_policy`. A host's policy wins over the cluster's; with
  neither, the default verdict is not logged. `--rate` (records a second) and
  `--burst` are each 1-10000, default 5 and 10. A stored policy this build
  cannot read is read as off at the default budget and raises
  `firewall.policy.unreadable`.
- Reading the log needs the verb `firewall.log.view` at `/`, which among the
  built-in roles only Admin holds (docs/auth.md). Without `--host`,
  `lv firewall log` asks every active host and merges the records by time; a
  host that does not answer is named. `--follow` polls from each host's newest
  record.

**Budgets and fairness.**

- Each guest NIC side has its own budget, `--rate`/s with `--burst`, shared by
  every log line of that side: a guest can cause at most that many records a
  second per NIC side, whatever it sends. A record past the budget is not
  written; the packet still gets its verdict.
- Rules in the cluster and host tiers also log routed traffic, under one
  budget per table (`lv_lg_routed` in each of the two tables), so a host's
  routed log can reach twice the rate. Routed traffic dropped by the default
  policy is not logged; only the per-NIC default verdict is.
- In observe mode a per-NIC drop is logged as `would-drop`; a frame a tier
  rule also drops on the routed path is logged twice, once as `would-drop` and
  once as `drop`.
- The routed budget and the host's cap are first come, first served: one busy
  flow can use them up, and an attacker can do that on purpose to keep other
  traffic out of the log. The per-NIC budgets are not affected.
- The daemon keeps at most `firewall.log_max_rate` records a second (default
  200) across the host. `litevirt_firewall_log_records_total{outcome}` counts
  records `kept`, `rate_limited` by that cap, and lost to `overflow` (the
  kernel dropped them before the daemon read them).
- The kernel sends records to the daemon within about 10 ms, or at once when
  16 are waiting. A record's time is the kernel's timestamp of the packet. A
  packet the host itself sends has none, so its record carries the time the
  daemon read it, within about 10 ms of the packet. The JSON lines on disk say
  which as `time_source`: `packet` or `received`. A record with no
  `time_source` was written by an older build.

**Kernel support.** At start the daemon checks, with `nft -c`, that the kernel
loads a named limit and a log line to its group (`nft_log`,
`nfnetlink_log`, `nft_limit`). A host that refuses them renders no log line,
keeps its per-NIC table, and raises `firewall.log.unavailable`; loading the
modules later takes a daemon restart. A group the daemon cannot hold (another
program holds it) raises `firewall.log.listener`, and no log line is rendered
until the daemon holds it: packets are not logged on that host. Losing the
group removes the lines in the next pass, run at once, and holding it again
restores them.

**Data at rest.** Records name any tenant's addresses and ports.

- The daemon keeps the newest 10,000 in memory and writes JSON lines under
  `<data_dir>/firewall-log/` (directory 0700, files 0600), rotated so the
  directory never holds more than `firewall.log_retain_mib` (default 64; 0
  keeps memory only, and removes the log files at the next start), checked by
  size, so lowering the cap takes effect at the next start. Records older than `firewall.log_retain_days` (default 7; 0 for
  no age bound) are removed, on disk and in memory, within about an hour of
  passing it: a file spans at most an hour (or a 24th of the bound, when
  shorter) and goes once its newest record is past the bound.
- No litevirt backup includes `<data_dir>`. `lv uninstall` removes it unless
  `--keep-data` is given. `lv host rm` does not touch the removed host's disk:
  delete `<data_dir>/firewall-log/` there.

## Audit trail

Every firewall-policy change made through the daemon lands in the signed
audit log (`lv audit ls`, see [audit-log.md](audit-log.md)). That covers the
CLI, the REST API and the web UI alike, because all three reach the same gRPC
handlers with the caller's own credential. The same handler therefore decides
who may make a change and records it: security-group edits need `sg.write` at
`/` (Admin or NetworkAdmin) whether they come from `lv sg` or the web UI, and
the row names the user the session belongs to. So do cluster and host rules,
ip sets and default policies (`lv firewall cluster-rule add/rm`,
`lv firewall host-rule add/rm`, `lv firewall ipset add/rm`,
`lv firewall default-deny`, and the same actions in the UI): they are global
rows every host enforces, as a stack's firewall is. Operator holds only
`sg.read`, and its refusal names the grant that lets it:
`lv role grant NetworkAdmin <principal> --path / --propagate`. A caller with
no role binding of its own falls back to its legacy role, where operator
passes.

| Action | Target | Recorded by |
|---|---|---|
| `firewall.default-deny` | the scope (`cluster` or a host name) | `lv firewall default-deny`, UI default-policy toggle |
| `firewall.cluster-rule.add` / `.rm` | rule id | `lv firewall cluster-rule add/rm`, UI |
| `firewall.host-rule.add` / `.rm` | rule id | `lv firewall host-rule add/rm`, UI |
| `firewall.ipset.add` / `.rm` | set name (add) / set id (rm) | `lv firewall ipset add/rm`, UI |
| `sg.bind` | VM name | `lv sg bind`, `POST /api/v1/vms/bind-sgs` |
| `sg.add` / `sg.rm` | group name (add) / group id (rm) | `lv sg create/rm`, UI |
| `sg.rule.add` / `sg.rule.rm` | group id (add) / rule id (rm) | `lv sg rule-add/rule-rm`, UI |
| `nic.guard.set` | VM name, or `ct:<host>/<name>` | `lv firewall nic-guard set` |
| `firewall.enforcement` | `cluster` | `lv firewall enforce on/off` |
| `firewall.tag.set` / `.rm` | VM name, or `<host>/<name>` for a container | `lv firewall tag set/rm` |
| `firewall.tag_group.set` / `.rm` | group name | `lv firewall tag-group set/rm` |
| `firewall.log_policy` | `(cluster)` for the cluster policy, or the host name | `lv firewall log-policy on/off/inherit` |
| `firewall.synflood` | `cluster`, or `host/<name>` for a host's policy | `lv firewall synflood on/off/inherit`; the genesis seed of a new cluster, by `litevirt` |

The row's user is the authenticated caller. Its detail records the policy
before and after the change, in the form `before=<state> after=<state>`:

```
firewall.default-deny      cluster   before=deny after=accept
firewall.cluster-rule.rm   9f2c…     before={ingress tcp port=22 cidr=10.0.0.0/8 accept priority=100} after=none
sg.bind                    web-1     network=lan before=[isolate] after=[web,ssh]
```

The before-state matters most on a removal. A removed rule is tombstoned, so
after that the audit row is the only record of which port the removal opened.
A state is one of:

- `{…}`: the rule, ip set or group, with every field that decides what it
  matches or does. A removed group lists the rules that went with it.
- `none`: a read that succeeded found no such row.
- `unset`: no default policy for the scope, so it inherits (cluster: accept).
- `unknown(<error>)`: the read failed, so the row claims nothing about what
  was there. A failed read is never recorded as `none`.

`lv sg create`, `lv sg rm`, `lv sg rule-add` and `lv sg rule-rm` go through
the daemon's `CreateSecurityGroup`, `DeleteSecurityGroup`,
`AddSecurityGroupRule` and `RemoveSecurityGroupRule` RPCs. Before that they
wrote the host's Corrosion database straight from the CLI process, which
skipped authorization and left no audit row. Each RPC checks the `sg.write`
verb at `/` (Admin and NetworkAdmin hold it; Operator holds only `sg.read`; a
cluster with no role bindings falls back to the operator role), and re-renders
the connected host's ruleset at once, as the other tiers do. A group created
with `lv sg create <name> --project <p>` belongs to project `p`: its writes
check `sg.write` on `/projects/<p>/security_groups/<name>` instead, so a
NetworkAdmin bound on `/projects/<p>` manages it, and only `p`'s workloads may
bind it. A NIC of any other project that names it is refused where the binding
is written (create, NIC attach, `lv sg bind`, clone, restore) and is rendered
without it. Group names stay unique across projects. A project's group must
name an existing project, and an IPv6, logged or tag-group rule on one still
needs `sg.write` at `/`. Project groups are the release feature `sg_projects`
(see [design/security-group-projects.md](design/security-group-projects.md)).
`lv compose up` of a stack with a firewall block needs `sg.write` at `/`: its
groups, ip sets and default policy are global. So do `lv compose up` and
`lv compose down` of a stack that already has a firewall: it owns firewall
rows, or its stored compose file declares a firewall block (a default-deny it
only asks for while another stack owns the row included), or that file cannot
be read. Both are refused before anything changes, and the refusal names the
exits: `lv role grant NetworkAdmin <principal> --path / --propagate`, or an
Admin runs the command. The plan `lv compose up` shows before it applies lists
the refusal as a warning. `lv compose down` on a node that holds no record of
the stack, by a caller without `sg.write` at `/`, removes only the workloads
that node lists, and nothing retries one it cannot delete. It leaves whatever
of the stack's record, load balancer, networks, backup-repo registrations and
firewall exists anywhere: a first `lv compose up` that failed leaves its
workloads, its networks and its backup-repo registrations, and no record. The
CLI, the UI and the REST API (`local_only`, `notice`) all say so. An Admin
removes the rest with `lv compose down --name <stack>`, from any node, whether
or not a stack record exists. Against a daemon
older than these RPCs the four commands fail with an error saying to upgrade
litevirtd; they do not fall back to writing the database.

`lv sg ls` and `lv sg rule-ls`, and the web UI, read security groups through
the `ListSecurityGroups` RPC with the caller's credential. The CLI reads the
node's local database instead only when no daemon answered: the CLI has no
credentials to connect with, the daemon is down, it predates the RPC, or it
does not accept the credential (a revoked session). It says so on stderr when
it does. A caller the daemon authenticated and refused gets the refusal; that
is never routed around. `sg.read` at `/` (every built-in role with `*.read` or
`sg.read` holds it; with no role bindings, any viewer) lists every group and
rule. A token scoped to a project, or a grant below the cluster root, lists
only the groups of projects it holds `sg.read` on; `lv sg ls --project <p>`
adds the global groups, without their rules, since `p`'s workloads may bind
them.

## Default-deny rollout

Default-deny applies **per guest NIC, in both directions**, on every path the
NIC's traffic takes — including traffic between the guest and its own host,
which the old forward-hook placement never filtered. DHCP toward the link's
server, DNS to a managed network's gateway, the built-in load balancer's
traffic to its backends — from the host its haproxy runs on, on whichever host
the backend runs — and link-scoped neighbour discovery always pass.
Routed traffic that involves no guest NIC is still judged by the `inet` forward
chain's cluster and host tiers and policy. On an upgraded cluster, run in
observe mode first and read `lv firewall enforce status` before
`lv firewall enforce on`.

Switching a running cluster to default-deny is risky if a rule is
missing. Recommended order:

1. Define every needed SG with its rules; bind to NICs.
2. Run with `default-deny: false` for a few days. The reconciler
   applies all rules but the policy stays accept — every miss merely
   logs.
3. Audit `nft list table inet litevirt-fw` per host to confirm rules
   look right.
4. Flip `default-deny: true` and re-deploy the stack.

## Per-NIC SG binding + reload

- **Per-NIC SG binding** — the `security_groups` JSON column of the NIC's
  `vm_nics` row, or of its `vm_interfaces` row when it has no `vm_nics` row.
  Compose `network[].security-groups: [web]` persists on VM create, and
  clone, promote, live-restore and NIC hot-attach carry the NIC's groups
  too; `lv sg bind <vm> --network <net> --sg web` mutates at runtime: it
  rewrites the NIC's `vm_nics` row (and its `vm_interfaces` row, for peers on
  an older build), so the next reconcile applies it. A bind naming a network
  the VM has no NIC on is refused rather than answered OK.
  A runtime bind of a stack VM's NIC is drift for `lv compose diff` and
  `lv compose up` only when the file declares that NIC's `security-groups:`.
  `up` rebinds the file's list only with `--allow-weaken`; without it, the
  rebind is withheld and the plan says so. A NIC whose file names no groups
  keeps the runtime binding, through a recreate too (docs/compose.md,
  "Security groups and guards a file does not declare").
- **The chain follows the tap libvirt gives the NIC now.** libvirt hands out
  a new `vnetN` on every start, so the tap recorded at create is stale after
  a stop and start, a migration or a failover. Every tick the reconciler asks
  libvirt for each local NIC's tap by MAC and binds the chain to that; a NIC
  of a VM that is not running has no tap and gets no chain. A running VM
  whose NIC libvirt cannot name is logged as a warning, because that NIC is
  not filtered. If libvirt cannot be asked at all (the connection is down,
  libvirtd is restarting, or it does not answer within 10s), the pass fails
  and the ruleset already applied stays in place; `lv firewall show` reports
  the error.
- **Group names are unique, and a duplicate fails closed.** `lv sg create`
  and a stack deploy refuse a name another live group holds. Two live groups
  can still share a name (rows written before this check, by a node on an
  older build, or by two nodes racing). The reconciler cannot know which one
  a NIC meant, so it renders neither: every NIC bound to that name gets a
  chain that drops all new traffic in both directions (replies to existing
  connections still pass), a warning is logged each tick, and
  `litevirt_firewall_sg_duplicate_name_nics{sg}` counts the NICs held.
  `lv sg ls` shows both ids; remove one with `lv sg rm <sg-id>` (or, for a
  stack's group, rename it in the compose file and re-deploy) to release
  them.
- **Containers get identical per-NIC enforcement on their veth.** A managed
  container NIC's `container_interfaces.security_groups` binds to its
  deterministic veth exactly like a VM NIC binds to its tap — the same
  `CorrosionPlanLoader` emits a `nic_<veth>` chain (host-scoped, live containers
  only, skipping a NIC with no veth yet). Set at create with
  `lv ct create --network network=<net>,security-groups=web;db` (or compose). A
  day-2 CT-aware rebind (the `lv sg bind` analogue) is a follow-up.
- **`lv firewall reload` actually forces** — `ReloadFirewall` RPC
  drives the local reconciler synchronously and returns a
  `FirewallStatus` snapshot.

## What's still in flight

- The link-layer address option is checked where every stack puts it (the
  first option); a crafted solicitation with it later is not.
- Reservations are IPv4; a DHCPv6 lease is confined to the subnet.
- IGMP-specific rules.
