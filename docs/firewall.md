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
    MAC in ARP and neighbour discovery, and may not answer DHCP (unless the
    guard allows it) or advertise a router, but it is **not** checked against
    the NIC's addresses: the addresses a guest uses inside a VLAN are no one's
    to know. So an IPv4 or IPv6 source, a link-local address, a neighbour
    advertisement's target and an ARP sender address are all unchecked inside a
    VLAN tag;
  - a **priority-tagged** frame (VID 0) is native-VLAN traffic (the host and a
    `vlan_filtering` bridge treat it as untagged), so it is held to the NIC's
    addresses exactly as an untagged frame is;
  - a **doubled** tag (an 802.1ad outer tag, or an 802.1Q tag inside the outer
    one) is dropped: the checks above cannot see inside it. QinQ through a
    guarded NIC needs the guard off (`--mode off`).
  A guarded trunk NIC is held the same way for a single tag, and its doubled
  tags are dropped by its confinement (above). The NIC-guard list below states
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
new NICs enforce in either mode — they protect new NICs only.

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
replica that has caught up with its peers (or is the cluster's only host). No
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
- **SNAT** — a load balancer on a host-isolated network rewrites guest egress to
  its VIP (`oifname <uplink> ip saddr <subnet> snat to <vip>`), emitted before
  masquerade.
- **Host isolation** — an `input` chain drops guest→host traffic per isolated
  bridge (`iifname <bridge> drop`), punching through VRRP + declared LB VIP ports
  first so guests can still reach an HAProxy VIP.

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
  `@<name>` matches either. Do not name another set `<name>_v6`.
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
default guard, not its source's relaxations or its source's lack of a record. A macvtap (`direct`) NIC bypasses
the bridge and gets no guard; setting one is refused.

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
VM or container is deleted, and a record written for another incarnation of the
same VM name guards nothing; a re-create carries only the guard state of the
incarnation it replaces.

**Neighbour discovery.** A guarded NIC's solicitations and advertisements are
held to the header and one 8-byte option (the link-layer address, or a
duplicate-address-detection nonce), router solicitations to one option: only
the first option is checked against the guest's MAC, so a second one could
otherwise smuggle another.

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

# Cluster tier: rules applied to every NIC on every host
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
lv firewall default-deny on [--scope node-1]

# Per-NIC anti-spoofing (see "NIC guards")
lv firewall nic-guard set <vm> --network <net> --mode on --allow 10.0.0.250
lv firewall nic-guard ls
lv firewall nic-guard resume <vm>   # a VM held paused for its guards (see "Held paused")

# Observe or enforce the per-NIC rules (see "Observe and enforce")
lv firewall enforce status

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

## Audit trail

Every firewall-policy change made through the daemon lands in the signed
audit log (`lv audit ls`, see [audit-log.md](audit-log.md)). That covers the
CLI, the REST API and the web UI alike, because all three reach the same gRPC
handlers with the caller's own credential. The same handler therefore decides
who may make a change and records it: security-group edits need `sg.write` at
`/` (Admin or NetworkAdmin) whether they come from `lv sg` or the web UI, and
the row names the user the session belongs to.

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
the connected host's ruleset at once, as the other tiers do. Against a daemon
older than these RPCs the four commands fail with an error saying to upgrade
litevirtd; they do not fall back to writing the database.

`lv sg ls` and `lv sg rule-ls`, and the web UI, read security groups through
the `ListSecurityGroups` RPC with the caller's credential. The CLI reads the
node's local database instead only when no daemon answered: the CLI has no
credentials to connect with, the daemon is down, it predates the RPC, or it
does not accept the credential (a revoked session). It says so on stderr when
it does. A caller the daemon authenticated and refused gets the refusal; that
is never routed around. The RPC checks the `sg.read` verb
at `/` (every built-in role with `*.read` or `sg.read` holds it; with no role
bindings, any viewer), so a token scoped to a project, or a grant below the
cluster root, gets a 403 on `/security-groups`, no group names in the
Add-NIC dialog, and a permission error from `lv sg ls` and `lv sg rule-ls`.

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
- Application-aware logging (`log prefix`, `log group`) for
  rejected packets — useful in deny-by-default audits.
