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

A guest's NIC (a VM's `vnetN` tap, a container's veth) is a port of a Linux
bridge, so per-NIC policy is enforced in a **bridge-family** table,
`bridge litevirt-nic`, on the hooks every frame through a bridge port passes:

| Path | Hook | Chain run |
|---|---|---|
| guest to guest on one bridge | bridge `forward` | sender's `nic_out_<dev>`, then receiver's `nic_in_<dev>` |
| guest to the host, or to be routed out | bridge `input` | sender's `nic_out_<dev>` |
| the host, or routed traffic, to a guest | bridge `output` | receiver's `nic_in_<dev>` |

`nic_out_<dev>` holds every tier's **egress** rules for that NIC (cluster, then
host, then each bound security group, then the NIC's own rules) and
`nic_in_<dev>` holds the **ingress** rules, first match wins. An egress
`accept` lets the frame go on to the receiver's ingress rules rather than
ending the evaluation, so traffic between two guests must be allowed by the
sender's egress rules **and** the receiver's ingress rules. Under default-deny
each chain ends in `drop`.

Every filtering chain first accepts established and related traffic, frames
that are not IP or IPv6 (ARP and the rest of layer 2 are the
[NIC guard](#nic-guards)'s business), the ICMPv6 that IPv6 needs (neighbour
and router discovery, MLD, and the errors path-MTU discovery uses), and DHCP and
DHCPv6 client/server exchanges, so a guest can always get an address and find
its neighbours.

Replies are recognised by bridge connection tracking, `nf_conntrack_bridge`,
which the daemon loads (`modprobe`) the first time it applies a per-NIC table.
`br_netfilter` is not needed and not used.

**This replaces an enforcement point that did not work.** Before, the per-NIC
chains lived in the `inet` forward hook and matched the tap by
`iifname`/`oifname`. Traffic between two guests on one bridge never reaches that
hook, and with `br_netfilter` loaded the hook sees the bridge, not the tap, so
security groups were not enforced on guest-to-guest traffic at all, nor on
traffic between a guest and its host. The rules were rendered and listed by
`lv firewall show`, which is why nothing caught it.

The `inet litevirt-fw` table keeps the forward chain for routed traffic that
involves no guest NIC (cluster and host tiers, then the default policy), and
accepts there anything to or from a bridge that carries guest NICs, since that
traffic was already decided per NIC on the bridge. With nothing to enforce per
NIC (no guard, no rule of any tier, default policy accept) no bridge table is
rendered at all.

Each host replaces both tables in **one** `nft -f` transaction, so moving
enforcement from the old hook to the new one on upgrade never leaves a moment
with neither applied. A table the daemon no longer renders is deleted on the
next apply, because libvirt reuses `vnetN` names and a stale chain would hold
the next VM to get that name to another VM's policy.

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

## IPv6

Rules take IPv6 CIDRs and the `icmpv6` protocol, and ip sets take IPv6
elements, in every tier:

```
lv firewall cluster-rule add --direction ingress --proto tcp --port 22 --cidr 2001:db8::/32 --action accept
lv firewall cluster-rule add --direction ingress --proto icmpv6 --action accept
lv firewall ipset add admins --cidr 10.0.0.0/8 --cidr 2001:db8:1::/48
```

- An IPv6 CIDR renders as `ip6 saddr` / `ip6 daddr`. `icmp` is ICMP for IPv4
  and `icmpv6` (or `ipv6-icmp`) is ICMPv6; a rule pairing either with the
  other family's CIDR is refused, since it could match nothing.
- nftables sets are typed, so a set holding both families renders as the IPv4
  set `<name>` plus an IPv6 companion `<name>_v6`, and a rule referencing
  `@<name>` matches either. Do not name another set `<name>_v6`.
- A rule without a CIDR on `tcp`, `udp` or `all` matches both families, as it
  always did.
- Neighbour discovery, router solicitation and advertisement, MLD and the
  ICMPv6 errors are accepted ahead of every tier, so a drop-everything rule or a
  default-deny policy does not break IPv6 itself.

**Rolling upgrade.** Until every host runs a build that renders IPv6, an IPv6
rule would make an older host refuse its whole firewall plan, so nothing writes
one until the mandatory, replication-gated capability `firewall_ipv6_v1` has
latched. Before that, adding one fails with FailedPrecondition naming the
token; IPv4 rules are unaffected.

## NIC guards

A NIC guard holds a guest NIC to its own identity on the wire (Proxmox's
`ipfilter` / `macfilter`, plus DHCP and router-advertisement guards). It runs at
the bridge `prerouting` hook, ahead of everything else, and drops what a
guarded guest sends:

- from any MAC but the NIC's own;
- as an 802.1Q / 802.1ad tagged frame (its payload cannot be checked);
- ARP that claims another MAC, or another IPv4 address than the guest's;
- IPv4 from an address that is not the guest's (a DHCP client asking for one,
  from `0.0.0.0`, still passes);
- IPv6 from an address that is not the guest's (link-local and the unspecified
  address used by duplicate address detection always pass), and neighbour
  advertisements for an address that is not the guest's — the IPv6 form of ARP
  spoofing;
- DHCP and DHCPv6 server replies, unless the guard allows the guest to answer
  DHCP;
- router advertisements and redirects, unless the guard allows the guest to act
  as a router.

**Which addresses are the guest's.** For each family:

- an address litevirt assigned the NIC (a static `ip:`, an IPAM or NetBox
  address, a static `ipv6:`), plus the guard's **allowed addresses**;
- with no assigned address of that family, the network's `subnet:` (a guest
  that takes a DHCP lease from litevirt's dnsmasq gets some address in it, and
  litevirt does not track which), plus the allowed addresses;
- with neither and no allowed address of that family: **unrestricted**. A guest
  on a plain bridge served by a DHCP server or router litevirt does not run has
  addresses nobody told litevirt about, and cutting it off would break it. The
  MAC, ARP-sender-MAC, VLAN, DHCP-server and router-advertisement guards still
  apply.

Listing an allowed address of a family restricts that family: on a network
where litevirt does not know the guest's address, list that address (or its
subnet) too.

**Defaults.** A NIC created by this release — `CreateVM`, a compose deploy, a
rebuild, a clone or `lv attach-nic` — is guarded unless its request says
otherwise. A NIC that existed before has **no guard** and keeps working exactly
as it did, whatever addresses it uses; set one with `lv firewall nic-guard set`.
An imported VM (`lv import`) is not guarded by default either, since its guest
was addressed before litevirt knew it. A clone gets the default guard, not its
source's relaxations. A macvtap (`direct`) NIC bypasses the bridge and gets no
guard.

**Relaxing a guard needs cluster-root authority.** Turning a guard off, listing
allowed addresses, or letting the guest answer DHCP or advertise routes lets
that guest impersonate other tenants' addresses, so it needs `network.update` at
`/` — a NetworkAdmin of one project cannot do it for a VM in that project. That
applies to `lv firewall nic-guard set` and to the same settings in a create or
deploy request. A rebuild carries the guard its original create stored.

```
# Per NIC, by MAC or by network (when the VM has one NIC on it)
lv firewall nic-guard set web-1 --network prod --mode on --allow 10.0.0.250 --allow 10.0.0.251
lv firewall nic-guard set lb-1 --mac 52:54:00:12:34:56 --mode on --allow-router-advertisement
lv firewall nic-guard set router-vm --network prod --mode off
lv firewall nic-guard ls [<vm>]      # mode, the source addresses each NIC may use, and its allowances

# At hot-attach
lv attach-nic web-1 prod --spoof-guard on --allow-address 10.0.0.250
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
```

The built-in load balancer's VIPs live on the hosts, not in guests, so a guarded
backend needs no allowed address for them; a guest that runs its own
keepalived needs its VIP listed.

Guards are stored per NIC in the replicated `cluster_policies` table under
`nic_guard/<vm>/<mac>`, which nothing writes until `failover_scope_v1` has
latched. Before that, a NIC is created unguarded with a warning, and a request
that sets guard options is refused rather than silently unguarded. A record
outlives its VM, harmlessly: a NIC created under the same VM name and MAC
writes its own.

Containers are not guarded yet: their NICs keep their per-NIC rules but get
no guard.


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
| `nic.guard.set` | VM name | `lv firewall nic-guard set` |

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
NIC's traffic takes — including traffic between the guest and its own host
(DNS to the host's dnsmasq, for example), which the old forward-hook placement
never filtered. DHCP, DHCPv6 and the essential ICMPv6 always pass. Routed
traffic that involves no guest NIC is still judged by the `inet` forward
chain's cluster and host tiers and policy.

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

- NIC guards for containers.
- Guest-tagged VLAN frames from an *unguarded* NIC are not judged by the
  per-NIC rules (only IP and IPv6 frames are); a guarded NIC may not send them.
- IGMP-specific rules.
- Application-aware logging (`log prefix`, `log group`) for
  rejected packets — useful in deny-by-default audits.
