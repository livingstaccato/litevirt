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

Rules are evaluated top-to-bottom inside the kernel forward chain:

1. **Cluster default** (`cluster_default` chain) — applies to every
   NIC. Use it for blanket policy such as "block any forward to
   RFC1918 from the public VLAN".
2. **Host overrides** (`host_overrides` chain) — applies to every NIC
   on this host. Use it for host-local exceptions: "allow this NFS
   server to reach all OSDs."
3. **Per-NIC rules** (`nic_<dev>` chain) — security groups + per-NIC
   extras. This is the layer compose mostly cares about.

Each chain is a regular nftables chain; the forward chain hooks the
netfilter forward path and `jump`s into the three tiers in order.

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

So reply traffic is always allowed. Rules need only describe the
*new connection* direction. Default-deny mode is therefore safe: the
SSH SYN you allow keeps its reply path open without you writing a
matching egress rule.

## Direction semantics

litevirt follows the AWS / GCP / Proxmox convention:

| Direction | What it means | nftables match |
|---|---|---|
| `ingress` | traffic ARRIVING at the VM | `oifname <tap>`, `ip saddr` |
| `egress`  | traffic LEAVING the VM | `iifname <tap>`, `ip daddr` |

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
lv sg rule-add <sg-id> --direction ingress --proto tcp --port 80 --action accept
lv sg rule-ls <sg-id>
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

# Inspect the live ruleset on this host / force a reconcile now
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
credentials to connect with, the daemon is down, or it predates the RPC. It
says so on stderr when it does. A refusal is
never routed around that way. The RPC checks the `sg.read` verb
at `/` (every built-in role with `*.read` or `sg.read` holds it; with no role
bindings, any viewer), so a token scoped to a project, or a grant below the
cluster root, gets a 403 on `/security-groups`, no group names in the
Add-NIC dialog, and a permission error from `lv sg ls` and `lv sg rule-ls`.

## Default-deny rollout

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

- IPv6 is staged behind the IPv4-first matchers. Render emits
  `ip protocol`; an `ip6` parallel pass is mechanical. Until then, an IPv6
  CIDR in a rule or ipset is **rejected at validation** (rather than silently
  mis-rendered into an invalid rule that would poison the whole ruleset) — so
  security-group rules are IPv4-only for now.
- ICMPv6 + IGMP support.
- Application-aware logging (`log prefix`, `log group`) for
  rejected packets — useful in deny-by-default audits.
