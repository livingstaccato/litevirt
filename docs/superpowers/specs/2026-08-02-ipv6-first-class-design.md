# IPv6 as a First-Class Feature (§F P1)

**Date:** 2026-08-02

**Status:** Draft — awaiting Tim's review. Directive (Tim, 2026-08-02): "IPv6 is
treated as a first class citizen/feature in the future. The lab needs to be set
up to support IPv6 as well as IPv4."

## Purpose

litevirt's cluster transport is IPv4-only, and until 2026-08-02 an IPv6 address
could *enter* the cluster (via `advertise_address` or a dual-stack hostname on
`lv host add`) and half-work: the row replicated, gossip looked healthy, but the
gRPC listener binds `0.0.0.0`, the peer probe built its target with `%s:%d`
(mangling a v6 literal into an unparseable string), and every health probe
failed — a config value silently becoming a fencing event.

The guardrail commits (`800002a`…`aadd3f6`, PR #125) made that state
unreachable: `advertise_address` must be a bare IPv4 literal (rejected at
config load, verified on lab hardware), `resolveHost` prefers A records and
refuses AAAA-only names, and every dial target / URI authority brackets via
`net.JoinHostPort` (`corrosion.PeerTarget`). This spec is the plan for removing
those refusals by making each layer genuinely dual-stack, in an order where no
intermediate state can strand a host or split the cluster.

## Principles

1. **Dual-stack, not v6-only.** Every host keeps an IPv4 cluster identity for
   the foreseeable future; IPv6 is added alongside it. v6-only clusters are a
   later phase with their own spec — trying to leap there directly reintroduces
   the mixed-reachability hole the guardrails just closed.
2. **A guardrail is removed only by the phase that makes it safe.** The config
   rejection of a v6 `advertise_address` stays until the transport phase lands;
   the AAAA-only refusal in `resolveHost` stays until then too.
3. **Reachability must never depend on which peer upgraded first.** Peers dial
   v6 only when *both* sides advertise it and the capability latch is up;
   otherwise they use the IPv4 address that every supported build understands.
   The latch follows the standard model: an `enforcement.ipv6_transport` flag
   (default false), token `ipv6_transport_v1`, monotone durable latch, config
   uniformity required, partitions fail closed.
4. **Bracket everywhere, always.** `net.JoinHostPort` / URI-authority
   bracketing is complete (defence in depth from `49ea864`) and every new dial
   site goes through `corrosion.PeerTarget` — that discipline is what makes the
   later phases mechanical instead of a hunt.
5. **Nothing ships un-lab-verified.** The dual-stack lab (Phase 0) precedes the
   transport phase; every phase names what the lab run must show.

## Phases

### Phase 0 — Dual-stack lab (prerequisite, no product code)

`~/litevirt-lab/lab.sh` gives each guest one cluster NIC (`net1`, qemu
multicast socket) with only `10.77.0.x/24` from the `clusternet` netplan
stanza. Add a ULA per node alongside it:

```yaml
addresses: [10.77.0.1$i/24, "fd77::1$i/64"]
```

Multicast-socket transport is L2, so v6 between guests needs no host support.
Acceptance: every pair of nodes can `ping -6 fd77::1N` and open a TCP socket on
the ULA; the existing IPv4 campaign still passes unchanged. (The SSH user-net
NIC stays IPv4 — it is host plumbing, not cluster transport.)

### Phase 1 — Dual-stack transport

The core slice. Changes:

- **Listeners.** `internal/daemon/daemon.go` binds gRPC/metrics on
  `fmt.Sprintf("0.0.0.0:%d", …)`; switch to `net.JoinHostPort(bindAddr, port)`
  with a new `bind_address` config key defaulting to `::` (dual-stack via
  v4-mapped addresses) and falling back to `0.0.0.0` on v6-less kernels. The
  UI/REST loopback listeners follow the same rule.
- **Gossip.** memberlist gains a `gossip.bind_addr` config key (today it binds
  the wildcard and derives its advertise address by enumeration — the §A trap).
  Advertise stays the IPv4 `advertise_address`; a second advertised v6 address
  rides the hosts table (below), not memberlist, so gossip semantics don't
  change.
- **Schema (claims next version, ≥48).** `hosts.address6 TEXT NOT NULL DEFAULT ''`
  — the host's cluster IPv6 literal, empty when not configured. Written from a
  new optional `advertise_address6` config key, validated as a bare global/ULA
  v6 literal (canonicalized; v4-mapped forms rejected — that spelling belongs
  in `advertise_address`). The existing `advertise_address` remains required
  and IPv4.
- **Dialing.** `corrosion.PeerTarget`/`resolvePeerTarget` learn the preference
  rule: use `address6` iff it is non-empty on the *target* row, the local host
  also advertises one, and `ipv6_transport_v1` is latched; otherwise IPv4.
  One function, one rule, every caller (peer gRPC, health probe, qemu+tls,
  spice/vnc, migrate targets) inherits it.
- **PKI.** `lv host init` puts both literals in the cert SAN when
  `advertise_address6` is set; re-issue path documented for existing hosts
  (same flow as an address change today).
- **`getOutboundIP` / auto-detection.** Never auto-detects v6. v6 is explicit
  config only — auto-detection is exactly how the v4 multi-homed trap (§A)
  happens, and v6 multiplies the candidate set (link-local, temporary
  addresses, ULA vs GUA).
- **Guardrail changes.** Config validation now *accepts* `advertise_address6`
  (new key) while `advertise_address` stays IPv4-only. `resolveHost` accepts
  AAAA-only names once the target cluster advertises `ipv6_transport_v1` — but
  since `lv host add` runs before the peer is admitted, the practical rule is:
  hostname resolution still prefers A; an explicit v6 literal is accepted for
  `--address6` style flags only. The hard refusals never come out ahead of the
  code that makes the address dialable.

Verification: fleet tests bind real listeners on `::1` per node and assert
outcomes (the `TestCheckHost_IPv6PeerProbesSuccessfully` pattern — status, not
strings); a lab campaign on the dual-stack lab runs the full delete-terminality
suite over v6-preferring transport, plus a mixed round where one node has no
`address6` (must fall back to v4 with zero errors) and one round with the latch
deliberately un-latched (must stay v4-only).

### Phase 2 — Workload networking

- **IPAM.** `ip_allocations` gains an address-family dimension (schema bump,
  same version claim as its slice); managed networks may declare a v6 subnet
  (ULA or GUA) next to the v4 one; leases allocate per family.
- **DNS.** AAAA records for VM/container names alongside A; the auto-record
  writer and reaper handle both.
- **DHCPv6 / RA.** dnsmasq config rendering for managed networks: RA +
  stateless or stateful DHCPv6 per network config.
- **Firewall/SG.** The nftables renderer emits inet-family rules (most chains
  already are `inet`; audit the v4-literal matches); security groups accept v6
  CIDRs; container veth rules follow.

Verification: fleet for allocation/DNS-record logic; lab: a VM and a container
on a managed dual-stack network reach each other and the host over v6, SG
blocks what it should, records resolve both families.

### Phase 3 — LB / VIP

- `grpcapi.validBackendAddress` already accepts a bare `::1` — but
  `internal/lb/config.go` renders it into an invalid HAProxy `server` line.
  Fix the templates (bracketed `server`/`bind` forms), and until then REJECT
  v6 backends at validation instead of accepting them into a broken render
  (that closing-the-gap commit can land immediately, independent of the other
  phases — it is the same "refuse rather than half-work" principle).
- keepalived VRRP v6 VIP support (separate `vrrp_instance` per family).

### Phase 4 — UI, docs, and the v6-only question

Host/network forms expose the v6 fields; docs/configuration.md documents the
new keys (the docs guard enforces this); a follow-up decision doc addresses
v6-only clusters (out of scope here).

## Out of scope

- v6-only clusters, NAT64/DNS64, and translating existing v4 identities.
- IPv6 for the lab's SSH/user-net path.
- Live renumbering of an existing cluster's v4 addresses.

## Open questions for review

1. **ULA vs GUA guidance** for the cluster LAN — the spec assumes "operator's
   choice, validated as global-or-ULA unicast"; is a stronger recommendation
   (ULA for cluster transport) wanted in docs?
2. **Preference order** — this spec prefers v6 when both sides advertise it
   (latched). Prefer-v4-until-operator-opts-in per network is the conservative
   alternative; one extra config knob (`prefer_ipv6: bool`, default true once
   latched) would settle it.
3. **Schema packaging** — `hosts.address6` in Phase 1 claims schema v48 (or the
   next free version at land time); confirm no conflict with the host-network
   config slice, which also expects ~v48.
