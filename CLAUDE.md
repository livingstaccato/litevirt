# Working in this repo

## Before you push

```bash
go build ./... && go vet ./...
go test ./...
make ci-guards          # schema bump, writecheck, stmtshapecheck, docs truth
```

`make ci-guards` is the one people forget. It runs checks CI also runs, and a
couple that only exist there — notably `stmtshapecheck`, which fails any
replicated SQL builder whose statement shape is not in the compatibility ledger.

**`-race` on `internal/corrosion` or `internal/grpcapi` needs an explicit
`-timeout`.** Both run past Go's 10-minute default under the race detector —
`internal/corrosion` takes ~40 minutes on a current laptop, and
**`internal/grpcapi` takes ~68** — so the plain command fails like this:

```
FAIL	github.com/litevirt/litevirt/internal/corrosion	600.588s
```

600s is the timeout, not a race. Nothing is wrong with the package; the run was
killed. Reach for a real budget:

```bash
go test -race -timeout 60m ./internal/corrosion/
go test -race -timeout 90m ./internal/grpcapi/
```

**Both numbers have been raised once already, and will drift again.** The
corrosion budget said 30m against a measured ~18½ minutes; the package has
since grown past it, and a run at 30m died at `FAIL ... 1817.560s` looking
exactly like a finding. A re-run at a real budget passed in 2358s — 39 minutes,
with zero warnings. When either package times out, measure before believing it.

**grpcapi is the one that catches people out**, because 30m is nowhere near
enough for it and the failure is indistinguishable from a real finding: a 45m
budget dies at `FAIL ... 2717.486s`, which is close enough to a plausible
runtime to look like the detector found something. It did not — the same package
passes at 90m in 4091s with no warnings. Anything under ~70m on grpcapi is a
budget failure.

**`internal/health` needs one too.** It takes about 20 minutes under `-race`
in full, so a 15m budget dies with `panic: test timed out` — the budget, not a
race:

```bash
go test -race -timeout 45m ./internal/health/
```

Do not pipe a race run through `tail -N`. That discards the `panic: test timed
out` header and leaves only a goroutine dump, which is exactly the evidence you
need to tell the two apart. Redirect to a file and grep it.

Or, for a change confined to a few files, run the race detector over just the
tests that cover them — seconds instead of twenty minutes, and the same signal
for the code you touched:

```bash
go test -race -timeout 5m ./internal/corrosion/ -run 'TestStmtShape|TestLex_'
```

This trips people because a timeout and a detected race look identical at a
glance, and the honest reading of a 600s FAIL on a package you just edited is
"I broke something". Confirm which it is before chasing it: a real race prints a
`WARNING: DATA RACE` block, a timeout prints `panic: test timed out`.

Commits follow conventional-commit style (`fix(cluster):`, `test(fleet):`,
`docs:`). Scope names match the package or subsystem.

## Test tiers

| Tier | Location | Needs | Covers |
|---|---|---|---|
| Unit | alongside the code | nothing | package-local logic |
| Fleet | `tests/fleet/` | nothing | multi-node spine: CLI → gRPC → mTLS → corrosion → replicator → LWW apply → scheduler |
| E2E | `tests/e2e/` | live 4-node cluster | real qemu / nftables / dnsmasq |

**`tests/fleet/` is the one to reach for.** It runs N real daemons in one `go test`
process over real gRPC and real CRDT replication, with `internal/libvirtfake`
injected — no external binaries, no root, sub-second without `-race`. Anything
whose failure mode is *multi-node* belongs here, because a single-package test
structurally cannot reach it. See `tests/fleet/cluster.go` for the harness and
`hardware_v2_latch_test.go` for the shape.

Each node gets two in-process backends: `n.Virt` (`internal/libvirtfake`) for VMs
and `n.CT` (`tests/fleet/ctfake.go`) for containers. `CTFake` keeps a real
on-disk container dir per node and does a real tar export/import, so a container
migrate genuinely moves bytes between two directories over gRPC — assert on
`n.CT.Payload(name)` and a migration that moved nothing cannot pass. It also has
an `OnExport` hook that runs mid-archive, which is the only way to reach the
target-side failures a source preflight would otherwise catch first.

`tests/e2e/` needs two variables that are easy to miss — without them it prints
one line and exits 0, which reads like a pass:

```bash
export LITEVIRT_E2E=1                 # opt in to touching a live cluster
export LV_BIN=$PWD/bin/litevirt       # pin the binary under test
```

## Mutation-verify anything you assert

A passing test proves nothing until you have seen it fail. Break the property,
confirm the test goes red, restore. The repo already institutionalises this —
see `make test-telemetry-mutation` and `scripts/ci/telemetry-mutation.sh`.

This catches vacuous tests, which are easy to write here. A real example: a test
asserted that a peer received the configured gossip advertise address, and passed
with the wiring deleted — because it bound `127.0.0.1`, and memberlist's
auto-detection derives its advertise address from a specific `BindAddr`, so it
produced the same answer either way. Binding `0.0.0.0` and advertising
`127.0.0.1` gave auto-detection a different answer to produce, and the mutation
finally failed.

## Capability tokens

Hardening features are gated on cluster-wide capability tokens
(`internal/capabilities`). The pattern is uniform:

- each has an `enforcement.*` config flag, default **false**. The one
  exception is `enforcement.audit_signature`, which defaults **true**: each
  host signs only its own rows, so no node relies on a peer, and a key that
  fails to load leaves the daemon running and reports its unsigned rows as
  evidence (docs/audit-log.md, "Turning signing on"). An explicit `false`
  is its kill switch
- **advertising is not enforcing.** Most tokens are advertised on the strength
  of the BUILD, whatever the local flag says, so the cluster can latch them —
  the node's own flag then decides whether it acts. A latched token therefore
  proves a uniform build, **not** config uniformity, and a cluster can have a
  token fully latched while members silently do not enforce it.
  `PingResponse.not_enforcing` is the only way to see that (diagnostic only).
  A token is withheld while its flag is off when some node RELIES on a peer
  honouring it — where a flag-off peer would corrupt rather than merely be
  permissive. `advertisedCapabilities` is the authority on the list
  (operation_protocol_v1, isolation_epoch_v1, owner_epoch_v1 and the others
  named there, `recovery_claim_v1` among them); for those, a latched token
  DOES mean config uniformity. `recovery_claim_v1` is also withheld until the
  node is ready (`grpcapi.RecoveryClaimReadiness`), and nothing enforces it
  until the flag, the latch AND an adopted voter generation all hold
  (docs/design/recovery-claims.md §5).
  **Ask where the guarantee is enforced before adding one.** A guarantee
  enforced at the point a dangerous action is CREATED does not need the peer
  to enforce anything, so withholding buys no safety and costs a great deal
- **`shared_storage_fence_v1` looks like it should be withheld and must not be**
  — it has been proposed twice, so the reasoning lives in
  `advertisedCapabilities` and in `TestAdvertise_SharedStorageFenceIsUnconditional`.
  It gates a corruption hazard, but the coordinator refuses to CREATE an
  unproven shared-disk transfer at the source, so no node relies on a peer. The
  cost of withholding is concrete: `internal/health/capability.go` has no role
  filter, so a **witness** with the flag off (its operator has no reason to set
  it) would hold the fence off fleet-wide forever; every node mid-rollout would
  stop enforcing; and a config-on token that cannot latch costs
  `driveCapabilityActivation` one Ping sweep of its one-token-per-cycle budget
  on every rotation (`activateOneUnlatched` rotates its starting token, so later
  tokens in `Supported()` still get their turn)
- the latch is monotone and durable: once formed it survives a restart and does
  not re-open when a peer becomes unreachable (a partition fails **closed**)
- enabling on one node changes nothing

There are exceptions, of two different kinds, and neither is "the one":

- **Mandatory** — no config flag, `tokenEnabled` returns true unconditionally,
  so they latch on every cluster with no operator opt-in. The set is declared in
  one place, `capabilities.mandatory` (read it; prose copies of it have gone
  stale twice). They are reserved for a token stating a *fact about the binary*
  rather than a policy — at the time of writing `split_brain_gate_v1`,
  `lease_term_ledger_v1`, `credentials_split_v1`, `host_membership_split_v1`,
  `failover_scope_v1` and `voter_config_v1`, but trust the declaration, not
  this list. A mandatory token has no flag to turn off in an incident — see
  the per-token stand-down notes beside that declaration.
  `credentials_split_v1` has none at all. Once latched, hosts dual-write the
  credential tables and the old secret columns and never clear the old ones.
  A rollback below it is still not clean: the rolled-back binary enters WAL
  quarantine (`preflightCapabilityRollback`) and emits no replicated writes
  until upgraded again or reseeded. What the two copies buy is that its
  old-column reader still validates tokens, checks passwords and fences, where
  a cleared column lost all three, and that upgrading again loses nothing.
  Clearing the old columns is a later release's step behind a second token
  (docs/design/credentials-clear.md). Do not add a clear to this one.
  `host_membership_split_v1` follows the same shape for `hosts.state` and the
  isolation pair: both copies written, nothing cleared, readers take the
  `host_membership` row when it exists
  (docs/design/host-membership-retire-old-columns.md).
  **Neither split may compare a copy against its parent row's `updated_at`.**
  Unrelated writes bump it (a version report bumps `hosts`), so a replica that
  refused one half of a dual write holds a stale value on a newer row, and a
  newer-row-wins rule brings a rotated-out password, or `active` over
  `fenced`, back cluster-wide. A write from a node that has not latched is
  recognised by its ENTRY instead — the old column is set with no new-table
  statement beside it (`internal/corrosion/unlatched_origin.go`) — and
  absorbed locally on apply and on the local write path.
  `failover_scope_v1` has no flag either: the replicated `cluster_policies`
  row is the opt-in, and `lv cluster failover-scope cluster` is the stand-down
  (docs/design/region-scoped-failover.md).
  `voter_config_v1` is mandatory but advertised only once the node can vote
  durably (`grpcapi.VoterConfigReadiness`: `synchronous=FULL`, host signing key
  loads). A flag would let one node count a different majority from its peers,
  so its stand-down is the decided `lv cluster voter reset`, which moves every
  node back to the derived voter set at one generation. Once a generation is
  adopted, `corrosion.VoterSet` returns its members whatever host state or any
  flag says (docs/design/recovery-claims.md §4).
- **Conditionally advertised** — `hardware_v2` has no flag of its own either,
  but it is gated differently: each node's startup hardware audit plus a latched
  `operation_protocol_v1` decide whether it is advertised at all.

Some mandatory tokens are additionally `capabilities.ReplicationGated`
(`lease_term_ledger_v1`, `credentials_split_v1`, `host_membership_split_v1`,
`failover_scope_v1`, `voter_config_v1`, plus the flag-gated `recovery_claim_v1`,
the one member that is not mandatory; the set is
`capabilities.replicationGated`): the latch is a claim about what every host
still receiving replication can *decode* or *read*, so it is confirmed against
admitted memberlist membership — not merely against voting-eligible members. A
host parked in `maintenance` on an older build therefore holds that latch off,
which is the intended invariant and not a bug.

**`enforcement.operation_protocol` is required for all hotplug.** Disk, NIC, and
concrete-address PCI attach/detach are journaled and have no un-journaled path,
so they refuse outright while it is off. That is deliberate and pinned by tests
(`TestAttachDevice_ProtocolInactiveRejected`) — do not "fix" it by adding a
fallback.

## Traps

- **`lv host init --local` bakes a `127.0.0.1`-only certificate SAN.** Peers can
  never dial that node. For anything multi-node use the remote form
  (`lv host init root@<ip>`), which puts the real address in the SAN. A node
  cannot init *itself* remotely — the binary push becomes a same-file copy and
  fails; run it from another node.
- **Set `advertise_address` on any multi-homed host.** Auto-detection uses two
  different heuristics — default-route source IP for the host record, first
  private IP by interface enumeration order for gossip — which can disagree with
  each other and with reality. When the wrong address is identical on every node
  (a NAT'd lab), each node dials itself, gossip looks healthy, and the cluster
  never converges.
  never converges. It must be a bare IPv4 literal — the daemon refuses to start
  on a hostname, a host:port, or IPv6.
- **Cluster transport is IPv4-only.** Gossip and gRPC both bind `0.0.0.0`, so an
  IPv6 address anywhere in the peer path is a trap, not a feature: nothing fails
  at startup, every peer probe just fails forever and the failure detector fences
  a live host. `advertise_address` and `resolveHost` reject IPv6 at the two entry
  points; `corrosion.PeerTarget` / `corrosion.URIHost` (never `Sprintf("%s:%d")`)
  keep the dial paths correct if one gets in anyway.
- **`internal/pki` is not importable across modules.** External consumers build
  their own peer TLS config from `ca.crt` / `host.crt` / `host.key`.
- **Open a test database with `corrosion.NewTestClientT(t)`, not
  `NewTestClient()`.** A shared-cache in-memory DB lives as long as a handle to
  it is open, and modernc's sqlite allocates outside the Go heap — so a client
  that is never closed holds ~2 MB that no heap profile shows. Once per test,
  that grew the `internal/grpcapi` test binary to 4.4 GB of RSS, and two of
  them at once took down a 22 GB laptop. `NewTestClientT` closes the client in
  `t.Cleanup`. If you must use `NewTestClient()`, close what it returns. RSS
  that climbs steadily through a test run while `GODEBUG=gctrace=1` shows a
  flat live heap is this.
- **Docs are guarded in both directions.** `cmd/litevirt/docs_triangulation_test.go`
  fails on a doc referencing a command that does not exist, a command or config
  key that no doc mentions, and a `litevirt_*` identifier absent from the code.
  Adding an operator-facing flag means documenting it.

## A local 4-node cluster

Nested VMs on plain qemu, no libvirt or root on the host. See the lab script
kept outside the repo (`~/litevirt-lab/lab.sh`) — nodes boot with `-cpu host` so
guests inside get real KVM, cloud-init is seeded over HTTP via the SMBIOS DMI
serial (a VVFAT seed disk does **not** work — the synthesized FAT volume carries
no `blkid` LABEL of `CIDATA`, so `ds-identify` finds no datasource and disables
cloud-init silently), and the cluster LAN is a qemu multicast socket.
