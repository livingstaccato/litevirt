# Design: region-scoped failover

| | |
|---|---|
| Status | **Implemented**, off by default. |
| Issue | colonelpanik/litevirt#265 |
| Base | `main` at `8cbe00bb`, schema v57 |
| Decision | Opt-in now, as a cluster-wide replicated policy rather than per-node YAML. A default for new clusters is revisited later. |

**Reading this document.** It describes what this branch implements. The
operator-facing parts are also in `docs/federation.md`,
`docs/operating-model.md` and `docs/configuration.md`, which the docs guard
checks. Nothing here is proposed unless it is marked *deferred*.

## 1. Problem

A region is a host label (`hosts.region`). Quorum is one cluster-wide count
over `corrosion.VoterSet`, the failover coordinator fences any host that
`floor(N/2)+1` voters report down, and recovery targets are every `active`
host. So a WAN partition between two sites is a majority/minority split of one
cluster. The majority site fences the minority site's hosts, which it cannot
tell apart from powered-off ones, and restarts their workloads on itself
(docs/federation.md, "What a site partition does").

The goal is an opt-in policy under which a site partition leaves the minority
site's workloads alone, while a host that really dies inside a site is still
fenced and recovered by that site.

## 2. The rule

With the policy on, a host in region R is fenced, and its workloads recovered,
only by a decision whose quorum is R's own voters. Recovery targets stay in R
unless the workload says otherwise (§6).

Definitions:

- `V` is `corrosion.VoterSet`: whatever set of host names it returns. This
  design reads nothing else about voting (§9).
- `region(h)` is `hosts.region`, `default` when empty.
- `V_R = { v ∈ V : region(v) = R }`, R's voters. Witnesses in R are in it.
- `q(R) = floor(|V_R| / 2) + 1`.

### 2.1 Fencing

Today the coordinator fences host `h` when fresh `host_health` rows from at
least `floor(|V|/2)+1` distinct observers in `V \ {h}` report it failed.

Region-scoped, it fences `h` in region R when fresh rows from at least `q(R)`
distinct observers in `V_R \ {h}` report it failed. Observations from voters
in other regions do not count, however many there are.

In a site partition, the majority site's replica holds only stale rows from
the minority site's voters. It has no quorum on a minority host, so it fences
nothing there. The minority site fences its own hosts only if it has `q(R)` of
its own voters to say so.

### 2.2 Re-admitting a host

`recoverHosts` returns an `offline` host to `active` when `floor(|V|/2)+1`
voters report it healthy. Region-scoped it takes `q(R)` of `V_R \ {h}`, the
same population that may fence it.

### 2.3 Decision gates

With `split_brain_gate_v1` latched, each recovery decide site in the
coordinator (reschedule, auto-promote, container relocate, resuming a
relocation, resuming from an operator confirmation) re-checks `DecisionGate`:
this daemon itself probed a live majority of `V`.

Region-scoped, those sites call `DecisionGateForRegion(R)` for the failed host's
region R. The deciding daemon must have probed `q(R)` of `V_R` live itself
(counting itself when it is in `V_R`), and it must be coordinator-eligible as
today. The proof records the regional `live`/`needed`.

There is still one failover lease. Any coordinator may decide for any region,
but only on that region's quorum. Across a partition each side can hold the
partition-local lease (the CRDT lease already behaves that way), and each side
can act only for the regions whose voters it can reach. The rebalancer and
the other `DecisionGate` consumers keep the cluster-wide gate: they are not
failover decisions and can move work across regions.

### 2.4 Execution gate

`ExecutionGate` is the gate a host checks before it executes a
runtime-ownership action on itself: starting a VM another node placed there, a
restart-policy restart, promoting a replica, re-keying a container, asserting
ownership.

Region-scoped, a host in region R passes it when it has probed `q(R)` of `V_R`
live. Cluster-wide quorum no longer suffices, and is no longer needed.

Both halves are required for the rule to hold:

- **Regional quorum is needed.** A host in R that can reach the other regions
  but not a majority of R is exactly the host R's majority may fence. It must
  stop acting on its workloads, as a minority host stops today. So "cluster
  quorum OR regional quorum" would be unsafe.
- **Cluster quorum is not.** Without this, recovery inside a region stalls
  whenever that region is on the smaller side of a partition, and in an even
  split on both sides, which is what the policy exists to fix.

Two consumers keep cluster-wide quorum, because what they decide is not
regional:

- the dual-run detector's condition resolution (`resolveGateValid`) proves
  absence cluster-wide, so it also requires the cluster-wide `QuorumProof`.
- VIP self-demotion (`VIPDemoter`) reads the cluster-wide `QuorumProof`, so a
  minority site still stands its VIPs down after
  `quorum_loss_demote_after_sec`, as today. VIPs can be announced across a
  stretched L2, and nothing here proves they are not. *Deferred:* a
  per-LB region scope.

The lease-term barrier (`enforcement.lease_term`) also keeps the cluster-wide
count. Its safety rests on its quorum intersecting every node that accepted a
superseding term, and answers from other regions counted toward a regional
`needed` would not. With `enforcement.lease_term` on, recovery during a site
partition therefore proceeds only on the side holding a cluster majority.
*Deferred:* a barrier that counts only regional answers.

### 2.5 Recovery targets

- **VM reschedule.** The placement request carries a hard constraint,
  `placement.Request.RequireRegion = R`. A host outside R is rejected with the
  reason `region (host in X, recovery stays in R)`. If no host in R fits, the
  VM stays on the fenced host, as any other unsatisfiable hard constraint
  leaves it, and `litevirt_failover_stranded_workloads` counts it.
- **Replica auto-promotion.** Promotion runs on whichever host holds the
  replica. Region-scoped, the coordinator promotes only if that host is in R.
  Otherwise it falls through to the reschedule, which is region-constrained.
- **Container relocation.** The same hard constraint on the container's
  placement request.

## 3. Regions too small to fence their own

`V_R \ {h}` has `|V_R| - 1` members, and a fence needs `q(R)` of them.
`|V_R| - 1 ≥ floor(|V_R|/2) + 1` holds exactly when `|V_R| ≥ 3`. A region with
one or two voters therefore **cannot fence any of its own hosts**. It is never
silently degraded to the cluster-wide count; its hosts have no automatic
failover while the policy is on.

That is reported in three places:

- `lv cluster failover-scope` prints every region's voters, workers,
  witnesses and quorum, and marks a region with fewer than three voters
  `cannot fence its own hosts`. It prints the same table when the policy is
  set, so the operator sees it at the moment they choose it.
- `litevirt_failover_regions_without_quorum`, a gauge the lease holder
  publishes each cycle: the number of regions holding at least one worker with
  fewer than three voters. 0 while the policy is off.
- When a host in such a region would have been fenced under the cluster-wide
  rule, the coordinator logs it and counts
  `litevirt_failover_attempts_total{phase="quorum",result="refused",error_class="region_too_small"}`.
  When a host in a region large enough is reported down only by other
  regions' voters, the partition case, the class is `region_scoped`.

Adding a witness to a region counts: two workers plus a witness is three
voters. A witness in a third site, the tie-breaker the cluster-wide layout
recommends, votes only for its own region under this policy.

## 4. Storage and the operator command

The policy is one replicated row. Schema v58 adds a small generic table:

```sql
CREATE TABLE IF NOT EXISTS cluster_policies (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    set_by     TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    deleted_at TEXT
);
```

Key `failover_scope`, value `cluster` or `region`. No row means `cluster`. It
is last-writer-wins like any cluster fact, anti-entropy repairs it, and an
equal-timestamp tie between two different values is left unresolved rather
than coin-flipped.

A reader that finds a value it does not know (a newer release's scope, say)
fails closed: the coordinator fences nothing that cycle, and
`ExecutionGate`/`DecisionGateForRegion` report `no_quorum`.

The command is one flat subcommand of `lv cluster`:

```bash
lv cluster failover-scope            # show the policy and every region's quorum
lv cluster failover-scope region     # turn region scoping on
lv cluster failover-scope cluster    # back to one cluster-wide quorum
```

It calls `GetFailoverScope` / `SetFailoverScope` and needs the `admin` role.

## 5. Changing it: mixed versions and mid-change

### 5.1 The token

`failover_scope_v1` is mandatory and ReplicationGated, like
`host_membership_split_v1`, for two facts about the binary:

- it can decode `cluster_policies` statements. They are that table's first
  replicated shapes, and a previous-release peer's apply fails closed on them
  and stalls its stream, so nothing writes the table until the token has
  durably latched (`Client.SetClusterPolicyGate`, fail-closed when unwired).
- it honours `failover_scope`.

**Where is the guarantee enforced?** At the fence decision, in whichever
coordinator holds the lease, and in each host's `ExecutionGate`. A guarantee
enforced where the dangerous action is created needs no peer to honour
anything, but here the creator can be any node: the lease moves. A coordinator
on a build that does not read the policy would fence across regions while
every other node believes it will not. So the policy may not be set until
every node, and every replication recipient, runs a build that honours it.
That is what a latched mandatory token proves.

There is no `enforcement.*` flag. The row is the opt-in, it is replicated, so
its uniformity comes from replication rather than from matching YAML, and a
flag would keep a mandatory token from latching. Standing down in an incident
is `lv cluster failover-scope cluster`. A binary rolled back below the token
enters WAL quarantine, as below every latched token.

### 5.2 A change in flight

Each node acts on the value in its own replica. Delivery is ordinary
replication, so for a moment after a change nodes can disagree:

| Transition | A node that has not seen it yet | Hazard |
|---|---|---|
| `cluster` → `region` | still fences with the cluster-wide count | none new: that is the behaviour being replaced |
| `region` → `cluster` | still executes on regional quorum | a node on the minority side of a partition that has not seen `cluster` keeps executing while the majority, which has, may fence it and recover its workloads |

The second row is the dangerous one, and it needs a partition to arise. So
`SetFailoverScope` refuses unless **every** voter is reachable from the
handling daemon (self, or in `HealthyPeers`), naming the ones that are not.
A change is made on a whole cluster, and it reaches every node before a
partition can hide it from one. The residual window is a partition that
begins within one replication delay of the write.

Changing a host's region while the policy is on changes two regions' voter
sets. Relabelling hosts on the far side of a partition would let the near side
count them as its own and fence them. So `ConfigureHost` refuses a region
change under `region` scope unless every voter is reachable, the same
precondition.

## 6. Cross-region DR

Losing a whole site leaves nothing automatic: no quorum of that region exists
to fence its hosts. That is deliberate. From the outside, a lost site and a
partitioned one look the same, and telling them apart is what an operator is
for. What remains:

- **Manual.** `lv replication promote <vm>` brings a VM up from its replica on
  whichever host holds it, and `lv region migrate` moves a VM whose source is
  still reachable. Promoting while the site is only partitioned produces two
  copies. Confirm the site is down first, and fence it (`lv host fence-confirm`)
  so the record says so.
- **Policy-gated, per workload.** A VM whose spec carries the label
  `litevirt.failover_any_region=true` may be *recovered onto* a host in another
  region, and may auto-promote a replica held there. The *decision* is still
  its home region's quorum (§2.1). The label widens where a VM may go when its
  own region has fenced its host but has no room, not who may decide.
  Containers have no equivalent yet (*deferred*); they always stay in region.

## 7. Replication relays

A host that is not a replication relay pushes only to relays (three by
default). If every relay sits in one site, then during a partition the other
site's hosts reach each other only through the leaf fallback, which starts no
sooner than 15 seconds after the relays stop answering. Until then their
failure reports about each other do not meet, so their own region's fence
waits for it. The fleet scenarios make every node a relay
(`Options.Relays`) so each side of the cut converges at once. *Deferred:*
region-aware relay election.

## 8. What does not change

- Policy `cluster` (the default) is today's behaviour, code path for code
  path: `DecisionGateForRegion` is not called, `ExecutionGate` counts `V`, and
  placement carries no region constraint.
- A single-region cluster is unaffected under either value: `V_default = V`, so
  every count and every candidate set is identical.
- Gossip and health probes still span every region.

## 9. The voter set

This design depends only on `corrosion.VoterSet`'s contract: a set of host
names whose size is a quorum denominator and whose members' observations
count. Today it is derived from host state. colonelpanik/litevirt#251 step 2
(docs/design/recovery-claims.md §4) makes it an explicit, generation-numbered
member list. Nothing here changes when that lands. `V_R` becomes the adopted
generation's members whose `hosts.region` is R, and a fenced member stays in
the denominator until removed, exactly as it does cluster-wide.

Two points for that work:

- A region's voter set changes when a member is relabelled as well as when
  one is added or removed. Under an explicit voter config, a relabel is a
  change to two regions' memberships and ought to go through the same
  generation change. Until then, §5.2's reachability precondition covers it.
- Recovery claims (recovery-claims §3) decide by a majority of the generation.
  Under this policy a claim on a workload in region R ought to need a majority
  of the generation's members in R. That is a change to the claim protocol and
  is not made here.

## 10. Tests

- `tests/fleet/region_scoped_failover_test.go`: five independent replicas in
  regions `east` (3) and `west` (2), coordinators on the nodes, and a site
  partition cut with per-link `Block` faults.
  - `SitePartition/cluster`: the east majority fences both west hosts and moves
    the west VM east. This pins today's behaviour.
  - `SitePartition/region`: nothing is fenced on either side, both VMs stay put
    in every replica, and east reports declining (`region_too_small`, since
    west has two voters).
  - `DeathInsideRegion` (connected, partitioned, and both again with the
    proof-gated decide path): an east host dies, east fences it and
    reschedules its VM onto another east host, never west, although the
    scorer prefers the empty west hosts. Partitioned, east holds 2 of 5
    voters, so a cluster-wide count could recover nothing.
  - `ContainerRelocationStaysInRegion`: the same for a container, whose target
    comes from a different placement call. It runs on scenario-steered
    replicas because of a pre-existing defect: on independent replicas the
    image-recreate relocation's entry is refused by every receiver (its
    guarded source delete is not the batch's final statement), which stalls
    the stream on `main` whatever the scope.
  - `TooSmallRegionIsReported`: a west host dies; the cluster scope fences it,
    the region scope does not, reports `region_too_small`, and publishes one
    region without quorum.
  - `ChangeFromTheFarSide`: `region` written on the west side of an existing
    partition never reaches east, which fences west as before. This is the
    mid-change behaviour §5.2 describes and the reason for the reachability
    precondition.
- `tests/fleet/failover_scope_command_test.go`: the RPC over real gRPC with a
  real `health.Checker` per node. Refused before `failover_scope_v1` latches
  (nothing on the stream), refused while a voter is unreachable, then written
  and replicated to every replica.
- Unit tests in `internal/health` (regional quorum, the execution gate under
  each scope, `DecisionGateForRegion`, unknown scope), `internal/failover`
  (fence and re-admission arithmetic, a single region unaffected, unknown
  scope, the gauge, promotion and recovery regions, a cluster-only gate
  refused), `internal/placement` (the region constraint),
  `internal/corrosion` (the policy row and its gate), `internal/grpcapi` (the
  RPC preconditions, the relabel guard, the in-region promotion, dual-run
  resolution) and `internal/daemon` (the gate wiring).
