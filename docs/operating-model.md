# litevirt Operating Model

> Plain-language description of what a litevirt cluster guarantees and what
> it does *not* guarantee. Read this before deploying.

---

## Architecture in one paragraph

Every host runs `litevirt`. There is **no master node**. State (hosts, VMs,
networks, etc.) is replicated as a CRDT via the embedded Corrosion store using
the Crescent relay-quorum protocol over mTLS gRPC. Each host's Hybrid Logical
Clock orders the replication log and de-duplicates mutations; row **conflict
resolution is last-writer-wins by the row's `updated_at`** (sub-second monotonic
per node), so all hosts must run NTP (HLC does not arbitrate conflicts). An
**exact-timestamp tie** with differing content is settled by a **table-aware
resolver**: a deterministic winner where any pick is safe, otherwise the row is
kept-local and flagged for repair (ownership/tenancy/policy/auth are never
coin-flipped) — see [Diagnostics](diagnostics.md). Health is observed
peer-to-peer every 2 s, by an
application-level readiness probe that performs a trivial local read — not by a
TLS handshake, which a daemon with a wedged database completes perfectly. An
observer that was itself not running (suspended, swapped out, starved of CPU)
does not count the probes it timed out while stopped, or any unreachable probe
in the 10 s after it resumes, and its coordinator decides no fence in that
window. See [Migration & Failover](migration-failover.md) → "An observer that
stopped running is not a witness".
Failover is decided by quorum among observers, gated by a CRDT-stored leader
lease. Fencing has multiple strategies; safety guards refuse to reschedule
VMs after a fence failure so that the same VM never runs on two hosts at once.

---

## What the cluster guarantees

### Three different guarantees, one vocabulary

Most of the confusion about what litevirt promises comes from one word —
"replicated" — standing in for three things of very different strength. They are
named separately here, and the rest of this page uses these names.

| Term | What has happened | What it does NOT mean |
|---|---|---|
| **Local commit** | The write is durable in this host's SQLite store and the RPC has returned. | Nothing has left the host. |
| **Peer-durable** | At least one other host has applied the write. | Not a majority, and not an ordering guarantee. |
| **Quorum-authorized** | A majority of reachable voting members was confirmed *before the action was taken*. | Not that the action's record has replicated anywhere. |

Almost every write is **local commit** only. Replication is an asynchronous push
over the relay topology, woken by the write and backstopped by a 60 s
anti-entropy pass; no ordinary API call waits for a peer to apply anything. A
write that commits locally and is followed immediately by the loss of that host
is lost, and no amount of peer *reachability* changes that — reachability is
measured by a probe, not by an acknowledgment of your write. Peer-durability is
observable after the fact (`litevirt_replication_min_watermark_seq` advances,
`lv cluster converge` reports matching digests); it is not something an
operation can be asked for.

**Quorum-authorized** is a separate axis and applies to a short list: fencing a
host, and every runtime-ownership action behind `DecisionGate`/`ExecutionGate`
in `internal/health/gate.go`. Those refuse to proceed without a live majority
this daemon itself probed. It is an authorization to act, computed at the moment
of acting — it says nothing about whether the resulting rows have replicated.

### Replication
- **Eventual consistency** of all CRDT-replicated tables across all healthy
  members. After any partition heals, all hosts converge to the same state
  for any record whose `updated_at` you can observe stabilizing.
- **A local commit is not peer-durable.** A write returns once it is durable in
  the local store; the push to peers is asynchronous. If the host dies between
  those two moments the write is gone. A peer being *reachable* is not a peer
  having *applied* anything — reachability is what the health probe measures.
  Where a write must survive the loss of
  its origin host, confirm it landed — `litevirt_replication_min_watermark_seq`
  advancing past the write, or `lv cluster converge` reporting matching digests
  — rather than assuming a healthy cluster implies it did.
- **Anti-entropy** (`internal/corrosion/antientropy.go`) runs every 60 s
  and is the safety net for divergence the WAL replicator missed. A scheduled
  pass does not contact every peer: it contacts this node's relays (a leaf's
  assigned pair, or a relay's fellow relays) plus two other peers, taken in
  turn from a random ordering of the rest. With M non-relay peers every peer
  is reached within any 2·⌈M/2⌉−1 consecutive passes. Public,
  operator-readable state is repaired table by table: a pass pulls only the
  tables whose digests disagreed (`StreamTableDump`, which adds the parent rows a
  child table's merge checks against), and falls back to the full
  `StreamStateDump` against a peer too old to serve it; eligible secret-bearing config
  uses a separate peer-mTLS-only sensitive dump. Within a table that disagrees,
  the pass asks the peer for the table's 256 bucket digests
  (`GetTableBucketDigests`) and pulls only the buckets that differ, a child
  table's parent narrowed to the same buckets; a peer without that RPC gets the
  whole table. The pull itself is paged (`StreamTableRows`: at most 1,000 rows
  or 1 MiB of rows a message, merged as each arrives), with the blob
  `StreamTableDump` as the fallback for a peer without it. A table's digest is
  kept between passes (never for `lv cluster converge`, which has every host
  scan) until a row of it
  changes (at most 10 minutes), so a pass rescans only the tables written since
  the last one ([design/ae-incremental.md](design/ae-incremental.md)). Observation tables
  (`host_health`, `health_evaluator_status`, `host_capacity_observations`),
  whose writers re-publish them every few seconds to a minute, are pulled by a
  scheduled pass at most once per 5 minutes per node; control-state drift in
  the same exchange is pulled at once. A table held apart from a peer only by
  unresolved ties this node already tracks, proven by the pull before, is not
  pulled again until either side's digest moves. A node whose replica is not caught up,
  and `lv cluster converge`, pull everything that disagrees. The older unary `GetStateDump`
  is retained as a fallback for mixed-version clusters. Convergence is automatic;
  `lv cluster converge` only *accelerates* it (kicks an immediate anti-entropy
  pass, which contacts every peer rather than a sample) and *verifies* it (cross-host digest report) — it never exports or merges
  redacted state itself.

- **A host's state has its own clock.** Replication applies a write only if it
  is newer than the row it lands on, so two writes to different columns of one
  row are not independent: the host that applies the newer one first refuses
  the older one. A host's state and isolation epoch are decided by the
  coordinator, by operators and by the peers that isolate it, and they are
  read from `host_membership`, one row per host with its own `updated_at`,
  apart from the version, schema and resources the host reports about itself
  in `hosts`. A fence and a concurrent version report therefore both land on
  every host. The `hosts` row keeps a copy of state and isolation, written in
  the same batch, for a host rolled back one release; that copy can still lose
  a concurrent write, exactly as before, and no reader ever takes it over the
  `host_membership` row. A state change made through a host that is not yet
  writing `host_membership` (mid-roll, or rolled back one release) is absorbed
  into it by every host that applies that change, the writer included, and
  reaches any host that missed it by anti-entropy. State and isolation share their row
  with each other, and a host's operator-set configuration (fence strategy,
  role, region) shares the `hosts` row with its self-reports. On a cluster that
  has not finished rolling to a build carrying `host_membership_split_v1`,
  state is read from `hosts.state` and a state change can lose to a concurrent
  report — see
  [upgrades.md](upgrades.md#host-state-moves-to-its-own-row-after-the-roll).

### HA / Failover
- **Quorum-gated fencing.** A host is fenced only after `floor(N/2)+1` fresh
  observers report `consecutive_failures ≥ 5` for it, where N is the voter
  set (see *The voter set is explicit once genesis has run*, below). Stale
  observer rows (older than 30 s) are excluded. Under region-scoped failover
  (`lv cluster failover-scope region`) N and the observers are the members of
  the voter set in the host's own region instead; see "A site partition" below.
- **The voter set is explicit once genesis has run.** Every quorum — the fence
  quorum, the recovery quorum and `DecisionGate`'s quorum proof — counts over
  one voter set. Until the cluster has a voter generation, that set is derived
  from host state: every host not `offline`, `maintenance` or `fenced`,
  witnesses included, in every region. A derived set is only as agreed as
  replication, so two coordinators can count different denominators
  (colonelpanik/litevirt#251). Once `voter_config_v1` has latched and every
  host is voting-eligible and reachable, the leader-lease holder decides
  **generation 1** of an explicit set, unanimously; each host adopts it once
  its certificate — a signed accept from every member — verifies. From then on
  the voter set is that generation's members and nothing else: a member that
  goes `offline`, into `maintenance` or is fenced still counts in every
  denominator until it is removed. It changes only through a decided change —
  `lv cluster voter add` / `rm`, one member per generation, decided by a
  majority of the current generation, or `lv cluster voter reset`, which
  returns every host to the derived set at one generation. No flag changes it.
  `lv host rm` of a current voter is refused; `lv host rm --dead <host>` removes
  a voter that is fenced proof-grade and gone for good, taking it out of the
  voter set first. While genesis cannot run, the
  `ha.voter.genesis_pending` health condition names each host holding it back;
  `lv cluster voter init --members` is the fallback for a cluster that cannot
  become clean. A voter whose state database was recreated (re-imaged or
  reseeded) abstains from every decision until it is removed and re-added:
  `lv cluster voter ls` shows it. `ha.voter.unavailable` names every member
  that is fenced, offline, removed or abstaining, with the command that removes
  it — there is no automatic shrink, so each one is fault tolerance the cluster
  does not have. Once a majority of the voters is gone for good no decided
  change can succeed, and `lv cluster voter force-reconfigure --lost <hosts>` is
  the audited break-glass: every named host must be fenced proof-grade, it is
  refused while a majority is actually reachable, and `ha.voter.forced` stays
  raised until each lost host is removed with `lv host rm --dead`. Capability
  latches still count voting-eligible hosts by state, so a fenced member cannot
  hold every future latch off. Design:
  [design/recovery-claims.md](design/recovery-claims.md) §4.
- **Recovery is a decided claim when recovery claims are enforced.** The lease
  and `DecisionGate` cannot stop two coordinators that each believe they lead
  from each authorizing a destination for the same workload. With
  `enforcement.recovery_claim: true` on every host, `recovery_claim_v1`
  latched and a voter generation adopted, a reschedule, promote or container
  relocation is minted only once a majority of the voter set has certified it —
  a single-decree Paxos decision per (workload, owner epoch, attempt) — and the
  destination verifies that certificate against its own replica and the
  cluster CA before it executes (`recovery_claim_unproven` otherwise). Each
  voter probes the recorded owner before it accepts and refuses while it can
  reach it (`recovery_claim_owner_reachable`), so a host most voters can reach
  is never recovered, whatever the coordinator's health view. The loser of a
  duel writes the winner's proof and nothing naming itself. A recovery decided
  for a destination that then died is stranded (`ha.claim.stranded`) until the
  destination returns or is removed with `lv host rm --dead`; the claim then
  moves to the next attempt. `lv cluster claim <kind>/<name>` shows every
  voter's state for a stuck claim. **A partial stand-down is the hazard, not a
  degraded mode:** a host with the flag off mints and executes uncertified
  proofs. The token is advertised only while the flag is on, so a stood-down
  host drops it from its capabilities — its enforcing peers raise
  `ha_degraded` (unsupported member) — and, having latched it, reports it in
  `PingResponse.not_enforcing`. The full stand-down is the flag off on every
  host and a restart; the voter set and the voters' history are unchanged.
  Design: [design/recovery-claims.md](design/recovery-claims.md).
- **Leader-gated recovery — best-effort, not exclusive.** The lease is a CRDT
  row with a 45 s TTL, re-validated before every destructive action. A CRDT row
  store cannot offer linearisable compare-and-swap across a partition, so the
  lease *suppresses* concurrent coordinators rather than excluding them: both
  sides of a partition can believe they hold it (`acquireLease` says so in as
  many words). That is why the lease is never sufficient on its own — a decision
  site requires `holdLease()` **and** `DecisionGate.OK`, which is a quorum this
  daemon probed for itself, and the minority side fails closed there. Read "only
  one coordinator acts" as the intended end state of the exclusivity work, not
  as something the current code guarantees. What the code *does* guarantee is
  that a split with a healthy network does not last: when several survivors
  claim an expired lease at once — the ordinary shape of a leader death, since
  every node polls on the same interval — the lowest-sorting claimant keeps the
  lease on a fresh term and every other claimant stands down on the tick it
  learns of that claim (see *A contested lease still converges* below). A fence additionally requires 30 s of the lease
  still to run before it may start, because an IPMI power-off plus its
  verification can take 23 s and a fence cut short is reported as unconfirmed.
- **Only the peers a node actually pushes to can pin its log.** Replication is
  push over the relay topology, so a node serves a subset of the cluster. When
  the topology changes, the peer's watermark row is left behind and can never
  advance again — nothing will push to it from here. Such a row is ignored
  rather than treated as a slow peer.
- **A peer that stops acknowledging stops pinning the log.** `mutation_log` is
  retained until the slowest peer has acked it. A peer only counts while it is
  both recently-acked and currently pushable: the watermark timestamp advances
  only on a successful push, so a peer that has just gone unreachable would
  otherwise look recent while its sequence is frozen, and block all compaction
  until the whole live-watermark window elapsed. Dropping a peer's tail is safe
  — it resyncs by anti-entropy, not log replay.
- **No double-fencing.** Once a successful fence is recorded in `fencing_log`
  (or operator confirmation under manual strategy), no coordinator will
  re-fence the same host within a 5-minute window.
- **A fence and its recovery can land on different coordinators.** The fence is
  bounded by the lease that authorises it, and the leader re-checks the lease
  before rescheduling anything. If it lost the lease meanwhile it stops there —
  but the verified power-off is already recorded, in `fencing_log` and in the
  host's `fenced` state, so the next leader resumes the reschedule from that
  record instead of powering the host off a second time. The resumed pass is
  counted as `phase=recovery, error_class=recovery_resumed`.
- **Split-brain refusal.** If a fence fails (and the strategy is not
  `best-effort`), the coordinator refuses to reschedule the host's VMs.
  Operator must intervene.
- **A new VM is never published `running` before it can prove its
  generation.** Every path that creates a VM row — `CreateVM`, template
  instantiation, import, live-restore autostart and a renamed replica
  promotion — records it as `creating`, assigns its first ownership generation,
  stamps both runtime markers (libvirt domain metadata and the host-local marker
  file), and only then flips it to `running`. When any step fails the VM keeps
  running and its row stays `creating`: it is neither published at generation 0
  nor torn down. The owning host's reconciler finishes such a row on its next
  sweep — when the domain is running there and no create operation, pending
  start proof or VM lock holds the row. The dual-run detector therefore has no
  newborn grace: a VM running on its owner at generation 0 with no marker pages
  as an owner-epoch mismatch, however recently it was created. Containers do not
  take this path: they graduate on the backfill sweep.
- **A VM published as `running` is marked at the same time, on the host that
  runs it.** Every local transition that sets a VM to `running` — start,
  snapshot restore, import, a failed migration healing back, the reconciler's
  self-heals, the health checker's restarts, repair-owner, and replica
  promotion — goes through one of two chokepoints, and a CI guard
  (`make ci-guards`) fails the build on a new call site that does not — and on a
  new statement in `internal/corrosion` that writes the `state` column without
  being registered as belonging to one ordering or the other.
  The two orderings are not interchangeable. A write that leaves the ownership
  generation alone marks first and commits only if the markers landed. A write
  that ADVANCES the generation in the same statement must commit first, read
  back, and mark that — marking first would stamp the generation the row is
  about to leave, which is the marker/row disagreement the dual-run detector
  reports. Three producers that insert a row already at `running` — a clone
  started with `--start`, a live-restore with autostart, and a renamed replica
  promotion — assign the first generation at insert instead.
  **Three gaps remain, deliberately.** The first two predate this work; the
  third is the cost of the rule that one marker is enough to publish.
  1. *Ownership handoffs.* Migration cutover, drain, the cold firmware handoff,
     and the health checker's migration retry all commit a row naming a
     DIFFERENT host, while running on the host giving the VM away — whose domain
     libvirt has already undefined. There is nothing local left to mark, and
     gating those commits on a marker write would refuse them on every
     successful migration. The destination marks its own runtime on its next
     convergence pass (at most one reconcile interval, 15s), and until then it
     runs a VM it cannot prove. The source also keeps a now-meaningless marker
     file for a VM it no longer runs; nothing reads it, because its domain is
     gone.
  2. *A generation that moves mid-publish.* The generation is read before a
     non-minting commit and after a minting one, and a concurrent ownership
     transition can land in that window. A marker that lags the row is safe —
     it is exactly what the superseded-runtime check should see when ownership
     has genuinely moved. The unsafe direction, stamping a runtime with the NEXT
     owner's generation, is refused: BOTH orderings re-check that the row still
     names this host before writing anything, and the non-minting one refuses
     the whole transition rather than publish a row another host owns. The
     convergence sweep that REPAIRS a marker checks the same thing — its own
     precondition is only that the local domain is running, which is also true
     of a domain this host has not yet torn down after losing ownership.
  3. *A host that can write neither marker.* One marker is enough to publish, so
     a failed libvirt metadata write falls back to the durable file marker and
     vice versa. Losing BOTH refuses the transition — the invariant working as
     intended — but a host whose data volume is full or read-only AND whose
     libvirt refuses metadata will leave its rows behind while its guests run.
     A non-minting transition REFUSES in that case, and the refusal is counted
     on the state-write-failure metric. A minting one cannot: its commit has
     already landed by the time the markers are attempted, so losing both is
     logged for convergence to repair and is neither refused nor counted.
- **A marker value of `0` is not a generation.** It is refused wherever it would
  be written — the marker file and the domain metadata alike — and reported as a
  corrupt marker wherever it is read, with one deliberate exception: the
  superseded-runtime check that decides whether a rejoined host may restart a VM
  from local state reads it as generation `0` rather than as unreadable. That
  check does not fail closed on an unreadable marker (which would strand a
  legitimately-owned VM), so treating a `0` as unreadable there would turn its
  refusal into a permission — the dual-run the marker exists to prevent. A
  NEGATIVE marker gets no such treatment: it is garbage, and no decision is
  derived from it. A VM running with a `0` marker is therefore not provable,
  and reports as such rather than passing silently.

### Time
- HLC rejects remote timestamps more than **5 minutes ahead** of local wall
  time. One misconfigured peer cannot pin the cluster's logical time forward.
- Clock skew above 1 s is logged as a warning and recorded in the
  `clock_skew` table for metrics.

---

## What the cluster does NOT guarantee

### CRDT is not linearizable
- The leader lease is a CRDT row, **not** a strongly-consistent CAS. Under a
  partition, both sides may briefly believe they hold the lease.
  Consequences:
  - Two coordinators may race to fence a host. Both will find each other's
    work via the `recentlyFenced()` check on the next cycle, but during the
    race window both may have called `fence.Execute`.
  - Fencing primitives are designed to be idempotent (IPMI on an already-off
    host is a no-op; SSH poweroff likewise). Ensure your fence method has
    this property.
- VM placement and other state writes use last-writer-wins on the row's
  wall-clock `updated_at`. **The most recent writer (by wall clock) wins**; there
  is no two-phase commit. If two operators concurrently modify the same VM, one
  set of changes is silently lost — and under clock skew the host with the faster
  clock wins, so NTP is required.

### Leader-lease terms, and what enforcing on them does and does not buy

Every acquisition of a leader lease — `failover`, the rebalancer, the dual-run
detector — records a **term**: an incarnation number for that holder's tenure,
in the `leader_lease_terms` table. A renewal keeps its term, so a leader's term
is stable for as long as it holds the lease, and a coordinator that restarts
still holding its lease recovers the same number rather than a new one.

Terms exist because `leader_election` records *who* holds a lease but not
*which tenure*, which is what makes a stale leader's writes indistinguishable
from a current leader's.

A term is minted whenever a **tenure** begins, which is not the same as
whenever the holder changes. These all mint:

- another host taking the lease (the ordinary case);
- the same host re-taking its own lease **after it expired** — a GC pause,
  SIGSTOP or IO stall longer than the TTL ends a tenure, because the lapse is
  exactly the window other hosts were entitled to act in;
- once per lease key, ever: a node upgraded from a build with no term ledger
  comes back still holding its lease with no term recorded, and mints one.

Nothing mints until the cluster has finished rolling. Minting waits for
`lease_term_ledger_v1` to latch durably on the node doing it — a token with no
config flag, advertised by every build that has the ledger, so nothing is
required of you: it latches on its own once every host is upgraded, and terms
begin at the next tenure change. Before it latches, leases are taken exactly as
they were before terms existed; you will see `leader_election` move with an
empty `leader_lease_terms`.

It gates the mint rather than the read because the mint is the first write this
table ever replicated, and a host still on the previous release cannot decode
it: the write would not be ignored, it would stall that host's replication
entirely. So the latch is the proof that no such host is listening.

**"Every host" means every host still receiving replication, not every host that
votes.** A host in `maintenance` does not vote, but its daemon is up, it is in
memberlist, and it is still a replication target — so it holds this latch off
until it is upgraded or its daemon is stopped. That is the invariant rather than
a quirk: while it is listening, we must not send it shapes it cannot decode. If
a roll appears not to complete, look for a host parked in `maintenance` on an
older build.

Three operational consequences.

A cluster stuck mid-roll — one host held back — mints no terms at all. This is
by design: you see an empty `leader_lease_terms` rather than an error, and
`litevirt_ha_degraded{reason="capability_rollout_pending"}` rather than
`unsupported_member`. The two are deliberately distinct — a rollout in progress
is not a fault, so it does not page, but a rollout that never finishes is worth
a look. `unsupported_member` stays reserved for a capability you asked to
enforce that the cluster cannot confirm, and for one that latched and later
regressed.

`lease_term_v1` will not advertise ready on a host whose ledger token has not
latched, because enforcing on terms while producing none would refuse every
reschedule that host coordinates. The withheld-readiness reason names the token,
so a host that looks stuck says which of the two is outstanding.

There is no way to stand the ledger token down, deliberately. It has no config
flag, and deleting its marker file does not last — the monitor re-latches as
soon as the fleet is uniform.

**Rolling a host back does NOT stop minting, and makes things worse.** The
latch is monotone by construction: `DurablyLatched` reads the persisted
activation markers and never consults current peer support, which is the whole
point of a fail-closed latch — a partition must not silently re-open the legacy
path. A host that drops below this build therefore stops *nothing*. The nodes
that already latched keep minting, and the rolled-back binary cannot resolve
the mint's statement shape, so an unregistered shape back-pressures its entire
replication stream. The one host you rolled back to regain control is the one
that stops replicating.

If you need minting to stop, there is no supported switch; treat it as a
defect to report rather than an operation to perform. What you can stop is
anything ACTING on the terms: `enforcement.lease_term` is a real config flag,
it is authoritative for both enforcement and recovery, and terms are additive
audit facts that nothing reads until it is on. In an incident that is the lever
you want.

So an ordinary rolling restart of an N-host cluster mints roughly 3N terms —
each of the three leases moves once per host — on **every** roll. Size a
term-growth alert against that, not against the one-off upgrade backfill.

#### Turning enforcement on

Enforcement is **off by default** and needs two things: `enforcement.lease_term`
in config, AND the `lease_term_v1` capability latch. Neither alone does
anything. Before both hold, behaviour is exactly what it was before terms
existed — a stale term refuses nothing.

`lease_term_v1` will not latch on a cluster with **fewer than three
voting-eligible hosts**, whatever the flag says. The barrier needs
`liveHosts/2+1` answers: on two hosts that is both of them, so a single host
outage would refuse every protected action — and a host outage is precisely when
failover has to work. On one host quorum is self-satisfied and the barrier is a
no-op that protects nothing. Three is the smallest size where enforcing is both
meaningful and survivable.

**The latch is one-way.** A cluster that shrinks below three hosts after
latching keeps enforcing, because a latch that re-opened when a peer became
unreachable would fail open in exactly the partition it exists for. Setting
`enforcement.lease_term: false` and restarting is the way out: the flag is
authoritative for enforcement and for recovery, so it stops enforcement
regardless of the latch marker. Do not delete marker files to achieve this.

#### The two refusal reasons

Both appear in `litevirt_runtime_action_refused_total{action,reason}` and in the
refusal returned to the caller. They mean different things and are deliberately
not merged:

- **`stale_lease_term` — FENCED.** The proof's term is below the
  quorum-observed high water for its lease, or it names a coordinator this node
  did not record as holding that term. The mechanism worked and refused
  something it should refuse. A burst of these around a failover is the feature
  doing its job; a steady trickle in calm conditions means something is minting
  proofs from a tenure it no longer holds.
- **`lease_term_unconfirmed` — NOT fenced; could not establish whether it
  was.** This node could not reach a quorum to ask. It is a degradation and
  wants investigation: the action was refused for lack of evidence, not because
  anything was found wrong. Look for a partition or unreachable peers, not for a
  split-brain.

An operator who cannot tell these apart will hunt a split-brain that never
happened, which is why they are separate strings rather than one "refused".

#### What it costs

An **accepted** proof pays one peer fan-out — a quorum read of every reachable
peer's newest term for that lease key. The budget is 3s for the whole sweep, not
per peer, so an unreachable fleet cannot multiply a single sweep. A **refusal**
can be served from a short-lived cache without any fan-out, because the observed
high water only rises — so an old reading is a lower bound, and refusing on a
lower bound is sound while accepting on one is not. Accepts are never served
from that cache, so **every accepted proof pays for a fresh sweep**.

That makes the recovery burst the cost that matters, and it does not coalesce.
Concurrent callers do share one sweep, but the reschedule path has no concurrent
callers: the destination's reconciler walks pending workloads in one serial
loop, so a host loss with 40 workloads is 40 back-to-back sweeps rather than a
burst. Sharing is real and does nothing here.

What that costs depends on whether a peer is *connected but silent* — one that
died within the health-probe interval, so it is still counted as reachable and
still accepts a connection. There is normally no such peer, and a sweep then
costs milliseconds. When there is one, the numbers are:

| 40-workload host loss | added latency |
| --- | --- |
| every peer answering | milliseconds per proof |
| one connected-but-silent peer | ~13s total (one 3s sweep, then a 250ms probe per proof) |

The bound comes from remembering that a peer answered nothing and giving it a
250ms probe on the next sweep instead of the full budget, for up to 10s. It
never changes which peers are asked, and it cannot cause a refusal: a sweep that
falls short of quorum re-runs the fan-out at full budget before refusing
anything, so a peer that recovered but is merely slow is still counted.

#### What enforcement does NOT do

Stated plainly, because the name invites more confidence than the mechanism
earns:

- **It does not stop two nodes believing they hold the lease.** That needs
  consensus, which a CRDT row store does not provide. Everything in *CRDT is not
  linearizable* above still holds in full.
- **It is not consensus, and a contested term is not resolved cluster-wide.**
  Two partitioned nodes can each mint the same term naming themselves, and
  nothing here elects a winner *for that term's ledger rows* or ever will — see
  *What this table will and will not show you* below. The LEASE moves on
  instead: one claimant retires the contested term by minting above it, so the
  term both rows name is never current again.
- **One host will not act for two claimants of one tenure.** That is the real
  guarantee, and it is narrower than it sounds: the claim binds an executor to
  the first claimant it acted for at that `(key, term)`, so the second is
  refused on that host.
- **But two hosts may each act for a different claimant**, and nothing produces
  agreement about which was legitimate. If that happens you have two
  coordinators that each got one host to act, and the ledger's job is to make it
  VISIBLE rather than to prevent it.

So enforcement narrows the blast radius of a stale leader; it does not eliminate
the split. Do not size a recovery plan as though it did.

#### Which proofs carry a term, and which legitimately do not

Not every proof is stamped, and an unstamped one is usually correct rather than
broken. A producer can only stamp a term if it holds a lease to take one from.

- The **failover coordinator** holds the failover lease, so it stamps the term
  of its own recorded tenure onto the reschedule and relocate proofs it mints.
  `reschedule` is the one action whose every producer holds a lease, so it is
  the one action where an unstamped proof is refused outright.
- **Container cold migration, LB apply and automated replica promotion** hold no
  lease at all. They mint term 0 with an empty key, and that is their normal
  output — refusing it would break container migration, load-balancer
  reconfiguration and post-fence promotion the moment the token latched, which
  is why the term requirement is scoped to `reschedule` rather than applied
  everywhere.

One consequence worth knowing: `relocate` has producers of both kinds, so an
unstamped relocate proof is either a lease-less producer's ordinary output or a
coordinator on an older build, and nothing can tell those apart. Narrowing that
needs a decision about whether container cold migration may require the
coordinator.

A proof's term and key are also part of a check that is INDEPENDENT of term
enforcement and runs whether or not it is switched on. An executor field-matches
the proof it was handed against the proof row it has persisted — action, target
kind and name, coordinator, destination, relocation token, fence epoch, owner
epoch, and the lease term and key; `corrosion.ProofBindingEqual` is the one
definition of that set. A mismatch refuses the action ungated, exactly as a
mismatched relocation token does. That catches a DIVERGENT PROOF ROW,
which is a different question from whether the term is current.

A proof's term and key are validated at every point where they could otherwise
become authoritative, which is more than one point. A carried proof is validated
on receipt, before it is persisted, because persisting it replicates it: an
unvalidated key would become that row's permanent authorization record on every
peer, and enforcement reading a nonexistent ledger for it would find
`MAX(term) = 0` and pass every proof naming it. Promotion validates the proof it
was handed before it seeds the row itself. And the key is checked again where a
term is JUDGED, because the reschedule path — the action this regime exists for
— never sees a carried proof at all: the destination reads the replicated row.
A row can therefore carry a key this node's own receipt check never saw, from a
peer still running a binary that did not narrow it, so the row is not trusted on
the strength of where it came from. A negative term is refused outright at the
same places.

The stamp also has to SURVIVE being persisted, which is not automatic while the
cluster is still activating. Latches form on each node independently, so a
coordinator whose `lease_term_ledger_v1` latch has formed can hand a stamped
proof to a receiver whose own latch has not. That receiver may put only the
previous release's proof shape on the wire, and that shape has no term columns:
seeding the row through it would strip the stamp — on that node and, because the
seed replicates, on every peer — and the retry of the identical proof, which is
how an interrupted action recovers, would then be refused as divergent. So a
receiver that cannot yet emit the stamp refuses the proof before writing
anything, with a **retryable** error rather than a divergence. During activation
you may see a direct action refused once or twice with a message about a stamp
the node cannot yet emit; it clears on its own when that node's latch forms,
which happens from the same peer set the coordinator's did.

Membership in the three lease names is **not** sufficient, and treating it as
sufficient was a real hole. The key SELECTS which ledger the threshold is
computed against, and the three advance independently, so naming a quieter
lease moves the bar — on a cluster that has never rebalanced, to 0, where any
term clears. So the accepted set is narrowed to the keys a proof PRODUCER
actually holds, which today is `failover` alone: the failover coordinator is
the only thing in the tree that stamps a key on a proof. The rebalancer and the
dual-run detector hold leases but produce no proofs. Widening that set is a
deliberate act, and the case that will force it is container cold migration,
which has producers of both kinds.

To read the current terms:

```sql
SELECT key, term, holder, acquired_at
FROM leader_lease_terms
ORDER BY key, term DESC;
```

A term is never reused, even after its row is tombstoned: allocation takes
`MAX(term) + 1` over every retained row, and the table survives a reseed for the
same reason. Do not add retention or GC to it without reading the constraints
recorded at `nextLeaseTerm` in `internal/corrosion/leader_lease.go`.

#### What to alert on

`litevirt_leader_lease_term{key=...}` is the highest recorded incarnation per
lease key. Its **rate** is leadership churn: terms climbing faster than the
failover rate you expect means flapping health checks, a TTL too short for the
environment, or a partition that keeps re-electing. This is the routine signal,
and it needs no conflict to be useful.

`litevirt_lww_tie_unresolved_current` going above zero for this table is the
serious one: **two nodes recorded themselves as holding the same term.** That is
the event the ledger exists to make visible, and it is a safety fault, not a
transient. `litevirt_lww_tie_unresolved_total` counts them cumulatively.

`litevirt_runtime_action_refused_total{reason="stale_lease_term"}` is
enforcement firing. Expect a burst around a genuine failover; a steady trickle
in calm conditions means a producer is minting proofs from a tenure it no longer
holds, and that producer is worth finding.

`litevirt_failover_stranded_workloads` is the one to alert on, and it is a
GAUGE rather than a rate: it counts workloads still assigned to a host in state
`fenced` or `offline` that failover would move off a dead host.

It is the lease holder's view. Every node runs a coordinator and serves
`/metrics`, but a node that is not driving failover publishes `0`, so alert on
`max()` across instances — or join on `litevirt_failover_leader` — and never on
`avg()`, which divides the real count by your fleet size.

Zero is the normal value. Non-zero means workloads are sitting on a host the
cluster considers down, and **what you should do depends on why it is down.**
Check `lv host inspect <host>` and the last `fencing_log` row before acting:

| Why the host is down | What to do |
| --- | --- |
| Fence never confirmed — `manual` strategy awaiting confirmation, a `best-effort` fence with a writable shared disk, or a fence that failed | `lv host fence-confirm <host>`, **after** you have confirmed the power state yourself. This is a normal state for a `manual`-strategy host, and the likeliest non-zero you will see. |
| Fenced successfully, but recovery was then refused — lost quorum, an ungated target, a superseded lease term, no placement candidate, a store error on the proof write | `lv host undrain <host>` once you have confirmed the host is dead. |
| Marked down by hand — `lv host fence <host>`, which never enumerates workloads | Nothing, if intended; the state clears on its own once quorum sees the host healthy. Use `lv host drain <host>` first next time, which moves the workloads. |

Do **not** reach for `lv host undrain` on an unconfirmed fence. It returns the
host to `active` while the machine may still be running, which is exactly the
split-brain the gate refused to create.

Two things the gauge will not tell you. Dropping to zero is not proof of
recovery: any command that moves the host out of `fenced`/`offline` — `undrain`
included — takes it out of the count whether or not the workloads went anywhere,
so confirm placement with `lv ls --host <host>` rather than trusting the
metric. And a re-fence is not immediate: a successful fence inside the last five
minutes suppresses the next one, so expect a delay before the ordinary failover
path runs again.

The refusal window itself cannot be closed. The checks that can refuse sit as
late as they do deliberately, because they close races against the writes they
guard, and moving them before the fence would make them staler than the thing
they protect. So the coordinator reports the condition instead of retrying it.

Automatic recovery was built, reviewed and withdrawn, and the reason is worth
knowing before anyone proposes it again. Acting unattended requires proving the
host was POWERED OFF, and nothing available to a coordinator proves that.
A host's recorded state records only that somebody decided it — `lv host fence-confirm`
writes `fenced` on any host with no precondition, so a mistyped hostname marks a
live one. Health quorum proves unreachability, which is equally true of a
partitioned host still running its VMs. Evacuating on either gives you two hosts
writing one shared disk, which is worse than the stranding it fixes. Doing it
safely needs a fence proof bound to the current outage, and the schema does not
carry one yet.

`litevirt_runtime_action_refused_total{reason="lease_term_unconfirmed"}` is
enforcement UNABLE to fire. It says actions are being refused for lack of
quorum evidence, so alert on it separately and treat it as an availability
signal rather than a safety one — this is the reason that appears when a
partition, not a stale leader, is the problem.

`litevirt_ha_degraded{reason="capability_rollout_pending"}` says a mandatory
token has not latched yet. During an upgrade that is expected and should not
page; persisting long after one is the signal that a host is stuck — most often
one parked in `maintenance` on an older build.

#### What this table will and will not show you

`PRIMARY KEY (key, term)` makes two rows for one term unrepresentable, so **no
single node's query can show you that two nodes held the same term.** Each node
keeps its own claim and refuses to overwrite it, so the disagreement lives
*between* nodes and in the metric above — never as two rows on one host. An
ordinary-looking table on the host you happened to query is not evidence that no
concurrent leadership happened.

A contested term is deliberately **not** resolved into a winner. Electing one
would destroy the losing claim and hand a future enforcement path a confident
answer to a question the cluster never agreed on. Instead both claims persist on
their own nodes and the conflict is flagged, which is why the alert above is the
access path rather than a query.

#### A node that was away does not claim a term from a stale ledger

A new tenure's term is one above the highest term in the claiming node's own
replica. That is only unique if the replica already holds every term the
cluster has minted, and a node that was away does not. A restarted daemon, or
a node reconnecting after a partition, comes back holding the ledger as it was
when it left. Its own expired lease then looks free, and it would claim the
term a peer took while it was gone: two claimants for one term, which is the
permanent conflict described above.

So before recording a **new** term, a node asks its peers for their newest term
for that key. This is the same quorum read the lease-term barrier makes for
executors (`GetLeaseTermHighWater`, sent to every healthy peer, with a quorum of
answers required). The node records the term only when no answer has reached
it. Otherwise the claim is withheld and the lease reported not held. Replication
then delivers the row the node was missing, and on its next poll the node sees
the real holder: it defers to a live holder, or takes over a dead holder's lease
at the term after the one it was missing. The check keys on the ledger rather
than on uptime, so a long partition healing is covered the same way a restart
is.

What a node waits for, concretely:

- **After a daemon start: one health-probe cycle.** Until the checker's first
  cycle completes, quorum reads as unknown, so no new term is claimed. In the
  fleet harness that is about 2 s from start. A peer's newer term then holds
  the claim back until replication delivers the row, which took about 1 s in
  the fleet harness once the links healed.
- **In the common case, nothing measurable.** A takeover mint costs one RPC per
  healthy peer: about 7 ms in the fleet harness, against under 1 ms without the
  read, on a lease with a TTL of tens of seconds. A renewal claims no term and
  asks nothing, so a holder keeps its lease exactly as before, and a node that
  sees a peer's live lease never gets as far as asking.
- **A cluster of one does not wait at all.** A node with no other host in its
  `hosts` table and no gossip member has nobody to ask and nobody who could hold
  a higher term. It claims at once, including during the checker's warm-up.
- **A node that has peers but reaches no quorum of them does not claim.** It
  cannot tell whether a peer already took the term. This withholds a number,
  not an action: everything the lease authorises (a fence, a reschedule) needs
  quorum anyway. It claims as soon as a quorum answers. A holder that loses its
  peers keeps renewing the term it already has.

While a claim is withheld the daemon logs `leader lease: not claiming a new term
yet` once per key, with the reason, and logs `new-term claim cleared` when the
claim goes through.

#### A node whose lease row is behind does not depose a live holder

A current ledger is not enough on its own. Whether the lease is *live* is read
from the node's own `leader_election` row, and that row can lag the ledger:
renewals write only `leader_election`, and anti-entropy does not carry that
table. So a node can hold every term row and still have the holder's expiry
from several renewals ago, or no row at all (a node that got its ledger from
anti-entropy or a reseed). Such a node reads a live lease as lapsed. The term
check passes, because nobody has minted the term it would claim. Minting that
term would depose the live holder. The holder would fail closed on its next
renewal once the term arrived, and until then both nodes would act as leader.

So when a node **takes over** a lease (its own replica shows no live tenure of
its own), the same quorum read also returns each peer's own `leader_election`
row. The takeover is withheld while any answering peer shows the lease live for
another holder. The holder itself answers too if it is reachable. The node
waits until the renewal reaches it, and then defers to the holder. If the
holder is really gone, it waits until every expiry a peer reported has passed,
which is one TTL after the last renewal that reached anyone, as with an ordinary
expiry. A mint over the node's own live lease (retiring a contested term) is not
a takeover and is not held to this. A peer on an older build reports no row, so
against that peer a takeover is judged on the term alone, as before. The
withholding reason names the peer and the holder it reported live.

#### A contested lease still converges

Keeping both claims is about the *evidence*. It does not mean both claimants
keep acting. Without the rule below they would: each replica's
`leader_election` row names its own claimant (a peer's renewal is a no-op
against a live row with another holder, and that table is anti-entropy
excluded), each replica's term row names its own claimant, so every claimant
classifies every tick as a renewal of its own tenure and renews forever.

Once a node learns another node claimed its current term — on the WAL,
the moment the peer's mint arrives, or on the next anti-entropy pass:

- **Every claimant but the lowest-sorting holder name stands down.** It stops
  renewing and reports the lease not held on that tick. Every claimant computes
  the same answer from the same set of claims, and the lowest one can never be
  told to stand down by it, so the rule cannot elect two or none.
- **The one that continues does not act under the contested term.** It mints a
  fresh term above it, atomically with its renewal. The contested term is then
  below every replica's rejection threshold, so neither of its two rows can
  authorise anything again. Both rows stay; the `ha.lww.unresolved` condition
  still fires for them, and still needs the acknowledgement below.
- **A stood-down claimant does not take the lease back when its own stale row
  expires.** An expired lease whose row names someone other than the ledger's
  current holder is left for one further TTL, which a live holder's renewal
  lands well inside. If the holder is dead, the lease is taken over one TTL
  later than an ordinary expiry would allow.
- **`litevirt_failover_leader` follows the ledger, not the row.** A stood-down
  claimant's own lease row still names it until that row expires, but the gauge
  reads the ledger's newest (contest-aware) holder too, so it drops to `0` on
  the loser as soon as its replica learns of the contest or of the winner's
  fresh term. `sum(litevirt_failover_leader) != 1` does not stay tripped for a
  TTL after the lease has converged.

Which claims a node knows about lives in memory. After a restart it is rebuilt
by the next anti-entropy pass, because the two rows still disagree and a
restarted daemon's first pass against each peer pulls and re-compares them
(later passes skip a table whose only difference is a tie already tracked);
until then a restarted claimant may renew a
contested term it had already stood down from. A contested term that is not a
key's *newest* term — history below the current tenure — needs nothing: it is
already below every threshold, and only its tie condition remains.

#### Clearing the condition once you have seen it

Because a contested term is never resolved into a winner, there is no
remediating write for the `ha.lww.unresolved` condition to wait for.
`leader_lease_terms` rows are immutable, the two rows disagree forever, and the
condition therefore stays dirty forever. Waiting it out does not work, and
neither does a restart on its own: the tie register is in memory, so a restart
empties it and the next anti-entropy pass re-registers the same tie within
seconds.

What clears it is a human saying they have seen it:

```
lv cluster acknowledge-lease-term --key failover --term 7
```

Five things about that command:

- **It clears evidence tracking, not the conflict.** Both claims stay in the
  ledger, no winner is elected, and the acknowledgement is written to the audit
  log with your principal, the key and the term.
- **It is durable.** The acknowledgement is kept in two local-only tables,
  `acknowledged_ties` and `acknowledged_tie_versions`, and reloaded at start.
  When a restarted daemon's first pass re-registers the tie, it is registered
  as acknowledged: `ha.lww.unresolved` stays clear and nothing re-alerts.
- **It covers the term as this host has seen it.** You name a lease and a term,
  so the acknowledgement covers every claim for that term the host has met, not
  only the one peer it met last. A term that five nodes claimed needs one
  acknowledgement per host, and later passes can meet the peers in any order.
  A claim the host meets for the first time *after* you acknowledged is new
  evidence. It is not covered: the condition comes back and `converge` reports
  a SAFETY-FAULT again. Investigate it, then acknowledge again on that host.
  Running the command again with nothing new to cover changes nothing and
  prints "No tracked tie".
- **It is node-local.** The register belongs to one daemon, and the RPC refuses
  peer certificates so that no node can silence its own split-brain evidence.
  The acknowledgement is not replicated either, for the same reason: one
  node's word would silence the evidence on hosts whose register nobody
  checked. Point `LV_HOST` at each host `lv health` names and run it there;
  verify with `lv cluster converge`.
- **It needs the `cluster.lww.acknowledge` verb**, held by Operator and Admin.
  That verb grants this and nothing else.

The two rows still differ on each host after the acknowledgement, so the table
never digests equal. `lv cluster converge` lists it as `ACKNOWLEDGED`, with the
number of acknowledged ties, and counts it as converged, but only when all of
the following hold on every host that reports the table:

- every tie the host tracks in the table is acknowledged;
- the host's *residual* digest agrees with every other host's. The residual is
  the table hashed with each acknowledged row replaced by its primary key, so
  two residuals agree only when nothing but the acknowledged rows differs.

If one tie on any host is unacknowledged, the table is a `SAFETY-FAULT`, with
the unacknowledged and acknowledged counts. It is also a `SAFETY-FAULT` if a
host cannot vouch for a residual (it tracks no tie there yet, or runs an older
build), or if the residuals disagree, because another row differs as well.
`lv cluster digest` shows the acknowledged count in its `TIES` column.

Investigate before acknowledging. Two nodes recording the same term means the
fencing token did its job — enforcement will refuse proofs from the losing
tenure — but something upstream let both nodes believe they held the lease.
Usually that is only two survivors of a leader death claiming it within one
replication round, which converges on its own as described above; a contested
term whose claimants were cut off from each other is a partition. A term claimed
a few seconds after its claimant's daemon started, minutes after the other
claim, is the stale-ledger claim described above, made by a build that did not
yet wait for the quorum read.
`litevirt_leader_lease_term` around the event tells you whether this was
leadership churn or a partition.

### Even-N clusters cannot fence in a 2/2 partition
- A 4-node cluster split exactly 2/2 has no majority. Both sides compute
  quorum=3 with 2 observers each → neither side can fence.
- **Use a witness host** for any even-N deployment. A witness participates
  in quorum but holds no workloads. Add the host normally, then promote it
  (the host must have no VMs):
  ```
  lv host config witness-1 --role witness
  ```

### A site partition is a majority/minority split of one cluster (by default)
- Under the default failover scope (`cluster`), region is a placement label,
  not an HA boundary. Quorum, gossip and health probes span every region, and
  failover picks its targets from every `active` host in the cluster. So when the link between two sites fails, the site
  holding a majority of voters fences the other site's hosts and reschedules
  their workloads onto itself, across the WAN, even though the other site may
  be alive. The minority site stalls. It fences and reschedules nothing, and
  its runtime-ownership actions refuse without quorum. Its running workloads
  keep running.
- What protects you on the majority side is the fence strategy.
  `ipmi` over a management path that survives the partition powers the
  minority off first. `ssh` and `manual`, and `ipmi` with an unreachable BMC,
  all fail closed and move nothing. `best-effort` does not: without
  `enforcement.safe_fence_default`, it reschedules VMs that are still running
  on the other side.
- Under cluster scope, keep an odd number of voting sites, or put a witness in
  a third site, and pin workloads that must not cross with `placement.require`
  on a per-site host label.
- **Region-scoped failover** is the opt-in alternative:
  `lv cluster failover-scope region`. A host is then fenced, re-admitted and
  recovered only on a majority of its own region's voters; its host's
  execution gate counts its own region; and recovery targets stay in its
  region. A site partition fences nothing on either side and the minority
  site's workloads keep running where they are. A host that really dies is
  still fenced and recovered by its own region, **if that region has at least
  three voters** — a region with fewer has no automatic failover while the
  policy is on, reported by `lv cluster failover-scope` and
  `litevirt_failover_regions_without_quorum`. VIP self-demotion and the
  lease-term barrier still count the whole cluster. The change is refused
  mid-roll and while any voter is unreachable. See
  [Federation](federation.md) → "Regions and failure" for the full contract
  and [design/region-scoped-failover.md](design/region-scoped-failover.md) for
  the reasoning.

### NTP is required
- All hosts must run NTP (chrony / systemd-timesyncd / ntpd). HLC tolerates
  ±5 minutes, but **anti-entropy LWW depends on monotonic, comparable
  timestamps** across hosts. Sustained skew above tolerance silently
  corrupts ordering of LWW-resolved fields.
- The daemon emits the `litevirt_cluster_clock_skew_seconds` metric per
  peer. Alert if any value exceeds 5 s.
- **Recommended alerting** on `litevirt_hlc_rejected_total > 0`: if any
  remote HLC has been rejected, a peer's clock is severely wrong; investigate
  immediately.

### CRDT replication is not synchronous
- A write committed locally may take **seconds** to appear on every peer in
  a healthy LAN cluster, longer over WAN. Code that needs "this write is
  visible everywhere before I act" should use a confirmation read on the
  target peer, not assume convergence.

### Gossip admits only known hosts, and is authenticated only when encrypted
- Gossip membership (memberlist, `gossip_port`) admits a member only when its
  name is a `hosts` row this node holds that is not removed, and it announces
  the address that row records. A name with no row, a removed host, and a real
  host's name announced from another address are all refused, and none of them
  counts anywhere membership is counted: relay election, replication and
  anti-entropy targets, and the recipients a replication-gated capability such
  as `lease_term_ledger_v1` must confirm.
- A host that joins before its `hosts` row has replicated to some existing node
  is refused by that node until the row arrives, then admitted by the next
  gossip exchange that mentions it — memberlist's periodic full-state exchange,
  30 s on the LAN profile and longer past 32 members. `lv host add` writes the
  row on the node it talks to before it starts the new daemon, so that node
  admits the newcomer at once, and the rest follow within replication time plus
  that interval.
- A node that holds no `hosts` row but its own, live or removed, and was given
  `join_peers`, admits what its seeds introduce, because that is the only way a
  newly added host can find the peers it learns the hosts table from. That
  window closes at the first replicated row. A founder with no `join_peers`
  never opens it.
- A host whose gossip address differs from its recorded address is refused and
  logged with both addresses. On a multi-homed host, set `advertise_address` to
  the address the host was added with.
- Admission checks names and addresses, and neither is a secret. What makes
  gossip authenticated is the cluster gossip key (`<pki_dir>/gossip.key`) with
  `enforcement.gossip_encryption: true` on every host: each packet and stream is
  AES-256-GCM under that key, and a node drops anything unencrypted or under a
  key it does not hold — before admission even sees it. See
  [Gossip encryption](auth.md#gossip-encryption) for the key, the rollout and
  rotation.
- **An unauthenticated gossip segment is not supported.** Until every host runs
  `gossip_encryption: true`, gossip is plaintext (or accepts plaintext, in the
  `install` and `staged` rollout stages): a machine on the segment can announce
  a real host's name from that host's own address, read the membership, or
  disturb failure detection. Keep `gossip_port` on a network only cluster hosts
  can reach until the rollout is finished. Even encrypted, the key is one shared
  secret: every host holding it can speak for any member, a removed host keeps
  what it knew, and encryption does not hide that gossip traffic exists — so
  rotate the key after removing a host you no longer trust, and keep the port
  firewalled regardless.

### Secret-bearing repair is peer-only
- Secret-bearing config is **excluded from the operator-readable full-state
  dump**. `GetStateDump` (and the `lv cluster converge` digest report, which shows
  only table hashes) do not export registry passwords, notification webhook URLs,
  or 2FA material.
- Eligible secret-bearing config (`registry_credentials`,
  `notification_targets`, `notification_routes`, `user_2fa`, `user_2fa_sets`,
  `recovery_codes`, `recovery_code_sets`) is repaired by a separate peer-mTLS-only
  anti-entropy lane. Peers already receive these rows through WAL replication; the
  peer-only pull is a repair path when a push was missed.
- 2FA/recovery are LWW-repairable: `user_2fa` soft-deletes, and each of 2FA and
  recovery codes is gated by a per-user active-set pointer (`user_2fa_sets`,
  `recovery_code_sets`). A factor/code is valid only when its epoch/set_id matches
  the pointer, so a row a partitioned peer resurrects (one a node never saw) can
  merge but never validate, and `DeleteUser` tombstones the pointers so a
  delete→recreate can't bring old auth state back. Safety holds once all
  auth-mutating nodes run ≥ schema v32.

### Disk-full is not auto-recovered
- The Corrosion store is a SQLite file. If the disk fills, the daemon stops
  accepting mutations. The cluster does not auto-evict the host. Monitor
  free disk; alert below 10%.

### Manual fence requires manual confirmation
- `FenceStrategy = "manual"` does not assume the host has been powered off.
  The operator MUST run `lv host fence-confirm <host>` after confirming the
  hardware is off. Without confirmation, VMs on the host remain in their
  pre-fence state, **even if the cluster has marked the host offline**.
- This is the safest behavior for clusters using shared storage where two
  running copies of a VM would corrupt the disk.

### No application-aware quiescence
- Backups, snapshots, and live migration are crash-consistent at the block
  level: each takes a real point-in-time view (a libvirt pull-mode session for
  backups, qemu's own machinery for migration).
- **Scheduled volume replication is weaker than that, and the difference
  matters.** A full (non-incremental) replica of a RUNNING VM is
  `qemu-img convert -U` reading the image the guest still has open, with no
  snapshot: the copy is smeared across however long it took, so it is not
  point-in-time and not crash-consistent either. The `--incremental` path DOES
  open a point-in-time session and is crash-consistent. See
  [Backups](backups.md). The guest's database, filesystem, etc. must tolerate "as if power
  was cut" recovery. For application-consistent backups, install
  `qemu-guest-agent` in the guest and use the `freeze`/`thaw` hooks
  (currently best-effort; richer integration is on the roadmap).

---

## Sizing and deployment recommendations

### Cluster size
- **3 nodes**: minimum for any HA workload. 1-node failure tolerated.
- **5 nodes**: recommended. 2-node failure tolerated.
- **Even N**: only with a witness. 2-node with witness is fine for homelab.
- **Beyond ~5 nodes**: no size is load-tested. The largest automated cluster in
  this repo that runs workload scenarios is 3 nodes (`tests/fleet/`), the only
  larger one measures anti-entropy alone (below), and the largest by hand is
  the 4-node lab. The relay-quorum protocol scales O(n) by design and there is no known
  ceiling, but a figure like "tested and supported at ~50 nodes" is not
  backed by a sustained load test and should not be planned
  against. Larger clusters will likely need the anti-entropy interval tuned.
- **Anti-entropy pass cost, measured at 50 nodes.** `TestFleet_AntiEntropyScale_PassCost`
  in `tests/fleet/` runs 50 daemons in one process, each with its own replica
  and real gRPC/mTLS, holding 200 VMs of state; `LITEVIRT_FLEET_AE_NODES=50`
  selects that size. One scheduled pass on every node costs 408 anti-entropy
  RPCs and 0.53 MB of responses when the replicas agree (8.2 RPCs per node),
  where a pass contacting every member costs 4,900 RPCs and 6.3 MB. With one
  row drifted on one node the pass pulls 730 bytes of table dumps, where
  answering every mismatch with the full dump pulls 7.9 MB, and the row reaches
  all 50 replicas within 3 passes. That is the cost of one pass in one
  process, not a sustained load test.
- **Health-probe cost.** Voters probe every peer; a non-voter probes every
  voter plus three other non-voters, so every host is still observed by every
  voter and fence and recovery quorums see the same rows as a full mesh.
  `TestProbesPerCycle_Scale` in `internal/health/` counts real probe cycles,
  per 2 s cycle: with every host voting (today's voter set, where every host
  not `offline`, `maintenance` or `fenced` votes) the cost is unchanged at 20,
  380 and 2,450 probes for 5, 20 and 50 nodes (2,450 is 1,225 probes/s).
  With 3, 5 and 5 voters it is 20, 215 and 605. The saving needs a voter set
  smaller than the cluster; until then the probe mesh is still N·(N−1).
- **Digest cost.** One full public digest over a 50-node cluster's worth of
  rows (a full `host_health` mesh and 2,000 VMs) takes about 55 ms and
  allocates 5.7 MB (`BenchmarkStateDigest_50Nodes`). A pass and every peer
  that asks take unchanged tables from the digest cache instead
  (`BenchmarkStateDigestCached_50Nodes`), so the scan cost falls to the tables
  written since the last pass: with a `host_health` row rewritten between
  digests (that table is most of the rows, and is rescanned), 11 ms and 2.4 MB
  against 29 ms and 6.8 MB for a full scan on the same machine. One drifted row in a 4,000-row table costs a
  bucketed pass about 8 KB and 21 rows, against 180 KB and the whole table for
  the pull before buckets (`TestFleet_AntiEntropy_Buckets_OneDriftedRowPullsOneBucket`).

### Network
- **Inter-host RTT < 10 ms**: comfortable. Default replicator and
  health-check intervals work without tuning.
- **Inter-host RTT 10-100 ms**: still works but increase `pollInterval`,
  `healthFreshness`, and `leaseDuration` proportionally to avoid lease
  thrash.
- **Multi-DC (RTT > 100 ms)**: supported in principle; tune intervals up
  significantly. Under the default failover scope a multi-DC cluster is still
  one failure domain: a site partition fences and reschedules across the WAN.
  `lv cluster failover-scope region` makes each site its own failure domain
  (see "A site partition is a majority/minority split of one cluster" above).

### Fencing strategy
- **Production with shared storage**: `ipmi` (mandatory). SSH and watchdog
  are insufficient because a network-isolated but otherwise-healthy node can
  refuse SSH but continue writing to the shared volume.
- **Production without shared storage**: `ssh` is acceptable; `best-effort`
  for clusters that explicitly opt out of split-brain protection.
- **Homelab / single-tenant**: `manual` works if you're awake to confirm.
- **All hosts**: configure `watchdog` as a backstop so a hung daemon
  self-fences within the watchdog timeout.

### NTP
- Mandatory. Run `chrony` and verify `chronyc tracking` reports
  `Leap status: Normal` on every host.

---

## Observability checklist

Operators should monitor these Prometheus metrics:

| Metric | Alert threshold |
|---|---|
| `litevirt_peer_healthy` | 0 for any pair sustained > 30 s |
| `litevirt_cluster_clock_skew_seconds` | > 5 |
| `litevirt_hlc_rejected_total` | > 0 (sustained) |
| `litevirt_fence_failures_total` | rate > 0 over 5 min |
| `litevirt_failover_leader` | sum across cluster != 1 sustained |
| `litevirt_failover_attempts_total{result="error"}` | rate > 0 over 5 min (a failover decision hit a store/fence error) |
| `litevirt_failover_regions_without_quorum` | `max() > 0` under region-scoped failover (a region holding workloads cannot fence its own hosts) |
| `litevirt_mutation_log_rows` | rapidly growing (replication backlog) |
| `litevirt_replication_min_watermark_seq` | not advancing for > 5 min |
| `litevirt_replication_backlog_age_seconds` | > 300 s sustained |
| `litevirt_daemon_open_fds` | > 5000 (FD leak) |
| `litevirt_lb_keepalived_up{lb}` | `== 0` sustained (a load balancer's VIP is not assigned — see [compose.md](compose.md#load-balancer)) |

The web UI at port 7445 surfaces the most critical of these on the
**Cluster** page; full dashboards are on the roadmap.

---

## Recovery playbook (one-line summaries)

| Symptom | Action |
|---|---|
| Host unreachable, fence-pending alert | Confirm out-of-band; if dead, `lv host fence-confirm <host>` |
| Fence failed, VMs stuck on offline host | Inspect IPMI; if power-off confirmed externally, run fence-confirm |
| Two leaders observed via metric | Kill the older daemon; investigate clock skew |
| HLC rejected counter rising on one peer | Check NTP on that peer; expect to fence it |
| Replication backlog growing | Identify slow peer via watermarks; consider `lv host drain` |
| Disk full on one host | Drain → repair disk → re-add as fresh peer |
| A voter is gone for good | `lv cluster voter rm <host>`, then `lv host rm <host>` |
| `lv cluster voter ls` shows a member ABSTAINING | `lv cluster voter rm <host>` then `lv cluster voter add <host>` |
| `ha.voter.genesis_pending` persists | Clear what it names, or `lv cluster voter init --members <hosts>` |

---

## Anti-features (deliberate non-guarantees)

litevirt does not provide any of the following. Each is an intentional
boundary, not an oversight:

- **Strong consistency for cluster state.** Use anti-entropy + LWW; design
  workloads to tolerate it.
- **Synchronous cross-host writes.** All writes are local; replication is
  async.
- **Automatic *true* split-brain reconciliation.** A divergence that's safe to
  resolve — a workload running on exactly one host whose DB ownership drifted — is
  reclaimed automatically (runtime owner-assert / re-key, on all-peers-absent
  proof). But a genuine split-brain (the same workload running on two hosts) is
  never auto-resolved by host-order: litevirt refuses, alerts, and a human decides
  (destruction needs positive fencing proof). See [Diagnostics](diagnostics.md).
- **Cluster-wide rolling-upgrade automation that is invisible to operators.**
  Upgrades are explicit (`lv host upgrade`) and can be batched but never
  silent.
- **Multi-master reconciliation of conflicting application state.** That's
  the application's job; we sync metadata, not user data.
