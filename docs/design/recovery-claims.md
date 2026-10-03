# Design: single-winner recovery claims

| | |
|---|---|
| Status | **Implemented.** §3's voter side, proposer and certificates and §4's voter set landed with `feat/voter-set` (colonelpanik/litevirt#251 step 2); recovery enforcement (`recovery_claim_v1`), attempt progression and `lv host rm --dead`, forced reconfiguration, `ha.voter.unavailable` and `lv cluster claim` landed with `feat/recovery-claims` (colonelpanik/litevirt#250). See *Implementation status* below and §10 for where the code departs from the text. |
| Issues | colonelpanik/litevirt#250; colonelpanik/litevirt#251 (step 2) |
| Base | `main` at `8dde9cc7` |
| Pinned by | `TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner` (`tests/fleet/failover_two_coordinators_test.go`): two writable owners without claims, one with them |

**Reading this document.** Present tense describes code that exists. Where
the landed code does something other than the text, §10 says what and why; the
body was corrected where it described the mechanism. The docs guard
(`cmd/litevirt/docs_triangulation_test.go`) only scans `README.md` and
`docs/*.md`, so it does not read this file. The operator-facing parts live in
`docs/migration-failover.md`, `docs/operating-model.md`,
`docs/configuration.md`, `docs/cli-reference.md`, `docs/diagnostics.md` and
`docs/upgrades.md`, and the guard checks them there.

**Implementation status.**

| Part | State | Where |
|---|---|---|
| Ballots, value digest, signed accepts, certificate verification (§3.2, §3.4, §3.9) | exists | `internal/corrosion/recovery_claims.go` (`ClaimVerifier.Verify`) |
| Voter rules, grant table, durability, incarnation, owner probe (§3.5–§3.8, §3.11) | exists | `internal/corrosion/recovery_claims_voter.go`, `voter_local.go`, `internal/grpcapi/claim_probe.go` |
| Claim RPCs (§3.3) | exist | `PrepareRecoveryClaim` (with supersede evidence), `AcceptRecoveryClaim`, `GetRecoveryClaim`, `ListRecoveryClaims` (`internal/grpcapi/recovery_claims.go`) |
| Proposer (§3.13 steps 3–6), including retry at the same round | exists | `internal/claims` |
| Voter set, genesis, add / rm / reset, seal and transfer, `VoterSet` (§4.1–§4.5) | exists | `internal/corrosion/voter_config.go`, `internal/grpcapi/voter_config.go`, `lv cluster voter` |
| `voter_config_v1` (§5.1) | exists | `capabilities.VoterConfigV1`, `grpcapi.VoterConfigReadiness` |
| `recovery_claim_v1`, `enforcement.recovery_claim` (§5.1–§5.2) | exists | `capabilities.RecoveryClaimV1`, `grpcapi.RecoveryClaimReadiness`, `Server.RecoveryClaimEnforced` |
| Claim before mint at reschedule, promote and container relocate (§3.13 steps 1–2, §9 Q7) | exists | `internal/failover/claims.go` (`claimRecovery`), `grpcapi.Server.claimPromote` |
| `claim_certificate` column and field (§3.9 carriage), schema v60 | exists | `internal/corrosion/recovery_claims_proof.go`, `RuntimeActionProof.claim_certificate` |
| Verify before execute (§3.10) | exists | `corrosion.VerifyClaimCertificate` at `startPendingVM`, the container checker and `claimCarriedProof` |
| Abandonment, `local_abandoned_proofs` (v61), removal evidence, `lv host rm --dead`, `ha.claim.stranded` (§3.12) | exists | `internal/corrosion/recovery_claims_supersede.go`, `internal/grpcapi/recovery_claim_supersede.go`, `internal/cli/host_rm.go` |
| `lv cluster voter force-reconfigure`, `force:` rows, `local_voter_seals` (v62), `ha.voter.forced`, re-certification (§4.6) | exists | `internal/corrosion/voter_force.go`, `internal/grpcapi/voter_force.go`, `Coordinator.recertifyReplaced` |
| `ha.voter.unavailable`, `lv cluster claim` (§4.3, §5.4) | exist | `internal/grpcapi/recovery_claim_inspect.go` |

Sections are numbered so a reviewer can approve or reject each one separately.
§3 and §4 carry the safety argument. §5 onward depends on them.

---

## 1. Problem

### 1.1 What recovery does today, and why no layer picks one winner

A host failure is recovered by the failover coordinator
(`internal/failover/coordinator.go`). Every node runs one. Each poll
(`pollInterval`, 5 s) does this:

1. **Lease.** `acquireLeaseResult` calls `corrosion.AcquireLeaseWithTerm`. That
   is a guarded upsert into the *local* `leader_election` row plus a term mint
   into the *local* `leader_lease_terms` ledger. The comment on `acquireLease`
   says it plainly: *"The CRDT row store cannot offer linearisable CAS across
   partitions, so this is best-effort."*
2. **Quorum.** `corrosion.VoterSet` gives the denominator. Fresh `host_health`
   rows whose observer is in that set (`countsAsVote`) give the numerator.
   Since `a480937f` both come from one set (colonelpanik/litevirt#251 step 1).
   That set is still *derived* from replicated `hosts.state`.
3. **Fence.** `failover()` checks `holdLeaseAtLeast(minFenceLease)`, fences
   within the lease that authorises it, records `fencing_log`, and re-checks
   `holdLease` before going on.
4. **Authorize recovery.** For each VM, `recoverWorkloads` either promotes a
   replica (`Promoter.AutoPromoteReplica`, which carries a proof over RPC) or
   reschedules. Under `split_brain_gate_v1` the reschedule mints an
   `ActionProof` and writes it with `corrosion.WriteVMRescheduleProof`. That
   guard checks `vm_owner_epoch` against the *local* row. Containers go through
   `relocateContainers` / `startRelocation`.
5. **Execute.** The destination's reconciler (`startPendingVM` in
   `internal/health/reconciler.go`) or its gRPC handler (`claimCarriedProof` in
   `internal/grpcapi/action_proof.go`) validates the proof against its own
   replica and calls `ClaimActionProofFenced`.

Each layer is real, and none of them picks a single winner per workload:

| Layer | What it guarantees | Why two coordinators both pass |
|---|---|---|
| Leader lease | Suppresses concurrent coordinators once replication has delivered the other's claim | The acquire and its read-back are both local. Two replicas that have not exchanged rows each confirm their own holder. |
| Lease-term ledger + contest rule (`leader_lease_contest.go`) | A contested term is retired and the lowest-sorting claimant keeps the lease, *once the claims replicate* | Convergence starts only after replication. The decision window is before that. |
| `DecisionGate` quorum | The deciding node probed a live majority itself | Both survivors genuinely see a majority. Only replication is delayed. |
| Action proofs | Single use per proof ID (`claimProofSQL`) | Each coordinator mints its own proof ID. Single use per proof is not single winner per workload. |
| `owner_epoch` binding | A proof cannot outlive an ownership change it did not cause (ABA) | Both proofs bind the same, still-current epoch. |
| `local_term_bindings` fence (`ClaimActionProofFenced`) | One executor never acts for two claimants of one `(lease_key, term)` | Two *different* executors each bind to a different claimant. `docs/operating-model.md` says this outright: *"two hosts may each act for a different claimant"*. |

### 1.2 Harness evidence

`TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner` builds three
independent replicas with `failedHostFleet`: survivors `a` and `b`, and a victim
holding `vm-victim`. It lets both survivors' failed probes of the victim
replicate, so each sees quorum. Then it blocks replication between `a` and `b`
(`SetLinkFaultBoth(a, b, LinkFault{Block: true})`) and has each survivor stop a
workload of its own that the other does not hear about. That is the independent
history colonelpanik/litevirt#250 describes, and it makes the two placements
differ. Both coordinators then tick inside the window, and each survivor's
reconciler runs once.

Run without its `t.Skip`, the test fails in **both** arms:

- **legacy** (no split-brain gate): each coordinator acquires the lease in its
  own replica, fences the victim, and calls `UpdateVMHost` pointing the VM at
  itself. Each reconciler starts it.
- **proof-gated** (`quorateGate`, which admits every decision exactly as a
  latched `split_brain_gate_v1` with real quorum would): each coordinator mints
  its own proof for its own destination. Each executor finds a valid, unspent,
  epoch-matching proof in its own replica and claims it. Both start the VM.

Both coordinators fence, and both destinations run `vm-victim`. The run's
report also showed that **the split outlived the heal by 40 s or more**. When
replication resumes, the `vms` row converges by LWW to one `host_name`, but a
row converging does not stop a domain that is already running. The second
writer outlives the partition. The fix therefore has to stop the second start.
It cannot rely on repairing afterwards.

### 1.3 The voter set (colonelpanik/litevirt#251)

Step 1 (`a480937f`) made the fence quorum, the recovery quorum and
`health.QuorumProof` count over one `corrosion.VoterSet`. That set is still
computed from `hosts.state`, which is eventually consistent. Two coordinators
can compute different denominators. The set also changes on its own when a
`hosts` row replicates. A claim protocol that counts a majority needs a
majority *of something both sides agree on*, which a set derived from LWW rows
is not. Step 2 (§4) makes the set explicit.

---

## 2. Goals and non-goals

**Goals**

- **G1.** For each workload ownership generation, at most one recovery
  destination can receive valid authority to start the workload, whatever the
  replication delay, message loss, duplication or reordering, and however many
  coordinators believe they hold the lease.
- **G2.** The destination enforces G1 and does not trust the coordinator. A
  destination starts a recovered workload only if it holds a verifiable majority
  certificate for that exact decision.
- **G3.** No new external dependency, no permanently special node, and no
  second replication system. The state that makes G1 true is small and local
  to each voter.
- **G4.** The voting population is explicit, identical on every node, and
  changes only through an operator action (colonelpanik/litevirt#251 step 2).
  Once initialized it is permanent: it does not depend on whether recovery
  claims are enforced, and no kill switch dissolves it.
- **G5.** Off by default and inert until the cluster latches it. A kill switch
  must return recovery authorization to today's behaviour.
- **G6.** A certificate also records that a majority of voters, each probing
  for itself, could not reach the workload's recorded owner. No coordinator,
  whatever its own health view says, can certify the recovery of a host that
  most voters can still reach.

**Non-goals**

- **Fencing itself is not serialized.** Two coordinators may both fence the
  victim. Fence primitives are required to be idempotent
  (`docs/operating-model.md`, *CRDT is not linearizable*), and a second
  power-off of a host the quorum already agrees is down creates no second
  writer. Claims serialize what comes *after* the fence.
- **The lease is not replaced.** It stays as a liveness mechanism: it keeps
  proposers from duelling. It stops being what safety depends on.
- **Operator-initiated moves are out of scope:** live migration, drain,
  `lv host fence-confirm` followed by a resumed recovery the operator drives,
  and `lv cutover`. Each is either source-driven while the source is alive or
  already serialized by an operator.
- **Inventory, observations, placement and every other LWW table stay as they
  are.** Only the recovery decision gets a stronger authority.
- **No general-purpose consensus.** Voter-config changes (§4) are the only
  other decision routed through claims.
- **No storage-level exclusivity.** See §8.2.

---

## 3. The claim protocol

### 3.1 Overview

A recovery decision is one instance of single-decree Paxos. The coordinator is
the proposer. The members of the voter config (§4) are the acceptors. A
**claim** is keyed by what is being decided:

```
claim key = (target_kind, target_name, incarnation, owner_epoch, attempt)
```

- `target_kind` / `target_name` are `vm` / `container` and the workload name.
  These are the same fields as `ActionProof.TargetKind` / `TargetName`.
- `incarnation` is the workload row's `created_at`, which names one
  incarnation of the name: every path that moves a row keeps it (a container
  relocation too, since §10 item 37), and every path that brings a name back
  to life stamps a fresh one. It is `""` (a
  *legacy* key) until `claim_incarnation_v1` latches, and always for
  `voter_config`. §10 item 37 says why it was added.
- `owner_epoch` is the generation being *left*: `vms.vm_owner_epoch` or
  `containers.owner_epoch`, read from the row at the decision boundary exactly
  as `WriteVMRescheduleProof` reads it today.
- `attempt` starts at 0. It advances only when the destination of a decided
  claim has provably refused to execute it (§3.12).

The **value** decided is the complete proof binding, so any coordinator can
turn a decided value back into its proof (§3.4). The **certificate** is a
majority of signed accept replies for one ballot and one value (§3.9).

```
coordinator (proposer)             voters (acceptors, incl. itself)          destination
  fence victim (unchanged)
  Prepare(key, ballot) ───────────▶ promise if ballot > promised;
                                    fsync; reply with any accepted value
  ◀── majority of promises
  value := highest-ballot accepted value among promises, else own proposal
  Accept(key, ballot, value) ─────▶ accept if ballot >= promised
                                    and I cannot reach the old owner;
                                    fsync; sign; reply
  ◀── majority of signed accepts = certificate
  write proof + certificate  ──── replication / carried RPC ────────────▶ verify certificate,
                                                                          then ClaimActionProofFenced,
                                                                          then start
```

### 3.2 Ballots

```
ballot = (round uint64, coordinator string, boot_nonce [16]byte)
```

- **Order.** A higher `round` ranks higher. At an equal `round`, the
  lexicographically *lower* coordinator name ranks higher. That matches the
  lease-contest rule in `leader_lease_contest.go`, which keeps the
  lowest-sorting claimant, so the node that rule keeps also wins an equal-round
  duel. `boot_nonce` breaks any remaining tie.
- **Round seed.** The first round a coordinator tries is `max(c.LeaseTerm(), 1)`.
  A newer lease incarnation therefore outranks an older one without any extra
  message. After a rejection, the next round is `max(rejected.promised.round) + 1`.
- **Why `boot_nonce`.** Paxos requires that a ballot is never used with two
  different values. A proposer that crashes after sending `Accept(b, v1)` and
  restarts could otherwise re-derive the same `(round, coordinator)` and propose
  `v2`. Two values would then sit at one ballot on different voters, and the
  "highest accepted ballot" rule would stop being well-defined. A random nonce
  drawn at process start makes every incarnation's ballots distinct, so the
  proposer needs no durable state. Within one process, a ballot is bound to
  exactly one value in memory.

### 3.3 Messages

The claim RPCs are in `proto/litevirt/v1/service.proto`. Prepare, Accept and the
bulk `ListRecoveryClaims` are authorized like replication RPCs: the caller must
present a known host certificate, and a ballot's `coordinator` must be the
caller's certificate CN. `GetRecoveryClaim` is read-only and also answers an
operator. The wire messages carry a few more fields than the sketch below
(`RecoveryClaimValue.voter_config`, refusal reason and detail on Prepare, the
key on `ClaimAccept`, the adopted generation on `GetRecoveryClaim`).

```proto
message RecoveryClaimKey {
  string target_kind = 1;  // vm | container | voter_config
  string target_name = 2;  // workload name; "" for voter_config
  int64  owner_epoch = 3;  // generation being left; config generation for voter_config
  int64  attempt     = 4;
}
message ClaimBallot { uint64 round = 1; string coordinator = 2; bytes boot_nonce = 3; }

message PrepareRecoveryClaimRequest  { RecoveryClaimKey key = 1; ClaimBallot ballot = 2; int64 config_generation = 3; }
message PrepareRecoveryClaimResponse {
  bool        promised          = 1;
  ClaimBallot promised_ballot   = 2;  // on refusal: what this voter has promised
  ClaimBallot accepted_ballot   = 3;  // unset if nothing accepted
  RecoveryClaimValue accepted_value = 4;
  string      voter             = 5;
  string      voter_incarnation = 6;
}
message AcceptRecoveryClaimRequest  { RecoveryClaimKey key = 1; ClaimBallot ballot = 2; RecoveryClaimValue value = 3; int64 config_generation = 4; }
message AcceptRecoveryClaimResponse {
  bool        accepted        = 1;
  ClaimBallot promised_ballot = 2;
  ClaimAccept accept          = 3;
  string      voter           = 4;
  string      refusal_reason  = 5;  // e.g. recovery_claim_owner_reachable (§3.5.1)
  string      refusal_detail  = 6;  // e.g. "node-3 still reaches node-2 (Ping answered in 4 ms)"
}

// Read-only. Used by coordinators to learn, and by `lv cluster claim` to inspect.
message GetRecoveryClaimRequest  { RecoveryClaimKey key = 1; }
message GetRecoveryClaimResponse {
  PrepareRecoveryClaimResponse state = 1;
  ClaimAccept accept                 = 2;
  string last_refusal_reason         = 3;  // this voter's most recent refusal for the key
  string last_refusal_detail         = 4;
}
```

`RecoveryClaimValue` carries the `ActionProof` binding fields and the source
host (§3.4). `ClaimAccept` is one voter's signed accept (§3.9). A voter keeps
its last refusal per key in memory only. It is diagnostic, is not persisted,
and does not survive a restart.

### 3.4 The value

A value is everything the destination binds on. It is the field set of
`corrosion.ProofBindingEqual`: `id`, `action`, `target_kind`, `target_name`,
`dest_host`, `coordinator`, `relocation_token`, `fence_epoch`, `owner_epoch`,
`lease_term`, `lease_key`. It adds one claim-only field, `source_host`: the
recorded owner being left, which is the host every voter probes before it
accepts (§3.5.1). `source_host` is not a proof binding field and is not added to
`ProofBindingEqual`, but it is inside the digest, so a certificate names the
source its voters could not reach. Each value is identified by

```
value_digest = SHA-256("litevirt-recovery-value-v1"
                       || canonical(binding fields) || source_host)
```

The value holds the whole proof and not just a destination name, for this
reason: a coordinator that learns a decided value in phase 1 can re-materialize
the *same* proof, with the same ID, through `WriteVMRescheduleProof`,
`WriteActionProof` or the carried RPC. Completing someone else's decision is
then idempotent. It never produces a second proof.

### 3.5 Voter rules

The voter's handler, `internal/corrosion/recovery_claims_voter.go`, does this for
each message. Each step runs in one local SQLite transaction:

```
Prepare(key, b, gen):
  refuse unless gen == my adopted config generation AND I am a member at gen
         AND my voter_incarnation matches the member entry            (§3.11, §4)
  row := local_recovery_claims[key]
  if row.promised > b: reply {promised:false, promised_ballot: row.promised}
  if row.promised == b: reply {promised:true, ...}      (the same Prepare again: already on disk)
  row.promised := b ; COMMIT (durable) ; reply {promised:true, accepted_ballot, accepted_value}

Accept(key, b, v, gen):
  same membership checks
  if row.promised > b: reply {accepted:false, promised_ballot: row.promised}
  if row.accepted_ballot == b and row.value_digest != digest(v): refuse (proposer bug)
  if key is a workload key and row.value_digest != digest(v):              (§3.5.1)
      if v.source_host == me:
          refuse {owner_reachable, "<me> is the owner"}
      if my settled row for the target at key.owner_epoch names a host != v.source_host:
          refuse {source_mismatch}
      if probeOwner(v.source_host) reached it:
          refuse {owner_reachable, "<me> still reaches <source_host>"}
  row.promised := b ; row.accepted_ballot := b ; row.value := v
  row.signature := Sign(accept payload) ; COMMIT (durable) ; reply {accepted:true, accept}
```

A refusal writes nothing. A voter keeps promises and acceptances forever for a
key. It never deletes or downgrades one (§9, Q6). Duplicate and replayed
messages are idempotent by construction. A repeated `Accept(b, v)` returns the
stored signed accept. A replayed older `Prepare` or `Accept` is refused by the
`promised` check.

#### 3.5.1 The owner probe

Before a voter accepts a workload value it has not accepted before, it checks
the precondition itself: it probes `v.source_host` directly and refuses if it
can reach it. It does not read replicated `host_health` rows to decide this.
Those rows are only as fresh as replication, so a voter that trusted them would
refuse, or accept, on another node's stale observation.

- **Accept, not Prepare.** A promise carries no value, so it cannot authorize a
  recovery. Only accepts form a certificate, and gating the promise as well
  would protect nothing. Gating it would also break phase 1 as the way to
  *learn*: a lagging coordinator (§3.12) and `lv cluster claim` both
  read decided values through it, and must be able to while the owner is up. A
  voter starts the probe when a `Prepare` arrives, so the `Accept` rarely
  waits for it. The probe runs detached from both RPCs, and only a probe that
  finished is stored (§10 item 36).
- **The probe.** A `Ping` over the peer transport (mTLS, host certificate) to
  the address in the voter's `hosts` row for `source_host`. It counts as
  *reached* only if the handshake completes, the peer certificate's CN is
  `source_host`, and the RPC returns. Anything else, including a different
  host answering on a reused address, is *not reached*. Its timeout is
  `claimProbeTimeout` (2 s), the same order as `health.checkTimeout`
  (3 s).
- **Cost per recovery.** The probe runs once per `(voter, source_host)`, not
  once per workload: every `Accept` naming the same source within
  `claimProbeMaxAge` (5 s, one `claimTimeout`) reuses the result. A
  failed host with fifty workloads costs each voter one probe per
  `claimProbeRefreshAge` (2 s), never two at once. Voters probe in
  parallel, so the claim's added latency is at most one `claimProbeTimeout`,
  and less when the probe started at `Prepare`. A powered-off host usually
  costs the full timeout, because nothing answers the dial.
- **Already-accepted values are not re-probed.** A voter that already holds
  `digest(v)` for this key checked the source when it first accepted `v`, and
  re-accepting it at a higher ballot does not probe again. Without this, a
  value that a majority chose just before the owner came back could never be
  certified (§3.15). A certificate therefore means: *a majority of voters each
  could not reach `source_host` when it first accepted this value.*
- **The source cross-check.** A voter whose own `vms` / `containers` row for
  the target is at `key.owner_epoch` and not pending checks that its
  `host_name` is `v.source_host`, and refuses with
  `recovery_claim_source_mismatch` if it is not. A row at another
  epoch, or one mid-transfer, says nothing about this key, and the voter does
  not wait for it. The row for epoch `e` was written when the workload last
  moved, normally long before the failure, so this does not race the decision
  the way `host_health` freshness does.
- **Refusals are named.** The refusal carries the voter and what it reached,
  for example `recovery_claim_owner_reachable` with detail
  `node-3 still reaches node-2 (Ping answered in 4 ms)`. The coordinator
  reports every refusing voter in its gate refusal (§5.4), and
  `lv cluster claim` prints each voter's last refusal for the key.
- **Asymmetric reachability.** If a majority of voters reach the owner, no
  certificate forms and recovery refuses. That is correct: the owner is up for
  most of the cluster, whatever the coordinator's own view. If only a minority
  reach it, the rest can form a certificate, and recovery proceeds after the
  fence exactly as it does today. With an even voter count, an exact split
  refuses, because a certificate needs more than half.
- **Proof-grade fencing.** The claim runs after the fence (§3.13). After an IPMI
  power-off, the probe cannot succeed, so the check never refuses and costs only
  its latency, most of which the `Prepare`-time start hides. Where the fence was
  best-effort and did not take, the probe is what stops the recovery of a host
  that is still up.
- **A voter that is the old owner** refuses outright, without probing. If it
  can answer an `Accept`, it is up, and it must not count toward certifying its
  own eviction. It still counts in the denominator, as a fenced member does
  (§4.3), so the other voters must supply the majority on their own.
- **A rogue or buggy coordinator.** A coordinator with a wrong failure
  detector, or a peer key used to forge `host_health` or `fencing_log` rows,
  cannot make a majority of voters fail to reach a host that is up. So it
  cannot certify that host's eviction, and the cross-check stops it from naming
  a dead host as the source of a workload whose row is settled. The probe does
  not stop a coordinator that genuinely powers the owner off first (fence
  primitives remain their own trust boundary), and for a row mid-transfer it
  relies on the probe alone.
- **What it does not check.** It probes the owner's daemon, not its domains. A
  daemon that has crashed while qemu keeps running reads as unreachable. That
  is why the probe adds to fencing and does not replace it.
- **Safety is unaffected.** Paxos lets an acceptor refuse any `Accept` for any
  reason, and a refusal changes no state, so §3.16's argument holds unchanged.
  The probe only removes certificates. It never creates one.

The probe applies to workload keys only. A `voter_config` key has no source
(`source_host` is `""`), and its changes are gated as §4.3 and §4.6 describe.

### 3.6 The local grant table

In `schemaDDL` (`internal/corrosion/schema.go`), and like
`local_term_bindings` absent from `tableNames` (`internal/corrosion/sync.go`)
and from every sync path:

```sql
-- NODE-LOCAL. Never in tableNames, never relayed, never anti-entropy repaired.
CREATE TABLE IF NOT EXISTS local_recovery_claims (
    target_kind        TEXT    NOT NULL,
    target_name        TEXT    NOT NULL,
    owner_epoch        INTEGER NOT NULL,
    attempt            INTEGER NOT NULL,
    promised_round     INTEGER NOT NULL DEFAULT 0,
    promised_coord     TEXT    NOT NULL DEFAULT '',
    promised_nonce     BLOB    NOT NULL DEFAULT x'',
    accepted_round     INTEGER NOT NULL DEFAULT 0,   -- 0 = nothing accepted
    accepted_coord     TEXT    NOT NULL DEFAULT '',
    accepted_nonce     BLOB    NOT NULL DEFAULT x'',
    value_json         TEXT    NOT NULL DEFAULT '',  -- RecoveryClaimValue, canonical
    value_digest       TEXT    NOT NULL DEFAULT '',
    accept_signature   BLOB    NOT NULL DEFAULT x'',
    config_generation  INTEGER NOT NULL,             -- config the last write was made under
    updated_at         TEXT    NOT NULL,             -- wall clock, display only
    PRIMARY KEY (target_kind, target_name, owner_epoch, attempt)
);

-- NODE-LOCAL. Identity of this voter's claim state (§3.11).
CREATE TABLE IF NOT EXISTS local_voter_incarnation (
    id          INTEGER PRIMARY KEY CHECK (id = 1),
    incarnation TEXT NOT NULL,   -- random, minted when this table is first created
    created_at  TEXT NOT NULL
);
```

Incarnation-scoped keys live in `local_incarnation_claims` (schema v63), which
has the same columns with `incarnation` in the primary key; legacy keys stay in
`local_recovery_claims` (§10 item 37).

This is schema v59 (v56 is the credentials split, v57 is `host_membership`,
colonelpanik/litevirt#267, and v58 is `cluster_policies`,
colonelpanik/litevirt#265), with the `createTableUnits` markers. The accept is
stored as JSON in `accept_json`, which carries the signature, rather than in a
bare `accept_signature` column.

### 3.7 What a voter persists, and when

A voter must never reply `promised` or `accepted` unless the state that reply
depends on would survive a crash at that instant. A voter that promises, loses
the promise in a crash, and then promises a lower ballot breaks the
intersection argument in §3.13.

- **Write before reply, commit before write.** The reply is built only after the
  transaction's `COMMIT` returns.
- **fsync.** `sqliteDSN` (`internal/corrosion/client.go`) opens `state.db` with
  `journal_mode(wal)` and does not set `synchronous`, so it gets SQLite's
  compiled default. With `synchronous=FULL`, a WAL commit is fsynced before
  `COMMIT` returns. The design does not rely on the compiled default of
  `modernc.org/sqlite`: `sqliteDSN` sets `_pragma=synchronous(full)`, which is a
  no-op where the default is already FULL (it is, on a WAL database under
  modernc today), and `VoterConfigReadiness` reads `PRAGMA synchronous`. Below
  2 the node does not advertise `voter_config_v1` (§5.1), and `Prepare` /
  `Accept` return `FailedPrecondition`.
- **Not through `mutation_log`.** The write must not be relayed. Today
  `local_term_bindings` avoids relaying by doing its `INSERT` inside the
  *guard* of `ExecuteBatchGuarded`, where statements are not logged. The claim
  handler needs a plain local transaction with nothing to relay:
  `Client.ExecuteLocal(ctx, func(*corrosion.LocalTx) error)`, which runs under
  the same client mutex and writes nothing to `mutation_log`. `LocalTx.Exec`
  refuses any statement whose target is not a registered node-local claim
  table, at runtime, and `stmtshapecheck` refuses the same statically at every
  call site (`scripts/ci/stmtshapecheck/localwrites.go`). That keeps "local" a
  property the tooling checks, not a convention.

### 3.8 Why local and not replicated

The grant table lives on each voter and is never replicated. That choice is the
design. It is not an optimization.

1. **A grant is a statement about what this voter promised.** Paxos safety
   comes from each acceptor's own promise. A replicated table would let any
   cluster member write a grant on a voter's behalf. That is the
   `local_term_bindings` lesson from v55: evidence that a peer can author is a
   lever, not evidence.
2. **LWW would coin-flip two grants.** Two promises for one key would merge by
   `updated_at`, and the loser would silently disappear. A voter's promise
   history must be monotone, and LWW is not.
3. **Anti-entropy would repair it.** A voter that was correctly behind would be
   brought up to date with someone else's promise, and a voter that was
   correctly ahead could be regressed.
4. **Durability is per voter anyway.** What makes a certificate safe is that a
   majority *each* durably accepted. Replicating the row would add traffic and
   no safety.

Coordinators and operators see the state through `GetRecoveryClaim`. They never
read a replica of it.

### 3.9 The certificate

A voter signs each accept with its existing cluster identity (`pkiDir/host.key`,
CN = host name, signed by the cluster CA). This is the bootstrap that audit
signing already uses (`internal/corrosion/audit_sign.go`, `LoadAuditKeyring`),
with its own domain separator:

```
accept payload = "litevirt-recovery-accept-v1"            (a legacy key)
              or "litevirt-recovery-accept-v2" || incarnation  (§10 item 37)
              || canonical(key) || config_generation || canonical(ballot)
              || value_digest || voter || voter_incarnation
ClaimAccept    = { voter, voter_incarnation, config_generation, ballot, value_digest,
                   cert_pem, signature }
certificate    = { key, config_generation, ballot, value_digest, source_host,
                   accepts: [ClaimAccept...] }
```

The domain string is chosen so that no TLS handshake and no audit row ever signs
the same bytes. `cert_pem` rides with each accept, so the destination can verify
without an extra RPC.

**Carriage.**

- Column `runtime_action_proofs.claim_certificate TEXT NOT NULL DEFAULT ''` (schema v60),
  appended last for the digest reason v53 and v54 give. It is written in the
  same batch as the proof. That covers the reschedule path, which never uses an
  RPC.
- Field `RuntimeActionProof.claim_certificate` (the JSON certificate, a string) for the
  carried paths: promote and container relocation.
- The certificate is *evidence*, not a binding field. It is not added to
  `ProofBindingEqual`. `WriteActionProofValidated` accepts a row that gains a
  certificate, or whose certificate is replaced by one for the same
  `value_digest` at a later generation (the re-certification §4.6 requires). It
  refuses one whose certificate names a different `value_digest` from the
  proof's own.

A new replicated column changes `insertProofSQL`'s statement shape. An older
peer has no ledger entry for that shape, and an unregistered shape
back-pressures its whole stream. That is why `recovery_claim_v1` is
`ReplicationGated` (§5.1).

### 3.10 Verification at the destination

Verification is `corrosion.VerifyClaimCertificate(ctx, c, verifier, proof)` and
runs at every executor trust boundary:

- `startPendingVM` (`internal/health/reconciler.go`), after the existing
  exact-match and owner-epoch checks and **before** `ClaimActionProofFenced`.
- `claimCarriedProof` (`internal/grpcapi/action_proof.go`), after
  `WriteActionProofValidated` and the owner-epoch check, and before the claim.

The check, in order. Any failure refuses with the reason
`health.ReasonClaimUnproven` (`"recovery_claim_unproven"`) and leaves the row
pending, the same way every other gate refusal does:

1. The certificate is present and parses.
2. `cert.key` equals `(proof.TargetKind, proof.TargetName, proof.OwnerEpoch, attempt)`,
   and, when the key names an incarnation, the destination's own live row for
   the target is that incarnation (§10 item 37),
   and `proof.OwnerEpoch` equals the destination's fresh row epoch. The second
   half is the check `startPendingVM` already makes.
3. `cert.value_digest == digest(proof binding fields, cert.source_host)`. The
   certificate authorizes this exact proof, destination and coordinator, and
   nothing else.
4. `cert.config_generation` is a config the destination has adopted (§4), and is
   not at or below a generation that a forced generation replaced (§4.6). Those
   generations certify nothing any more. A value carried across a forced
   reconfiguration executes only on its re-certification at the forced
   generation. The accepts come from **distinct** members of that generation,
   number at least `len(members)/2 + 1`, all carry `cert.ballot` and
   `cert.value_digest`, and each `voter_incarnation` matches that member's
   entry.
5. For each accept: `cert_pem` chains to the cluster CA, its CN equals `voter`,
   it is not listed in `cluster_crl`, and `signature` verifies over the accept
   payload.

Signatures, not a live read, are what make this safe. A certificate in a
replicated row can be written by any peer. Without signatures, a forged row
could name any voters. With them, a forger would need a majority of voters'
private keys.

The destination does **not** re-query voters. Checking offline keeps execution
independent of voter reachability, beyond the `ExecutionGate` quorum it already
requires.

### 3.11 Voter incarnation: a voter that lost its state must not vote

The one crash Paxos cannot survive is an acceptor that comes back with *empty*
state under its old identity. In litevirt that happens in ordinary ways: a
re-imaged host, a restored or reseeded `state.db`, the lab's WAL-quarantine
rollback.

`local_voter_incarnation.incarnation` is minted when the table is first created.
It is stored in `state.db` itself, so it disappears in exactly the cases where
the claim state disappears. Each voter-config member entry (§4.1) records the
incarnation it was admitted with. A voter whose local incarnation does not match
its member entry **abstains**: it refuses `Prepare` and `Accept`. It keeps
answering `GetRecoveryClaim` so the mismatch is visible. The operator heals it
with `lv cluster voter rm` then `lv cluster voter add`, which is two
config changes. A voter that lost its state costs availability, never safety.

### 3.12 Epoch and attempt progression

- **Normal case.** `(vm, e, 0)` decides destination D. D's `CompleteVMStartProof`
  advances `vm_owner_epoch` to `e+1` in the same mutation that clears the
  pending marker (this is what happens today). The next failure of that VM is
  decided at `(vm, e+1, 0)`.
- **A lagging coordinator.** A coordinator whose replica still shows epoch `e`
  after D has completed will run phase 1 on `(vm, e, 0)`. It learns the decided
  value and re-materializes the same proof. D's `ClaimActionProofFenced`
  returns `ErrProofSpent`. No second owner appears, because the stale replica
  cannot reach a new decision for an epoch that already has one.
- **Decided but refused.** Promote falls back to reschedule on *any* error today
  (`recoverWorkloads`). Under claims, a decided promote holds the key, so the
  fallback reschedule needs a new attempt. `attempt + 1` is allowed only with
  **supersede evidence**: a signed *abandonment* by the attempt-`n`
  destination. That destination records the proof ID in a node-local
  `local_abandoned_proofs(proof_id PRIMARY KEY, reason, abandoned_at)`,
  commits, and returns a signature over
  `"litevirt-recovery-abandon-v1" || proof_id || key`. From then on it refuses
  that proof forever, and the abandonment is checked in the same transaction as
  any later claim. Voters verify the abandonment before promising at
  `attempt + 1`. A destination abandons only a proof it has not executed. The
  promote handler returns an abandonment on every error path taken before
  `StartDomain`, and none after.
- **Decided, destination dead before it acted.** No abandonment can be obtained,
  so the workload stays pending on D. This is deliberately a liveness cost: D
  might come back and execute its valid certificate. A health
  condition `ha.claim.stranded` names each such workload, its destination and
  the command below.
- **Decided, destination dead for good.** The second kind of supersede
  evidence is the destination's permanent removal: D is **fenced proof-grade**
  (an IPMI power-off or `lv host fence-confirm` in `fencing_log`), **not a
  member** (no live `hosts` row), and **revoked** (its certificate serial is in
  `cluster_crl`). Each voter checks all three in its own replica before
  promising at `attempt + 1`, and refuses retryably while any is missing, so
  replica lag here delays and never admits. The revocation is what closes the
  hazard: a revoked D can no longer authenticate to any peer, so a D that
  reboots from a stale replica cannot rejoin, and cannot pass the
  `ExecutionGate` quorum a destination needs before it executes (§3.14). What
  is left is the exposure every removed host already carries (§6).
  One operator command produces the evidence, `lv host rm --dead <host>`:
  1. It refuses unless the host is fenced proof-grade, and prints the fence
     command if it is not.
  2. If the host is a member of the adopted voter config, it removes it first
     through the `voter rm` claim, with seal and transfer (§4.3, §4.4). If no
     majority of the current generation is reachable, it stops and names
     `lv cluster voter force-reconfigure` (§4.6).
  3. It removes the host as `lv host rm` does, including the CRL publication
     that command already performs. Workloads still recorded on the host do not
     need `--force`: they are the stranded ones, and their rows stay in place
     for the supersede.
  4. It prints how many stranded recoveries will now retry at `attempt + 1`,
     and names each one.

  `--dry-run` runs every check and prints the same plan and count without
  changing anything. There is no `lv cluster claim abandon`: an operator never
  asserts a decision away, only removes the host the decision named.

### 3.13 Coordinator algorithm, and the order with fencing

`c.claimRecovery` (§10 gives its landed signature)
in `internal/failover`. It is called at each place a coordinator mints an
ownership-transfer proof. Three are in `coordinator.go`: the reschedule branch
of `recoverWorkloads`, `startRelocation` and `imageRecreateOrSkip`. The fourth
is the promote proof minted inside `Server.AutoPromoteReplica`
(`internal/grpcapi/promote.go`). The coordinator claims before calling
`Promoter.AutoPromoteReplica` and passes the certificate in, which widens that
interface by one argument.

1. Fence as today. The claim is made after `holdLease` re-confirms following the
   fence, and before any proof is written.
2. Build the proposal from the placement result. `proposal.ID = randid.New()` is
   drawn once per call.
3. Phase 1 to every member of the adopted config, in parallel, including self.
   The deadline is `min(claimTimeout, leaseLeft - leaseFenceMargin)`, with
   `claimTimeout` a constant of 5 s.
4. With a majority of promises: if a majority report the *same* accepted
   ballot and value, that value is already certified, so fetch the stored
   accepts with `GetRecoveryClaim` and go to step 5. Otherwise adopt the
   accepted value with the highest ballot, if any, and otherwise the proposal.
   Phase 2 to every member. `claimTimeout` leaves room for one
   `claimProbeTimeout` inside phase 2 (§3.5.1).
5. With a majority of signed accepts: build the certificate and write the proof
   with it. If the value is *someone else's*, write that proof, which is
   idempotent by ID. Its destination is theirs, not ours.
6. Without a majority, stop and let the next tick retry. Do **not** fall back to
   an unclaimed proof. If the refusals are ballot refusals, record
   `phase=claim, result=lost` or `no_majority`, and the next tick uses a higher
   round or learns the winner. If they are owner-probe refusals, record
   `recovery_claim_owner_reachable` with every refusing voter and
   what it reached, and retry at the same round: nothing is contending, the
   source is up.

The loser writes nothing: no proof, no pending row, no `fenceRelocated` claim.
That differs from today, where `WriteVMRescheduleProof` points the VM at the
loser's destination in the loser's own replica. That write is exactly what the
harness's losing executor acts on.

### 3.14 Interaction with existing mechanisms

- **Action proofs.** They are unchanged, and a certificate adds to them. Single
  use (`claimProofSQL`) still stops one proof being executed twice. The
  certificate stops two proofs being authorized for one generation.
- **`owner_epoch`.** It is the claim key's epoch, and it stays the executor's
  ABA check. The certificate uses the epoch and does not replace it.
- **Lease and lease terms.** The lease becomes a liveness aid. It keeps usually
  one proposer active, and the lease term seeds the ballot round. Stamping and
  judging lease terms (`leaseStamp`, `judgeProofLeaseTerm`, `local_term_bindings`)
  is unchanged. It still limits a stale leader's reach on paths claims do not
  cover (LB apply, owner assert).
- **`DecisionGate` / `ExecutionGate`.** Unchanged. A coordinator that fails the
  gate never proposes. A destination that fails the gate does not execute, even
  with a certificate.
- **`shared_storage_fence_v1`.** Unchanged and orthogonal. The value's
  `fence_epoch` carries the proof-grade fence, and the executor re-verifies it
  as it does today.
- **Two coordinators both fencing.** Allowed (see non-goals). `fencing_log`
  records both fences.

### 3.15 Failure cases

| Case | What happens | Why it is safe |
|---|---|---|
| Coordinator crashes before any Accept | Promises remain. The next proposer's higher ballot supersedes them. | Nothing was accepted, so nothing can have been chosen. |
| Coordinator crashes after some Accepts, before a certificate | The next proposer's phase 1 sees the accepted value if a majority promised and one of them accepted. It must adopt that value. | Standard Paxos: a value that *might* have been chosen is re-proposed. The value holds the full proof, so re-materializing it yields the same ID. |
| Coordinator crashes after the certificate, before writing the proof | The next proposer learns the value and writes the proof itself. | Same proof ID, same destination. |
| Voter crashes, keeps its disk | It restarts with its promises intact (§3.7). | Durability before reply. |
| Voter crashes, loses its disk | Its incarnation changes, and it abstains until re-added (§3.11). | It cannot promise against a promise it forgot. |
| Duplicated or reordered message | Idempotent, or refused by the `promised` check (§3.5). | Acceptor state is monotone in ballot. |
| Message lost | The proposer times out or collects a majority from the rest. | Liveness only. |
| Minority partition | The coordinator cannot reach a majority of promises. | A minority cannot produce a certificate. |
| Majority partition with two coordinators inside it | Ballots order them. At most one value is chosen. | §3.16. |
| Forged certificate in a replicated row | The destination's signature check fails. | §3.10 step 5. |
| Revoked voter key | Its accepts stop verifying, and a certificate relying on them is refused. The next proposer re-collects fresh signed accepts for the same value. | Liveness cost only. The decided value does not change. |
| Old owner reachable from a majority of voters | They refuse with `recovery_claim_owner_reachable`, naming what they reached. No certificate forms. | The owner is up for most of the cluster (§3.5.1). |
| Old owner reachable from a minority of voters | The others accept, and recovery proceeds after the fence, as today. | The certificate records that a majority could not reach it. Fencing is what stops the owner writing. |
| Coordinator proposes recovery of a live host (wrong failure detector, forged `host_health`) | Voters reach the host and refuse. | A forged row cannot make a majority fail to reach a live host. |
| Coordinator names the wrong source for a settled workload | Voters whose row names another owner refuse with `recovery_claim_source_mismatch`. | §3.5.1, the source cross-check. |
| Old owner returns after a value was chosen, before its certificate was written | The voters that accepted the value re-accept it without probing, or their stored accepts are fetched (§3.13 step 4). The certificate completes. | The value was chosen while a majority could not reach the owner. The returning owner's workloads are held by the fence and `owner_epoch`, as today. |

### 3.16 The harness scenario, walked through

The config is `{a, b, victim}`, so a majority is 2. The victim is dead: its
claim RPCs fail, and every voter's owner probe of it fails, so the probe never
refuses below. Replication `a↔b` is blocked. Claim RPCs are ordinary gRPC and,
in this scenario, reach their peer. The worst ordering:

1. `a` prepares `(1, a)` on itself: promised. `b` prepares `(1, b)` on itself:
   promised.
2. `a`'s `Prepare(1, a)` reaches `b`. `b` has promised `(1, b)`. At equal round
   the lower name ranks higher, so `(1, a) > (1, b)`, and `b` promises `(1, a)`.
   `b`'s `Prepare(1, b)` reaches `a`, which has promised `(1, a) > (1, b)`, and
   `a` refuses.
3. `a` holds promises from `{a, b}`, which is a majority, and none reports an
   accepted value. It proposes `v_a` (destination `a`, proof `P_a`) and sends
   `Accept((1, a), v_a)` to `a` and `b`. Both accept. That is certificate `C_a`.
4. `b` retries at round 2 with `Prepare(2, b)`. `a` and `b` both promise and
   both report `accepted ((1, a), v_a)`. `b` **must** propose `v_a`. The best it
   can produce is a certificate for `P_a`, destination `a`.
5. The executors. `a`'s replica holds `P_a` + `C_a`. `a` verifies and starts. If
   `b` wrote anything, it wrote `P_a`, whose destination is `a`, and `b`'s
   reconciler refuses it on `pr.DestHost != r.hostName`, as it already does
   today. `b` holds no `P_b` with a valid certificate, because none exists.

Result: one writable owner. The same ordering with names swapped, or with `b`
winning step 2, gives the mirror image. There is never a second owner.

**Safety argument.** Suppose certificates exist for `(ballot₁, v₁)` and
`(ballot₂, v₂)` at one key, with `ballot₁ < ballot₂`. Both are majorities of the
same config generation (§3.10 step 4). By §4.4, for keys spanning a config
change, the config state is carried forward. (A forced reconfiguration, §4.6,
is the one exception, and says what it gives up.) Owner-probe refusals do not
enter the argument: they change no state. So the promise majority behind
`ballot₂` shares at least one voter with the accept majority behind `ballot₁`.
That voter accepted `ballot₁` before promising `ballot₂`, because once it has
promised `ballot₂` it refuses any accept at `ballot₁ < ballot₂`. So its promise
reply reported an accepted ballot `≥ ballot₁`. By induction over ballots in
`[ballot₁, ballot₂)`, the highest accepted value reported is `v₁`. The proposer
of `ballot₂` therefore proposed `v₁`, so `v₂ = v₁`. Because the value holds
`dest_host` and the proof ID, at most one destination and one proof can ever
carry a valid certificate for a key. G2 makes the destination check it. That
gives G1.

---

## 4. Voter set (colonelpanik/litevirt#251 step 2)

### 4.1 Tables

Replicated:

```sql
-- Immutable once written, like leader_lease_terms. One row per generation.
CREATE TABLE IF NOT EXISTS voter_configs (
    generation    INTEGER PRIMARY KEY,
    members_json  TEXT NOT NULL,   -- sorted [{name, incarnation}]
    members_hash  TEXT NOT NULL,
    change        TEXT NOT NULL,   -- genesis | add:<name> | rm:<name> | force:<name,...> | reset
    certificate   TEXT NOT NULL,   -- claim certificate deciding this generation (§4.3),
                                   -- or the forced-generation evidence (§4.6)
    created_by    TEXT NOT NULL,   -- principal, for audit
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
```

The merge rule is keep-local, as for `leader_lease_terms`, in its own
`voterConfigMergeKeepLocalRow`: the certificate is evidence rather than a fact
of the row, since two proposers that completed one decision hold different,
equally valid certificates for it, so those converge on the greater encoding;
any other difference is flagged and never taken. A receiver adopts a generation only if its certificate verifies against
the generation before it (§3.10 steps 4–5, with key
`("voter_config", "", generation-1, 0)`). Two different rows for one generation
cannot both carry valid certificates (§3.16). A row that fails to verify is
evidence, and it is reported on the `ha.lww.unresolved` path rather than
adopted. A `force:` row is verified by the rule in §4.6 instead, and it is the
one exception to keep-local: a verified forced row replaces an ordinary row for
the same generation.

Node-local: `local_voter_adoption(generation PRIMARY KEY,
imported_from TEXT, adopted_at TEXT)`. It records which generation this node has
adopted and from which sealed majority it imported claim state (§4.4).

### 4.2 Bootstrap

A cluster with no `voter_configs` rows uses today's derived `corrosion.VoterSet`
until genesis. Genesis is automatic, so every cluster reaches the explicit voter
set without an operator remembering a step. A cluster that never ran a manual
step would otherwise keep colonelpanik/litevirt#251's bug for good.

- **Automatic genesis.** Once `voter_config_v1` is durably latched (§5.1), the
  leader-lease holder proposes generation 1 on each reconcile tick, with its
  derived `VoterSet` as the members. It proposes only on a **clean** cluster:
  every non-deleted host is voting-eligible and reachable. None is in
  `maintenance`, `offline` or fenced. Genesis therefore never freezes a host out
  of the voter set because it happened to be away when the token latched. It
  writes generation 1 only if **every** proposed member returns a signed
  accept. Genesis is unanimous because no earlier config exists whose majority
  could decide it. Genesis is itself a claim, with key `("voter_config", "", 0, 0)`,
  so two proposers racing across a lease hand-off decide one value.
- **While genesis is blocked**, the health condition
  `ha.voter.genesis_pending` (evaluator `voter_config`) names each host holding
  it back, its state, and what clears it: finish the maintenance, bring the
  host back, or leave it out with `lv cluster voter init --members`.
  `lv host rm --dead` (§3.12) is the other way out for a dead host.
- **Manual genesis.** `lv cluster voter init [--members a,b,c]` is
  the fallback for a cluster that cannot become clean, for example one with a
  permanently dead host the operator has not removed yet. It prints the
  proposed members, defaulting to the derived `VoterSet`, and asks for
  confirmation. The same unanimity applies. It is refused while automatic
  genesis could still succeed without it, which keeps one path for the common
  case.
- Both are refused until `voter_config_v1` is durably latched, so neither can
  write a new replicated shape before every peer can decode it. Neither needs
  `recovery_claim_v1` or `enforcement.recovery_claim`: the voter set is useful,
  and permanent, on its own (§4.5).

**Reset.** `lv cluster voter reset` returns the cluster to the
derived set. It is a config change like §4.3: change kind `reset`, empty
members, decided by a majority of the current generation. So every node leaves
the explicit set at the same generation, which is what a per-node flag cannot
do (§5.1).

- On adopting a `reset` generation, each node's `VoterSet` is derived again.
  Claim enforcement stops, because its predicate needs an adopted member config
  (§5.1), and recovery is authorized as today. The claim tables are kept.
- A reset is sticky. Automatic genesis runs only while `voter_configs` is
  empty, so after a reset only `lv cluster voter init` starts a new member
  generation, unanimously, as genesis is.
- If the majority needed to decide the reset is lost, `force-reconfigure`
  (§4.6) comes first.
- Reset is the exit from explicit voting when the voter config itself is
  suspect. It is **not** a rollback tool. A binary rolled back below
  `voter_config_v1` enters WAL quarantine whether or not a config exists, as it
  does below every latched token (§5.1).

### 4.3 Add and remove

- `lv cluster voter add <host>` and `lv cluster voter rm <host>`
  change **exactly one** member per generation.
- The change from generation `g` to `g+1` is itself a claim, with key
  `("voter_config", "", g, 0)` and the new member list as its value. It is
  decided by a majority of generation `g`, so two operators running concurrent
  changes cannot both succeed.
- `add` requires the new member to be reachable. It supplies its incarnation and
  imports claim state (§4.4) before it counts toward any majority.
- `rm` of an unreachable member is allowed. That is the post-fence case, and a
  majority of `g` is enough.
- `lv host rm <host>` of a current voter is refused, by the CLI before it
  revokes the certificate and by `RemoveHost` itself, and names
  `lv cluster voter rm` first. `lv host rm --dead <host>` (§3.12), for
  a host that is fenced and gone for good, will make the voter change itself. Deleting a `hosts` row
  must no longer change the voting population implicitly.
- **No automatic shrink.** After a fence, the fenced host stays a member and
  counts in the denominator until the operator runs `lv cluster voter rm` or
  `lv host rm --dead`.
  Operational state (`offline`, `maintenance`, `fenced`) no longer changes
  voting, which is the point of colonelpanik/litevirt#251. A health
  condition `ha.voter.unavailable` names every member that is fenced, offline or
  abstaining, with the command that removes it.

### 4.4 Claims across a config change: seal and transfer

**The hazard.** A value chosen in generation `g` by majority `M_g` must stay
visible to any later proposer. Changing one member at a time keeps adjacent
generations' majorities intersecting (`|M_g| + |M_{g+1}| > |g ∪ g+1|`), but two
successive removals do not. For example, with `{a,b,c,d,e}` and `v` chosen by
`{a,b,c}`: remove `a`, then remove `b`, and `{d,e}` is a majority of `{c,d,e}`
that never saw `v`.

**The rule.** A generation carries claim state forward explicitly:

1. Deciding `g+1` also **seals** `g`. A voter that accepts the config change
   stops answering `Prepare` / `Accept` for workload keys under `g`.
2. Before a member of `g+1` votes under `g+1`, it **imports**. It calls
   `GetRecoveryClaim` in bulk (`ListRecoveryClaims`, streaming) on a majority of
   sealed `g` members. For every key, it records the highest-ballot accepted
   value it sees as its own accepted value, with `config_generation = g+1`.
   Because the sealed majority intersects every `g` majority, it sees any value
   chosen in `g`. After import, every `g+1` voter holds every value chosen so
   far, so any `g+1` majority reports it.
3. Only after that does it record `local_voter_adoption(g+1)` and vote.

**Why not joint consensus.** Joint consensus (both majorities for every
decision during the transition) adds a second quorum rule to every message and
leaves a transitional state that has to be ended by yet another decision. Seal
and transfer keeps every decision on exactly one generation and one majority.
It is also cheaper in the case colonelpanik/litevirt#251 is about: removing one
dead voter. The cost is that recovery claims pause for one generation hand-off,
which is seconds on a healthy majority, and a member added later has to import
before it votes.

### 4.5 What reads the voter set

With a voter config adopted, `corrosion.VoterSet` returns the adopted
generation's members. It no longer filters on `hosts.state`. So it feeds the
same set to its three consumers today (the fence quorum, the recovery quorum in
`recoverHosts`, and `health.QuorumProof`) and to claims.

This holds whatever `enforcement.recovery_claim` says. The voter set is a fact
the cluster agreed on, not a policy, so no flag makes `VoterSet` ignore
`voter_configs`, and colonelpanik/litevirt#251 step 2 ships and stands on its
own (§9, Q4). The only ways to change it are §4.2 (reset), §4.3 and §4.6.

The capability-latch sweep (`activationTargets`) keeps its current derived
`VotingEligible` population, so a fenced voter that is still a member cannot
hold every future latch off (§9, Q5).

### 4.6 Losing a majority of voters for good: forced reconfiguration

`lv cluster voter rm` is a claim decided by a majority of generation
`g`. Once a majority of `g` is permanently gone, it can never succeed, and
neither can any recovery claim. The break-glass is
`lv cluster voter force-reconfigure --lost <host>[,<host>...]`, in
the style of etcd's `--force-new-cluster` and Consul's `peers.json` recovery.
It runs against one survivor, which drives the rest.

**It refuses**, naming what failed, unless all of these hold:

1. Every named lost host is a member of `g` and is fenced proof-grade: an IPMI
   power-off or `lv host fence-confirm` recorded in `fencing_log`.
2. The members of `g` not named lost, the survivors, are fewer than a
   majority of `g`. If they are a majority, `voter rm` can succeed, and the
   command names it instead. (With four voters and two lost, neither half is a
   majority, so this is the break-glass case.)
3. The survivor probes every member of `g` as §3.5.1 does. It refuses if it
   reaches a majority of `g`, or any named lost host. A majority that is
   actually reachable means this is not the break-glass case.
4. Every member of `g` not named lost is reachable, and signs the new
   generation. The survivors are unanimous, as genesis is (§4.2).
5. Every other host in `hosts` is either reachable from the survivor or fenced
   proof-grade. A live host the survivors cannot see may hold a certificate
   they cannot see.

**What it does.**

1. **Seal.** Every survivor stops answering `Prepare` / `Accept` under `g`.
2. **Converge.** It runs one full anti-entropy pull from every reachable host,
   so each survivor's replica holds every proof, certificate and ownership row
   any reachable host holds. If that pull delivers a verified ordinary `g+1`
   row the survivors never saw, it stops: the survivors adopt that generation,
   and the operator re-runs the command against it if it is still needed.
3. **Import.** For every key, each survivor records as accepted at `g+1` the
   highest-ballot accepted value held by *any* survivor, and the value of every
   certificate at a generation up to `g` found in `runtime_action_proofs`.
4. **Write** generation `g+1`: members are the survivors, `change` is
   `force:<lost,...>`, and `certificate` holds the survivors' unanimous
   signatures over `"litevirt-voter-force-v1" || g || members || lost`, the
   fence evidence for each lost host, and `created_by`.
5. **Announce.** It writes a signed audit event `voter.force_reconfigured`
   and raises `ha.voter.forced`, naming the lost hosts
   and the new generation. The condition stays until every lost host has been
   removed and revoked with `lv host rm --dead`, and the command
   prints that line for each one.

Before running, it prints the plan: survivors, lost hosts, their fence evidence,
and the number of keys it will import. The operator confirms it.

**Recovering the lost hosts' workloads.** Precondition 1 can usually be met
only by `lv host fence-confirm`, run before anything has fenced the lost hosts
for this outage: no fence quorum can form while a majority of `g` is gone.
That confirmation records each host `fenced`, and a host recorded terminal is
never a fence candidate. Once `g+1` is adopted, the survivors' coordinator
therefore fences each lost host afresh, on the strength of a confirmation made
during the outage it is still in, and recovers from that fence under every gate
an ordinary fence applies (docs/migration-failover.md, "A confirmation before
any fence of this outage fences the host afresh"). The confirmation authorises
the fence, not the recovery. Before this, nothing fenced them, and the recovery
waited for `lv host undrain` and a fresh fence five minutes later (drill 6 on
main-8d1e56dc).

**Adopting a forced row.** A receiver adopts a `force:` row only if the
survivors' signatures are unanimous over its members, members plus lost hosts
equal `g`, the members are fewer than a majority of `g`, and the receiver itself
probes each lost host and reaches none. A receiver that reaches a named lost
host refuses the row and raises `ha.voter.forced` with the conflict: valid
signatures do not make a false claim of loss true, so a single compromised
survivor key cannot seize the voter set by naming live voters as lost. A named
lost host that receives the row adopts it without probing. Adopting only removes
its own vote.

**What safety is given up.** An ordinary change keeps every `g+1` majority
intersecting the sealed `g` majority it imported from (§4.4). A forced change
cannot: the survivors are fewer than a majority of `g`. What they import is
every value at least one survivor accepted, and every certificate that reached
the replica of any reachable host. What stays invisible is a value accepted
*only* by lost voters whose certificate reached no reachable host. The survivors
may decide a different value for that key, and G1 would then rest on the
invisible value never executing. Three things make it so, and the first is why
the lost hosts must be fenced before recovery resumes:

- **The lost voters are off.** A lost majority that is merely partitioned is
  still a working majority of `g`. It could go on certifying under `g`, and
  destinations on its side, which never adopt `g+1`, would execute those
  certificates while the survivors recover the same workloads. That is a split
  brain. A proof-grade fence is what makes "lost" true, so this command trusts
  the fence evidence in a way G1 otherwise never needs to. A false
  `lv host fence-confirm` here can produce two owners.
- **No live host is out of sight.** Precondition 5 means every host that could
  hold an invisible certificate is either fenced or was pulled in step 2, and a
  pulled certificate is imported.
- **Replaced generations certify nothing.** Once `g+1` is adopted, a
  destination refuses any certificate at `g` or below (§3.10 step 4). A value
  imported in step 3 executes only after the survivors re-certify it at `g+1`,
  which the next coordinator tick does as a lagging coordinator would
  (§3.12). The proof keeps its ID and gains the new certificate.

A lost host must not come back as it left: it may hold an ordinary `g+1` its
majority decided and nobody saw. `lv host rm --dead` revokes it, so a returning
lost host cannot authenticate to any peer, and the forced row replaces any
ordinary row for its generation (§4.1).

---

## 5. Rollout

### 5.1 The capability tokens

There were two tokens at first; `claim_incarnation_v1`, the third, changes how
a workload claim is keyed and is described in §10 item 37. The two are split
so that the voter set (colonelpanik/litevirt#251 step 2)
ships and stays in force independently of whether claims are enforced (§4.5,
§9, Q4).

**`voter_config_v1`** (`capabilities.VoterConfigV1`) covers the voter
set and the voter side of the protocol: `voter_configs`, the claim RPCs, the
node-local grant tables and the voter incarnation.

- **Mandatory: yes.** It states a fact about the binary: this build can decode
  `voter_configs` and can answer `Prepare` / `Accept` / `GetRecoveryClaim`
  durably. Latching it starts automatic genesis (§4.2). Until genesis
  completes, `VoterSet` is derived exactly as today.
- **Advertised when ready:** `PRAGMA synchronous` ≥ FULL (§3.7), the host
  signing key loads, and the voter incarnation is readable; the claim RPCs are
  compiled in. `grpcapi.VoterConfigReadiness` is the local-only probe, in the
  pattern of `LeaseTermReadiness`.
- **`ReplicationGated`: yes.** Latching it allows the new replicated shape
  `voter_configs`. That is a claim about what every host still *receiving*
  replication can decode, which is the `lease_term_ledger_v1` argument.
- **Stand-down: no flag, by design.** A flag would be worse than none. A node
  with it off would count a different majority from its peers, which is the
  split-brain the voter set exists to prevent. The incident tools are
  `lv cluster voter rm` / `add` and `lv cluster voter reset` (§4.2, §4.3), and,
  with the follow-up, `lv host rm --dead` and
  `lv cluster voter force-reconfigure` (§3.12, §4.6). Each is a decided change, so every node
  moves at the same generation. `reset` is the full exit back to the derived
  set. A host rolled back below this build after the token has latched enters
  WAL quarantine, as for every latched token, whether or not a config exists.
  That note is beside the declaration, above `capabilities.supported`.

**`recovery_claim_v1`** (`capabilities.RecoveryClaimV1`) covers
enforcement: coordinators claiming before they mint, and destinations
verifying before they execute.

- **Flag:** `enforcement.recovery_claim`, default **false**.
- **Advertised conditionally** in `Server.advertisedCapabilities` when the flag
  is on **and** this node is ready: `split_brain_gate_v1` is latched (the
  certificate rides on proofs) and `voter_config_v1` is ready on this node. A
  `grpcapi.RecoveryClaimReadiness` is the local-only probe.
- **`ReplicationGated`: yes.** Latching it allows the new replicated statement
  shape of `runtime_action_proofs.claim_certificate`, by the same argument.
- **Mandatory: no.** It states a policy, not a fact about the binary. It needs a
  flag to turn off in an incident.
- **Enforcement predicate:** flag **and** `Enforced(recovery_claim_v1)` **and**
  an adopted voter config. Coordinators then require a certificate before
  minting any reschedule, promote or relocate proof. Destinations require one
  before claiming any such proof.
- **Voters answer regardless of the flag** once a voter config is adopted:
  answering is `voter_config_v1`'s job, not this token's. Answering changes
  nothing unless someone relies on the answer. It also keeps promise history
  unbroken while flags are toggled during a staged rollout or stand-down.

### 5.2 Why `recovery_claim_v1` is withheld while off, and `shared_storage_fence_v1` is not

`CLAUDE.md` asks: *where is the guarantee enforced?* A token must be withheld
while its flag is off when some node **relies on a peer honouring it**, where a
flag-off peer would corrupt rather than merely be permissive.

| | `shared_storage_fence_v1` | `recovery_claim_v1` |
|---|---|---|
| Hazard | A shared-disk VM started while the old owner may still write | Two destinations each starting the same workload |
| Where the guarantee is made | At **creation**: the coordinator refuses to create a shared-disk transfer without a proof-grade fence of the old owner | At **execution**: only a destination can refuse, because a coordinator cannot stop *another* coordinator from creating a transfer |
| What a flag-off peer does | As a destination, starts a transfer that could only exist if the old owner was provably down. Safe. | As a coordinator, mints an uncertified proof. As a destination, starts one. Either way it is the second owner. |
| Does anyone rely on a peer? | No | Yes: every flag-on node relies on every peer verifying certificates and claiming before minting |
| Right advertisement | Unconditional | Withheld while the flag is off (with `operation_protocol_v1`, `isolation_epoch_v1`, `owner_epoch_v1`, …) |

A concrete corruption with a partial rollout. Coordinator X has the flag off and
writes an uncertified proof for destination D'. D' also has the flag off and
starts the VM. Coordinator Y has the flag on and collects a certificate for D.
D starts. That is two owners, and the flag-on nodes did everything right. The
latch is what keeps the cluster from relying on the protocol before every node
has opted in. For this token, a latch therefore has to mean config uniformity,
not just a uniform build.

The costs that make withholding wrong for `shared_storage_fence_v1` do not carry
over:

- **Witnesses.** A witness with the flag off would hold the latch off fleet-wide.
  For the fence token that is a trap, because a witness has no role in fencing.
  Here a witness runs a failover coordinator like every node (§1.1), and a
  flag-off coordinator mints uncertified proofs, so its operator must opt in,
  and holding the latch off until then is correct. Its role as a *voter* needs
  no opt-in: that is `voter_config_v1`, which is mandatory.
- **Nodes mid-rollout stop enforcing.** For this token there is nothing to lose
  before the latch. Enforcement partway through a rollout is unsafe (the example
  above), not just weaker.
- **Latch-drive budget.** A config-on token that cannot latch yet still takes a
  turn in `driveCapabilityActivation`. `activateOneUnlatched` now rotates its
  start point, so this costs one fresh-Ping sweep per rotation during a staged
  rollout and does not starve the tokens after it.

### 5.3 Mixed versions

- **An old binary** advertises neither token, so neither can latch
  (`ReplicationGated` includes hosts in `maintenance`). Every node behaves as
  today.
- **Every host on a new build:** `voter_config_v1` latches by itself, because
  it is mandatory, and automatic genesis follows on the next reconcile tick on
  a clean cluster (§4.2). Until then `VoterSet` is derived, and
  `ha.voter.genesis_pending` names whatever holds genesis back.
- **After genesis:** `VoterSet` counts the explicit set for the fence
  quorum, the recovery quorum and `health.QuorumProof`, and voter changes are
  claims. Recovery itself is authorized as today until claims are enforced.
- **A new binary with `enforcement.recovery_claim` on, before
  `recovery_claim_v1` latches:** it advertises and enforces nothing.
- **After `recovery_claim_v1` latches, with no voter config:** enforcement
  stays off (the predicate needs an adopted config), and `lv doctor` says so.
- **After the latch, with a config:** fully enforced. A node whose flag is later
  turned off stops enforcing locally. It appears in `PingResponse.not_enforcing`,
  and `ha_degraded` is raised, as for `operation_protocol_v1`. Its `VoterSet`
  does not change.

### 5.4 What an operator sees

- **Gate refusals** use the reasons `recovery_claim_unproven`
  (destination), and `recovery_claim_lost` / `recovery_claim_no_majority` /
  `recovery_claim_owner_reachable` / `recovery_claim_source_mismatch`
  (coordinator). An owner-probe refusal's detail names every refusing voter and
  what it reached, for example `node-3 still reaches node-2`. They go through
  the existing `noteGateRefused` observers, so they appear on the current
  gate-refusal metric with no new series.
- **Coordinator metrics** use the existing `mAttempt` triple with a
  `PhaseClaim` and the results `ok`, `lost` (another value was decided),
  `no_majority`, `owner_reachable` and `superseded`.
- **`lv cluster claim <kind>/<name>`** calls `GetRecoveryClaim` on
  every member and prints each voter's promised and accepted ballot, value
  digest, destination, source host, incarnation status, and last refusal with
  its detail. This is the one place a stuck claim can be diagnosed.
- **Health conditions:** `ha.claim.stranded` names each workload
  decided for a destination that is fenced or gone, with the exact
  `lv host rm --dead <host>` command (§3.12). `ha.voter.genesis_pending` names
  each host holding automatic genesis back and what clears it (§4.2).
  `ha.voter.unavailable` names
  voters that are fenced, offline or abstaining (§4.3). `ha.voter.forced` marks
  a forced reconfiguration until its lost hosts are removed (§4.6).
- **`lv cluster voter ls`** shows the adopted generation, its
  members, and per member reachable, fenced or abstaining, with incarnation
  mismatches.

### 5.5 Turning it on

1. Roll every host to a build with the claim protocol. Run `lv doctor fence`
   and confirm the fence posture is what you expect.
2. Wait for `voter_config_v1` to latch and genesis to complete. Neither needs
   config. `lv cluster voter ls` shows generation 1 and its members.
   If `ha.voter.genesis_pending` persists, clear what it names, or run
   `lv cluster voter init --members` for a cluster that cannot
   become clean. This step stands on its own: a cluster can stop here and keep
   an explicit voter set without ever enforcing claims.
3. Set `enforcement.recovery_claim: true` on **every** host, witnesses included,
   and restart them one at a time.
4. Wait for `recovery_claim_v1` to latch. `lv doctor` shows it, and
   `not_enforcing` is empty everywhere. The next failover is claim-gated.
5. Validate with a partition drill before relying on it (§7.3), in the same
   spirit as the operator note in `capabilities.supported`.

### 5.6 Standing down in an incident

The kill switch follows the reversible `configFlag && latch` model described in
`internal/capabilities/capabilities.go`:

- **Full stand-down:** set `enforcement.recovery_claim: false` on **every** node
  and restart. Coordinators mint uncertified proofs and destinations accept
  them. That is exactly today's behaviour, including its documented
  double-owner exposure. Do not delete latch markers (retired practice). Voters
  keep answering and keep their tables, so turning the flag back on resumes
  with history intact.
- **Partial stand-down is the hazard in §5.2.** Nodes with the flag off become
  the uncertified second owner. `not_enforcing` shows them. If recovery is
  stalled on claims, first try the unblocks in §6, which keep the guarantee.
  One workload held by `ha.claim.legacy_held` behind a proof stuck in flight
  on a live destination is released on its own with
  `lv cluster claim-release <kind>/<name>` (§10 item 37), not by a stand-down.
- **The voter config is not part of the stand-down.** It is a fact the cluster
  agreed on, and `VoterSet` reads it whatever the flag says (§4.5, §9, Q4). The
  fence quorum and recovery quorum keep counting the explicit set. A voter set
  that has itself become the problem is repaired with `lv cluster voter rm` /
  `add`, or `lv cluster voter reset`; with the follow-up, `lv host rm --dead`
  and, when a majority is gone for good, `lv cluster voter force-reconfigure`
  (§3.12, §4.6).

### 5.7 Schema summary

- Node-local table (v63, with `claim_incarnation_v1`): `local_incarnation_claims`.
- Node-local tables (v59): `local_recovery_claims`, `local_voter_incarnation`,
  `local_voter_adoption`. `local_abandoned_proofs` (v61) comes with §3.12 and
  `local_voter_seals` (v62) with §4.6.
- Replicated table (v59): `voter_configs`, written only after `voter_config_v1`
  latches.
- Replicated column (v60, with `recovery_claim_v1`):
  `runtime_action_proofs.claim_certificate`, appended last and emitted only
  after `recovery_claim_v1` latches.
- Statement-shape ledger entries for every new replicated shape
  (`stmtshapecheck`).
- `check-schema-bump.sh`, a `CurrentSchemaVersion` bump, and a matching history
  line.

---

## 6. Failure modes and liveness

Claims trade availability for safety in named places. Each one below says what
stalls and how the operator unblocks it without giving up G1.

| Stall | Symptom | Unblock |
|---|---|---|
| **No reachable majority of voters** | `recovery_claim_no_majority`. Workloads stay on the fenced host. | Same as today's no-quorum case: restore connectivity. If some voters are gone for good but a majority of the current generation remains, remove them with `lv host rm --dead` or `lv cluster voter rm`. If a majority is gone for good, fence each lost host proof-grade and run `lv cluster voter force-reconfigure --lost <hosts>` (§4.6). That is audited, raises `ha.voter.forced`, refuses while a majority is actually reachable, and gives up the guarantees §4.6 names. |
| **Dead voter still in the config** | Fault tolerance is one lower than the host count suggests. For example, a 3-voter cluster with one fenced member needs both survivors. | If the host is gone for good: `lv host rm --dead <fenced>`, which removes it from the voter config and then from the cluster (§3.12). If it stays a host but should stop voting: `lv cluster voter rm <host>`. `ha.voter.unavailable` names it. There is no automatic shrink, by decision. |
| **Voter with a changed incarnation** (re-imaged or reseeded) | It abstains, and `lv cluster voter ls` shows the mismatch. | `lv cluster voter rm` then `lv cluster voter add`. |
| **Duelling proposers** | Repeated rejected ballots, and `recovery_claim_lost` alternating between nodes. | Self-heals: the lease-term round seed, the lease-contest rule, and randomized back-off (0–1 poll) on rejection. If it persists, look for a lease that is not converging (`ha.lww.unresolved`). |
| **Stranded on a dead destination** (decided, destination died before starting) | The VM stays `pending` on D. `ha.claim.stranded` names it with the command, and `lv cluster claim` shows a decided value naming D. | D returns and either executes or abandons. If D is gone for good: fence D proof-grade, then `lv host rm --dead D` ( `--dry-run` first shows what it will do). It removes D from the voter config if it is a voter, removes the host, publishes the CRL and prints how many stranded recoveries will retry. Voters then accept the supersede evidence *"destination fenced proof-grade, not a member, and revoked"* for `attempt + 1` (§3.12). The residual risk, a revoked host rebooting from a stale replica, is the same exposure every removed host already carries. |
| **Old owner still reachable** | `recovery_claim_owner_reachable`, naming each refusing voter and what it reached. Workloads stay where they are. | Not a stall to unblock: most of the cluster can reach the owner. Find out why the coordinator judged it failed (failure detector, `host_health`). If the host is up but must not keep its workloads, fence it proof-grade: the probe then fails, and the next tick's claim proceeds. |
| **Destination refuses the certificate** (CA or CRL mismatch, config generation not yet adopted) | `recovery_claim_unproven` on the destination. | Usually replication lag on `voter_configs` or `cluster_crl`, which clears on the next reconcile. If not, compare `lv cluster voter ls` across nodes. |
| **Voter-config hand-off in progress** | Claims pause while `g+1` members import. | Completes when a majority of `g+1` has imported. A member that cannot import is removed like a dead voter. |
| **`synchronous` below FULL** | Neither token is advertised, so neither latches. | Fix the DSN or build. Never force the latch. |

Claims decide ONE new owner; they do not stop the OLD one. A best-effort
fence that cannot reach a partitioned host records `assumed`, and that host
keeps running the copy the claim replaced (lab drill 1, 2026-10-02). The
companion design [partition-pause.md](partition-pause.md) closes that gap in
two layers: a host that cannot see a majority of this voter set pauses its
recoverable workloads, and the majority waits out that pause before it
recovers (`partition_pause_v1`, assurance `self_paused`); a host that comes
back holding a copy a certified claim gave away stops it, on the certificate
and nothing weaker.

---

## 7. Testing plan

Every assertion below is mutation-verified per `CLAUDE.md`: break the property,
see the test go red, restore. Each item names its mutation.

### 7.1 Fleet (`tests/fleet/`)

- **Un-skip `TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner`.**
  The harness gains a way to latch `voter_config_v1`, complete genesis, enable
  `enforcement.recovery_claim` and latch `recovery_claim_v1` on the
  independent-replica fleet.
  - *proof-gated arm*, with claims enforced: assert at most one owner by libvirt
    state, as today. Also assert the loser wrote **no** pending row and no proof
    naming itself. Mutation: skip `VerifyClaimCertificate` in `startPendingVM`,
    and the test must go red.
  - *legacy arm*: it cannot coexist with claims, because readiness requires
    `split_brain_gate_v1` latched. Replace it with an assertion that
    `recovery_claim_v1` is not advertised until `split_brain_gate_v1` has
    latched. Mutation: drop that readiness predicate.
  - *heal*: after `ClearLinkFaults`, both replicas agree on one owner within one
    reconcile interval, and no second domain ever ran. That turns the 40 s split
    in the report into zero.
- **Claim-RPC faults.** Extend the per-link injector (`tests/fleet/replicas.go`,
  `LinkFault`) so it can target the claim RPCs separately from
  `partitionedMethods`, with `Drop`, `Duplicate`, `Reorder` and `Delay`. Run the
  two-coordinator scenario across seeds with each fault. Mutation: make a voter
  accept a ballot lower than its promise.
- **Split vote with a dead voter.** Config `{a, b, victim}`, both coordinators
  self-promise first (§3.16 step 1), and the claim still resolves within N
  polls. Mutation: remove the round bump on rejection. The claim should then
  stall, and the test catches that liveness failure.
- **Coordinator crash mid-collection.** An `OnAccept` hook kills the coordinator
  after one accept. The successor must complete the *same* proof ID. Mutation:
  make the proposer ignore accepted values in promises. Two certificates then
  exist, which must fail.
- **Voter restart and amnesia.** Reopen a voter's DB between phases: the promise
  survives. Recreate the DB: the voter abstains. Mutation: mint the incarnation
  on every start.
- **Promote→reschedule fallback.** A promote refused before `StartDomain`
  returns an abandonment, and the reschedule at `attempt + 1` succeeds.
  Mutation: return the abandonment after `StartDomain`.
- **Voter change during an open claim.** Two removals back to back with a value
  accepted by the removed voters (§4.4 example). The value survives. Mutation:
  skip import.
- **Containers.** The same two-coordinator scenario through `startRelocation`,
  asserting on `n.CT.Payload(name)` that exactly one node holds the payload.

**The owner probe (§3.5.1).** These use `Options.IndependentReplicas` and a
directed per-link fault on the probe. `LinkFault` sits on the receiving side
keyed by the caller's CN, so `SetLinkFault(voter, owner, LinkFault{Block: true})`
makes the owner unreachable to that one voter and to nobody else. The injector
gains the probe's `Ping` as a separately targetable method, as it gains the
claim RPCs above. Each test forces the coordinator's decision gate open with
`quorateGate`, so what is under test is the voters' own check, not the
coordinator's health view.

- **Owner reachable from a majority.** Config `{a, b, c}`, owner `d` alive.
  Block the probe on `a→d` only. `a` proposes, `b` and `c` reach `d` and refuse.
  Assert no certificate, no proof, `recovery_claim_owner_reachable` naming `b`
  and `c` with what each reached, and the same in `lv cluster claim` output.
  Mutation: skip the probe in the `Accept` handler. A certificate then forms,
  which must fail.
- **Owner reachable from a minority.** Block `a→d` and `b→d`. `c` refuses, `a`
  and `b` accept, and recovery proceeds with one owner. Mutation: probe
  `dest_host` instead of `source_host`. The claim then refuses, which must fail.
- **Proof-grade fencing.** Power `d` off through the fence fake before the
  claim. Assert the claim forms on the first tick and no voter recorded an
  owner-probe refusal. Mutation: run the claim before the fence in
  `failover()`. Voters then reach `d` and refuse.
- **Probe budget.** Hold the probe on every `voter→d` link with a `Delay`
  longer than `claimProbeTimeout`, with twenty workloads on `d`. Assert every
  claim completes within `claimTimeout`, and that each voter probed `d` once
  (counted by a probe hook). Mutation: drop the per-source result reuse. The
  probe count then fails.
- **A voter that is the old owner.** Config `{a, b, victim}`, the victim alive
  and wrongly declared failed. The victim's `Accept` refuses with "is the
  owner". Mutation: remove the `source_host == me` check, with the probe
  stubbed to report self-dials as unreachable.
- **A rogue coordinator.** A test client holding a host certificate sends
  `Accept` directly: once naming a live host as the source, once naming a dead
  host as the source of a workload whose settled row names a live one. Assert
  `owner_reachable` and `source_mismatch` refusals from a majority. Mutation:
  drop the source cross-check. The second case then certifies.
- **Owner returns after a value was chosen.** The `OnAccept` hook kills the
  coordinator after a majority accepted. Unblock the owner. The successor
  completes the same proof ID and certificate. Mutation: re-probe on an
  already-accepted value. The claim then stalls forever, which must fail.

**Dead destinations and dead voters (§3.12, §4.6).**

- **`lv host rm --dead`.** A decided promote to `D`, and `D` destroyed before
  `StartDomain`. `ha.claim.stranded` names the workload and the command.
  `--dry-run` reports one stranded recovery and changes nothing. It refuses
  while `D` has no proof-grade fence. With the fence it removes `D` from the
  voter config (when `D` is a voter), removes the host and publishes the CRL,
  and the next tick supersedes at `attempt + 1` with one owner. Mutation: skip
  the revocation check in the voters' supersede verification. A supersede
  before the CRL lands then succeeds, which must fail.
- **The voter set survives the kill switch.** After genesis, set
  `enforcement.recovery_claim` false on every node. `VoterSet` still returns the
  config's members, and a fenced member still counts in the denominator.
  Mutation: make `VoterSet` fall back to the derived set when the flag is off.
- **Automatic genesis waits for a clean cluster.** Five hosts, `voter_config_v1`
  latched, `node-4` in `maintenance`. No generation is written and
  `ha.voter.genesis_pending` names `node-4`. Ending the maintenance writes
  generation 1 with all five members on the next tick. Mutation: drop the
  clean-cluster check. Genesis then writes four members, which must fail.
- **Genesis across a lease hand-off.** Two nodes each believe they hold the
  lease, via IndependentReplicas with a directed link fault, and both propose
  genesis. Exactly one generation-1 value is decided, and every node adopts
  it. Mutation: write generation 1 without the claim. Two rows then exist,
  which must fail.
- **Reset is decided and sticky.** After genesis, `lv cluster voter reset`
  with one voter unreachable is decided by the other four. Every
  node's `VoterSet` becomes derived at the same generation, and automatic
  genesis does not run again on later ticks. Mutations: apply a reset on one
  node without the claim, so the nodes disagree on `VoterSet`, which must fail.
  Separately, let automatic genesis run after a reset, which must fail.
- **`lv cluster voter force-reconfigure`.** Five voters, three destroyed. It
  refuses while any named host lacks a proof-grade fence, when only two are
  named (a majority survives), and while a non-voter host is neither reachable
  nor fenced. With all three fenced it writes `g+1` from the two survivors,
  emits the audit event and raises `ha.voter.forced`. A value accepted at `g`
  by one survivor alone is imported and re-certified at `g+1` with the same
  proof ID. Mutation: skip the forced-seal check at the destination. A
  `g`-certificate held on a destination then executes after the force, which
  must fail.
- **A forged forced row.** A node writes a `force:` row naming live voters as
  lost. Every node that reaches them refuses to adopt it. Mutation: skip the
  receiver-side probe.

### 7.2 Unit (`internal/corrosion`, `internal/grpcapi`, `internal/failover`)

- Voter rules (§3.5) as a table-driven test over ballot orderings. A property
  test (random schedules, 3 and 5 voters) checks that there is never more than
  one `value_digest` with a majority of accepts at one key.
- Certificate verification: a forged signature, a wrong CN, a self-minted
  certificate (the `TestAuditSigning_RejectsASelfMintedCertificate` shape), a
  revoked certificate, one voter counted twice, the wrong generation, a
  generation replaced by a forced one, a digest mismatch (including a changed
  `source_host`), a stale incarnation.
- The owner probe's verdict: a CN that is not `source_host` is *not reached*, a
  result older than `claimProbeMaxAge` is not reused, and an already-accepted
  value is not re-probed.
- Forced-row adoption: members plus lost equal to `g`, survivors fewer than a
  majority, unanimity, and replacement of an ordinary row at the same
  generation.
- `ExecuteLocal` never writes `mutation_log`, and `stmtshapecheck` refuses it
  for a replicated table.
- A `TestAdvertise_RecoveryClaimWithheldWhileOff` test, paired with the existing
  `TestAdvertise_SharedStorageFenceIsUnconditional`, pins the reasoning in §5.2
  in the place a future reviewer will look.
- Race runs with a real budget, per `CLAUDE.md`: a focused
  `go test -race -timeout 5m ./internal/corrosion/ -run 'TestRecoveryClaim|TestVoterConfig'`,
  and the full packages at 60m (corrosion) and 90m (grpcapi).

### 7.3 Lab (5-node kvm003)

Verify with `virsh list --all` and `lxc-ls` on **every** node, not through
litevirt. That follows the repo's rule that a fleet fake cannot prove qemu did
the thing.

1. **Majority/minority partition.** nftables drops everything between `{n1, n2}`
   and `{n3, n4, n5}`, with n5 destroyed from the lab host. Expect one recovery
   on the majority side, none on the minority side, and exactly one running
   domain per workload after heal.
2. **Two coordinators.** `SIGSTOP` the lease holder for longer than
   `leaseDuration` (45 s) while a victim is destroyed, then `SIGCONT` it. It
   resumes believing it leads. Expect it to lose the claim and leave no running
   copy.
3. **Voter removal after a fence.** Fence n5, run `lv cluster voter rm n5`
   then fail n4. The claim still forms on `{n1, n2, n3}` of 4.
4. **Owner reachable.** Drop only n1's traffic to n4 with nftables so n1's
   coordinator judges n4 failed. Expect `recovery_claim_owner_reachable` naming
   the voters that still reach n4, and n4's domains untouched.
5. **Stand-down.** Flag off everywhere, restart: behaviour matches the pre-claim
   build, and `lv cluster voter ls` still shows the explicit set. Flag on again:
   the claim history is intact (`lv cluster claim`).
6. **Forced reconfiguration.** Destroy three of five voters, record
   `lv host fence-confirm` for each, and run
   `lv cluster voter force-reconfigure` on a survivor. Expect a
   two-member generation, the audit event, and recovery resuming on it.

These drills run on the kvm003 5-node lab, not on a laptop-hosted lab.

---

## 8. Alternatives considered

### 8.1 Embedded Raft (3 or 5 voters)

This is what colonelpanik/litevirt#250 suggests first, and it is the right end
state if more state ever needs linearizability. It is not the right next step
for this issue:

- **It is a second replication system.** It brings a log, snapshots, compaction,
  leader election, its own membership changes and its own upgrade story, next to
  CRDT replication and its statement-shape ledger. Every rolling-upgrade rule in
  this repo would need a Raft counterpart.
- **It adds a leader whose availability recovery depends on.** Claims have no
  leader: any coordinator with a reachable majority can finish a decision,
  including one someone else started.
- **The decision is per key and write-once.** Single-decree Paxos per
  `(workload, epoch, attempt)` is the smallest thing that gives G1: a voter
  handler, a proposer loop and a verifier that reuses the audit signing
  identity.
- **It is compatible with later work.** If Raft arrives, the claim key and
  certificate format become a Raft-committed record, and destinations keep
  verifying the same certificate. The executor side of this design does not
  change.

### 8.2 Storage-enforced fencing

Examples: SCSI-3 persistent reservations, RBD exclusive-lock with blocklisting,
NFSv4 leases. This is the strongest guarantee, where it exists: the second
writer's I/O fails. It does not cover the cases here:

- local-disk VMs recovered from a replica (promote), where the "shared resource"
  is ownership, not a disk;
- container relocation, which recreates from an image;
- backends without the primitive (plain NFSv3, local qcow2).

`shared_storage_fence_v1` is already host-fence-gated rather than storage-gated.
Storage fencing is worth adding as defence in depth for shared-disk backends
that support it, and it is tracked separately. It is not a substitute for G1.

### 8.3 Smaller options, rejected

- **Strict "one grant per `(vm, epoch)`" with no ballots.** This is the literal
  starting point. Two coordinators that each self-grant first, with one voter
  dead, deadlock at 1–1 **permanently**, because a grant cannot be revoked and
  the epoch does not advance. That is exactly the harness scenario. Ballots are
  the minimal fix, and they keep "at most one *value* per key", which is what
  the goal needs.
- **A single witness as the decider (CAS on one node).** It is simple, but it
  makes one node special, and recovery stops when that node is down.
- **Counting grants in a replicated table.** This recreates
  colonelpanik/litevirt#250 one layer down. The issue says so: *"Incrementing
  a counter independently on each replica recreates the same race."*

---

## 9. Decisions

Each question as it was put, then what was decided and why. The body of this
document already follows every decision.

1. **The literal decision vs. Paxos ballots.** The brief was "each voter
   durably grants at most one coordinator per `(vm, owner_epoch)`", which taken
   literally deadlocks on the harness scenario (§8.3).
   **Decision: Paxos ballots, as written.** The invariant is at most one
   *value* per key, and a voter may move its promise to a higher ballot. That
   keeps the property G1 needs and removes the permanent 1–1 deadlock.
2. **Should a voter check the precondition itself?**
   **Decision: yes, by probing the recorded old owner directly (§3.5.1).**
   Before accepting a value it has not accepted before, each voter probes
   `source_host` over the peer transport and refuses, naming itself and what it
   reached, if it can reach it. Probing directly rather than reading replicated
   `host_health` avoids the replica-lag cost that made this look expensive, and
   makes a certificate mean that a majority of voters could not reach the
   source (G6), which also defends against a coordinator whose health view is
   wrong or forged.
3. **Supersede without an abandonment.**
   **Decision: keep the evidence rule, "destination fenced proof-grade, not a
   member, and revoked", and give it one command, `lv host rm --dead`
   (§3.12).** There is no `lv cluster claim abandon`. Revocation is
   what makes the rule safe, and one command that checks the fence, removes
   the voter and the host, and publishes the CRL means an operator cannot get
   the order wrong. `ha.claim.stranded` points at it.
4. **What should the kill switch restore?**
   **Decision: the voter set is permanent and independent of
   `enforcement.recovery_claim` (§4.5, §5.1, §5.6).**
   colonelpanik/litevirt#251 step 2 ships on its own token, `voter_config_v1`.
   A kill switch that silently changed the quorum denominator would be a second
   incident in the middle of the first. A cluster that has permanently lost a
   majority of voters, where `voter rm` can never succeed, has the audited
   break-glass `lv cluster voter force-reconfigure` (§4.6) instead.
   `voter_config_v1` is mandatory, with no flag, because a node with a flag off
   would count a different majority from its peers. Genesis is automatic on a
   clean cluster, so every cluster reaches the fixed set. The exit is a decided
   `lv cluster voter reset` (§4.2), which moves every node back to
   the derived set at one generation. Neither the exit nor anything else makes
   a rollback below a latched token clean: that enters WAL quarantine.
5. **Latch population.**
   **Decision: latch sweeps stay on derived liveness (`VotingEligible`), as
   written (§4.5).** Moving them to the voter config would let one fenced voter,
   which stays a member until removed, hold every future capability latch off.
6. **Garbage collection of `local_recovery_claims`.**
   **Decision: keep rows forever until measured otherwise, as written.** Rows
   are tiny and bounded by the number of recoveries, and keeping them is always
   safe. A GC rule would need a proof that no proposer can ever run phase 1 on
   a key again.
7. **Which mint sites are covered.**
   **Decision: scope as written.** Reschedule, promote and container relocate
   are claim-gated. `resolvePendingRelocations` reuses the certificates of the
   relocations it resumes. `ActionOwnerAssert` (a recorded owner reclaiming its
   own workload) and `ActionLBApply` stay on their current gates, because
   neither transfers ownership to a new destination.
8. **Signing key.**
   **Decision: reuse `host.key` with domain separation, as written (§3.9).**
   It is the identity every voter already has and the one audit signing
   bootstraps from. The `"litevirt-recovery-accept-v1"` and
   `"litevirt-recovery-abandon-v1"` separators keep its signatures disjoint
   from TLS and audit rows.

---

## 10. Where the implementation departs from the text above

Each of these was found while writing the code. The body has been corrected
where it described the mechanism; this list records what changed and why.

1. **An identical Prepare is answered as the promise already made** (§3.5).
   The sketch refused `promised >= b`. A duplicated Prepare at the ballot
   already promised changes nothing, so the voter answers `promised` for it;
   only a ballot strictly below the promise is refused.
2. **The proposer always runs phase 2.** §3.13 step 4's shortcut (fetch stored
   accepts when a majority already reports one value) is not implemented.
   Re-accepting a value it already holds is idempotent for a voter and does not
   re-probe, so running phase 2 costs one round trip and gives fresh accepts at
   the current generation, which an imported value needs anyway.
3. **Genesis unanimity is over both phases.** Phase 1 goes to every proposed
   member and needs all of them; the promises carry each member's incarnation,
   which is how the value's member entries are built. Phase 2 goes to the
   decided value's members, which may be another proposer's. Two proposers'
   member sets are both "every voting-eligible host", so they intersect.
4. **A voter answers only under the generation it has adopted**, including for
   voter-config keys. A proposer racing a config change that has already been
   decided and adopted is refused `recovery_claim_wrong_generation`, writes
   nothing, and learns the new generation from `voter_configs` by replication.
   In a genesis race across a lease hand-off, usually only the first proposer
   completes.
5. **Import raises the promise** (§4.4 rule 2). An imported accepted ballot
   can be higher than the importer's own promise; the importer raises its
   promise to it, so the accepted ballot never exceeds the promise. Imported
   state carries no signature; the value is re-signed at the new generation
   when a proposer re-accepts it.
6. **A frozen source is sealed or past.** An importer counts a member of `g`
   whose own state for `g` can no longer change: it accepted a change of `g`
   (sealed) or has already adopted a later generation.
7. **Revocation is read from the installed CRL bundle** (§3.10 step 5), the
   CA-verified union of every published `cluster_crl` row (`SyncClusterCRL`),
   not from the replicated rows directly.
8. **Digests.** Fields are length-prefixed rather than separator-terminated,
   and a voter-config value has its own domain,
   `litevirt-voter-config-value-v1`, so it can never collide with a workload
   value.
9. **An interrupted owner probe reads as reached.** A voter that could not
   finish its own check does not certify the eviction.
10. **`voter_configs` merge** — see §4.1: the certificate converges, the value
    never does.
11. **`lv host rm` refuses a voter before it revokes the certificate**, and
    names both ways out (`lv cluster voter rm`, and `lv host rm --dead` for a
    host gone for good): the daemon's own refusal would come after a
    revocation nothing undoes, leaving a voter that can no longer sign.
12. **Genesis proposes the derived voter set**, which on a clean cluster is
    every host; `lv cluster voter init` also starts the first member
    generation after a reset.
13. **`claimRecovery` returns the proof, not a separate certificate.** Its
    landed shape is `claimRecovery(ctx, proposal ActionProof, source string)
    (claimedProof, error)`: the certificate travels inside the returned proof
    (`ActionProof.ClaimCertificate`), which is the only form a destination ever
    sees. The attempt loop (§3.12) lives inside it.
14. **Promote is claimed inside the server**, once the promote destination is
    known (`Server.claimPromote`), rather than by widening the coordinator's
    `Promoter` interface. The coordinator still owns the refusal metrics.
15. **An owner-driven relocate is exempt from verification.** A container
    relocation the recorded owner started itself (a planned move, not a
    recovery) carries no certificate and needs none: the owner is not being
    evicted, so there is nothing for a claim to decide (`ownerDrivenRelocation`).
16. **`not_enforcing` reports a latched-but-withheld token.** A node whose
    `recovery_claim_v1` latched and whose flag was later turned off withholds
    the token, so it is not in its advertised set; it is still reported in
    `PingResponse.not_enforcing` so the cluster can see it.
17. **Containers take one decision for both tiers.** A container recovery's
    image-recreate and restore tiers share one claim; a coordinator that finds
    another coordinator's decided relocation completes it after
    `RelocateRestoreTimeout` instead of proposing its own.
18. **A retry keeps its round by re-proposing the same value** (§3.7). The
    proposer reuses its last ballot for a key when the value is unchanged
    (`claims.Spec.ReuseRound`) and binds each round to its phase-2 digest, so a
    different value can never be accepted at a round already used; a changed
    value takes a new round. The coordinator keeps the last proposal per key
    for the retry (`sameClaimIntent`).
19. **Abandonment is requested over an RPC** (`AbandonRecoveryProof`) from the
    coordinator that needs attempt `a+1`; the destination signs it only if its
    start checkpoint has not been written, and the checkpoint write
    (`AppendProofStepUnlessAbandoned`) refuses once the proof is abandoned. The
    two are checked under one transaction, so a started promote is never
    abandoned.
20. **Supersede evidence travels on Prepare only.** `Accept` at attempt `> 0`
    requires a promise made at that key, which the evidence check guarded; a
    voter that already holds an accepted value at the key skips the check, so
    the next proposer can still learn and finish a decided attempt.
21. **Removal evidence is "fenced proof-grade, no live `hosts` row, tombstone
    serial in the CRL"** (§3.12). Any proof-grade fence counts, not only one
    newer than the decided proof. After `lv host rm --dead`, the coordinator's
    next tick re-drives the removed host's recoveries at the next attempt
    (`recoverRemovedHosts`).
22. **Equal-binding proof copies converge on the greater encoding.** Two copies
    of one proof that differ only in evidence (one with a certificate, one
    without, after a heal) are tie-broken by row encoding in the merge, and
    the certificate is folded in, so every replica ends with the same bytes.
23. **`WriteVMRescheduleProof` re-materialises** a claimed proof whose local
    row was lost or overtaken, rather than refusing a proof the cluster decided.
24. **A forced receiver named lost refuses** (§4.6). Adopting a forced
    generation that names this node lost, while it is running, would let one
    compromised signing key seize the voter set; the node raises
    `ha.voter.forced` with the reason and departs instead.
25. **The seal is durable** (`local_voter_seals`, schema v62): a survivor that
    signed a forced change never again accepts at the replaced generation,
    across restarts.
26. **A forced row replaces an ordinary one only through the anti-entropy
    merge**, not through WAL apply. The WAL path keeps the ordinary
    first-writer rule; the forced row reaches every node by the next AE pass.
    On WAL apply `voter_configs` is `INSERT OR IGNORE`: a node with no row for
    the generation takes the forced row from the push alone and adopts it
    after its own checks, and a node already holding an unadopted ordinary row
    keeps it and drops the forced one without flagging a conflict (the WAL
    path reads a held row as a re-delivery; only the merge flags the pair).
    Such a node votes under neither row until the next AE pass replaces the
    ordinary one, so the cost is one AE interval of liveness, not safety.
    `TestFleet_VoterForcedRowOverTheWALPushPath` pins both.
27. **Import for a forced generation comes from every survivor plus every
    verified certificate in `runtime_action_proofs`**, and the coordinator runs
    a re-certification pass (`recertifyReplaced`) that re-decides each value
    certified at the replaced generation. A destination refuses a certificate
    at a generation a forced one replaced (`ReplacedByForcedGeneration`).
28. **Schema is three versions**: v60 adds `claim_certificate`, v61
    `local_abandoned_proofs`, v62 `local_voter_seals`.
29. **The proto certificate is a string** (the JSON encoding), not bytes, so
    it round-trips through the TEXT column without a second encoding.
30. **The abstention check behind `ha.voter.unavailable` is cached for 30 s**,
    so the leader's health tick does not issue a claim RPC to every voter on
    every pass.
31. **A forced row never replaces an ordinary row a node has adopted** (§4.6).
    The anti-entropy merge lets a forced generation replace an ordinary row
    for the same generation only on a node that has not adopted that
    generation. A node that has adopted the ordinary row was told by a
    majority of the previous generation that it was decided; replacing it by
    a merge would switch its electorate without the forced row's checks or the
    import, and two electorates would each decide that generation. It keeps
    the row it adopted, the conflict stays flagged as an unresolved tie, and
    `ha.voter.forced` reports the refusal. Such a node is one the forced
    change named lost, or one that must be removed (`lv host rm --dead`) and
    reseeded; the design has no way to reconcile the two generations, so the
    node does not try.
32. **A proof's certificate is replaced only by one that verifies on this
    node** (§3.9), on the write path and in the anti-entropy merge alike:
    signatures and a majority of a generation this node has adopted that no
    adopted forced generation replaced. A verifying certificate replaces one
    that does not verify here, or one at an earlier generation. The merge
    picks the copy that replaces the other, else the one that verifies here,
    else the greater encoding, so nodes that have adopted the same generations
    and CRL choose the same copy; a node behind on adoption can choose
    differently until it adopts, and the rows still differing is what makes
    the next pass merge them again.
33. **Proofs minted before enforcement are claimed, not grandfathered.** A
    pending reschedule or relocation without a certificate, minted before
    enforcement turned on, is claimed by the lease holder for its own value at
    attempt 0, with the old owner its proof-grade fence binding (fence_epoch)
    names as the source; a decided claim attaches the certificate, and a claim
    another value won is handled as `recovery_claim_lost`. While it waits,
    `ha.claim.uncertified` names it. The source is never inferred from
    timestamps or from whichever host is fenced now, so a proof that binds no
    proof-grade fence cannot be claimed; the condition says to stand claims
    down until it has run.
34. **An interrupted owner probe is not cached** (item 9). A probe whose
    caller's context ended mid-dial reads as reached and is not stored, so the
    next Accept naming the source probes again. Item 36 replaces the
    mechanism: no caller's context reaches the probe any more, so no dial is
    interrupted, and the rule that only a finished answer is stored remains.
35. **A supersede's prior certificate obeys the destination's generation
    rule** (§3.12): at a generation this voter has adopted and not one a
    forced change replaced. The coordinator re-decides the previous attempt
    under the current generation first, which certifies the same value again.
36. **The owner probe runs detached from the RPC that wants it, and a
    Prepare starts it** (§3.5.1; supersedes item 34). On the kvm003 lab a
    hard-killed owner that was also a voter took five rounds to decide. Its
    dial failed only after about 3 s (ARP), phase 1 waited out its Prepare for
    the proposer's whole call timeout (3 s), and the Accept then arrived with
    under 2 s of `claimTimeout` left. The probe ran under that Accept's
    context, so every voter's dial was cancelled with it. Item 34 rightly did
    not cache an interrupted dial, and so nothing ever learned "not reached"
    until a round happened to let a probe finish. Now:
    - a probe runs under its own `claimProbeTimeout` and no caller's context,
      one per source host at a time (fifty Accepts share one dial). It stores
      only the answer it finished with, and that answer, "not reached"
      included, is used for `claimProbeMaxAge` and no longer, so a host that
      comes back is probed again. A probe that timed out on its own
      `claimProbeTimeout` is a finished "not reached", as it always was;
    - an Accept waits for the probe up to its own deadline. If the probe has
      not finished by then, the Accept reads as reached ("probe in flight"),
      as item 9 requires, and the probe runs on;
    - a Prepare for a workload key starts the probe of the host this voter's
      row names at the key's epoch, and of the source the last Accept at the
      key named. It skips a host being probed and one whose answer is younger
      than `claimProbeRefreshAge`. That age is `claimProbeMaxAge` minus the
      proposer's call timeout, so a result the Prepare leaves alone is still
      valid when the round's Accept arrives. The start decides nothing: the
      Accept probes the source its value names.

    The timing budget, with call timeout C = 3 s, `claimProbeTimeout` P = 2 s,
    `claimProbeMaxAge` M = 5 s, refresh age M − C = 2 s and `claimTimeout`
    5 s: a probe started at Prepare finishes within P < C. When the dead
    source is a voter, phase 1 lasts C, so the answer is already cached when
    the Accept arrives. When it is not a voter, the Accept arrives at once and
    waits at most P for the answer. Either way a dead source decides in its
    first round. A round that still misses, for example because the lease cut
    the claim deadline short, is retried on the next coordinator tick, whose
    Prepare refreshes the probe, so it decides in the second.
    `forcedProbe` (§4.6) still probes afresh under the operator's context.

37. **A claim key names the workload's incarnation** (§3.1). On the kvm003
    lab (2026-10-01) a VM named `claimvm` was recovered under the claim
    `vm/claimvm@1#0`, deleted, and re-created under the same name on another
    host. A new VM starts at the owner epoch every VM starts at, so when its
    host died its claim was `vm/claimvm@1#0` again. The voters still held the
    first VM's accepted value there, and Paxos obliges a proposer that learns
    an accepted value to re-propose it: the value named the first VM's owner
    as its source, its old owner refused it as its own eviction, a voter whose
    row named the new owner refused it as a source mismatch, and the new VM
    was never recovered. In the fleet reproduction enough voters held the old
    value to re-certify it without a check, and the new VM was pointed at the
    first VM's spent proof instead, which never runs; a re-created container
    was re-keyed under the first one's proof and relocation token. Promises
    are kept forever (§9 Q6), so nothing would ever have cleared the key.

    Owner epochs cannot be made to carry the difference: a name's tombstone
    is purged on re-create and garbage-collected after its retention, so the
    node that re-creates it cannot know the epoch a previous incarnation
    reached. The incarnation is the row's `created_at`, the identity the
    anti-entropy merge already decides live-against-tombstone from: every path
    that brings a name back to life stamps a fresh one at nanosecond
    precision, and every path that moves a row preserves it. That last was
    not true of one path until this item: a container image-recreate
    relocation (`RelocateContainerWithToken`) stamped its target row afresh,
    so a relocation decided at the source's incarnation refused at its
    destination for good, the source row already tombstoned, and the
    container's next recovery would have had a fresh key past a stranded
    decision. It now keeps the source's `created_at`, as the runtime re-key
    already did (`RekeyContainerOwnerGuarded`). Before the latch a pre-epoch
    source still takes the retained upsert, whose conflict arm revives a
    stale same-name tombstone on the target and keeps ITS created_at; after
    the latch it takes the guarded `INSERT OR REPLACE` shape, which writes the
    source's (both shapes predate this item, and the latch is
    replication-gated, so every receiver knows it). The destination also
    accepts the row that carries the decision's relocation token, which covers
    a relocation made before the latch: the token is random per decision and
    digested into the certified value, so that row was written by this
    decision and nothing else. The VM
    UUID in the spec was the other candidate; a container has none, and the
    claim must cover both. A row with an empty `created_at` cannot occur
    through any writer (both columns are `NOT NULL`, and every writer stamps
    one), but an unstamped row is given the fixed incarnation `unstamped`
    (`corrosion.IncarnationOf`) rather than falling back to the legacy key,
    so the key format never depends on a row's contents.
    - **Key, certificate, voter state.** `ClaimKey.Incarnation`
      (`RecoveryClaimKey.incarnation`, field 5) is the row's `created_at`.
      A voter keeps incarnation-scoped keys in `local_incarnation_claims`
      (schema v63), with `incarnation` in the primary key, and legacy keys in
      `local_recovery_claims`, so a re-created workload starts with no claim
      history at all. An accept at a scoped key is signed under its own
      domain, `litevirt-recovery-accept-v2`, with the incarnation in the
      payload, so a signature for one incarnation never verifies for another
      or for the legacy key; an abandonment likewise
      (`litevirt-recovery-abandon-v2`). A legacy key's bytes are unchanged,
      so every certificate minted before this release still verifies. The
      value digest is unchanged too: the incarnation is bound by the key,
      which the accept signs, and the value it decides is the same proof.
    - **The destination binds it.** `VerifyClaimCertificate` refuses a
      scoped certificate unless the destination's own live row for the target
      is the incarnation it names (`certificateIncarnationIsLive`): a
      certificate for a deleted VM authorizes nothing for the VM re-created
      under its name. A legacy certificate binds none, as before.
    - **Voters do not refuse a mismatched incarnation.** A row of another
      incarnation says nothing about the key, exactly as a row at another
      epoch does: the source cross-check reads only the voter's row of the
      key's incarnation (`rowIsIncarnation`). Refusing would add no safety,
      since the destination enforces the binding, and would cost liveness: a
      voter whose replica is behind a re-create would refuse the new
      workload's recovery until it caught up.
    - **Old claim rows are left alone.** A previous incarnation's rows are
      harmless once nothing shares its key, and deleting a voter's promise is
      the one thing §9 Q6 forbids: a stale coordinator still recovering the
      deleted workload would find a key with no history and could decide it
      again. They are bounded by the recoveries a cluster has ever made. A
      later GC could drop rows whose incarnation's tombstone has itself been
      purged; nothing in this release needs one.
    - **Rollout: `claim_incarnation_v1`, mandatory and ReplicationGated.** A
      voter on an older build drops the key's incarnation, so it would answer
      an incarnation-scoped Prepare at the legacy key, which is the very
      collision being fixed, and its accept would not verify. A coordinator
      may change the format only once no voter can be an older build, which is
      a latch over every host; it states a fact about the binary, so it has no
      flag (a flag would let two coordinators claim one recovery under two
      keys). Until it latches every coordinator claims the legacy key and
      behaves exactly as before, bug included; once it has, every coordinator
      claims the scoped key. The proposer also counts only an accept that
      signs its own key, so a voter that drops the incarnation certifies
      nothing.
    - **Crossing the latch: seal and bridge.** Nodes latch a few seconds
      apart, so one recovery can be claimed at its legacy key by a node that
      has not latched and at its scoped key by one that has. A voter's
      promise at a scoped key reports what it accepted at the legacy form of
      the same (kind, name, epoch, attempt), in the same transaction that
      writes the scoped row; from then on it refuses that legacy key
      (`recovery_claim_legacy_key_sealed`). A majority of promises therefore
      holds everything the legacy key can ever decide. When no promise reports
      a value at the scoped key itself, the proposer re-proposes the
      highest-ballot legacy value (`claims.Spec.AdoptLegacy`), and a voter
      that accepted it at the legacy key re-accepts it without probing again
      (§3.15), though still cross-checking its source against its row of this
      incarnation. The proposer re-proposes the legacy value unless it is
      PROVEN to be another incarnation's and never to run
      (`Server.legacyValueExcluded`), and it is never decided beside one that
      is not. Proof comes from the one host that could execute the value, its
      destination, reading its own database
      (`corrosion.AbandonForeignProof`, asked for over `AbandonRecoveryProof`
      with `foreign_only`): it ran or failed the proof while this incarnation
      stayed at the epoch (a VM proof completes in one local batch with its
      row's epoch bump, and a relocated container's row carries the token
      its relocation wrote), or the proof never started and this
      incarnation is not pending on it. It then records the proof as
      abandoned and signs, and never runs it. A destination removed for good
      (`lv host rm --dead`) counts too: it can run nothing. Neither wall
      clocks nor sources take part. An earlier revision attributed a legacy
      value by its proof's mint time against the row's `created_at`, with a
      clock-skew margin, and by its source; both failed unsafe. A creator
      clock more than the margin ahead made this incarnation's own decision
      look like a previous one's, so a second value was decided beside a
      legacy certificate that still verified. A stranded decision names its
      dead destination, not the owner the next claim leaves, so a mismatched
      source is no proof either. Whatever the destination cannot show — it
      is unreachable, an older build, or holds no row of the proof — the
      value is adopted, as the legacy key itself did: ambiguity costs
      liveness, never a second decision. If its voters then refuse it, the
      recovery waits, and `ha.claim.legacy_held` names the workload, the
      decision and why it could not be excluded. If they accept it, the
      scoped key decides it; a decided proof that has already run or failed
      is never written (it would take the workload off its failed host for a
      proof that never executes), and the coordinator's supersede asks the
      destination for the same foreign abandonment, which moves the claim to
      the next attempt (`supersedeEvidence`). The condition is a replicated
      per-workload row, written by the deciding node and resolved only by the
      lease holder once the workload's own rows show it has moved on, so it
      neither clears because the key decided nor lives in one node's memory.
      It is raised only for a value that is genuinely ambiguous: one the
      deciding node's own replica shows to be this incarnation's pending
      decision (its row, at the key's epoch, points at the live proof —
      `corrosion.ProofIsPendingDecisionOf`) is the value the key should
      re-propose anyway, and a destination that is merely slow to say so
      within `claimExclusionTimeout` raises nothing. That check only
      withholds a warning; adoption does not depend on it. Once the scoped
      key has decided an adopted spent value the bridge never runs again for
      it, so the coordinator re-asserts the condition on every tick it
      refuses that value (`NoteLegacyHeld`): a raise whose write failed is
      retried there, and a row already open for the same decision is not
      rewritten.
      A proof left in flight on a live destination cannot be excluded by the
      bridge, which must not abandon what may be running. Its escape is
      scoped to the one workload: `lv cluster claim-release <kind>/<name>`
      (admin, `ReleaseLegacyHeldClaim`), which the condition names. It reads
      the decision from the open condition and asks its destination for the
      same foreign abandonment with `operator_release` set. That flag
      overrides exactly one of `AbandonForeignProof`'s refusals — a proof the
      destination itself claimed and left in progress, with no start
      checkpoint (`corrosion.AbandonForeignProofInFlight`) — and only after the
      destination has confirmed, from its own state, that nothing runs it
      (`Server.holdWorkloadIdle`): it takes the holds a runner takes (for a
      VM the operation lock and the per-VM start lease; for a container the
      operation lock) and under them finds no active domain or running
      container of the name. Those holds are not the safety argument,
      though: a runner can claim a proof before it takes them (a backup
      restore claims its carried proof, then opens the repo, then takes the
      container lock), and the start lease expires under a start that runs
      past `vmLockTTL`. What decides is the database. Every executor of an
      ownership move — promote, reschedule start, restore relocation, the
      sweep's relocate-recreate — records the start checkpoint
      `start_attempted` through `AppendProofStepUnlessAbandoned` before it
      defines, lays down or starts anything. That append and the release's
      record read the same node-local table in their own transactions, so
      exactly one wins: a release recorded first makes the executor refuse at
      its checkpoint (terminally — a reschedule fails its proof, so the row
      leaves pending instead of retrying), and a checkpoint recorded first
      makes the release refuse the proof. The abandonment also refuses every
      later claim of the proof, the destination's own resume included; the
      bridge's next ask is then answered from that row and the claim decides
      afresh. A destination that is never reached confirms nothing, and the
      command refuses and names `lv host rm --dead`. A request that reached
      the destination but brought back no verified answer (a timeout, a
      dropped connection, an abandonment that does not verify) may have been
      recorded, so it is reported as an unknown outcome, never as nothing
      released; running the command again answers, since a recorded release
      is signed again. A destination on a build that predates the release
      ignores `operator_release` and refuses the proof as in flight on it,
      and that refusal is named as needing an upgrade. Every call writes a
      `recovery_claim.release` audit row — `ok`, `refused` or `unknown` —
      with a context detached from the caller's. The cluster-wide stand-down
      (`enforcement.recovery_claim: false`) remains the last resort for a
      destination that keeps refusing. While the destination
      answers, the next tick decides; if it is gone for good,
      `lv host rm --dead` releases it. This incarnation's completed decision
      is never excluded (its row is past the epoch at its destination), so a
      coordinator still reading the epoch it left completes a no-op. A
      previous incarnation's spent decision is excluded rather than adopted,
      so it cannot hold the new workload's recovery for good. Pending proofs
      are not retired when their workload is deleted: retiring needs a new
      replicated statement shape, and could not mark the proofs minted before
      the upgrade that the bridge exists for. The exclusion does that work
      when it is needed. A recovery decided across the upgrade is completed,
      not decided twice; the lab's stale value is left behind.
    - **Schema bump: yes, v63**, one additive node-local table. No
      replicated statement shape changes: the certificate column is the same
      TEXT, and the ledger is untouched.
