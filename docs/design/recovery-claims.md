# Design: single-winner recovery claims

| | |
|---|---|
| Status | **Proposed**. Nothing in this document is implemented. Its open questions are decided (§9). |
| Issues | colonelpanik/litevirt#250; colonelpanik/litevirt#251 (step 2) |
| Base | `main` at `8dde9cc7` |
| Pinned by | `TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner` (`tests/fleet/failover_two_coordinators_test.go`, skipped until this lands) |

**Reading this document.** Present tense describes code that exists on `main`.
Anything that does not exist yet is marked *proposed*: RPCs, tables, columns,
config keys, commands, metrics and health reasons. The docs guard
(`cmd/litevirt/docs_triangulation_test.go`) only scans `README.md` and
`docs/*.md`, so it does not read this file. Every proposed command is still
marked "(proposed)" where it appears, so a reader never mistakes one for a
command that exists. If the guard is ever widened to `docs/design/`, those
lines need `ci:skip-cmd`. When a section lands, its operator-facing parts move into
`docs/migration-failover.md`, `docs/operating-model.md` and
`docs/configuration.md`, and the guard checks them there.

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
claim key = (target_kind, target_name, owner_epoch, attempt)
```

- `target_kind` / `target_name` are `vm` / `container` and the workload name.
  These are the same fields as `ActionProof.TargetKind` / `TargetName`.
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

Three peer-only RPCs are *proposed* in `proto/litevirt/v1/service.proto`. They
are authorized like replication RPCs: the caller must present a known host
certificate. Operator and CLI certificates are refused.

```proto
// proposed
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

// Read-only. Used by coordinators to learn, and by `lv cluster claim` (proposed) to inspect.
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

The voter's handler, *proposed* as `internal/corrosion/recovery_claims.go`, does
this for each message. Each step runs in one local SQLite transaction:

```
Prepare(key, b, gen):
  refuse unless gen == my adopted config generation AND I am a member at gen
         AND my voter_incarnation matches the member entry            (§3.11, §4)
  row := local_recovery_claims[key]
  if row.promised >= b: reply {promised:false, promised_ballot: row.promised}
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
  *learn*: a lagging coordinator (§3.12) and `lv cluster claim` (proposed) both
  read decided values through it, and must be able to while the owner is up. A
  voter may start the probe when a `Prepare` arrives, so the `Accept` rarely
  waits for it.
- **The probe.** A `Ping` over the peer transport (mTLS, host certificate) to
  the address in the voter's `hosts` row for `source_host`. It counts as
  *reached* only if the handshake completes, the peer certificate's CN is
  `source_host`, and the RPC returns. Anything else, including a different
  host answering on a reused address, is *not reached*. Its timeout is
  `claimProbeTimeout` (proposed, 2 s), the same order as `health.checkTimeout`
  (3 s).
- **Cost per recovery.** The probe runs once per `(voter, source_host)`, not
  once per workload: every `Accept` naming the same source within
  `claimProbeMaxAge` (proposed, 5 s, one `claimTimeout`) reuses the result. A
  failed host with fifty workloads costs each voter one probe. Voters probe in
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
  `recovery_claim_source_mismatch` (proposed) if it is not. A row at another
  epoch, or one mid-transfer, says nothing about this key, and the voter does
  not wait for it. The row for epoch `e` was written when the workload last
  moved, normally long before the failure, so this does not race the decision
  the way `host_health` freshness does.
- **Refusals are named.** The refusal carries the voter and what it reached,
  for example `recovery_claim_owner_reachable` (proposed) with detail
  `node-3 still reaches node-2 (Ping answered in 4 ms)`. The coordinator
  reports every refusing voter in its gate refusal (§5.4), and
  `lv cluster claim` (proposed) prints each voter's last refusal for the key.
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

*Proposed*, in `schemaDDL` (`internal/corrosion/schema.go`), and like
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

This is a v57 schema change (v56 is the credentials split). The ledger entries
follow the pattern v55 used for `local_term_bindings`, plus the
`createTableUnits` marker.

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
  `modernc.org/sqlite`. It *proposes* adding `_pragma=synchronous(full)` to
  `sqliteDSN`, which is a no-op if the default is already FULL, and a startup
  check that reads `PRAGMA synchronous`. If the value is below 2, the node
  advertises neither `voter_config_v1` nor `recovery_claim_v1` (§5.1), and
  `Prepare` / `Accept` return `FailedPrecondition`.
- **Not through `mutation_log`.** The write must not be relayed. Today
  `local_term_bindings` avoids relaying by doing its `INSERT` inside the
  *guard* of `ExecuteBatchGuarded`, where statements are not logged. The claim
  handler needs a plain local transaction with nothing to relay. It is
  *proposed* as `Client.ExecuteLocal(ctx, func(*sql.Tx) error)`, which runs
  under the same client mutex, writes nothing to `mutation_log`, and is refused
  by `stmtshapecheck` for any table in `tableNames`. That keeps "local" a
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
accept payload = "litevirt-recovery-accept-v1"
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

- *Proposed* column `runtime_action_proofs.claim_certificate TEXT NOT NULL DEFAULT ''`,
  appended last for the digest reason v53 and v54 give. It is written in the
  same batch as the proof. That covers the reschedule path, which never uses an
  RPC.
- *Proposed* field `RuntimeActionProof.claim_certificate` (bytes) for the
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

Verification is *proposed* as `corrosion.VerifyClaimCertificate(ctx, c, cert,
proof, voterConfig) error` and runs at both executor trust boundaries:

- `startPendingVM` (`internal/health/reconciler.go`), after the existing
  exact-match and owner-epoch checks and **before** `ClaimActionProofFenced`.
- `claimCarriedProof` (`internal/grpcapi/action_proof.go`), after
  `WriteActionProofValidated` and the owner-epoch check, and before the claim.

The check, in order. Any failure refuses with the *proposed* reason
`health.ReasonClaimUnproven` (`"recovery_claim_unproven"`) and leaves the row
pending, the same way every other gate refusal does:

1. The certificate is present and parses.
2. `cert.key` equals `(proof.TargetKind, proof.TargetName, proof.OwnerEpoch, attempt)`,
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
with `lv cluster voter rm` then `lv cluster voter add` (proposed), which is two
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
  destination. That destination records the proof ID in a *proposed* node-local
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
  might come back and execute its valid certificate. A *proposed* health
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
  One operator command produces the evidence, `lv host rm --dead <host>`
  (proposed):
  1. It refuses unless the host is fenced proof-grade, and prints the fence
     command if it is not.
  2. If the host is a member of the adopted voter config, it removes it first
     through the `voter rm` claim, with seal and transfer (§4.3, §4.4). If no
     majority of the current generation is reachable, it stops and names
     `lv cluster voter force-reconfigure` (proposed, §4.6).
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

*Proposed* `c.claimRecovery(ctx, key, proposal) (proof ActionProof, cert Certificate, err error)`
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
   `claimTimeout` a *proposed* constant of 5 s.
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
   `recovery_claim_owner_reachable` (proposed) with every refusing voter and
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

*Proposed*, replicated:

```sql
-- Immutable once written, like leader_lease_terms. One row per generation.
CREATE TABLE IF NOT EXISTS voter_configs (
    generation    INTEGER PRIMARY KEY,
    members_json  TEXT NOT NULL,   -- sorted [{name, incarnation}]
    members_hash  TEXT NOT NULL,
    change        TEXT NOT NULL,   -- genesis | add:<name> | rm:<name> | force:<name,...>
    certificate   TEXT NOT NULL,   -- claim certificate deciding this generation (§4.3),
                                   -- or the forced-generation evidence (§4.6)
    created_by    TEXT NOT NULL,   -- principal, for audit
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL
);
```

The merge rule is `immutableMergeKeepLocalRow`, the rule `leader_lease_terms`
uses. A receiver adopts a generation only if its certificate verifies against
the generation before it (§3.10 steps 4–5, with key
`("voter_config", "", generation-1, 0)`). Two different rows for one generation
cannot both carry valid certificates (§3.16). A row that fails to verify is
evidence, and it is reported on the `ha.lww.unresolved` path rather than
adopted. A `force:` row is verified by the rule in §4.6 instead, and it is the
one exception to keep-local: a verified forced row replaces an ordinary row for
the same generation.

*Proposed*, node-local: `local_voter_adoption(generation PRIMARY KEY,
imported_from TEXT, adopted_at TEXT)`. It records which generation this node has
adopted and from which sealed majority it imported claim state (§4.4).

### 4.2 Bootstrap

A cluster with no `voter_configs` rows keeps today's derived `corrosion.VoterSet`.
The fixed set begins with an explicit operator action:

- `lv cluster voter init` (proposed) takes the connected node's current
  `VoterSet` as the proposed members, prints it, and asks for confirmation. It
  writes generation 1 only if **every** proposed member returns a signed accept
  for it. Genesis is unanimous because no earlier config exists whose majority
  could decide it. Unanimity on a healthy cluster is a small cost for a one-time
  step.
- It is refused unless `voter_config_v1` is durably latched (§5.1), so it
  cannot write a new replicated shape before every peer can decode it. It does
  not need `recovery_claim_v1` or `enforcement.recovery_claim`: the voter set
  is useful, and permanent, on its own (§4.5).

### 4.3 Add and remove

- `lv cluster voter add <host>` (proposed) and `lv cluster voter rm <host>`
  (proposed) change **exactly one** member per generation.
- The change from generation `g` to `g+1` is itself a claim, with key
  `("voter_config", "", g, 0)` and the new member list as its value. It is
  decided by a majority of generation `g`, so two operators running concurrent
  changes cannot both succeed.
- `add` requires the new member to be reachable. It supplies its incarnation and
  imports claim state (§4.4) before it counts toward any majority.
- `rm` of an unreachable member is allowed. That is the post-fence case, and a
  majority of `g` is enough.
- `lv host rm <host>` of a current voter is refused (proposed change) and names
  the two ways forward: `lv cluster voter rm` first, or
  `lv host rm --dead <host>` (proposed, §3.12) for a host that is fenced and
  gone for good, which makes the voter change itself. Deleting a `hosts` row
  must no longer change the voting population implicitly.
- **No automatic shrink.** After a fence, the fenced host stays a member and
  counts in the denominator until the operator runs `lv cluster voter rm` or
  `lv host rm --dead` (proposed).
  Operational state (`offline`, `maintenance`, `fenced`) no longer changes
  voting, which is the point of colonelpanik/litevirt#251. A *proposed* health
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
   `GetRecoveryClaim` in bulk (a *proposed* streaming variant) on a majority of
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
own (§9, Q4). The only ways to change it are §4.3 and §4.6.

The capability-latch sweep (`activationTargets`) keeps its current derived
`VotingEligible` population, so a fenced voter that is still a member cannot
hold every future latch off (§9, Q5).

### 4.6 Losing a majority of voters for good: forced reconfiguration

`lv cluster voter rm` (proposed) is a claim decided by a majority of generation
`g`. Once a majority of `g` is permanently gone, it can never succeed, and
neither can any recovery claim. The break-glass is
`lv cluster voter force-reconfigure --lost <host>[,<host>...]` (proposed), in
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
   (proposed) and raises `ha.voter.forced` (proposed), naming the lost hosts
   and the new generation. The condition stays until every lost host has been
   removed and revoked with `lv host rm --dead` (proposed), and the command
   prints that line for each one.

Before running, it prints the plan: survivors, lost hosts, their fence evidence,
and the number of keys it will import. The operator confirms it.

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
majority decided and nobody saw. `lv host rm --dead` (proposed) revokes it, so a returning
lost host cannot authenticate to any peer, and the forced row replaces any
ordinary row for its generation (§4.1).

---

## 5. Rollout

### 5.1 The capability tokens

There are two tokens, so that the voter set (colonelpanik/litevirt#251 step 2)
ships and stays in force independently of whether claims are enforced (§4.5,
§9, Q4).

**`voter_config_v1`** (proposed, `capabilities.VoterConfigV1`) covers the voter
set and the voter side of the protocol: `voter_configs`, the claim RPCs, the
node-local grant tables and the voter incarnation.

- **Mandatory: yes.** It states a fact about the binary: this build can decode
  `voter_configs` and can answer `Prepare` / `Accept` / `GetRecoveryClaim`
  durably. It enforces nothing on its own. The operator's opt-in is
  `lv cluster voter init` (proposed), and until that runs `VoterSet` is derived
  exactly as today.
- **Advertised when ready:** `PRAGMA synchronous` ≥ FULL (§3.7), the host
  signing key loads, and the claim RPCs are registered. A *proposed*
  `grpcapi.VoterConfigReadiness` is the local-only probe, in the pattern of
  `LeaseTermReadiness`.
- **`ReplicationGated`: yes.** Latching it allows the new replicated shape
  `voter_configs`. That is a claim about what every host still *receiving*
  replication can decode, which is the `lease_term_ledger_v1` argument.
- **Stand-down: none, by design.** An adopted voter config is permanent. The
  incident tools are `lv cluster voter rm` / `add`, `lv host rm --dead` and
  `lv cluster voter force-reconfigure` (all proposed, §3.12, §4.3, §4.6), not a
  flag. A host rolled back below this build after `voter init` cannot decode
  `voter_configs` and back-pressures its stream, so rollback below it is
  unsupported once a config exists. That note belongs beside the declaration
  in `capabilities.mandatory` when it lands.

**`recovery_claim_v1`** (proposed, `capabilities.RecoveryClaimV1`) covers
enforcement: coordinators claiming before they mint, and destinations
verifying before they execute.

- **Flag:** `enforcement.recovery_claim` (proposed), default **false**.
- **Advertised conditionally** in `Server.advertisedCapabilities` when the flag
  is on **and** this node is ready: `split_brain_gate_v1` is latched (the
  certificate rides on proofs) and `voter_config_v1` is ready on this node. A
  *proposed* `grpcapi.RecoveryClaimReadiness` is the local-only probe.
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

| | `shared_storage_fence_v1` | `recovery_claim_v1` (proposed) |
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
- **Every host on a new build, before `voter init`:** `voter_config_v1` latches
  by itself, because it is mandatory. Nothing changes: `VoterSet` is still
  derived. `lv doctor` (proposed check) says
  `voter_config_v1 latched; run lv cluster voter init` (proposed command).
- **After `voter init`:** `VoterSet` counts the explicit set for the fence
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

- **Gate refusals** use the *proposed* reasons `recovery_claim_unproven`
  (destination), and `recovery_claim_lost` / `recovery_claim_no_majority` /
  `recovery_claim_owner_reachable` / `recovery_claim_source_mismatch`
  (coordinator). An owner-probe refusal's detail names every refusing voter and
  what it reached, for example `node-3 still reaches node-2`. They go through
  the existing `noteGateRefused` observers, so they appear on the current
  gate-refusal metric with no new series.
- **Coordinator metrics** use the existing `mAttempt` triple with a *proposed*
  `PhaseClaim` and the results `ok`, `lost` (another value was decided),
  `no_majority`, `owner_reachable` and `superseded`.
- **`lv cluster claim <kind>/<name>`** (proposed) calls `GetRecoveryClaim` on
  every member and prints each voter's promised and accepted ballot, value
  digest, destination, source host, incarnation status, and last refusal with
  its detail. This is the one place a stuck claim can be diagnosed.
- **Health conditions** (proposed): `ha.claim.stranded` names each workload
  decided for a destination that is fenced or gone, with the exact
  `lv host rm --dead <host>` command (§3.12). `ha.voter.unavailable` names
  voters that are fenced, offline or abstaining (§4.3). `ha.voter.forced` marks
  a forced reconfiguration until its lost hosts are removed (§4.6).
- **`lv cluster voter ls`** (proposed) shows the adopted generation, its
  members, and per member reachable, fenced or abstaining, with incarnation
  mismatches.

### 5.5 Turning it on

1. Roll every host to a build with the claim protocol. Run `lv doctor fence`
   and confirm the fence posture is what you expect.
2. Wait for `voter_config_v1` to latch, which needs no config, and run
   `lv cluster voter init` (proposed) from any node. Confirm the member list.
   This step stands on its own: a cluster can stop here and keep an explicit
   voter set without ever enforcing claims.
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
- **The voter config is not part of the stand-down.** It is a fact the cluster
  agreed on, and `VoterSet` reads it whatever the flag says (§4.5, §9, Q4). The
  fence quorum and recovery quorum keep counting the explicit set. A voter set
  that has itself become the problem is repaired with `lv cluster voter rm` /
  `add`, `lv host rm --dead`, or, when a majority is gone for good,
  `lv cluster voter force-reconfigure` (all proposed, §4.6).

### 5.7 Schema summary (v57, proposed)

- Node-local tables: `local_recovery_claims`, `local_voter_incarnation`,
  `local_abandoned_proofs`, `local_voter_adoption`.
- Replicated table: `voter_configs`, written only after `voter_config_v1`
  latches.
- Replicated column: `runtime_action_proofs.claim_certificate`, appended last
  and emitted only after `recovery_claim_v1` latches.
- Statement-shape ledger entries for every new replicated shape
  (`stmtshapecheck`).
- `check-schema-bump.sh`, `CurrentSchemaVersion = 57`, and a `v57:` history
  line.

---

## 6. Failure modes and liveness

Claims trade availability for safety in named places. Each one below says what
stalls and how the operator unblocks it without giving up G1.

| Stall | Symptom | Unblock |
|---|---|---|
| **No reachable majority of voters** | `recovery_claim_no_majority`. Workloads stay on the fenced host. | Same as today's no-quorum case: restore connectivity. If some voters are gone for good but a majority of the current generation remains, remove them with `lv host rm --dead` or `lv cluster voter rm` (proposed). If a majority is gone for good, fence each lost host proof-grade and run `lv cluster voter force-reconfigure --lost <hosts>` (proposed, §4.6). That is audited, raises `ha.voter.forced`, refuses while a majority is actually reachable, and gives up the guarantees §4.6 names. |
| **Dead voter still in the config** | Fault tolerance is one lower than the host count suggests. For example, a 3-voter cluster with one fenced member needs both survivors. | If the host is gone for good: `lv host rm --dead <fenced>` (proposed), which removes it from the voter config and then from the cluster (§3.12). If it stays a host but should stop voting: `lv cluster voter rm <host>` (proposed). `ha.voter.unavailable` (proposed) names it. There is no automatic shrink, by decision. |
| **Voter with a changed incarnation** (re-imaged or reseeded) | It abstains, and `lv cluster voter ls` shows the mismatch. | `lv cluster voter rm` then `lv cluster voter add` (proposed). |
| **Duelling proposers** | Repeated rejected ballots, and `recovery_claim_lost` alternating between nodes. | Self-heals: the lease-term round seed, the lease-contest rule, and randomized back-off (0–1 poll) on rejection. If it persists, look for a lease that is not converging (`ha.lww.unresolved`). |
| **Stranded on a dead destination** (decided, destination died before starting) | The VM stays `pending` on D. `ha.claim.stranded` (proposed) names it with the command, and `lv cluster claim` shows a decided value naming D. | D returns and either executes or abandons. If D is gone for good: fence D proof-grade, then `lv host rm --dead D` (proposed; `--dry-run` first shows what it will do). It removes D from the voter config if it is a voter, removes the host, publishes the CRL and prints how many stranded recoveries will retry. Voters then accept the supersede evidence *"destination fenced proof-grade, not a member, and revoked"* for `attempt + 1` (§3.12). The residual risk, a revoked host rebooting from a stale replica, is the same exposure every removed host already carries. |
| **Old owner still reachable** | `recovery_claim_owner_reachable` (proposed), naming each refusing voter and what it reached. Workloads stay where they are. | Not a stall to unblock: most of the cluster can reach the owner. Find out why the coordinator judged it failed (failure detector, `host_health`). If the host is up but must not keep its workloads, fence it proof-grade: the probe then fails, and the next tick's claim proceeds. |
| **Destination refuses the certificate** (CA or CRL mismatch, config generation not yet adopted) | `recovery_claim_unproven` on the destination. | Usually replication lag on `voter_configs` or `cluster_crl`, which clears on the next reconcile. If not, compare `lv cluster voter ls` across nodes. |
| **Voter-config hand-off in progress** | Claims pause while `g+1` members import. | Completes when a majority of `g+1` has imported. A member that cannot import is removed like a dead voter. |
| **`synchronous` below FULL** | Neither token is advertised, so neither latches. | Fix the DSN or build. Never force the latch. |

---

## 7. Testing plan

Every assertion below is mutation-verified per `CLAUDE.md`: break the property,
see the test go red, restore. Each item names its mutation.

### 7.1 Fleet (`tests/fleet/`)

- **Un-skip `TestFleet_TwoCoordinators_OneFailedHost_AtMostOneWritableOwner`.**
  The harness gains a way to latch `voter_config_v1`, run `voter init`, enable
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
  and `c` with what each reached, and the same in `lv cluster claim` (proposed) output.
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

- **`lv host rm --dead` (proposed).** A decided promote to `D`, and `D` destroyed before
  `StartDomain`. `ha.claim.stranded` names the workload and the command.
  `--dry-run` reports one stranded recovery and changes nothing. It refuses
  while `D` has no proof-grade fence. With the fence it removes `D` from the
  voter config (when `D` is a voter), removes the host and publishes the CRL,
  and the next tick supersedes at `attempt + 1` with one owner. Mutation: skip
  the revocation check in the voters' supersede verification. A supersede
  before the CRL lands then succeeds, which must fail.
- **The voter set survives the kill switch.** After `voter init`, set
  `enforcement.recovery_claim` false on every node. `VoterSet` still returns the
  config's members, and a fenced member still counts in the denominator.
  Mutation: make `VoterSet` fall back to the derived set when the flag is off.
- **`lv cluster voter force-reconfigure` (proposed).** Five voters, three destroyed. It
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
   (proposed), then fail n4. The claim still forms on `{n1, n2, n3}` of 4.
4. **Owner reachable.** Drop only n1's traffic to n4 with nftables so n1's
   coordinator judges n4 failed. Expect `recovery_claim_owner_reachable` naming
   the voters that still reach n4, and n4's domains untouched.
5. **Stand-down.** Flag off everywhere, restart: behaviour matches the pre-claim
   build, and `lv cluster voter ls` (proposed) still shows the explicit set. Flag on again:
   the claim history is intact (`lv cluster claim`).
6. **Forced reconfiguration.** Destroy three of five voters, record
   `lv host fence-confirm` for each, and run
   `lv cluster voter force-reconfigure` (proposed) on a survivor. Expect a
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
   (proposed, §3.12).** There is no `lv cluster claim abandon`. Revocation is
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
   break-glass `lv cluster voter force-reconfigure` (proposed, §4.6) instead.
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
