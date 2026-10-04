# Canonical registry credentials

Status: **planned, not implemented; opt-in removed on 2026-10-04.**

This note tracks the deterministic-id model for registry credentials (OCI/Docker
logins). It records the problem, what an earlier build shipped and why that was
taken out, and the activation contract the real feature has to implement.

## 1. The problem

A registry credential is one row in `registry_credentials`, keyed by a random
`id`, with a partial `UNIQUE(scope, owner, registry) WHERE deleted_at IS NULL`.
The only writer (`corrosion.UpsertRegistryCredential`, called by
`SetRegistryCredential`, i.e. `lv registry add`) sends one batch: tombstone the
live row for the triple, then INSERT a row under a freshly minted id.

On one node the partial index guarantees one live row per triple. Across nodes it
does not. If two nodes write the same triple before either write has replicated
to the other, each mints its own id:

| | node A (older login, `rand-a`) | node B (newer login, `rand-b`) |
|---|---|---|
| receives the other's entry | B's tombstone wins LWW over `rand-a`; `rand-b` inserts. **Applies.** | A's tombstone loses LWW to `rand-b`; A's INSERT collides with live `rand-b` on the partial UNIQUE. **Back-pressures.** |
| live row afterwards | `rand-b` (`rand-a` tombstoned) | `rand-b` |

So **the newer login wins** everywhere, and nothing is corrupted or silently
picked. A's entry is held at the head of A's stream into B, and everything A
logs after it waits behind it. The entry clears through a side effect.
The peer-only (sensitive) anti-entropy lane notices that B lacks A's `rand-a` row,
which B's login has already tombstoned on A. It merges that tombstone into B, at
B's newer `updated_at`. On the next retry, A's INSERT is a last-writer-wins no-op
against that row, so the entry applies and the stream resumes.
The stall therefore lasts about one anti-entropy interval
(`anti_entropy_interval_sec`, 60s by default). If the sensitive lane is not
completing between the pair, it lasts until the entry ages out at
`MaxLogRetention` (24h) or an operator tombstones the row.

Before this note the docs said the collision "does not auto-resolve". That was
wrong whenever anti-entropy runs. The section was rewritten when this note was
added.

Observable symptoms (runbook in [diagnostics.md](../diagnostics.md#registry-credentials-a-concurrent-login-collision)):

- the replicator logs `apply failed — back-pressuring replication` with a
  `UNIQUE constraint failed: registry_credentials.scope, …` error;
- `litevirt_replication_peer_pending_entries` rises for the A→B pair until the next
  sensitive anti-entropy cycle has merged.

**Reproduction.** `TestRegistryLegacyConcurrentLogin_StallsUntilSensitiveAE`
(`internal/corrosion/registry_creds_test.go`) seeds both nodes and exchanges the
two legacy batches through `ApplyRemoteMutations`. It asserts both rows of the
table above. It then merges A's sensitive dump into B and asserts that the held
entry applies. It was added with this note. Before it, no test reproduced the
legacy collision; the H2 tests covered only the canonical side
(`TestRegistryCanonical_ConcurrentConverges`, since removed). Mutation checks:
with `idx_registry_creds_triple` dropped from the schema the back-pressure
assertion fails, and without the sensitive merge the recovery assertion fails.
Recovery is proven at the merge level only. A `tests/fleet/` test driving the real
anti-entropy loop is still missing (§5).

**How often.** It needs two writes of the same triple on two different nodes
inside one replication window. We have no field data. The back-pressure log line
is the only signal, and nothing counts collisions separately. Reasoning about the
triggers:

- interactive use is unlikely to hit it: one person rarely logs in to the same
  registry from two nodes within milliseconds;
- automation that fans out to every node is the likely trigger, for example
  configuration management running `lv registry add --global` against each host
  instead of against one endpoint;
- a partition widens the window to the length of the partition. Any write of
  the same triple on both sides collides when the partition heals.

It is rare, and the cost when it happens is a bounded stall of one peer stream.
That is a weaker case for the activation contract below than the earlier docs
made. §6 asks whether the contract is worth building at all.

## 2. What was built, what was removed, and why

The "Part H2" work arrived in `e365827c` (colonelpanik/litevirt#118, "Fail-closed
corrosion replication apply-safety"), a squash merge first released in v1.4.0.
Its H2 sub-commits, in order:

1. *Part H2 expand — deterministic-id registry credential writer*;
2. *Part H2 expand — converge created_at, gate + verify the canonical shape*;
3. *Part H2 converge — legacy-row consolidation + apply/writer gate split*;
4. *Part H2 converge — race-safe writer + consolidation, split readiness*;
5. *Part H2 converge — full-content CAS keeps equal-ts conflicts fail-closed*;
6. *Part H2 — advertise + latch canonical_registry_v1 (accept gate)*;
7. *Part H2 — registry migration controller*, then *machine-checked writer
   activation (phase-2 latch) + legacy reject*, then *one state machine — freeze,
   drain, irreversible*;
8. *defer H2 writer activation — ship the reversible core only*, which removed 7;
9. *reduce H2 to honest preparatory infrastructure*, which removed the controller
   and the writer abstraction;
10. *durable canonical-registry latch*, which moved acceptance onto `DurablyLatched`.

What shipped from v1.4.0 through v1.9.0:

- `RegistryCredentialID`, the frozen derivation (`credential/v1` domain tag,
  length-prefixed fields, SHA-256, v8 UUID);
- `UpsertRegistryCredentialCanonical`, a canonical writer with **no production caller**;
- `ConsolidateRegistryCredentials`, an idempotent legacy-to-canonical migration
  with no caller, that refused to run unless the token had latched;
- `RegistryWriterReady` / `RegistryContractReady`, readiness reads with no caller;
- `enforcement.canonical_registry`, a flag whose only effect was to **advertise**
  `canonical_registry_v1`;
- once that token was **durably** latched, the `DispReject → DispCanonicalRegistry`
  ledger promotion: receivers **accepted** the canonical upsert, after checking
  that its id matched its triple.

**Why remove it.** A latch is durable and one-way. The marker survives restarts,
it does not reopen, and rolling a binary back below it quarantines the node. This
latch did not protect anything. Nothing wrote the shape it accepted, so the only
change a latched cluster saw was a new way for a peer to inject rows. Its meaning
was also wrong for the real feature. It said "accept canonical rows" when the
activation needs "every node is frozen, drained, consolidated and switched". A
cluster that latched it would come up pre-latched for whatever the name meant
later. Turning the flag on was a permanent commitment to an unfinished design.

**Removed** in `c6d990d1` (*chore(capabilities): retire the canonical_registry
opt-in until its writer ships*, 2026-10-04):

- the `enforcement.canonical_registry` config field and its docs;
- `Server.SetCanonicalRegistryEnforce` / `enfCanonicalRegistry`, the advertisement
  filter and the `tokenEnabled` case;
- `canonical_registry_v1` from `capabilities.Supported()` and `capabilities.All()`;
- `Client.SetCanonicalRegistryAccept`, the `capabilityActive` case, the daemon wiring,
  `DispCanonicalRegistry` and `Replicator.applyCanonicalRegistry`;
- `UpsertRegistryCredentialCanonical` and `ConsolidateRegistryCredentials`. Each
  was useful only alongside the accept path. With that path gone, every peer
  refuses their output, so any future caller would stall the cluster's streams.

**Kept:**

- `RegistryCredentialID` and its frozen-encoding tests. It is pure and needs no
  latch, and it is the one part of the design that must not change before the
  writer ships;
- `registryCanonicalUpsertSQL`, registered as **plain `DispReject`** with no
  capability gate. It is listed with consolidation's by-id tombstone in the
  `canonical_registry_v1_retired` historical family, so retiring it removed nothing
  from the ledger. Every node on this build refuses the shape, whatever marker it holds;
- `RegistryWriterReady` / `RegistryContractReady`. These are local reads with no
  latch, and they encode the two readiness predicates §4 uses. Their test no longer
  depends on consolidation.

### Retiring the token without stranding a cluster

`preflightCapabilityRollback` WAL-quarantines a node that finds a durable marker
for a token its binary does not know, because that is how a rollback looks. If
the name had simply been deleted, every cluster that latched
`canonical_registry_v1` would have been quarantined on upgrade. So the
capabilities package now has a **retired** set (`capabilities.Retired`,
`capabilities.RetiredCanonicalRegistryV1`):

- retired tokens are not in `All()`, so the checker never loads their markers and
  nothing reads them as latched; they are not in `Supported()`, so nothing
  advertises, drives or reports them;
- the preflight treats a retired marker as known: it logs the marker and does not
  quarantine;
- the marker is left in place. It is still evidence that the node ran as a member
  (the founder-marker check relies on that), and a binary rolled back to v1.9.0
  reads it as it always did;
- names in the set are never removed and never reused.

`TestPreflightCapabilityRollback_RetiredTokenIsNotARollback`
(`internal/daemon/rollback_detect_test.go`) writes the marker by its on-disk name
and asserts no quarantine, and that a genuine unknown marker beside it is still
flagged. It failed against the naive deletion before the retired set existed.
`TestCanonicalRegistryV1Retired` and
`TestCanonicalRegistry_RetiredIsNeverAdvertisedOrDriven` pin the rest.

**Canonical rows already applied** stay valid. A canonical row is an ordinary
`registry_credentials` row whose id happens to be `RegistryCredentialID(triple)`.
The resolver and list return it, the legacy writer tombstones it by triple like
any live row, revoke removes it, and a replicated legacy login converges over it.
`TestRegistryCanonicalRows_StayValidForTheLegacyPaths` covers all of this. Nothing
has to be migrated. In practice no production path ever wrote such a row.

**Upgrading a cluster that latched it.** During the roll, an old-build node with
`enforcement.canonical_registry: true` and the latch will see upgraded peers stop
advertising the token, and will raise `ha_degraded` (`unsupported_member`) until it
is upgraded too. Set the flag to `false` on the old nodes before rolling. That
turns off their `tokenEnabled` and silences the alarm. Nothing else changes,
because nothing emits the canonical shape. The lab never enabled it (no config
key, no marker).

## 3. Which token ships the feature

**A fresh token, `canonical_registry_v2`.** Do not reuse `canonical_registry_v1`:

- clusters may already hold its marker. Reusing the name would make them come up
  pre-latched for the new contract without having gone through it;
- v1.4.0–v1.9.0 binaries advertise the v1 name (flag on) with accept-only
  semantics. In a mixed-version cluster the reused name could latch across nodes
  that do not implement the freeze, the barrier or legacy rejection;
- the retired set's rule is that a retired name is never reused.

v2 should be **advertised on the strength of the build** and **replication-gated**
(`capabilities.replicationGated`). It states a fact about the binary: this build
accepts the canonical shape, honours the freeze, and rejects the legacy shape
once activation is recorded. Every replication recipient must be able to do that,
including a maintenance host on the previous build. It should **not** be the
opt-in. The opt-in is the operator running the activation, recorded as a
replicated row. That is the `failover_scope_v1` pattern, where the token is the
capability and the row is the decision. It avoids a flag that only advertises,
which is the mistake this note retires.

## 4. The activation contract

Activation is **one operator-run operation**: a single command (name to be
decided), run once per cluster, which either completes every step or leaves the
cluster on the legacy writer. It is not a config boolean. Readiness is evaluated
synchronously at each step and never read from a cache. The command holds a
leader lease (`corrosion.AcquireLeaseWithTerm`, key `registry_canonical`) for its
whole run, so two coordinators cannot interleave.

State lives in a new replicated single-row table, `registry_migration(id,
state, epoch, participants, barrier, updated_at)`. `state` is one of
`legacy → freezing → consolidated → canonical`, plus `aborted`. Every transition is
an LWW write by the coordinator. Its statement shapes are new, so they need the
first-replicated-shape decision `stmtshapecheck`'s `newtables.go` asks for. v2
being latched is what keeps those shapes off an older peer's stream.

### Step 0 — preconditions (refuse, change nothing)

- `canonical_registry_v2` is **durably** latched on the coordinator. Because the
  token is replication-gated, this means every memberlist member runs a v2 build;
- the **participant set** is every host that is not decommissioned, voters,
  witnesses and maintenance hosts included. Every participant is reachable over
  peer gRPC, not WAL-quarantined, not isolated, and reports v2 latched;
- the voter majority is reachable (no `no_quorum` gate);
- no peer stream is held on a registry-credential entry
  (`litevirt_replication_peer_pending_entries` is flat for every pair). Step 2
  proves this anyway; checking first gives a better error message.

*Mixed version:* an older-build member keeps v2 unlatched, so the command refuses.
*Rollback:* none needed.

### Step 1 — writer freeze

The coordinator writes `state=freezing, epoch=N, participants=[…]`. A node that
has applied it refuses every registry-credential write (create, rotate and revoke)
with `Unavailable` (retryable). Freezing revoke too means no tombstone can race
the barrier. Each participant then answers a `RegistryFreezeAck(N)` RPC with the
`seq` of its own mutation-log head **after** it applied the freeze. That head is
its **barrier seq**. No legacy registry write from that node can come after it.

*Mixed version:* every participant runs v2 (step 0), so every participant honours
the freeze. *Rollback:* write `state=aborted`; nodes lift the freeze. Nothing else
has changed.

### Step 2 — durable barrier / watermark proof

For every ordered pair of participants (origin, receiver), the receiver's
persisted `mutation_seen` watermark for that origin must be **≥** the origin's
barrier seq. The coordinator collects this matrix over RPC and retries until it
holds or a deadline expires. The watermark is the durable record that the
receiver has *applied*, not just received, everything the origin logged up to the
freeze. So every pre-freeze legacy registry entry has been applied on every
participant, and no relay or mutation log still holds one that could arrive later.

A held collision (§1) keeps its receiver's watermark below the barrier, so the
proof waits, and fails at the deadline, instead of hiding it. The command reports
the pair and points at the runbook. The next sensitive anti-entropy cycle normally
clears it, before the deadline.

*Mixed version:* not reachable (step 0). *Rollback:* abort as in step 1.

### Step 3 — consolidation

Only the coordinator writes. Every participant now holds the same live row per
triple (frozen and drained), so one writer is enough and its result is
deterministic. For each triple whose live row is not canonical, it sends one batch:
a full-content-CAS tombstone of that exact legacy row by id, plus the canonical
upsert carrying the legacy content (`created_at` kept, the legacy `updated_at`
carried). This is the old `ConsolidateRegistryCredentials` algorithm, which is in
git history. Then it writes `state=consolidated` and repeats the step 2 barrier
against the coordinator's new head.

Receivers **accept** the canonical upsert only while v2 is durably latched **and**
their local `registry_migration` state is `consolidated` or later, or the incoming
batch is the coordinator's consolidation for the current epoch. Acceptance still
checks `id == RegistryCredentialID(scope, owner, registry)`. Without that check,
an approved shape carrying the wrong id could take over another credential's row
through `ON CONFLICT(id)`.

*Rollback:* abort. Canonical rows are valid rows for the legacy writer and
reader (§2), so an abort here needs no data change.

### Step 4 — convergence proof

Every participant returns `RegistryWriterReady == true` (no non-canonical live
row) and a keyed HMAC digest of its live `registry_credentials` rows (id, triple,
username, secret, created_at, updated_at), computed under the sensitive lane's
per-scan key. All digests must be equal. Any difference aborts. A difference here
means something wrote around the freeze, which is a bug to investigate, not
something to retry past.

### Step 5 — writer switch and legacy-shape rejection

The coordinator writes `state=canonical, epoch=N`. On applying it, a node:

- routes every registry write through the canonical writer, a LWW-guarded upsert
  on the deterministic PK;
- **rejects** the legacy INSERT shape (`registryLegacyInsertSQL`) on the WAL path.
  Its ledger entry becomes capability-gated on the activation state:
  `DispPlainInsert` before, `DispReject` after;
- rejects a **live** non-canonical credential arriving over the sensitive
  anti-entropy lane (keep-local, counted). Tombstones still merge, so revokes
  still converge;
- lifts the freeze.

A node that has not applied the row yet is still frozen, so it writes nothing. A
canonical write from a switched node reaching an unswitched one is accepted, per
step 3. No order of delivery lets a legacy write follow a canonical one.

*Rollback after activation:* a separate operator operation that runs steps 1
and 2 and then writes `state=legacy`. No data has to change. The binary cannot
go below v2 once v2 has latched, as with every token: the rollback preflight
quarantines the node.

### Step 6 — node admission and reseed

- **A host added after activation** (`lv host add`) is seeded from a peer snapshot.
  It gets the canonical rows and the `canonical` state, and admission refuses a
  host that does not advertise v2.
- **A participant restored from a pre-activation backup** has a `state.db` that
  does not record activation. Its mutation log may also hold legacy entries no
  peer has seen. On activation every participant writes a durable local marker
  (`registry_canonical.<epoch>` in `data_dir`). A node that starts with the marker
  but without the `canonical` row enters WAL quarantine until it is reseeded. This
  reuses the rollback-preflight mechanism.
- **A host that was not a participant** cannot rejoin in the presence of a
  `canonical` state without a reseed. It was decommissioned, because step 0
  requires every non-decommissioned host. Peers refuse its WAL until it is reseeded.

### Step 7 — index contract (separate, later, the only irreversible step)

Once every participant reports `RegistryContractReady` (no non-canonical physical
row, live or tombstoned), a schema migration replaces the partial index with
`UNIQUE(scope, owner, registry)`. This waits until the watermark-safe GC has
reclaimed the legacy tombstones. The step is defense in depth. The deterministic
PK already guarantees one row per triple after step 5. It is a schema bump, it
cannot be undone by a binary rollback, and it ships in a later release than
steps 0–6.

## 5. Tests that must exist before it ships

Each one mutation-verified (break the property, watch it fail, restore):

- **the baseline fleet test, first** (`tests/fleet/`): concurrent `lv registry add`
  of one triple on two nodes today, through the real anti-entropy loop, measuring
  how long the stream stays held. This replaces the merge-level evidence in §1, and
  its result decides whether the rest of this list is worth building;
- **the headline fleet test**: three nodes, concurrent `lv registry add` of one
  triple on every node *after* activation. All nodes converge to one row and no
  stream back-pressures at all. This is the canonical counterpart of
  `TestRegistryLegacyConcurrentLogin_StallsUntilSensitiveAE`;
- a fleet test of the whole operation from a cluster holding legacy rows,
  collisions already remediated, through step 5, asserting identical rows and
  digests on every node;
- step 0 refuses with an older-build member, with a maintenance member on the old
  build, with an unreachable participant, and with a quarantined node;
- writes refused during the freeze, revoke included, on every node;
- the barrier proof fails while a legacy collision is held (the §1 scenario),
  and passes once anti-entropy or the runbook has cleared it;
- convergence proof aborts on a digest mismatch;
- receivers refuse the canonical upsert before v2 latches, refuse a mismatched
  id after it, and refuse the legacy INSERT only after `canonical`;
- post-activation sensitive-AE merge rejects a stale live legacy row and still
  merges a tombstone;
- abort at each of steps 1–4 leaves a cluster on the legacy writer with readable
  rows, and the deactivate operation round-trips after step 5;
- a node restored from a pre-activation backup is quarantined; a new host is
  seeded correctly; a non-participant cannot rejoin unreseeded;
- a node holding only the retired `canonical_registry_v1` marker is not latched
  for v2;
- `RegistryCredentialID` frozen vectors (already present:
  `TestRegistryCredentialID_Frozen`, `_LengthPrefixed`, `_NoLowercasing`);
- an e2e run on the lab cluster (`tests/e2e/`) covering the operation and
  post-activation concurrent logins, checked against each node's database rather
  than through litevirt alone.

## 6. Open questions

- **Is the contract worth building?** §1 found that the collision clears itself
  within one sensitive anti-entropy cycle. What remains is a bounded head-of-line
  stall plus an error log line. A cheaper option is to make the WAL apply treat this
  one collision as a no-op when the receiver's live row for the triple is newer than
  the incoming INSERT. That decision is local and deterministic, and it needs no
  writer switch, freeze or migration. Measure the stall on a fleet (§5) before
  choosing.
- **Or reuse identity resolution?** `canonical_identity_v1` already resolves
  natural-key collisions for `snapshots` / `container_snapshots` on the receiver,
  by re-keying to a deterministic winner (`internal/corrosion/identity.go`).
  Adding `registry_credentials` to `tableIdentityKeys` might clear the held
  entry with no writer switch, freeze or migration. The partial-on-live index and the tombstone+insert
  batch shape are the parts that need checking.
- Should the freeze carry a deadline after which the coordinator aborts by
  itself, so a coordinator that crashes mid-freeze does not leave writes frozen
  until an operator notices? Lease expiry is the natural trigger.
- Should the participant set include decommissioned-but-reachable hosts, or is
  "not decommissioned" enough?
- On rotate, should `created_at` be preserved (the old writer's choice) or reset?
  It affects nothing but display, and it has to be decided before the canonical
  upsert shape is frozen again.
- Should the new writer reuse `registryCanonicalUpsertSQL` exactly, so the existing
  `DispReject` entry turns into the gated entry, or use a fresh shape? Reusing it
  means a v1.9.0 receiver still refuses it, which is the fail-closed answer, but
  ties the new design to the old full-image SET.
- Is step 7 worth a schema bump at all, given step 5 already makes duplicates
  impossible by construction?
