# Cluster diagnostics

Tools for inspecting and repairing cluster-state health. The **divergence
scanner** (`lv doctor divergence`) is strictly read-only — it never writes or
merges state. **Repair commands** under `lv doctor` (e.g. `repair-owner`,
below) are intentionally mutating and audited; each is called out as such.

## Operation recovery (`lv operation`)

Each mutating VM operation holds a per-VM **mutation barrier**
(`active_operation_id`); other mutations defer while it is set. A crash mid-
operation is normally cleared by the owner's startup recovery, but a wedged
operation can be inspected and force-cleared manually:

```
lv operation show <vm>            # inspect the operation holding the barrier + its steps
lv operation abort <vm> --force   # force-clear the barrier so the VM is mutable again
lv operation abort <vm> --operation <id> --force   # the same, only if <id> is the active operation
lv operation release-reservation <operation-id> --force   # release a host reservation no running operation holds
```

`show` is read-only. `abort` is admin-only, requires `--force`, is audited, and
clears the barrier only via the exact owner-epoch + spec-generation
compare-and-swap — so it can never clear a newer operation's barrier, and an
ordinary mutation's `--force` never bypasses the barrier. Without
`--operation`, `abort` clears whichever operation is active when it runs;
with `--operation <id>` it is refused unless `<id>` is that operation, so an
operation that finished, or one that began, after you ran `show` is never
the one cleared. A daemon too old to honour `--operation` is refused before
anything is sent. The commands act on the host the CLI targets (`LV_HOST`).

## Host reservations

Admission counts every in-flight capacity claim against its target host until
the operation that made it is terminal at its header's owner epoch. A claim
left counted after its operation stopped running shrinks the host's free
capacity until it is released.

`lv host inspect <host>` lists them under `reservations`, and reports their sum
as `reservedCpu` and `reservedMemMib`: the figures admission subtracts from the
host's free capacity. A reservation whose data cannot be read is left out of
the list and named in `reservationsError`, and `reservationsPartial` is then
true: the reserved figures count only the listed reservations. `lv host inspect`
prints it as a warning on stderr, and the rest of the host is still shown.
`reservationsError` gives the reason only to a caller who may `vm.read` across
the cluster; anyone else sees the operation ids, and the daemon log has the
reason. Each row carries the operation id, the RPC that made it
(`method`), `kind`, the vCPU and MiB it holds, its age, its header owner epoch,
a `state` and a one-sentence `detail`. The `vm` and `project` fields, and the
workload name in `detail`, are shown only to a caller who may `vm.read` that
workload; the amounts and state are shown to every viewer.

| `state` | meaning | released by |
|---|---|---|
| `in-flight` | the VM's or container's mutation barrier names the operation | the operation, when it finishes |
| `admitting` | younger than 15 minutes, no barrier: an admission that may still be committing | the operation |
| `auto-expires` | an admission lease (`kind` `admission-lease`, or `transfer-lease` for a migration or drain); `detail` names the expiry instant | the stale-lease sweep: 15 minutes after creation, 6 hours for a transfer lease. A live migration of a Secure Boot / vTPM VM whose source daemon died holding its transfer lease has it released by that daemon's recovery of the move, once it restarts |
| `journal` | a `vm_replace` or `drain_cold_move` journal | its own recovery; never released by hand |
| `releasable` | the operation finished at a later owner epoch than its header's, or the VM it was for no longer exists (or was re-created after it began) | the reservation sweep on the target host |
| `stale` | no barrier, past the admission window, and nothing proves the operation finished | `lv operation release-reservation <operation-id> --force` |
| `release-blocked` | a `releasable` or `stale` reservation whose release key is held by a tombstoned release row (`releaseBlocked` is true; `detail` starts `still counted; release blocked:`). A reservation in any other state keeps that state, with `releaseBlocked` true | `lv operation release-reservation <operation-id> --force`, which writes a `failed` step at the header owner epoch instead |

The reservation sweep runs on every host, once at startup after resize
recovery and then every 60 seconds. It releases each `releasable` reservation
targeting that host within 60 seconds of the evidence reaching it, by writing a
`cancelled` step at the operation's header owner epoch. A finished operation
whose target host has been removed or is not active is released by the
lexically smallest active host instead; a reservation for a VM that no longer
exists is released only by its target host. The sweep releases nothing while
the host's replica has not caught up, and skips a VM whose lock is held until
the next pass. A reservation whose data cannot be read is never released; the
sweep logs `reservation sweep: a reservation could not be read` once per
operation and goes on with the rest.

`lv host inspect` prints a note on stderr when the host holds `stale` or
`release-blocked` reservations.

### Releasing a reservation by hand

```
lv operation release-reservation <operation-id> --force
```

It releases the reservation of an operation that is no longer running: a
`stale`, `release-blocked` or `releasable` one. The release is decided on the
reservation's target host, under the VM's (or container's) lock there, so a
request to another node is forwarded to that host; a target host that has been
removed (`lv host rm`) is decided on the node called. It needs the
`host.reservation.release` permission (built-in Admin) and `--force`, and every
request, released or refused, is audited once, as
`operation.reservation.release`, on the node called. Asking again for a
reservation already released answers `already released`. A refusal names the
VM or container only to a caller who may `vm.read` it.

| Refusal | Code |
|---|---|
| No `--force` | `FailedPrecondition` |
| No such operation, or it was reaped | `NotFound` |
| The operation holds no counted reservation | `FailedPrecondition` |
| The operation's reservation data cannot be read | `FailedPrecondition` |
| A `vm_replace` or `drain_cold_move` journal | `InvalidArgument` |
| An admission or transfer lease; the message names the instant the stale-lease sweep releases it | `FailedPrecondition` |
| The operation holds the VM's or container's mutation barrier | `FailedPrecondition` |
| Younger than 15 minutes with no barrier: it may still be admitting | `FailedPrecondition` |
| The VM's or container's lock is held on the target host | `Unavailable` |
| The target host's replica has not caught up | `Unavailable` |
| The target host is unreachable, or refused the request before handling it (a forwarded login it has not replicated yet, or WAL quarantine) | `Unavailable` |
| The same, for a finished operation (`releasable`, not `release-blocked`) on a fenced, offline or maintenance host: the message says the sweep's deputy releases it within a pass | `Unavailable` |
| The target host runs a build without the release (`lv host upgrade <host>`) | `FailedPrecondition` |

## `hardware_v2` — typed hardware, with no kill switch of its own

`hardware_v2` makes the typed hardware tables (disks, NICs, PCI intents) the
source of truth instead of the free-form VM spec, and unlocks hardware mutation
on a **stopped** VM. Until it activates, attaching a PCI device to a VM that
isn't running is refused outright:

```
Error: stopped-VM PCI attach for "web" is not available until hardware_v2 is active
```

Every other token in the split-brain/hardening family is gated on an
`enforcement.*` flag you set fleet-uniformly (see docs/configuration.md).
`hardware_v2` is the exception: it has **no flag of its own** and activates on
its own once both conditions hold on every voting-eligible host —

1. **`operation_protocol_v1` is latched.** Hardware mutations need the crash-safe
   operation journal, so it is a hard prerequisite. That token *does* have a
   flag — `enforcement.operation_protocol` — which is where an operator controls
   `hardware_v2` indirectly.
2. **The node's startup hardware audit has finished.** Each daemon populates the
   typed tables from every VM's persistent domain definition at boot, and
   withholds `hardware_v2` from the capabilities it advertises until that pass
   completes. A node that advertised earlier could let the fleet latch — and stop
   maintaining the legacy spec mirror — while its own tables were still empty, so
   a peer would read hardware that isn't there. The audit itself waits for the
   node's replica to catch up with the cluster (its first completed anti-entropy
   exchange, logged as `replica caught up`): it writes rows for the VMs the node
   believes it owns, and a node back from a fence still believes it owns the VMs
   failover moved away. Until then the log says `hardware backfill deferred`.

One node still working through its backfill therefore holds the entire cluster
at pre-latch behavior. That is intended. Like the rest of the family the latch is
monotone and durable: once formed it survives a restart and does not re-open if a
peer later becomes unreachable.

Use `lv hardware-ls <vm>` to see a VM's typed hardware.

### Adoption state and blocked VMs

The audit classifies each VM as it goes. A VM whose hardware it cannot reconcile
— no readable persistent definition, or a PCI device set it cannot attribute
unambiguously — is recorded **blocked** with a reason rather than adopted.

Before the latch that verdict is informational and gates nothing. Once
`hardware_v2` is latched, a blocked VM refuses hardware mutation **and refuses to
start** until it is repaired and re-audited, failing with the recorded reason.

To clear it: fix the underlying definition or device problem, then restart the
daemon on the VM's host. The audit pass runs at startup, and a VM that now
reconciles is adopted on that pass.

## `lv doctor divergence`

Read-only.



Scans every active node and reports replicated rows that **disagree across nodes**,
plus cluster-wide **semantic-invariant violations**. This is the pre-remediation
evidence-capture step for the equal-timestamp last-writer-wins repair: run it
*before* any change to merge behavior, because convergence destroys the per-node
evidence.

```
lv doctor divergence [--json] [--table <name>]... [--include-sensitive]
```

Admin-only. The daemon you call fans out to every active peer (over peer mTLS),
compares per-row metadata, and returns a classified report.

### What it detects

**Diverging rows** — for each primary key, how the row differs across nodes:

| Class | Meaning |
|---|---|
| `equal_updated_at_different_content` | Same PK, **same `updated_at`** on every node, different content — the pathological LWW tie that never re-converges. |
| `stuck_different` | Different `updated_at` that **persisted across both samples** — a converged-wrong or lost-write split. |
| `different_updated_at` | (Transient) usually in-flight replication; only reported as `stuck_different` if it survives resampling. |
| `missing_row` | Present on some nodes, absent on others. |
| `tombstone_vs_live` | Tombstoned (soft-deleted) on some nodes, live on others. |
| `terminal_vs_live` | A workload terminal (stopped/error) on some nodes, running on others. |
| `schema_shape_mismatch` | The table's column **set** differs across nodes (a missing or extra column). Column *order* alone is ignored — a fresh `CREATE TABLE` vs an upgraded `ALTER ADD COLUMN` does not trip this. |
| `acknowledged_tie` | **Not a divergence.** A contested row that every host holding it has acknowledged (`lv cluster acknowledge-lease-term`), in a table where nothing else differs. Listed separately, under *Acknowledged ties*, because both claims are kept as evidence; a scan that finds only these reads `no divergence detected.` |

**Acknowledged ties.** A `leader_lease_terms` row is immutable, so a contested
term never stops differing, even after an operator has acknowledged it. The
scan decides whether a row is an acknowledged tie from every host's
verification digest, by the same rule as `lv cluster converge` uses for
`ACKNOWLEDGED` (see
[operating-model.md](operating-model.md#clearing-the-condition-once-you-have-seen-it)):
every host acknowledged every tie it tracks in the table, and every host's
residual digest agrees. Anything short of that keeps the row's class:

- acknowledged on **some** hosts only: the row stays a divergence, and its line
  ends `(tie not acknowledged on <hosts>)`, naming the hosts still to
  acknowledge. A host that cannot vouch for the table is named here too: one
  that tracks no tie in it at all (a rebuilt host with an empty acknowledgement
  table), one that supplied no residual digest, or one whose digest could not
  be read;
- acknowledged on **every** host, but the residuals disagree: the row stays a
  divergence and its line ends `(tie acknowledged on every host, but the table
  differs elsewhere)`, because another row of the table differs as well.

The evidence is per host and per table, not per row: a host "has acknowledged"
when every tie it tracks in that table is acknowledged. In `--json`, the
`tie_acknowledged_on` and `tie_unacknowledged_on` fields of a row carry the
split; both are empty on a row of a table where no host acknowledged anything.

A divergence is reported **only when it persists across two samples** with
unchanged per-node content hashes — an in-flight replication delta changes between
samples and is filtered out.

**Semantic-invariant violations** — states that survive convergence (every node
holds the *same* rows, digests match, a dump-diff is clean) yet are *jointly*
illegal:

- `duplicate_live_container` — the same container name live on more than one host
  (a cross-host ownership split the per-row resolver structurally can't see).
- `duplicate_ip_owner` — one IP owned by more than one workload. Owner identity is
  fully qualified (`vm:<name>`, `ct:<host>:<name>` with `owner_kind`/`owner_host`),
  so two same-named containers on different hosts are never collapsed into one
  owner.

> **Not yet covered (deferred to a later phase):** *duplicate runtime ownership*
> and *runtime-vs-DB owner mismatch* — i.e. the DB rows have converged but disagree
> with which host actually runs the workload. Detecting those requires per-host
> runtime introspection (the peer-only `GetRuntimeInventory`), which lands with
> the runtime-repair phases; until then `lv doctor divergence` checks only the
> DB-level invariants above. A clean report does **not** yet prove the DB agrees
> with runtime truth.

### Remediating a persistent `schema_shape_mismatch`

`schema_shape_mismatch` fires only on a real column-**set** difference, not a pure
column reorder. A genuine mismatch means one node's table was created with a
different column set than another's — usually an interrupted or skipped migration.
The scanner is read-only; clearing it is a one-time, **quiesced**, per-node
operation on the offending node:

1. **Make it safe.** Move any workload the table backs off the node (e.g. relocate
   the load balancer / VIP) so the node can be taken out of service.
2. **Stop the daemon** and take a **SQLite-consistent backup** (the `.backup` API,
   or copy the DB after a WAL checkpoint, including the `-wal`/`-shm` files).
3. In a `BEGIN IMMEDIATE` transaction, **recreate the table from the canonical
   schema of the node's current version**, copy and validate rows, drop/rename,
   then **recreate named indexes and triggers** (they don't survive the drop).
4. **Validate structurally** with pragmas — `foreign_key_check`, `integrity_check`,
   `table_info`, `index_list`/`index_xinfo`, `foreign_key_list`, triggers,
   constraints/defaults/collations, table options (`STRICT`/`WITHOUT ROWID`), and
   `user_version` — compared against a known-good node (not raw `sqlite_master`
   text). `COMMIT`.
5. **Restart**, run `foreign_key_check` again after reopening, then confirm the
   workload listing is unchanged and `lv doctor divergence` (and the cluster
   digest) have converged.

> A pure column-order skew classifies as
> row-content divergence when the positional (v1) digest is in force. The
> order-invariant **digest_v2** (below, on by default) makes that skew hash
> identically across nodes, preventing the recurrence entirely — leave it on
> fleet-wide instead of repeatedly running the data remediation above for a
> column-order-only skew.

### `digest_v2` — the order-invariant table/row digest

The positional (v1) content digest hashes each row's cell **values in physical column
order**, so a fresh `CREATE TABLE` node and an `ALTER ADD COLUMN`-upgraded node
compute different table/row hashes for logically identical data. That is not a
corner case: a node founded at an older schema holds every later ALTER's column
after `deleted_at`, while a fresh node holds it where `CREATE TABLE` declares it,
and no single `CREATE TABLE` order matches every founding version. `hosts`, `vms`,
`vm_interfaces`, `snapshots`, `lb_configs`, `users`, `tokens`, `ip_allocations`,
`containers`, `host_pci_devices` and (for a database created by an early v51
build) `netbox_bindings` all depend on the founding version. The merge is
column-**name**-safe, so this never corrupts data — but the hashes stay different
every cycle, causing perpetual no-op anti-entropy pulls and a standing
`lv doctor divergence` / `lv cluster digest` mismatch on the reordered tables.

**digest_v2** pairs each value with its column name, sorts by name, and hashes a
canonical, order-invariant encoding — so column order stops mattering. It is
negotiated **pairwise by field presence**: a node emits the v2 hash only when its
own `enforcement.digest_v2` flag is on (the default), and any two peers compare v2
**only when both supply it**, otherwise both compare v1. There is no capability
latch — the digest only *detects*, and each node compares independently, so a
non-uniform rollout only affects which node pulls, never data. The same rule
governs every place a digest is compared: anti-entropy and its bucket digests,
`lv cluster converge`, `lv doctor divergence`, and a reseed's convergence check. `lv cluster digest` /
`lv cluster converge` print a `VER` column showing which version was compared per
table.

**Rollout.** It is on by default, so upgrading is the activation: each upgraded
node emits v2, and each pair of upgraded nodes compares v2. While some nodes still
run an older build (which emits v1 only, since the flag defaulted off there), every
comparison involving one of them stays v1 — exactly the behavior before the
upgrade, so a column-order-only table may still read `DIVERGENT` (`VER v1`) in `lv
cluster converge` until the last node is upgraded. Then:

1. **Confirm** every node is upgraded (`lv host ls`) and none sets
   `enforcement.digest_v2: false`.
2. **Controlled resync** — `lv cluster converge --all` (one anti-entropy pass).
   Precise outcome:
   - Column-order-only tables **stop pulling** and read converged (`VER v2`).
   - Strictly-newer LWW drift **may** heal (normal LWW), as always.
   - Genuine **equal-timestamp safety faults still require explicit remediation** —
     LWW never auto-heals a tie. `lv doctor repair-owner` restamps **VM-owned rows
     only** (the `vms` table); other tables (e.g. `lb_configs`) need the quiesced
     table-remediation procedure above or a table-specific restamp — `repair-owner`
     cannot repair them, and `lv cluster converge` labels them accordingly.
   - **In-memory unresolved-tie records do not auto-clear** just because a table's
     v2 digest now matches; they clear on the next daemon restart. The one
     exception is `leader_lease_terms`, whose rows are immutable: a restart
     empties the register but the next anti-entropy pass re-registers the same
     tie, so that one needs `lv cluster acknowledge-lease-term` on each host.
     The acknowledgement is durable: after a restart the tie is re-registered
     as acknowledged. Once every host has acknowledged it and nothing else in
     the table differs, `lv cluster converge` lists the table as
     `ACKNOWLEDGED` and counts it as converged, and `lv doctor divergence`
     lists its rows as `acknowledged_tie` rather than as divergences. A new, unacknowledged claim
     for the term makes it a `SAFETY-FAULT` again — see
     [operating-model.md](operating-model.md#clearing-the-condition-once-you-have-seen-it).

Kill switch: set `enforcement.digest_v2: false` and restart to revert a node to
v1-only emission (peers then compare v1 against it). Because negotiation is by
field presence, a mixed fleet is always safe — never a spurious v1-vs-v2 mismatch.

### `canonical_identity` — natural-key identity resolution

A few tables mint a **random-UUID primary key** but carry a **UNIQUE natural key**:
`snapshots` (`vm_name`, `name`) and `container_snapshots` (`host_name`, `ct_name`,
`name`). Two nodes can independently create the *same logical object* — the same
snapshot name for the same VM — while each mints its **own** id. The replicated
rows then collide on the secondary UNIQUE, and the fail-closed apply path
**back-pressures** (keeps local, retries) rather than pick a winner, so the two ids
persist and `lv doctor divergence` reports the natural-key group as diverging.

With `enforcement.canonical_identity` enabled **and the `canonical_identity_v1`
token latched cluster-wide**, an upgraded receiver resolves these tables by their
**natural key**: it collapses each such pair to a single deterministic winner (newer
`updated_at` wins; on an **exact-instant tie** the smaller id wins **only if the two
rows' non-id content is provably equivalent** — a NULL is distinct from an empty
string, and equivalence requires a **complete** local-schema image, so under schema
skew an uncompared receiver-only column is treated as a fault, never assumed equal).
The collapse **re-keys the surviving row in place** — a single column-preserving
`UPDATE`, never a delete-then-insert — so receiver-only columns a newer-schema node
holds are **not** erased when an older-schema winner arrives. Because identity
resolution *mutates shared state* it is **not** negotiated pairwise like `digest_v2`,
and — like `operation_protocol` — the token is advertised only while the flag is on,
so the latch requires **config** uniformity: a partially-configured cluster stays
non-destructive (nodes not yet opted in keep back-pressuring) and converges once
every node has latched.

**Fail-closed guards** (nothing is silently discarded): an exact-instant tie whose
content is not provably equivalent is an **unresolved identity fault** — keep local,
remain divergent, and track it in `litevirt_lww_tie_unresolved_current`
(category `identity_content_conflict`, keyed by natural key) so it alerts. It clears
only on genuine convergence — a successful collapse/apply, or observing the same-id,
fully-equivalent converged row — never merely because a later observation was older.
A collapse also fails closed if the incoming id already belongs to a **different**
natural key locally (would destroy an unrelated row), or if an existing child
references the losing id (`snapshots.parent_id`, unused today, would be orphaned since
references are not rewritten). The tracker/alert side effects run only after the merge
transaction commits, so a rollback can't leave a stale fault or a false alert.

**Orphaned artifacts:** a collapse whose losing row referenced a **different physical
artifact** — a different `(host, path)` pair — leaves the losing file unreferenced.
The winner's pair is read back from the surviving row **after** the column-preserving
re-key, so a path column the sender omitted (schema skew) is correctly seen as
preserved-and-still-referenced, never falsely flagged. Orphaning covers a different
host (the whole losing snapshot is stranded) **and** a same-host path change (e.g. a
`vmstate_path`/`path` rewrite; because `host_name` is part of the `container_snapshots`
natural key, its collapses are always same-host, so a path change is the only way one
orphans a file). It is **not** auto-deleted — the losing id/host/path is logged (WARN,
after commit) and counted in `litevirt_identity_collapse_orphaned_total` so an operator
can reclaim the space.

**Scanner lane:** while it is active fleet-wide, `lv doctor divergence` keys these
tables by their natural key too, so a still-converging group shows as **one**
content divergence instead of two phantom `missing_row`s; a converged group reads
clean. The lane engages only when the scanning node has latched (uniform fleet).

**Activation**: ship the supporting binary everywhere (flag off,
behavior-neutral), confirm every node is upgraded, then set
`enforcement.canonical_identity: true` and rolling-restart. Existing divergent
pairs consolidate on the next anti-entropy pass (`lv cluster converge --all`) — no
separate data migration. Kill switch: set it `false` and restart (the node reverts
to back-pressuring the collision, still non-destructive).

#### A deleted name re-used: the tombstone yields

Deletes are soft, so a snapshot that is deleted and then re-created under the
same name is two rows of one natural key on every peer: the tombstone and the
new row. A build that minted a fresh id for the re-create shipped a row that
failed `UNIQUE(vm_name, name)` on every peer, which back-pressured the
origin's whole replication stream (lab 2, F-2). Two changes close it, neither
behind a token:

- **The origin re-uses the deleted row's id.** `InsertSnapshot` and
  `InsertContainerSnapshot` take the id of the row already held under the
  natural key (a caller-supplied id is used only when no row holds the name),
  and when that row is a tombstone they add the existing per-row-LWW delete
  shape with a NULL `deleted_at`, stamped after the insert. The lookup and the
  write are one guarded transaction. Every released receiver already applies
  both statements, so a mixed fleet receives the re-create as an ordinary
  newer write to the same row.
- **A receiver decides a collision with a tombstone.** On the WAL and on
  anti-entropy, when an incoming row's natural key is held here by a row with
  a *different* id and at least one of the two is a tombstone:

  | here | incoming | outcome |
  |---|---|---|
  | tombstone | strictly newer row | the tombstone yields: removed, the incoming row applies |
  | tombstone | older or equal-time live row | the incoming row is skipped: a newer delete of the name supersedes it (a delete wins an exact tie) |
  | tombstone | tombstone | the newer stays; an exact tie keeps the smaller id, so every node converges |
  | live row | older tombstone | the incoming tombstone is stale and is skipped |
  | live row | newer or equal-time tombstone | anti-entropy tombstones the row here in place, keeping its id and taking the tombstone's `deleted_at` and `updated_at`; the two tombstones are then settled as above. For a strictly newer tombstone this is the by-name delete's effect. At an exact tie the WAL keeps the live row and anti-entropy tombstones it; both converge |

  Two live rows under one name are `canonical_identity`'s decision and are
  never touched. A yield is refused — the apply then proceeds as before — when
  a child row references the tombstone, when the incoming id is already bound
  to another name, or when the incoming clock is future-skewed with the skew
  guard on. The in-place tombstone is likewise not decided for a future-skewed
  tombstone with the skew guard on. The yield and the incoming row's apply
  share a savepoint: if the incoming row does not land, the tombstone is put
  back. Logged at INFO as `a deleted row yielded its name to a newer row` or
  `skipped a row a newer delete of its name supersedes`, and at WARN as
  `anti-entropy: a newer delete of its name tombstoned the row here`. When
  that row recorded an artifact path (`vmstate_path`, or `path` for a
  container snapshot), the file stays on disk and is logged at WARN as
  `anti-entropy tombstoned a live row whose artifact is now unreferenced (not
  auto-deleted; needs cleanup)` with its host and path, and counted in
  `litevirt_identity_collapse_orphaned_total`.

This is what un-wedges a stream that already carries a fresh-id re-create: the
entry is still in the sender's log, and an upgraded receiver applies it on the
next push. It also matters with `canonical_identity` on: its WAL collapse
re-keys the losing row with a column-preserving `UPDATE`, and a replicated
`INSERT` does not carry `deleted_at`, so collapsing a tombstone into a
re-created row would leave that row deleted on every peer.

### `vm_replace` — `lv cutover`

`lv cutover` gives the `<vm>-next` replacement the name of the VM it replaces. That VM is
deleted first, and the delete is a **soft** delete, so its tombstone still occupies the
`vms.name` PRIMARY KEY — and every child table it tombstones holds its own composite key
the same way.

No pre-existing replicated statement shape makes that handover safe on a **receiver**.
Clearing the tombstone with a retention DELETE is applied unconditionally there, while the
write meant to replace the row is only last-writer-wins gated — so a delayed replay erases
a tombstone and puts nothing in its place. Moving it aside instead splits the handover into
two independently gated statements, and a receiver can commit one and skip the other,
leaving no row at the name, or moving a still-live VM aside when its own newer ownership
made the sender's delete decline there. Neither addresses the merge rules, which decide a
both-live conflict at the contested name on owner/generation authority alone: the replaced
VM has usually been running longer than its replacement, so its stale copy simply
overwrites it.

The transition therefore ships as **one receiver decision**: every statement in the batch
carries the same `workload_replace_v1` guard over both VMs' incarnations and authority, and
a receiver applies all of them or none. The row installed at the contested name keeps the
**replacement's** `created_at` — a delete is terminal only for its own incarnation, so a
delayed tombstone of the replaced VM must read as an older one — and carries authority
above **both** inputs.

**The cleanup is journaled.** The transition and the destruction of what the replaced VM
owned cannot be one commit: the destruction is filesystem and storage-driver work that has
to follow it, and the transition itself displaces the rows describing what to free — the
replaced VM's parent row, and any child row whose key the replacement claims. A crash in
between would leak its volumes with nothing left in the database naming them.

So a `vm_replace` operation records an immutable manifest — the replaced VM's disk records,
its firmware UUID and cloud-init ISO path, plus the replacement's spec and state — while
those rows are still intact, and the step that AUTHORIZES the destruction is written in the
same batch as the transition. Its phases are:

| step | meaning |
|---|---|
| — | before anything is torn down, the REPLACED VM's domain is verifiably removed from the contested name: stopped if active (a paused one included) and undefined, with absence confirmed. A name still held by a domain makes the replacement's definition there fail, because the UUID differs — and by then its disks would be gone. A failure here changes nothing. Only on the node the cutover RUNS on: a replaced VM hosted elsewhere is asked about instead, and only a complete survey reporting no domain at the name is accepted — a domain still defined there, an incomplete survey, or an unreachable or older peer all refuse, before the operation is even journaled. Absence that could not be established is not absence, and proceeding would hand the name and the address over while that guest was still using both. |
| `planned` | the manifest exists and **nothing** is authorized. A crash here is safe: the resources it names are still owned by a VM that still exists. |
| `desired_persisted` | the transition landed. Written in the same batch, so it cannot be observed without it. Its facts carry the **runtime intent** the transition committed to — the replacement's accepted state at that moment — which is what the handoff restores. |
| `released` | the replaced VM's IPAM addresses are given back — **after** the transition. Releasing first means a delete that then declines leaves a live VM whose address has already gone back to the pool, in the external IPAM too. Journaled because the release can fail on its remote half, and a best-effort attempt that did would strand the address under a cutover reporting success. The manifest carries each address's external object id **and the identity it was claimed under**, so a retry can finish a release whose local half already landed — and can prove first that it is finishing its own. Captured for every address the replaced VM holds, wherever that VM is hosted: leases are cluster-global, unlike the volumes and firmware beside them in the manifest. |
| `config_applied` | the replaced VM's resources are freed. This also **closes** the destruction phase — past it the replacement's own firmware has moved onto the contested name, so a repeated name-keyed wipe would destroy the replacement's state. |
| `journaled` | the replacement's exact domain definition is durably recorded, **before** anything undefines it. Without it a transient redefine failure leaves neither name defined and no way to obtain the XML again. |
| `stopped` | the replacement's domain is confirmed INACTIVE — via libvirt's own activity query, not the coarse state, which collapses paused, shut-off and pm-suspended into "stopped" and so cannot see that a PAUSED domain is active. Activity is re-checked before **every** undefine, including a retry that already has this phase recorded: the record is a statement about the past, and an external start or libvirt autostart can reactivate the domain in between. libvirt cannot rename a domain, and undefining an **active** one leaves it running as a *transient* domain still holding its UUID — after which defining that UUID under the contested name is refused. **Cutting over a running replacement therefore restarts it**; no libvirt operation moves a live domain to another name, and `lv cutover` says so before it starts. |
| `redefined` | the replacement's libvirt domain and firmware answer to the new name. The database transition does not do this, and a restart that finished only the destruction would leave a committed cutover with no domain at the name. |
| `completed` | appended only after **both** later phases have run. |

A restart resumes whichever phases are outstanding, from the manifest — never by
re-running the transition, and never by reading the reused name, which now belongs to the
replacement. Every runtime action checks the **recorded domain UUID** first, including the
already-done shortcut, and a read that merely FAILED is neither "ours" nor "absent" — only
a verified not-found is absence, so a transient libvirt error cannot authorize acting on a
name whose real occupant is unknown: the temporary name is free the moment the transition commits, so a
delayed recovery acting by name alone would undefine whatever VM has since taken it. The
desired runtime state is read from the database at the moment the handoff acts, so an
operator stop accepted mid-cutover is not undone by replaying a stale snapshot, and the
whole operation — handler and recovery alike — is serialized against lifecycle calls on
both names. A phase is recorded only when its step actually succeeded; a failed redefine or
start leaves it owed. A firmware VM's failure is surfaced in its `state_detail`,
never as `state=error` — operation failure and running intent are different facts, and
overwriting the state made the retry read the row as "not asked to run" and finish with the
VM shut off. For the same reason the running intent is taken from the JOURNAL rather than
the row: an unfinished handoff looks exactly like a VM that stopped out of band, so a
reconciler pass would otherwise sync it to `stopped` and erase the start still owed. Nor
from the manifest, which is older still — captured before the first attempt's teardown and
adopted verbatim by every retry, so a start the operator asked for between two attempts is
not in it; the manifest is the fallback only for an operation journaled before the intent
was recorded. Only an explicit operator stop overrides either, and the reconciler leaves a
VM with an owed handoff alone in the first place. That marker is never overwritten by failure
reporting either — it is the only override there is, so replacing it with diagnostic text
would let the next retry start a VM the operator stopped. A failure goes to the VM's event
feed and leaves the operation owed in the journal. The firmware file moves only while the temporary name is still the
replacement's, and the destination definition is derived independently of whether this
attempt performed that move, so a retry after a failed redefine does not point the VM at a
vars file that has already gone. The operation's identity includes the replacement's **incarnation**, not just
the two names: both are reused by the next deployment, and an identity built from names
alone collides with the previous cutover's header. A retry of the same cutover therefore
finds its own header and **adopts the manifest already journaled there** rather than taking
a second one. It has to: a manifest can only be captured while the replaced VM's rows are
intact, and an attempt retrying past its own teardown reads live-only rows that no longer
describe the VM it is finishing. Only the recorded owner **epoch** may not have moved —
every phase is keyed on it, and continuing at another one would write the authorization
where no resume can read it back. Name-keyed artifacts — the vars file and the cloud-init ISO — are deleted only while the
contested name still holds the incarnation this operation transitioned, judged from a read
that sees **tombstones** as well as live rows. A name that has since been deleted and
recreated belongs to a different VM, and so do its files — including when that newer VM was
itself deleted with its disks retained, which deliberately keeps its firmware and reads as
"nobody owns this name" to any live-only lookup. This operation's own tombstone still
counts as its own, so a cutover whose result was later deleted is still cleaned up. The
swtpm tree is keyed by the replaced VM's own UUID and is freed regardless. Destruction
exempts **no** VM from the
shared-reference check, because the temporary name is free and reusable — a VM created
after a crash can legitimately reference a captured volume. IPAM allocations move by their
own primary key and their **complete owner tuple** — `(owner_kind, owner_host, vm_name)`,
which is what stops a same-named container's address being taken by a VM cutover, and the guard carries a digest of the leases both
names hold: an address the receiver released and reallocated to an unrelated VM declines
the whole transition rather than being quietly taken. The release phase applies the same
rule to what it destroys. The allocation at that key is read **owner-blind**, because an
owner-scoped read answers a foreign live row and a genuinely absent one with the same
nothing — and those license opposite actions, since absence is what permits finishing a
remote delete alone. An allocation another workload now holds vetoes both halves, and is
left for the orphan sweep rather than retried, so it cannot wedge the phases behind it.
One that is still this operation's has to also carry the same MAC and back the **same
external object** the manifest captured — name, MAC and key agreeing prove nothing once
the contested name belongs to the replacement and the MAC may have been reused. A row that is already gone is
finished remotely only after the external object is read back **by identity** and still
answers to the one the replaced VM claimed it under: the object id is a name, not a claim,
and an address reallocated elsewhere keeps the id while the identity moves. That read is
also what makes the phase idempotent — an object that is no longer there reads as absent,
which is a completed release, so a crash between a successful delete and its record resumes
instead of retrying into a permanent not-found. A read that FAILS is neither, and leaves the
phase owed.

That is why `operation_protocol_v1` is a hard dependency and not merely a companion.

That is new receiver behaviour, which nothing in the historical ledger can retrofit onto an
older peer, so it is gated:

- **`enforcement.operation_protocol`** must be active too — the manifest lives in the
  operation journal. Cutover treats a missing journal as not-available, checked before any
  side effect.
- **`enforcement.vm_replace`** (config flag, default false) gates **advertisement** of
  `vm_replace_v1`, so the cluster-wide latch requires config uniformity rather than just a
  uniform build — the same rule as `operation_protocol`.
- **`lv cutover` REFUSES** while the flag is off or the token has not latched, and it
  refuses as its first act, before stopping a domain or writing to either VM. A cluster
  that has not opted in has a cutover that declines, not one that half-applies.
- A receiver that has not latched **rejects** the batch's statements rather than applying
  them under a disposition never designed for them, which is why the sender is gated too.

Rollout: upgrade every node (flag off, behavior-neutral — cutover simply refuses), then set
`enforcement.vm_replace: true` everywhere and rolling-restart; the latch closes once every
voting-eligible member advertises the token. Kill switch: set it `false` and restart;
cutover goes back to refusing. Acceptance of an already-emitted batch is NOT revoked by the flag — it reads the
durable latch, because a batch in flight must not become unacceptable across a restart.

### Registry credentials: a concurrent-login collision

Registry logins mint a **new random `id` per login** and write via a tombstone+insert
batch. When the same `(scope, owner, registry)` credential is written on two nodes before
either write reaches the other, there are two live ids for one triple, and they collide on
the partial `UNIQUE(scope,owner,registry)`. The **newer** login wins: its entry applies on
the older node. The **older** login's entry cannot apply on the newer node. Its by-triple
tombstone loses LWW, and its INSERT then hits the newer live row. The entry back-pressures
fail-closed, which holds that sender's stream to that peer. There is no corruption and
nothing is silently picked.

The stall normally clears by itself. The peer-only (sensitive) anti-entropy lane carries
the older node's copy of its own row, already tombstoned by the newer login, to the newer
node. Once that copy has arrived, the retried entry's INSERT is a last-writer-wins no-op,
and the stream resumes. One anti-entropy cycle is enough (`anti_entropy_interval_sec`, 60s
by default). `TestRegistryLegacyConcurrentLogin_StallsUntilSensitiveAE` reproduces both the
stall and the recovery at the merge level. It has not yet been reproduced on a fleet.

The fix is a deterministic id per triple. It is **planned, not implemented**:
[design/canonical-registry-credentials.md](design/canonical-registry-credentials.md). An
earlier opt-in, `enforcement.canonical_registry`, was removed on 2026-10-04. It only
advertised a token for a writer that never shipped.
A node that latched its `canonical_registry_v1` token keeps the marker. This build
recognises the marker as a retired token and does not quarantine the node.

**Operator runbook.**

- **Detect:** the replicator logs `apply failed — back-pressuring replication` with a
  `UNIQUE constraint failed: registry_credentials.scope, …` error, and
  `litevirt_replication_peer_pending_entries` rises for that origin→peer pair. It should
  fall again within an anti-entropy interval or two.
- **If it persists:** the sensitive anti-entropy lane between those two nodes is not
  completing. Check the anti-entropy logs on the stalled receiver. Until the lane completes,
  the entry stays at the head of the stream until it ages out at `MaxLogRetention` (24h).
  Other tables still converge over the public anti-entropy lane in the meantime. To clear it
  by hand, soft-delete (tombstone) the live credential for that triple on the affected
  node(s), a single `deleted_at` write per node. Then have the user re-establish the login
  with `lv registry add`. No data is lost; the credential is simply re-created.

### The sensitive lane

`--include-sensitive` also scans secret-bearing tables (2FA factors, recovery
codes, registry credentials, notification targets). Those tables' primary keys and
content are themselves secret — a `recovery_codes` PK contains a bcrypt hash — so
the lane **never returns raw PKs or plaintext**. Each node computes
**domain-separated keyed HMACs** of its rows under a single random per-scan key
distributed to peers only over the peer-mTLS channel (never logged). Identical rows
produce identical HMACs across nodes, so divergence is still detectable, while a
different scan reveals no cross-scan equality.

### Reachability, partials, and stability

Comparison runs only over nodes reachable **in both samples** (per lane). A node
that flaps between samples is excluded from row classification — so its absence
can't fabricate a `missing_row` — and surfaced in `nodes_unreachable`. Under
`--include-sensitive`, a host whose sensitive (HMAC) lane fails is listed in
`sensitive_unreachable`: its secret-bearing tables were **not** scanned, so the
sensitive result is partial for that host and never silently "clean".

The report's `stable` flag is true only when the cluster was **quiescent** across
the scan: the reachable node set was identical in both samples **and** no scanned
table's content changed between them. When `stable` is false, a reported
`stuck_different` may be lagging replication backlog rather than a true permanent
split — re-run once the cluster settles. An unknown `--table` value is rejected
outright rather than scanning nothing.

### Output

Human-readable table by default; `--json` for the full structured report (node
lists incl. `sensitive_unreachable`, per-row per-node `updated_at`/hash, `stable`,
and violations). `--table` restricts the scan to specific tables.

The human-readable summary reads `no divergence detected.` when there are no
diverging rows and no violations; acknowledged ties do not count. In `--json`,
acknowledged ties are still in `rows`, so a script deciding "clean" must skip
rows whose `class` is `acknowledged_tie`.

## `lv doctor machine-types`

Read-only. Lists VMs whose **persisted spec** carries an unversioned machine
alias (`q35`, `pc-q35`, or empty) rather than a concrete versioned type such as
`pc-q35-9.0`.

```
lv doctor machine-types
```

An alias is resolved by libvirt against the **local** qemu, so a VM carrying one
can have its guest ABI shift underneath it when it migrates or fails over to a
host running a different qemu version. Two paths already pin the concrete type
at define time — `lv run` (create) and the stopped-VM redefine — and the
reconciler backfills the pin for any VM it sweeps on its current host. A VM
listed here therefore came from another path (clone, import, restore, promote)
and has not yet been swept where it now lives.

To pin one: start it (the reconciler pins on its next sweep) or, while it is
stopped, run `lv update <vm> --machine <concrete-type>`. Neither is urgent on a
homogeneous cluster — every host resolving the alias identically is why this is
a warning and not an error — but it should be cleared before introducing a host
with a different qemu version.

## `lv doctor fence`

Read-only. Reports whether a cross-host transfer of a shared-disk VM would
actually be fenced.

```
lv doctor fence
```

Starting a VM on a second host while the first may still be writing the same
shared disk corrupts it. The guard against that is a **proof-grade fence** — an
IPMI- or Redfish-confirmed power-off, or an operator `lv host fence-confirm` — required
before an ownership transfer of any VM with a disk on shared storage
(`nfs`, `ceph`, `rbd`, `iscsi`). Local-disk VMs need no fence: a relocation
target holds a different image, not the same bytes.

The guard has **two independent switches, and both must be on**:

| Switch | Scope | Default |
|---|---|---|
| `shared_storage_fence_v1` | latches cluster-wide once every host advertises it | latches on upgrade |
| `enforcement.shared_storage_fence` | per-host config | **false** when absent; `lv host init` writes **true** on a new cluster's first node |

The gap this command exists to close: a host advertises the token **regardless
of its own config flag**, because advertisement means "this binary supports the
feature", not "this node enforces it" (see `advertisedCapabilities`). A cluster
can therefore show the capability fully latched while any subset of hosts
silently skips the fence — a state no peer and no operator could observe. This
command asks every host for its own posture via `PingResponse.not_enforcing`,
so the answer reflects what each node will actually do.

That the token is advertised unconditionally is deliberate, and the reasoning is
kept in `advertisedCapabilities`: the fence is enforced where a transfer is
*created*, so no node relies on a peer enforcing it, and withholding the token
would leave a witness — or any host mid-rollout — holding the whole cluster on
the legacy path.

A host is reported as `unknown` rather than as enforcing whenever its posture
cannot be read, which covers five cases: it did not answer; it did not report a
posture (it runs a binary predating the field, or it withheld posture from this
caller — see below); it advertises nothing because it is self-fenced or
WAL-quarantined; it advertises other tokens but not this one; or the report's
overall budget expired before it was probed.

Posture is answered only to a caller presenting a **host** certificate.
`not_enforcing` names which security kill-switches are off, and `Ping` bypasses
the identity interceptor, so the distributable `lv-cli` certificate would
otherwise read it with no session and no role. The daemon's own fan-out uses its
host certificate, so this is invisible in normal use; a caller reaching `Ping`
some other way lands in the `unknown` bucket above rather than being told
anything.
Unknown counts against readiness exactly as "not enforcing" does — a diagnostic
that cannot see a host must not report the cluster clear on its behalf.

Witness hosts are excluded. A witness never hosts a workload, so it can never
perform the fence and its flag will never be on; counting it would pin the
warning on permanently.

Exit code: `0` when no shared-disk VM is exposed · `1` when one or more are.

### Recovery-claim posture

The same sweep reports each host's recovery-claim posture
(`enforcement.recovery_claim`, default on; see
[design/recovery-claims.md](design/recovery-claims.md)), witnesses included,
since a witness runs a failover coordinator too, and whether
`recovery_claim_v1` has latched on the queried node. Unlike the fence token,
`recovery_claim_v1` is withheld while a host's flag is off, so a host that
answers with other tokens but not this one is reported `NOT enforcing`: its
flag is off, or its `split_brain_gate_v1` has not latched yet. A host that
withholds `voter_config_v1` as well cannot vote durably yet, which withholds
the token whatever its flag says, so it is reported `unknown` rather than
accused. The queried node's own row is read the same way — by whether it
advertises the token, not by its flag alone — so one state reads alike from
whichever node you ask, and its detail names the reason when it does not.

When the token has latched and any **reachable** host is not enforcing, the
command prints a WARNING naming each one with the fix: add
`enforcement.recovery_claim: true` explicitly to that host's config and restart
it. The usual cause is a host rolled back to an older build, or one that missed
the roll and rejoined on one. That build reads a missing key as `false`, and it
knows the token, so it is not WAL-quarantined. It mints and runs recovery
proofs without a certificate. A host whose flag is already on and that is
still listed is not ready to advertise the token — usually a host that just
joined, whose `split_brain_gate_v1` has not latched yet; the warning says so,
and `lv doctor fence` run with `LV_HOST` pointed at that host names the reason
in its own row. An unreachable host is listed as `unknown` and does not raise
the warning. The warning is diagnostic only and does not change the exit code.

### What a fence established

`lv doctor fence` also warns about two fencing postures, neither of which
changes the exit code: the hosts that fence only over SSH (`ssh`,
`best-effort`, or unset), whose failed workloads wait for their partition pause
or `lv host fence-confirm`, with a recommendation of `ipmi` or `redfish`; and,
separately, the hosts that trust a confirmed SSH power-off
(`lv host config <host> --trust-ssh-poweroff`), whose workloads are recovered
on a confirmation without proof the host is off. The web UI's health page shows
the same two lists.

`lv doctor fence` also lists the fences of the last 7 days (newest 20), each
with an **assurance** — what that fence actually establishes about the host.
The stored `fencing_log.result` cannot make this distinction: it says `fenced`
both for an IPMI or Redfish power-off that was observed off and for an SSH poweroff nobody
checked.

| Assurance | Produced by | Means |
|---|---|---|
| `verified` | `ipmi` or `redfish` + `fenced` | Powered off, then observed off (IPMI chassis power status, or Redfish `PowerState` `Off`). |
| `operator-confirmed` | `lv host fence-confirm` | A person attested the host is down. |
| `requested` | `ssh` or `watchdog` + `fenced` | The host accepted a forced power-off, or its watchdog heartbeat was stopped. Nothing checked it went down. |
| `assumed` | `best-effort-ssh` + `fenced` | Written only by an earlier build: SSH failed and the best-effort strategy proceeded anyway. Not even the request is known to have arrived. This build does not recover from such a row. |
| `self_paused` | `best-effort-ssh` + `fenced`, detail prefixed `[relies on the host's partition pause]` | A best-effort fence that did not confirm the power-off, relied on because `partition_pause_v1` has latched and the host said it pauses: the coordinator waited out the host's own partition pause before it recovered anything, so the old copy had stopped executing. It says nothing about power. `litevirt_fences_total` counts it as `assumed`. |
| `awaiting-confirmation` | `manual` + `partial` | A manual fence waiting for a person. Not a failure. |
| `failed` | any + `partial` | The fence ran and reported failure, or was refused, or (best-effort) did not confirm the power-off with the host's pause not relied on. |

Only `verified` and `operator-confirmed` are proof-grade: they satisfy the
shared-storage fence, and only they record a host `fenced` once
`fence_state_v1` has latched (`corrosion.FenceProofGrade` is defined in terms
of this table, and the coordinator judges a live fence by the same one). A
`requested` or `self_paused` fence records the host `offline`. A `self_paused`
one lets the coordinator that ran it reschedule **local-disk** VMs once the pause
wait has passed, and a `requested` one does too on a host that trusts a
confirmed SSH power-off (`litevirt.trust_ssh_poweroff`), which is why the command
prints a note when it finds one. A later coordinator resumes a recovery from
one while it still stands, and never fences the host again for it (see
[Resuming a recovery from a recorded fence](migration-failover.md#resuming-a-recovery-from-a-recorded-fence)).
`lv host fence` prints the same assurance for the fence it just ran.

A host recorded `fenced` is taken to be **off** only when its newest fence is
proof-grade. Before `fence_state_v1` latches, or from a leader on an older
build, an SSH fence records `fenced` too; owner-assert still asks that host
whether it runs a workload, and `lv host rm --dead` does not count a
proof-grade fence from an earlier life of that host: confirm it off
(`lv host fence-confirm`) first.

`litevirt_fences_total{method,assurance}` counts the same classification. Note
that the older `litevirt_fence_failures_total` counts every result other than
`fenced` and `manual-confirmed`, so a manual fence **awaiting confirmation**
shows there as a failure; read `litevirt_fences_total` for the distinction.

### What it does not establish

Printed on **every** run, clean or not. These are the two things that would make
a clean result wrong, and the host table reads most misleadingly on the warning
path — a fleet can show a column of `enforcing` above a WARNING, and an operator
who fixes the one host the remedy names would otherwise never learn that the
per-host latch is unobservable:

- **Each host's own capability latch.** The latch is per-node state
  (`internal/health.Checker`'s `activated` map plus its marker files) with no
  wire representation, so `capability_latched` is the *queried node's* latch.
  During a rollout one node can latch before another finishes its sweep, and a
  host that has not latched takes the legacy path whatever its config flag says.
  `enforced_everywhere` therefore covers the per-host **config** half only —
  true means "nothing is switched off", not "every node will fence".
- **Shared-disk VMs this node has not replicated.** The count comes from the
  queried node's `vm_disks` rows, so a VM created on a peer whose rows have not
  arrived is not counted. A zero is "none that this node knows of".

When `capability latched` is false and any host reads `enforcing`, the report
says so explicitly: `enforcing` is that host's config flag, and the flag does
nothing until the capability has latched cluster-wide, so no host is fencing
whatever the table shows. Without that line a mid-rollout fleet — every operator
having already set the flag — prints a column of `enforcing` that reads as
covered.
## `lv doctor cpu-mode`

Read-only. Lists VMs whose **persisted spec** has an empty `cpu_mode`.

```
lv doctor cpu-mode
```

Such a VM is defined with no `<cpu>` element, so libvirt passes no `-cpu` to QEMU
and the guest runs on QEMU's x86_64 default, `qemu64` — a model with no `sse4.1`,
no `sse4.2` and no `xsave`, and therefore neither AVX nor AVX2, however capable
the host is. Guest software that assumes a modern baseline will not start, and the
fault presents as a broken binary rather than a hypervisor setting.

New VMs default to `host-model` (see `vm.default_cpu_mode` in
[configuration](configuration.md)). VMs listed here were created before that
default existed. Their stored spec is honored verbatim and deliberately not
rewritten: changing the CPU a running guest sees is not something an upgrade
should do behind the operator's back.

To move one forward, with the VM **stopped**:

```
lv update <vm> --cpu-mode host-model
```

or, in one step on a running VM, `lv update <vm> --cpu-mode host-model
--restart-if-needed`, which does a stop → redefine → start under a single VM
lock.

The retrofit is an **in-place patch of libvirt's own inactive domain XML**, not a
regeneration from the stored spec, so every libvirt-assigned detail the spec does
not describe — guest PCI slot addresses, controller models, disk ordering —
survives unchanged. That matters for guests (e.g. Windows) that key licensing off
stable hardware addresses. If the patch cannot be applied for any reason the
redefine falls back to full regeneration rather than failing.

Two things to expect. It changes the guest-visible CPU, so it needs a full
stop/start rather than a guest reboot. And it narrows live migration for that VM
to hosts with an equal-or-richer CPU — the trade the modern instruction set
costs, and no trade at all on a homogeneous cluster.

## `lv doctor privileged-containers`

Read-only. Lists containers that run **privileged** (no user namespace: root in
the container is root on the host) or with **legacy confinement** (AppArmor
nesting allowed, the template's seccomp policy and capabilities).

```
lv doctor privileged-containers
```

Every container created before unprivileged containers became the default is
both, and keeps running exactly as it is: nothing converts it behind the
operator's back. `lv ct inspect <name>` shows the same for one container. To
move one over, stop it and run
`lv ct convert --unprivileged --confinement default <name>` (see
[containers.md](containers.md), "Security"). A container an Admin created with
`--privileged` or `--confinement legacy` is listed too: that is the point of
the report.

## `lv doctor project-spellings`

Read-only. Lists project names that are live under more than one spelling
(`acme` beside `/acme`): two rows of one canonical name, which a create on a
much older release could leave. It checks the spellings only: the project
listing carries no incarnation, so it cannot tell whether a listed project
still holds the pre-upgrade identity.

```
lv doctor project-spellings
```

A listed project is never given a stable identity by the adoption pass
([upgrades.md](upgrades.md#projects-created-before-the-upgrade-get-a-stable-identity))
while one of its spellings still holds the pre-upgrade identity; the pass
counts those, and only those, in
`litevirt_project_adoption_blocked{reason="spellings"}`. Either way its parent
references stay in conflict for automation.

There is no repair command yet. Do **not** delete one spelling to merge them:
both spellings share one RBAC root, and a delete retires the grants under it,
so the surviving spelling can lose its grants. Leave both in place; the
project keeps working as it does today.

## `lv doctor vm-uuids`

Read-only. Lists VMs whose **persisted spec** carries no domain uuid.

```
lv doctor vm-uuids
```

The uuid is what makes a NetBox identity incarnation-unique
(`lv:<fingerprint>:<uuid>:<mac>`), so a VM without one cannot be named in NetBox
at all. The inventory mirror skips it **and** counts it as an unreadable record —
and an unreadable record is indistinguishable from a destroyed VM, so the mirror
withholds *every* delete while one exists. A single VM listed here stops the
whole mirror converging, which is why this matters even on a cluster that does
not care about the individual VM.

libvirt mints a uuid for every domain it defines regardless of what litevirt
stored, so the reconciler adopts it from the persistent domain XML as it sweeps
each VM on its **owning host** — running or stopped. No other node can read that
XML, which is why there is no cluster-wide repair command. A VM listed here has
not been swept yet, or its host is down.

The backfill never overwrites a uuid the spec already has, even if libvirt
reports a different one: the stored value is the identity other systems already
hold, and replacing it would orphan every object stamped with it.

To fill one in: make sure its host is up and wait for the next reconciler sweep.

## Persisted LWW clock & backward-clock protection

The `updated_at` conflict key is minted from a **monotonic** clock whose high-water
mark is persisted to `<dataDir>/nowts.hwm`, so a wall-clock step-back or a restart
can't mint an older-sorting key that silently loses cluster-wide. This protection is
**always on** (no flag). Enabling `enforcement.hlc_lww` additionally flips the key
*format* to HLC (see [configuration.md](configuration.md)); the persisted clock works
the same either way.

Operational notes:

- **Sticky future-skew.** If a node's clock jumps far into the future, the persisted
  high-water stays ahead even after the clock is corrected — the node keeps emitting at
  the old ceiling until wall time catches up, and (with `lww_skew_guard`) peers may
  quarantine its writes in the meantime. **Recovery:** correct the clock (NTP) and wait
  it out. As a last resort, stop the daemon and delete `<dataDir>/nowts.hwm` to reset the
  ceiling — this re-opens the backward-regression window until wall time passes the old
  ceiling, so only do it when the skew was large and you understand the trade-off.
- **Re-image / dataDir wipe.** A node whose `dataDir` is wiped loses its high-water and
  regains the regression window until its wall clock passes the pre-wipe ceiling. Ensure
  NTP is healthy before rejoining.
- **A full disk does not stop the clock** on ext4 and xfs. `nowts.hwm` has a fixed size
  and is overwritten in place, so saving the ceiling needs no new disk space there. On
  btrfs and ZFS an in-place write still needs new space (copy-on-write). The daemon marks
  the file no-copy-on-write when it creates it, which avoids that on btrfs except for the
  first save after each snapshot of the subvolume; ZFS has no equivalent, so a full ZFS
  data directory still stops the daemon as described below. The daemon writes
  it in that layout at start; a node upgraded from an earlier build converts the file
  then, and a node rolled back to an earlier build still reads it.
- **Persistence failure is fail-closed.** If the daemon cannot persist a higher ceiling
  and its in-memory headroom is exhausted, it **exits** rather than emit a key below the
  last durable ceiling. That takes an error the in-place save cannot write around: an
  I/O error, a read-only filesystem, or a disk that was already full when the file
  needed creating or converting. The crash surfaces it loudly. Recovery = fix the filesystem.

## Equal-timestamp tie resolution

Strict last-writer-wins settles every conflict whose `updated_at` values differ.
An **exact** tie (byte-equal instant) with differing content is the pathological
case `equal_updated_at_different_content` above: keeping local on the tie is a
per-node choice, not a cluster total order, so the two values never re-converge.

On an exact tie the merge consults a **table-aware resolver**. Every replicated
table is assigned exactly one resolution chain (enforced by coverage tests — a new
table cannot silently get a default). A chain is either a deterministic total
order (both nodes pick the same winner, so the row converges) or it deliberately
**refuses to converge** and leaves the row for a human / runtime repair:

| Category | Tables | On an exact tie |
|---|---|---|
| content-default | inventory/config tables with no authorization, isolation, runtime, or auth meaning (`images`, `hosts`, `dns_records`, …) | a one-sided soft-delete wins, else the canonically-greater row wins (deterministic; converges) |
| runtime-owned | `vms.host_name` | **unresolved** — never adopt an owner by value (it could name a non-running host); defer to runtime repair |
| opaque definition | the workload/resource definition blobs: `vms.spec`, `containers.create_spec`, `networks.config`, `volumes.config`, `stacks.spec`/`compose_yaml` | **unresolved** when the blob differs — the canonical encoder orders specs by their length prefix, so content-max is an arbitrary, non-semantic tiebreak that could silently downgrade a live definition to a stale serialization; a human / runtime repair makes one side authoritative |
| tenancy | `project` on `vms`/`containers`/`networks`/`storage_pools`/`volumes`, `project_name` on `backup_schedules` | **unresolved** when the tenancy column differs (a content-max could silently move a resource between tenants) |
| policy | `roles`, `role_bindings`, `users`, `tokens`, `projects`, firewall/SG tables, secret-bearing config | a delete wins, else **unresolved** (a value tiebreak could converge to the more-permissive grant) |
| auth | `user_2fa` (replay ratchet → max; consume/tombstone irreversible), `recovery_codes`, the active-set pointers | converging rules where safe, else **unresolved** (never resurrect a superseded factor/code) |
| LB | `lb_configs`, `lb_backends` | a non-empty incarnation token beats empty; two different non-empty tokens are **unresolved** |

A table can mix categories in one chain — e.g. `vms` resolves a `host_name` tie as
runtime-owned, a `project` tie as tenancy, a `spec` tie as opaque, and any other
column tie by content-max — applied in that order, first strict decision wins.
`hosts` settles a tie between two live rows with different `created_at` (two
incarnations: a host's stale database against its re-admission) by the later
`created_at`, ahead of its control-plane columns, reported as `incarnation`.
Anti-entropy also refuses to replace a re-admitted `hosts` row with a newer
row of the host's previous incarnation: it is counted in
`litevirt_merge_apply_rejected_total{table="hosts",path="ae",reason="older_incarnation"}`
and logged.

`containers` ownership is part of the primary key, so an ownership split is two
distinct rows (not a single-row tie) — detected by `duplicate_live_container`
above and repaired by the container runtime-repair phase, not the row resolver.

The anti-entropy merge is the authority; the WAL fast-path resolves full-image
upserts through the same engine and otherwise keeps local and lets anti-entropy
converge the row, so the two paths can never disagree.

### Metrics

- `litevirt_lww_tie_break_total{table,resolver,winner}` — ties that converged by a
  deterministic resolver (`content_max`/`numeric_max`/`timestamp_max`/
  `non_null_wins`/`lb_generation`/`incarnation`/`project_adoption`). A steadily climbing value means a node is
  minting colliding timestamps (the upstream smell), not just a one-off split.
- `litevirt_lww_tie_unresolved_total{table,path,category}` — **monotonic counter**
  of distinct unresolved ties *observed* (counted once per row, not per cycle).
  Use `increase(...)` to alert on "a new unresolved tie appeared" — a bare `> 0`
  would page forever, since a counter never decreases. `category` ∈
  {`runtime_owned`, `opaque`, `tenancy`, `policy`, `control_plane`, `auth_factor`,
  `auth_pointer`, `lb_token`}.
- `litevirt_lww_tie_unresolved_current` — **gauge**: distinct ties this node is
  *currently* tracking as unresolved. Drops back to 0 when the rows are repaired
  (the per-(table,PK) tracking is cleared on any newer write). This is the right
  signal for "something is divergent right now."
- `litevirt_lww_tombstone_tie_total{table}` — ties a one-sided soft-delete settled
  (a delete racing a write). Benign and expected; tracked separately so it doesn't
  muddy the tie-break smell.
- `litevirt_runtime_owner_assert_total{kind,result}` — runtime ownership repair
  outcomes. `kind` ∈ {`vm`, `ct`}; `result` ∈ {`asserted`, `rekeyed`,
  `split_brain`, `inconclusive`, `error`}. A `split_brain` is a workload running on
  two hosts at once → page; sustained `inconclusive` means a peer the repair needs
  is unreachable.
- `litevirt_merge_apply_rejected_total{table,path,reason}` — **monotonic counter** of
  replicated write ATTEMPTS the apply path refused (kept-local / back-pressured). `path` ∈
  {`ae`, `wal`}; `reason` is a bounded class (never SQL text or parameters). Because it counts
  *attempts*, a permanent fault re-increments every cycle — so alert on its **rate**, correlated
  with replication backlog (`litevirt_replication_min_watermark_seq`) and `lv doctor
  divergence`, **not** on its absolute value.
  `reason="spec_edit_dropped"` (table `vms`) is different in kind: a VM spec edit that met
  another made from the same generation and lost (see
  [operating-model.md](operating-model.md#replication)). Each one is also a
  `vm.spec_edit_dropped` event on the VM, quoting the dropped spec.
- `litevirt_spec_edit_held_total` — **monotonic counter** of lines of VM spec edits this node
  holds off a VM because an operation on it has not finished, counted once per VM and
  operation when the hold is confirmed (a second consecutive pass); each
  raises `vm.spec_edit_held` (see
  [the condition](#a-line-of-spec-edits-is-held-off-by-a-running-operation-vmspec_edit_held)).
- `litevirt_replication_parked_entries{origin}` — **gauge**: received changes this node
  holds because a constraint refuses them, per sender (see
  [`replication_entry_parked`](#a-received-change-this-node-cannot-apply-replication_entry_parked)).
  The sender's stream continues past them. Nonzero means those changes have not happened here.
- `litevirt_legacy_mutation_transformed_total{transformer}` — **monotonic counter** of prior-
  release WAL statements this node NORMALIZED before applying (a supported historical shape, e.g.
  a param-bound `crl_versions` rewrite). A brief rate during a rolling upgrade is expected; a
  **continuing** rate means an old emitter is still writing or a relay is retaining pre-upgrade
  WAL — investigate that peer/relay.
- `litevirt_antientropy_digest_tables_total{result}` — tables a state digest took
  from the digest cache (`cached`) or scanned (`computed`), counted for every digest a
  pass computes and every one a peer asks for. On a quiet cluster `cached` dominates;
  a node where `computed` tracks the total has its cache off
  (`anti_entropy_legacy_repair: true`) or a table written every pass.
- `litevirt_antientropy_pull_rows_total{scope}` — rows a repair pull received:
  `bucket` for a table narrowed to the buckets whose digests disagreed, `table` for one
  pulled whole (a peer on an older build, a table that is not bucketed, or the
  stand-down). A steady `table` rate against current peers is worth a look.
- `litevirt_antientropy_digest_seconds`, `litevirt_antientropy_dump_bytes`,
  `litevirt_antientropy_rows_merged_total`, `litevirt_antientropy_rows_skipped_total` —
  the wall time of one digest (cached tables cost almost nothing), the compressed size
  of one repair pull, and the rows a merge applied or kept local
  ([design/ae-incremental.md](design/ae-incremental.md)).

### Alerts

```promql
# Something is divergent RIGHT NOW (clears automatically on repair — gauge, not counter).
max(litevirt_lww_tie_unresolved_current) > 0
# A NEW auth/policy-critical unresolved tie appeared — page distinctly (use increase,
# since the _total series is a monotonic counter that never returns to 0).
increase(litevirt_lww_tie_unresolved_total{category=~"auth_factor|auth_pointer"}[15m]) > 0   # auth_unresolved_tie
increase(litevirt_lww_tie_unresolved_total{category="policy"}[15m]) > 0                       # policy_unresolved_tie
# Sustained ties ⇒ a node is minting colliding timestamps (an upstream clock/ID bug).
# Tombstone ties (a delete racing a write) are benign individually but, if sustained,
# are the same colliding-timestamp evidence — include at a lower severity.
rate(litevirt_lww_tie_break_total[15m]) > 0
rate(litevirt_lww_tombstone_tie_total[15m]) > 0   # lower severity
# A workload running in two places at once — page immediately.
increase(litevirt_runtime_owner_assert_total{result="split_brain"}[10m]) > 0
# Replicated writes are being refused faster than they clear (a builder bug, a mixed-version
# gap, or malformed input). Correlate with replication backlog + divergence, not the raw total.
rate(litevirt_merge_apply_rejected_total[15m]) > 0
# A received change is held because it cannot apply here (the sender's stream continues).
max by (host, origin) (litevirt_replication_parked_entries) > 0
```

The **signal** is bounded — `lww_tie_unresolved_total` counts a row once and the
alert fires once per distinct divergence, not per cycle. The **divergence itself
is not suppressed**: while a row remains unresolved its table's digest stays
mismatched, and the tie stays in the register, the `ha.lww.unresolved`
condition, `lv doctor divergence` and `litevirt_lww_tie_unresolved_current`.
What anti-entropy stops doing is re-pulling it. After a pull, the node checks
the pulled rows against its own: when every row that still differs is a tie it
already tracks and both versions — its own and the peer's — are among those it
has met for that row (a lease term contested by every node has one version per
node, and each peer's is recognised), the table is settled against
that peer, and scheduled passes skip it until either side's digest moves. Any
write to the table on either side — a new row, a repair — moves a digest and the
next pass pulls it. A table that also holds a difference the register does not
explain is pulled every pass, as before. A replica that is not caught up, a
restarted daemon's first pass, and `lv cluster converge` pull regardless.

Resolve an unresolved row by making one side authoritative with a fresh write —
which clears the tracking and lets the table converge.

A `control_plane` tie on a `hosts` row is not cleared by `lv host config` or
any other write to the row: each applies to both copies. Once
`release_2026_11_v1` has latched, run `lv host rm <name>` and then `lv host add`
for the machine; the re-admission is a later incarnation of the row and every
node keeps it ([upgrades.md](upgrades.md)). The host does not need to be
reachable.

### VM ownership ties — automatic and manual repair

A `vms.host_name` split is the runtime-owned category: the resolver keeps it
local (never picks an owner by value) and defers to runtime repair.

- **Automatic (runtime owner-assert).** Each host's reconciler watches for a VM
  that runs **locally** but whose DB row points at another host. Before
  reclaiming it, it queries **every workload-capable peer's local libvirt** (the
  peer-only `GetRuntimeInventory` RPC) and re-stamps ownership to itself **only when
  all of them answer `absent`**, no migration/lease marker is present, and the
  condition has persisted past a short debounce. If any host reports `running`
  it's a true split-brain → it refuses to act and logs an alert (destruction
  needs fencing proof, never a host-order coin-flip). If any host is unreachable
  or holds a stale definition → inconclusive → it retries later. This is why a
  segmented host's VM (e.g. one the rest of the fleet can't reach) is left for
  manual repair rather than auto-reclaimed.
- **Manual.** `lv doctor repair-owner <vm> <host>` forwards to `<host>`, which
  re-stamps ownership only if it confirms the VM runs there locally. Use it for
  the segmented case, or to force a specific owner the operator knows is correct.
  It refuses while a shared disk's row names a third host that is not proven
  powered off (`vm.shared_disk_withheld`, docs/backups.md), and names
  `lv host fence-confirm <host>`.

Either way the fresh timestamp wins everywhere by ordinary LWW and clears the
unresolved tracking. Both also move the VM's `vm_disks` rows to the host that
runs it, in the same write. Failover moves them with the VM too. Builds before
that re-keyed only the `vms` row, so a VM recovered by one of them can still
have disk rows naming the host it left. Running `lv doctor repair-owner <vm>
<host-that-runs-it>` once realigns them. A migration also commits over such a
row, as long as the row has not changed since the migration began. A row of a
disk on shared storage moves, by either, only once the host it names is
proven powered off (`lv host fence-confirm <host>` first), or, for repair-owner,
once that host is active and attests that no domain on it uses the disk:
until then it keeps naming that host, and repair-owner refuses
(docs/backups.md).

A migration whose ownership commit is refused after the cutover (a disk row
changed while it ran) moves the `vms` row to the target, where the guest now
runs, and reports the refusal. It no longer leaves the row `migrating` on the
source, where nothing would repair it.

### Container ownership — automatic runtime re-key

Container ownership is part of the primary key `(host_name, name)`, so an
ownership split is **two distinct rows**, not a single-row tie — the row resolver
can't see it (it's surfaced as `duplicate_live_container` above). The container
reconciler repairs it directly: when a container runs **locally** but its only
live DB row points at another host (and no live local row exists), it queries
**every workload-capable peer's local LXC** (the peer-only `GetRuntimeInventory`
RPC) and, only if none reports it running (a peer's stale *stopped* leftover does
not block; an unreachable/unknown peer does), performs an atomic **PK re-key** of
the container's whole ownership footprint: in one transaction it tombstones the
remote container row **and its managed `container_interfaces` rows**, inserts a
local row carrying the container's `create_spec` and a distinct
`runtime-owner-rekey` provenance marker, rebuilds the managed interface rows on
the local host (veth recomputed), and **transfers the IPAM leases**
(`owner_host`) — so firewall/SG binding, DNS/LB, quota, and IPAM ownership all
follow. It stands
clear of any container under an active relocation/restore/migration (PR #57
markers / `relocate_token`), skips ambiguous cases (a live local row, more than
one remote row, templates), and — like the VM path — only an active worker acts,
a peer reporting `running` is a logged split-brain (no re-key), and a debounce
guards the transition window.

## Operational repair flow

When `lv doctor divergence` reports rows (or an alert fires), work through them in
this order. The ordering is a **safety invariant**: the selfFence non-destruction
guard must be live on every node before the tie resolver runs anywhere, or a
converged-wrong `host_name` could drive a node to destroy a live workload.

1. **Capture evidence first.** Run `lv doctor divergence` (add `--json`) and save
   it — convergence destroys the per-node evidence, so this is your only snapshot
   of who-had-what.
2. **Roll the guard fleet-wide, then the resolver.** When deploying the LWW repair
   itself: get the selfFence guard onto *every* node first; only then roll the
   resolver. Mixed guard/no-guard during the resolver roll is the unsafe window.
3. **Classify each reported row:**
   - **`vms`/`containers` ownership** (`runtime_owned` / `duplicate_live_container`)
     — leave it to the **automatic runtime repair** (it reclaims on positive
     all-peers-absent proof), or force it: `lv doctor repair-owner <vm> <host>` for
     a VM, or for a container that the fleet can't auto-resolve (e.g. a segmented
     host) make the running side authoritative. Never destroy by host-order.
   - **`opaque` / `tenancy` / `policy` / `auth_*` / `lb_token`** — these are
     deliberately unresolved (a wrong auto-pick would lose data or escalate). Pick
     the correct side and make it authoritative with a fresh write **through the
     normal API** (e.g. re-save the VM spec, re-apply the role binding, re-enroll
     the factor). The fresh `updated_at` wins by ordinary LWW and clears the
     tracking.
   - **`schema_shape_mismatch`** — a column-order/shape skew from ALTER history,
     not an LWW tie; harmless but it keeps a table's digest mismatched. Normalize
     it on the next schema touch.
4. **Re-run `lv doctor divergence`** to confirm the row converged, and verify the
   live views agree (`lv ls`, `lv host ls`, per-host `virsh`/`lxc-info`).

> **Never edit `state.db` directly.** Every repair goes through the daemon (an API
> write or an audited `lv doctor` command) so it replicates and is auditable. A
> direct SQLite edit isn't replicated, isn't audited, and re-creates the very
> divergence you're fixing.

## Cluster health: durable conditions and the admission gate (v50)

Health is durable cluster state, not a per-leader memory. Detector findings
(dual-run, owner mismatch, owner-epoch mismatch, coverage gaps, unresolved
ties) live in replicated `health_conditions` rows with an
observed → confirmed → resolved lifecycle:

- first positive scan → **observed** (warning); second consecutive scan →
  **confirmed** (critical for the corruption-class codes);
- a VM or container seen on two hosts counts as positive only if a re-probe
  of those hosts, begun after the scan's gather, still sees it on both — or
  cannot see them completely. Hosts are probed one by one, so a scan can read
  a migration's source before the cutover and its target after it; the
  re-probe settles that, and a real dual run is still recorded in the same
  scan. A domain that libvirt undefines while a host is being probed (a
  migration source at the end of its cutover) is reported absent, not as a
  probe error: it was in the host's domain list and libvirt then answered "no
  such domain" for it. Any other per-domain error still makes the host's
  answer partial, and a partial re-probe leaves the sighting standing. Nor
  does a re-probe ever narrow a workload that already has an open
  `vm_dual_run` / `ct_dual_run`: a real dual run whose second copy flaps is
  missed by a re-probe now and then, and counting those scans clean would
  resolve it while both copies run;
- resolution needs **two consecutive clean scans with complete coverage** by
  the detector lease holder under a valid decision gate — an unreachable,
  partial, or older-binary peer blocks resolution (blind is not clean);
- resolution is proven by **whichever voter holds the detector lease**,
  including a witness or a draining host: what it needs is the voter
  majority, not to be an active worker;
- coverage is judged **per condition**, against the hosts that could hold the
  condition's subject. A `coverage_gap` or `lww_unresolved` on host H needs
  only H completely probed. A VM condition (`vm_dual_run`,
  `runtime_owner_mismatch`, `owner_epoch_mismatch`) is not held open by an
  unreachable host whose last liveness evidence in `host_health` (rows it
  wrote, or rows a peer wrote after it answered) is more than 5 minutes older
  than the VM's `created_at` — a host dead since before the VM existed cannot
  be running a copy of it. That host is still probed, keeps its own
  `coverage_gap`, and the evaluator still reports `partial`. The exemption
  never applies to the VM's DB owner, a host the condition names as involved,
  or a host that answered partially or from an older binary, and it fails
  closed on missing or unparseable evidence, a post-dated `created_at`, or a
  failed DB read. A `runtime_owner_mismatch` or `owner_epoch_mismatch` whose
  VM has since been deleted can never be raised again, so a clean scan
  proves nothing about it: it resolves only once every host it names was
  completely probed and has no domain of that name in any state. A named
  host that still has one keeps it open; a litevirt-stamped one is also
  reported as `vm_orphan_runtime` on its host. Container and VIP
  conditions keep the cluster-wide rule (names are not unique; a VIP has no
  creation stamp), so a registered host that is permanently gone still
  freezes those until `lv host rm`;
- leadership changes and restarts preserve counts and confirmed state;
- resolved conditions stay readable for 30 days (`lv health --resolved`),
  then are tombstoned;
- a condition whose subject is gone resolves on the next reconciler pass of
  any node whose replica has caught up: a VM or container that was deleted
  (a tombstoned row and no live one; a name with no row at all is not
  proof), or a host removed with `lv host rm`, whether the subject names the
  host itself, a pool on it (`<pool>@<host>`) or a workload on it
  (`<name>@<host>`). These outlive their subject and stay: the dual-run
  detector's (it resolves its own), `vm_orphan_runtime` /
  `ct_orphan_runtime`, the certificate and audit conditions,
  `vm_disk_stranded`, `vm_failover_held`, `vm_start_cancelled`,
  `ct_rootfs_stranded`, `reservation_stale`, the `iscsi_lun_hold_*` pair,
  `ceph_image_leftover`, `ceph_trash_leftover`,
  and the inputs failover recovery reads (`partition_paused`,
  `partition_pause_failed`, `partition_one_way`, evaluator `failover`);
- remove the cause, and the evaluator proves the resolution. For a
  condition it can no longer prove, an admin can resolve it by hand:
  `lv health resolve <code> <kind>/<id> --reason "..."`, with the code and
  subject as `lv health` prints them. Only the dual-run detector's
  conditions can be resolved this way, and only once the detector has
  looked and not seen it: its last scan must be later than the condition's
  last sighting and must have completely probed every host the condition
  names. Otherwise it is refused, naming what is missing (a scan still
  pending or still seeing it, no detector lease holder, or a named host the
  scan could not probe). It needs the `cluster.health.resolve`
  verb (Admin), writes a `health.condition.resolve` audit row with your
  principal and reason, and publishes `ha.condition.resolved`. It proves
  nothing: the detector re-derives its findings every pass, so a condition
  that still holds is raised again, observed and gating admission, on the
  next one.

`lv health` prints the overall state (HEALTHY / DEGRADED / CRITICAL /
UNKNOWN), every active condition with its involved hosts, evaluator
coverage, peer connectivity, and per-host effective capacity — and exits
0 / 1 / 2 so scripts can gate on it. Under any state but HEALTHY it lists
each cause on its own `- ` line beneath the overall state, including the ones
that are not conditions: an evaluator whose last scan is more than 5 minutes
old (stale: its scan has stopped, or no node holds its lease), an evaluator
with incomplete coverage, an incomplete capacity sample, and a link not
proven good.

Peer connectivity counts toward that state: a link the checker cannot prove
good is a coverage gap, so a `suspect` or `failing` edge reads DEGRADED
rather than being reported and ignored. Links whose **target is in
maintenance** are the exception — nothing probes a host that is out of
service, so its last recorded status would never change again and counting
it would hold the cluster DEGRADED for as long as the host stays down. Those
edges are still listed; they just stop voting.

**The same rows drive admission.** An active ownership condition blocks
capacity-growing admission to every involved host and runtime-changing
actions on the affected workload; an incomplete local runtime inventory
blocks new workloads on that host; a VIP dual-holder freezes that VIP's LB
changes (and only those). `--allow-overcommit` bypasses numeric headroom
only. Automated recovery (self-heal restarts, owner assertion, container
re-key) refuses any workload with an active ownership condition, and owner
assertion additionally demands the host-local owner-epoch marker be valid
and exactly equal to the DB epoch being superseded — missing, corrupt,
unreadable, or unequal evidence refuses with a distinct reason.

Effective capacity: every host samples the union of its database and
runtime workloads each minute into `host_capacity_observations`, and again
within a few seconds of any change to the database's record of the host's
workloads (one arriving, leaving, changing state or being resized) — a rogue
runtime the database does not know about still consumes headroom in
placement, and an uncapped rogue container makes the host's capacity
explicitly *incomplete*, which disqualifies it as a placement target until
resolved. A VM that is migrating is charged by neither placement nor
admission, so its qemu counts in EXTRA on the host it runs on until the move
commits.

The `capacity:` table in `lv health` has one row per host that has sampled:

```
capacity:
  HOST    EFFECTIVE   DB                    EXTRA    COMPLETE  DETAIL
  node-4  1c/1280MiB  1c/768MiB +512MiB ct  0c/0MiB  true
```

- **DB** is what the database holds on the host now, read at request time
  with the rules both placement and admission charge by: running and
  starting VMs at their recorded vCPU and memory (placement also charges a
  VM still `creating`, which is not shown here), then (`+… ct`) the memory of running containers. A container is
  charged its memory and nothing else — its cpu is a cap in cores, not a
  reservation — and carries no qemu overhead.
- **EXTRA** is the sampler's finding: runtime usage beyond the database (a
  runtime grown past its record, or a rogue the database does not know). A
  container the database records is never counted here again, and a rogue
  container adds only its memory.
- **EFFECTIVE** is DB + EXTRA — what placement admits against.
- **COMPLETE** false means the host's runtime could not be fully accounted
  for, and placement treats it as unknown.

Automatic containment is intentionally not implemented: no path destroys a
disputed runtime. Any future containment mechanism must first prove complete
fleet runtime coverage, a current-epoch authoritative holder, a strictly older
conflicting holder, no in-flight migration/operation/lock/failover, and quorum
or explicit fencing authorization. The evidence and decision must be durable
before any stop is issued.

### Voter genesis pending (`ha.voter.genesis_pending`)

Evaluator `voter_config`, subject `cluster/voters`, severity warning. Written by
the leader-lease holder while `voter_config_v1` has latched but automatic
genesis cannot write generation 1 of the explicit voter set: a host is in
`maintenance`, `offline` or `fenced`, or did not sign. Genesis waits for a clean
cluster so it never freezes a host out of the voter set because it happened to
be away when the token latched. The evidence names each host, its state and
what clears it; the condition resolves on the tick genesis succeeds. While a
witness that is up or a host in maintenance exists, the evidence names it:
until genesis completes, a split of the voters that it reaches both halves of
stalls failover (`ha.recovery.bridged`). With a witness the severity is
critical; a host in maintenance alone keeps it a warning.

For a cluster that cannot become clean — a host that is dead for good and has
not been removed — `lv cluster voter init --members <hosts>` proposes the
generation by hand. Every listed member must sign. `lv cluster voter ls` shows
the adopted generation once one exists.

### Voters that cannot vote (`ha.voter.unavailable`)

Evaluator `voter_config`, subject `cluster/voters`, severity warning. Written by
the leader-lease holder. Every member of the adopted voter generation counts in
every quorum's denominator whatever its state — there is no automatic shrink —
so a member that is `fenced`, `offline`, in `maintenance`, removed, or
abstaining (its claim state is a different incarnation from the one it was
admitted with: re-imaged or reseeded) is fault tolerance the cluster does not
have. A three-voter cluster with one fenced member needs both survivors. The
evidence names each such member and the command that clears it:
`lv host rm --dead <host>` for one gone for good, `lv cluster voter rm <host>`
for one that should stay a host but stop voting, and `lv cluster voter rm`
then `lv cluster voter add` for an abstaining one.

### A lease with no claim majority (`ha.lease.claim_no_majority`)

Evaluator `lease_term_claim`, subject `cluster/<lease key>`, severity warning.
Raised by a node that has seen a lease with no live holder and could not take
it over for want of a voter majority for longer than one of the lease's TTLs,
so nobody holds the lease (docs/operating-model.md, "Two nodes taking a lease
over at once record one term"). That covers a node that has lost the voter
majority and stands down from the lease, a quorum high-water read that no
quorum answered, and a claim no majority of the voter generation could
decide. Resolved once the lease is no longer contested: a
claim for it is decided, a term is recorded without a claim, or a node sees a
live holder renewing it. During a split, a node that cannot see the holder may
raise it again, and the row then alternates between observed and resolved
without reaching confirmed. `litevirt_lease_term_claim_no_majority_total{lease}`
counts each such poll. A claim lost to another claimant of the same term, with
a majority there to decide it, is not counted. The evidence names the reason,
and for a claim the refusing voters.
Voter changes are decided by the same majority, so `lv cluster voter rm`,
`add` and `reset` may not be able to run while this is raised. Repair a voter
while `ha.voter.unavailable` names it, before it is needed. Once this is
raised, the exits are restoring the lost voter, or fencing proof-grade every
member that cannot vote, abstaining ones included, and naming each in
`lv cluster voter force-reconfigure --lost <host>[,<host>...]`. `lv cluster voter reset`
returns lease takeovers to the two-holder race.

### A forced voter reconfiguration (`ha.voter.forced`)

Evaluator `voter_config`, subject `cluster/voters`, severity warning. Raised
after `lv cluster voter force-reconfigure` until every host it named lost has
been removed and revoked with `lv host rm --dead`: a lost host may hold an
ordinary generation its majority decided that nobody saw, so it must not come
back as it left. A lost host is the voter entry, name and incarnation, so a
machine rebuilt under its name after `lv host rm --dead` counts it gone once
it answers as a new incarnation, or once the adopted generation lists it as a
voter under one. A name with a fenced row keeps the condition raised with the
`lv host rm --dead` step. A host in service under the name that cannot say
which incarnation it is keeps it raised too, but the evidence only asks for it
to be reached: removal is never advised for a host in service or a current
voter. The evidence names each lost host still to settle. It is also
raised by a node that REFUSED a forced generation — because it can reach a host
the generation names lost, or because it is itself named lost and running —
with the reason: valid signatures do not make a false claim of loss true.
`lv cluster voter ls` on each host shows which generation it adopted.

### A recovery held by a bridged split (`ha.recovery.bridged`)

Evaluator `failover`, subject the host, severity critical, written by the
failover lease holder. A host's recoverable workloads stay paused, and nothing
recovers them, because observers outside the voter majority still see the host
answer: a host that reaches both halves of a split of the voters (a witness,
or a host in maintenance) relays the minority's view. Nothing runs twice. It
is raised in one of three forms:

- **At the deadline.** The host was fenced relying on its partition pause, the
  wait passed, and its workloads were not recovered because observers had
  seen it answer since the fence. On a derived voter set (no generation
  adopted) any such observer holds the recovery; on an adopted generation it
  is held while the host has not reported its pause during this outage. A
  report stamped more than 5 s before the voters first lost the host counts
  as an earlier outage's, so a host whose clock runs that far behind is held
  for as long as the bridge lasts, though it paused; once no observer sees it
  answer, the deadline recovers it. A store error reading that report is not
  a bridge and raises nothing; the `host.recovery.stalled` notification names
  it. The deadline is re-checked every cycle while a quorum of voters fails
  the host (while fewer do, the notification says so); the condition resolves when it goes ahead, or when the refusal
  is no longer a bridge (a voter majority sees the host answer), and
  workloads its limit leaves on the host are named by the
  `host.recovery.stalled` notification instead.
- **Before any fence.** The host has kept `partition_paused` open for longer
  than the pause wait and is no fence candidate: some voters see it down, but
  the observers that see it answer leave too few voters failing it for a
  quorum. This is a witness bridge on a derived voter set, where the witness
  votes. Nothing is fenced or recovered.
- **After a failed fence.** The host's fence failed (an `ipmi` or `redfish`
  BMC that did not answer, say), and its retry is refused on every cycle
  because observers saw the host answer after the attempt. Those observers
  hold no voter majority, and the host has `partition_paused` open, so its
  workloads are paused and held by the bridge rather than coming back. The
  `host.recovery.stalled` notification names the refused retry too.

The evidence names the paused `workloads`, the `observers` that see the host
answer, whether the cluster is on a `derived_voter_set`, and the `remedy`:
heal the partition, and the host returns and resumes its workloads; or, once
the host is powered off, `lv host fence-confirm <host>`, and the coordinator
recovers its workloads. On a derived set, complete voter genesis once every host is back
(clear what `ha.voter.genesis_pending` names, or
`lv cluster voter init --members <hosts>`) so the next split does not stall.
The condition resolves once the host is removed; a fenced or offline host
once no recoverable workload is left on it; any other host once it is no
longer held (a quorum of voters sees it answer, or its pause is over).

### A fence held because nothing needs it (`ha.fence_held`)

Evaluator `failover`, subject the host, severity warning, written by the
failover lease holder. A quorum of voters fails the host, but nothing on it
needs a fence: no workload a failover would move (every VM and container on it
is `on_host_failure: none`, stopped on a host-local disk, or otherwise left in
place; a VM stopped on shared storage with a policy is moved off still stopped,
and does need the fence), no workload recorded mid-transfer, no container
relocation marker and no pending recovery proof. Fencing it would power off what nothing restarts elsewhere, so the host
is recorded `offline`, **not fenced**, and no `fencing_log` row is written.
Whatever runs there keeps running. `lv status` shows the host `offline`; the
evidence names each workload left on it with its state and policy.

The decision is made again every cycle. Once something recoverable is recorded
on the host (a VM's policy changed to `restart-any`, a workload placed there),
the next cycle fences it as any failed host is fenced, and recovers its
workloads. If that fence is a best-effort one that did not reach the host, it
recovers nothing until `lv host fence-confirm <host>`: what became recoverable
during the hold was never paused by the host's partition pause, so it may
still run there. This holds even for a host labelled
`litevirt.unsafe_auto_failover=true`: that label opts out of the safe-fence
policy, not out of this. An `offline` host whose fence is held is not proven
off: a move off it still needs `lv host fence-confirm <host>` once it is
powered off. Bring its daemon back and it returns to `active` once a quorum
sees it healthy. The
condition resolves when the host leaves `offline` (back `active`, or fenced),
when a fence of it is recorded, or when it is removed.

A failover leader on an older release reads such a host as one whose fence
already failed, and does not fence it again, even if something recoverable is
recorded on it later. Upgrade the leader, or confirm the host off.

### A failed re-fence (`refence_failed`)

Evaluator `failover`, subject the host, severity critical, written by the
failover lease holder. A successor that found a verified fence of the host aged
or in doubt fenced it again before resuming its recovery, and that re-fence
failed, so nothing was recovered and the host is not re-fenced every cycle
(migration-failover.md). The evidence names the recorded fence and the failure.
Confirm the host is powered off, then run `lv host fence-confirm <host>`: the
recovery resumes from it. The condition resolves once a later fence of the host
succeeds or an operator confirms it off, or the host is back `active` or
removed.

A re-fence that **succeeds** is recorded as a `host.refence` audit entry,
naming the recorded fence it renewed and the method. The entry replicates, so
`lv events` on any node shows it, and so does the audit export. The failover
leader also publishes it live as `host.refenced` on its own event stream. A host
fenced by hand (`lv host fence`) while it was still answering has a fence
that does not stand, so with `ipmi` (or another verified method) the leader
powers it off once more, 15-20 s later, before it recovers the host's
workloads. This happens even if the host has just been powered back on. To
bring a fenced host back, `lv host undrain` it (or hold it at
`--fence-strategy manual`) before powering it on.

### Recovery-claim refusals (`recovery_claim_*`)

With recovery claims enforced (`enforcement.recovery_claim`), a recovery that
did not happen is counted in `litevirt_runtime_action_refused_total{reason}` and
logged with every refusing voter's detail:

- `recovery_claim_owner_reachable` — voters could still reach the workload's
  recorded owner and refused to certify its eviction, for example
  `node-3 still reaches node-2 (Ping answered in 4ms)`. The owner is up for
  most of the cluster: find out why the coordinator judged it failed. If it
  must not keep its workloads, fence it proof-grade; the probe then fails and
  the next tick's claim proceeds (at the same round).
- `recovery_claim_source_mismatch` — a voter's settled row names a different
  owner than the one the coordinator named.
- `recovery_claim_no_majority` — no majority of the voter generation answered:
  restore connectivity, or remove voters gone for good.
- `recovery_claim_lost` — another coordinator's recovery was decided; this one
  wrote that proof (or deferred to it) and nothing of its own.
- `recovery_claim_unproven` — a destination refused a proof whose certificate
  does not verify here: usually `voter_configs` or `cluster_crl` replication
  lag, which clears on a later reconcile; compare `lv cluster voter ls` across
  hosts if it persists.

`lv cluster claim vm/<name>` (or `container/<name>`) is where a stuck claim is
diagnosed: per attempt and per voter it prints the promised and accepted
ballot, the accepted value's digest, proof, destination and source, whether the
voter's incarnation matches its entry, and its last refusal with the detail. A
voter keeps its last refusal in memory only, so the column is `-` after that
voter restarts. That is by design (design/recovery-claims.md §3.3): a refusal
writes nothing, and a refusal from before a restart describes a probe or a
ballot that no longer holds. Re-run the recovery, or wait for the
coordinator's next attempt, to see a current one.

### Recovery stranded on a dead destination (`ha.claim.stranded`)

Evaluator `recovery_claim`, subject `cluster/claims`, severity warning. Written
by the leader-lease holder while recovery claims are enforced
(`enforcement.recovery_claim`). A recovery claim decided a destination for a
workload, and that destination then failed before it started it: the workload
stays pending on a host that is fenced or offline. This is deliberate. No
abandonment can be obtained from a dead host, and it might come back and
execute the certificate it holds, so no other destination may be authorized
until it is proven gone. The evidence names each workload, the destination and
its state, and the exact command:

```
vm/db-1 is decided for node-4, which is fenced and cannot run it; if node-4 is gone for good,
`lv host rm --dead node-4` (try --dry-run first) lets it retry at attempt 1.
```

If the destination comes back it executes the recovery (or, having failed
before starting, abandons it) and the condition resolves. If it is gone for
good, `lv host rm --dead <host> --dry-run` shows the plan: the proof-grade
fence it rests on (run `lv host fence-confirm <host>` first if there is none),
whether the host is removed from the voter set first, and each stranded
recovery. The real run removes the host from the voter set if it votes,
revokes its certificate, publishes the CRL and removes it. Every voter then
checks, in its own replica, that the destination is fenced proof-grade, no
longer a member and revoked before it promises at the next attempt; until the
CRL has reached them it refuses with `recovery_claim_supersede_unproven`, and
the next lease-holder tick retries. See
[design/recovery-claims.md](design/recovery-claims.md) §3.12.

### A recovery minted before recovery claims were enforced (`ha.claim.uncertified`)

Evaluator `recovery_claim`, subject `cluster/claims`, severity warning. Written
by the leader-lease holder while recovery claims are enforced. A reschedule or
container relocation minted without a certificate just before enforcement
turned on (the `recovery_claim_v1` latch forming, genesis, or
`lv cluster voter init` after a reset) is refused by its destination with
`recovery_claim_unproven`, because nothing is grandfathered. The lease holder
claims each such proof for its own value on its next tick, naming as the source
the old owner its proof-grade fence binding records, and attaches the
certificate; the destination then runs it and the condition resolves. If
another recovery was decided for the workload instead, that one is written in
its place. The evidence names each workload, its destination and proof, and
where a refusal shows (`lv cluster claim vm/<name>`).

A proof that binds no proof-grade fence of its old owner (a best-effort fence)
names no owner for the voters to probe, so it cannot be claimed and will not run
while recovery claims are enforced; the evidence says so. Set
`enforcement.recovery_claim: false` on every host until it has run, then turn it
back on.

### A recovery held by a decision made before the claim key changed (`ha.claim.legacy_held`)

Evaluator `recovery_claim`, subject `vm/<name>` or `container/<name>`, severity
warning. Written by the node whose claim re-proposed the decision, as a
replicated row, so a restart or a lease hand-off keeps it; resolved by the
leader-lease holder once the workload has moved on (a fresh decision, a later
owner epoch, or the workload deleted). After
`claim_incarnation_v1` latches, a recovery claim names the workload's
incarnation. A decision some voter accepted at the old, unscoped key for the
same name and owner epoch may belong to this workload or to an earlier one
deleted and re-created under its name. Unless the decision's destination shows,
from its own database, that it is not this workload's and will never run (it
signs a foreign abandonment), or that destination has been removed for good,
the claim re-proposes the old decision rather than deciding a second one beside
it. If the voters then refuse it, for example because it names an earlier
workload's owner, the recovery waits and this condition names the workload, the
decision's proof, destination and source, and why it could not be excluded. It
is not raised when the old decision is visibly this workload's own pending one
(its row points at the proof) and the destination was only slow to answer.

The condition stays raised even when the old decision is decided at the new
key: a decision whose proof has already run or failed can never run again, so
the coordinator does not point the workload at it, and asks the destination
again on the next tick. Each of those ticks also re-asserts this condition, so it
reappears if its first write failed. While the destination answers, the next
tick moves the claim on. If the destination is gone for good,
`lv host rm --dead <host>` (after a proof-grade fence) releases the decision.

If its proof is stuck in flight on a live destination, release that one
workload with `lv cluster claim-release vm/<name>` (or `container/<name>`;
admin). The destination does the release: under the workload's own locks it
confirms that nothing there runs the proof (no start or operation holds the
workload, and no live domain or container of its name exists), then records and
signs that it will never run it. After that no runner can take the proof, the
destination's own resume included: every executor records a start checkpoint
before it lays anything down or starts it, and the database lets either that
checkpoint or the release land, never both. The next recovery tick then decides
the workload afresh. The command refuses, and changes nothing, when the
destination finds anything that might run the proof, when the proof has reached
its start checkpoint, when the destination runs a build that predates the
command (upgrade it), and when the destination cannot be reached: only the
destination can confirm that the proof is not running, so for one that is gone
the way out is `lv host fence-confirm <host>` and `lv host rm --dead <host>`.
If the request reached the destination but no verified answer came back (a
timeout, a dropped connection), the outcome is unknown, not refused: the
destination may have recorded the release. Run the command again (a release
already recorded is signed again, so it answers either way) or check
`lv cluster claim vm/<name>`. Every call writes a `recovery_claim.release` audit
row with result `ok`, `refused` or `unknown`;
the destination also writes its own `recovery_claim.abandon`. Only if the
destination keeps refusing is the cluster-wide stand-down left:
`enforcement.recovery_claim: false` on every host until the workload has
recovered, then back on. See
[design/recovery-claims.md](design/recovery-claims.md) §10 item 37.


### A received change this node cannot apply (`replication_entry_parked`)

A received replicated change that a constraint here refuses used to roll back
the whole push, so the sender retried it forever and every later write from
that sender waited behind it. For the natural-key identity tables —
`snapshots` and `container_snapshots`, whose rows carry a random id beside a
`UNIQUE` name that a deleted row still occupies — the node now **holds** such a
change instead, when every statement in it is an unguarded last-writer-wins
row write to one of those tables. A refusal on any other table, or of any
other kind, back-pressures as before; no table is holdable unless it is on
that list. The one other replicated table with a secondary `UNIQUE`,
`registry_credentials`, was judged not holdable: it is secret-bearing, and its
`UNIQUE` covers live rows only, so a re-create after a delete cannot collide.

- The held entry is rolled back on its own and the rest of the push applies
  once and is acknowledged, so the sender's stream keeps moving. The held
  change is recorded seen, and a relay forwards it as it forwards any entry.
- Nothing is overwritten to make room for it: the conflicting row here is
  left exactly as it is.
- It is retried automatically — after later pushes and every 30 seconds — and
  applies as soon as the conflict is gone.
- At most 256 changes are held per node; past that a refusal back-pressures
  as before.

Its limits:

- **Applying late is not always applying in order.** A later update of the
  held row from the same sender waits for the row only ten minutes, and not
  across a restart. Past that, anti-entropy carries the sender's newest row,
  which is what repairs it.
- **A delete by name reaches this node's own row.** While a held change
  conflicts with a different-id row here, a later delete of that name from the
  sender applies to the row that holds the name *here*. It is tombstoned, not
  destroyed — any local overlay or vmstate file stays on disk, unreferenced —
  which is the existing meaning of a by-name statement. Once both rows are
  tombstones the collision rules above settle them, and the held change
  releases.
- **A restart forgets the held entry, not the condition.** The sender keeps
  offering its row to anti-entropy, and every pass that refuses an identity
  table's row re-raises the same signal under that row (it clears when the row
  applies or is superseded, or when no pass has re-raised it for ten minutes
  or three anti-entropy intervals, whichever is longer).
  A restart therefore does not turn the alert green while the row is still
  divergent; expect the signal back within one anti-entropy pass.

What an operator sees:

- an ERROR line, `replicator: held a change this node cannot apply; the rest
  of the sender's stream continues`, naming the sender, sequence, table, SQL
  and failure; a WARN at most every five minutes per change while it still
  cannot apply; and an INFO line when it finally applies;
- `litevirt_replication_parked_entries{origin}`, the count held per sender
  (held entries and anti-entropy refusals of identity-table rows, each row
  once). For an anti-entropy refusal, `origin` is the row's `host_name`, the
  host that wrote it;
- `litevirt_ha_degraded{reason="replication_entry_parked"}` and an
  `ha.degraded` event whose detail names the oldest held changes: a held entry
  as `<sender> seq <n> on <table>`, an anti-entropy refusal as
  `<host> row <id> on <table> (anti-entropy)`;
- `litevirt_merge_apply_rejected_total{path="wal",reason="held"}` per table
  (counted when the change is held; the retries are not counted).

A held change means the row it writes has not changed on this node yet. Look
at the table in `lv doctor divergence` and resolve the conflict the failure
names the way the [repair flow](#operational-repair-flow) describes; the held
change then applies on its own. This is receiver-side only: an older receiver
still back-pressures, and upgrading it is what releases the sender's stream.

### A peer refuses replication: its schema is behind (`replication_peer_schema_behind`)

Evaluator `replication_schema`, subject kind `host`, subject `<peer>`,
severity warning (it degrades the cluster's health). A node whose database
schema is behind a sender's refuses every push from it (`sender DB schema
version N, local M (receiver is missing migrations ...)`), so nothing that
sender writes reaches it. Each sender that sees the refusal raises the
condition on the peer, and the refusing node raises it on itself, so its own
`lv health` says so too (a node on a release before this one does neither).
Either raises it only once the refusals have lasted five minutes: during a
normal `lv host upgrade` each host not yet pre-staged refuses the hosts
already pre-staged until its own turn, so a pass that takes longer than that
on a large cluster can show the condition until the pass ends. The evidence
records both schemas and the fix, `lv host upgrade <peer>`. The sender also logs, once per run of refusals, an
ERROR `replication: a peer refuses this node's pushes: its database schema
is behind`, naming the peer and the fix.

The usual cause is a member left on the old schema during a rollout, or one
brought back from an old backup. `lv host upgrade` pre-stages every member's
schema before it swaps any binary (see [upgrades.md](upgrades.md)), so a
rollout that used it leaves one only when `--skip-prestage` named it. Run `lv host upgrade <peer>`; its
pre-stage brings the peer's schema forward and the refused writes then apply.
The condition resolves once a sender's push at the refused schema is
accepted, or the refusing node's own schema reaches it.

### A VM held on its point-in-time overlay (`pit_overlay.held`)

Evaluator `pit_overlay`, subject kind `disk`, subject `<vm>/<disk>`, severity
warning (it degrades the cluster's health). Raised, as a replicated row, by the
host that held the VM: a layer-2 point-in-time copy left an overlay
(`.<disk file>.lv-pit`) beside the disk that may hold the guest's newest writes
and cannot be verified against the disk (docs/backups.md, "How a full replica
is copied"). The VM is not started or defined on the bare disk while it stands.
Its evidence carries the hold's text: the two files, the verdict
(`matches`, `half-written`, `pivoted` or `unknown`) with its reason, and what to
do for that verdict. `lv inspect <vm>` shows the same text as
`pitOverlayHeld`, read from this row. The hold is notified once when it begins
(`disk.pit_overlay_held` event, `replication.pit_overlay_held` notification) and
then at most once a day while it lasts.

A host that does not hold the `pit_overlay` release feature raises it for any
overlay it finds, verifiable or not: it settles none (docs/backups.md, "Older
builds and `.lv-pit` overlays"). It resolves when the hold clears: the overlay is committed or found already
merged by any later start, copy, move or define of the disk; an admin resolves
it with `lv resolve-pit-overlay <vm> <disk>`;
`lv backup restore-from --repo <repo> --vm <vm> --disk <disk> --timestamp <timestamp> --in-place`
sets the overlay aside once it has restored the disk; or the disk is deleted
(a host that cannot see the disk never resolves it). Run that
command without `--confirm` first: it prints the verdict, the disk's identity
then and now, and what `--commit` and `--discard` would each do.

### A VM started without a shared disk (`vm.shared_disk_withheld`)

Evaluator `shared_disk_start`, subject kind `vm`, subject the VM's name,
severity warning. Raised by the host that built the VM's domain from its disk
rows — a reconciler or onboot start, an operator's start or restart that
re-judged it, a redefine — without a shared disk whose row names another host
that is not proven powered off (a partial promotion leaves such a row naming
the VM's old owner; docs/backups.md). The VM was started, or defined, without
that disk. The evidence names each disk, why, and the remedy: once that host
is powered off, `lv host fence-confirm <host>`, then `lv restart <vm>`. Until
then no move of the VM re-points that disk's row, and `lv doctor repair-owner`
refuses to (docs/backups.md). `lv inspect <vm>` shows the same
text as `sharedDiskWithheld`. It is notified (`vm.shared_disk_withheld` event
and notification) when raised or when its text changes, and resolves when the
next build of the VM's domain withholds nothing.

### A volume move that did not finish (`vm.move_unresolved`)

Evaluator `move_volume`, subject kind `vm`, subject the VM's name, severity
warning. Raised by the host running an `lv move-volume` before its cutover
changes the persistent config or the disk record, and resolved when the two
agree again. It stays open after a move that could not be rolled back, or
whose daemon stopped mid-cutover. The evidence names the host holding the
move's record and, per disk, both files and whether the guest was pivoted.
Starts, migrations, replications, clones, image builds, backups and moves
settle it first or are refused (docs/storage.md, "A move that cannot be
rolled back"). It is resolved by the host holding the record; by the VM's
owner once every move it lists is proven settled there; and for every host
when the VM is deleted or a new VM takes its name. An admin resolves it by
hand with `lv health resolve vm.move_unresolved vm/<vm> --reason "…"
[--accept <path> …]`, accepted on the holding host itself, where it also
removes the record, and from any host once that host is proven powered off:
fenced or removed over an IPMI power-off or an operator's `lv host
fence-confirm <host>` of its last life. `lv health` prints each move first:
both files, whether the guest was pivoted (or the copy was named before the
move), and the move's error.

`--accept <path>` names the file to keep of one disk's move, once per disk.
A disk record is pointed at another file only on the VM's owner, and only
where it reads the same file as the holding host: its own file on a host that
is both, or a file on a mounted shared pool both hosts define alike (the same
export mounted at the same directory, the pool's own source). On a holding
host that does not own the VM, `--accept` may only name the file the disk
record already names. A resolution never keeps a file the move proves stale:
after a pivot only the copy is accepted, except in a forked history (below).
A live move with no pivot recorded is
refused without an `--accept` for its disk: nothing in the cluster knows
which file the guest wrote last, and neither the disk record nor a persistent
config naming the copy is evidence of it (the move names the copy in the
config before the pivot). The one exception is the holding host that owns the
VM, whose persistent config and disk record both name the source: no pivot
happened. Judge it from the holding host's persistent config, or from the two
files on the shared pool (the later modification time, `qemu-img compare`).
On the VM's owner, with its domain defined, the persistent config, which `lv
start` boots, must name the file each disk record is left on (point it there
with `virsh edit` or pass that file to `--accept`), and no disk record is
changed while the domain is active (`lv stop` it first); on the holding host
that owns the VM the domain must be shut off. A condition whose evidence
cannot be read is resolved only on the VM's owner with its domain shut off and
its persistent config naming the file each disk record names, and keeps the
disk records as they are; a holding host that returns with a record of a move
of one of those disks begun before the resolution drops it, unless the record
knew a pivot, a catch-up or an error: that one is raised again.

**A forked history.** A pivoted move whose condition reached the VM's new
owner only after a failover there (replication from the holding host was cut,
or the condition was resolved over unreadable evidence) leaves two histories:
the copy holds the writes the holding host made after the pivot, and the
source, which the VM may have been started on since, holds the writes made
there. Neither file is complete, and the owner's starts are refused with a
text naming both exits. Once the holding host is proven powered off, on the
VM's owner (`LV_HOST=<owner>`; the holding host too, once the VM came back to
it):

- `lv health resolve vm.move_unresolved vm/<vm> --accept <source> --reason
  "…"` keeps the writes made on the source. It is accepted when the VM
  changed hands after the move began (another owner, or a later ownership
  generation, than the move recorded); the domain may keep running when its
  persistent config and the disk record already name the source. A persistent
  config naming the copy is pointed at the source with the domain shut off;
  with no domain of the VM a start rebuilds it from the disk record. It is
  refused on any other host than the owner, and while the copy was modified after the
  source: the holding host wrote only the copy after the pivot, so nothing
  was written to the source since. `--force` takes it anyway, with the reason
  audited. A disk record naming the copy is pointed at the source (the
  domain must be shut off); the copy is kept on disk, and a
  `health.condition.hand_diverged` audit row names it.
- `--accept <copy>` keeps the holding host's writes and discards every write
  made on the source since the failover. With the owner's domain defined it
  needs the domain stopped (`lv stop`) and its persistent config pointed at
  the copy, as any other `--accept` of the copy on the owner. Once the VM
  changed hands it is taken only on the VM's owner, and refused while the
  source was modified after the copy, or either file cannot be read there,
  unless `--force` is given, with the reason audited.

With the domain running, only the file the running guest has open is kept,
whatever its persistent config and the disk record name.

The refusal prints both files' sizes and modification times (a source
modified after the copy was written since the failover) and the starts of the
VM recorded since the move began. A start through `lv start`, an HA restart
or failover, the reconciler, a health check's restart, a replacement's restart
or a promotion leaves a replicated `vm.starting` event naming the host and the
ownership generation, and a domain the reconciler finds already running a
`vm.adopted_running` event; `lv events <vm>` lists both, and the refusal
lists them; `lv audit ls --target
<vm>` lists its failover reschedules (action `failover`). The list may be
incomplete either way: an event stamped by a host whose clock runs behind,
one pruned with the VM's old events or beyond the newest 1000, one that has
not reached the host, and a start by a build that records none are not
listed. Each host also keeps a record of the ownership generation it last
started a VM at, under `move-started` in its data directory, and the refusal
names a start there since the move began.

With no domain of the VM on its owner, a start never points the disk record
at the copy by itself: nothing there proves the VM did not run on the source
since the move began. So a failover that lands between a pivot and the end
of the move holds the VM even when nothing ran it since: once the holding
host is proven powered off, `lv health resolve vm.move_unresolved vm/<vm>
--accept <copy> --reason "…"` on the owner starts it on the copy. The one
automatic repoint left is on an owner whose domain is shut off with a
persistent config naming the copy on a shared pool; it writes a
`health.condition.auto_repoint` audit row.

A disk record that names the copy is no proof either once the VM changed
hands after the move began: a host that missed the holding host's commit
reads the source, and may have run the VM there since. The owner's start is
then refused with both exits, as above; `--accept <copy>` keeps the record as
it is, and `--accept <source>` points it at the source. The holding host that
gets the VM back after it changed hands does not trust its own persistent
config either: its start is refused with both exits, and an admin's
resolution made while it was away stands only when its config names the file
the resolution left the disk record on.

These refusals do not hold an operation that cannot pick the wrong file while
the VM's domain runs on its owner: a live migration without storage (`lv
migrate`, a host drain), and a backup, replication, clone or image build
reading the file the running guest has open. The condition stays open for the
VM's next start.

A holding host that rejoins after an admin resolved its move from another
host drops its record of that move instead of raising the condition again,
unless it now owns the VM. When its record knew more than the evidence the
admin resolved (a pivot that never replicated, for example), the decision
still stands, and the host logs a warning and writes a
`health.condition.hand_diverged` audit row naming what it knew: check that the
file the disk record names holds the guest's data. While it holds an open
condition, run the resolution against it (`LV_HOST=<host>`). Removing a host
does not resolve the condition.

### A cluster default-deny held by a torn-down stack (`firewall.default_deny_orphaned`)

Evaluator `stack_reconciler`, subject kind `cluster`, subject `cluster`,
severity warning. Raised by the stack reconciler when the cluster default-deny
is owned by a compose stack that was torn down and no live stack's file asks
for it, for example after two stacks went down at the same time. The deny
stays in force: the reconciler never turns the cluster default-allow on its
own. `lv firewall default-deny off` removes it, and `lv firewall default-deny
on` keeps it as the operator's; a stack deployed later that asks for
default-deny takes it over. The condition resolves on the next pass after
either.

### A cluster default-deny nothing asks for (`stack.firewall_deny_unasked`)

Evaluator `stack_reconciler`, subject kind `cluster`, subject `cluster`,
severity warning. Raised by the stack reconciler when the cluster default-deny
is owned by a live compose stack, and neither that stack's file nor the
intent its last deploy with `sg.write` at `/` recorded asks for it, nor does
any other stack (every stack's file can be read). For example, a reconciler
pass gave the deny back to a stack while a deploy without it was being
recorded, or the stack was deployed before `cluster_policies` could be
written. No reconciler pass removes a deny on its own: one replica's view may
miss a newer deploy that asks for it. The deny stays in force.
`lv firewall default-deny off` turns it off and `lv firewall default-deny on`
keeps it as the operator's; both need `sg.write` at `/`. A stack that asks
for default-deny takes it over. The condition resolves on the next pass after
any of them.

When the cluster has no default-deny row in force and a stack asks for one
(its file, or the intent its last deploy with `sg.write` recorded, or a torn-down
stack's standing intent), the stack reconciler sets it again, owned by that
stack, whatever removed it. An intent recorded after a stack's file outranks
the file's ask: an Admin's `lv compose up` that drops the deny is not undone
while its file is still being recorded. A stack with no recorded intent
(deployed before `cluster_policies` could be written, or by a previous
release) is judged by its file alone: a redeploy of it that drops the deny
can get the deny back from the old file while it runs, and once the new file
is recorded the deny raises this condition.

### A VM that outlived its stack's teardown (`stack.vm_outlived_stack`)

Evaluator `stack_reconciler`, subject kind `vm`, subject the VM's name,
severity warning. Raised by the stack reconciler on the VM's host, once that
host's replica has caught up, for a live VM whose record names a compose
stack that was torn down while the VM existed; a VM recorded on a removed
host is not reported. A teardown deletes the VMs it listed, each as the
incarnation it listed, so a VM of a member's name created during
`compose down` (a `compose up` running beside it, or the member re-created
on another host) is left, and nothing else deletes it. The evidence names the stack, the VM's host and when each was
created and torn down. `lv rm <vm>` removes the VM; deploying the stack again
(`lv compose up`) makes it the stack's again. The condition resolves on the
next pass after either. A VM created after the stack was torn down is a
deploy of that stack name in progress, and is not reported.

### A stack firewall a caller could not remove (`stack.firewall_teardown_held`)

Evaluator `stack_reconciler`, subject kind `stack`, subject the stack's
name, severity warning. `lv compose down` and `lv compose up` by a caller
without `sg.write` at `/` run only where the entry node sees no firewall for
the stack, and that node may hold an older record of it. Raised by the stack
reconciler on a host that holds a firewall of the stack (a security group,
ip set, cluster or host rule or firewall default it owns, a stored file that
declares a firewall or cannot be read, or the intent the stack's last deploy
with `sg.write` recorded) in four cases:

- the stack is `deleting` and its teardown may not remove that firewall: its
  caller did not hold `sg.write` at `/`, or its record does not say (begun by
  an older build, before `cluster_policies` could be written, or re-stamped
  since). The firewall stays in force and the stack stays `deleting`; its
  workloads and networks are still removed, and `lv compose up` of the name
  is refused naming this condition.
- the stack was torn down while this host holds a security group, ip set,
  or cluster or host rule it owns, written before the teardown. They stay in
  force. A cluster default-deny it owns is `firewall.default_deny_orphaned`.
- the stack was torn down, and the intent its last deploy with `sg.write`
  recorded still stands and declares a firewall: the teardown's caller did
  not hold `sg.write` at `/`, it ran on a host still on the previous
  release, or a deploy with `sg.write` recorded the intent after it. It
  still counts for the name: a default-deny it asked for passes to it when
  the stack that owns the deny goes, and stays with it, and `lv compose up`
  of the name without `sg.write` is refused.
- the stack is live and its file no longer declares the firewall, or the
  default-deny, its last deploy with `sg.write` declared: a deploy that
  recorded no intent replaced it (one without `sg.write`, or one on a host
  still on the previous release), or that deploy failed after writing its
  firewall and before recording its file. What the recorded deploy declared still
  stands: the stack still asks for the default-deny, and a deploy without
  `sg.write` is still refused. A stored file this build cannot read keeps the condition open,
  saying whether it still declares that is unknown.

An Admin finishes a teardown with `lv compose down --name <stack>`, from any
node, record or not, and settles a live stack's firewall with `lv compose up`
of the file it should have; `lv role grant NetworkAdmin <principal> --path /
--propagate` lets another caller do either. The condition resolves on the
next pass after that: a torn-down stack's rows are gone and an Admin's
`lv compose down --name <stack>` has cleared its intent, or a live stack's
file declares what its last deploy with `sg.write` did. A pass that cannot
read the stacks or their intents leaves the condition as it is.

### SYN-flood condition (`firewall.synflood.unavailable`)

Raised per host by its firewall reconciler, severity warning, and resolved on
the next pass that no longer finds the cause. docs/firewall.md, "SYN-flood
protection". An unreadable SYN-flood policy row raises
`firewall.policy.unreadable` (see "Firewall logging and policy conditions").

| Condition | Raised when |
|---|---|
| `firewall.synflood.unavailable` | the SYN-flood policy is on for this host, but its kernel refused the SYN-flood rules of one or both address families at daemon start (`nft_limit` missing, or an nft that cannot key a set by an IPv6 prefix): that family's SYNs to its guest NICs are not limited, and the evidence names it. Restart the daemon once it can |

### Tag-group conditions (`firewall.tag_group.*`)

Raised per host by its firewall reconciler, and resolved on the next pass that
no longer finds the cause. Each names the rules, groups or workloads involved
(at most ten, then a count) and the command that fixes them. docs/firewall.md,
"Tag groups", says what each one holds back.

| Condition | Severity | Raised when |
|---|---|---|
| `firewall.tag_group.missing` | critical | a rule has named a tag group this host's replica does not hold for a minute: an accept matches nothing, a drop or reject loses its address match |
| `firewall.tag_group.unreadable` | critical | a group's row cannot be read here, or its set cannot be declared (`<x>_v6` beside `<x>`) |
| `firewall.tag_group.tags_unreadable` | critical | a workload's tags row cannot be read: its NICs are held at drop |
| `firewall.tag_group.identity_shared` | critical | two live workloads hold one firewall identity (a copy): every NIC of each is held at drop |
| `firewall.tag_group.identity_lost` | critical | a workload has no firewall identity while a tags row of an earlier incarnation of its name remains: its NICs are held at drop as for an unreadable tags row; the evidence gives the `lv firewall tag set` command |

`litevirt_firewall_tag_group_members{group}` is a gauge of each group's members
in this host's view, 0 for a group this host cannot read. Hosts can differ for
up to one replication lag plus the 30 second reconcile tick;
`lv firewall tag-group ls --members` shows the members.

### Firewall logging and policy conditions

Raised per host; each resolves when its cause goes. docs/firewall.md,
"Logging", has the detail.

| Condition | Severity | Raised when |
|---|---|---|
| `firewall.log.unavailable` | warning | at start the kernel or nft refused the logging forms (`nft_log`, `nfnetlink_log`, `nft_limit`): no packet is logged on this host; the per-NIC rules are unaffected. Load the modules and restart the daemon |
| `firewall.log.listener` | warning | the daemon cannot hold its NFLOG group (another program holds it): no log line is rendered on this host, so packets are not logged and nothing reaches that program (a listener that loses the group has its lines removed by the next pass, run at once). Set `firewall.log_group` to a free group and restart |
| `firewall.policy.unreadable` | warning | a firewall policy row cannot be read here; the evidence names each row and the fallback it is read as: a SYN-flood policy (`firewall_synflood`, `firewall_synflood/<host>`) as on at 200/1000, a log policy (`firewall_log`, `firewall_log/<host>`) as logging off at the default budget. Set that policy again to replace the row: `lv firewall synflood on`, `off` or `inherit --scope <host>`, or `lv firewall log-policy on`, `off` or `inherit --scope <host>` |

`litevirt_firewall_log_records_total{outcome}` counts log records `kept`,
`rate_limited` (over `firewall.log_max_rate`) and lost to `overflow`.

### Deferred out-of-band stop sync after a restart or rejoin

When a VM's domain is found shut off out of band (a crash, an external
`virsh destroy`, a fence that powered the host off), the owning host's
reconciler syncs the cluster record to `stopped`. That write is decided from
the host's own replica and replicated to every peer, so it waits until that
replica is known to be current: the host must have completed an anti-entropy
exchange with at least one peer — digests compared equal, or the peer's state
merged without error — since the daemon started and since the host last lost
sight of every gossip peer. Until then the sync is deferred and retried every
pass, and the journal says so once per VM:

```
reconciler: VM looks stopped out-of-band, but deferring the cluster state sync (retries each pass) vm=ha1 cause="replica not caught up" ...
replica caught up: anti-entropy exchange with a peer completed; decisions published from the local replica may proceed peer=node-1
```

The reason is a host that comes back after a fence: its replica can still name
it the owner of a VM that was rescheduled and is running elsewhere, and an
unguarded sync would replicate `stopped` over the real owner's row (the VM
lists as stopped while it runs; the owner's health sweep flips it back each
time). This guard is on in every configuration; with `enforcement.owner_epoch`
enabled and latched the write is additionally epoch-conditioned. While the
replica is not caught up, the anti-entropy loop tries an exchange every few
seconds (starting right after the daemon starts, and right after it loses
sight of every peer) instead of waiting for its interval
(`anti_entropy_interval_sec`), so with a peer reachable the deferral lasts
seconds. Passes are still at least 12 s apart, so a first try that finds no
peer yet costs up to about 12 s. A single-node cluster — no other host in the
hosts table — is not gated, and neither is a node with no gossip peer whose
only other hosts are `joining` (`lv host add` admitted them and their daemons
have not started, as on a founder adding its second host). The same sync is also withheld, on a current
replica, while the VM has an active ownership condition (`vm_dual_run`,
`runtime_owner_mismatch`, `owner_epoch_mismatch`), matching the self-heal
restart.

A host that stays `replica not caught up` is not completing anti-entropy with
anyone: check that it sees gossip peers and can reach them over gRPC.

### Workload commands refused after a restart or rejoin

The same catch-up gates the commands that act on an existing workload through
the host its record names: start, stop, restart, delete, rebuild, update,
migrate, hotplug, resize, snapshot, backup and restore of VMs and containers,
and `lv compose up` / `lv compose down`. Until the serving host's replica has
caught up, they fail with `Unavailable` and nothing is touched:

```
DeleteVM refused on node-1: this node's replica has not caught up with the cluster yet (no anti-entropy exchange with a peer has completed since this process started; 3s so far), so it cannot tell which host owns the workload now. It retries the exchange every few seconds and this clears as soon as one peer answers — retry shortly, or run the command against another node
```

Served from a stale record, such a command acts on the wrong copy and writes
the stale owner back. Observed on a lab: a VM rescheduled from node-1 to node-4
while node-1 was down; node-1 came back and served `lv compose down` three
seconds before its first anti-entropy exchange. It destroyed its own shut-off
leftover and tombstoned the record naming itself, and that tombstone replaced
the owner's record everywhere — the VM kept running on node-4 with no record.
Retry after the `replica caught up` journal line, or run the command on any
other host. With a peer reachable that line follows a daemon restart within
seconds; the refusal says how long the node has been waiting, so a count that
keeps growing points at the peers rather than the node (see below). A
single-node cluster is not gated, nor is a node with no gossip peer whose only
other hosts are still `joining` (admitted, their daemons not started yet). Once
such a host's daemon starts it is a peer like any other, and the node waits for
its first exchange with it.

A host whose peers are all down cannot catch up, so it refuses these commands
until one of them answers. That is deliberate: it cannot know whether another
host took the workload over while it was away. If those peers are gone for
good, fence them and remove them with `lv host rm --dead <host>`; a host left
as the only member is a single-node cluster and is no longer gated.

### Gossip isolation (`gossip_isolated`)

A node that has lost every gossip peer, and whose re-join attempts reach none
of its seeds or admitted hosts, raises a `gossip_isolated` condition about
**itself**. The subject is the host, keyed on the node's own name, so each row
has exactly one writer. No leader could raise this one: a leader cannot see
another node's gossip view, and an isolated node cannot reach the leader.

| Raised when | Clears when |
|---|---|
| A re-join pass (every 30–45 s) finds no visible peers **and** fails to join any target. Observed on the first such pass, confirmed on the second. The evidence carries the last join error. **Warning** severity: an isolated node is how a workload can end up running in two places — its peers may fence it and restart its VMs — but the isolation is the precondition, not the corruption. | The first pass that sees a peer, or that re-joins successfully. No run of clean passes is needed: visible peers are positive evidence of membership, not an absence of evidence of isolation. A condition left open by a previous daemon process is resolved too. |

**Where you can see it.** Run `lv health` on the isolated node itself — it
reads its own local store and shows the condition immediately. Its peers see
the row only after replication resumes, by which point it is normally resolved;
`lv health --resolved` then shows the episode with its `first_seen` and
`resolved_at`. From the peers' side, the live signal while the node is isolated
is its connectivity edges going `suspect`.

A single-node cluster with no seeds is never reported: it has nobody to be
isolated from.

A node that sees **some** peers is not isolated, even when hosts it lists are
missing from gossip, as on either side of a partition. The same pass dials those
missing hosts, on a per-host backoff, so the two sides merge again once the
network heals. It logs what came back and what did not, but raises no condition.
See [Gossip membership heals itself after a
partition](operating-model.md#gossip-membership-heals-itself-after-a-partition).

### A host whose boot kept its fence (`boot_kept_fence`)

A host recorded `fenced` or `offline` returns to service on its own when its
daemon boots ([migration-failover.md](migration-failover.md), "A graceful
restart stays `upgrading` until it serves"), except when that boot cannot
write `boot-unclean-history` in its `data_dir` (a full or read-only disk). It
then keeps the fence: its daemon runs and serves, and the host stays `fenced` or
`offline`, unplaceable. Evaluator `host_boot`; the host writes the row about
**itself**, and logs the same at warning level.

| Raised when | Clears when |
|---|---|
| The boot of a host recorded `fenced` or `offline` could not record its unclean-boot history and kept the fence. **Warning** severity. The evidence names the state kept, the cause and the remedy. | The host is recorded as anything but `fenced` or `offline` (`lv host undrain <host>`). One left open by an earlier daemon process is resolved by the next boot once that holds. |

Fix what the cause names, confirm the host should run workloads again, then
run `lv host undrain <host>`.

### Resource pressure (`host.pressure`)

A host's own sampler grades its data directory, its pools, and the daemon's
descriptors and memory ([configuration](configuration.md#resource-pressure)).
The host reports the grade on the readiness probe. Evaluator `pressure`,
subject the host. The failover lease holder writes it from each host's latest
probe answer, so a host whose disk is full is still described by a peer.

| Raised when | Clears when |
|---|---|
| The host reports `warn` or `degrade` (**warning**) or `critical` (**critical**). The evidence names the level, the pressured resources, `since`, `time_to_full_sec`, `sampled_at` and `stale`. | The host reports `ok`, answers without pressure (`pressure.enabled: false`, or an older build), or is removed. |

The lease holder acts only on an answer at most 10 minutes old. A host it has
no such answer from (down, cut off, or in maintenance) keeps its condition as
it was, `last_seen` included. With no lease holder, no condition is written,
while `lv host inspect` and the metrics still show each host's level.

`lv host inspect <host>` shows every resource's free and total. Free space on
the named filesystem, or move workloads off with `lv host drain <host>`. The
condition clears on its own once the level does. Nothing is refused because of
it in this release, and a pressured host stays ready and keeps its vote.

### Two hosts admitted at one address (`host.address_shared`)

`lv host add` admits one name per machine: the admission write is refused, in
its own transaction, while another live or joining host holds the address at
gRPC port 7443. That check sees only the replica that admits. Two admissions
made on two hosts at once, each before the other's row reached it, can both be
written, and both names then point at one machine. Evaluator `host_admission`,
subject `cluster/hosts`; the leader-lease holder writes it.

| Raised when | Clears when |
|---|---|
| Two live or joining hosts hold one address at one gRPC port (a port of 0 matches any). **Warning** severity. The evidence names each pair and the address. | No two live hosts share an address and port. |

A host recorded `active` there keeps the address; otherwise the one admitted
first, or the lesser name when both were admitted at the same moment. The
evidence names it. The other is never recorded `active`: the write that would
record it checks the address in its own transaction, a joining host that does
not keep its address stays `joining` at boot, one already `upgrading` stays so
(`upgrading_unconfirmed` names the host that holds the address), and the
`lv host add` that admitted it is refused before it installs anything. The
machine serves the certificate of one of them. Remove the other with
`lv host rm <host>`, or `lv host rm --dead <host>` if it is fenced and gone for
good.

### A host stuck `upgrading` while its daemon runs (`upgrading_unconfirmed`)

After a restart the host stays `upgrading` until its daemon answers its own
Ping and records it `active` ([migration-failover.md](migration-failover.md),
"A graceful restart stays `upgrading` until it serves"). Peers that cannot
reach such a host fence it once it has been `upgrading` for 2 minutes. Peers
that reach it do not, so a daemon that runs but never records itself `active`
leaves its host unplaceable, listed as draining, and nothing else shows why.
Evaluator `host_boot`; the host writes the row about **itself**.

| Raised when | Clears when |
|---|---|
| The host has been recorded `upgrading` for 2 minutes or more, and its daemon's serving check still has not recorded it `active`: its own Ping does not answer, or the write that records it `active` fails (that write is retried with backoff, 1 s doubling to 1 min, until it lands). **Warning** severity. The evidence names the cause, the time the host turned `upgrading` and the remedy. | The check records the host `active`, or finds it recorded as something else (fenced, drained, undrained), whether or not its own Ping answers yet. One left open by an earlier daemon process is resolved too. While it stays open its row is written again only when the cause changes, and otherwise every 10 minutes. |

While it is open the host also exports `litevirt_host_upgrading_unconfirmed 1`,
and logs the cause and the remedy at error level. Fix what the cause names:
the daemon's own mTLS client or its listener on 127.0.0.1, or the write (a
WAL-quarantined node writes nothing, this condition included, so there only
the log and the metric show it). The host then records itself `active`. Or run
`lv host undrain <host>` to record it `active` now; it does so only if the
host's daemon answers a Ping from the node handling the undrain.

### Partition pause (`partition_paused`, `partition_pause_failed`, `partition_one_way`, `vm_settled`, `vm_settle_declined`)

Evaluator `partition_pause` (design/partition-pause.md). Every row is written by
the host it is about, except `partition_one_way`, which the failover lease
holder writes.

- `partition_paused` (host, warning): this host lost the voter majority for
  10 s and paused its recoverable workloads itself. The evidence lists them.
  It resolves when the last one resumes or its record is dropped, also when
  the daemon restarted in between (a power cycle while paused). Each
  workload resumes on its own once the majority is back, its row still names
  this host at the same owner epoch and incarnation, and a majority of
  voters confirms that this host is not fenced and that no recovery claim
  moved it. One that stays paused is logged
  with the reason:
  ```
  partition-pause: paused workload       kind=vm name=<vm> reason="lost the voter majority for 10s (…)"
  partition-pause: resumed workload      kind=vm name=<vm> reason="majority regained; …"
  partition-pause: workload stays paused kind=vm name=<vm> reason="voter node-4 has node-1 HOST_OFFLINE"
  partition-pause: dropped a pause record that no longer describes a paused workload kind=ct name=<ct> reason="the container no longer exists on this host and has no live row here"
  ```
  A record whose VM domain is undefined, or whose container has no live row on
  this host and no longer exists in LXC, is dropped with the last line.
  A VM is resumed only while it is paused by this host's own pause: libvirt's
  paused reason is `user`, and the domain carries the mark the pause set. One
  that an operator suspended or QEMU paused on a disk I/O error is held, and
  the evidence names it under `not_paused_by_this_host`:
  ```
  partition-pause: workload stays paused kind=vm name=<vm> reason="the domain is paused on a disk I/O error, not by this host's partition pause; …"
  ```
  No `lv` command resumes a paused VM (`lv stop` and `lv start` drop the
  record but reboot the guest). On the VM's host, once it should run:
  ```
  virsh resume <vm>
  ```
  The next pass drops the record. For an I/O-error pause, free space in the
  storage pool or repair the disk first: a resume into the same failure
  pauses the guest again at once. A VM whose pause mark could not be set is
  held the same way, and the reason then reads "this host's pause could not
  mark the domain". A VM left paused on purpose keeps `partition_paused`
  open, and memory snapshots and NIC firewall arming stay refused for it,
  until it is resumed or stopped.
  A host the majority fenced while it was paused stays paused until
  `lv host undrain` (or until failover returns it to active, when its fence
  moved nothing). A workload that a certified claim moved is stopped by the
  settle step below, not resumed.

  A resume (an Unfreeze for a container) that libvirt or LXC has not
  answered within its 3 s step is abandoned, and the workload stays paused
  with `reason="resume failed: did not return within …"` (`unfreeze
  failed: …`). The call is still out, and when it lands later:
  ```
  partition-pause: an abandoned resume landed late with the voter majority there throughout and confirming again; it stands kind=vm name=<vm>
  partition-pause: an abandoned resume landed late; paused again kind=vm name=<vm>
  ```
  It stands only when the host read the majority as present at every
  reading since the step began, reads it present again, and a majority of
  voters confirms the workload again. Otherwise it is paused again at once,
  and a later pass resumes it on a fresh confirmation. A libvirtd that is
  slow on every call therefore still resumes the VM, a few seconds late.

  A call that never returns means libvirtd, or the domain's QEMU monitor, is
  wedged. The VM stays paused, and `partition_paused` stays open, for as
  long as it lasts. Restarting libvirtd (`systemctl restart libvirtd`) makes
  the call fail, and the next pass resumes the VM. If the domain's QEMU is
  wedged itself, `lv stop <vm> --force` and `lv start <vm>` restart the
  guest.

  If the majority is lost again while such a call is out, the pause pass
  kills the VM's QEMU directly, because a call that may land cannot be
  undone in time:
  ```
  partition-pause: killed the QEMU of a VM whose abandoned resume was still out under a lost majority; it cannot land now name=<vm>
  ```
  libvirt then reports the domain shut off, crashed. The majority recovers it
  from its disks. If the majority never fenced this host, the VM's restart
  policy decides, as for any crash, once this host holds a quorum. If the
  kill cannot be done (no pid file, the pid is not that domain's QEMU, or
  the QEMU has not exited within the call's timeout, typically stuck flushing
  its disks to cut storage), and for a container, whose Unfreeze has no such stop, the workload is
  reported in `partition_pause_failed`.
- `partition_pause_failed` (host, critical): this host lost the majority and
  could not pause a workload it had to. While it is open, the majority does
  not rely on this host's pause, so a best-effort fence of it is no fence, and
  its workloads are held until `lv host fence-confirm <host>`.
  With a verified hardware watchdog armed the host also self-fences. It
  resolves once every pause succeeds or the majority returns. A record that
  cannot be written (a full `data_dir`), or whose write does not return within
  2 s, raises it only under `enforcement.partition_pause_record_failure:
  self_fence`, or `reserve` with the reserve unwritable too, and only with a
  verified watchdog armed; otherwise the host pauses anyway and logs
  `partition-pause: cannot write the pause record to the record directory;
  pausing with it held in reserve` (or `memory`), with
  `fallback=no_verified_watchdog` when `reserve` or `self_fence` fell back for
  want of a watchdog.
- `partition_one_way` (host, critical): a quorum of voters cannot reach the
  host while the host's own rows, written after those failures began, still
  mark a majority healthy. That is a one-way partition, in which the host may
  never pause. Nothing is recovered differently; find the asymmetric link.
  The lease holder resolves it once the quorum reaches the host again or the
  host no longer counts a majority, whichever holder raised it (a row
  another holder raised stands for one lease, 45 s, first). It is not
  raised for a host restarting (`upgrading`) within its allowance. A host
  booting back from a fence comes up `fenced` or `offline`, not `upgrading`,
  and can still raise it for the 15-25 s before its gRPC server serves.
- `vm_settled` / `ct_settled` (`<name>@<host>`, warning): a host came back
  holding a copy of a workload that a decided recovery claim, whose
  certificate verifies, gave to another host at the same incarnation and an
  owner epoch at least its own, on a proof its destination completed, while
  the destination's own runtime reports the workload running. A copy this
  host's partition pause holds paused does not wait for that: it is stopped
  as soon as the proof is live (not failed, not taken by another host),
  because a paused QEMU keeps a shared disk's image lock and the destination
  cannot start the VM until it is gone. That destroy waits for no resume:
  it runs under the pause's mark lock, only while the domain is still
  paused with the pause's mark, and a pass that finds otherwise declines
  with reason class `pause_changed`. The host
  stopped its copy (a VM is destroyed, which keeps its definition and disks)
  and wrote a `partition.settle` audit row. The leftover cleanup then handles the shut-off domain as usual.
  The host resolves `vm_settled` on the pass that finds no domain of that
  name defined there, or the VM's row naming it again.
- `vm_settle_declined` (`<name>@<host>`, warning): the host runs a copy of a
  VM whose row names another host, and settle declined to stop it for two
  passes in a row. The evidence carries the `reason` (the clause of the proof
  that is missing), what the host knows of its copy (`local`: incarnation,
  owner epoch, and where it read them), and a `remedy`. The same is logged
  once per kind of reason (`reason_class`, for example
  `incarnation_unknown` or `destination_unreachable`) and again every 10
  minutes while it lasts:
  ```
  partition-settle: declined to stop a local copy whose row names another host vm=<vm> row_host=<dest> reason_class=<class> reason="…" remedy="…"
  ```
  A common reason is `the local copy's incarnation is unknown`: an older
  build defined the domain, so it carries no incarnation stamp. Settle does
  not fall back to the domain UUID, because a live restore or a renamed
  promote gives a new incarnation an earlier one's UUID.

  `proof_uncertified` means the recovery completed on the destination, but
  its proof carries no certificate: it was minted while recovery claims were
  not enforced, as on a derived voter set. It is reported only for a live
  proof at an owner epoch at least the local copy's, and only when no
  certified proof gave a reason of its own. Settle acts only on a certificate,
  so a paused copy stays paused. There is no claim for `lv cluster claim` to
  show. Confirm with `virsh domstate <vm>` on the destination that it runs
  there, then stop the copy on this host with `virsh destroy <vm>`, as below.

  The row naming another host is not proof on its own: a converged-wrong
  `host_name` looks exactly the same. Before stopping anything, confirm which
  copy is current. `lv cluster claim vm/<vm>` shows the decided claim and its
  destination, and `virsh domstate <vm>` on that destination shows whether it
  runs there. Only if the claim gave the VM to that host and it runs it there
  is the local copy a superseded duplicate. Stop it on this host with
  `virsh destroy <vm>`. Its disks are kept. The next reconcile pass undefines
  a destroyed domain whose row moved; its NVRAM and vTPM state, if it has
  any, go into `<data_dir>/fwmig-quarantine/<vm>-reconciled-<unix>/`.
  `lv host superseded-disks <host>` lists these directories. They are kept
  while a VM of that name exists, and removed by the hourly sweep once it is
  gone and they are older than `superseded_disk_retention_days`; remove one
  by hand with `--remove <dir>`, or put one back as the VM's firmware state
  with `--restore <dir>`. While the reconciler is part way through one
  (`<vm>-reconciling-<uuid>`), the VM's start on that host is refused, so it
  never boots on blank firmware state. Otherwise leave the local copy running.
  The condition resolves once the copy is no longer declined.

### Audit chain held (`audit_chain_held`)

A host re-added under a name with audit history raises `audit_chain_held` about
**itself** while it holds its own audit rows until that history has reached it
from its peers ([audit-log.md](audit-log.md#rebuilding-a-host-under-its-old-name)).
Its audit rows are durable in its local spool but are not yet in the cluster's
audit log, so `lv audit ls` elsewhere does not show what was done on it.

| Raised when | Clears when |
|---|---|
| The host's admission record (`<pki_dir>/audit-rejoin.json`) names a row of its chain its replica does not hold; re-raised once a minute while held. **Warning**; **critical** once the hold is full (10000 rows), when the host refuses every audited client action and login with `Unavailable`. The evidence carries `held_rows` and `waiting_for`. | The recorded row, and a row at every seq below it, have arrived, and every held row has landed. |

**If it does not clear,** the host cannot reach a peer holding its history:
check `lv health` for replication and gossip, and that the survivors are
reachable from it. `waiting_for` saying the row "does not hash" means the
replica holds a different history than the cluster had for the name — the
hold stays closed rather than fork the chain; investigate before anything else.
`waiting_for` naming a missing seq means the row below the recorded one has not
arrived; if no node holds it, the history has a gap and the hold cannot open by
itself. If no node will ever hold the history, removing `<pki_dir>/audit-rejoin.json`
on the host and restarting its daemon ends the hold at the cost of a permanent
fork finding for that host
([audit-log.md](audit-log.md#rebuilding-a-host-under-its-old-name)).

### Own row held (`own_row_held`)

A daemon raises `own_row_held` about **itself** while it makes no write to its
own `hosts` row, because that row is not the cluster's admission for the
certificate the daemon serves ([upgrades.md](upgrades.md)). Its boot report,
address correction and certificate re-record wait; replication and its gRPC
server run.

| Raised when | Clears when |
|---|---|
| At start or at runtime, the host's own row is live and names a serial other than the installed certificate's (evidence `arm` `a`), or is removed (`arm` `b`). Re-raised once a minute while held. **Warning**. The evidence carries `reason` (`at_start`; `superseded`: another admission replaced the row; `removed`), `held_for`, `timed_out`, `installed_serial` and `recorded_serial`. | The host's own row is live and names the installed certificate's serial. |

When the hold opens, the daemon writes its boot report, and a re-added host
records itself active once it serves, without a restart. Anti-entropy can
bring the re-admission's `hosts` row before its membership row, so the hold
can open while the host still reads the removed machine's state; the daemon
writes the boot report again when the admission's `joining` reaches it.

A host whose installed certificate renewed the recorded one (`lv host
renew-cert`, live or while the host was down) is not held: it records the new
serial at once. Neither is a host whose certificate was reissued outside
`lv host renew-cert` while its row is still the admission it was last admitted
under, which it records in `<pki_dir>/own-admission.json`: it records the
reissued serial when the daemon starts, so `auth.trust_rotated_peer_certs`
converges it.

At incarnation 1 or higher, a certificate swapped in while the daemon runs that
is not a renewal of the recorded one is not recorded until the daemon restarts,
and peers refuse it until then. The host raises `certificate/cert_swapped_at_runtime`
about itself (**warning**; evidence `recorded_serial`, `serving_serial` and
`remedy`). Peers refuse that host's writes until then, so the condition is
only on that host's own replica: run `lv health` against that host
(`LV_HOST=<its address> lv health`). Restart the daemon on that host
(`systemctl restart litevirt`); the condition clears once the serial is
recorded. The restart records it only when the host remembers its admission;
if the condition is still open after the restart, the restart was held, and
`own_row_held` below says why.

A hold raised at start over a row at incarnation 0 reports `timed_out` after
ten minutes, and the daemon then makes the writes the previous release makes.
A hold over a row at incarnation 1 or higher, and a hold raised at runtime
(`superseded`, `removed`), never times out. A held row that becomes another
admission while held is reported as `superseded`.

**`reason` `at_start`** is raised at start, for one of two causes:

- the host was re-added while its data directory still held its old database,
  so its replica still holds its own old row. This clears once the host's
  replica receives the re-admission from a peer;
- the host is at incarnation 1 or higher, its certificate was reissued outside
  `lv host renew-cert` (its PKI directory was regenerated or restored), and its
  `<pki_dir>/own-admission.json` is missing or records another admission. This
  does not clear by itself.

If it does not clear:

1. Check that a peer is reachable from the host.
2. On another node, run `lv host inspect <name>` and note the serial it shows.
   That is the cluster's admission for the name, and it is the serial every
   step below means. Do not use `recorded_serial` from `lv health` on this
   host: it is this host's own replica, which may be stale. If the serial from
   `lv host inspect` equals this host's `installed_serial`, the re-admission
   has not reached the host yet: go back to step 1.
3. Find out whether any machine **holds** the serial from step 2, running or
   powered off: its `<pki_dir>/host.crt` carries that serial
   (`openssl x509 -noout -serial -in <pki_dir>/host.crt` prints it in upper
   case). If a machine other than this host holds it, this host is superseded:
   follow the `superseded` procedure below, and do not remove the name. A
   machine that is powered off still holds its admission.
4. If this host holds a certificate and key with the serial from step 2 (for
   example in a backup of its PKI directory), put them back as
   `<pki_dir>/host.crt` and `<pki_dir>/host.key`. The hold then opens by
   itself.
5. Only when step 3 found no machine, running or powered off, that holds the
   serial from step 2, and step 4 did not apply: stop the daemon on this host,
   then remove the host and add it again.

**`reason` `superseded`** is a host whose admission another `lv host add` of
the same name replaced. Peers no longer accept its certificate. To recover:

1. On another node, run `lv host inspect <name>` and note the serial it shows.
   That is the cluster's admission for the name, and it is the serial every
   step below means. Do not use `recorded_serial` from `lv health` on the
   superseded machine: it is that machine's own replica, which may be stale.
2. Stop the litevirt daemon on the superseded machine, outside the cluster,
   and confirm that its workloads are stopped.
3. Find the machine that **holds** the serial from step 1, running or powered
   off: its `<pki_dir>/host.crt` carries that serial
   (`openssl x509 -noout -serial -in <pki_dir>/host.crt` prints it in upper
   case). A machine that is powered off still holds its admission. If it is
   the machine to keep, leave the name alone: wipe the superseded machine's
   data directory before adding it under any name.
4. Run `lv host rm --dead <name>` only when step 3 found no machine, running
   or powered off, that holds the serial from step 1, or when the operator has
   decided to retire the machine that holds it, after stopping that machine's
   daemon and confirming its workloads are stopped. Run it only after step 2
   is confirmed, then run `lv host add` for the machine to
   keep. `lv host add` is refused while workloads are still recorded on the
   name; `lv health` shows `ha.claim.stranded` for any the failover
   coordinator cannot recover.

**`reason` `removed`** is a host removed while its daemon runs. It clears if
the host is re-added and its re-admission reaches it.

### Audit replica not seeded (`audit_not_seeded`)

A node whose replica is not known to hold the cluster's history raises
`audit_not_seeded` about **itself**. `lv host add` run against it is refused,
because the audit chain position it would hand the new machine may be missing
history ([audit-log.md](audit-log.md#rebuilding-a-host-under-its-old-name)).
Run `lv host add` against a node without this condition.

| Raised when | Clears when |
|---|---|
| The daemon starts on a replica that is not seeded, and every 30 s after that. **Info** for the ordinary case: a node that has just joined and has not yet completed an exchange with a seeded node on this build. **Warning**, with an error line, when `<data_dir>/audit-seeded.json` exists but cannot be read or written; the node then stays not seeded (it fails closed). The evidence carries `problem`. | The replica becomes seeded: an anti-entropy exchange with a seeded node that is not holding its own audit rows. |

**If it does not clear,** check that a seeded node on this build is reachable;
a node on an older build cannot seed one. With `problem` set, fix or remove the
marker file and restart; while the marker cannot be written, the node also
holds its own audit rows (`audit_chain_held`). If no node in the cluster is
seeded, see "No seeded node" in
[audit-log.md](audit-log.md#rebuilding-a-host-under-its-old-name): root asserts
with the `assert_nonce` in the node's marker, which neither this condition, the
log, nor any RPC shows, and which a marker with `problem` set does not have. The
condition row is rewritten only when what it says changes.

### Container mount prefix shares a protected filesystem (`container_mount_prefix_overlap`)

A node raises `container_mount_prefix_overlap` (warning) about **itself** when
one of its `containers.bind_mount_paths` prefixes reaches a protected tree by
filesystem identity but not by path — the prefix is on a filesystem that also
holds `data_dir`, a pool or a backup repo, mounted somewhere else
([passthrough.md](passthrough.md)). The daemon still starts: such a config
loaded before identity was checked. Mount sources beneath the prefix that lie
in the protected tree are refused when they are resolved; the rest of the
prefix keeps working. The evidence carries `overlaps`, one line per prefix,
naming the prefix and the tree; the daemon log says the same at start.

| Raised when | Clears when |
|---|---|
| The daemon starts with such a prefix configured. | The daemon starts with no such prefix (the prefix moved to a filesystem of its own, or removed). |

### vTPM state not durable (`vtpm_state_not_durable`)

Evaluator `vtpm`, subject kind `host`, severity warning. A node with swtpm
installed and `vtpm_state_sync` on (the default, docs/configuration.md) sets
the sync attribute on `/var/lib/libvirt/swtpm` at start and every minute, so
each vTPM state write is on disk before the TPM command returns. The node
raises `vtpm_state_not_durable` about **itself** when it cannot. The evidence
carries `state`, `path`, `fs`, `error` and `remedy`:

- `unsupported`: the filesystem refuses the attribute (tmpfs, NFS, ZFS);
- `not_inherited`: a file created there does not get it (btrfs);
- `rename_not_synchronous`: the filesystem does not commit swtpm's rename of
  the state file synchronously (xfs mounted without `dirsync` or `wsync`,
  or a filesystem not known to);
- `failed`: some entries could not be read or set, or were left alone and
  reported: a directory deeper than libvirt's layout or with more than
  100000 entries, a directory on another filesystem, or a hard-linked file
  (`error` names them);
- `timed_out`: a pass has not finished within 10 seconds (a hung NFS server).
  The vTPM capability label stays false until a pass completes.

A vTPM write made shortly before a power cut on that host can be lost.

While it is open, or before the host's first pass has completed, the host is
no target of a live firmware move: its `litevirt.fw_live_migrate` label is
false, and a move's Prepare refuses there with the condition and its remedy.
vTPM itself is still offered on the host.

| Raised when | Clears when |
|---|---|
| A pass finds the tree cannot be made synchronous, or does not finish. | A pass makes it synchronous, `vtpm_state_sync: false` is set and the daemon restarted, or swtpm is removed from the host. A node rolled back to a build without this check leaves the row as it was until it runs a build that checks again. |

### Operation not reapable (`operation_unreapable`)

Every node runs the operation reaper hourly. It tombstones each finished
operation, and its steps, once the last step is older than
`tombstone_gc_retention_hours` (default 24) and no VM barrier names it. A node
raises `operation_unreapable` (warning) about **itself** when a pass could not
reap one or more of those operations. The reaper goes on to the next operation,
so one failure does not hold the others. Each failure is logged once per pass as
`operation reaper: could not reap an operation`, with `operation_id` and
`error`, for up to 20 operations; past that, one line,
`operation reaper: could not reap more operations`, carries `more` and `total`.
The evidence carries `count`, `operations` (up to 20, each with `id`
and `error`) and `remedy`.

| Raised when | Clears when |
|---|---|
| A reaper pass could not read an operation's steps or write its tombstone. | A complete pass has no failures. A pass that ends early never clears it: WAL quarantine, shutdown, or a failure of the pass's opening reads. A pass that ends early after failures raises it with only the operations reached, so `count` can be low until the next complete pass. |

**If it does not clear,** the `error` of each listed operation says why its
steps could not be read or its tombstone could not be written. Fix that cause;
the next pass retries every listed operation.

### UEFI vars flush failed (`nvram_flush_failed`)

Evaluator `uefi-vars`, subject kind `host`. Each node fsyncs the UEFI vars
files that changed, in `<data_dir>/nvram/` and `/var/lib/libvirt/qemu/nvram/`,
once a second. A node raises `nvram_flush_failed` (critical) about **itself**
when one of those fsyncs fails, and logs `UEFI vars flush failed` with `path`,
`vm` and `error`. The evidence carries `files` (each with `path`, `vm`,
`error`, `at`, `dev`, `ino`, `mtime` and `episode`) and `remedy`. Each failed
fsync is a new `episode`, even of a file already listed.

No later fsync clears it, whether or not the guest wrote the file again. The
kernel reports a writeback error to one fsync and marks the lost pages clean,
and qemu writes back only the sectors a later guest write changes, so the lost
pages stay stale on disk. The failure belongs to the file, not its name: a
file renamed within or between those directories (a replacement's cutover
renames the new VM's vars file) is listed under its new name. A file that
cannot be looked at stays listed, and a removed file is dropped only once two
sweeps in a row found it nowhere. The node also records its failures in
`<data_dir>/nvram-flush-failures.json`, so they survive a daemon restart
whatever the condition row says. A failure that file does not hold yet (its
write failed) is named here only once `nvram_flush_unrecorded` holds it. If that file cannot be read, the node lists
it as a failure of its own, since the failures it held are not known.

| Raised when | Clears when |
|---|---|
| An fsync of a vars file failed. | Every listed file is removed or replaced by another file, or an admin acknowledges each listed failure episode. |

**What to do.** The listed file may be missing UEFI variable writes the guest
made. Check the disk (`dmesg`, `smartctl`). Writing the variables again in the
guest does not clear it, and stopping the VM does not write the store out
again. The ways out:

- A Secure Boot or vTPM VM: `lv snapshot restore <vm> <name>` from a snapshot
  taken before the failure replaces its vars file. A plain UEFI VM's snapshot
  carries no firmware state, so this does not apply to it.
- Any VM: `lv rm <vm>` removes its vars file. `lv rm --keep-disks` keeps it,
  and the condition with it. A later create of the name sets a plain UEFI VM's kept file aside
  (`<file>.superseded-<time>`) rather than adopting it.
- A VM kept as it is: an admin accepts that its vars store may be stale with
  `lv health resolve nvram_flush_failed host/<host> --accept-stale-uefi-vars
  --reason <why>`, which prints the files accepted. It is audited, naming every
  file the condition named with its inode and `episode`, and the host's daemon then stops reporting exactly
  those failure episodes (path, inode and `episode`). Any other failed file is
  raised again, and so is a new failure of a file it named, including one that
  happened after the condition was read.
  A request without `--accept-stale-uefi-vars` (an older `lv`, or a script that
  sends only a reason) is refused.

`lv backup restore-from` restores a disk, not firmware state, and is not a way
out. Nor is `lv backup restore-live` for this VM: it restores firmware state
only for a Secure Boot or vTPM VM, only with `--auto-start`, and only into a
new VM (`--name`), and the old VM still needs `lv rm`.

### UEFI vars flush failure not recorded (`nvram_flush_unrecorded`)

Evaluator `uefi-vars`, subject kind `host`, severity critical. A node raises
it about **itself** while a failed vars fsync is not in
`<data_dir>/nvram-flush-failures.json` because that file could not be
written. The evidence carries `files` (as `nvram_flush_failed`) and `remedy`.
The node names such a failure in `nvram_flush_failed` only once this
condition holds it, and carries it over a restart from here. It cannot be
resolved by hand.

| Raised when | Clears when |
|---|---|
| The state file could not be written with a failure in it. | A write of the state file succeeds (or the failure is gone). |

**What to do.** Fix the filesystem holding `<data_dir>` (`dmesg`, `df`), then
follow `nvram_flush_failed`.

### UEFI vars file not flushed (`nvram_flush_blocked`)

Evaluator `uefi-vars`, subject kind `host`. A vars file that could not be
opened for its fsync is logged as `UEFI vars file could not be opened to flush
it` and retried every second. A node raises `nvram_flush_blocked` (warning)
about **itself** once a file has not been openable for a minute, logged at
error. Nothing is known lost, but that file's writes are not being made
durable. The evidence carries `files` (each with `path`, `vm`, `error` and
`at`, when the episode began) and `remedy`.

It also covers what keeps a whole directory from being flushed: a vars
directory that cannot be read, or whose fsync fails, for a minute (logged as
`UEFI vars directory could not be read` or `UEFI vars directory fsync failed`,
and when it recovers), and a sweep stuck in an fsync for more than 10 seconds,
listed for as long as it is stuck (`UEFI vars flush is stalled`).

| Raised when | Clears when |
|---|---|
| A vars file has not been openable for its fsync, or a vars directory not readable or fsyncable, for a minute; or a sweep has been stuck in an fsync for 10 seconds. | Every listed file or directory is flushed again (logged as `UEFI vars file flushed again after it could not be opened`, `UEFI vars directory readable again`, `UEFI vars directory fsync succeeded again`), or is gone, and no sweep is stuck. |

**What to do.** The `error` says why the file could not be opened: fix that
cause (its permissions, the daemon's open-file limit, or what replaced the
file).

### Reservation not released (`reservation_stale`)

Evaluator `reservation-sweep`, subject kind `host`, subject the host the
reservations are counted against, severity warning. Each node's reservation
sweep runs at startup and every 60 seconds. It releases a reservation whose
operation finished at an owner epoch past its header's, or whose VM no longer
exists, and logs `released a host reservation whose operation is no longer
running`. A node raises `reservation_stale` about **itself** while a
reservation counted against it is older than 15 minutes, no operation holds it
in flight, and the sweep cannot release it, or while a reservation counted
against it cannot be read. The evidence carries `count` and
`reservations` (up to 20), each with `operation_id`, `method`, `vm`, `vcpu`,
`memory_mib`, `created_at`, `class` and `remedy`.

| `class` | Why the sweep does not release it | Remedy |
|---|---|---|
| `no_running_operation` | Nothing proves its operation stopped: no VM or container barrier names it, and it has no terminal step at an owner epoch past its header's. | Check with `lv operation show <vm>` (`lv ct inspect <container>` for a container) that nothing is running, then `lv operation release-reservation <operation-id> --force`. |
| `terminal_past_header` or `vm_gone` | Its release row (a `cancelled` step at the header's owner epoch) is tombstoned and cannot be written again. | `lv operation release-reservation <operation-id> --force`, which writes a `failed` step at the header's owner epoch instead. |
| `terminal_past_header` or `vm_gone` | The release write failed. | The write is retried every pass, and the daemon logs `reservation sweep: could not release a reservation` once per operation with the error. |
| `unreadable` | Its reservation data (vector, project binding or authority facts) cannot be read, so it is not classified. The entry carries only `operation_id`. | The daemon logs `reservation sweep: a reservation could not be read` once per operation with the error; `lv host inspect <host>` names it under `reservationsError`. `lv operation release-reservation` refuses it. |

| Raised when | Clears when |
|---|---|
| A sweep pass finds such a reservation. | A sweep pass finds none: each one was released, or its operation was reaped. |

When the target host is removed or not active, its `terminal_past_header`
reservations are released by the smallest active host instead. While that host
runs an older build or its replica is untrusted, nobody releases them, and a
release it cannot write is logged there but raises no condition; the operation
reaper still removes the operation about a day after its last step.

A removed host (`lv host rm`) raises nothing about itself, so the smallest
active host keeps its `reservation_stale` instead, under the removed host's
subject, and resolves it, along with any the host left open, once none is
left. It lists what no sweep releases there: `no_running_operation`, `vm_gone`
(released only by its target), blocked, and `unreadable` reservations. Each
still counts against its project quota until `lv operation release-reservation
<operation-id> --force` releases it; for a removed host that is decided on the
node called.

### Observer stalled (`observer_stalled`)

A node that was itself not running — its VM suspended, swapped out, or starved
of CPU — raises `observer_stalled` about **itself**, with one writer per row like
`gossip_isolated`. While it is open, the node counts no failed probe against a
peer and its failover coordinator decides no fence: probes that timed out while
it was not running say nothing about the peer. It is not an ownership condition
and never blocks admission.

| Raised when | Clears when |
|---|---|
| The health checker's heartbeat (every 250 ms) sees a gap longer than one probe interval (2 s), on either the monotonic or the wall clock. Confirmed at once: it is a measurement of the node's own scheduling, not an inference from a scan. **Warning** severity. The evidence carries `gap_seconds` and `grace_until`. A further stall inside the window extends the same episode, and `gap_seconds` keeps its longest pause: a long pause is often followed by a short one as the node catches up. | The grace window closes: 5 probe intervals (10 s) after the stall, the time a normal fence verdict takes to build. A condition left open by a previous daemon process is resolved on start. |

After the window, the evidence may also carry `silent_runs`: for each peer
whose first failing run after the stall began without the node having seen
the peer answer since it stopped, the run's start (`run_start`, as its
`host_health` verdict carries it) and `silent_since`, when the node stopped.
Failover reads a failing run that began after a fence as the observer having
seen the host answer, and refuses the recovery; a run recorded here is not
read that way.

**What you see.** A host that died while its observers were stalled is fenced
up to one grace window later than usual. `lv doctor fence` lists the stalled
nodes under `stalled observers (fence votes withheld)` with the pause length
and the time the window closes. A forward NTP step larger than 2 s also reads
as a stall; it delays a fence by one window and never causes one.

**If it keeps reappearing,** the node is being starved: an overcommitted host, a
VM swapping, or a laptop running the lab alongside heavy builds. A node that
stalls repeatedly keeps withholding its vote, which is safe but slows failover.

### VM probe failing (`vm_probe_failing`)

A VM's compose `healthcheck` is probed by the host that owns the VM, and that
host keeps one `vm_probe_failing` row per VM (evaluator `vm_probe`, subject
`vm/<name>`) with its current verdict in the evidence: `verdict` (`healthy`,
`unhealthy` or `unknown`), the probe's last failure `reason`,
`consecutive_failures`, and the `incarnation` it was observed on (owner host,
owner epoch, `created_at` and the VM row's `updated_at`). The row is **open**
(confirmed) while the probe is failing and **resolved** otherwise, so `lv health`
lists failing VMs and `lv health --resolved` lists every probed VM. This row is
what the compose `depends-on: { condition: vm_healthy }` wait and the rolling
update's `health-wait` read — see [Compose](compose.md#health-checks).

It is **info** severity and not an ownership condition: a failing application
probe is the workload's state, not the cluster's, so it neither degrades the
overall health state nor refuses admission.

| Raised when | Clears when |
|---|---|
| `retries` consecutive probes fail (default 3) on the VM's current incarnation. Written once, on the transition — not once per probe. | One probe passes (verdict `healthy`); the VM stops or loses its healthcheck (verdict `unknown`); the probe can no longer be run — no address is known for the VM, or its target cannot be interpreted (verdict `unknown`, with the reason); or the VM is deleted or moves to another host — the host that raised it resolves it, and the new owner publishes its own verdict after its first probe. |

**Reading it.** A verdict whose `incarnation` no longer matches the VM — the VM
was restarted, recreated or migrated since — counts as `unknown`, never as a
pass, and so does any verdict while the owner host is `offline`, `fenced` or in
`maintenance`. `lv inspect <vm>` shows the verdict as it is read that way
(`health` / `healthDetail`), which is the quickest way to see why a
`vm_healthy` wait is still waiting.

### VM paused on an I/O error (`vm_io_paused`)

When a guest's disk write fails with ENOSPC — the storage pool its disks
live on is full, or a thin volume has run out of backing space — QEMU pauses
the guest rather than fail the write inside it. That is QEMU's default
write-error policy (`werror=enospc`), and litevirt sets no other: any other
write error (EIO) and every read error are reported to the guest, which is
not paused. The VM's owner host raises `vm_io_paused` about it
(evaluator `vm_io_pause`, subject `vm/<name>`, **warning** severity), with
the pause reason (`paused_reason`, `io-error`), the `host` and a `remedy` in
the evidence. The guest is frozen, not stopped: its row stays `running`, it
is not recorded as an out-of-band stop, and the restart policy does not
restart it. A pause an operator asked for raises nothing.

litevirt does not resume the guest by itself. A resume into a pool that is
still full pauses it again.

| Raised when | Clears when |
|---|---|
| The owner's reconcile pass finds the VM's domain paused by libvirt for an I/O error. | The owner sees the domain in any other state: resumed (`virsh resume <vm>` on its host, once space is freed), stopped, or gone. A pass that cannot read the domain's state leaves it as it was. |

### Corrupt operator-stop marker (`operator_stop_marker_corrupt`)

`lv stop --force` on a host in write quarantine records the stop in a local
marker, `<data_dir>/operator-stops/<vm>.json`, before it kills the guest, and
the host records the stop on the VM once the quarantine lifts
([upgrades.md](upgrades.md#rolling-back-after-a-release-token-latched)). A marker that cannot be read or
parsed — truncated, another format version, naming another VM — **fails
closed**: the VM is held stopped on that host (no restart policy, `onboot`,
self-heal or `lv start`), and the stop is not replayed, so the VM's row can
still read `running` with its domain shut off. The host logs an error every
10 minutes, `litevirt_operator_stop_markers{state="corrupt"}` counts the
marker, and once the host can write again it raises
`operator_stop_marker_corrupt` (evaluator `operator_stop_marker`, subject
`vm/<name>`, **critical** severity) with the `host`, the marker's `path`, the
read `error` and a `remedy` in the evidence. `lv start` is refused with
`FailedPrecondition`, naming the file.

To clear it, look at the file, then record the stop with `lv stop <vm>`: a
stop recorded on the VM's row removes its marker, whatever the marker holds.
Then `lv start <vm>` starts it.

`lv ct stop --force` keeps a container's marker the same way, in
`<data_dir>/ct-operator-stops/<name>.json`. One that cannot be read holds the
container stopped (no restart policy, no `lv ct start`) and raises the same
condition with subject `container/<name>`. Its remedy is `lv ct stop <name>`,
then `lv ct start <name>`; for a deleted container, remove the file by hand.

While the host is still in write quarantine, leave the file: nothing can
start the VM there meanwhile (`lv start` is refused, and the automated starts
cannot take their lease), and removing it loses the operator's stop — the row
still reads `running`, so once the quarantine lifts the reconciler would
start the guest again. Wait for the lift, then `lv stop <vm>`.

Only when the VM was deleted (`lv stop` answers `NotFound`) is there no stop
to record: remove the file by hand on the host the condition names
(`rm <data_dir>/operator-stops/<vm>.json`). The condition resolves on that
host's next reconcile pass.

| Raised when | Clears when |
|---|---|
| A reconcile pass on a host out of write quarantine finds a marker it cannot read. | The marker is gone: removed by a recorded `lv stop`, or by hand. |

### Runtime owner mismatch (`runtime_owner_mismatch`)

The dual-run detector raises `runtime_owner_mismatch` about a **VM** when the
host its database row names as owner is not the host actually running it:
exactly one host runs the VM, and it is a different host. The involved hosts
are the DB owner and the host running the VM. It is a corruption-class code.
While it is active it blocks admission onto both hosts and runtime-changing
actions on the VM, and automated recovery (self-heal restart, owner-assert)
refuses to act on that VM.

| Raised when | Clears when |
|---|---|
| A detector scan finds exactly one host running the VM, that host is not the DB owner, **and** the DB owner was fully probed and reported the VM not running. A VM whose owner could not be probed is left to `coverage_gap` instead, and a VM mid-migration is skipped. Observed on the first such scan, confirmed (critical) on the second. | Two consecutive clean scans with complete coverage: the owner in the row and the host running the VM agree again. |

**The common benign cause is a host coming back after a fence.** While the
host was down its VMs were rescheduled, and the database moved their rows to
the survivors. The evaluator reads its own replica, so a node whose replica is
still catching up right after it rejoins can briefly see the old owner in the
row while a survivor is running the VM. That clears on its own once
replication delivers the move, two scans later.

**The returning host also keeps a leftover libvirt domain** for every VM that
was moved away. The fence cut the power, so `virsh domstate --reason <vm>`
there prints `shut off (unknown)`: libvirt does not keep the shutoff reason
across a power loss. A shut-off domain is not running, so it does not raise
this condition by itself. The reconciler on that host removes it (destroy and
undefine, NVRAM included; disks are kept) once it has proof that the domain is
a leftover. A shutoff reason of `guest-shutdown`, `destroyed`, `daemon` or
`failed` counts as proof on its own. Reason `unknown` needs two more checks:
the domain has **no managed-save image**, and the DB owner, asked for its own
libvirt view, reports the VM **running**. Until then it logs every tick:

```
reconciler: NOT destroying a local domain whose DB row points elsewhere — not a clearly-dead leftover; deferring to runtime ownership repair
```

The `unproven` field on that line says which check failed. The usual one is
that the owner has not started the VM yet or cannot be reached. Any other
reason (`paused`, `pmsuspended`, `saved`, `crashed`, `migrated`,
`from-snapshot`, `shutting-down`) is never removed automatically, because the
domain may still hold state that can be resumed.

**If the condition persists** past a few scans:

1. Run `lv health` to see the condition and its two hosts, then
   `lv doctor divergence` to check whether the replicas disagree about the VM's
   row. Save the output before you change anything.
2. Check on each host which one is really running the VM
   (`virsh domstate --reason <vm>`).
3. If the host running it is the right owner, run
   `lv doctor repair-owner <vm> <host>`. It writes the row only if `<host>`
   confirms it is running the VM, and it never touches the domain itself.
4. If a host keeps a leftover domain that the reconciler will not remove,
   check the `unproven` field first. Remove it by hand only after confirming
   that another host is running the VM, and that the leftover has no
   managed-save image (`virsh dominfo <vm>` reports `Managed save: no`). Then
   run `virsh undefine --nvram <vm>` on that host. Use `--keep-nvram` instead
   if you want to keep the firmware variables.

### Shared iSCSI LUN (`shared_lun`)

The `shared_lun` evaluator raises `shared_lun` (subject kind `cluster`, subject
the LUN) when more than one guest writes one iSCSI LUN — two VMs, or two disks
of one VM, on iscsi pools that name the same target and LUN (through any
portal), or a VM whose disk is a LUN that an OLDER linked clone reads as its
base: a clone's source is always older than the clone, so a younger VM on its
base took the LUN after the source was deleted with `--keep-disks`. An iscsi
pool is one LUN and holds one disk ([storage.md](storage.md#iscsi-one-lun-one-disk)),
and a create refuses a second disk on one; a cluster where an older build let
it happen is what this reports. The evidence names every VM, disk and host on
the LUN; the involved hosts are the hosts those VMs are on.

| Raised when | Clears when |
|---|---|
| A scan of the replica's `vm_disks` finds two or more live disks of live VMs whose recorded paths are one LUN (the target compared case-insensitively, the portal ignored), or such a disk and an older linked clone layered on it. Observed (warning) on the first such scan, confirmed (critical) on the second. | Two consecutive scans find no such use, under a valid decision gate. |

It runs once a minute on whichever node holds its own lease
(`shared_lun_detector`). A survivor takes that lease over once a quorum of
voters runs a build that answers for the key; until then the scan stops when
its holder does, and `lv health` lists `shared_lun` as stale after 5 minutes.
It is detection only: the voter-majority LUN claim
at create time is the prevention ([storage.md](storage.md#iscsi-one-lun-one-disk)).
It **changes nothing**: no disk is touched, and it is not an ownership code, so
admission — starting either VM included — does not read it. Refusing the start
would not undo what both guests already wrote. Decide which VM keeps the LUN,
stop the others, and move their disks to LUNs of their own (a pool per LUN).

### iSCSI LUN holds (`iscsi_lun_hold_unreadable`, `iscsi_lun_hold_standing`)

A rebuild or recreate of a VM with a disk on an iSCSI LUN moves the LUN's
claim, and the host running it keeps a durable hold on the LUN until the
evidence that it may let go arrives
([storage.md](storage.md#iscsi-one-lun-one-disk)). Each host reports its own
holds (evaluator `iscsi_lun_hold`, subject kind `host`, the subject the host),
so each row has one writer. Neither condition is an ownership code: admission
never reads it.

| Code | Severity | Raised when | Clears when |
|---|---|---|---|
| `iscsi_lun_hold_unreadable` | critical | The host cannot read its hold records under `<data_dir>/iscsi-lun-holds/`: the directory or a record cannot be read, or a record does not parse. The evidence names the file. While it stands the host answers no LUN question: every iSCSI create on it, and every create elsewhere that must ask it, is refused. | The records read cleanly again: a read error is retried on every question; a record that does not parse stays until `lv host lun-hold discard` moves it aside. |
| `iscsi_lun_hold_standing` | warning | A hold has stood for more than five minutes with no re-create running under it. The evidence names each VM, its LUNs and the host it was re-created on — normally that host cannot be asked, or the VM's rows have not reached the holding host. | The hold is released (its evidence arrived) or discarded. |

The holds are checked every five seconds, and a condition is written only when
it changes. `lv host lun-holds <host>` lists them. Discard one only after the
check in [storage.md](storage.md#iscsi-one-lun-one-disk): a hold is what keeps
a second VM off a LUN whose re-created VM's rows are still on their way.

### Two NICs on one MAC (`mac_duplicate`)

Each host looks, at start and every minute, for a MAC that the live NICs of
two workloads record, one of them on this host: two hosts that drew one MAC
at the same moment, each before seeing the other's NIC, or NICs an earlier
build made. Both copies of a container a migrate is moving (or whose source
it parked) are one workload, not two. While one is there the host raises
`mac_duplicate` (evaluator `nic_identity`, subject `host/<host>`, critical);
the evidence names the MAC and each NIC (its VM or container, network and
host). It resolves on the first look that finds none.

Nothing is rewritten: a running guest keeps its MAC. A stopped VM whose NIC's
MAC another workload's NIC holds is refused `lv start` until it has a new one
(an address lease alone holding the MAC raises nothing and refuses nothing);
a start that resumes a guest a drain moved here is not refused. A drain does
not cold-move a running VM whose NIC's MAC another NIC holds: it is refused
before the shutdown and keeps running where it is. A container's start is not
refused. On one network the two NICs receive each other's traffic: the
MAC-keyed forwarding entries of a vxlan network and the DHCP reservation keyed
by the MAC send one guest's unicast and DHCP replies to the other. Give one a
new MAC: for a VM, `lv detach-nic <vm> <mac>`, then `lv attach-nic <vm>
<network>`; for a container, clone it under a new name and remove the
original (`lv ct clone <ct> <new-name>`, then `lv ct rm <ct>`), which keeps
its data.

During a rolling upgrade, only hosts on this build look: two colliding NICs
whose hosts both still run an earlier build raise nothing until one of the
hosts is upgraded.

### A host has pool rows it does not trust (`pool_row_untrusted`)

A host acts on a storage pool row naming it only when its config defines the
pool, it created the pool, an operator confirmed it there with `lv pool trust`,
or the pool's directory is in the daemon's own pool areas (see
[storage.md](storage.md#which-pool-rows-a-host-acts-on)). While it has any other
row naming a host path, the host raises `pool_row_untrusted` (evaluator
`pool_trust`, subject `host/<host>`, warning) on its pool refresh (60 s). The
evidence lists each pool with its driver, source, target and why it is not
trusted, and the daemon logs each one at WARN with the command that confirms
it. Nothing is written, mounted or listed in such a pool; a content call or
write that names it is refused naming `lv pool trust`.

The condition is also raised while the host's trust ledger could not be read:
the evidence's `ledger_unreadable` names the copy kept as
`<data_dir>/pool-trust.json.corrupt-<time>`. None of its entries is trusted
until each pool is confirmed again; review the kept copy, then remove it.

A row you did not make is a row another member, or anything able to inject a
replicated write, made for this host: delete it with
`lv pool delete <pool> --host <host>`, which removes only the row. A pool of
yours that the host holds untrusted — after an upgrade it could not adopt, or
after its ledger was lost — confirm with `lv pool trust <pool> --host <host>`,
which shows the host's row and asks before it records it. The condition
resolves on the next pool refresh once the host trusts every row naming it and
no unreadable ledger is kept.

### An iSCSI pool has no session (`iscsi_session_missing`)

Each host checks, at start and every 30 s, that it has a session to the target
of each of its iscsi pools through the pool's portal. A session missing since
the daemon started (after a reboot, with node records at `node.startup =
manual`) is logged in. A session the daemon saw up and that then disappeared
was logged out on purpose and is not logged back in
([storage.md](storage.md#iscsi-one-lun-one-disk)). While a session is
missing, the host records the pool's state as `degraded` and raises
`iscsi_session_missing` (evaluator `iscsi_pool`, subject `host/<pool>@<host>`,
warning; observed on the first such check, confirmed on the next). Nothing is
refused on it: a VM whose disk is on the LUN cannot open the device, and its
start fails as it did before. The evidence carries the reason:

- **logged out while the daemon ran; `lv start` of a VM using it or a daemon
  restart logs it back in**: someone logged the host out. Start a VM on the
  pool, restart the daemon, or log in by hand (`iscsiadm -m node -T <target>
  -p <portal> --login`) when the target should be back.
- **the login failed** (the portal does not answer, an authorization failure,
  no node record and one could not be created): fix what iscsiadm's output
  names, which is the portal's reachability from the host, the CHAP settings
  (in iscsid.conf, or in the node record: `iscsiadm -m node -T <target> -p
  <portal>`; a pool or disk create keeps a record's settings unless the
  target refuses them, see
  [storage.md](storage.md#iscsi-one-lun-one-disk)), or the target's ACL for
  this initiator. The login is retried every 30 s.
- **a login is in progress in iscsid**: an earlier login is still being
  retried by iscsid; the next check sees how it ended.

The pool returns to `active` and the condition resolves on the first check
that finds the session. Deleting the pool resolves it too.

### An NFS pool is not mounted (`nfs_mount_missing`)

Each host checks, at start and every 30 s, that the export of each of its
`nfs` pools is mounted at the pool's mount point. An export not mounted since
the daemon started (after a reboot) is mounted. One the daemon saw mounted and
that then disappeared was unmounted on purpose, and is not mounted back
([storage.md](storage.md#nfs-pools-after-a-reboot)). While an export is not
mounted, the host records the pool's state as `degraded` and raises
`nfs_mount_missing` (evaluator `nfs_pool`, subject `host/<pool>@<host>`,
warning; observed on the first such check, confirmed on the next). A start of
a VM with a disk on the pool is refused with the same reason. The evidence
carries the reason:

- **unmounted while the daemon ran, and litevirt leaves it so**: someone
  unmounted it. When it should be back, restart the litevirt daemon on the
  host, or mount it by hand (the pool's next use hardens a hand mount's
  options in place, see [storage.md](storage.md#host-paths)).
- **the mount failed** (the server does not answer, the export is not
  exported to this host, `mount.nfs` refused an option): fix what mount's
  output names. The mount is retried every 30 s.
- **a mount has been running since … without finishing**: the server does
  not answer. Raised 5 s into the mount, while it still runs; the mount is
  given up at its timeout (30 s by default) and the reason then becomes the
  mount's error. Fix the server or the network path to it.
- **the mount point holds local files** (it names up to five of them): they
  were written while the export was not mounted, so they are not on it, and
  litevirt does not mount over them. Move them out of the directory; the next
  check mounts the export.
- **the mount point is a symlink**: replace it with an empty directory.
- **the mount point holds another mount** that is not NFS: unmount it; the
  next check mounts the pool's export there. (An NFS mount there, of any
  export, counts as mounted.)
- **resolving the symlinks of the mount point's parent did not finish**: a
  symlink on the way leads into an NFS mount whose server does not answer.
  Fix that server or the path; the check is tried again every 30 s.

The pool returns to `active` and the condition resolves on the first check
that finds the export mounted. Deleting the pool resolves it too.

### A bridge cannot carry an access-VLAN NIC (`bridge_vlan_filtering_off`)

A NIC with a `trunk:` of one VLAN is an access port, and needs a Linux bridge
with VLAN filtering on: every start of its VM on a host whose bridge has it
off is refused, a failover's included
([networking.md](networking.md#vlan-trunk-mode)). Each host checks every 30 s
which of its bridges is a Linux bridge with VLAN filtering off (or
unreadable) while some VM of the cluster has an access-port NIC on a network
using it, and raises `bridge_vlan_filtering_off` (evaluator `access_vlan`,
subject `host/<bridge>@<host>`, warning; observed on the first such check,
confirmed on the next) for each. The evidence names the bridge and the host,
counts the VMs that cannot start there and lists up to ten of them, and says
the fix. A bridge that does not exist on the host is reported too: litevirt
would create it for a start there, without VLAN filtering. A device that is
not a Linux bridge is not judged.

While it is open, failover recovers such a VM onto a host whose bridge is not
reported, when one qualifies; only when none does is it placed on a reported
host, where its start is refused and the VM waits for the fix: it stays
`pending` (or `starting`, for an onboot start), its detail naming the bridge,
is tried again on every reconcile pass, and starts by itself once the bridge
filters VLANs. A refused `lv start` or health restart is not retried: start
the VM again with `lv start <vm>` after the fix. `lv migrate` and `lv host
drain` never move such a VM onto a reported host: the target refuses the move
before anything is copied, and a drain does not choose it, unless the VM's
network allows it (`--allow-unfiltered-access-vlan-moves`, below).

Fix it on the host the subject names: `ip link set dev <bridge> type bridge
vlan_filtering 1`, with the VLAN on the bridge's uplink, and keep it across a
reboot in what creates the bridge
([networking.md](networking.md#access-vlan-nics-need-a-vlan-filtering-bridge)).
The condition resolves on the first check that finds the bridge filtering
VLANs, or no VM with an access-port NIC on it.

### A network lets access-VLAN VMs move onto unfiltered bridges (`access_vlan_unfiltered_moves_allowed`)

`lv network set <net> --allow-unfiltered-access-vlan-moves=true` (admin only,
audited as `network.access_vlan_unfiltered_moves`) lets `lv migrate` and `lv
host drain` move a VM with an access-VLAN NIC on that network onto a host whose
bridge does not filter VLANs, or does not have the bridge yet, where the NIC
joins the bridge's untagged segment. While it is on, `access_vlan_unfiltered_moves_allowed`
(evaluator `access_vlan`, subject `network/<name>`, warning) is open for the
network, and `lv doctor access-vlan-moves` lists it. Starts on such a bridge are
still refused. Turn it off with `--allow-unfiltered-access-vlan-moves=false`;
the condition resolves on the next check (every 30 s), or when the network is
removed.

### A start left paused (`vm_start_stranded_paused`)

A start of a VM whose NICs need their tap VLANs (or a NIC guard under a tap
libvirt names) creates the guest paused, readies it and then resumes it. If
the daemon stopped in between, or the libvirt connection dropped so that
neither the resume nor the destroy landed, the guest stays paused. Each such
paused start is recorded on the host (under `start-paused/` in the data
directory) before the guest is created, and the record is removed when the
start ends. When the daemon starts again, before anything else can start a
guest, it finishes each start that still has a record: the domain is paused,
its row names this host as running or starting, and nothing else holds it (no
partition pause mark on the domain, no partition pause record in memory, the
reserve or the record directory, no hand-over, no firmware move; any of them
unreadable counts as held). It puts the firewall and VLANs in force and resumes
it. A domain paused without a record (by partition pause, a snapshot, an
operator) is never resumed by it. One it cannot finish
stays paused and is named by `vm_start_stranded_paused` (evaluator
`start_guard`, subject `vm/<name>@<host>`, warning), with why. Fix the cause
and `lv restart <vm>`, or `lv stop <vm> --force`. The condition resolves on
the next check (every 30 s) that finds the guest running, stopped or gone.

## `lv doctor access-vlan-moves`

Read-only. Lists the networks that have `--allow-unfiltered-access-vlan-moves`
on (see above).

```
lv doctor access-vlan-moves
```

### Orphaned runtimes (`vm_orphan_runtime`, `ct_orphan_runtime`)

Each host reports the workloads **litevirt created** that are still present on
it while their record is gone: no live row on the host's replica, either missing
or tombstoned. The subject is the workload **and** the host (`vm/<name>@<host>`,
`container/<name>@<host>`, evaluator `orphan_runtime`), so each row has exactly
one writer. The condition is replicated, so `lv health` on any node shows it.

This is the gap the reconciler's self-fence and owner-assert leave by design:
both decide from a workload's row, so a domain with no row gives them nothing to
decide from. The lab case that motivated it was a stale delete that tombstoned a
VM's row on every replica while the VM kept running on its real owner. Nothing
else reported it.

**What counts as litevirt's.** Only a runtime carrying litevirt's own stamp,
never one guessed from a name:

- a domain whose metadata holds the owner-epoch element
  (`https://litevirt.dev/xmlns/owner-epoch/1`; check with
  `virsh metadata <vm> https://litevirt.dev/xmlns/owner-epoch/1`)
- a domain whose metadata holds the managed stamp
  (`https://litevirt.dev/xmlns/managed/1`; check with
  `virsh metadata <vm> https://litevirt.dev/xmlns/managed/1`)
- a container with an owner-epoch marker at `<data_dir>/containers/<name>/owner_epoch`
- a container with the managed stamp at `<lxcpath>/<name>/litevirt-managed`
  (`/var/lib/lxc/<name>/litevirt-managed` by default)

The evidence's `recognised_by` says which (`owner_epoch` or `managed_stamp`).

**The managed stamp** is written by litevirt itself. On every reconcile pass
(every container sweep, for containers) each host stamps every runtime it
holds that has a **live row naming that host**, and nothing else. The stamp
says only "litevirt manages this". It carries no ownership generation and
gates nothing. It covers the runtimes the owner-epoch markers miss:

- VMs created before owner-epoch markers existed
- VMs whose row is still at the pre-epoch generation 0, because
  `enforcement.owner_epoch` is off (the default)
- shut-off VMs
- containers (the owner-epoch marker is written only on relocation)

A live row naming the host is the proof. It is what litevirt already manages
the runtime by. The stamp then outlives the row, and that is when this report
needs it. Stamping waits for a caught-up replica, as the report does. Both
stamps are part of the runtime and go when it goes: undefining a domain drops
its metadata, and `lxc-destroy` removes the container directory.

Nothing older litevirt wrote proves more than this. The domain XML generator
never emitted metadata, a title or a description. A name, or a disk path under
`<data_dir>/disks/`, is a string anyone can reuse.

A domain or container you created by hand is never stamped, because it never
had a live row on that host. So it is never reported, even when it reuses a
deleted VM's name and litevirt's disk paths. What stays unrecognised:

- a litevirt runtime whose row was already gone before this release first ran
  on its host
- a runtime whose stamp is unreadable
- a runtime on a container backend without stamp support

A copy of a litevirt domain's XML (`virsh dumpxml` then `virsh define` under
another name) carries its stamps with it. It is reported like the original.

**A start that outlived its record.** The reconciler re-reads a VM's record
right before it boots the domain, and boots nothing when the record is gone,
was deleted and created again (another `created_at`), or names another host;
the definition it made in that pass is undefined again, firmware state kept. A
record can still be deleted while the boot itself runs (a delete replicated
from another host, or one run by an older binary, which does not hold the
start lease). Then the reconciler stops the guest it booted a moment ago, and
gives back the passthrough devices its hardware pre-start claimed. A domain
with no disks is undefined as well. One with disks is kept, shut off, with the
managed stamp, so it is reported here (info severity) for the procedure below;
its disks are never touched. Before this, such a guest ran with no stamp and
no record, and nothing reported it.

The UEFI vars file is name-keyed (`<data_dir>/nvram/<vm>_VARS.fd`), and a
create of a Secure Boot or vTPM VM under the name is refused while it exists.
When the reconciler removes a disk-less domain like this, it also removes the
vars file if that boot created it (no file before the define, and no record of
the name left). Vars that were there before are kept, and the log line names
the file. A `delete --keep-disks` keeps them on purpose. If no kept VM of that
name needs them, remove the file by hand before you create the name again.

| Raised when | Clears when |
|---|---|
| Two consecutive reconcile passes (15 s apart) see a recognised runtime whose name has no live row: `row` is `missing` (no row at all) or `tombstoned`. A single sighting is never reported, because a delete in flight removes the runtime a moment before or after its tombstone lands. **Warning** severity while the runtime is running, **info** otherwise. The evidence carries `runtime_state`, `marker_epoch`, `row`, and for a tombstone the `row_host`, `row_owner_epoch` and `row_deleted_at` it last had. | The first pass that no longer sees it: the runtime is gone, or its name has a live row again. |

Nothing is reported, and nothing is resolved, while the host's replica has not
caught up after a restart or rejoin. Until then it cannot tell a row that is gone
from one it has not received yet. See
[Deferred out-of-band stop sync](#deferred-out-of-band-stop-sync-after-a-restart-or-rejoin).
It is not an ownership condition and never blocks admission.

The same runtimes are exported as `litevirt_orphan_runtime{kind,host,name,row}`,
a gauge of 1 per orphan while it is reported:

```promql
# A workload litevirt created is running with no record.
max by (host, name) (litevirt_orphan_runtime{row="tombstoned"}) > 0
max by (host, name) (litevirt_orphan_runtime{row="missing"}) > 0
```

**One orphan is undefined automatically:** a shut-off domain (no managed-save
image) recognised by its owner-epoch element, whose tombstoned record names
another host at a strictly newer owner epoch than the domain's and the host's
`<data_dir>/vms/<vm>/owner_epoch`. Its host undefines it on the second
sighting, or when the delete asks it, and removes that marker: disks and TPM
state stay, its UEFI vars are renamed to `<vars>.superseded-<time>` (listed by
`lv host superseded-disks`, never removed by the host), and a
`vm.leftover.undefined` event records it.

**Nothing else reaps an orphan automatically.** The only tombstone that could prove a
running workload is unwanted is one naming this host at the runtime's own owner
epoch. The delete paths remove the runtime before they write that tombstone, so
such a pair only appears after a crash or a replication anomaly, which is
exactly when an automatic destroy is least trustworthy. The lab tombstone named
a different host at an older epoch: it was decided against a runtime that no
longer existed. Destroying the running VM on the strength of it would have acted
on a stale decision.

**Reaping one by hand.** On the host named in the subject:

1. Run `lv health` and read the evidence. `row_host` and `row_owner_epoch` say
   which host and generation the deleted record last named. A `row_owner_epoch`
   below `marker_epoch` means the delete was decided against an older copy of
   the workload, not the one still running. A runtime recognised by the managed
   stamp has no marker epoch (`marker_epoch` is 0), so there is no generation
   to compare. Judge it by `row_host` and `row_deleted_at`.
2. Decide whether the workload is still wanted. If its deletion was intended
   (`lv compose down`, `lv rm`, `lv ct rm`), reap it. If the record was lost
   by accident, keep the runtime and copy its disks out before you do anything
   else (`virsh domblklist <vm>` lists them). litevirt has no command that
   re-adopts a running runtime into a new record, so the way back is a fresh VM
   from those disks, for example with `lv import`.
3. VM: `virsh destroy <vm>`, then `virsh undefine --nvram <vm>`. Undefine
   leaves the disks in place; delete the files `domblklist` listed once you are
   sure.
   Container: `lxc-stop -n <name>`, then `lxc-destroy -n <name>` (which takes
   the managed stamp with the container directory), then remove
   `<data_dir>/containers/<name>/owner_epoch` if it exists.
4. The next reconcile pass resolves the condition.

### A host's ceph keyring holds another key (`ceph_keyring_mismatch`)

Each host records a one-way fingerprint of the key its ceph pool's keyring
holds on its own row of the pool. When another host's row of the same pool
records a different key, the host raises `ceph_keyring_mismatch` (evaluator
`ceph_pool`, subject `host/<pool>@<host>`, warning) naming itself and the
hosts whose key differs. It is a diagnostic: a start is gated on the host's
own key opening each disk (`rbd info`), never on other hosts' rows; a live
migration onto a host whose key differs from the source host's is refused
before libvirt is asked. Install the cluster's keyring for the client on the
odd host; the next reconcile (30 s) resolves the condition.
See [storage.md](storage.md#ceph-rbd-pools).

### A line of spec edits is held off by a running operation (`vm.spec_edit_held`)

After a partition, one side can hold a longer line of out-of-band edits to a
VM's spec (labels, a deploy's metadata) while the owner runs an operation on
the VM from an earlier generation (a hotplug, a resize). The line waits until
the operation has finished, so the operation can complete
([operating-model.md](operating-model.md#replication)). Meanwhile the hosts
disagree: the owner, and those that saw the operation first, show the
operation and its spec; the others show the line and no operation. Each host
that holds the line raises `vm.spec_edit_held` (evaluator `spec_conflict`,
subject `vm/<name>@<host>`, warning): observed at the end of the first
anti-entropy pass that holds, confirmed at the end of the second consecutive
one for the same operation, each time only if the operation still has not
finished once the whole pass has merged. A pass that brings the
operation's terminal step therefore does not confirm it; it resolves the
condition at its end. On
confirmation the host logs a warning and counts
`litevirt_spec_edit_held_total`, once per VM and operation. The evidence
names the operation, the owner host it shows on (the VM's host as of the
latest pass) and the remedy: on that host, check `lv operation show <vm>`;
if that operation is wedged there, run
`lv operation abort <vm> --operation <id> --force`, which is refused if
another operation is active by then. On a host that kept the line,
`lv operation show <vm>` reports no operation. The condition resolves when
the operation turns terminal there, the held line applies, or the VM is
deleted; anti-entropy carries the line on its next pass after that. A host
removed with `lv host rm` never resolves its own, so the removal resolves
them. Nothing ends an operation that never reaches a terminal step on its
own.

### A cancelled start is still recorded (`cancelled_start_kept`)

`lv stop --force` of a VM whose start libvirt has not answered cancels the
start and records the cancel in `<data_dir>/cancelled-starts.json`, so a
domain libvirt starts for it later is destroyed. While the record is kept, a
VM in `error` is neither recorded running nor restarted by its restart
policy. A record kept longer than an hour raises `cancelled_start_kept`
(evaluator `held_start`, subject `host/<host>`, warning), whose evidence lists
each VM, the row the cancel wrote and when. `lv start <vm>` ends the record;
so do deleting or moving the VM, a host boot, or a restart of the libvirt
daemon (when exactly one `libvirtd` or `virtqemud` runs on the host). The next reconcile pass (30 s) resolves the condition once none is
older than an hour. See [storage.md](storage.md).

### The record of cancelled starts cannot be read (`cancelled_starts_unreadable`)

When `<data_dir>/cancelled-starts.json` does not read (a crash truncated it),
the host raises `cancelled_starts_unreadable` (evaluator `held_start`,
subject `host/<host>`, warning) naming the file and the error. Meanwhile no
start can be cancelled with `lv stop --force`, and the VMs the file may name
(those the daemon last read from it, or, if it never read it, every VM in
`error`) are neither recorded running nor restarted. Fix or remove the file;
the next reconcile pass (30 s) reads it again and resolves the condition.

### A deleted ceph image is not purged from the trash (`ceph_trash_leftover`)

A ceph image a VM delete (or a rollback of litevirt's own copy) removes is
moved to its pool's trash, and its objects are purged in the background with
`rbd trash rm <pool>/<id>`, retried until it succeeds and resumed after a
daemon restart. While a purge this host owes has failed, the host raises
`ceph_trash_leftover` (evaluator `ceph_pool`, subject `host/<host>`, warning).
The evidence lists each leftover with its trash reference (`<pool>/<id>`), the
image it was, a `state`, why it is listed, and the command that deals with it
by hand (`by_hand`):

- `purge_failing`: the purge keeps failing and is retried. The image's
  capacity stays used until then. Common causes: the cluster unreachable from
  the host, or snapshots on it. By hand: `rbd trash rm <pool>/<id>`.
- `held`: a client has the image open in the trash. It opened the image just
  before the move, and `rbd trash mv` does not refuse an open image. It may be
  a running VM's disk, so it is **never purged automatically**. Put it back
  with `rbd trash restore <pool>/<id>`.
- `half_moved`: a `rbd trash mv` that failed left the image both in the trash
  and under its name. It is never purged. Check it with
  `rbd trash ls --all --long <pool>` and `rbd info <pool>/<image>`, then restore
  it.
- `settling`: a `rbd trash mv` failed and the trash or the image could not be
  read to settle what it did, so the image may still be live under its name.
  It is retried. Check it with `rbd trash ls --all --long <pool>` and
  `rbd info <pool>/<image>`; litevirt advises no removal.
- `untracked`: a litevirt-named image in a ceph pool's trash that no purge on
  this host tracks, seen by two scans in a row (every 5 minutes). Causes: an
  interrupted `rbd rm`, a crash that lost the queue, another host's purge
  still running, or another host holding it because a client has it open.
  Restoring it (`rbd trash restore <pool>/<id>`) is never destructive;
  removing it may be, so litevirt advises only the restore. Remove it by hand
  only once the host that put it there no longer names it.

`unreadable_queue_files` names purge queue files found unreadable and moved
aside (`<data_dir>/ceph-trash-purges.json.unreadable-<time>`). The purges they
held are no longer tracked; check the pools' trash, then remove the file. A
held entry is forgotten once its trash no longer lists it.

The condition resolves on the next reconcile (30 s) once nothing is listed.
See [storage.md](storage.md#ceph-rbd-pools).

### A VM delete left a ceph image in its pool (`ceph_image_leftover`)

A VM delete frees its disks best effort. A ceph image that a client still has
open is refused as in use. The VM is deleted anyway, as before, but the image
stays in its pool. That client may be another VM still running on the image.
`lv rm` prints one line per image left in place, with its pool, name and the
reason. This host also records the image in `<data_dir>/ceph-kept-images.json`
and raises `ceph_image_leftover` (evaluator `ceph_pool`, subject
`host/<host>`, warning). For each image, the evidence gives the VM and disk
it came from, when the delete left it, the reason, and the check to run
(`by_hand`: `rbd status <pool>/<image>; rbd info <pool>/<image>`).
litevirt removes none of these images; decide by hand once you know who has
the image open. An image stops being named as soon as a VM's disk names it
again, and is forgotten once its pool answers without it (checked every 5
minutes).

An image is also left, and named the same way, when its cluster cannot be
told as its domain would be given it. Its litevirt pool is the host pool, or
for a compose stack's volume the stored stack's volume, its locator names
(`lvpool`). The image is left when that pool, the stack or the pool's
monitors cannot be read, when the pool of its name here is not a ceph pool,
when its locator carries an option a domain cannot be given, or when its pool
is not on this host (or the stack no longer has the volume) and its locator
recorded monitors (`mon_host`). Those recorded monitors may no longer be its
cluster's, so no rbd command is run on them. The VM's delete does not come
back for the image: find the Ceph cluster that holds it and remove it there
by hand (`rbd -m <that cluster's monitors> rm <pool>/<image>`). A journaled
cutover cleanup that kept one retries by itself, and succeeds once the pool
is on this host.

### Replicas in a pool are not removed (`replica_removal_held`)

Before a replica file is removed, whether by a schedule's prune, the orphan
sweep or a pool content delete (`DeleteStoragePoolContent`, as
`lv iso rm` and docs/storage.md use it), its host checks that no disk reads
it. It checks the disk records, and also the qcow2 header chain of every disk
of the replica's VM and of every live disk in the pool. A `--no-localize`
promotion's disk is an overlay on its replica, and a record can lack its
backing, so the header is what counts.

While a header in that chain, or the disk records, cannot be read, whether
the replica is in use cannot be told. The replica is kept, and so is every
other replica in the pool, because each removal checks every disk in the
pool. The replicas pile up until that file reads again.

The host raises `replica_removal_held` (evaluator `replica_prune`, subject
`host/<host>/<pool>`, warning), one per pool. Its evidence holds one entry
for each file that cannot be read:

- the file's path, or `""` when the disk records cannot be read;
- its VM and disk;
- the error;
- since when;
- how many replicas it has kept, and up to ten of them by path.

The VM a held replica belongs to gets a `vm.replica_removal_held` event
naming the file, at most once an hour while the hold lasts. A pool content
delete that is held is refused with the same reason.

To recover, fix that file's header or its storage, or move the file out of
the pool. The next prune or sweep that reads every disk it checks removes
what was held and resolves the condition.

### A VM delete kept a disk file (`disk_leftover`)

A VM delete never removes a disk it cannot prove unused, and never leaves one
unnamed. It keeps a disk when whether another VM uses it cannot be told (a
record read failed, or another VM's disk is on storage that does not answer),
and, for a VM with no domain on any host, any disk that is not a file on this
host's own storage or that it cannot tell is not in use elsewhere. The VM is
deleted all the same. A disk whose removal failed fails the delete instead:
the VM's record is kept, and a retry removes what it can and names the rest.

Each kept disk is named three ways. `lv rm` prints it with its host and the
reason. The VM gets a `vm.disk_kept` event and an audit entry. The host the
delete ran on records it in `<data_dir>/kept-disks.json` and raises
`disk_leftover` (evaluator `vm_delete`, subject `host/<host>`, warning), whose
evidence gives each path, its host, the VM and disk, when, and the reason.
The stack reconciler records there too, on its own host, the disks of a stack
member it deleted while keeping them because it could not prove the teardown
let them go (the teardown recorded no disk choice, or another teardown's); the
reason names the stack. Unless that stack delete asked to keep disks, they are
leftovers.
litevirt removes none of them on its own: check that nothing uses each one
(another VM's disk, a process holding it open), then release it with
`lv host kept-disks <host> --release <vm|path>`, which removes the chain with
its note and record entries, refuses while anything still references a file
of it, audits each file it removes, and clears the condition for it; or remove
it by hand. A file on that host is forgotten once it is gone; a disk is not named while another VM's disk
names its path again. A VM of the same name does not count (a delete that
failed keeps its record, which still names its disks), so a disk adopted by a
VM re-created under the deleted one's name stays named until its entry is
removed as below. To stop naming a disk you keep on purpose, or one recorded on
another host, check it and remove its entry from `<data_dir>/kept-disks.json`
on the host that raised the condition; the file is re-read within 30 s. A file
that cannot be read is never written over: the condition says so, the disks
stay named from memory, and fixing or removing the file recovers.
While an entry is there, a create on that host never clears the file it names,
nor a file that disk's backing chain reaches: the create is refused, naming
the file (docs/cli-reference.md, `lv rm`). A disk the delete of a VM with no
domain kept is also in `<data_dir>/kept-disks/<vm>.json`, with the files its
chain backs on. Every entry's file is also noted there (`recorded`), for the
scan below alone: that holds no file, so a retry of a delete whose removal
failed still frees it, and the note goes with the entry once the file is
gone or released. While `kept-disks.json`, a note `<data_dir>/kept-disks/<vm>.json`,
the listing of the set-aside `.kept-` and `.superseded-` copies, or the
backing chain of a disk one of them names, cannot be read, the evidence names
the file under `creates_refused`
(the condition is raised for it alone, and resolves once it reads), and each
import, create or clone that writes a disk file on the host's own storage,
disk attach that creates a new disk, volume move into a pool on the host's
own storage, backup restore to a `--target-path`, migration onto the host that
copies a host-local disk, and failover rebuild of a missing overlay disk on
that host is judged by the disk files there (every file under
`<data_dir>/disks`, the disk store's directory, `<data_dir>/pools`,
`<data_dir>/mounts` and the directory of every file-based pool of the host,
usable or not, following any symlink below them, every file a note names,
and every set-aside `.kept-` or `.superseded-` copy beside any local disk a
disk row names; only regular files are opened, nothing on a pseudo-filesystem
such as `/proc` or `/sys` is listed or read, a backing file there ends its chain, and a scan past 250,000 files,
256 MiB of headers read or 1 minute stops): it is refused when one of them is,
or backs on, a path it writes, and refused whatever its name when one of
them, or a directory of them, cannot be read, or the scan stops, either,
which `creates_refused` then names too. A create
that clears a file an earlier VM of its name left is refused. Any other goes
ahead, as does a create or clone with no disk file, or with every disk on
shared nfs, ceph or iscsi storage outside the disk directory. A migration's
target (the cold copy's check-only preflight and its write, the live copy's
disk stubs) and the reconciler's rebuild of a missing overlay disk get the
same check as a create at a kept overlay's missing base; a refused rebuild
raises
[`vm_disk_kept_base`](#a-failover-rebuild-is-refused-at-a-kept-overlays-missing-base-vm_disk_kept_base).
While the backing chain of a file a note `<data_dir>/kept-disks/<vm>.json`
names cannot be read, every path on that host that removes disk files leaves
every file, `lv rebuild` is refused on that host, `lv start` and
`lv migrate` are refused for a VM that could be a linked clone's base (a
template, or one whose disk a disk row records as its backing disk), and
`lv host kept-disks --release` refuses, naming the file and the note: fix that
file, move it away, or, once nothing needs it, remove its entry from the note
(docs/cli-reference.md, "Releasing kept disks").

### A drain's live move timed out (`drain_move_timed_out`)

`drain_move_timed_out` (evaluator `drain`, subject `host/<host>`, warning)
names the VMs whose live move off a drained host did not finish within the
VM's migration policy `timeout-sec` and was aborted. Each keeps running on
that host; the drain did not shut it down for a cold move. One whose abort
libvirt did not answer is finished in the background and ends on that host or
on its target (its drain result says which may happen; `lv events <vm>` shows
where it ended); one that completes there leaves the condition. The evidence
lists the VMs (`vms`) and what to do (`detail`). Raise the VM's
`timeout-sec`, move it with `lv migrate <vm> <target-host>`, or stop it with
`lv stop <vm>` and run `lv host drain <host>` again. The condition is resolved
by a drain of the host that has no such move, and by `lv host undrain <host>`;
a VM whose move is still finishing in the background stays named until it
ends.

### A VM left recorded `migrating` (`vm.migration_unresolved`)

`vm.migration_unresolved` (evaluator `drain`, subject `vm/<vm>`, critical)
names a VM recorded `migrating` with no move of it running: a drain's live
move that ended without libvirt's answer while the guest was not running on
the drained host (or its state there could not be read), or a daemon that
stopped mid-move, raised when it starts again. The guest may run on the move's
target, so the record stays `migrating`, a drain's target keeps its capacity
reservation, and nothing starts or moves the VM: `lv start`, `lv restart` and
`lv update --restart-if-needed` of it are refused, and a drain skips it,
pointing here. No start path starts a VM recorded `migrating`, on any host:
only the move itself brings its guest up, on the target. The evidence names the
VM's host (`source`), the target (`target`) and what happened (`detail`).
Find where the guest runs (`virsh list` on both hosts). If it runs on a host,
`lv doctor repair-owner <vm> <host>` records it there; if it runs on none,
`lv stop <vm>` settles the record. Either resolves the condition, and so does
`lv rm <vm>`; each releases the target's reservation. Any other ending that
moves the record off `migrating` on its host resolves it too, within a minute,
on the host the record then names: a re-point, a `lv doctor firmware-move`
action (at once), or a live firmware move's own recovery. A firmware move still
marked on that host keeps it open.

While the condition is open, the move's target never replaces a paused domain
of the VM: that copy may be the guest's only one. A lease holder on an older
build can reschedule a VM recorded `migrating` onto its target, and the
target's reconciler would otherwise destroy the paused guest and boot the VM
afresh from its disks. It leaves the start pending instead, and logs why, and
the condition stays open on the host the record names while that host holds a
paused domain of the VM and the record does not say running there. Resume the
guest there (`virsh resume <vm>`) and it is recorded running; or discard it
(`virsh destroy <vm>`) and the VM is started there from its disks. `lv stop
<vm>` and `lv rm <vm>` discard the paused copy too, without asking: it may be
the guest's only copy. Each resolves the condition within a minute. A guest
held paused there for its NIC guards (`firewall.nic.held`) is resumed by its
host once its guards are in force, which is the resume above.

`lv stop` and `lv rm` of a VM recorded `migrating` whose guest is not running
on its host first ask the move's target whether it holds a domain of the VM.
They are refused when it does (pointing at `lv doctor repair-owner`), and when
the target cannot be asked, unless the target is proven powered off: fenced,
or removed, over a verified IPMI or Redfish power-off or an operator's
`lv host fence-confirm <target>`. A target that is gone for good is made so
with `lv host fence-confirm <target>` once it is powered off (and then
`lv host rm <target> --dead`). A guest still running on its host is stopped
there, after any migration job libvirtd still runs for it is aborted.

Failover asks the same question of a VM recorded `migrating` on a host it
recovers: a migration that cut over in libvirt runs the guest on its target
even when the source died before recording the move. Before anything is
started, the coordinator asks each such VM's target, once per target per
poll, a few at a time and within a bounded time, so a target that does not
answer holds only its own VMs.

- The guest runs there: the record is moved to the target, running, with a
  `vm.failover.repointed` event, and nothing is started. Its disk rows still
  name the source and its replication still runs from there:
  `lv doctor repair-owner <vm> <target>` moves them.
- The target has no domain of the VM, or is proven powered off as above: the
  VM is recovered as any running VM (a Secure Boot / vTPM VM excepted, below).
- Anything else holds the VM where it is recorded, raises
  `vm.migration_unresolved` naming why, and is asked again on the next poll.
  It counts in the failover metrics with error class `migrating`. `lv stop`
  does not settle it, since it forwards to the failed source. What does:
  - the target does not answer: if it is down, once it is powered off,
    `lv host fence-confirm <target>`, and the next poll recovers the VM;
  - the target holds the VM paused or shut off: no `lv` command settles it
    while the source is down. Start or resume the guest on the target
    (`virsh start` or `virsh resume`) and the next poll records it there;
  - the record names no target: find where the guest runs, and
    `lv doctor repair-owner <vm> <host>` records it there;
  - a Secure Boot / vTPM VM is never moved by its record alone, and
    failover never restarts one: its NVRAM and TPM state live on its source
    and its target. What settles it depends on what its target holds:
    - the target holds it paused: once the source is powered off,
      `lv host fence-confirm <source>`, then
      `lv doctor firmware-move <vm> --adopt-target-copy` adopts that copy,
      records it on the target and resumes it;
    - the target runs it, or holds it shut off: no `lv` command handles that
      yet. Pause it on the target (`virsh suspend <vm>`, or
      `virsh start --paused <vm>` for a shut-off copy); the next poll then
      names the steps for a paused copy. A copy in any other state
      (pm-suspended, crashed, shutting down) has no `lv` command and no
      host-side step known to be safe: contact the litevirt maintainers;
    - the target does not answer: no `lv` command starts the VM while both
      hosts are down, and none handles this yet. Bring the target back and
      the next poll names the step for what it holds; or bring the source
      back (below);
    - the target answers with no copy, or is proven powered off: failover
      goes on and skips the VM, and no `lv` command starts it while the
      source is down. Bring the source back (below). If the source cannot
      come back, its firmware state is lost with it, and no `lv` command
      handles that.

    When the source comes back, its daemon takes the move up from its own
    records and asks the target. A target that holds the guest takes it: the
    move commits there. A target that holds no copy parks the move as
    `firmware_migration_source_state_suspect`;
    `lv doctor firmware-move <vm> --accept-source --acknowledge-rollback`
    then `lv start <vm>` start it on the source (a move that had not reached
    libvirt's migration is undone instead, and `lv start <vm>` alone starts
    it). While the target does not answer, the move stays parked as
    `firmware_migration_target_unreachable`; `lv doctor firmware-move <vm>`
    shows the phase it parked from. From `prepared`,
    `lv host fence-confirm <target>` once the target is powered off resolves
    it within a minute, recording the VM stopped on the source, and
    `lv start <vm>` starts it. From `cutover`, no `lv` command handles it yet,
    and a fence of the target does not resolve it: only the target answering
    again settles it.

### A firmware move record cannot be read (`firmware_migration_record_unreadable`)

A live firmware migration keeps its records under `<data_dir>/fwmig-inflight/`
(the source) and `<data_dir>/fwmig-hold/` (the target), and a target keeps a
leftover an owed DISCARD names under `<data_dir>/fwmig-leftover/`. While a record names a
VM, its starts, stops, redefines and firmware state writes are refused. A
record file that cannot be read could name any VM, so the refusal is
host-wide for every operation that carries a domain uuid (a define, a firmware
state restore, a wipe), and covers every operation on the VM the file is named
after. The refusal names the file, and the host raises
`firmware_migration_record_unreadable` (evaluator `firmware_move`, subject
`host/<host>`, critical), whose evidence gives each file, why it does not
read, and every firmware state wipe it refused: that state is still on disk,
and each such VM also gets a `vm.firmware_wipe_refused` event. Repair the file,
or move it out of its directory once no firmware move on the host needs it;
the condition resolves within a pass once every file reads.

### Live firmware migration (`firmware_migration_*`)

A live move of a Secure Boot / vTPM VM
([migration](migration-failover.md#secure-boot--vtpm-vms)) raises these
conditions: evaluator `firmware_migration`, subject `vm/<vm>`, shown by
`lv health`. The evidence gives the VM, the attempt, the source and target,
the host that raised it, the hashes and paths it is about, a `detail`, and an
`action` when an operator has one. While a move is parked, its records stay
on both hosts (`<data_dir>/fwmig-inflight/<vm>.json` on the source,
`<data_dir>/fwmig-hold/<vm>.json` on the target), so starts, stops, redefines
and firmware state writes of the VM stay refused there, and nothing is
deleted on either host. The source's recovery looks at each parked move every
minute and at daemon start.

| Code | Severity, host | What happened | What you do; when it resolves |
|---|---|---|---|
| `firmware_migration_target_unreachable` | critical, source | The source could not finish a call to the target (unreachable, a build without the RPCs, or the target reports no record of the attempt while a domain of the VM is defined there). Also a mismatch whose discard of the target's copy did not get through | Bring the target back; the retry resolves it. If the target is down for good, give it a proof-grade fence: an `ipmi` or `redfish` fence that powered it off, or `lv host fence-confirm <host>`. An `ssh`, `watchdog` or best-effort fence does not count (see [What a fence records](migration-failover.md#what-a-fence-records)). Then, when the VM's row still names the source, and the move had not reached cutover or the source's guest stopped for the migration, the source drops its record and `firmware_migration_discard_owed` follows. The VM's row becomes `running` when its source domain runs, `error` when the domain is active but not running, and `stopped` otherwise; from `stopped`, `lv start <vm>` starts it from the source's firmware state. When the row names the target, it stays parked: with the target proved off, `lv doctor firmware-move <vm> --accept-source --acknowledge-rollback` returns the VM and its disks to the source (not after a storage copy, whose commit deleted the source's disks, and not when a disk row changed since the commit), and `--accept-target` finishes the source cleanup of a released move. A held domain the target lost after the commit (`held_domain_absent` in the detail) takes `--push-source-nvram` or `--accept-source --acknowledge-rollback`. A move parked before cutover whose target keeps refusing the abort takes `--discard-target` |
| `firmware_migration_discard_owed` | warning, source; critical while the target refuses | The move was resolved by fence, and the target's copy is still to be discarded. The source sends the discard every minute | Nothing while a warning. Resolves when the discard lands on the target's return, or the target host is removed (`lv host rm <host>`). Critical: the target refused it because the VM's domain runs there, or a domain of the VM is still defined there. While the target holds the move's hold, `lv doctor firmware-move <vm> --discard-target --stop-target` stops that guest and discards its copy. With no hold left there, the DISCARD puts the target's domain under a leftover record, which keeps it from being started, stopped or undefined there (`lv doctor firmware-move <vm>` shows it as `leftover`); `lv doctor firmware-move <vm> --discard-target` (with `--stop-target` while its guest runs) moves its state into `<data_dir>/fwmig-quarantine/<vm>-<attempt>/` and undefines it keeping its state. Once no host owes the DISCARD, `--discard-target` still takes a leftover that is shut off, on the target's own record. A shut-off leftover the target's reconciler cleans first has its state moved into `<data_dir>/fwmig-quarantine/<vm>-reconciled-<unix>/`, never wiped (listed by `lv host superseded-disks <host>`, kept while the VM exists and while any firmware move record or open `discard_owed` names it). When the VM's row later names the target for the leftover's own incarnation and no host owes the DISCARD, `lv doctor firmware-move <vm> --adopt-target-copy --acknowledge-rollback` drops the leftover record and keeps the shut-off domain and its state as the VM's own. That state is as old as the leftover: without the acknowledgement the refusal gives its age and names every newer copy the hosts report (a domain of the VM, a `<vm>-reconciled-*` quarantine), and `lv host superseded-disks <host> --restore <dir>` puts such a quarantine back as the VM's firmware state on the host the VM is placed on (the VM stopped there; the state it replaces is set aside the same way) |
| `firmware_migration_unverified` | critical, source | The target's vTPM state did not match the source's final copy, or the target's guest was no longer there, after the source's guest stopped for the migration. The target's copy is quarantined; the VM is `stopped` on the source with its firmware state | `lv start <vm>` runs it on the source. The quarantine on the target is for inspection (`firmware_migration_quarantine`). `lv doctor firmware-move <vm> --resolve unverified` closes the condition |
| `firmware_migration_source_state_missing` | critical, source | After the guest left the source, the source's final vTPM state or NVRAM is missing, or the source domain's state cannot be read. The target's guest stays paused | Nothing is deleted. Retried every minute. `lv doctor firmware-move <vm> --adopt-target-copy` takes the target's copy when the source's final state is missing; after the commit `--accept-target` hashes the source's final NVRAM again and resends Release; before it, with the state present, `--reverify` for a park from cutover, and the minute retry for a park from migrating (`--reverify` refuses that one) |
| `firmware_migration_source_state_suspect` | critical, source | The target's copy did not match, or its guest is gone, and the source's guest had stopped for a reason other than the migration (a host crash or reboot), so the source's copy may be stale. Both copies kept; the target's guest stays paused | Not retried. `lv doctor firmware-move <vm> --adopt-target-copy` takes the target's copy (the source's guest shut off), or `--accept-source --acknowledge-rollback` the source's |
| `firmware_migration_target_ran` | critical, source | The target's guest was found running before it was released, or a discard of the target's copy was refused because its guest runs | Not retried. Nothing is deleted on either host. Before cutover, with the source's guest running: `lv doctor firmware-move <vm> --discard-target --stop-target`. After it: `--adopt-target-copy`, or `--accept-source --acknowledge-rollback --stop-target` |
| `firmware_migration_source_paused` | critical, source | The migration failed with the source's guest paused and a domain of the VM on the target. Both guests are paused | Not retried. `lv doctor firmware-move <vm> --accept-source` discards the target's copy, then resumes the source's guest (one already running is left running). It is refused while the target's guest runs, or is paused under a hold that is not `prepared`: that copy ran after the source paused. Shut the source's domain off, then `--adopt-target-copy` |
| `firmware_migration_nvram_unconfirmed` | critical, source | The guest runs on the target, but the target's NVRAM did not equal the source's final NVRAM within 10 s of the resume. A guest writing EFI variables just after the resume can cause it. The source's state is kept; the VM cannot be started on the source, nor started or stopped on the target | The guest keeps running on the target. `lv doctor firmware-move <vm> --confirm-target-nvram --accept-nvram-hash=<sha256>` accepts the target's NVRAM by the hash it has now; with the guest powered off, `--push-source-nvram --acknowledge-rollback` writes the source's final NVRAM there (`--stop-target` stops the guest first). Either way the source cleans up after |
| `firmware_migration_cleanup_failed` | critical (warning for a draining, maintenance or removed target, or a VM moved on to a third host), source | The guest runs on the target, but the source cleanup stopped: writing the retained bundle, undefining the source's leftover definition, wiping the source's state, or removing the record failed. The source's state is kept | Fix the cause the detail names; the cleanup is retried every minute and at daemon start, and the condition resolves when it finishes. If the detail says the source's state changed after the cutover, it is never wiped automatically and a retry does not heal it: `lv doctor firmware-move <vm> --accept-target` moves it into `<data_dir>/fwmig-quarantine/<vm>-<attempt>/` on the source and ends the move. The cleanup undefines the source's domain only while the target is active, answers, and shows a domain of the VM's uuid with no error reading its records; in every other case (offline, fenced, proved off, draining, maintenance, removed, unknown, not answering, or answering without the VM's copy) it holds before the undefine and the detail says why. Each of these holds goes on by itself once the target is active, answers and holds the copy again, except the one below for a VM that moved on. A hold for a target in `draining` or `maintenance`, or removed from the cluster, is a warning; for a removed target `--accept-target` is the exit. When the VM's row names a third host (it moved on from the target), the cleanup holds at warning and never goes on by itself: `--accept-target` is the only exit. `lv doctor firmware-move <vm> --accept-target` ends a hold at any time, the source's state quarantined. A target is proved off by an `ipmi` or `redfish` fence that powered it off, or by `lv host fence-confirm <host>`; a target removed after a proof-grade fence counts as proved off for the exits below. A cleanup never takes the state of a VM whose row names the source again. If the target is down for good, once it is powered off and `lv host fence-confirm <host>` recorded, `lv doctor firmware-move <vm> --accept-source --acknowledge-rollback` returns the VM and its disks to the source, stopped, from the source's state (refused when that state changed since the cutover, or when the cleanup already undefined the source's domain); then `lv start <vm>` |
| `firmware_migration_vf_missing` | critical, source (`runs_on` names where the guest runs) | The guest runs (on the source after a failed move, or on the target) without SR-IOV VFs the move detached from it; `vfs` lists them | Attach the VFs to the guest again, or restart it on that host so its devices are allocated again. Resolves once the guest runs there with all its VFs, or is stopped, deleted, or moved off that host |
| `firmware_migration_held` | warning, target | A hold with a domain of the VM has existed for 5 minutes (it starts when the target prepares the move). A long storage copy reaches this in a move that is going well | Resolves when the hold goes. A hold whose source holds no marker of the move (its host lost, or only an owed discard left there): `lv doctor firmware-move <vm> --adopt-target-copy` with the source host proved off, or `--discard-target` while the VM's row does not name the target |
| `firmware_migration_quarantine` | warning, target | The target moved a held copy (vTPM state, NVRAM, record) into `<data_dir>/fwmig-quarantine/<vm>-<attempt>/`, with `reason.txt` giving every hash. This happens on a mismatch, on the abort of a hold that was past `prepared`, when a new move of the VM finds an earlier attempt's hold with no domain, and when the hold sweep finds a hold with no domain older than 2 hours whose VM is gone, recreated, or not migrating to this host | Nothing removes a quarantine. Inspect it and remove the directory by hand when it is no longer needed. `lv doctor firmware-move <vm> --resolve quarantine` closes the condition; the directory stays |

In a quarantine made before the guest resumed on the target, the NVRAM is the
source's NVRAM the target materialised when it prepared the move, not libvirt's
template.

`lv doctor firmware-move <vm>` shows each host's records of the move, the
VM's domain on each host, and every hash and path. With one action it resolves
a parked move on the host whose record it acts on. Each action refuses a state
it has no row for and leaves both records and both copies as they were. Every
action is audited (`vm.firmware-move`).

### A VM's disk is missing on its own host (`vm_disk_missing`)

A start on the VM's own host never boots it from a blank disk. This covers the
onboot autostart, the restart of a VM the database says is running that is not
in libvirt, and a start interrupted by a daemon restart. If the file at a
disk's path is missing, the start refuses and the VM goes to `error`. The
reconciler raises `vm_disk_missing` (evaluator `vm_disk`, subject
`vm/<name>@<host>`, critical). It does not rebuild the disk from the VM's image,
which would start the VM with its data silently reset. The evidence names the
disk, its path and its backing image.

Only an ownership transfer onto a host rebuilds a missing disk from its image:
a VM rescheduled off a failed host, whose host-local disk stayed behind there
(see [VM failure policies](migration-failover.md#vm-failure-policies)).

| Raised when | Clears when |
|---|---|
| A start that is not an ownership transfer finds a disk's file missing. | The VM has left `error` on this host: it was started or stopped, rebuilt, deleted, or moved to another host. |

To recover, do one of these:

- If the disk still exists somewhere, for example on another host, in a
  backup, or as a `.superseded-*` copy next to its path, put it back at the
  path in the evidence and run `lv start <vm>`.
- If its data is lost for good, run `lv rebuild <vm>`. It recreates the VM from
  its spec with blank disks and keeps its IP and MAC addresses.

### A failover rebuild is refused at a kept overlay's missing base (`vm_disk_kept_base`)

An ownership transfer onto a host rebuilds a disk missing there as a fresh
overlay of its image, at `<disks>/<vm>-<disk>.qcow2`. A delete on that host may
have kept an overlay of an earlier VM of the same name whose missing backing
file is that very path: the rebuilt disk would become its base. The rebuild is
refused, as a create is. While `kept-disks.json` or a kept chain cannot be
read it is judged, as a create is, by the disk files on the host, and refused
when one of them is, or backs on, its path or when they cannot all be read; it
is refused too while storage or the database does not answer. The start
fails as any failed rebuild does: one that carries a transfer proof is retried
on each reconciler pass (and the coordinator may place the VM on another
host); one without a proof goes to `error`, as before. The reconciler raises
`vm_disk_kept_base` (evaluator `vm_disk`, subject `vm/<name>@<host>`,
warning), written again only when what it says changes. The evidence names the
disk, its path, the `cause` (`kept_overlay`, `kept_state_unreadable` or
`no_answer`), the error naming the kept overlay or the file that cannot be
read, and the fix for that cause.

| Raised when | Clears when |
|---|---|
| The rebuild of a missing overlay disk is refused by the kept-create check. | The VM has left `pending`, `starting` and `error` on this host: it was started or stopped, moved to another host, or deleted. |

To let the VM start on that host:

- `kept_overlay`: move the kept overlay off it (or `qemu-img rebase -u -b <new
  path>` it onto a copy of its base), or, once nothing needs the kept disk,
  remove its entry from `<data_dir>/kept-disks.json`. Kept disks are listed
  under `disk_leftover` in `lv health`.
- `kept_state_unreadable`: repair the file named (`kept-disks.json`, or a kept
  disk's chain), or move it away or remove its entry once nothing needs it.
- `no_answer`: nothing to do once the storage or database answers; the next
  attempt checks again.

### A VM's real disk is on another host (`vm_disk_stranded`)

A failover restarted a VM with a host-local disk on another host, on a disk
rebuilt from its image, because that host could not reach the real one (see
[VM failure policies](migration-failover.md#the-real-disk-a-restart-leaves-behind)).
The coordinator raises `vm_disk_stranded` (evaluator `vm_disk`, subject
`vm/<name>@<host>`, warning) naming the host that holds the real disk. The
evidence lists each disk: its `path` there, and once the host is back and has
set it aside, its `copy` (`<path>.superseded-<time>`). A host that sets aside an
old copy it found at a failover start records it the same way. `lv inspect
<vm>` shows the same list as `strandedDisks`.

| Raised when | Clears when |
|---|---|
| A failover restarts the VM elsewhere and leaves a host-local disk on the failed host, or a host sets a copy of the VM's disk aside. | Nothing is left to keep: every copy was removed (`--remove`) or restored (`--restore`), or the VM was deleted. After a delete the host clears it once it has set aside the disk still at its path, or left a disk the delete kept (`--keep-disks`, `delete_with_vm=false`, or a record that does not say what the delete decided) where it is. It waits while a domain of the VM's name runs there, or while the path is missing and its directory is absent, empty or cannot be listed (as a volume not mounted yet reads). A path missing from a directory that lists other files is gone, and does not hold the record open. A record for a host removed from the cluster clears once the VM is deleted. |

Every copy is kept while the VM exists. To run the VM on its real disk again,
or to give the data up, see the commands in
[migration-failover.md](migration-failover.md#the-real-disk-a-restart-leaves-behind).

### A restart-same VM waits for its host (`vm_failover_held`)

A VM with `on-host-failure: restart-same` and a host-local disk was on a host
that failed. Failover left it there instead of restarting it elsewhere on a
disk rebuilt blank from its image. The coordinator raises `vm_failover_held`
(evaluator `vm_disk`, subject `vm/<name>@<host>`, warning); the evidence names
the host, the disks and what to do (see
[VM failure policies](migration-failover.md#vm-failure-policies)). A held VM
still counts in the failover's stranded-workloads gauge: it is a workload on a
down host that no other host runs.

| Raised when | Clears when |
|---|---|
| Failover leaves a restart-same VM with a host-local disk on its failed host. | The host is back and the VM runs there again (a host that boots again turns `active` on its own, after `upgrading` until its daemon serves; one that answered again without restarting and stays `fenced` or `offline` needs `lv host undrain <host>` first), or, once the host is back, the VM is on another host or deleted. A record for a host removed from the cluster clears once the VM is deleted or on another host. |

### A start an operator cancelled (`vm_start_cancelled`)

`lv stop --force <vm>` of a VM in `pending` or `starting` with no domain
defined (a start deferred because its storage did not answer) cancels the
start: the VM is recorded stopped by its operator. The stop raises
`vm_start_cancelled` (evaluator `vm_disk`, subject `vm/<name>@<host>`, info).
While it is open, the disk copies a failover set aside for the VM stay held, as
they were while the start was under way: `lv host superseded-disks <host>
--remove` refuses them.

| Raised when | Clears when |
|---|---|
| A forced stop cancels a start that had no domain. | The VM runs on that host again, or is on another host, or is deleted. `lv start <vm>` makes the cancelled start again: the VM goes back to `starting`, and the reconciler defines and starts it as it would have (a transfer still sets aside an old copy at the disk path). |

### A relocated container's own rootfs is on another host (`ct_rootfs_stranded`)

Failover relocated a container off a failed host, recreating it from its image
or restoring it from a backup, and its own container directory, with what it
wrote since, stayed on the failed host. The coordinator raises
`ct_rootfs_stranded` (evaluator `ct_rootfs`, subject `container/<name>@<host>`,
warning). When that host is back it adds the rootfs path to the evidence.
Nothing moves or removes the rootfs; `lv ct inspect <name>` shows it.

| Raised when | Clears when |
|---|---|
| A relocation moves the container off a host that ran it. | No container of that name is left on that host, or a relocation back adopted it (`ct.relocate.adopted` in the audit log). |

### File restore without a barrier (`file_restore_unsandboxed`)

A host whose daemon config lets restore VMs run without one of their barriers
raises `file_restore_unsandboxed` about **itself** (evaluator `file_restore`,
subject `host/<name>`), with one writer per row like `observer_stalled`. The
keys are `file_restore.allow_unsandboxed` (`seccomp`, `mac`, `root`, or `true`
for all three) and `file_restore.allow_shared_run_as`; both are off by
default and dangerous (see [backups](backups.md#single-file-restore)). It is
not an ownership condition and never blocks admission.

| Raised when | Clears when |
|---|---|
| The daemon starts with file restore on and either key set. Confirmed at once; **info** severity. The evidence lists the keys set (`allow_unsandboxed: [seccomp]`, `allow_shared_run_as`). | The daemon starts with neither key set, or with file restore off. |

**What it means.** On this host a malicious backup meets one barrier fewer on
its way to the host: no seccomp sandbox, no MAC (neither the AppArmor profile
nor Landlock), a non-root daemon's own uid, or a shared qemu user. Every
restore VM actually started that way is audited as
`backup.file_restore_unsandboxed`, with `sandbox=on|off apparmor=on|off|absent
landlock=<abi>|off uid=<n>`; the same summary is in every
`backup.file_restore` row. Fix what the key works around (a qemu with seccomp,
`apparmor_parser`, a kernel with Landlock, a root daemon) and remove the key.

## NetBox IPAM: metrics and health findings

Every counter below is registered on the same `/metrics` endpoint as the rest,
on every node whose config enables the NetBox integration.

| Metric | Labels | Meaning |
|---|---|---|
| `litevirt_netbox_api_errors_total` | `class` = `transport` / `client` / `server` | NetBox API failures by class. `transport` is no answer at all, `client` is a 4xx (NetBox answered and said no), `server` is a 5xx — the last two are the AMBIGUOUS ones, where a write may have committed before the response was lost. |
| `litevirt_netbox_ambiguous_claims_total` | — | Address claims whose outcome could not be read off the response and had to be resolved by a lookup. Invisible to the caller (a recovered claim returns an address like any other), so this is the first sign that responses are being lost between litevirt and NetBox. |
| `litevirt_netbox_orphans_reclaimed_total` | — | NetBox IP objects deleted by the orphan sweep under a whole-cluster negative proof. |
| `litevirt_netbox_sweeps_skipped_total` | `reason` (closed set: `hosts_read`, `no_eligible_hosts`, `host_unreachable`, `host_returned_no_proof`, `incomplete_proof`, `host_still_claims`, `proof_count_mismatch`, `membership_changed`, `membership_unproven`, `leader_lease_lost`, `netbox_reread_failed`, `netbox_object_changed`, `release_failed`, `identity_unresolvable`, `error`) | Reclamations the sweep declined. Every skip leaves the address allocated, which is always the safe direction; the full reason (which names an address and a host) goes to the log, never to the label. |
| `litevirt_netbox_stuck_leases_total` | — | Addresses whose NetBox object was queued for release while a live local allocation row still names them. Never resolved automatically — see [Stuck leases](networking.md#stuck-leases). |
| `litevirt_netbox_bindings_suspended_total` | — | Cumulative bindings taken out of service **and left that way**: by revalidation drift, or by a bind whose adoption of the addresses its guests already hold could not finish. A bind that adopts them successfully suspends the binding only for the duration of the adoption and is not counted here. |
| `litevirt_netbox_bindings_suspended` | — | **Gauge:** bindings suspended *right now*. Use this one for alerting — the counter above keeps rising after an operator has repaired a binding. |
| `litevirt_netbox_duplicate_objects_total` | — | NetBox objects found duplicated for one litevirt identity by the inventory mirror. |
| `litevirt_netbox_unclaimable_discoveries_total` | `reason` (closed set: `not_ours`, `unknown`, `no_allocator`, `no_identity`) | Addresses a guest was discovered USING on a bound network that litevirt declined to record — see [Addresses discovered after the bind](networking.md#addresses-discovered-after-the-bind). `not_ours` is the serious one: NetBox holds that address for something else, so two things are using it, and nothing repairs that automatically. `unknown` is a claim whose outcome could not be established (usually NetBox unreachable) and normally clears on the next 30-second tick. |
| `litevirt_netbox_sync_queue_depth` | — | **Gauge:** pending items in the inventory mirror's work queue. The queue is a latency optimisation — the periodic sweep is the correctness mechanism — but a depth that never returns to 0 means the mirror is not draining. Expected to climb during a NetBox outage: items are acked only after a sweep succeeds, and the backlog clears in one pass on recovery (see [The queue during a NetBox outage](networking.md#the-queue-during-a-netbox-outage)). |
| `litevirt_netbox_mirror_objects_total` | `kind` = `virtual_machine` / `vminterface`, `op` = `created` / `updated` / `deleted` | NetBox objects the inventory mirror actually WROTE. Only writes are counted — an object the sweep adopted, or a delete of one already gone, wrote nothing. The mirror writes on change only, so over unchanging inventory this must stop climbing; one that keeps rising under `updated` is a field the diff cannot round-trip, and under `created` is a mirror that is not recording what it wrote. |
| `litevirt_netbox_mirror_sweeps_total` | `result` = `ok` / `error` | Inventory mirror sweeps that ran to a conclusion. Counted on the leader only: a node that does not hold the `netbox` lease runs no sweep and records neither. |
| `litevirt_netbox_mirror_last_success_seconds` | — | **Gauge:** unix time of the last *successful* mirror sweep on this node, 0 if it has never completed one. Never advanced by a failed sweep, so `time() - <this>` is the staleness of the mirror — alert on the cluster-wide **max**, because only the leader sweeps and every other node sits at its own last turn as leader (or at 0). |

### Health findings

Eight NetBox failures are silent to everything else litevirt reports, so they are
also durable `health_conditions` rows and appear in `lv health` (see
[Cluster health](#cluster-health-durable-conditions-and-the-admission-gate-v50)).
The first two are raised by the orphan sweep and the last by the inventory
mirror, both of which run under the `netbox` leader lease, so the cluster has
exactly one writer. The other five are
per-node — they are about one node's own configuration or its own runtime, which
no peer can read — so every configured node raises them for itself, keyed on its
own host name, and a node that agrees never clears a peer's finding. All eight
are **warning** severity, so they show as DEGRADED and never as CRITICAL, and
none gates admission.

| Code | Subject | Raised when | Clears when |
|---|---|---|---|
| `netbox_binding_suspended` | the network | A `netbox_bindings` row is suspended. The evidence names the network, the prefix, and the drift reason. New allocations on that network refuse until an operator runs `lv netbox resume` (or `lv netbox rekey` if the cluster fingerprint moved); running workloads are untouched. | Two consecutive sweeps see the binding un-suspended. |
| `netbox_sweep_blocked` | `netbox` (cluster) | Three consecutive sweeps declined every reclamation because a host would not answer the absence proof. One unreachable host is ordinary — a reboot, a restart — but while it is away NOT ONE address can be reclaimed, and the pool fills with orphans in silence. | Two consecutive sweeps complete without a `host_unreachable` skip. |
| `netbox_cluster_name_mismatch` | the host | This node's `netbox.cluster_name` resolves to a different NetBox `virtualization.cluster` than the one the cluster's bindings are pinned to, so this node refuses to mirror inventory and refuses `lv netbox rekey`. The evidence names both values and the binding holding the pin. `netbox.cluster_name` must be identical on every node (or unset on every node): the mirror sweep runs on whichever node holds the `netbox` leader lease, so a disagreement moves the whole inventory between two cluster objects as leadership moves. Address allocation is unaffected. Fix the config on the node that is wrong and restart it. | Two consecutive revalidation passes on **that node** resolve the same name the pin holds. |
| `netbox_dhcp_would_race` | the host | Provisioning a bound network on **this** host would start litevirt's own DHCP server over the bound prefix, so this host refuses to provision it. It happens when a managed bridge with a subnet is bound to a NetBox prefix and the bridge does not exist on this host: litevirt would create one and serve DHCP on it, which is a second allocator over NetBox's range. **The refusal does not stop a placement** — every caller logs it and creates the bridge itself — so what actually happens is that a VM lands here on a bridge litevirt just made, with no DHCP server, no uplink and no gateway, holding an address NetBox believes is routable. Whether litevirt has to create the bridge is host-local runtime state no row records, so a bind validated on one node cannot speak for another; this finding is that fact stated per host. Fix it by giving the bridge an uplink on this host (a NIC, a bond, or a VLAN sub-interface), or by defining the network so litevirt serves no DHCP on it (a VLAN, type `direct`, or no subnet). | Two consecutive revalidation passes on **that node** in which the bridge exists **and has an uplink**, or in which the definition no longer makes litevirt serve DHCP. A bridge that exists but enslaves nothing is the one a placement auto-created, and does **not** clear the finding. |
| `netbox_cluster_name_unpublished` | the host | A **live** host has published no resolved `netbox.cluster_name` at all, so this node cannot establish that the setting is uniform and **declines to mirror**. The evidence names the hosts it is waiting for. Every node configured for NetBox publishes on its first maintenance pass, so this normally clears within one interval; the one shape that does not clear itself is a live **worker** running with `netbox.enabled` off, which never publishes because it runs no NetBox pass — enable NetBox there, or remove the host. A host with `role=witness` is excluded from the wait: it votes, never hosts a workload, and so has nothing to be uniform about, and must not be able to block mirroring forever. A witness that *is* configured for NetBox still mirrors like any other node — what makes excluding it safe is that it runs the same comparison itself and declines when it disagrees, which is also why a witness never excludes another witness. Mirroring stops rather than running against a set litevirt knows to be incomplete: a peer that has not spoken may be about to publish a different name, and one pass is enough to write the whole inventory under the wrong cluster. Address allocation is unaffected. | Two consecutive revalidation passes on **that node** in which every live host has published. |
| `netbox_discovery_unclaimable` | the host | A guest **on this host** is using an address on a bound network that NetBox will not grant it, so litevirt refused to record it. `reason=not_ours` is the serious one: NetBox holds that address for something else, which means two things are using it — the collision the feature exists to prevent, arriving from the one direction litevirt cannot stop (a DHCP server it does not run). The evidence names every affected guest, its address and the bounded reason. The address is left off the NIC record rather than asserted as litevirt's, so it is also missing from cloud-init, from the inventory mirror and from every "is this address free" answer. Nothing repairs it automatically: find what else holds the address and move one of them off. | Two consecutive revalidation passes on **that node** after the address becomes claimable — the IP scanner re-attempts every 30 seconds, so a refusal that has resolved clears on its next tick. |
| `netbox_cluster_name_disagreement` | the host | A **live** peer published a different resolved `netbox.cluster_name` than this node resolves, so this node refuses to mirror inventory. The evidence names both values and the peers holding the other one. This is the check a cluster with **no bound network** has — there is no binding row to pin, and mirroring is the only thing such a cluster does with NetBox — and it is raised on **every** disagreeing node, because with two nodes holding two values neither is authoritative. Only voting-eligible hosts count (`health.VotingEligible`), minus witnesses, so neither a host that is offline, in maintenance, fenced or decommissioned nor a `role=witness` host (which has nothing to be uniform about, and still gates itself) can block mirroring with a stale or absent published value. Address allocation is unaffected. Fix the config on the node that is wrong and restart it. | Two consecutive revalidation passes on **that node** see every live host publishing the same name. |
| `netbox_address_not_changeable` | the NetBox address id | The inventory mirror withheld removing an interface or VM because an address on it could not be detached: the NetBox API token litevirt uses may view the address but not change it, and removing what holds an address destroys it in NetBox. The evidence names the address, the interface and the object being removed. Nothing else stops: every other action in the pass runs, and only that one removal is withheld, on every pass. Give the token change permission on `ipam.ipaddress`, or detach the address in NetBox by hand. | Two consecutive mirror passes that attempt every removal they plan and withhold none for that address. A pass that held back its removals for want of evidence (see the withholding warnings above) attempts none, so it neither raises nor clears this finding. |

The three-pass threshold is deliberately per-process state held by the lease
holder: a daemon restart or a lease handover re-arms it, and three fresh passes
re-raise the finding. Forgetting is the safe direction for a warning whose whole
claim is "this has been stuck for a while".

## Cluster HA disarm conditions

`lv cluster ha` disarms and arms automatic fencing and recovery
([migration-failover.md](migration-failover.md#disarming-ha-for-planned-maintenance)).
Each condition below is written by the host it is about (subject
`host/<name>`), and appears in `lv health`.

| Code | Severity | Raised when | Clears when |
|---|---|---|---|
| `ha_disarmed` | warning | This host's replica holds a disarm. The evidence names who set it, when and why. | The host's replica holds an arm. |
| `ha_policy_unreadable` | critical | This host holds an HA policy row it cannot read, or its in-memory copy of the policy has failed to load for five seconds (`HA cache load failing on <host>: <err>`). Its failover coordinator decides nothing, and its health-probe answer holds every other coordinator back. Set the policy again with `lv cluster ha arm` or `disarm`, or fix the host's store. | The row reads again. |
| `ha_disarm_peer_veto` | warning | The failover lease holder's own replica says armed, and a live voter's answer held a fence or a recovery back. The evidence names each voter and the rule: `disarmed` (it holds a disarm not older than this host's row), `stale` (its answer's probe was sent more than 20 s ago), or `unknown` (it has not loaded the policy). A disarm the lease holder has not received yet looks like this. Fewer than a majority of voters live is an ordinary loss of quorum, counted as `no_quorum`, and does not raise it. | A cycle passes in which no live voter vetoes. |

