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
```

`show` is read-only. `abort` is admin-only, requires `--force`, is audited, and
clears the barrier only via the exact owner-epoch + spec-generation
compare-and-swap — so it can never clear a newer operation's barrier, and an
ordinary mutation's `--force` never bypasses the barrier.

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
advertised a token for a writer that never shipped. A config that still sets it is ignored.
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
IPMI-confirmed power-off, or an operator `lv host fence-confirm` — required
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

### What a fence established

`lv doctor fence` also lists the fences of the last 7 days (newest 20), each
with an **assurance** — what that fence actually establishes about the host.
The stored `fencing_log.result` cannot make this distinction: it says `fenced`
both for an IPMI power-off that was observed off and for an SSH poweroff nobody
checked.

| Assurance | Produced by | Means |
|---|---|---|
| `verified` | `ipmi` + `fenced` | Powered off, then observed off. |
| `operator-confirmed` | `lv host fence-confirm` | A person attested the host is down. |
| `requested` | `ssh` or `watchdog` + `fenced` | The host accepted a forced power-off, or its watchdog heartbeat was stopped. Nothing checked it went down. |
| `assumed` | `best-effort-ssh` + `fenced` | SSH itself failed and the best-effort strategy proceeded anyway. Not even the request is known to have arrived. |
| `self_paused` | `best-effort-ssh` + `fenced`, detail prefixed `[relies on the host's partition pause]` | As `assumed`, but with `partition_pause_v1` latched: the coordinator waited out the host's own partition pause before it recovered anything, so the old copy had stopped executing. It says nothing about power. `litevirt_fences_total` counts it as `assumed`. |
| `awaiting-confirmation` | `manual` + `partial` | A manual fence waiting for a person. Not a failure. |
| `failed` | any + `partial` | The fence ran and reported failure. |

Only `verified` and `operator-confirmed` satisfy the shared-storage fence
(`corrosion.FenceProofGrade` is defined in terms of this table). A `requested` or
`assumed` fence still lets the coordinator that ran it reschedule **local-disk**
VMs, which is why the command prints a note when it finds one. A later
coordinator never resumes a recovery from one — resuming needs a proof-grade
fence. `lv host fence` prints the same assurance for the fence it just ran.

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
- **Persistence failure is fail-closed.** If the daemon cannot persist a higher ceiling
  and its in-memory headroom is exhausted, it **exits** rather than emit a key below the
  last durable ceiling. Because the state DB shares the `dataDir` filesystem, a full disk
  already fails writes; the crash surfaces it loudly. Recovery = free space.

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

`containers` ownership is part of the primary key, so an ownership split is two
distinct rows (not a single-row tie) — detected by `duplicate_live_container`
above and repaired by the container runtime-repair phase, not the row resolver.

The anti-entropy merge is the authority; the WAL fast-path resolves full-image
upserts through the same engine and otherwise keeps local and lets anti-entropy
converge the row, so the two paths can never disagree.

### Metrics

- `litevirt_lww_tie_break_total{table,resolver,winner}` — ties that converged by a
  deterministic resolver (`content_max`/`numeric_max`/`timestamp_max`/
  `non_null_wins`/`lb_generation`). A steadily climbing value means a node is
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

Either way the fresh timestamp wins everywhere by ordinary LWW and clears the
unresolved tracking. Both also move the VM's `vm_disks` rows to the host that
runs it, in the same write. Failover moves them with the VM too. Builds before
that re-keyed only the `vms` row, so a VM recovered by one of them can still
have disk rows naming the host it left. Running `lv doctor repair-owner <vm>
<host-that-runs-it>` once realigns them. A migration also commits over such a
row, as long as the row has not changed since the migration began.

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
  scan;
- resolution needs **two consecutive clean scans with complete coverage** by
  the detector lease holder under a valid decision gate — an unreachable,
  partial, or older-binary peer blocks resolution (blind is not clean);
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
  failed DB read. Container and VIP conditions keep the cluster-wide rule
  (names are not unique; a VIP has no creation stamp), so a registered host
  that is permanently gone still freezes those until `lv host rm`;
- leadership changes and restarts preserve counts and confirmed state;
- resolved conditions stay readable for 30 days (`lv health --resolved`),
  then are tombstoned;
- there is **no force-clear**: remove the cause, and the evaluator proves
  the resolution.

`lv health` prints the overall state (HEALTHY / DEGRADED / CRITICAL /
UNKNOWN), every active condition with its involved hosts, evaluator
coverage, peer connectivity, and per-host effective capacity — and exits
0 / 1 / 2 so scripts can gate on it.

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
runtime workloads each minute into `host_capacity_observations` — a rogue
runtime the database does not know about still consumes headroom in
placement, and an uncapped rogue container makes the host's capacity
explicitly *incomplete*, which disqualifies it as a placement target until
resolved.

The `capacity:` table in `lv health` has one row per host that has sampled:

```
capacity:
  HOST    EFFECTIVE   DB                    EXTRA    COMPLETE  DETAIL
  node-4  1c/1280MiB  1c/768MiB +512MiB ct  0c/0MiB  true
```

- **DB** is what the database holds on the host now, read at request time
  with the rules placement charges by: running VMs at their recorded vCPU and
  memory, then (`+… ct`) the memory of running containers. A container is
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
what clears it; the condition resolves on the tick genesis succeeds.

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
enabled and latched the write is additionally epoch-conditioned. Expect the
deferral to last up to one anti-entropy interval (`anti_entropy_interval_sec`,
60 s by default) after a restart. A single-node cluster — no other host in the
hosts table — is not gated. The same sync is also withheld, on a current
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
DeleteVM refused on node-1: this node's replica has not caught up with the cluster yet (...), so it cannot tell which host owns the workload now. Retry in a minute, or run the command against another node
```

Served from a stale record, such a command acts on the wrong copy and writes
the stale owner back. Observed on a lab: a VM rescheduled from node-1 to node-4
while node-1 was down; node-1 came back and served `lv compose down` three
seconds before its first anti-entropy exchange. It destroyed its own shut-off
leftover and tombstoned the record naming itself, and that tombstone replaced
the owner's record everywhere — the VM kept running on node-4 with no record.
Retry after the `replica caught up` journal line, or run the command on any
other host. A single-node cluster is not gated.

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

### Partition pause (`partition_paused`, `partition_pause_failed`, `partition_one_way`, `vm_settled`, `vm_settle_declined`)

Evaluator `partition_pause` (design/partition-pause.md). Every row is written by
the host it is about, except `partition_one_way`, which the failover lease
holder writes.

- `partition_paused` (host, warning): this host lost the voter majority for
  10 s and paused its recoverable workloads itself. The evidence lists them.
  It resolves when the last one resumes. Each workload resumes on its own once
  the majority is back, its row still names this host at the same owner epoch
  and incarnation, and a majority of voters confirms that this host is not
  fenced and that no recovery claim moved it. One that stays paused is logged
  with the reason:
  ```
  partition-pause: paused workload       kind=vm name=<vm> reason="lost the voter majority for 10s (…)"
  partition-pause: resumed workload      kind=vm name=<vm> reason="majority regained; …"
  partition-pause: workload stays paused kind=vm name=<vm> reason="voter node-4 has node-1 HOST_OFFLINE"
  ```
  A host the majority fenced while it was paused stays paused until
  `lv host undrain` (or until failover returns it to active, when its fence
  moved nothing). A workload that a certified claim moved is stopped by the
  settle step below, not resumed.
- `partition_pause_failed` (host, critical): this host lost the majority and
  could not pause a workload it had to. While it is open, the majority does
  not rely on this host's pause and recovers on an `assumed` fence as before.
  With a verified hardware watchdog armed the host also self-fences. It
  resolves once every pause succeeds or the majority returns.
- `partition_one_way` (host, critical): a quorum of voters cannot reach the
  host while the host's own rows, written after those failures began, still
  mark a majority healthy. That is a one-way partition, in which the host may
  never pause. Nothing is recovered differently; find the asymmetric link.
- `vm_settled` / `ct_settled` (`<name>@<host>`, warning): a host came back
  holding a copy of a workload that a decided recovery claim, whose
  certificate verifies, gave to another host at the same incarnation and an
  owner epoch at least its own, on a proof its destination completed, while
  the destination's own runtime reports the workload running. The host
  stopped its copy (a VM is destroyed, which keeps its definition and disks)
  and wrote a `partition.settle` audit row. The leftover cleanup then handles the shut-off domain as usual.
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

  The row naming another host is not proof on its own: a converged-wrong
  `host_name` looks exactly the same. Before stopping anything, confirm which
  copy is current. `lv cluster claim vm/<vm>` shows the decided claim and its
  destination, and `virsh domstate <vm>` on that destination shows whether it
  runs there. Only if the claim gave the VM to that host and it runs it there
  is the local copy a superseded duplicate. Stop it on this host with
  `virsh destroy <vm>`. Its disks are kept, but its definition and NVRAM are
  removed on the next reconcile pass, because the leftover cleanup undefines
  a destroyed domain whose row moved. Otherwise leave the local copy running.
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
[audit-log.md](audit-log.md#rebuilding-a-host-under-its-old-name). The condition
row is rewritten only when what it says changes.

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

**Nothing reaps an orphan automatically.** The only tombstone that could prove a
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

Seven NetBox failures are silent to everything else litevirt reports, so they are
also durable `health_conditions` rows and appear in `lv health` (see
[Cluster health](#cluster-health-durable-conditions-and-the-admission-gate-v50)).
The first two are raised by the orphan sweep, which runs under the `netbox`
leader lease, so the cluster has exactly one writer. The other five are
per-node — they are about one node's own configuration or its own runtime, which
no peer can read — so every configured node raises them for itself, keyed on its
own host name, and a node that agrees never clears a peer's finding. All seven
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

The three-pass threshold is deliberately per-process state held by the lease
holder: a daemon restart or a lease handover re-arms it, and three fresh passes
re-raise the finding. Forgetting is the safe direction for a warning whose whole
claim is "this has been stuck for a while".
