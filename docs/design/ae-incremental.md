# Incremental anti-entropy: bucketed digests and streamed repair

Status: **in progress** — bucketed digests and the digest cache first, then
streaming. This is the last part of colonelpanik/litevirt#262,
"Repair and probe traffic is not O(N)". The probe plan, observation repair,
table-scoped dumps and settled N-way ties landed first (see
[operating-model.md](../operating-model.md#replication)). What they left:

- **Every pass recomputes every digest.** `StateDigest` scans every
  replicated table, encodes every row and hashes the sorted encodings, once for
  the pass and once for every peer that asks (about 55 ms and 5.7 MB at 50-node
  scale, `BenchmarkStateDigest_50Nodes`), whether or not anything changed.
- **One drifted row still costs its whole table.** A table-scoped dump carries
  every row of each mismatched table, so one row of 50,000 is 50,000 rows sent
  and merged.
- **A pull is materialised whole.** The server builds the entire payload in
  memory, marshals it, gzips it and only then chunks it; the client reassembles
  every chunk, inflates, unmarshals and only then merges.

## Options for the digest

**A rolling per-table digest maintained on apply.** Each write updates the
table's hash in place. Rejected. The current table hash (sorted SHA-256 over
row encodings) cannot be updated without the other rows, so this needs a new
homomorphic hash *and* a hook on every path that writes a row: the WAL apply,
the merge, every local writer, schema migrations, and `NewLocalClient` in
another process. A path that is missed leaves the digest permanently wrong, and
the dangerous direction is a digest that says *equal*: anti-entropy is the
safety net, and a net with a hole that nothing ever re-checks is worse than a
slow one.

**A version-vector or HLC watermark** ("I have everything up to T from
host H"). Rejected. Merges resolve on wall-clock `updated_at`, not on the
HLC, and a watermark cannot express what the merge keeps local on purpose: an
unresolved tie, a future-skewed row the skew guard refused, a row refused by an
authority gate or an audit floor, a hard delete, `audit_log` rows with no
`updated_at` at all. Every one of those is "newer than T and still different",
which is exactly the case a watermark reports as in sync.

**Bucketed digests (a one-level Merkle tree).** Chosen. Each table's rows are
split into 256 buckets by a hash of a *bucket key*, and each bucket has its own
count and hash, built exactly like the table hash. When two table digests
disagree, the peers exchange that table's bucket digests and the pull carries
only the buckets that differ. It changes nothing about what "equal" means — a
bucket hash is the table hash's own construction over fewer rows — so there is
no new way to be wrong, only a narrower pull.

**And the recompute:** a per-table cache of the table digest and its bucket
digests, dropped whenever anything touches the table. The trigger is an SQLite
*pre-update hook* on every connection of the daemon's pool
(`digest_cache.go`), which SQLite fires for every row an INSERT, UPDATE,
DELETE, UPSERT or REPLACE changes, WITHOUT ROWID tables and a `DELETE` with no
`WHERE` included (a registered hook disables the truncate optimisation). It
sits below every Go write path, so no writer can forget to invalidate. It is
still not the only defence:

- `PRAGMA schema_version` is part of the cache key, so DDL (which fires no row
  hook) drops everything;
- the `digest_v2` flag is part of the key;
- an entry is never trusted past `digestCacheMaxAge` (10 minutes). That bounds
  what the hook cannot see: a write by another process (`NewLocalClient`) and a
  writer that commits outside `Client.mu` (none today; the generation is read
  under the same read lock the scan holds, and every in-package writer holds
  the write lock across its commit);
- `lv cluster converge` (`RunOnce`) recomputes its own digests from a scan.

A single-row incremental update of the bucket hash was considered and left
out: the pre-update hook fires before the transaction commits, so a rolled-back
write would corrupt a running hash. Rescanning a table that changed is correct
by construction and costs what a pass costs today, for that table only.

## The bucket key

A bucket must mean the same rows on both sides, and it must keep together the
rows the merge reads *from the same payload*. The only such dependency is the
authority manifest (`anti_entropy_authority.go`): a VM child row is checked
against the `vms` row in the payload that has its `vm_name`, and a container
interface against its `containers` row. So:

| Table | Bucket key |
|---|---|
| `vms` | `name` |
| `vm_interfaces`, `vm_disks`, `vm_nics`, `vm_pci_intent`, `vm_pci_realizations` | `vm_name` |
| `containers` | `host_name`, `name` |
| `container_interfaces` | `host_name`, `ct_name` |
| `operation_steps` | not bucketed |
| every other table | its primary key |

With the parent and its children keyed by the same value, "buckets 3 and 7 of
`vm_disks`" resolves to "buckets 3 and 7 of `vm_disks` and of `vms`", which is
every parent row those children can name. `operation_steps` reads the
operation *and* the workload that operation names, which no single key can
co-locate, so it is always pulled whole with its parents, as today.

The index is the first byte of SHA-256 over the key cells, length-prefixed in
their canonical digest_v2 form. The table name is deliberately left out so
that co-keyed tables share buckets. The scheme is versioned
(`bucket_scheme = 1`, 256 buckets); a peer answering with another scheme is
treated as one that cannot bucket.

Every other merge decision reads the local database, not the payload
(natural-key identity, tombstone sweeps, the audit floors, the credential
floor), so merging a subset of a table's rows is the same as merging all of
them where the rest were byte-identical — and a row in an agreeing bucket is
byte-identical, because its bucket hash covers its whole encoding.

## Correctness by row class

- **LWW.** Unchanged: the rows that reach the merge are the peer's rows,
  merged by the one engine. A bucket that differs is pulled whole, both sides'
  rows included.
- **Tombstones.** A soft-deleted row is a row; its `deleted_at` changes its
  encoding and so its bucket. A hard delete makes the bucket differ; the pull
  carries the peer's remaining rows and the merge, non-destructive as always,
  keeps the local one, exactly as a whole-table pull does.
- **Sensitive lane.** Bucket digests for sensitive tables are served only to a
  replication peer whose certificate names the sender, the same check the
  sensitive dump makes. The sensitive dump now also takes the mismatched table
  list and their buckets instead of always sending every sensitive table.
- **Settled ties.** The proof that a table differs only by tracked ties
  compares the pulled rows with the local rows *in the pulled buckets*, and
  requires every other bucket's local digest, taken in the same scan, to equal
  the peer's. Its record is unchanged (the whole-table digest pair), so a
  settled table is still not pulled until either side's digest moves, and the
  bucket exchange is not even made for it.
- **The guarded statement rule** applies to replicated WAL entries. Repair
  merges write nothing to `mutation_log`, and this change adds no replicated
  statement, so the ledger and `stmtshapecheck` are unaffected.

## Mixed versions

No capability token. The guarantee here is pairwise and checked at the point
of use: a node asks one peer for bucket digests and uses them only if that
peer answers with the same scheme. No node relies on a third party honouring
anything, so a latch would buy no safety and would hold the saving off until
the last node upgraded. It is not `ReplicationGated` either: nothing new is
replicated or stored.

- A new node against an old peer: `GetTableBucketDigests` is `Unimplemented`,
  so the pass pulls whole tables exactly as today.
- An old node against a new peer: it never asks for buckets, and the new
  server answers the old RPCs as before.
- An old server receiving the new bucket fields ignores them (proto3) and
  sends whole tables, a superset the merge handles; a new client asks only a
  peer that has just answered the bucket RPC.
- `anti_entropy_legacy_repair: true` is the stand-down: this node asks for no
  buckets, pulls whole tables, streams nothing and caches no digest. It still
  serves the new RPCs to its peers.

## Streaming

`StreamTableRows` (and `StreamSensitiveTableRows`) replace the one-blob dump
for a new pair. The server reads each table in primary-key order a page at a
time (at most `antiEntropyPageRows` rows, each page under its own brief read
lock, keyset-paginated), filters it to the requested buckets and sends it as
messages of at most `antiEntropyPageRows` rows and `antiEntropyPageBytes` of
encoded rows each, gzipped. The client merges each
page as it arrives, so neither side holds more than a page of an ordinary
table.

The exception is the parent tier. The authority manifest must see every
`vms`, `containers` and `operations` row of the payload before a child row
is judged, and before any parent row is applied (the manifest also detects a
duplicated identity). The server sends tables in merge-dependency order, and
the client buffers the parent tier, builds the manifest, merges the parents
and then streams everything after them. A table with tracked ties is also
kept, so its settled-tie proof can read it. So memory is bounded by one page
plus the parent tier of the pull — which, bucketed, is only the parent rows in
the pulled buckets.

A page is not a snapshot of its table, and it never was: the whole-table dump
already read each table under its own lock. The merge converges per row, so a
row written between pages is either in a later page or caught by the next pass.

## Operator-visible

- `litevirt_antientropy_digest_tables_total{result}` — tables whose digest a
  pass or a peer's request took from the cache (`cached`) or scanned
  (`computed`).
- `litevirt_antientropy_pull_rows_total{scope}` — rows a repair pull received,
  from a bucketed table (`bucket`) or a whole one (`table`).
- `litevirt_antientropy_digest_seconds` is unchanged in meaning (the wall time
  of one digest); with the cache it falls to the tables that changed.
  `dump_bytes` is the compressed size of one repair pull, now a bucketed or
  paged one; `rows_merged_total` and `rows_skipped_total` count as before.
- `anti_entropy_legacy_repair` (default `false`).
