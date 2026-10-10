# Design: retiring the old host-state columns

| | |
|---|---|
| Status | **Implemented** behind `host_membership_retire_v1`, with the deviations listed under "As implemented". |
| Issue | colonelpanik/litevirt#267 |
| Follows | schema v57, `host_membership_split_v1` |

**Reading this document.** It was written before the token existed; the
section "As implemented" at the end records what the code does.

## Where v57 leaves things

Once `host_membership_split_v1` latches, every writer of a host's state and
isolation writes both `host_membership` and `hosts.state` /
`hosts.isolation_epoch` / `hosts.isolation_reason`, in one batch under one
`updated_at`. Readers resolve from `host_membership`. Nothing clears the
`hosts` columns.

The `hosts` copy exists for exactly one reader: a host rolled back one release,
which reads state and isolation from `hosts` and nowhere else. It costs the
thing #267 set out to remove, but only on that copy — each state write still
moves the `hosts` row's clock, so a state change can still overwrite a
concurrent version or resource report on some replica. The `hosts` row's
self-reported columns keep that exposure for as long as the copy is written.

## Proposed: stop writing the copy, one release later

A second token, *proposed* `host_membership_retire_v1`, mandatory and
ReplicationGated like the first. It is advertised by the release AFTER v57's.
Its latch proves every replication recipient is at least that release, whose
rollback target is the v57 release. That release reads `host_membership`, so
it no longer needs the `hosts` copy.

Once it latches:

1. Writers stop writing `hosts.state` and the isolation columns. A state
   change then moves only the `host_membership` row's clock, and the `hosts`
   row is written only by the host itself and by operator configuration.
2. Absorbing hosts-only writes (`absorbUnlatchedMembershipWrite`) goes away.
   The retire token's latch proves no replication recipient still writes the
   `hosts` columns alone, so there is nothing to absorb.
3. The columns are **not** cleared. `hosts.state` is `NOT NULL`, and clearing
   it is a `hosts` write that would race the host's own reports. A column
   nothing writes or reads is inert. Dropping it is a schema change the
   additive-only migration rule does not allow, and it can wait for a rebuild
   of the table if one ever happens.

Rolling back from the release that latched the retire token lands on the v57
release, which reads `host_membership`. So the step is rollback-safe one
release back, as v57's was.

## As implemented

- `host_membership_retire_v1` is mandatory, ReplicationGated and advertised
  unconditionally. Its gate reads the durable marker on disk, like the split
  gate (`internal/corrosion/host_membership_retire.go`).
- The pure state and isolation writers — `UpdateHostState`,
  `RecordFenceWithState`, `IsolateHost`, `ClearHostIsolation` — write
  `host_membership` alone once a live node has latched it.
- `InsertHost`, `AdmitHost`'s re-admission and `UpdateHostStartup` keep their
  `hosts` statements, `state` included: each writes other `hosts` columns in
  the same statement, so the row clock moves anyway, and keeping the shape
  adds no ledger entry.
- **Readers.** The membership row is read whenever one exists, live node
  or not, and on a node that has latched the retire token a host with no row
  reads as `unknown` (not `active`, voting-eligible) instead of from the
  frozen copy (review M1).
- **Copies.** Before the retire latch the split pass's copy is stamped at a
  floor (the hosts row's time moved back 40 years), so it only fills an
  absence; after it, the pass copies nothing (review H1: a copy stamped with
  the hosts row's moving clock over a frozen state undid a fence
  cluster-wide). An absorb on a retired node creates a missing row only from
  a complete write (review L2).
- **"unknown" acts on nothing** (re-review I2). The failover coordinator
  neither fences nor recovers a host it reads as `unknown`; it logs and skips
  it (`state_unknown`), and re-reads it next cycle. On a derived voter set such
  a host stays in every quorum's denominator but its probes never count toward
  the live numerator (`corrosion.VoterSetWithUncounted`, read in one pass with the voter set); with an adopted voter
  generation the generation's members count as usual.
- **A state write never inserts from the frozen copy** (re-review m1). A live
  writer on a retired node that has no row for the host updates an existing
  row only (`hostMembershipStateOnlySQL`); the row, with that state, reaches
  this node by anti-entropy from any node that had it.
- **A floor copy dates its hosts row** (re-review 2, N6). The floor is the
  copied hosts row's instant moved back by a fixed shift, so `HostsActiveSince`,
  `HostActiveSince` and `HostFenceLife` undo the shift and date the host's life
  from that hosts row's time, as before the split — decoded from the copy's
  own stamp, with no parent row read or compared.
- **Unknown voters never answer a resume** (re-review 2, N4).
  `CheckPartitionResume` keeps a voter it reads as unknown in the majority it
  must reach but does not ask it, the rule the quorum count applies; both read
  the voter set and the unknown set in one read
  (`corrosion.VoterSetWithUncounted`).
- **A re-admission creates or revives the row** (re-review 2, N5). A
  re-admission from a node not writing host_membership yet rewrites the
  identity row whole, so a retired node's absorb creates the host's missing
  membership row and revives a tombstoned one (keeping its isolation), instead
  of leaving the host unknown forever.
- **Absorbing hosts-only writes stays (deviation from item 2 above).** A latch
  is per node: a neighbour that advertises the retire token but whose own
  `host_membership_split_v1` latch has not formed yet still writes `hosts`
  alone, and a retired node must still take that write. A retired writer's
  entries carry their `host_membership` statement and are never absorbed, so
  keeping the absorb costs nothing.

## Known limits

- **A node that has not latched the retire token yet** (re-review m2) still
  reads, and before the latch copies at the floor, the `hosts` copy for a host
  it has no membership row for. Latches form per node, so a joiner whose
  anti-entropy merged `hosts` but not `host_membership` can read a host fenced
  after the latch as `active` until the row arrives. A failed merge marks the
  replica not caught up, which holds the coordinator back, and a floor copy
  always loses to the real row; the window closes with that node's next
  anti-entropy pass or its retire latch.
- **A previous build's copy** (re-review m4) is stamped with the raw `hosts`
  timestamp, so during the roll it beats this build's floor copy even when it
  was made from an older `hosts` row. Ordering the two would need the copy
  compared against its parent row's `updated_at`, which CLAUDE.md forbids.
  It is transient: before the retire latch the `hosts` copy is current, and
  any real or absorbed write wins.
- **Re-admission** of a removed host that has no membership row at all (it
  was removed before the split) creates one taking the isolation pair from the
  `hosts` copy, the only one there is. On a retired node, where that copy may
  be behind, the created row takes a fresh isolation epoch one above the
  copy's and is stamped just past the floor copy of the re-admission (re-review
  3, R5). Nodes that still hold the tombstoned row revive it at the
  re-admission's own timestamp with the current epoch, so their row replaces
  the created one everywhere; an equal timestamp, which would be a tie between
  two epochs that no rule resolves, cannot occur. The cost is one extra epoch
  on that node until the revived row arrives, in the fail-closed direction. A
  re-admission is recognised by its statement fingerprint, the same
  recogniser host_readmit.go uses.

## Out of scope

The operator-config and self-reported column groups (#267's host_config and
host_runtime) take the same two-release path in their own slices. State and
isolation still share `host_membership`'s one clock with each other.
