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
- **Absorbing hosts-only writes stays (deviation from item 2 above).** A latch
  is per node: a neighbour that advertises the retire token but whose own
  `host_membership_split_v1` latch has not formed yet still writes `hosts`
  alone, and a retired node must still take that write. A retired writer's
  entries carry their `host_membership` statement and are never absorbed, so
  keeping the absorb costs nothing.

## Out of scope

The operator-config and self-reported column groups (#267's host_config and
host_runtime) take the same two-release path in their own slices. State and
isolation still share `host_membership`'s one clock with each other.
