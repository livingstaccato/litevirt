# Design: retiring the old host-state columns

| | |
|---|---|
| Status | **Proposed**. Nothing in this document is implemented. |
| Issue | colonelpanik/litevirt#267 |
| Follows | schema v57, `host_membership_split_v1` |

**Reading this document.** Present tense describes code that exists. Anything
marked *proposed* does not exist yet, including the token and statement named
below.

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
2. The absorb exception in the read rule goes away. With no writer left that
   writes the `hosts` columns alone, nothing is there to absorb.
3. The columns are **not** cleared. `hosts.state` is `NOT NULL`, and clearing
   it is a `hosts` write that would race the host's own reports. A column
   nothing writes or reads is inert. Dropping it is a schema change the
   additive-only migration rule does not allow, and it can wait for a rebuild
   of the table if one ever happens.

Rolling back from the release that latched the retire token lands on the v57
release, which reads `host_membership`. So the step is rollback-safe one
release back, as v57's was.

## Out of scope

The operator-config and self-reported column groups (#267's host_config and
host_runtime) take the same two-release path in their own slices. State and
isolation still share `host_membership`'s one clock with each other.
