# Design: per-project security groups

| | |
|---|---|
| Status | **Implemented** |
| Base | integration `458db618`, schema v68 |
| Schema | one additive column, `security_groups.project` (v80, renumbered at merge) |
| Token | `sg_projects_v1`: mandatory, replication-gated, no flag |

## 1. Data

`security_groups` gains `project TEXT NOT NULL DEFAULT ''`, appended last in
the `CREATE TABLE` and added by an `ALTER TABLE ... ADD COLUMN` (additive
only; nothing is rewritten or dropped).

- `project = ''` is a **global** group. Every existing group migrates as
  global, and every group a stack creates is global.
- `project = 'P'` is owned by project P. It is set at create and never
  changed.
- Group names stay unique cluster-wide, across projects. A NIC binds a group
  by name, so a name two groups hold is still held at drop (unchanged).

## 2. RBAC

A group's path is `/` for a global group and
`/projects/<P>/security_groups/<name>` for a project group.

| RPC | Check |
|---|---|
| `CreateSecurityGroup` | `sg.write` on the new group's path |
| `DeleteSecurityGroup`, `AddSecurityGroupRule`, `RemoveSecurityGroupRule` | `sg.write` on the path of the group (for a rule, the rule's group); a rule no live group owns needs `/` |
| `ListSecurityGroups` | per row, below |

`ListSecurityGroups`:

- `sg.read` at `/` sees every group and rule (root sees all). `project` narrows
  the list to that project's groups plus global groups.
- Otherwise each project group is listed when the caller holds `sg.read` on its
  path. With `project` set (and `sg.read` on that project), global groups are
  listed too, without their rules: a project's VMs may bind them, and their
  rules stay readable only at `/`, as before. A caller with neither gets an
  empty list, not a refusal.

`CreateSecurityGroup` refusing a duplicate name names the existing group's id
only when the caller may read that group.

## 3. Which groups a workload may reference

A workload in project W may bind a global group or a group owned by W, never
another project's (`tenancy.AdmitAttach`, the network rule). Enforced twice:

- **At write**, on the node that writes the binding: `CreateVM`,
  `AttachDevice` (NIC), `BindSecurityGroups`, container create, VM import,
  VM and container clone, and live restore refuse a foreign group with
  `PermissionDenied`. A name no group holds is accepted, as before.
- **At render**, on every host: the firewall reconciler does not resolve a
  foreign project's group for a NIC; it is skipped like an unknown name and
  logged. This covers a binding made before the group existed (a name another
  project later creates) and any write path not listed above.

## 4. Rolling upgrade

The project-carrying insert is a new statement shape. A previous-release peer
has no ledger entry for it and no `project` column, so its apply would fail
closed and stall its stream. Corrosion therefore refuses to write a group with
a project until `sg_projects_v1` has durably latched (`Client.SetSGProjectsGate`,
wired to `Checker.DurablyLatched`); the RPC answers `FailedPrecondition`. A
global group keeps the previous insert shape and is never gated.

`sg_projects_v1`:

- **Replication-gated** (`capabilities.replicationGated`): the claim is about
  what every host still receiving replication can decode, a maintenance host
  on the previous build included.
- **Mandatory** (`capabilities.mandatory`), advertised unconditionally. It
  states a fact about the binary: it decodes the column, refuses foreign
  references at write and skips them at render. Both guarantees are enforced
  on the node that writes or renders, so no node relies on a peer's config
  and a flag would buy nothing; a flag-gated token withheld while off would
  only keep the latch from forming.
- Stand-down: none needed. Latching changes nothing until a project group is
  created; removing such groups (`lv sg rm`) undoes the use.
- Rollback below the latched token: WAL quarantine, as below every latched
  token. Roll forward.
- Retiring it later: move it from `All()` to `capabilities.retired` in the same
  change, never delete the name, never reuse it.

Before the latch, anti-entropy rows of `security_groups` sent from an upgraded
node carry the `project` column, which a previous-release peer refuses as an
unknown column; it still applies the WAL entries (the v68 precedent).

## 5. CLI

```
lv sg create <name> --project <P>   # owned by P; omit for a global group
lv sg ls --project <P>              # P's groups and the global groups
```

`lv sg ls` prints a PROJECT column (empty = global).
