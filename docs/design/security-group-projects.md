# Design: per-project security groups

| | |
|---|---|
| Status | **Implemented** |
| Base | integration `9eb7951f`, schema v69 |
| Schema | one additive column, `security_groups.project` (v70, renumbered at merge) |
| Gate | release feature `sg_projects` of `release_2026_11_v1` |

## 1. Data

`security_groups` gains `project TEXT NOT NULL DEFAULT ''`, appended last in
the `CREATE TABLE` and added by an `ALTER TABLE ... ADD COLUMN` (additive
only; nothing is rewritten or dropped).

- `project = ''` is a **global** group. Every existing group migrates as
  global, and every group a stack creates is global.
- `project = 'P'` is owned by project P, which must exist; the group is stored
  under the project's own name. It is set at create and never changed.
- A project that still owns a group is not deleted (`lv project rm` refuses).
- A project's group has no stack (create refuses both together), and it never
  adopts rules an older client stored under its name: it starts empty, and
  deleting it leaves such rules alone.
- Group names stay unique cluster-wide, across projects. A NIC binds a group
  by name, so a name two groups hold is still held at drop (unchanged).

## 2. RBAC

A group's path is `/` for a global group and
`/projects/<P>/security_groups/<name>` for a project group.

| RPC | Check |
|---|---|
| `CreateSecurityGroup` | `sg.write` on the new group's path |
| `DeleteSecurityGroup`, `AddSecurityGroupRule`, `RemoveSecurityGroupRule` | `sg.write` on the path of the group (for a rule, the rule's group); a rule no live group owns needs `/` |
| `AddSecurityGroupRule` of an IPv6, logged or tag-group rule on a project group | also `sg.write` at `/`: it records a cluster-wide release-feature use, and a logged rule writes host logs |
| `DeployStack` with a firewall block, or of a stack that owns firewall rows (a redeploy replaces or drops them) | `sg.write` at `/`: stack groups, ip sets and the default policy are global. Checked before anything changes; a dry run is not refused and reports that the real run would be |
| `DeleteStack` (`lv compose down`) of a stack that owns firewall rows | `sg.write` at `/`, checked before anything is torn down, so a refused down leaves the stack whole |
| `ListSecurityGroups` | per row, below |

`ListSecurityGroups`:

- `sg.read` at `/` sees every group and rule (root sees all). `project` narrows
  the list to that project's groups plus global groups.
- Otherwise each project group is listed when the caller holds `sg.read` on its
  path. With `project` set (and `sg.read` on that project), global groups are
  listed too, without their rules: a project's VMs may bind them, and their
  rules stay readable only at `/`, as before. A caller with neither gets an
  empty list, not a refusal.

`CreateSecurityGroup` and `DeployStack` refusing a duplicate name name the
existing group's id only when the caller may read that group.

## 3. Which groups a workload may reference

A workload in project W may bind a global group or a group owned by W, never
another project's (`tenancy.AdmitAttach`, the network rule). Enforced twice:

- **At write**, on the node that writes the binding: `CreateVM`, VM
  recreate, `AttachDevice` (NIC, at the entry and at the owner),
  `BindSecurityGroups`, container create, VM and container clone, live
  restore and container restore refuse a foreign group with
  `PermissionDenied`. A name no group holds is accepted, as before. (VM import
  carries no groups.)
- **At render**, on every host: the firewall reconciler does not resolve a
  foreign project's group for a NIC; it is skipped like an unknown name and
  logged. This covers a binding made before the group existed (a name another
  project later creates) and any write path not listed above.

## 4. Rolling upgrade

The project-carrying insert is a new statement shape. A previous-release peer
has no ledger entry for it and no `project` column, so its apply would fail
closed and stall its stream. A project group is therefore written only through
the release feature `sg_projects` of `release_2026_11_v1`
(`Server.WithReleaseFeature`, writer `corrosion.InsertProjectSecurityGroup`,
which checks the feature's grant). Until the release token has latched the RPC
answers `FailedPrecondition`; before the first project group the use is
recorded and acknowledged by every replication recipient, so a rollback below
the release quarantines only a cluster that created one. A global group keeps
the previous insert shape and needs no feature.

Before the latch, anti-entropy rows of `security_groups` sent from an upgraded
node carry the `project` column, which a previous-release peer refuses as an
unknown column; it still applies the WAL entries (the v68 precedent).

## 5. CLI

```
lv sg create <name> --project <P>   # owned by P; omit for a global group
lv sg ls --project <P>              # P's groups and the global groups
```

`lv sg ls` prints a PROJECT column (empty = global). Against a daemon that
does not declare the `sg_projects` feature (`GetUpgradeStatus`), `--project` is
refused rather than creating a global group or listing unfiltered. A token
scoped below the root cannot read the upgrade status; its create is sent, a
previous daemon refuses it (it checks `sg.write` at `/`), and the CLI checks
the created group's project. The web UI
takes a project on its create form and `?project=` on `/security-groups`, and
the Add-NIC dialog lists the VM's project's groups and the global ones.
