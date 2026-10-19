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
| `DeployStack` of a stack that has a firewall (below), or whose file declares one | `sg.write` at `/`: stack groups, ip sets and the default policy are global. Checked before anything changes; a dry run is not refused and reports that the real run would be |
| `DeleteStack` (`lv compose down`) of a stack that has a firewall | `sg.write` at `/`, checked before anything is torn down, so a refused down leaves the stack whole |
| `DeleteStack` of a stack the entry node holds no record of, without `sg.write` at `/` | not refused: a local-only teardown (below) |
| `ListSecurityGroups` | per row, below |

A stack "has a firewall" when it owns a firewall row on the entry node, or
its stored file declares a firewall block (a default-deny it only asks for
while another stack owns the row decides whether that deny is handed on), or
its stored file cannot be read (fail closed).

The entry node's replica may lag, and a teardown's stack state and record
writes are applied by name on every peer, whose `StackReconciler`
(`reconcileStack` → `DeleteStackFirewall`) then removes the stack's firewall
rows. So `DeleteStack` on a node that holds no record of the stack, by a
caller without `sg.write` at `/`, is local-only: it removes the workloads that
node lists by the stack's name and writes no stack state, record, load
balancer, network, backup-repo or firewall row, and nothing retries a workload
it cannot delete. A first `lv compose up` that failed in the workload phase
leaves such workloads and no record anywhere, and also its networks and
backup-repo registrations (registered before the workloads), which stay for an
Admin. The teardown sends a `local-only` progress status whose text says what
is left and how an Admin removes it (`lv compose down --name <stack>`, from any
node, record or not: an Admin's down is the full one, which finds networks and
backup repos by their stack name); the CLI, the UI and the REST API (`local_only`,
`notice`) report it as a local-only teardown, never as a complete one.

Residual: a node that holds an older stack file without a firewall, and
neither the newer file nor the rows, authorizes a non-root teardown or a
redeploy that withdraws a deny ask. The window is replication lag right after
an Admin deploy that adds the firewall (the deploy writes the rows before the
record). Closing it would mean recording the stack's `compose_hash` the entry
node authorized against in the teardown record `MarkStackDeleting` already
writes to `cluster_policies` (`stack_teardown/<name>`, free-form JSON, no
schema change), and having a peer's reconciler keep the firewall rows when its
own record's hash differs. Not implemented.

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

`lv sg ls` prints a PROJECT column (empty = global). Before `--project` is
used, the CLI probes the daemon with a listing of a malformed project: a build
that implements project groups validates that field before any authorization
and answers InvalidArgument; one that does not (including a build whose
release catalog only declares `sg_projects`) ignores the field, so the CLI
refuses rather than create a global group or list unfiltered. The probe needs
no more than a listing, so a token scoped to a project can make it. The CLI
also checks the created group's project. The web UI
takes a project on its create form and `?project=` on `/security-groups`, and
the Add-NIC dialog lists the VM's project's groups and the global ones.
