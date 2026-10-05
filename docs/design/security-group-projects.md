# Security groups owned by projects

Status: design, phase 1, decisions resolved 2026-10-05 (§10). Nothing here is implemented yet. Base: fork main
`c7aa96f9`.

## 0. Summary

A security group gets an owner. It is either **shared**, meaning cluster-wide
and managed only by holders of `sg.write` at the cluster root, or **owned by
exactly one project**. A workload may bind a shared group or a group of its own
project, and nothing else. Every path that creates a binding enforces that rule
at the point the binding is created. The firewall reconciler also enforces it
when it renders, so a reference that slipped past admission cannot take effect.

The binding namespace removes name collisions at the source. A NIC binding
stays a string, and the string is the group row's `name` column, as it is
today. For an owned group the server writes that column as
`<project>/<short-name>`. Two projects can both have `web`, stored as
`acme/web` and `bob/web`, alongside a shared `web`, and no two rows hold the
same key. Every existing binding is a bare name, every existing group becomes
shared, and a bare key only ever matches a shared row, so nothing that exists
today changes meaning. An older reconciler still resolves every key exactly,
because it matches on the same column it always has.

Ownership is a new replicated column, `security_groups.project` (schema v64).
Creating an owned group needs a new replicated statement shape, which a
previous-release peer cannot decode: its apply fails closed and stalls its whole
stream. So owned groups can only be created once a new mandatory,
replication-gated capability, `sg_projects_v1`, has durably latched. Shared
groups keep the existing statement shape and never wait on the token.

**Fix this first.** Per-NIC security groups are not reliably enforced today, and
the reasons have nothing to do with projects (§1.5). Unless that is fixed
first, the pickers and admission checks in this design would filter something
the dataplane mostly ignores. Commit 1 of the plan (§9) fixes it.

## 1. The current model

### 1.1 Schema

- `security_groups (id PK, name, stack_name, created_at, updated_at, deleted_at)`,
  `internal/corrosion/schema.go:2129-2136`. `name` has no UNIQUE constraint, and
  no other code enforces uniqueness either (§1.4).
- `sg_rules (id PK, sg_id, direction, proto, port_range, cidr, action, priority, …)`,
  `schema.go:2251-2263`. Rules reference their group by **id**.
- Both tables replicate (`internal/corrosion/sync.go:352`), and both carry an LWW
  key of `{"id"}` (`schema.go:2959-2960`).
- Bindings are JSON `[]string` of group **names** in three places:
  - `vm_interfaces.security_groups` (`schema.go:1552`; added by ALTER in v4,
    `schema.go:3040`), keyed `(vm_name, network_name)`;
  - `vm_nics.security_groups` (`schema.go:1600`, v42, keyed `(vm_name, id)`);
  - `container_interfaces.security_groups` (`schema.go:1573`).
  The VM spec JSON (`vms.spec`, `NetworkAttachment.security_groups`) and a
  container's `create_spec` (`internal/corrosion/containers.go:178`) hold a
  fourth and fifth copy. Rebuild, restore and relocation read those copies.

### 1.2 Stacks and projects

`stack_name` marks a group a compose file created, so that `compose down` can
tombstone exactly that stack's firewall state (`schema.go:2270-2272`,
`DeleteStackFirewall` at `internal/corrosion/firewall.go:310-325`).
`persistStackFirewall` (`internal/grpcapi/stacks.go:217-250`) tombstones the
stack's earlier groups and inserts fresh ones with new random ids on every
deploy. It runs before any VM is created (`stacks.go:107`).

A stack has **no project**. The `stacks` table has no project column
(`schema.go:1507-1515`). `DeployStack` gates on the legacy role
`RequireRole(…, "operator")` (`stacks.go:33`), which refuses any scoped token
(`internal/grpcapi/auth.go:695-699`), so in practice only cluster-wide
callers deploy stacks. Stack-defined networks are global by explicit choice
(`stacks.go:1972-1974`), and the compose VM spec never sets a project, so stack
VMs land in `_default`. **This design keeps every stack group shared.** A
project-scoped stack is a separate piece of work (§10, D7).

### 1.3 How the firewall resolves names to rules

`CorrosionPlanLoader` (`internal/firewall/reconciler.go:249-358`):

1. lists every live group, ordered by `name, id` (`reconciler.go:285`,
   `internal/corrosion/security_groups.go:66-76`), and their rules;
2. builds `valid[name]` (`reconciler.go:308-311`);
3. reads this host's VM NICs from **`vm_interfaces` only**
   (`ListVMInterfacesByHost`, `internal/corrosion/vms.go:519-543`), skips any
   with an empty `tap_device` (`reconciler.go:318`), and keeps only the bound
   names that are in `valid`. It drops an unknown name silently, by design
   (`reconciler.go:303-306`);
4. does the same for container NICs on `veth_device` (`reconciler.go:338-358`).

`Render` keys the groups by name, `sgByName[sg.Name] = sg`
(`internal/firewall/firewall.go:192-195`). `renderNICDispatch` expands each
bound name into the NIC's chain (`firewall.go:434-466`). Group names appear only
in an nft comment (`# security group %q`). Chain names come from the NIC
device, so a `/` in a group key is harmless to nft.

### 1.4 Duplicate names today

Two live rows can share a name: a stack and `lv sg create`, two stacks, or two
`lv sg create` calls (`CreateSecurityGroup` checks only that the name is
non-empty, `internal/grpcapi/security_groups.go:56-58`). The rows are listed in
`name, id` order and written into a map, so **the row with the
lexicographically highest id wins silently**. Every NIC bound to that name gets
only that row's rules, and the other row's rules render nowhere. The comment on
`firewall.SecurityGroup` (`firewall.go:99-102`) says operators "get a
deterministic error at deploy". That is false: `validate` (`firewall.go:543`)
checks only for an empty name. IP sets met the same problem and render the union
of the rows instead (`firewall.go:331-336`). For security groups a union would
change which traffic is accepted or dropped, and it would differ from what an
older node renders, so this design does not take that route (§3.5).

### 1.5 Pre-existing enforcement defects (found while reading for this design)

By code inspection, per-NIC security groups are enforced only for a NIC that
`CreateVM` created, and only until that VM next restarts or moves:

1. **The tap device is recorded once, at create.** `vm.go:886-900` resolves
   `vnetN` from libvirt and stores it in `vm_interfaces.tap_device`. Nothing
   else writes `tap_device`. The domain XML does not pin a NIC target
   (`internal/libvirt/testdata/xmlgen_spice_pci.golden:41-45`), so libvirt can
   assign a different `vnetN` on every start, on every host. After a stop and
   start, a migration or a failover, the recorded tap is stale. The per-NIC
   chain then matches nothing, or it matches **another VM's** tap on that host.
2. **Hot-attached NICs have no chain.** `writeNICAttachRows`
   (`internal/grpcapi/hotplug_nic.go:338-352`) writes the groups to `vm_nics`
   only. The legacy `vm_interfaces` row it dual-writes before the hardware_v2
   latch carries neither groups nor a tap (`InsertInterface`, `vms.go:1679-1686`,
   whose shape has no `security_groups` column). Once hardware_v2 has latched it
   writes no `vm_interfaces` row at all (`dualWrite: !latched`,
   `hotplug_nic.go:438`). The reconciler reads only `vm_interfaces`.
3. **Clones, promotes and auto-defined live restores lose their groups.**
   `CloneVM` (`internal/grpcapi/templates.go:244-256`), `doPromoteLocal`
   (`promote.go:980-992`) and `autoDefineRestoredVM`
   (`restore_live_autostart.go:231-243`) put `SecurityGroups` on the `vm_nics`
   record and leave it off the `InterfaceRecord`. `InsertVMWithHardware`
   writes the legacy column from the `InterfaceRecord` (`vms.go:190-200`), so
   that column stays NULL. The hardware view reads the `vm_nics`-preferring
   overlay (`MergedVMNICs`, `internal/corrosion/hardware.go:187-217`), so the UI
   **shows** the groups on those NICs while the host enforces none of them.
4. `BindSecurityGroups` updates `vm_interfaces` only (`vms.go:548-558`). The
   legacy-to-`vm_nics` bridge (`internal/daemon/daemon.go:1095-1098`) copies the
   change into `vm_nics`, so it converges, but neither path updates the VM spec.
   A later `RebuildVM` (`vm.go:3083`) restores the groups the VM was created
   with.

Adjacent, and also not about security groups: the comment at
`project_admission.go:8` says `admitNetworkAttach` gates "every create and day-2
path". In fact only `CreateVM` (`vm.go:199-204`) and container create
(`container_network.go:146`) call it. `AttachDevice` NIC, `CloneVM` into another
project, promote and live-restore auto-define attach networks without project
admission. §5 places the security-group admission at those same sites, so the
missing network admission belongs beside it (D8).

These findings come from reading the code, not from a running cluster. Commit 1
pins each of them with a failing test. The lab check in §8.3 confirms the
tap-staleness claim on real qemu before anything else is built on it.

## 2. The target model

| Group | `project` column | Binding key (`name` column) | Managed by | Attachable by |
|---|---|---|---|---|
| shared | `''` (the default) | `<name>` | `sg.write` at `/security_groups/<name>`, in practice a `/` grant | every workload |
| owned by P | `P` | `P/<short>` | `sg.write` at `/projects/P/security_groups/<short>` | workloads in P only |

- **Short names** are one path segment (`safename.ValidateName`), so they never
  contain `/`. New **shared** names must not contain `/` either. Hierarchical
  project names (`acme/team`) give keys like `acme/team/web`, and a key splits
  at its **last** `/`. The `project` column is the authority, though. Parsing a
  key is only an input convenience (§3.3). A row's ownership is never inferred
  from its name.
- Existing groups have `project = ''`, so they are shared. **No backfill.** Older
  nodes keep writing groups with the old insert shape, so their new groups are
  shared too.
- Admission is `tenancy.AdmitAttach(workloadProject, group.Project)`
  (`internal/tenancy/tenancy.go:80-85`). That is the rule networks and pools
  already use (`project_admission.go:40-57`): shared passes, otherwise the
  normalized projects must be equal. `_default` is a tenant, not the root, so it
  can own groups (`_default/web`). A `_default` VM may not bind `acme/web`.

## 3. The key hazard: name collisions

### 3.1 Options considered

| | Binding refers to | Old reconciler with two `web` rows | Existing bindings | Verdict |
|---|---|---|---|---|
| A | bare name, resolved in the workload's project at render | last-wins by id across projects: **can render bob's `web` rules on acme's NIC** | unchanged | rejected: corrupting mid-roll and after rollback |
| B | group id (`sg:<id>`) | unknown name, dropped: **NIC renders with no group rules** | unchanged, but two reference forms forever | rejected: an old node fails open on new bindings, and `persistStackFirewall` mints new ids on every redeploy |
| C | qualified key stored in `name` (this design) | exact match, no cross-project collision | unchanged (bare = shared) | **chosen** |

### 3.2 Why C holds up mid-roll

- The reconciler, old or new, matches a binding string against the `name`
  column (`reconciler.go:308-324`). Under C every owned row's `name` is unique
  across projects by construction, so an older node resolves `acme/web` to
  acme's row and to no other.
- **What an older node does with a new-style binding mid-roll:** before
  `sg_projects_v1` latches, no owned group exists anywhere, and new nodes refuse
  to bind a key that names no live attachable group (§5). A string like
  `acme/web` can therefore only reach a NIC through an old node's blind bind.
  An old reconciler drops it as an unknown name, which is exactly what it does
  with a typo today. After the latch, every replication recipient runs this
  build (§4.4), so no old reconciler remains. A node rolled back below the token
  goes into WAL quarantine and writes nothing, but its reconciler still renders
  its own NICs from its local database. It resolves keys exactly. The one thing
  it lacks is the render-time ownership filter (§3.4), and that is a residual
  (§6).

### 3.3 Input resolution (CLI, compose, REST)

The server always stores keys. Users type names:

1. Input containing `/` is a key, taken literally.
2. A bare name `N` for a workload in project `P` resolves to `P/N` if `P` owns
   a live `N`. Otherwise it resolves to the shared `N`. Otherwise it is
   NotFound. The project's own group shadows a shared one of the same name, the
   way a local variable shadows a global. D3 covers the way to name the shadowed
   shared group explicitly.
3. **Compose:** a name declared in the file's own `security-groups:` block is
   always the stack's shared group, stored bare, exactly as today. Only an
   undeclared name goes through rule 2. Without this rule, a project group
   called `web` would silently capture a stack's own `web`.
4. The UI pickers submit keys, never bare names, so the UI never depends on
   resolution.

The response always carries the resolved key, and the CLI prints it, so a user
sees which group they got.

### 3.4 The render-time ownership filter (defense in depth)

`CorrosionPlanLoader` keeps a bound key only if a live row holds it **and**
`AdmitAttach(nicWorkloadProject, row.Project)` holds. For that it needs each
NIC's project: `vms.project` for VM NICs (one more column in the SELECT of the
by-host NIC read) and `containers.project` for container NICs
(`container_interfaces.go:129-136` already joins `containers`). These are
read-side changes and add no statement shape.

Admission alone cannot close the case this covers: **dangling-reference
capture**. Today any name binds blind, including one that does not exist yet. An
acme NIC bound to `bob/web` before the upgrade, or through an old node mid-roll,
would start rendering bob's rules the moment bob creates `web`. The filter makes
such a reference inert forever. The reconciler logs every reference it drops
this way, with the NIC, the key and the reason (`unknown` or `cross-project`),
and `lv sg ls` reports them (§7.1).

### 3.5 Duplicates within one key

Two rows can still hold one key in two ways: the legacy ways in §1.4 (two shared
`web` rows), and a legacy shared row whose name contains `/` that equals a later
owned key. This design:

- **refuses** on the entry node to create a group whose key is held by a live
  row. Best effort only: two nodes can race, and a CRDT has no UNIQUE.
- **refuses** new shared names that contain `/`. Legacy ones keep working
  unchanged, as shared groups.
- keeps the reconciler's existing tie-break for two **shared** rows, last id
  wins, so old and new nodes render identical bytes for state that exists
  today.
- for an owned row and a shared row that hold one key: the owned row wins on new
  nodes. That case cannot arise before the latch, because owned rows do not
  exist yet, so mixed-version nodes never disagree about it.
- flags every duplicate in `lv sg ls` and on the security-groups page.

## 4. Schema, statement shapes and the rolling upgrade

### 4.1 Schema v64

- `ALTER TABLE security_groups ADD COLUMN project TEXT NOT NULL DEFAULT ''`
  is appended to `schemaMigrations`, `64` is appended to `alterVersions`
  (`schema.go:3290-3334`, whose length the init at `schema.go:3385` checks),
  and the same column goes into the `CREATE TABLE`, **after `deleted_at`**.
  Appending it last means fresh and upgraded databases share one physical column
  order, for the reason recorded at v53 (`schema.go:372-376`, and at
  `schema.go:1316-1322` for `runtime_action_proofs`). The order-invariant
  digest_v2 is on by default anyway (`digest_column_order_test.go:11-24`, the
  colonelpanik/litevirt#244 fix), but the positional v1 digest must agree as
  well, so the rule still applies. The `skewedTables` check in `digest_column_order_test.go`
  will cover the table automatically.
- `CurrentSchemaVersion = 64` (`schema.go:488`) with a `v64:` History line
  (`TestSchemaHistoryDocumentsCurrentVersion`).
- Migrations are additive, so an older binary tolerates the column. Pre-staging
  (`docs/upgrades.md`, "pre-stage pass") puts the column on every node before
  any binary is swapped. The PushMutations skew check (`docs/upgrades.md`
  item 5) covers a `--no-prestage` roll.
- **No backfill.** `DEFAULT ''` means shared, which is what every existing row
  is.

### 4.2 Statement shapes

**One new replicated shape. It is unavoidable under this design** (D1 gives the
alternative that avoids it):

```sql
INSERT INTO security_groups (id, name, stack_name, project, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
```

- It goes in a new writer, `InsertOwnedSecurityGroup`. `InsertSecurityGroup`
  (`security_groups.go:31-42`) keeps its exact shape and still creates shared
  groups, so nothing moves to the historical ledger and
  `check-ledger-drift.sh` stays quiet.
- Ledger: register it capability-gated, `Disposition: DispReject`,
  `RequiresCapability: sg_projects_v1`, `DispositionAfter: DispPlainInsert`.
  That follows the `vm_replace_v1` entries (`stmtledger_derive.go:151-155`,
  `:229-236`). Then regenerate `stmtledger_generated.go`. `stmtshapecheck`
  fails CI until it is registered. One thing to check during implementation:
  that `DispositionAfter: DispPlainInsert` takes the plain-insert upsert rewrite
  rather than a verbatim apply.
- **No other new shape.** Moving a group (§7.1) is make-before-break: an owned
  insert, then `SetInterfaceSecurityGroups`' existing UPDATE, then the existing
  tombstone. So the `project` column is never UPDATEd, and a row's owner never
  changes in place. Bindings keep the existing shapes (the column is JSON text,
  as before). The reconciler and RPC reads are not replicated.
- Commit 1's carry fixes (§1.5) use existing shapes only:
  `InsertVMWithHardware`'s interface insert already has the column
  (`vms.go:196`), and the hot-attach path follows `nic_retarget`'s
  insert-then-`SetInterfaceSecurityGroups` pair (`nic_retarget.go:239-248`).

### 4.3 Why the shape needs a gate

A receiver whose ledger lacks a fingerprint fails the apply closed: "unregistered
replicated statement shape" (`internal/corrosion/replicator.go:1534-1542`). The
whole batch rolls back and the sender's stream into that peer stops advancing.
That is head-of-line blocking for every later mutation, the hazard
`cluster_policy.go:16-23` and `cluster_record.go:85-98` describe. Pre-staging
equalises the schema first, so the schema-skew refusal sees no gap, which
leaves the binary-resident ledger as the only cross-version gate. **So the
owned-group insert must never be emitted while any replication recipient runs
an older build.**

### 4.4 The token: `sg_projects_v1`

CLAUDE.md asks where the guarantee is enforced before a token is added. Two
different things are guaranteed here, and they answer differently:

| Guarantee | Enforced where | Relies on a peer? | Needs the token? |
|---|---|---|---|
| a workload binds only shared or own-project groups | at the creation of every binding (§5), plus each host's own render (§3.4) | no | **no** |
| a replicated owned-group insert is decodable by every recipient | nowhere but the sender's restraint | **yes**: every recipient's ledger | **yes** |

The token therefore exists for the second row only, the same reasoning as
`failover_scope_v1` (`internal/capabilities/capabilities.go:820-823`) and
`credentials_split_v1`:

- **mandatory** (no flag; `capabilities.mandatory`, `capabilities.go:948`). It
  states a fact about the binary: this build decodes the owned-group insert and
  enforces ownership. It is not a policy. The opt-in is creating an owned group.
- **ReplicationGated** (`capabilities.replicationGated`, `capabilities.go:900`).
  The latch is confirmed against admitted memberlist membership, so a host
  parked in `maintenance` on an older build holds it off. That is intended.
- **advertised unconditionally**, so it latches on a uniform fleet.
- **Gate at two layers**, mirroring `SetClusterPolicyGate`
  (`cluster_policy.go:67`, `client.go:406-410`):
  `CreateSecurityGroup{project≠""}` and move return `FailedPrecondition` naming
  `sg_projects_v1` until it has durably latched, and the corrosion writer
  refuses the insert itself unless the injected gate says latched.
- **Stand-down:** nothing to stand down. Moving every owned group to shared
  (§7.1) returns to today's model. Because it is mandatory, rolling a binary
  back below it after the latch means WAL quarantine
  (`preflightCapabilityRollback`), as with every latched token. That is the real
  cost of this design (D1).
- Retiring it later follows `capabilities.retired`, never deletion.

### 4.5 What a mixed-version cluster permits

| Phase | Owned groups | Attach validation | Render filter | Character |
|---|---|---|---|---|
| some nodes old (pre-latch) | none can exist | new entry nodes validate, old ones bind blind (as today) | new hosts only | **permissive, not corrupting**: an old node can bind a missing name, which drops as today, and new hosts neutralise any capture |
| latched | creatable | every node | every node | full model |
| node rolled back after latch | exist | that node is quarantined and writes nothing | absent on that node's own render | residual (§6) |

No phase applies the wrong group's rules to a NIC. Stalled replication is
impossible because the gated shape is the only new one.

## 5. Every path that creates or carries a binding

New helper `admitSGBindings(ctx, project string, keys []string, mode)`, beside
`admitNetworkAttach` in `project_admission.go`. It resolves input names (§3.3),
returns the resolved keys and refuses:

- an unknown key with `InvalidArgument` naming it, in **strict** mode;
- a key owned by another project with `PermissionDenied`, in the same wording
  family as `admitNetworkAttach`.

The two modes:

- **strict**: the caller chose the groups. Every key must resolve to a live,
  attachable group.
- **carry**: the bindings are copied from the same workload's earlier state. A
  cross-project key is refused. An unknown key is kept, and the render filter
  makes it inert, so that rebuilding or relocating a VM never fails because
  somebody deleted a group it once had.

The owner leg of a forward re-checks only the cross-project rule. It treats an
unknown key as pass-through, because the group may not have replicated to the
owner yet; the render filter covers that case. Entry-side validation is the
authoritative check.

| # | Path | Where the binding is created | Mode | Today |
|---|---|---|---|---|
| 1 | `CreateVM` | `vm.go:199-204` (beside network admission), rows at `vm.go:657-681` | strict | blind |
| 2 | `AttachDevice` NIC | entry `attachNICEntry` (`hotplug_nic.go:110`), owner `attachNICOwner` (`hotplug_nic.go:218`) | strict (entry), cross-project (owner) | blind, and no network admission either |
| 3 | `BindSecurityGroups` | `sg_bind.go:57` | strict. Clearing the list (empty) is always allowed | blind |
| 4 | stacks: VM create (`stacks.go:442`, `:1361`; `stacks_rolling.go:45`) | through `CreateVM` | strict, with the compose rule of §3.3 | blind |
| 5 | stacks: containers (`stacks_containers.go`) | through container create | strict, same | blind |
| 6 | container create | `container_network.go:146` (managed NIC branch) | strict | blind |
| 7 | `nic_retarget` | `nic_retarget.go:245-248` | carry (same VM, same project) | carry |
| 8 | `CloneVM` (VM) | `templates.go:244-256`; target project from `req.Project` (`templates.go:80-84`) | carry if same project, **strict against the target project** if it differs | blind, and SGs dropped from the enforced row (§1.5) |
| 9 | container clone | `cloneContainerNICs` (`container_network.go:21-41`) | as #8 | blind |
| 10 | `ImportVM` | `importRecords` (`vmimport.go:706-740`) | none: an import binds no groups. A test pins that | n/a |
| 11 | `RestoreVM` / `RestoreFromBackup` (disk restores) | no NIC rows written | none | n/a |
| 12 | `RestoreLive` auto-define | spec from `req.Spec`, the manifest, or the existing row (`restore_live_autostart.go:29-49`), rows at `:231-243` | **strict** for `req.Spec` (caller-supplied), carry for the manifest and existing specs, both against `authProject` | blind |
| 13 | `RebuildVM` | `CreateVM` with the stored spec (`vm.go:3083`) | carry (pass the mode through; do not inherit strict) | blind |
| 14 | promote | `promote.go:980-992` | carry against the VM's project | blind, SGs dropped (§1.5) |
| 15 | container restore, relocate, migrate | `containercheck.go:338-341`, `migrateRestore` (`migrate_container.go:391`), `drivePeerRestore` | carry | carry |
| 16 | hardware backfill, legacy bridge, `vm_replace` cutover | `hardware_backfill.go:193`, `corrosion/hardware.go:290-320`, `corrosion/vm_replace.go:97-139` | mechanical copies of existing rows, so no admission. They are covered by the render filter | carry |

A fleet test enumerates this table, one assertion per row (§8.2), so a path added
later without admission shows up as a missing row rather than a silent hole.

## 6. Residual risks, stated plainly

- **A node rolled back below the token** renders its own NICs without the
  ownership filter. A dangling cross-project reference on a VM it hosts could
  render there. It writes nothing while quarantined, and its operator is already
  in an unsupported state.
- **A concurrent same-key create on two nodes** can produce two owned rows with
  one key. Both are in one project, so the rules can never cross a tenant
  boundary. Last id wins, and `lv sg ls` flags the duplicate.
- **Spec drift** (§1.5 item 4) is pre-existing. A `RebuildVM` after
  `BindSecurityGroups` restores the create-time groups. That is unchanged here
  (D6).
- **IPsets stay cluster-global.** A project rule may reference `@<ipset>`. It
  cannot read or edit the set's CIDRs through this design.
- **Incident isolation against a hostile tenant:** a tenant with
  `network.update` on their VM can unbind a shared "isolation" group an admin
  bound, which they can already do today (D5).

## 7. RBAC, CLI, REST and UI

### 7.1 RBAC

Paths follow `networkRBACPathFor` (`internal/grpcapi/authz_path.go:64-69`):

- shared: `/security_groups/<name>`
- owned: `projectRBACBase(P) + "/security_groups/" + <short>`

| Action | Check | Fallback (no bindings) |
|---|---|---|
| create shared | `sg.write` at `/security_groups/<name>` | operator, as today (`security_groups.go:36-38`) |
| create owned by P | `sg.write` at the owned path, and token latched | operator |
| delete, add rule, remove rule | `sg.write` at the **row's** path, through `requirePermResolved`, so a row not yet replicated never authorizes on a guess (`auth.go:775-800`) | operator |
| move (to shared, or to another project) | `sg.write` at `/` | admin |
| list (§7.2) | `sg.read` per project, see below | viewer |
| bind, attach | unchanged: `network.update` / `vm.update` / `vm.create` on the workload path. Group admission is a project rule, not an RBAC verb | unchanged |

- **Verbs:** the existing `sg.read` and `sg.write`. No new verb.
- **Built-in roles** (`internal/auth/permissions.go:318-381`): none change in
  the recommended option. `NetworkAdmin` (`sg.*`) bound at `/projects/acme`
  becomes "acme's network admin", which covers acme's networks and groups.
  `Operator` keeps `sg.read` only (D4). `Viewer` and `Auditor` read through
  `*.read`.
- **Scoped tokens:** `RequirePerm` intersects the scope with the path
  (`auth.go:752-755`). A token scoped to `/projects/acme` can therefore manage
  acme's groups and list acme plus shared, and it cannot touch shared groups or
  other projects' groups. That needs no special case.
- **Project deletion:** `corrosion.DeleteProject` refuses while the project owns
  live groups, beside its VM and container guards (`projects.go:124-142`). It
  adds a read-only SELECT and no shape.
- **Move:** make-before-break, as described in §4.2.
  1. Refuse if any binding of the old key belongs to a workload that would not
     be allowed the new owner. The error lists those bindings.
  2. Insert the group under the new owner with the same rules.
  3. Rewrite each binding with the existing UPDATE.
  4. Tombstone the old group.

  A crash part-way leaves both groups live, with some bindings on each, and the
  same rules in both. Re-running the move finishes it. Spec copies are not
  rewritten, the same as `BindSecurityGroups`. A carry-mode rebuild keeps the
  old key and it renders inert. The move's output says so and names the
  workloads to rebind (D6).

### 7.2 `ListSecurityGroups` (proto changes)

The proto change is wire-compatible: new fields only, and gRPC is not
replicated.

- `SecurityGroup` gains `project` (5), `short_name` (6), `writable` (7). The
  server computes `writable` with `RequirePerm(sg.write, row path)`, so the page
  knows what to grey out without a second call.
- `ListSecurityGroupsRequest` gains `attachable_to_project` (3).
- Visibility:
  - `sg.read` at `/` returns every group (today's behaviour for root
    readers and the legacy fallback).
  - Otherwise, for each project P where the caller holds `sg.read` at P's
    security-groups path, it returns P's groups, plus every shared group if
    there is at least one such P. Shared groups exist to be attached by tenants,
    so a tenant has to be able to read what one does (D2).
  - With `attachable_to_project = P`, it returns shared plus P's groups only,
    and refuses `PermissionDenied` unless the caller holds `sg.read` for P.
  - `include_rules` returns rules for exactly the groups listed.
  - The existing comment (`security_groups.go:152-158`) and the proto comment
    (`service.proto:1657-1660`) are rewritten to match.

The rule summary ("web — in tcp 80,443 from 0.0.0.0/0") is a pure function in
`internal/firewall` (`SummarizeRules`), used by both the UI and the CLI, so the
two never word a rule differently. It is not a proto field.

### 7.3 CLI

Every new command and flag goes into `docs/cli-reference.md`,
`docs/firewall.md` and `docs/auth.md` in the same commit, because the
triangulation test walks the cobra tree (`cmd/litevirt/docs_triangulation_test.go:214`).

- `sg create <name>` gains `--project <p>`, which is mutually exclusive with
  `--stack`. It prints the stored key.
- `sg ls` and `sg rule-ls` move from the local database (`cmd/litevirt/sg.go`,
  `openClusterDB`) to `ListSecurityGroups`, so a project user sees the filtered
  view and the command no longer needs to run on a node. `sg ls` gains
  `--project` and `--attachable-to <project>`, and PROJECT, KEY and SUMMARY
  columns, plus a DUPLICATE marker and a count of inert references (§3.4).
- A new `sg move <id>` subcommand, with `--project <p>` or `--shared`. It is
  admin only and prints the bindings it rewrote and any it could not.
- `sg bind` is unchanged in syntax. Names resolve per §3.3, and it prints the
  resolved keys.

### 7.4 REST

`POST /api/v1/vms/bind-sgs` (`internal/restapi/coverage.go:49`) is unchanged. It
inherits strict validation from the RPC. There are no REST routes for SG CRUD
today, and this design adds none (D9).

### 7.5 UI

- **Add-NIC** (`internal/ui/handle_vms.go:1170-1186`, `add_nic_modal.html:28`):
  read the VM's `spec.project` from `InspectVM`, call
  `ListSecurityGroups{attachable_to_project, include_rules}`, and render options
  `value=<key>`, labelled `<short> — <summary>` and grouped under "Shared" and
  "<project>". It keeps today's fail-safe: a refused read renders no control
  (`handle_vms.go:1166-1170`).
- **Create-VM** (`vm_new_modal.html`): there is no security-group control today,
  and **no project selector** (`handle_vms.go:70-80`, `:164-267`), so every
  UI-created VM is in `_default`. Add a per-network-row multi-select, populated
  for the chosen project. That needs a project selector first (D10).
- **Security-groups page** (`handle_security_groups.go:38-66`,
  `security_groups.html:24`): the filtered list, with a project badge ("shared"
  or the project's name). Edit and delete appear only where `writable`. The
  create modal gets a project select (the projects the caller can see, with the
  server refusing as the authority), and "shared" is offered only to root
  writers. The page shows the duplicate and inert-reference markers.
- Admins at `/` see everything, plus a Move action.

## 8. Test plan

Every assertion is mutation-verified. The mutation and its expected red are
listed with it.

### 8.1 Unit

- `firewall`: the render filter drops a cross-project key and an unknown key, and
  keeps shared and own-project keys. *Mutation:* make the filter pass everything,
  and a cross-project key renders.
- `firewall`: the tie-break for two shared rows stays last-id, so its output is
  byte-identical to the previous loader. *Mutation:* first-id wins.
- `firewall`: an owned row beats a shared row for one key.
- `firewall.SummarizeRules`: table test.
- `corrosion`: schema v64, the column is appended last, the `skewedTables` test
  stays green, and `TestSchemaHistoryDocumentsCurrentVersion` passes.
- `corrosion`: `InsertOwnedSecurityGroup` refuses while the gate is false.
  *Mutation:* drop the gate check.
- `corrosion` ledger: before activation the owned insert is DispReject, after it
  DispPlainInsert. *Mutation:* remove `RequiresCapability`, and the pre-latch
  apply succeeds.
- `grpcapi`: `admitSGBindings` strict and carry matrices, and §3.3 resolution
  including compose shadowing. *Mutation:* resolve shared-first, and the shadow
  test goes red.
- `grpcapi`: RBAC matrix, {Admin@/, NetworkAdmin@/, NetworkAdmin@/projects/acme,
  Operator@/projects/acme, a token scoped to acme, legacy fallback} ×
  {create shared, create owned, rule add, delete, move, list}. *Mutation:* check
  shared writes at the project path.
- `grpcapi`: `ListSecurityGroups` visibility. Acme sees shared plus acme, not
  bob. `attachable_to_project=bob` from acme is PermissionDenied. *Mutation:*
  skip the per-project check.
- `grpcapi`: `DeleteProject` refuses while the project owns a group.
- `ui`: the pickers render keys, labels and summaries. The page greys out
  non-writable groups. The refusal-status tests (`rpc_refusal_status_test.go`
  family) cover the new error paths.
- commit 1: each §1.5 defect gets a red-first test. The clone legacy row carries
  its SGs. The hot-attached NIC appears in the plan loader. A NIC whose tap
  changed after a restart renders on the new tap. *Mutation:* revert each fix.

### 8.2 Fleet (`tests/fleet/`, the tier that can see multi-node failures)

- **Pre-latch refusal and nothing on the wire** (the shape of
  `failover_scope_command_test.go:23-50`). With `sg_projects_v1` gated off on one
  node, creating an owned group is FailedPrecondition naming the token, and no
  mutation_log row on any node holds the owned-insert shape (as in
  `assertNoPolicyStatements`). *Mutation:* remove the RPC gate, and the
  corrosion-layer gate must still keep the log clean. Then remove both, and the
  test goes red.
- **Mixed version stands in for an older reader** (`credentials_split_test.go`'s
  `oldColumn` pattern). The query the previous release's loader runs
  (`reconciler.go:285` plus the name-keyed map) over a replica holding
  `acme/web`, `bob/web` and shared `web` resolves each binding to the right row.
  *Mutation:* store owned groups under their short name, and the old-reader
  query picks bob's rules for acme.
- **The latch forms on a uniform fleet and is held off by a maintenance host**
  (the ReplicationGated property).
- **Cross-node admission.** Bob creates `web` on node A. Acme's VM is on node B,
  and acme attaches through node C. Binding `bob/web` is refused at C. A
  dangling `bob/web` written directly into acme's row (standing in for a
  pre-upgrade blind bind) renders nothing on B, before and after bob's group
  replicates. *Mutation:* disable the render filter.
- **The §5 table:** one subtest per row, each attaching a cross-project key
  through that path over real gRPC and expecting a refusal (strict and
  cross-project), or a kept-and-inert key (carry).
- **Move:** make-before-break keeps every binding on a live group at every
  replicated step. A crash injected between the rebind and the tombstone
  (`FailNICRowWrites`-style hooks, `tests/fleet/cluster.go:1207`) leaves both
  groups live with identical rules. A re-run converges.
- **Replication never stalls:** after the latch, an owned insert on A applies on
  B and C and the watermarks advance.

### 8.3 E2E and lab (kvm003 lab when it is free; fleet fakes cannot prove nft did it)

Following the "verify everything on the lab" rule:

1. **Before any of this:** confirm §1.5 on real qemu. Create a VM with a group,
   stop and start it, and compare `vm_interfaces.tap_device` with `virsh domiflist`
   and `nft list table inet litevirt-fw`.
2. Two projects, each with `web` allowing a different port. Check with
   `nft list` on each VM's host that each tap's chain holds its own project's
   rules, and that a probe from a peer VM gets through only on the right port.
3. Hot-attach a NIC with a group, check that the chain exists. Restart the VM
   and check again. Migrate it and check on the target.
4. Rolling upgrade from the previous release binary, with groups and bindings in
   place: no change to `nft list` output on any host across the roll, the token
   latches at the end, and owned-group creation then works.

### 8.4 Race

The touched packages get a targeted `-race` run (CLAUDE.md:
`go test -race -timeout 5m ./internal/firewall/ ./internal/corrosion/ -run 'TestSG|TestStmtShape'`).
The full grpcapi race sweep runs on kvm003 through `race-sweep.sh` with a 90m
budget. It is not a merge gate.

## 9. Implementation plan

The first commit is a standalone fix on its own branch
(`fix/sg-enforcement-follows-the-nic`), as is the D8 network-admission fix
(`fix/network-admission-on-every-attach`). Commits 2–10 build on both and land
together, in order, on `feat/security-group-projects`.

| # | Commit | Content | Est. |
|---|---|---|---|
| 1 | `fix(firewall): enforce security groups on every NIC that has them` | render-time MAC→tap resolution on the owning host (or pin `<target dev>`, D11); the loader reads the `vm_nics` and `vm_interfaces` overlay by host; carry SGs into the legacy row on clone, promote, restore and hot-attach; red-first tests; lab check §8.3(1, 3) | 3 d |
| 2 | `feat(corrosion): security_groups.project (schema v64)` | ALTER, DDL with the column last, alterVersions, History; read paths return `Project` | 0.5 d |
| 3 | `feat(capabilities): sg_projects_v1` | mandatory, ReplicationGated, advertised unconditionally; daemon wiring of the corrosion gate; capability docs | 0.5 d |
| 4 | `feat(corrosion): owned security-group insert behind sg_projects_v1` | `InsertOwnedSecurityGroup`, gated ledger entry, regenerated ledger, stmtshapecheck | 0.5 d |
| 5 | `feat(grpcapi): project-owned security groups` | create, delete and rule RBAC on the row's path; ListSecurityGroups visibility and new fields; DeleteProject guard; move | 2 d |
| 6 | `feat(grpcapi): admit security-group bindings on every attach path` | `admitSGBindings` with §3.3 resolution; the 16 rows of §5; network admission at the same sites lands first on its own branch (D8) | 2.5 d |
| 7 | `feat(firewall): render only bindings the NIC's project may use` | project-aware loader, owned-over-shared tie-break, inert-reference logging | 1 d |
| 8 | `feat(cli): sg create --project, sg move, RPC-backed sg ls` | flags, docs (cli-reference, firewall, auth) | 1 d |
| 9 | `feat(ui): project-aware security-group pickers and page` | Add-NIC, Create-VM (with D10), SG page, create modal | 2 d |
| 10 | `test(fleet): security-group ownership across nodes and versions` | §8.2 | 2 d |
| — | lab verification, review rounds, fixes | §8.3(2, 4), afriend and code-review passes | 2–3 d |

**Honest total: about 17–19 working days**, roughly three and a half to four
weeks of elapsed time with review, and lab time depends on kvm003 being free.
The biggest uncertainty is commit 1. If tap resolution needs a libvirt event hook
rather than a render-time lookup, add two days. The §5 table is the
second-largest risk: each row is small, but sixteen of them each need their own
fleet subtest.

## 10. Decisions (resolved 2026-10-05)

Every recommendation below was approved on 2026-10-05. Each entry keeps the
option that was weighed and records the resolution.

- **D1. Column and token, or no schema change?** The alternative stores
  ownership in the existing `stack_name` column as a sentinel (`@project:acme`,
  following `backup_schedules`' `@project:Y` sentinels, `schema.go:53-59`), and
  keeps the qualified key in `name`. That means no new shape, no token, no
  schema bump and no rollback quarantine. The costs: it overloads a column's
  meaning, a stack group can never also be owned, and every reader of
  `stack_name` has to learn the sentinel. *Recommend the column and token:* it
  is how networks (v37) and pools gained owners, and the rollback cost is the
  same one every recent mandatory token carries. Pick the sentinel only if
  avoiding another mandatory token outweighs a hidden trap in the schema.
  **Resolved 2026-10-05:** column and token (`security_groups.project`, schema v64, `sg_projects_v1`).
- **D2. Who can read shared groups' rules?** *Recommend: anyone with `sg.read`
  in at least one project* (they can attach shared groups, so they need to know
  what those do). The alternative is root readers only, which leaves tenants
  binding shared groups blind.
  **Resolved 2026-10-05:** shared groups and their rules are readable by anyone holding `sg.read` in at least one project.
- **D3. Naming the shared group when a project group shadows it.** *Recommend a
  leading `/` as the explicit shared key form in input only* (`/web`), never
  stored. The alternative is to refuse the shadowing create outright, but that
  is best effort in a CRDT, so it cannot be the only answer.
  **Resolved 2026-10-05:** a leading `/` (`/web`) names the shared group explicitly, in input only; it is never stored.
- **D4. Give Operator `sg.write`?** *Recommend no.* Bound at `/`, it would let
  every cluster Operator edit shared groups such as "isolation". Project
  self-service is a `NetworkAdmin` binding at `/projects/<p>`. The docs will say
  so.
  **Resolved 2026-10-05:** Operator keeps `sg.read` only; project self-service is `NetworkAdmin` bound at `/projects/<p>`.
- **D5. Sticky shared groups for incident isolation.** Let a tenant add a shared
  group to its own NIC but require `sg.write` on that group to remove it, so a
  hostile tenant cannot undo an admin's quarantine. *Recommend deferring it to a
  follow-up.* Today the tenant-proof tool is a cluster-tier rule on the VM's
  address, which tenants cannot touch. Doing D5 now widens commit 6.
  **Resolved 2026-10-05:** deferred to a follow-up; tenant-proof isolation stays a cluster-tier rule on the VM's address.
- **D6. Make `BindSecurityGroups` and move update the VM spec too?** This is a
  pre-existing gap (§1.5 item 4). *Recommend a separate follow-up.* The spec
  write runs under the operation protocol, and folding it in doubles the risk of
  commit 6.
  **Resolved 2026-10-05:** separate follow-up; bind and move rewrite NIC rows only.
- **D7. Project-scoped stacks.** *Recommend out of scope.* Stacks stay
  root-deployed and their groups stay shared.
  **Resolved 2026-10-05:** out of scope; stack groups stay shared.
- **D8. Fix the missing network admission** (AttachDevice NIC, clone into
  another project, promote, live-restore; §1.5) in commit 6, at the same call
  sites? *Recommend yes, as its own `fix(grpcapi):` commit right before commit
  6.* The sites are the same, and leaving it means a tenant can still reach
  another project's network through the path this design hardens for groups.
  **Resolved 2026-10-05:** yes, as its own `fix(grpcapi):` commit (branch `fix/network-admission-on-every-attach`), landed before the admission commit.
- **D9. REST CRUD routes for security groups.** *Recommend not now.* None exist
  today, and adding them belongs with the REST coverage work.
  **Resolved 2026-10-05:** no REST CRUD routes now.
- **D10. Create-VM project selector.** The Create-VM picker can only list a
  project's groups once the modal has a project. *Recommend adding the selector
  in commit 9,* listing projects the caller can create VMs in. The server stays
  the authority.
  **Resolved 2026-10-05:** add a project selector to Create-VM in the UI commit.
- **D11. How commit 1 finds the tap:** resolve it at render through libvirt by
  MAC on the owning host, or pin `<target dev="lv-…">` in the domain XML so it is
  stable. *Recommend render-time resolution.* Pinning changes the domain XML of
  every VM, and an existing VM only picks the change up when it is redefined.
  The fix would then reach only new or redefined VMs. Containers already use
  deterministic veth names (`container_interfaces.go`, `ContainerVethName`).
  **Resolved 2026-10-05:** render-time tap resolution by MAC on the owning host (part of commit 1, branch `fix/sg-enforcement-follows-the-nic`).
