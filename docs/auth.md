# Authentication & authorization

litevirt's auth model has two halves:

- **Authentication** asks "who are you?". A *realm* validates the
  credentials and returns a *Principal* (subject + groups).
- **Authorization** asks "may you do this?". A *path-based RBAC engine*
  evaluates role-bindings to grant or deny each operation.

Tokens, sessions, and 2FA all sit on top of these primitives.

## Realms

A realm is a pluggable authentication backend. Three are shipped:

| Realm | Name format | When to use |
|---|---|---|
| Local | `local` | Single-cluster, small team. Bcrypt passwords stored in the cluster DB. Always present. |
| OIDC | `oidc:<short-name>` | Federated SSO with corporate IdPs (Okta, Auth0, Keycloak, Azure AD, Google Workspace). Auth-code flow with PKCE. |
| LDAP / AD | `ldap:<short-name>` | On-prem Active Directory or OpenLDAP. Search-then-bind; group memberships pulled from `memberOf` (or a follow-up search). |

Realms are configured under `auth.realms:` in `/etc/litevirt/config.yaml`
— see `docs/configuration.md` for the YAML shape. The daemon refreshes
group caches from external realms every 5 minutes; the last error per
realm is exposed via the status RPC.

Roles map to *principal IDs*: `user:<subject>@<realm>` and
`group:<name>@<realm>`. Bind a role to a principal in the engine and the
caller gets the role's verbs at the binding's path.

### External users and local accounts share one name space

A user's first LDAP or OIDC login creates a row in the users table with no
local password (a "shadow"), so roles and audit can name it. Because users
are keyed by name alone, an external login is refused when the name belongs
to a local account, which would otherwise hand the external principal that
account's role.

Once `credentials_clear_v1` has latched (docs/upgrades.md), every local
account's users row also has an empty password column, so a host decides
"external" only on positive evidence: an empty credential row for the user,
written when the shadow was made after `credentials_split_v1`, by a host's
first split pass for a shadow that host could vouch for, or by an
administrator. When a host cannot tell, the login is refused:

- `Unavailable` ("retry") while the host has not synced or not finished its
  first credentials pass: retry, or log in through another host;
- `FailedPrecondition`, naming the command below, when the host is up to date
  and still holds no evidence. That is an external user created before
  `credentials_split_v1` latched on a host that has since been removed without
  running this build. If the user is external, an administrator marks it:

  ```bash
  lv user mark-external <username>
  ```

  The command is audited (`user.mark-external`, refusals included),
  admin-only, refused while the host it runs on sees any local password for
  the name (in the users row, or in a credential row, live or deleted), and
  refused while that host has not caught up with its peers. The mark is an
  empty credential row with a timestamp older than any real write, so it never
  replaces a password. It holds for the account as it stands when it is made:
  if the user is deleted and created again, the login is refused again until an
  administrator decides again.

A host that has not synced its users table yet also refuses to create a NEW
shadow (`Unavailable`): "no row under this name" there may only mean the
local account has not arrived, and the new row would replace it everywhere.

### OIDC realm keys

Under `auth.realms[].oidc:`. `issuer_url`, `client_id`, and `redirect_url` are
required; prefer `client_secret_file` (checked for 0600 at load) over inlining
`client_secret`.

| Key | Purpose |
|---|---|
| `scopes` | Extra scopes to request beyond the defaults. |
| `groups_claim` | Token claim carrying group membership; each value becomes a `group:<name>@<realm>` principal. |
| `subject_claim` | Claim used as the stable subject — the `user:<subject>@<realm>` principal. Override when `sub` is an opaque id and you want a readable, stable alternative. |
| `email_claim` | Claim read as the user's email address. |
| `name_claim` | Claim read as the user's display name. |

The claim overrides exist because IdPs disagree on claim names. Changing
`subject_claim` on a live realm re-keys every principal id, so existing role
bindings stop matching — rebind before switching it.

### LDAP / AD realm keys

Under `auth.realms[].ldap:`. `url` and `user_base_dn` are required; prefer
`bind_password_file` over inlining `bind_password`.

| Key | Purpose |
|---|---|
| `user_filter` | LDAP filter selecting user entries (e.g. `(objectClass=person)`). |
| `group_base_dn` | Subtree searched for groups. |
| `group_filter` | LDAP filter selecting group entries. |
| `user_name_attr` | Attribute read as the login/subject name. |
| `user_mail_attr` | Attribute read as the email address. |
| `user_group_attr` | Attribute on the user entry listing group membership (typically `memberOf`). |
| `group_name_attr` | Attribute on a group entry holding its name. |
| `skip_tls_verify` | Disables certificate verification on the LDAPS connection. **Leave off outside a lab** — it makes directory traffic, including bind credentials, trivially interceptable. |

As with OIDC, changing `user_name_attr` or `group_name_attr` re-keys principal
ids and invalidates existing role bindings.

## Path-based RBAC

Resources live under a tree:

```
/
├── hosts/<host-name>
├── projects/<project>
│   └── vms/<vm-name>
├── storage/<pool>
└── sdn/zones/<zone>            (planned)
```

Project paths are live — projects ship as a tenancy bucket; see
`docs/tenancy.md` for `lv project create`, hierarchical names like
`/projects/acme/team-foo`, and quota admission.

A role is a list of *verb wildcards*:

- `*` — every verb
- `vm.*` — every verb in the `vm` namespace (`vm.start`, `vm.read`, …)
- `*.read` — read on every namespace
- `vm.start` — exact verb

Built-in roles (seeded by `auth.SeedBuiltinRoles`):

| Role | Verbs |
|---|---|
| Admin | `*` |
| Operator | `vm.*`, `ct.*`, `network.{read,create,delete}`, `lb.*`, `image.{read,pull,import,push,build}`, `backup.*`, `snapshot.*`, `sg.read`, `audit.read`, `host.read`, `storage.pool.{read,write}`, `storage.content.{read,write}`, `resourcemap.{read,write}`, `cluster.lww.acknowledge` |
| VMOperator | `vm.{start,stop,restart,console,read,exec}` |
| Viewer | `*.read` |
| Auditor | `*.read`, `audit.export` |
| BackupOperator | `backup.*`, `snapshot.*`, `vm.read` |
| NetworkAdmin | `network.*`, `lb.*`, `sg.*` |
| NoAccess | (none) |

`--allow-overcommit` (CreateVM/StartVM/UpdateVM) additionally requires
`vm.overcommit`: bypassing the host capacity check is an operator-level
judgment call, so a binding granting only lifecycle verbs (e.g. VMOperator)
cannot invoke it. Wildcard grants (`vm.*`, `*`) carry it; clusters on the
legacy role model (no bindings) are unchanged — any operator may pass it.

A *binding* attaches a role to a principal at a path. With
`--propagate` the binding applies to that path and all descendants —
this is how the `Admin` role on `/` grants cluster-wide superuser
access.

### Cluster-global vs project-scoped verbs

Some resources are cluster-global, not project-scoped, and their RPCs are
checked at the root path `/` — so a token whose scope is limited to a project
(e.g. `/projects/acme`) cannot reach them, while an operator with a `/`-rooted
binding can:

- **Images** are a shared base-image library: `image.{pull,import,push,build}`
  are checked at `/`. (Override with project-scoped image namespaces if needed.)
- **Storage pools** (`storage.pool.*`, configure host mounts/sources) and their
  **contents** (`storage.content.*`, file upload/list/delete) are both checked at the
  pool's project path via `poolRBACPathFor`: `/storage_pools/<name>` for a global pool
  (top-level — effectively a root/global grant, matching their real-infra authority),
  `/projects/<p>/storage_pools/<name>` for a project-owned one. Intra-cluster content
  calls (an entry-node forward, cross-host replication, auto-promote) authenticate as a
  cluster host cert and bypass this tenant check — a deliberate peer-trust boundary:
  any known cluster host cert can reach pool contents via these RPCs.
- **Host filesystem paths in storage** (`storage.hostpath`) are checked at `/`.
  A pool or compose volume that names a directory or file on the host (a `dir`
  pool, a `--target`, a btrfs source, NFS mount options, a Ceph conf or
  keyring), any network-backed pool (`nfs`, `ceph`, `iscsi`), any pool on
  host block storage (`zfs`, `lvm-thin`), a compose
  `backup-repos:` path, a custom absolute `repo_path`, and any `target_path` on
  a restore or `ReplicateVolume` RPC (a bare name included), and an import's
  `--server-path` or `--disk-map` outside `<data_dir>/imports/staging` all need
  it, because the daemon reads and writes there as root (the legacy `admin`
  role keeps it too, as before). Only `Admin` holds it (through `*`): `Operator` holds
  `storage.pool.write` but not this, at any path. A custom role gets it by
  naming it or `storage.*`. Without bindings the floor is `admin`. Using a pool
  an admin created — disks on a `zfs` or `lvm-thin` pool included — needs only
  the project's ordinary VM and disk permissions. See
  [storage.md](storage.md#host-paths).
- **Installer ISOs** (`VMSpec.iso`) are a read of a host file by the guest, so a
  VM names one from a library as `pool/file.iso`. The global library `isos` is
  open to every VM and written only with `storage.library.write` at `/` (Admin);
  any other pool needs `storage.content.read` on it (and its project's VMs only),
  and is written with `storage.content.write`. A pool the host refuses offers
  no ISO. An absolute host path needs `storage.hostpath` at `/`, which only
  Admin holds, as does `lv iso pull --from-host-path`. See
  [storage.md](storage.md#installer-isos).
- **Security groups** (`sg.write`: `lv sg create/rm/rule-add/rule-rm`) are
  cluster-global, bound to NICs by name, and checked at `/`. Admin and
  NetworkAdmin hold `sg.write`; Operator holds only `sg.read`. Binding groups to
  a NIC (`lv sg bind`) is `network.update` on the VM's own path.
- **Backup repository maintenance** (`backup.verify`, `backup.gc`,
  `backup.prune`, `backup.sync`) is checked at `/`. These are the
  `VerifyBackupRepo`, `GarbageCollectBackupRepo`, `PruneBackupRepo` and
  `SyncBackupRepo` RPCs, which the web UI's `/backups` actions call. A repo holds
  every project's backups, so a project-scoped grant cannot reach it. Operator
  and BackupOperator hold all four through `backup.*`. Viewer holds none:
  `backup.verify` is deliberately not a `*.read` verb, because a verify re-reads
  every chunk in the repo. Without bindings the floor is `operator`. See
  [backups.md](backups.md#repo-maintenance-rpcs).
- **Networks** (`network.create`, `network.delete`) and **resource mappings**
  (`resourcemap.*`, PCI/device pools) are cluster-global, checked at `/`.
- **Acknowledging a contested leader-lease term**
  (`cluster.lww.acknowledge`, `lv cluster acknowledge-lease-term`) is checked at
  `/`. It is the only `cluster.*` verb Operator holds, and deliberately not
  `cluster.update`: it clears one node's evidence tracking and elects no winner,
  so it is a day-to-day remedy rather than a cluster mutation. The RPC is
  node-local and refuses peer certs — see
  [operating-model.md](operating-model.md#clearing-the-condition-once-you-have-seen-it).

> **Content RBAC path:** storage-pool content ops are checked on the project-scoped path
> above, not on the flat path `/storage/pools/<name>`. An explicit `storage.content.*` grant
> on the flat path does not apply; issue it on the project-scoped path (admin / role-floor grants are unaffected).
> The check runs on the **entry** node a user authenticates to, so the isolation holds
> only where those nodes run this build — an entry node on an older build checks the flat path.

Interactive guest access — **console, VNC, and SPICE** — requires `vm.console`
on the specific VM's project path (`/projects/<project>/vms/<name>`), not just a
broad operator role.

```bash
lv role grant Admin    group:admin@local        --path /                --propagate
lv role grant Operator group:eng@oidc:corp      --path /projects/acme   --propagate
lv role grant Viewer   group:contractors@ldap:corp --path /projects/acme
```

`lv role ls` lists bindings (admins see all; non-admins see their own
only — server-side filtered). `lv role revoke <binding-id>` soft-deletes
a row by id.

Grants and revokes take effect **immediately**, without a daemon restart: a
grant reloads the engine synchronously, a revoke applies as an in-memory delta
(so it holds even if a subsequent reload fails, while the row tombstone keeps a
later reload from resurrecting it), and a ~30s backstop reload picks up bindings
mutated on a **peer** — the effective bound on a peer-side change is one
successful reload interval after it becomes locally visible. Deleting a user
tombstones that user's role bindings in the same transaction, so a deleted
account cannot retain access through a lingering binding.

## Sessions

`Login` mints an opaque session id (32 random bytes hex-encoded, prefixed
with `lvs_` on the wire so the auth interceptor distinguishes them from
API tokens). The session is stored in the cluster's `sessions`
table with three lifecycle markers:

- **Hard expiry** — 7 days after issue. Cannot be extended.
- **Idle timeout** — 8 hours of inactivity. Each authenticated RPC
  touches `last_used_at`. Idle sessions are auto-revoked on the next
  request.
- **Revoke** — user-initiated (`lv logout`, `lv session revoke <id>`)
  or admin-initiated.

Both timeouts are configurable in the daemon config under
`auth.session_idle_timeout` and `auth.session_hard_expiry` (Go duration
strings, e.g. `8h`, `168h`); the defaults above apply when unset.

Why not JWT? JWTs cannot be revoked before their `exp`. Real-world
incidents (lost laptop, leaked CI token) demand immediate kill. The
sessions table is small (one row per active login) and reads are an
indexed primary-key lookup, so the cost is in noise.

`lv session ls` shows your active sessions; `--user <name>` lists
another user's (admin only).

## API tokens

API tokens are long-lived bearer credentials for automation. They are
distinct from sessions:

- Stored as bcrypt(token) — verifiable but not recoverable.
- No idle timeout; an explicit `expires` (RFC3339) is the only bound.
- May carry **scope paths** that further restrict what the token can do.

```bash
lv user token-create alice ci-runner --expires 2026-12-31T00:00:00Z
lv user token-create alice deploy-acme \
    --scope-path /projects/acme \
    --scope-path /storage/main
```

A scoped token's effective permissions are
`intersection(user's role bindings, token scopes)`. Even if the bound
user is `Admin`, a token scoped to `/projects/acme` cannot touch
`/projects/other`.

## Two-factor authentication

Two factors are shipped:

- **TOTP** (RFC 6238 SHA-1 / 6 digits / 30s period) — works in the CLI
  and any authenticator app. Enroll with `lv 2fa enroll-totp`.
- **WebAuthn** (FIDO2 / passkeys) — browser-only because the protocol
  requires a resident authenticator. Enroll at `/account/2fa` in the
  web UI (requires `webauthn:` daemon config — see
  `docs/configuration.md`).

To enroll TOTP:

```bash
lv 2fa enroll-totp --label phone
```

The command prints:

- An `otpauth://` provisioning URL (paste into Google Authenticator /
  Authy / 1Password / etc., or render a QR in the UI).
- The base32 secret for manual entry.
- 10 single-use recovery codes — *save them now*; they are not stored
  in plaintext and cannot be re-shown.

After enrollment, `lv login` runs in two stages: it accepts the password,
the server returns `Requires_2Fa=true` with no token, and the CLI prompts
for the second factor. Recovery codes work in the same prompt — each
code is consumed on use.

For WebAuthn enrollment, open `/account/2fa` in the UI and click
"Register security key". The browser drives `navigator.credentials.create`
against the daemon; the resulting credential lands in the same
`user_2fa` table TOTP uses.

To disable a factor: `lv 2fa disable --method totp --label phone`.

## Migration from the legacy admin/operator/viewer roles

`users.role` holds a flat `admin > operator > viewer` ladder. The RBAC
engine respects these rows for backward
compatibility:

- Each legacy role appears as a synthetic group `group:<role>@local`.
- `RequirePerm` falls back to the legacy ladder ONLY when the engine
  has no bindings at all for the caller's principal set.
- One root binding migrates an entire team at once:

  ```bash
  lv role grant Admin    group:admin@local    --path / --propagate
  lv role grant Operator group:operator@local --path / --propagate
  lv role grant Viewer   group:viewer@local   --path / --propagate
  ```

Once those bindings exist, the legacy fallback never fires; the engine
is the only authority.

## Wire format quick reference

| Bearer prefix | Lookup table | Rejected on |
|---|---|---|
| `lvs_<hex>` | `sessions` | revoked, hard-expired, idle-timeout |
| `<hex>` (no prefix) | `tokens` (bcrypt match) | `deleted_at`, `expires_at` |
| (no Authorization header) | mTLS client cert → classified (see below) | invalid/expired peer cert |

## mTLS principal model

A bearerless mTLS caller (no `Authorization` bearer) is classified by its
certificate, not blanket-trusted as `admin`:

| kind | condition | authority |
|---|---|---|
| **local-root** | connection is loopback **and** the cert CN is a trusted cluster host | `admin` (on-node root — running `lv` on a node is already root-equivalent) |
| **peer** | non-loopback **and** the cert CN is a trusted cluster host | `admin` (a trusted cluster node: peer RPCs + relaying an already-authorized user forward) |
| **client** | any other cert — the distributable CLI client cert, an unknown/empty CN, or a **removed** host's CN | must present a session bearer (`lv login`); denied once strict mode is enforced |

A bearer, when present, always wins and yields the real user (role/scope).

"Trusted cluster host" is decided from the `hosts` row, and the three cases are
distinct:

- a **tombstoned** row (a removed host) is refused outright;
- a **live** row is trusted, in any operational state — draining, fenced,
  upgrading and maintenance all stay trusted, because a recovering node needs its
  own rejoin RPCs accepted. The removal boundary is `deleted_at`, not state;
- **no row at all** falls back to the certificate, and is trusted only if it
  carries `ServerAuth`. That is what `lv host init`/`lv host add` issue for a host
  and what the distributable `lv-cli` certificate deliberately does not, so the CLI
  cert is never a peer.

That last case exists because hosts learn about each other by replication, and
replication is what this gates: requiring a live row meant a freshly provisioned
cluster — where every node holds only its own row — could never converge. An
unreadable row is **not** the same as an absent one and is refused, because an
error cannot rule out a removal.

**Removing a host revokes its certificate.** `lv host rm` appends the host's
certificate serial to the cluster CRL, so removal does not rest solely on the
tombstone reaching every node. It needs the CA private key, so run it from the
machine that ran `lv host init`; if it cannot, the command says so rather than
skipping revocation silently.

The CRL is then **replicated**, not copied around by hand. `lv host rm` publishes
the revocation before tombstoning the host, every node installs it within about
half a minute, and each
daemon reloads `crl.pem` when the file changes. Two things make that safe to send
over a channel any peer can write to: a CRL is signed by the cluster CA, and every
node verifies that signature against its own `ca.crt` before the file is touched —
so a host publishing a CRL that omits its own serial is refused rather than
believed. Nodes enforce the union of every verified CRL they know, so equal-number
lists or a later list minted from stale state cannot un-revoke either branch. The
table is append-only and keyed by both the CRL hash and its signed bytes, so a
garbage row occupying a public hash cannot displace or bury the genuine row.
`lv health` warns for as long as any peer's CRL version is behind another's.

If minting or publishing fails — the cluster was unreachable, the daemon was
restarting — `lv host rm` refuses to tombstone the host, preserving the serial and
making the whole operation safe to retry. When a CRL was minted but publication
failed, `lv host publish-crl` can publish it directly; then rerun `lv host rm`.

Distribution deliberately does **not** go over SSH. SSH is the bootstrap channel —
`host init`, `host add`, `rotate-audit-key` — for reaching a machine that is not
yet a cluster member. A revocation goes to nodes that are already mutually
authenticated peers with a replicated store built for exactly this, where an SSH
fan-out would be best-effort with a list of hosts it failed to reach.

**Threat model.** The daemon runs as root against the local libvirt socket and a
replicated state DB, so root on a node is already full local + cluster power —
RBAC does not (and cannot) constrain it, and a host cert is a legitimately
root-obtained *node* identity. What this model closes is that a **distributable**
credential (the shared CLI client cert) does not equal admin: hand someone CLI
reach and they still need to `lv login` to act.

### Renewing a host certificate (`lv host renew-cert`)

A host's cluster certificate — the identity behind every peer and on-node mTLS
call — is valid for five years. Each daemon exports its expiry as
`litevirt_certificate_expiry_timestamp_seconds{cert="host"}` and sends a
`certificate.expiring` notification from 30 days out (error severity inside 7
days), then `certificate.expired`, repeating daily while it stands. Renew it from
the machine that holds the cluster CA key:

```bash
lv host renew-cert host-b
lv host renew-cert host-b --ssh root@10.0.50.11   # name isn't the address
```

The host keeps running throughout — no restart, no partition, nothing a peer
could read as a failure:

1. **The key is generated on the host.** The host (its own `litevirt` binary,
   over SSH) creates the new key and sends back only a certificate request; the
   CA machine signs the request and sends back only a certificate. The private
   key never crosses SSH and never exists on the CA machine.
2. The certificate is a **successor**: same name and addresses, a fresh
   five-year validity, and — signed by the CA — the serial of the certificate it
   replaces. Peers pin each host's recorded serial (that pin is what keeps a
   re-admitted name's old certificate out), and a peer whose record still names
   the predecessor accepts its successor immediately. The pin is not relaxed:
   only one hop is honoured, and an older certificate cannot name a serial
   recorded after it was minted.
3. **One atomic switch.** The host keeps each identity as a complete pair under
   `pki_dir/host.d/<serial>/`, with `host.crt` and `host.key` resolving through
   one `host.d/current` link, and the install is a single rename of that link.
   A crash or a dropped connection at any point leaves a pair the daemon starts
   with, and a daemon that finds its identity unloadable at start repairs it from
   the newest complete pair under `host.d`.
4. The daemon serves the new pair from the next handshake — its gRPC listener,
   its peer probes and its loopback clients read the identity at handshake time,
   and its recovery-claim votes are signed with it too. A replacement that does
   not chain to the cluster CA, names another host or does not match its key is
   refused, as is a renewed key not held safely. The identity a node already
   has is never refused over how its key file is held: a `host.key` outside the
   PKI directory, owned by another user, or with a mode that cannot be tightened
   is still served, logged as a WARN and raised as a degraded
   `certificate/key_file_unsafe` condition naming the file and the fix (move,
   `chown` or `chmod 600`); a key readable by others is tightened.
   **Established connections** are judged on every RPC, not only at the
   handshake. A connection made with a certificate the CA has **replaced** —
   see "Superseded certificates" below — starts no new RPC: the next one is
   refused with `Unavailable`, and the client reconnects and presents its
   renewed certificate. Only the RPCs already in flight on it — a cold-disk
   migration stream, a backup push — are left to finish, and the connection
   is closed when the last one ends, or after 15 minutes; one cut by that
   bound fails and must be re-run (cold-disk migration and peer backup streams
   do not resume), so renew outside long transfers. That holds once the
   replaced certificate is REVOKED too, as step 7 does at once: a revoked
   certificate with a standing CA-issued successor was revoked because it was
   renewed, and its connections drain the same way. A cold-disk migration
   opens a fresh connection for each disk, so one renewed mid-copy finishes
   the disk in flight and copies the rest with the renewed certificate; a
   container migrate or failover relocate likewise drives the target's
   restore over a fresh connection once its rootfs push has finished.
   A certificate revoked with **no** successor — `lv host rm`, `lv host
   revoke-cert` of a live identity — is the emergency path: a connection made
   with it (or on which the host served it) refuses its next RPC and is closed
   at once, streams in flight included. If you renewed because a key was
   stolen, a connection the thief opened before the renewal is not cut at
   once but drained: it starts nothing new, and what it had in flight runs out
   within 15 minutes; restart the daemons to cut it sooner. A host's own UI
   and REST clients reconnect by themselves when the host's certificate
   changes: the next request goes over a new connection with the renewed
   certificate, while a console or event stream already open on the old one
   runs on until it ends (or 15 minutes pass).
5. The command dials the host and **confirms** it presents the new certificate.
   It switches back only when the host demonstrably still presents the old one
   and the cluster does not record the new one; a probe that merely fails proves
   nothing, so nothing is undone on it. A successor that was signed but never
   used is revoked.
6. The daemon re-records its own serial within a minute, so the record moves on
   and the old certificate stops being accepted as that host.
7. Then the replaced certificate is **revoked, at once**. Every node on this
   build already refuses it — as a voter, as a claim signer and on every RPC
   (see "Superseded certificates") — so revoking it costs a pinning node
   nothing. The revocation is held only while the cluster has a node that does
   **not** pin: a live host on a different build (`--force`), or one running
   with `auth.trust_rotated_peer_certs` (each node reports that switch as its
   own `certificate/trust_rotated_peer_certs` condition, which is how the others
   know). For such a node the newest voter generation, if it needed the replaced
   certificate's accept, would stop verifying after the revocation
   ([recovery-claims.md §4.1](design/recovery-claims.md)); so while one exists,
   and only if the newest generation does need that accept, the revocation is
   **owed**: the CA-signed CRL is stored in a replicated
   `certificate/revocation_owed` health condition (a degraded reason in
   `lv health`), the host notifies `certificate.revocation_owed` daily, and the
   cluster publishes the CRL by itself as soon as no such node is left, or a
   newer voter generation no longer needs the accept. `--revoke-old` revokes at
   once regardless; `--keep-old` not at all.

   An owed revocation is published only by a node that can trust its own view:
   its replica has caught up, it has adopted the newest voter generation it
   holds, and a majority of that generation's members answer it now, each
   having adopted it and none holding anything newer. A node on the minority
   side of a partition, or one still mid-exchange after a heal, holds.

#### Superseded certificates

A successor is the CA's own statement that the certificate it names is no
longer the host's identity. Every node collects that statement wherever it sees
a successor — a TLS handshake in either direction, an accept carried in a claim
or voter certificate, its own renewed identity — and keeps it node-locally in
`pki_dir/superseded.pem` (re-verified against the CA on load, never replicated,
only ever added to). A certificate a node holds a standing successor of is
refused there:

- its accepts do not count — in workload claim certificates or in a voter
  generation the node has not yet adopted;
- every new RPC on a connection made with it is refused, and the connection
  drains as above;
- it is never the host for peer trust, whatever the host's row says.

None of this reads `hosts.cert_serial`. That column is replicated data any peer
can write — a compromised host could write a renewed voter's record back to its
replaced serial — so it decides nothing here; a host recorded with a serial
whose revocation is owed is reported as `certificate/serial_regressed` (a pki
directory restored from before a renewal, or a peer rewriting the row) and the
revocation is published regardless. Only the CA can take a successor back: a
successor it revokes unused (an abandoned renewal) hands the identity back to
its predecessor; one revoked because it was renewed in turn does not.

The record is fail-closed against loss: a `superseded.pem` the node cannot
read (unreadable, not a regular file, over 16 MiB) is left exactly as it is
and never written over, what the node learns meanwhile is kept in memory, and
the read is retried; once it succeeds, both are merged and saved. If the
installed CRL cannot be parsed, the node treats nothing in it as revoked — the
CRL's fail-open rule — so an abandoned (revoked unused) successor looks
standing there, and the predecessor it would hand back is refused on that node
until the CRL is readable again; `certificate/crl_install_failed` reports that
node.

A node that holds no successor for a certificate does not refuse it on that
ground; revocation is what ends it everywhere. Until it is revoked — while it is
owed, or after `--keep-old` — the replaced certificate still authenticates as a
**bearerless client** (`admin` unless `auth.strict_mtls_identity` is on) to a
node that has not yet seen its successor, and as a TLS server to anything that
dials it. Under `auth.trust_rotated_peer_certs` the supersession checks are off
on that node — its serial pins and the stale-connection judge with them — so
while that recovery switch is on, a replaced key's accepts DO count there.

#### Renewing a voter

A node that adopts a voter generation decided BEFORE one of its signers renewed
cannot count that signer's pre-renewal accept as it stands (§4.1's cost): the
pin refuses it, and once the renewal has revoked the replaced certificate, so
does revocation. Most of the time this is invisible: every node adopts within
seconds. A node that was offline, whose import was retrying, or that was
admitted later can be left one generation short.

Such a node asks the renewed voter to **re-attest** its accept: the voter
re-signs, with its current certificate, the accept it recorded in its own
durable claim state when it voted — the same key, generation, ballot and
value, never anything taken from the row or the caller — and the node adopts
the generation with that accept counted. Nothing is relaxed: the re-signed
accept is checked like any other, the replaced certificate counts for nothing,
and a voter asked about a generation it never accepted has nothing to give, so
a forged generation gets nothing. This works however many members are stuck,
including a MAJORITY of the newest generation, where no voter change could be
decided (a voter answers only at its adopted generation) and
`auth.trust_rotated_peer_certs` would not help (it relaxes the pin, never
revocation).

While the renewed voter cannot re-attest — unreachable, or on an older build
— the node raises `certificate/voter_generation_stuck`, naming the generation,
the voter it is waiting on, and the fixes: bring that host back on this build,
or **decide one more voter change** from a node that has adopted the newest
generation — `lv cluster voter add <host>`, or `lv cluster voter rm <host>`
and then add it back. Its accepts carry current certificates, it becomes the
stuck node's anchor, and the node adopts through it; the condition clears. A
voter change needs a majority of the newest generation, so when a majority is
stuck, re-attestation is the way out. To avoid all of this, renew voters only
when `lv cluster voter ls` shows every node on the newest generation.

The renewal deletes the replaced key from the host's PKI directory and the copy
`lv host init`/`lv host add` left on the CA machine (`<host>.key`, when it is
that key, together with `<host>.crt`, when it is the replaced certificate). A legacy `host.key` that resolved OUTSIDE the PKI directory is no
longer used but is not deleted (the renewal cannot know what else uses that
file); the command names it. Any other copy taken earlier is what `lv host
revoke-cert` closes, at any time.

An owed revocation is not a row a peer can quietly drop. It counts as done only
when its serial is in the CRL the node installed from CA-verified rows: a row
marked resolved or tombstoned without that is restored to owed, and a row whose
evidence no longer carries a CA-signed CRL listing its serial raises the
critical `certificate/revocation_owed_tampered` condition (and
`certificate.revocation_owed_tampered`), telling the operator to publish it with
`lv host revoke-cert`. Only a node that can trust its view judges this (the
same test as for publishing), after installing the cluster CRL that tick, and
only once the row has looked dropped there for three minutes — the row and the
CRL that justifies a legitimate resolve replicate independently, and a node
holding the first without the second accuses no one. A node that cannot install
the cluster CRL raises `certificate/crl_install_failed` once and judges nothing
until it can. A row deleted outright leaves the CA machine's
`pki/renewals.json` as the record.

A recovery whose claim certificate was signed with the replaced key before the
revocation lands is refused at execution (`recovery_claim_unproven`) and
re-certified at the coordinator's next attempt with the new certificate; it is
delayed, never run twice.

The command refuses, touching nothing, when the cluster's recorded serial and the
installed certificate disagree, and while hosts run different builds (`--force`
overrides): a peer on an older release does not recognise the successor and
refuses the renewed host until its re-recorded serial reaches it by anti-entropy
(`anti_entropy_interval_sec`, 60 s by default). A re-added host's audit admission
record, bound to its certificate serial, is re-signed for the new one. libvirt's
TLS listener (`qemu+tls://` migration) is asked to reload; if it cannot, it keeps
the old certificate until libvirt restarts, which is harmless because libvirt
does not read the cluster CRL. The migration-TLS certificates under
`pki_dir/migration` come from a separate CA and are not renewed by this command.

`lv host revoke-cert <host> --serial <hex>` is the manual path. It accepts only a
serial known to be the host's — one the CA machine's renewal log
(`pki/renewals.json`) records for it, or the predecessor named by the certificate
the host presents — and refuses a serial any other host is recorded with. The
host's own live or presented certificate needs `--force`, because revoking it
cuts the host off and gets it fenced (that is what `lv host rm` is for); and when
the host's presented certificate cannot be read, it refuses unless `--force`.

### Recovering the admin account (`lv user reset-admin`)

`lv user reset-admin` is for the cluster nobody can log in to, so it takes no
credential. It runs as root on a node and gives the existing `admin` account a
new random password, written to `/etc/litevirt/admin-password` (mode 0600). It
never creates an admin: on a node with no live admin it refuses, because a
joining node's credential replicates in and a deleted admin stays deleted.

Every reset is audited as `user.reset-admin`, attributed to `root@<host>`, with
target `admin` and a detail of `via=<channel> os_user=<who>`. `os_user` is
`SUDO_USER` when set, otherwise the login name. The CLI reports it and the daemon
records it as a claim, not as an authenticated identity. No password and no hash
is ever written to the row. The CLI mints the password, keeps it, and sends only
its bcrypt hash.

**With the daemon running**, the command calls the `ResetAdminPassword` RPC over
the host's local root channel. It dials `127.0.0.1` on the daemon's gRPC port and
presents this host's own certificate from `pki_dir`, with no bearer. It ignores
`LV_HOST`, `LV_TOKEN`, a stored `lv login` session and a CLI client bundle, since
any of those would make the call arrive as someone else. The daemon accepts the
call only from a **local-root** principal whose certificate CN is its own host
name. A peer's certificate (even over loopback), an admin session, an API token
and the distributable `lv-cli` certificate are all refused with
`PermissionDenied`. Holding a session is not the same as being root on the node.
The daemon also refuses a hash that is not bcrypt or is below the cluster's cost.
It writes the reset and the audit row itself, as `via=local-root`.

**With the daemon down**, the command falls back to writing the reset straight
into the local database. It records the audit entry in the host-local
pending-audit journal (`<data_dir>/pending-audit/`), and the daemon folds the
entry into the audit log once it is running. The row is signed (whenever the
host signs, which is the default) and carries the
time the reset actually happened, with `via=journal`. The journal entry is
written before the reset and updated with the outcome after, all under the
journal's lock. A reset that cannot be journalled is not made. A command that
died in between leaves the result `interrupted`. The mechanism is described in
[audit-log.md](audit-log.md#actions-taken-while-the-daemon-is-down).

The fallback is taken only when the daemon cannot be reached (`Unavailable`) or
is too old to have the RPC (`Unimplemented`). Any other answer, a refusal
included, is returned as it is. A timeout is returned too, not retried locally,
because the daemon may already have applied the reset and a second one would
leave the password file and the database disagreeing. Why the CLI may not simply
write its own audit row is in [audit-log.md](audit-log.md#actions-taken-while-the-daemon-is-down).

### Enforcement (`auth.strict_mtls_identity`)

Denial of bearerless `client` certs is off by default and gated by both the
`auth.strict_mtls_identity` config flag **and** the `strict_mtls_identity_v1`
capability being active cluster-wide. The config flag is the enforcement switch
**and** kill switch (set it false to disable regardless of any latch), and the
loopback local-root path is never gated — so a mis-flip is reversible and can
never lock out an on-node operator. Because peer/forwarded traffic uses host
certs (which stay `admin`), enabling it changes **no** node-to-node behavior; the
only operator-visible change is that a **remote** CLI must `lv login` first
(on-node `lv` over loopback is unaffected).

**The token is advertised by this build; enforcement remains default-off.**
`strict_mtls_identity_v1` is in `capabilities.supported`, so deploying this build
lets the capability activate + latch cluster-wide — but that is behavior-neutral,
because enforcement is `auth.strict_mtls_identity` (default false) **AND** the
latch. Deploying does NOT change auth. HA-degraded does NOT fire for an
advertised-but-disabled token (degraded tracks configured-to-enforce, not merely
advertised). Enabling is a single config step: set `auth.strict_mtls_identity:
true` on every node; the HA monitor drives the latch while the cluster is healthy,
and the config flag stays the reversible kill switch (set it false + restart to
stand down, regardless of the latch marker). Validate on an ephemeral cluster
before enabling.

### Realm-aware role bindings (`auth.rbac_realm`)

Role bindings enforce against **realm-qualified** principals
(`user:<name>@<realm>`), so a legacy **bare** grant (`user:<name>`) never matches
and is inert. `auth.rbac_realm` opts a node into realm-aware grant grammar so it
stops minting new inert bindings. Like `auth.strict_mtls_identity`, it is gated by
the config flag **and** the `rbac_realm_v1` capability latched cluster-wide, and
the flag is the reversible kill switch (default false):

- **Flag off (default):** a bare grant is stored verbatim — legacy behavior,
  mixed-version-safe.
- **Flag on, not yet latched:** a bare `user:<name>` grant is **rejected**
  (`FailedPrecondition`) — specify an explicit realm. This is the safe
  pre-uniformity state: while any peer might still mint bare bindings, we refuse
  rather than canonicalize.
- **Flag on and latched fleet-wide:** a bare grant for a **known local user** is
  **resolved** to `user:<name>@local` and stored canonically; one that names no
  known local user is rejected (spell out the realm).

The grammar treats a principal as realm-qualified only when the part after the
last `@` names a realm (`local`, `oidc:*`, `ldap:*`) — so `user:alice@example.com`
is a bare username (an email), while `user:alice@oidc:corp` is realm-qualified.

Existing bare bindings created before enabling this remain **inert** (they never
granted access) until rewritten. Once the capability has latched fleet-wide, run
the one-time idempotent migration `lv role normalize` (supports `--dry-run`) to
rewrite resolvable legacy bare rows to canonical form; a bare binding whose realm
can't be resolved is left in place and reported as skipped. External OIDC/LDAP
**group** bindings are not yet enforced (group claims are not session-persisted).

### Forwarded identity (`auth.forwarded_identity`)

Cross-node requests are authorized on the **entry** node against the real user,
then forwarded to the owning node. The entry node relays the user's bearer to the
owner in `x-litevirt-fwd-bearer` (send-side is always on and ignored by nodes
that don't enforce it). When `auth.forwarded_identity` + the
`forwarded_identity_v1` capability are active, the owner re-authenticates that
bearer and runs RBAC + audit as the **real user** instead of `admin`; a forward
with no bearer (a background/system continuation — failover, reconcilers,
rebalancer, LB refresh, self-upgrade, replication) stays `admin` and audits as
`system`. Owner-side validation is fail-closed and never falls back to admin: a
session/user not yet replicated to the owner returns a **retryable** `Unavailable`
("forwarded identity not yet visible on owner; retry"), an
expired/revoked/malformed bearer returns `Unauthenticated`, and a resolvable user
that RBAC denies returns `PermissionDenied` — so an action taken immediately after
login or a role grant may briefly need a retry until replication catches up. The
forwarded bearer is only honored from a **peer** principal; a client cannot inject
it to impersonate a user.

> Peer-only RPC set (for a future flip that would stop accepting host certs on
> user-facing RPCs entirely): the replication/anti-entropy lane
> (`PushMutations`/`AckMutations`/state digest+dump/sensitive dumps), backup/
> restore transfer (`HasChunks`/`PushBackup`), failover probes
> (`GetRuntimeInventory`/`CheckVIPParticipant`/`CheckLBPresent`),
> `FetchBinary`, `GetVMIPRemote`, proof-bearing `PromoteReplica`/`ApplyLB`, and the
> peer-gated `ProvisionNetwork`/`SyncVTEP`/`UpdateFDB`/`RefreshLB`/
> `PushReplicaIncrement`. Not enforced today. (`ListReplicas`, `PruneReplicas`
> and `PushReplica` ARE peer-only, enforced: a replica's record is written and
> read only by cluster hosts. `UploadStoragePoolContent` refuses a header with
> any field the receiver does not know, so no replica rides on an upload.)

### Who can read the state dump

`GetStateDump` and `StreamStateDump` return the full replication dump, the
representation anti-entropy repair merges, and `StreamTableDump` returns the
same representation restricted to named tables. It is unredacted, so it carries
the secret columns of replicated tables: `hosts.ipmi_pass`,
`users.password_hash` and `tokens.token_hash`. Once every host runs a build
carrying the `credentials_split_v1` capability, each host also writes those
secrets to `host_fence_credentials`, `user_credentials` and
`token_credentials`, which only the sensitive lane below carries. This release
keeps writing the three old columns too, so a host still reading only those
columns (one on the previous release, including one rolled back and under WAL
quarantine) reads current secrets, and the state dump **still carries the
secrets**. Once every host runs a build carrying `credentials_clear_v1` as
well, the old columns are emptied and the dump carries none (see
[upgrades.md](upgrades.md#the-old-secret-columns-are-emptied) and
[design/credentials-clear.md](design/credentials-clear.md)).
All three RPCs stay peer-only regardless: only a **peer** or **local-root**
caller (a cluster host certificate) can read them. An operator or admin bearer,
a session, and the `lv-cli` client certificate are all refused with
`PermissionDenied`, whatever their role. `StreamTableDump` never serves a table
of the sensitive lane below; naming one is refused with `InvalidArgument`.
The secret-bearing tables (`StreamSensitiveStateDump`, `GetSensitiveStateDigest`)
are narrower still: peer only, and the certificate must name the sender.
`GetTableBucketDigests`, which returns per-bucket counts and hashes for public
and sensitive tables alike so anti-entropy can pull only the buckets that
differ, has the same rule, as does `StreamSensitiveTableRows`, the paged form
of the sensitive dump. `StreamTableRows`, the paged form of
`StreamTableDump`, is peer-only and refuses a sensitive table exactly as that
RPC does.

Operators see convergence without row contents. `GetStateDigest` and
`GetClusterStateDigest` return per-table counts and hashes to an `operator`
bearer; `lv cluster converge` and the UI's **Force Sync** button call
`TriggerAntiEntropy`, which schedules a repair pass between the peers and returns
no state. `lv doctor divergence` (admin) has the connected node fetch each peer's
dump with its own host certificate, and returns only table names, primary keys
and row hashes — keyed HMAC labels for the secret-bearing tables.

## Gossip encryption

Everything above rides mTLS gRPC. Gossip does not: memberlist (`gossip_port`,
7946, TCP and UDP) speaks its own protocol, and it carries the membership that
relay election, replication targets, anti-entropy and capability activation all
count. [Admission](operating-model.md#gossip-admits-only-known-hosts-and-is-authenticated-only-when-encrypted)
refuses names that are not in the `hosts` table, but names and addresses are not
secrets. What authenticates gossip is a cluster-wide AES-256 key:
memberlist encrypts every packet and stream with it (AES-GCM), and a node that
enforces it drops anything unencrypted or under a key it does not hold.

**An unauthenticated gossip segment is not supported.** Until every host runs
`enforcement.gossip_encryption: true`, anyone who can reach `gossip_port` can
read the membership, announce a real host's name from its address, or disturb
failure detection. Keep the port on a network only cluster hosts can reach until
the rollout below is finished, and firewalled after it: the key is one shared
secret, so every host holding it can speak for any member, and a removed host
keeps what it knew until the key is rotated.

### The key file

`/etc/litevirt/pki/gossip.key` (`<pki_dir>/gossip.key`) on every host, mode
0600, beside `ca.crt`. One base64 32-byte key per line; the **first** encrypts,
**every** key decrypts; `#` lines are comments. The daemon refuses a file that
group or other can read, a key that is not 32 bytes, and a duplicate.

It is distributed exactly as the CA certificate is — pushed over SSH from the
machine that holds the CA, which keeps the canonical copy in its CLI PKI
directory (`~/.config/litevirt/pki/gossip.key`):

- `lv host init` mints it next to the CA and pushes it; `lv host add` pushes it
  alongside `ca.crt`, and refuses to add a host to a cluster whose enforcement
  block keys gossip when this machine has no key to give it;
- `lv host install-gossip-key` gives an existing cluster one;
- `lv host rotate-gossip-key` replaces it.

The key is never written to `config.yaml`, the replicated database (and so never
to a state dump) or a log. Logs, the CLI and the state file below name keys by a
16-hex-digit ID, a truncated domain-separated SHA-256 that cannot be reversed.
If the CA machine loses its copy, copy any host's `gossip.key` back, mode 0600.

The daemon re-reads `gossip.key` every 5 seconds and applies a changed keyring
**without a restart**. A missing, loose or unparseable file is logged and
ignored — the keys in use are kept, because an empty keyring would mean
plaintext. It reports what it is USING to
`/etc/litevirt/pki/gossip-keyring.state`:

```
mode=enforced
primary=3f1c9e0a7b2d4c61
keys=3f1c9e0a7b2d4c61
rejected=0
```

`primary` is the keyring's first key, and `keys` every key it decrypts with,
primary first. The order of the keys after the primary is the daemon's, not
the file's, and means nothing: a host whose `primary` and set of `keys` match
the file has loaded it. `primary` is set at every stage but `false` — `install` too, where
the host holds the key but still **sends plaintext** — so it says which key the
host encrypts with *once its stage sends encrypted*, not that it is encrypting;
`mode` says that. `lv host install-gossip-key` reports each host from both:

| `mode` | Reported as |
|---|---|
| `off` | `off (gossip plaintext; key file ignored)` |
| `install` | `install, sending plaintext, accepting plaintext and <keys>` |
| `staged` | `staged, encrypting with <primary>, accepting plaintext and <keys>` |
| `enforced` | `enforced, encrypting with <primary>, accepting only <keys>` |

`rejected` counts gossip this node dropped since it started for being
unencrypted or under a key it does not hold. It should stay flat through every
step below; a rising count is a peer this node cannot hear.

### The flag

`enforcement.gossip_encryption` defaults to `false`. Its values are four stages:

| Stage | Keyring | Sends | Accepts |
|---|---|---|---|
| `false` | none (the file is not read) | plaintext | plaintext |
| `install` | loaded | plaintext | plaintext and encrypted |
| `staged` | loaded | encrypted | plaintext and encrypted |
| `true` | loaded | encrypted | encrypted only |

Two nodes gossip with each other exactly when their stages are **adjacent** in
this table. Two apart cannot: a `staged` node is unreadable to a `false` one, and
a `true` node is deaf to an `install` one. That is the whole rollout rule — each
rolling restart moves every host one stage, and each finishes on **every** host
before the next begins. `install` is the stage it is tempting to skip; skipping
it makes the first `staged` host unreadable to every host with no keyring yet.

Every value but `false` refuses to start without a usable `gossip.key`, rather
than come up in plaintext under a flag that says otherwise. The stage is read
once at startup (memberlist fixes it for the life of the process); the keys are
not. A new cluster's enforcement block from `lv host init` sets it to `true`:
there is no plaintext host to stay compatible with.

There is no capability token for this flag, deliberately. The guarantee is
enforced by the **receiver**, locally: a `true` node drops what it cannot
authenticate, whatever its peers believe, so no node relies on a peer honouring
anything. A mis-staged pair loses gossip between the two of them — an
availability problem, visible in `rejected` and in membership — never a data
problem, since replication rides mTLS gRPC. A latch could not drive the rollout
either: memberlist cannot change stage under a running process, so it would take
effect at the next restart, which is the rolling restart the sequence already is.

### Turning it on in an existing cluster

Every host must first run a build that has this flag: a host on an older build
ignores the key and stays plaintext, so the `staged` roll would cut it off.

1. From the machine that holds the CA, install the key everywhere. Nothing
   changes on the wire yet:

   ```bash
   lv host install-gossip-key
   ```

2. On each host in turn, set the stage and restart, waiting for the host to be
   back before moving on:

   ```bash
   # /etc/litevirt/config.yaml
   enforcement:
     gossip_encryption: install
   ```

   ```bash
   systemctl restart litevirt
   lv host ls                            # the host is back and active
   cat /etc/litevirt/pki/gossip-keyring.state   # mode=install
   ```

   When **every** host is done, `lv host install-gossip-key` again: it writes
   nothing and lists every host's stage. All must read `install`.

3. The same roll with `gossip_encryption: staged`. All must read `staged`, and
   `rejected` must be flat on every host.

4. The same roll with `gossip_encryption: true`. All must read `enforced`, with
   `rejected` still flat. Gossip is now authenticated.

Do not add hosts in the middle of a roll: `lv host add` copies the enforcement
block of the node it reads, and a host more than one stage from any peer cannot
gossip with it. Rolling back is the same walk in reverse — `staged`, then
`install`, then `false`, each on every host — never a jump of two.

### Rotation

```bash
lv host rotate-gossip-key               # --grace 30s --timeout 2m
```

Run from the machine that holds the cluster's gossip key, with every host
reachable over SSH and its daemon running. No restart. memberlist encrypts with
the primary and decrypts with any installed key, so a new key must be on every
host before any host encrypts with it, and every host must stop encrypting with
the old one before any host drops it. The command does it in three phases, and
each waits for every host's state file to report the phase **loaded** — not just
the file written — before the next:

1. `[old, new]` — the new key is accepted everywhere; the old one still encrypts;
2. `[new, old]` — the new key encrypts; the old one is still accepted, for `--grace`;
3. `[new]` — the old key is removed.

"Add the new key as primary, then remove the old" in two steps is the tempting
shortcut, and it cuts off every host that has not loaded the new key yet for as
long as that takes.

If the rotation stops part-way — a host down, a phase that times out, Ctrl-C —
the cluster is safe as it stands, and the error names the host. Fix it and run
the command again: finding hosts on different keyrings, it puts them all back on
this machine's copy and then settles on that copy's primary alone (the new key
if phase 2 had started, the old one otherwise), and stops. Run it once more to
rotate. A host that is `false` takes the new file without being waited on; it
loads whatever is current when its stage changes.

Rotate after removing a host you no longer trust, after any suspected exposure
of a `gossip.key`, and periodically.
