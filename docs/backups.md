# Backups

litevirt's backup system mirrors Proxmox PBS in shape: a
content-addressed deduped chunk store, BLAKE3 hashing, dirty-bitmap
incrementals, AES-256-GCM encryption, mark-and-sweep GC, retention,
cross-repo sync, and live restore.

## Application consistency (guest fs-freeze)

`lv backup snapshot` takes a `--quiesce` mode (default `auto`). With `auto`, if the
VM advertises a QEMU guest agent, litevirt freezes the guest's filesystems
(`fs-freeze`) for the brief moment the pull-mode session establishes its
point-in-time, then thaws — yielding an **application-consistent** backup. Without a
guest agent (or with `--quiesce off`) the backup is crash-consistent.
A freeze failure is logged and the backup proceeds crash-consistent — it never fails
an otherwise-good backup. Scheduled backups inherit the `auto` default.

The implementation lives in `internal/pbsstore` (chunk store +
manifest + GC) and `internal/nbd` (live-restore NBD source). Operator
surface:

| Surface | What |
|---|---|
| `lv backup repo …` | local repo management — init, ls, gc, verify, prune, sync |
| `lv backup snapshot <vm>` | push a VM disk into a repo via the daemon (gRPC) |
| `lv backup restore-from` | offline restore: stream chunks to a target disk path |
| `lv backup restore-live` | live restore: serve manifest over NBD while the VM boots against a qcow2 overlay |
| `lv backup schedule …` | cron-driven backups, scoped per-VM, per-pool, per-project, or cluster-wide |
| compose `backup:` block | deploy-time hook that reconciles a `backup_schedules` row from the stack |
| `/backups` UI page | manifest list per configured repo, plus verify / GC / prune / sync through the daemon's repo RPCs |

## Repository

A *repository* is a directory on a host (typically NFS-mounted on a
dedicated backup host). One litevirt cluster can talk to many repos.

```bash
lv backup repo init /srv/backup/main
```

For a fresh encrypted repo:

```bash
# 32 hex bytes = 256 bits.
openssl rand -hex 32 > /etc/litevirt/backup.key
chmod 600 /etc/litevirt/backup.key

lv backup repo init /srv/backup/main \
    --encrypted --key-file /etc/litevirt/backup.key
```

Repos can be exposed to the UI's `/backups` page by registering them
in `/etc/litevirt/config.yaml`:

```yaml
backup_repos:
  main:    /srv/backup/main
  offsite: /mnt/dr/offsite
```

When set, `/backups` (no query string) lists each repo with snapshot
count + total size; click through to see manifests. Without the
config block, the page still works via `?repo=<path>` for one-off
exploration.

The on-disk layout:

```
/srv/backup/main/
├── repo.json                 # schema-version, encryption mode
├── chunks/
│   ├── 0a/0a1b2c…/           # one file per chunk; filename = BLAKE3(plaintext)
│   └── …
└── snapshots/<vm>/<ts>-<disk>.manifest.json
```

## How chunks dedupe

A 4 MiB rolling window over the source disk is BLAKE3-hashed. The hex
digest is the chunk's stable id and on-disk path. Two snapshots that
share even a single 4 MiB region (a guest OS image, a database WAL
segment, untouched filesystem regions) share the chunk file — the
second snapshot's manifest just references the existing chunk.

Compression is left to the underlying filesystem. Most backup hosts
already run on ZFS or btrfs with native lz4; layering Go-side
compression would just contend.

## Incremental backups

```bash
lv backup snapshot postgres-1 --repo /srv/backup/main --incremental
```

For a **running** VM, the daemon reads guest-visible content over a
pull-mode libvirt NBD export — this is the default backup path (wired
in `internal/daemon/daemon.go` via `SetBackupSource`, see
`internal/grpcapi/backup_snapshot.go`). `--incremental` resolves the
most-recent manifest for `(vm, disk)` via
`pbsstore.Repo.LatestManifestFor`, opens the session against that
parent's checkpoint, and queries the NBD `qemu:dirty-bitmap` meta-context
so only changed extents are read off disk; unchanged regions inherit the
parent manifest's chunk refs verbatim. A full (non-incremental) push uses
the `base:allocation` meta-context to skip holes and zero regions.

When no parent manifest exists yet, the daemon emits a progress note
("first incremental degrades to full") and does a full push so the
chain has a root. Subsequent runs go incremental.

**Fallback for stopped VMs / no libvirt / a missing parent checkpoint:**
the daemon backs up the qcow2 container file directly with
`pbsstore.PushFile`. The chunk store still dedups by content and the
manifest chain stays intact, but no read I/O is saved and an
`--incremental` request degrades to a full container backup. Operators
see the fallback reason in the progress stream. (Container backup only
works on file-based pools; a stopped VM on a block/object backend such as
Ceph must be backed up running, via the guest-content path.)

## Encryption

Encrypted repos seal each chunk with AES-256-GCM. The chunk ID stays
the BLAKE3 of the *plaintext* so dedup survives key rotation —
re-encrypting only the on-disk blob, not the metadata.

```bash
lv backup repo init … --encrypted --key-file /path/to/key
```

Wrong-key reads return a clear `ErrKeyMismatch`. Repository metadata
records the encryption mode in `repo.json`, so a downgraded binary
without the key will refuse to read rather than silently treat
ciphertext as garbage chunks.

Cluster-wide secrets management will move the key into the cluster's
KV store and replace `--key-file` with per-tenant keying.

## Garbage collection

```bash
lv backup repo gc /srv/backup/main
```

Mark-and-sweep: walk every manifest, collect the union of chunk IDs,
delete every chunk file not in that set. GC is safe to run alongside
*reads* but must not run alongside another writer in the same repo —
the snapshot scheduler takes a per-repo lease so its own pushes
serialize with operator-triggered GC.

## Retention

Proxmox-shaped buckets (last / daily / weekly / monthly / yearly)
applied per `(VM, disk)` pair:

```bash
lv backup repo prune /srv/backup/main \
    --keep-last 3 --keep-daily 7 --keep-weekly 4 \
    --keep-monthly 12 --keep-yearly 5
```

Defaults to dry-run; pass `--apply` to actually delete the manifests.
Run `lv backup repo gc` afterwards to reclaim chunk space.

The snapshot scheduler applies the same retention policy after each
successful push so an unattended cluster never grows without bound.

## Verify

```bash
lv backup repo verify /srv/backup/main
```

Every chunk referenced by any manifest is read, decrypted (if needed),
and re-hashed. Mismatches indicate bit-rot; missing chunks indicate a
botched copy from another repo.

## Sync (off-site DR)

Local-to-local copy of all snapshots that exist in `src` but not `dst`:

```bash
lv backup repo sync /srv/backup/main /mnt/dr/main-mirror
```

Dedup means re-running the sync is cheap. Encryption modes must match
on both ends — pushing plaintext chunks into an encrypted repo is
refused to prevent silently leaving cleartext data on a DR host.

## Schedules

`lv backup schedule` manages cron-driven backups. The scheduler ticks
every 60 s per host (no cluster-wide leader gate — a VM is owned by
exactly one host so the host-local model has no double-firing
exposure), pulls every active schedule row, evaluates the cron, and
fans out matching jobs.

The schedule scope is inferred from which target you supply (`--pool`,
`--project`, or a `<vm>` positional arg) unless you set `--scope` explicitly:

```bash
# Per-VM schedule (VM is a positional arg)
lv backup schedule add postgres-1 \
    --repo main \
    --cron "15 2 * * *" \
    --keep-daily 7 --keep-weekly 4 --keep-monthly 12

# Pool-level schedule (fans out to every VM on the named pool that
# this host owns; replaces the boilerplate of one schedule per VM)
lv backup schedule add \
    --pool fast-ssd \
    --repo main \
    --cron "0 3 * * *"

# Per-project (every VM in a tenancy project) and cluster-wide:
lv backup schedule add --project /acme/web --repo main --cron "0 4 * * *"
lv backup schedule add --scope cluster      --repo main --cron "0 5 * * *"

lv backup schedule ls
lv backup schedule rm postgres-1 --repo main
lv backup schedule rm --pool fast-ssd --repo main      # match the scope on removal
```

Pool-mode is per-host, not leader-gated for the same reason per-VM
mode isn't: each host fires for its own slice of the pool.

Repos referenced by schedules resolve through the cluster's repo map: a
top-level compose `backup-repos:` block (see below) or daemon config
`backup_repos:` (a flat `name: /path` map). When both define the same name,
daemon config wins.

## Replication schedules

The same scheduler also drives **volume replication** (`backup_schedules`
rows with `type='replication'`). Each run copies the VM's root disk to a
target pool as a timestamped, self-contained point-in-time copy, keeping the
newest `keep_replicas`. A fast-recovery layer, not a backup replacement, so keep
backups too.

**Consistency differs between the two replication modes, and the default is the
weaker one.** A full replica of a RUNNING VM is `qemu-img convert -U` reading
the image the guest still has open — no snapshot is taken, so the copy is
smeared over however long it ran. That is neither point-in-time nor
crash-consistent, and a guest filesystem restored from it may need repair. The
`--incremental` path opens a real point-in-time session (the same pull-mode
machinery backups use) and IS crash-consistent. Replicating a STOPPED VM is
consistent either way. Prefer `--incremental` for anything you intend to
promote, or replicate on a schedule the workload can tolerate being torn.

An `--incremental` run whose backup session fails **does not downgrade to the
full copy while the VM is running** — the run fails and produces no replica,
rather than silently substituting the weaker mechanism for the one you asked
for. A stopped source still falls back, because there is nothing writing the
image. Watch for `replication.failed` notifications: a schedule failing this
way keeps its previous replicas and stops making new ones.

A replica is also **published by rename**. The copy lands in a dotted
temp sibling and is renamed into its final name only once it has completed
and is non-empty — never over a file already there — so an interrupted run
cannot leave a truncated file promotion would select.

### Where replicas live, and how they are selected

A target pool is often a global pool every project uses, so replicas are not
plain files in it. Each VM has its own directory in the pool's daemon-owned
replica area, and each replica a **record** beside it:

```
<pool>/.replicas/<owner>/<disk>-<YYYYMMDD-HHMMSS>.<qcow2|raw>
<pool>/.replicas/<owner>/<disk>-<YYYYMMDD-HHMMSS>.<qcow2|raw>.json
```

The area and each owner directory are mode `0711`: a `--no-localize`
promotion boots qemu (the distro's qemu user) on a replica there, so qemu
must reach it by name, while no one but the daemon can list them.

`<owner>` is a hash of the VM's project and name; the record names the
project, VM, disk, format, time and the **schedule** that wrote it. Pruning
(`--keep`), the incremental fork base and promotion select replicas only from
the records of the VM's own project and name — never by a file-name prefix —
and pruning only the records of the schedule that is running. A file in the
area without a matching record is never read, forked from or deleted, and
pruning never deletes a replica a VM disk is backed by (a `--no-localize`
promotion records its replica as the disk's `backing_disk`). No pool-content
RPC reaches the area: uploads refuse dotted names, listings skip directories.
A cross-host replica is sent with its record over the peer-only `PushReplica`
(incremental ones over `PushReplicaIncrement`, which also carries the record),
and pruned on the peer through the peer-only `PruneReplicas`. Before a byte is
sent, the sender asks the receiver for the VM's records (`ListReplicas`). A
receiver on an older build (it has no `ListReplicas`) is sent the replica the
way that build receives one: a `<vm>-<disk>-<time>.<ext>` file at its pool's
top level (an upload, or an incremental push forked from its newest top-level
raw replica of the disk), which its failover promotes as before; it is pruned
there by name, to `--keep`. A receiver that cannot answer at all is sent
nothing. During a roll, a new host also takes an older sender's record-less
incremental push, at the pool's top level, only under the exact
`<vm>-<disk>-<time>.raw` name of one VM disk on the cluster and forked only
from a top-level raw replica of that disk. While any host cannot answer
`ListReplicas`, every run that writes a replica into the area also writes the
same data as the `<vm>-<disk>-<time>.<ext>` file at the pool's top level, so a
failover coordinated by an older host promotes the newest replica rather than
the last one written before the upgrade; once every host answers, runs stop
writing it and the top-level copies are pruned. A pruned replica is never one
a VM disk on any host references. "Every host" is the cluster's admitted
gossip membership — the hosts replication reaches — so a host that is down,
fenced or removed for good does not keep the copies coming; a member on an
older build does.

The owner directory is keyed by project and VM name: a VM deleted and
re-created under the same name in the same project inherits the earlier VM's
replicas (they can be promoted and are pruned by its schedule). No other
project's VM ever shares the directory.

A pool's content listing shows the replicas of the VMs the caller may read —
their file name (what `--replica` takes), VM, disk and time, from their
records — and never another project's. Replicas written by an earlier build
as `<vm>-<disk>-<time>.<ext>` files at the pool's top level are still
promotable: promotion and failover choose the newest of a disk's replicas from
both places, a top-level one by its pool record, or an unrecorded one by its
exact name ([storage.md](storage.md#uploads)). A run's `--keep` counts them
after the area's: once the area holds `keep` replicas of the disk, the
top-level ones are pruned too (never one a VM disk uses) — but only once every
host answers `ListReplicas`. While any host is on an older build, or cannot
be asked, the top-level replicas are kept to `keep` as that build kept them,
since its failover coordinator sees nothing else.

Manage it from the **Replication** section of the `/schedules` UI or the CLI:

```bash
lv replication schedule add web-1 \
    --cron "0 */4 * * *" --target-pool dr --target-host hostB \
    --keep 6 --incremental --auto-promote
lv replication schedule ls
lv replication schedule rm web-1 --target-pool dr
```

(RPCs `Create/List/DeleteReplicationSchedule`.)

Target model: an explicit **target host**, a **shared pool** (nfs/ceph/iscsi),
or — when neither is set — an auto-selected **healthy peer** that has the pool.
**Cross-host replication to a peer's non-shared local pool is supported**: the
source replicates to a scratch (or streams dirty extents), streams to the peer's
pool, and prunes old replicas there.

**Incremental** (`--incremental`): instead of a full copy each run, the daemon
reads only the dirty extents since the last run (via a libvirt backup
session/dirty-bitmap) and applies them into a sparse **raw** replica forked from
the previous one on the target — only changed extents cross the wire. Falls back
to a full copy for a stopped VM / old libvirt / broken chain.

### Promotion (disaster recovery)

A replica is inert until promoted. `lv replication promote <vm>` brings a VM up
from its newest recorded replica — locating it (from the VM's schedule, or
`--pool`/`--host`), copying it into a self-contained live disk on the host that
holds it, and defining + starting the VM there. `--replica` names one by its
file name (`<disk>-<time>.<ext>`, as the `disk.replicated` event reports it);
it must be one of the VM's own recorded replicas:

```bash
lv replication promote web-1                 # take over the name (host-loss case)
lv replication promote web-1 --new-name web-1-dr   # bring up alongside the original
lv replication promote web-1 --no-localize   # fast: boot off an overlay (pins the replica)
```

A split-brain guard refuses to take over the name while the original is on a
healthy host (`--force` overrides). The same action is on the VM detail page
("Promote replica").

**Automatic promotion** (`--auto-promote` on the schedule): after the failover
coordinator **confirms a fence**, it promotes the freshest replica for opted-in
VMs onto a healthy peer (so a VM on lost local storage resumes), falling back to
a bare reschedule on failure. Default off. Promotion uses the newest replica,
which is lagging by up to one schedule interval and — for a full (non-
incremental) replica of a VM that was running — is a torn copy rather than a
crash-consistent one, as above. Enable only where a small lag window is
acceptable, and prefer `--incremental` on any schedule with `--auto-promote`.

Automatic promotion **refuses a replica older than two of the schedule's
longest intervals plus an hour** (or one whose filename carries no readable
timestamp) and falls back to a plain reschedule — the same outcome as having no
replica. Without a bound, a schedule that had been failing for days left a
replica as promotable as a fresh one, and failover would replace a VM running on
current data with a week-old disk. Two intervals tolerate one missed run; the
longest interval, not the typical one, so a weekday schedule's replica is not
refused on a Monday. An hourly schedule is bounded at 3 hours, a weekly one at
two weeks and an hour. When the schedule cannot be read the bound is 48 hours.
**Manual** `lv replication promote` is
not bounded: an operator who has seen the age and chosen it anyway is making a
different decision.

## Live restore

`lv backup restore-live` exposes a manifest as an NBD source so a VM
can boot in seconds against a qcow2 overlay, while data migrates to
the overlay on-demand:

`--vm`, `--disk`, and `--timestamp` (exact RFC3339, as shown by
`lv backup repo ls <path>`) are required; the manifest is not resolved
by "latest".

The daemon can define and start the VM for you against the overlay
(`--auto-start`) and then localize the disk in the background and tear down
the NBD server (`--blockpull`):

```bash
lv backup restore-live \
    --repo /srv/backup/main \
    --vm postgres-1 --disk root \
    --timestamp 2026-05-11T02:15:00Z \
    --name postgres-restored \
    --auto-start --blockpull
```

The overlay's backing is the NBD export, declared as a **raw** backing
(the export serves guest-visible content), so qemu opens it directly. With
`--blockpull` the command returns once the disk is fully local and
self-contained; without it the NBD server stays up until you Ctrl+C (after
running `virsh blockpull <vm> <dev> --wait` yourself).

If you prefer to drive it manually, omit `--auto-start`/`--blockpull` and
`virsh define && virsh start` against the overlay, then blockpull. Use
`--from-existing` to source the domain spec from the existing `vms` record
when the manifest has none.

The NBD server is read-only and rejects writes with `EPERM` — guests
that try to write straight to the backing source get a clear error
rather than silent corruption. All writes land in the qcow2 overlay.

## Containers

Containers back up to the same chunk store as VM disks:

```bash
lv ct backup web --repo /srv/backup/main          # freeze + archive rootfs+config
lv ct restore web --repo /srv/backup/main --timestamp <ts> [--start]
```

`lv ct backup` freezes a running container (consistent point-in-time), tars its
rootfs **and** LXC config, and pushes a content-addressed, **dedup'd** manifest
that embeds the container spec — so `lv ct restore` rebuilds it from the repo
alone, even after `lv ct rm` or if the original image is gone. Full-only (no
dirty-bitmap incremental); the chunk store's dedup gives storage-side
incrementality. Like VM backup it can run against the repo-owning daemon even
when the container lives elsewhere (the owner archives locally and streams the
manifest back — see *Peer streaming* below); a container's footprint counts
toward the project's `backup_gib` quota. See
[containers.md](containers.md#backup--restore). (Local point-in-time snapshots
without a repo are `lv ct snapshot` — see that doc.)

## Peer streaming (no shared repo required)

Backup, restore, and cold migration move data between daemons over the existing
peer mTLS channel, so **a shared NFS/Ceph repo reachable from both hosts is no
longer required** for cross-host operations. The transport reuses the chunk
store's content-addressed dedup: only the chunks the destination is missing
cross the wire.

- **Remote VM / container backup** — call the daemon that owns the repo. If the
  workload lives on another host, that owning daemon reads the disk/rootfs
  locally and `PushBackup`-streams the new manifest's missing chunks back to the
  repo, then the called daemon confirms the manifest landed before reporting
  success.
- **Cold migrate / failover restore** — the repo-holding daemon streams the one
  manifest into the target's internal per-transfer staging repo, then drives the
  target's restore against it. No `--repo` reachable from both hosts needed.

Mechanics: chunks travel as **plaintext over mTLS** (the source decrypts on read;
no key crosses the wire — the chunk id is the plaintext BLAKE3, so dedup works
across repos regardless of encryption mode). The destination writes via its own
repo config: a **plaintext** repo stores chunks plaintext at rest (the same
posture as any local daemon backup today; the in-flight protection is the mTLS
transport), and an **encrypted** repo seals them with its own key. The daemon does
**not** yet carry repo encryption keys, so a peer push into a destination repo
marked encrypted is **refused (fail-closed)** rather than silently writing
plaintext into it — wiring daemon-side repo keys is a follow-up. The owner's
transient backup staging repo is itself encrypted with an ephemeral,
never-persisted key, so backup data is never at rest in plaintext even
mid-transfer. Each chunk's BLAKE3 id is verified on the receiver before it's
written, and the manifest is written last, only after every chunk it references
is confirmed present. The RPCs are peer-only (host cert) and load-shed under a
serving semaphore. Orphaned per-transfer staging repos are removed receiver-side
when a push doesn't commit, and any survivors are swept at daemon startup.

**Old-peer behavior differs by flow.** *Cold migrate / failover restore* fall
back to the shared-repo path when the target predates peer streaming (the target
re-opens the repo by name — it must then be reachable from both hosts). *Remote
VM/CT backup* has no pre-existing remote path to fall back to (cross-host backup
is new in this transport): if the sink daemon can't receive a push, the operation
returns an error rather than silently landing the backup on the wrong host.
Incremental READ for a remote backup (dirty-bitmap savings) is a follow-up — the
read is currently full, though the push still dedups so only changed chunks cross
the wire.

## Compose integration

Per-VM scheduled backup, configured directly in the stack:

```yaml
backup-repos:
  main:
    path: /srv/backup/main
  offsite:
    path: /mnt/dr/offsite

vms:
  postgres-1:
    image: ubuntu-24.04
    disks:
      data: { size: 200G, storage: hot }
    backup:
      repo: main
      schedule: "15 2 * * *"        # cron
      encryption: aes256gcm
      retention:
        keep-daily:   7
        keep-weekly:  4
        keep-monthly: 12
        keep-yearly:  5
```

`lv compose up` reconciles a `backup_schedules` row from each VM's
`backup:` block on every deploy. Removing the block soft-deletes the
schedule.

## Deprecated: raw full-disk backup/restore

The legacy raw-stream RPCs `BackupVM`/`RestoreVM` (streaming a whole disk
to/from the client) are **deprecated** and return `Unimplemented`. Use the
snapshot path instead — it is incremental, deduplicated, repo-backed, scoped to
the VM's project via path RBAC, and quota-aware:

- back up with **`lv backup snapshot`** (→ `BackupSnapshot`);
- restore with **`lv backup restore-from`** (→ `RestoreFromBackup`) or
  **`lv backup restore-live`** (→ `RestoreLive`).

### Where a restore writes

A restore never replaces a file it was merely told the name of. `<data_dir>/disks`
holds the disks of every project on the host, so a caller-chosen name there was
a way to overwrite another project's VM disk.

- **No `--target-path`** (the default): the daemon writes a new file of its own
  under `<data_dir>/disks` — `<vm>-<disk>-restore-<time>-<id>.img`, or
  `<vm>-<disk>-live-<time>-<id>.qcow2` for a live-restore overlay — and reports
  it (`target_path` in the DONE frame, the READY frame for `restore-live`).
- **`--in-place`** (`restore-from` only, `in_place` on the RPC): restore over
  the disk the VM's own record names. The VM must be in the backup's project,
  on the daemon's host, stopped, without snapshots, in a pool that passes the
  pool write check, and the file must be that disk's alone — no disk row on
  ANY host may use it. This is the only restore that replaces a file, and its
  path comes from the record, not the request.

  The backup's bytes are never placed as the disk; the restore rebuilds a
  **new** qcow2 from them, with the source format named and never probed, and
  swaps it in. What the bytes are is the backup's `content_format`: `raw` for
  a running VM's guest content (read over NBD), `disk-file` for a stopped VM's
  image file. A backup written before formats were recorded is classified from
  what the daemon wrote into its manifest — a guest-content backup always
  carries its checkpoint, a disk-file backup never does — never from its bytes;
  a container archive is refused.

  - **Raw guest content** (`qemu-img convert -f raw`) becomes a standalone
    disk. The guest controls every byte, so a qcow2 header it planted in
    sector 0 is restored as data, never followed.
  - **A disk file** (`-f qcow2`) has its header judged first — no external
    data file, one backing format. Whether it is restored as an overlay is
    the backup's own header: a standalone backup is restored standalone. An
    overlay backup keeps the backing of the disk it replaces, never one the
    backup names: a **linked clone** stays an overlay on its base, a
    **`--no-localize` promoted VM** on its replica, a **disk created from an
    image** on that image. That backing is the disk's CURRENT image header's,
    resolved through symlinks, judged like every chain a copy reads (see
    *Storage*: the image store, the recorded `backing_disk`, a pool the VM's
    project may use, a file the project owns by record), every layer
    pre-checked down to a standalone base; the disk's record (`backing_disk`,
    `backing_image`) must agree with it — `backing_image` with any version of
    that image. Its format
    comes from a record — a replica's own record, `qcow2` for an image or a
    VM's disk — and must match what the disk declares; it is never read from
    the bytes. The base must be the one the backup was taken on: a backup
    records its base's path, size and sha256 (`base_identity`), and a
    restore onto a base that has changed since is refused, naming both. A
    backup taken before that was recorded is restored onto a base that cannot
    change under its name (a replica, a template's disk), and onto an image
    only when the provenance of the very file the disk is built on shows it
    unchanged since the backup: that file was written on this host no later
    than the backup, and its bytes still have the sha256 recorded for it.
    Each image-store file carries that record (`<file>.sha256`); a file an
    earlier build left is given one when first seen — its sha256 then, and
    the later of this host's pull time for the image and the file's mtime.
    A refresh of the image name, here or on another host, writes another
    file and does not affect it. Otherwise it is
    refused, saying which, and restoring to a new file still works. That
    includes a file an earlier build re-pulled after the backup with
    byte-identical content: the pull moved the file's mtime and the pull
    time, and nothing recorded that the bytes stayed the same, so it cannot
    be told from a pull that changed them. Restore such a backup to a new
    file instead, which writes the backed-up bytes untouched. The
    restored header is re-pointed to the backing without opening
    what the backup named (`qemu-img rebase -u`), and the rebuilt overlay must
    name exactly that backing. An overlay backup of a disk that is now
    standalone (flattened by a move since) is rebuilt **flat** from the backup
    and the base it recorded — when that base still exists where the disk's
    chain may read from (the base's path in the backup is never trusted on
    its own), with the recorded size and sha256 — and the result must be
    standalone; the disk's record then names no backing. A missing, moved or changed base is
    refused, saying which; restoring to a new file still works.

  The restore streams into a temp beside the disk and rebuilds next to it, so
  it needs room for about twice the disk in that directory while it runs.
- **`--target-path`**: names the file. It needs `storage.hostpath` — the
  **admin** role — whether it is a bare name (under `<data_dir>/disks`) or an
  absolute path, and an existing file there is refused with `AlreadyExists`,
  for an admin too.

A custom absolute `repo_path` also requires the **admin** role.

## gRPC + WebUI

- **gRPC `BackupSnapshot` + `RestoreFromBackup` + `RestoreLive`** —
  the CLI commands are thin wrappers; programmatic clients can call
  the RPCs directly. A cross-host VM does not need a re-run against
  its owning daemon: the daemon you call (which owns the repo) has the
  owning host read the disk locally and **stream the manifest back**
  over peer mTLS (see *Peer streaming* below). A direct absolute
  `repo_path` stays local-only — remote streaming needs a configured
  logical repo name the sink can resolve.
- **WebUI `/backups`** — manifest list. With `backup_repos:`
  configured, lists every configured repo and its snapshot count +
  total size. Click through to drill into one repo's manifests.
  The page lists each repo through `ListBackupRepoSnapshots`, and its
  repo actions call the RPCs below, all with the session's credential,
  so the daemon authorizes and audits them as it would any other caller.
  Listing is checked at `/` with `backup.read` (legacy floor `viewer`):
  a cluster-wide Viewer can browse, a project-scoped grant or token
  cannot, and `?repo=` takes a registered repo name — a custom absolute
  path needs the **admin** role. Listing is a read and is not audited.

### Repo maintenance RPCs

The daemon verifies, garbage-collects, prunes and syncs a repo it holds
through four RPCs. Each is checked at `/` with its own verb. A repo holds
every project's backups, so a project-scoped grant or token cannot reach
it. Each RPC writes one audit row: the caller, the repo, the outcome, and
what the operation counted.

| RPC | Verb | Audit action | Detail |
|---|---|---|---|
| `VerifyBackupRepo` | `backup.verify` | `backup.repo.verify` | `chunks_checked mismatched missing` |
| `GarbageCollectBackupRepo` | `backup.gc` | `backup.repo.gc` | `manifests_scanned chunks_deleted bytes_reclaimed retained_young manifests_invalid` |
| `PruneBackupRepo` | `backup.prune` | `backup.repo.prune` | the `keep_*` policy, `kept`, `deleted` |
| `SyncBackupRepo` | `backup.sync` | `backup.repo.sync` (target `src -> dst`) | `manifests_copied chunks_copied chunks_skipped bytes_copied` |

All four sit in `backup.*`, which Operator and BackupOperator hold and
Viewer's `*.read` does not. Without RBAC bindings the floor is the
legacy `operator` role.

- **Prune** deletes manifests, and a manifest is what makes a set of
  chunks restorable. **GC** then deletes the chunks no manifest
  references, which makes a mistaken prune permanent. An operator can
  already make the scheduler prune through a schedule's `keep_*` policy,
  so neither needs more than operator.
- **Sync** writes into the destination and copies every project's
  snapshots out of the source.
- **Verify** changes nothing. It still reads and re-hashes every chunk in
  the repo, which is unbounded disk I/O started on request, so it is not
  a `*.read` verb and a Viewer cannot start one.

`repo` is a registered repo name; a custom absolute path requires the
**admin** role, as for `BackupSnapshot`. `PruneBackupRepo` without
`apply` only returns the plan. It is still checked against
`backup.prune`, because it previews a prune, and only an applied prune is
audited. GC always uses the default 24-hour chunk grace period, the
guard against sweeping a concurrent push's chunks. Only the local
`lv backup repo gc --grace` can lower it.

A refused call is audited as `denied`, and a failed one as `error`.

`lv backup repo …` does not use these RPCs. It acts on a local path
directly, with the invoking OS user's rights over that directory and no
daemon involved, so it can run on a backup host without litevirtd. It
writes no audit row, because only the daemon may extend its host's audit
chain (see [audit-log.md](audit-log.md#actions-taken-while-the-daemon-is-down)).
Holding write access to the repo directory already means being able to
delete it.

## What's still in flight

- `lv backup repo sync` over mTLS gRPC (the package-level helper
  works; the wire variant lands alongside federation).
- Application-aware quiesce (PostgreSQL/MySQL/MongoDB) on top of
  guest-agent hooks.
