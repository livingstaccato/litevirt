# Backups

litevirt's backup system mirrors Proxmox PBS in shape: a
content-addressed deduped chunk store, BLAKE3 hashing, dirty-bitmap
incrementals, zstd compression, AES-256-GCM encryption, mark-and-sweep GC,
retention, cross-repo sync, bandwidth limits, and live restore.

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
| `lv backup repo …` | local repo management — init, ls, gc, verify, prune, sync, set-compression |
| `lv backup snapshot <vm>` | push a VM disk into a repo via the daemon (gRPC) |
| `lv backup restore-from` | offline restore: stream chunks to a target disk path |
| `lv backup restore-live` | live restore: serve manifest over NBD while the VM boots against a qcow2 overlay |
| `lv backup file-ls` / `file-restore` | browse a VM or container backup and extract single files, read inside a throwaway restore VM |
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

## Compression

A compressed repo compresses each chunk with zstd before it is written (and before it is sealed, in an encrypted repo). The
chunk id stays the BLAKE3 of the *uncompressed* bytes, so dedup is unchanged,
spans compressed and uncompressed repos, and sync and peer streaming still
move plain chunks — a DR copy can differ in compression from its source. A
chunk zstd cannot shrink (already-compressed guest data) is stored as it is.

```bash
lv backup repo init /srv/backup/main                      # local, uncompressed (the default)
lv backup repo init /srv/backup/main --compression zstd   # compressed, via the daemon (below)
lv backup repo set-compression /srv/backup/main zstd      # existing repo, via the daemon
```

**zstd is explicit, and gated on the cluster's upgrade.** A plain `lv backup
repo init <path>` is exactly what earlier releases did: a local,
uncompressed repository, created by the CLI with your own rights and no
daemon. Compression is asked for with `--compression zstd` on `init`, or
`set-compression <path> zstd` on an existing repo. Until the cluster's
release token has latched — every host runs a build that reads compressed
repos — both are refused, naming the release feature `backup_zstd`.

Creating or converting to zstd is done by the **daemon of the host the CLI
is connected to** (`SetBackupRepoCompression`, below), not by the CLI alone:
the daemon's release-feature gate records that `backup_zstd` is in use
before `repo.json` changes. The path is then a path on that host, the repo is
owned by the daemon, a custom absolute path needs the admin role, and the
daemon refuses its own data and PKI directories. The CLI prints which host
created or converted the repo. `--force` skips the daemon and the gate and
writes the repo locally; nothing records that use, so it is for a repository
no older host or backup host reads (an air-gapped one). Creating an
uncompressed repo and turning compression off need no daemon and no feature.

**Older releases refuse a compressed repo.** A compressed repo's `repo.json`
says `"compression": "zstd"` and `"schema_version": 2`. Every release before
backup compression opens schema 1 only, so it stops at `repository
schema-version 2 newer than supported 1` before it reads anything — it never
misreads a compressed chunk as corrupt, and its GC never touches the repo.
That marker is permanent: `set-compression <path> none` stops compressing
new chunks, but compressed chunks are already there, so the repo stays
schema 2.

So an **existing** repo is never compressed behind your back: it stays
schema 1 and uncompressed, byte-identical to what earlier releases wrote,
until `lv backup repo set-compression <path> zstd`. Turning compression on
rewrites nothing: earlier backups stay as they are and keep restoring, and
only chunks written from then on are compressed.

A compressed chunk is a 4-byte marker followed by a zstd frame. Guest data
is arbitrary and may begin with the same bytes, so a chunk is taken as
compressed only when its decompressed bytes hash to the chunk id; otherwise
the stored bytes must. Decompression stops at the 4 MiB chunk size, so a
crafted chunk file in a shared repo cannot make a reader allocate more.

Daemon-internal transfer staging repos are created uncompressed.

## Bandwidth limits

A backup can be rate-limited per job and per target repo:

```bash
lv backup snapshot postgres-1 --repo main --bwlimit 50MiB
lv ct backup web --repo main --bwlimit 20MiB
```

```yaml
# daemon config, on the host(s) running the backups
backup_bwlimits:
  main: 100MiB      # per second; "512K" or a byte count also work
```

- **Per job** — `--bwlimit` (the `bwlimit_bytes_per_sec` RPC field).
- **Per target** — `backup_bwlimits:` in the daemon config, by repo name. One
  limit is shared by every backup job that host runs into that repo, so a
  scheduled fan-out over twenty VMs moves at the repo's rate in total, not
  twenty times it. It applies to scheduled backups too, which have no
  per-job limit of their own.

When both are set, the lower wins. A limit is at least 64 KiB/s (a lower
one is refused, or raised to it when it arrives over the RPC); a job that is
cancelled gives back the part of its reservation it did not use, so it does
not hold up the jobs sharing the repo's limit. A limit covers the bytes read from the
disk or container (holes, and regions an incremental inherits from its
parent, are not read and cost nothing) and, for a remote backup, the chunks
sent to the repo's host. For a remote backup the host you call (the repo's
host) hands the lower of the job limit and its own `backup_bwlimits` entry
for the repo to the host that reads the disk. A host on an older release
ignores the field and backs up unlimited. A container replication run pushes
into a backup repo on its target host, so the owner's `backup_bwlimits` entry
for that repo (the schedule's `--target-pool`) paces it too, sharing the
repo's limit with backups into it: the archive it reads and the chunks it
sends. A replication schedule has a limit of its own (`--bwlimit`, see
[Replication bandwidth limit](#replication-bandwidth-limit)). Restores are not
rate-limited.

A target limit is enforced per host: two hosts backing up into the same repo
each get the full limit.

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

A workload's own schedules end with it: `lv rm`, `lv ct rm` and
`lv compose down` remove the deleted VM's per-VM schedules (backup or
replication) and the deleted container's replication schedules. A rebuild, a
compose re-create, a blue-green or snapshot-and-replace cutover and a failed
clone keep them, and a schedule whose VM or container is gone for any other
reason stays dormant until the name comes back. A schedule left behind by a
delete the entry could not attribute (one entered on an older build, or made
with a host certificate) for a workload of a stack that has since been torn
down is removed by the failover lease holder's sweep 24 hours after the
workload was deleted, or after the last run that finished after it, and does
not keep that stack's backup repo registered.

Repos referenced by schedules resolve through the cluster's repo map: a
top-level compose `backup-repos:` block (see below) or daemon config
`backup_repos:` (a flat `name: /path` map). When both define the same name,
daemon config wins.

## Replication schedules

The same scheduler also drives **volume replication** (`backup_schedules`
rows with `type='replication'`). Each run copies every disk of the VM to a
target pool as timestamped, self-contained point-in-time copies, keeping the
newest `keep_replicas` of each disk. A fast-recovery layer, not a backup
replacement, so keep backups too.

**Replica sets.** One run replicates every disk with one run time, so the
replicas a run writes are a set: the root disk first, exactly as before (its
`--incremental` chain, its fallback, its top-level copy for a host on an older
build), then each other disk as a full point-in-time copy. Each disk keeps its
own replica and record, so `keep_replicas` applies per disk and the storage
cost is one replica per disk per kept run. A run whose copy of any disk fails
reports the run failed (`disk.replicated` names the disk), and the disks it
did copy stand. What a run does not copy:

- a disk on shared storage (nfs, ceph, rbd, iscsi, or any pool with a shared
  driver): it is reachable from another host as it is, so it is never copied
  and a promotion reattaches it as-is (below); reported as `disk.replicated`
  with result `skipped` on every run, and not a failure;
- a disk on host-local storage that is not file-based (zfs, lvm): `skipped` the
  same way, and a promotion cannot recover it;
- a cdrom;
- every disk but the root, when the target host runs an older build, which
  promotes the root disk alone (`skipped`, naming the host).

**`--incremental` schedules still copy the other disks in full on every run.**
The incremental chain covers the root disk only; per-disk incremental is a
tracked follow-up that needs verifying on real libvirt first. A VM with large
data disks on an `--incremental` schedule therefore pays a full copy of each
data disk per run, in time, I/O and target storage.

**The VM lock during another disk's copy.** The root disk's run holds the VM's
lock as it always did. Each other disk takes it only for its brief
point-in-time step, never for the bulk copy, so a stop, migrate or hotplug of
the VM waits at most for that step:

- a shut-off VM's disk is copied without the lock (with `-U`, so a start in
  the meantime is not refused), and the copy is kept only if, under the lock
  again, the VM is still shut off and the disk file unchanged (size, mtime,
  inode); otherwise it is discarded and the run reports the disk failed;
- a running VM's backup session is opened under the lock, which is dropped as
  soon as the session's point in time is fixed; the export is read without
  it. A stop during the read aborts the session; the copy then falls back to
  the last resort below and is recorded as not point-in-time, with a
  point-in-time retry owed. While the session runs, libvirt refuses or times
  out every other operation that needs a block job or the disk: a migration,
  a backup (`lv backup snapshot`), a snapshot, `lv replicate-volume`,
  `lv move-volume` of a running VM's disk, `lv resize-disk`, a snapshot delete
  that flattens (`lv snapshot rm`), and a detach of that disk. Retry them once
  the run is done;
- each time a disk's copy takes the lock again, it checks that the VM is
  still this host's and its domain still defined here; if not (it migrated,
  moved or was deleted meanwhile) nothing more of it is copied in that run,
  not even by the last resort;
- the external-snapshot step (skipped until the `pit_overlay` release
  feature) keeps the lock throughout, as its overlay must not meet a move.

Each disk's copy is point-in-time on its own; the disks of a running VM are
copied one after another, so the set is not one instant across disks (a
shut-off VM's set is). A guest volume that spans disks (LVM or md across
disks) is therefore not crash-consistent across them.

**How a full replica is copied.** A full (non-incremental) replica — and the
full copy an `--incremental` run falls back to when its session fails — is made
by the strongest method the host has, tried in this order:

1. **Shut-off VM:** a plain `qemu-img convert` of the disk, *without* `-U`.
   "Shut off" is what libvirt reports, whatever state the VM's record is in (a
   VM in `error` whose domain is down is copied this way). If a qemu does hold
   the image, its lock fails the copy rather than letting it read a changing
   image. A paused or pm-suspended VM is not shut off (qemu still holds its
   image) and takes the steps below.
2. **Backup session:** a full pull-mode backup of the running disk (the same
   machinery backups and `--incremental` use, with no checkpoint, so no
   incremental chain is touched). Point-in-time and crash-consistent.
3. **External snapshot:** only on a host that holds the `pit_overlay`
   release feature — the cluster-wide promise that every host serving the
   pool understands the overlay this step leaves (see "Older builds" below).
   It is a feature of the release token `release_2026_11_v1`
   ([upgrades.md](upgrades.md)): until that token has latched on every host
   this step is skipped and the copy goes on to step 4, exactly as before,
   with no refusal and nothing recorded. The first overlay after the latch
   records that `pit_overlay` is used — a replicated row every host must hold
   before the overlay is made — and from then on a rollback below the release
   quarantines (`lv cluster upgrade-status` lists it). A copy that could not
   make an overlay here anyway (no running domain, a disk on tmpfs or a block
   device) records nothing. When no session opens (an older libvirt, a failed
   job), and only for a VM libvirt reports running or paused, an external
   disk-only snapshot moves the guest's writes onto an overlay — quiesced
   through the guest agent when one answers, otherwise crash-consistent — the
   now-frozen disk file is copied, and the overlay is committed back (active
   block-commit and pivot; a commit job already running is resumed, and a
   pivot that keeps failing is aborted so no job is left behind). Still
   point-in-time. The overlay is `.<disk file>.lv-pit` beside the disk, on the
   same pool, so a failover target on shared storage sees it too. It is never
   placed where it would not survive: a disk that is not a regular file (a
   `/dev` block device, whose directory is devtmpfs) or a pool directory on
   tmpfs takes the next step instead, because a reboot or a failover would
   lose the overlay and the guest's writes in it.

   **Never delete a `.lv-pit` file.** While one exists it may hold the
   guest's newest writes. It is bound to the exact disk file it was taken of:
   - before the snapshot, a new random token is written into an extended
     attribute of the disk file (`user.litevirt.pit_window`) and synced. A
     copy or restore of the file (`cp -p`, `rsync -a` without `-X`) does not
     carry it, and a new file at the same path does not have it;
   - a sidecar beside the overlay (`.<disk file>.lv-pit.id`) records the VM,
     its disk, that token, and the file's inode, size and modification time —
     not the device number, which differs between hosts mounting one NFS
     export and can change across a remount or reboot.

   On a filesystem without user extended attributes there is no token, and
   the size and time bounds below decide alone. Local ext4, XFS, btrfs and
   ZFS datasets, and tmpfs, have them; NFS has them only at version 4.2 (Linux
   5.9 or later on both ends), so an export mounted at 4.1 or 3 has none. A
   host that cannot read a token another host recorded (it mounts the export
   at an older version) holds the VM rather than guess. zfs zvols, lvm-thin,
   ceph and iscsi disks are block devices, which take no overlay at all.

   The sidecar is written, and synced, before anything relies on it, and it
   follows the commit: `committing` before the commit's first write to the
   disk (every attempt rewrites it, and a long commit rewrites it every ten
   minutes while it runs); the disk as each attempt left it, failed or not,
   once the attempt ends; `pivoting` just before a live commit pivots the VM
   onto the disk; and `committed` once a recorded pivot has landed. If a
   record cannot be written, the step it records does not happen: no commit
   starts, no pivot is made, and the window stays open, reported, and is
   retried. All the times compared are the filesystem's own (the disk's and
   the sidecar's modification times). On a local filesystem and on NFS, where
   the server sets both, a server clock that disagrees with the hosts' does
   not matter. On a cluster filesystem whose clients set file times (CephFS,
   GFS2, OCFS2) a client's clock goes into them: there, keep the hosts' clocks
   within a minute of each other, because the twelve-minute bound below is
   only as good as the agreement between the host that recorded a commit and
   the one that later writes the disk. If the commit fails, the VM keeps
   running on the overlay and a `disk.pit_overlay_stranded` event and a
   `replication.pit_overlay_stranded` notification say so.

   Every later copy (replication, `lv replicate-volume`), move
   (`lv move-volume`, live or offline), migration, backup, clone, `lv start`,
   reconfigure, in-place restore, `lv rm` of a disk it keeps, failover restart
   and the daemon's start-up sweep settles the overlay first. It judges it
   against the disk as it is now — a **verdict**:
   - **matches**: the disk is the file the overlay was taken of, unchanged.
     It is committed (`qemu-img commit`, without `-U`, pointing the overlay at
     the disk by its name beside it if another host took it under another
     mount path), the persistent definition is pointed back at the disk, and
     only then is the overlay removed. A running VM on the overlay is
     committed live instead;
   - **half-written**: a commit began and the disk is the file it was writing
     — same token, no smaller and no older than when the overlay was taken,
     and either exactly as the last attempt left it (nothing writes the disk
     after a failed attempt, so a restore over it in place, which keeps its
     inode and token, is caught) or, if the daemon died mid-attempt, written
     no later than twelve minutes after the daemon last recorded the attempt.
     The commit is finished the same way: only that makes the disk whole;
   - **pivoted**: the overlay is already in the disk — the commit was
     recorded, or a pivot was recorded and the VM runs on its disk, written no
     later than twelve minutes after that record (later, something else may
     have started the VM there: it is marked diverged and held). It is
     removed, never committed again over the guest's newer writes;
   - **unknown**: anything else — the overlay is another VM's or unbound; the
     disk was replaced, restored, re-created or written since; the token is
     missing or another; the VM was found running on its disk without the
     overlay (it is then marked so, and never committed automatically after);
     or a pivot was under way and, with the VM off, it cannot be told whether
     it landed. It is never committed (that could write stale blocks over
     newer data) and never dropped (it may hold the guest's writes): the VM is
     **held** — not started or defined on the bare disk, and the operation
     refused. If libvirt cannot say whether the VM runs, nothing is touched
     and the operation is refused until it can.

   A hold is a `pit_overlay.held` health condition per disk (a warning:
   `lv health` is degraded while it stands), and `lv inspect <vm>` shows it as
   `pitOverlayHeld`, read from that condition. A `disk.pit_overlay_held` event
   and a `replication.pit_overlay_held` notification name both files, the
   verdict and what to do for it — once when the hold begins, then at most
   daily. It resolves by itself once a later settle can commit the overlay or
   finds it merged, or when the disk is deleted. Only a host that sees the
   disk resolves it: one where a shared pool is not mounted leaves it open.

   An admin decides with `lv resolve-pit-overlay <vm> <disk>`, which is admin
   only and audited. Without `--confirm` it does nothing, and answers even
   while the VM runs: it prints the verdict, the disk's and the overlay's
   identity then and now, the overlay's backing file, and what each action
   would do. For a pivot that was under way with the VM off, it compares the
   two files' times: a disk written after the overlay means the pivot landed
   (discard), an overlay written last means it did not (commit). Carrying an
   action out (`--confirm`) needs the VM stopped.
   - `--commit --confirm` writes the overlay into the disk, through the same
     checks as every automatic commit, and is refused unless the verdict is
     matches or half-written. `--force-commit` overrides the verdict, for
     experts who have checked both files: if the disk is not what the overlay
     was taken of, it overwrites newer data with older blocks. Even forced, an
     overlay whose backing file is another file (another name, or a file of
     the same name in another directory of this host) is never pointed at
     this disk. An overlay already in the disk (verdict pivoted, or a
     committed binding) is refused even forced: committing it again writes
     its old blocks over everything the guest wrote since. Only
     `--overwrite-newer-writes` overrides that; `lv` prints the consequence
     and, without the flag, asks for a typed `yes` on a terminal before it
     sends anything. A committed overlay that has been written since (a VM
     ran on it after the commit) is refused the same way, but neither file is
     then the whole story: the disk and the overlay each hold writes the
     other lacks, and a discard needs `--accept-torn-disk`.
   - `--discard --confirm` deletes the overlay and its writes. Of a disk a
     commit had begun writing (half-written, or unknown after a commit began)
     it is refused unless `--accept-torn-disk` is given: without the overlay
     that disk is inconsistent. To start over from a backup or a replica
     instead, discard the overlay first (`--discard --accept-torn-disk`) and
     only then restore the disk — a restore over it in place with the overlay
     still beside it is not mistaken for the disk (the end record catches it),
     but the VM stays held.
     `lv backup restore-from --repo <repo> --vm <vm> --disk <disk> --timestamp <timestamp> --in-place`
     (the timestamp from `lv backup repo ls <repo>`) does both: once the
     restored image has been placed over the disk, the VM's definition is
     pointed back at the restored disk, then an overlay that holds the VM is
     set aside (kept, as `.<disk file>.lv-pit.orphan-<time>`), and the hold
     clears. A restore that fails before (a missing chunk, a cancel), a
     placement that fails, or a crash between the placement and the
     set-aside leaves the overlay beside the disk and the VM held: the
     overlay was taken of the file the restore replaced, so it is never
     committed into the restored one; re-run the restore to finish. If the
     repoint or the set-aside itself fails after the placement, the restore
     says so — the disk is restored, the VM stays held, re-run the restore or
     resolve the overlay — instead of "restore complete". A stopped VM whose
     definition still names an overlay that a restore by an earlier build set
     aside without the repoint is pointed back at the disk by its next start,
     move or copy, with a `disk.pit_definition_repointed` event; the
     set-aside overlay is kept. That happens only on proof of the set-aside:
     the overlay and its binding are both gone (not merely unreadable — an
     I/O or stale-handle error proves nothing) and a
     `.<disk file>.lv-pit.orphan-*` of the disk's current window lies beside
     it: when the disk carries a window token (`user.litevirt.pit_window`),
     only an orphan whose `.id` recorded that token counts, so an older
     window's orphan says nothing about a later one; without user xattrs
     nothing counts. An overlay moved
     anywhere else is not taken as set aside: the definition is left naming
     it and the start fails, naming the missing file — put the overlay back,
     then resolve it. `lv resolve-pit-overlay --discard` and a forced
     `--commit` likewise point the definition at the disk before the overlay
     goes, so a failure or a crash between the two keeps the overlay.

   When a disk is deleted (`lv rm`, rebuild), its overlay and sidecar are
   deleted with it. An import that finds an overlay where its new disk goes
   renames it `.<disk file>.lv-pit.orphan-<time>` (never over an earlier one
   or its sidecar), says where the file it was taken of went if the import
   moved that aside too, and reports it (`disk.pit_overlay_set_aside`);
   inspect both, then remove them with `lv pit-overlays rm`.

   A set-aside overlay is kept when its disk is deleted or moved away too.
   Only an orphan whose binding records the VM's own uuid, or none, counts as
   evidence for a disk: a VM re-created at the same path does not inherit an
   earlier VM's.

   `lv pit-overlays ls [--host <h>] [--vm <vm>]` lists the set-aside overlays
   of a host's VMs, answered on each VM's host, with their size and why one
   is in use; with `--host`, also the DETACHED ones in that host's file pool
   directories (no live disk where they were set aside; owner from their
   binding; listed only to a reader at the cluster root). Each caller sees
   only the VMs it may read. `lv pit-overlays rm <vm> <disk> <name>` removes
   one and its binding, on the VM's host, and
   `lv pit-overlays rm --host <h> --path <path>` a detached one (admin,
   audited as the operator who ran it, asks first unless `--yes`; event
   `disk.pit_overlay_removed`). It is refused while the overlay is in use: it
   is the set-aside evidence of the disk's current window (above), a VM disk
   references it, a domain defined on that host names it or backs on it
   through its disks' qcow2 chains (domains on other hosts sharing the pool,
   and image files no domain or VM disk uses, are not asked), the disk is held on its overlay, a live
   disk sits where a detached one was set aside, or anything about it cannot
   be read.
   The start-up sweep waits until the host's replica is trusted (caught up
   with a peer, or the cluster's only host), and on a shared pool touches only
   disks of VMs this host owns and has defined (others are left to their owner
   and reported as `disk.pit_overlay_left`).
4. **Last resort:** when neither 2 nor 3 can be made, the copy is what earlier
   builds always made — `qemu-img convert -U` reading the image the guest has
   open. That copy is **not point-in-time** (it is smeared over however long it
   ran, and a guest restored from it may need repair). It is still made, but
   the replica's record says `not_point_in_time`, a
   `disk.replica_not_point_in_time` event names the reason on every such copy,
   and a `replication.not_point_in_time` notification once per disk — again at
   most daily while its copies stay not point-in-time, and afresh after a
   point-in-time copy of it — and the scheduler retries a point-in-time copy
   at its next tick (a minute later, not a full interval). That retry makes a
   point-in-time copy or nothing; the schedule's own next run may make another
   `-U` copy if the cause persists.

The `disk.replicated` event names the method used. zfs, ceph and btrfs pools
replicated natively use their own snapshots and are point-in-time.

A replica is also **published by rename**. The copy lands in a dotted
temp sibling and is renamed into its final name only once it has completed
and is non-empty — never over a file already there — so an interrupted run
cannot leave a truncated file promotion would select.

A run on a host that may not act as the VM's owner now is **skipped, not
failed**. A host coming back from a fence or a partition still sees the VM's
row on itself until it has caught up, though the VM may have been promoted on
another host meanwhile. While it warms up, has lost its execution gate, is not
an active member in its own view, or holds an owner-epoch marker ahead of the
row, its scheduler logs `schedule run skipped` at info, raises no failure,
and writes nothing to the schedule row: `LAST RUN` and `LAST ERR` stay the
owner's. Skips that go on for 15 minutes (the host is still fenced, or its
view never catches up) raise `replication.skipped` (warn), at most hourly
while they continue: if the VM still runs there, no replica is being taken.
A run that is not skipped ends that episode.

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

When a schedule is removed (`lv replication schedule rm`), or its VM deleted
(`lv rm`), its replicas go too: each host removes, hourly, the recorded
replicas in its own pools whose schedule or VM was removed more than a day
ago. A schedule added again, or a VM re-created, within that day keeps them.
A replica a VM disk references, one a set-aside disk copy backs on, and a file
with no record are never removed. The removal also retires the incremental
chain's anchor (the `replication_checkpoints` row) that no remaining schedule
uses, and `lv rm` retires all of the VM's; the failover lease holder retires,
hourly, any other row no schedule uses that has not advanced for a day.
`lv replication checkpoints ls [--vm <vm>]` lists the rows, and
`lv replication checkpoints rm <vm> --target-pool <pool>` removes one (admin,
audited), refused while a live replication schedule uses it; it runs on the
VM's host, which drops the anchor's bitmap, and prints what became of it. Only
records in the replica area are removed this way, not top-level
`<vm>-<disk>-<time>.<ext>` files.

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

### Replication bandwidth limit

```bash
lv replication schedule add web-1 --cron "*/15 * * * *" \
    --target-pool dr --target-host hostB --bwlimit 50MiB
lv replication schedule ls        # RATE column; "-" is unlimited
```

- `--bwlimit` takes the same values as `lv backup snapshot --bwlimit` (`50MiB`,
  `512K`, a byte count per second) and is at least 64 KiB/s.
- The limit is per schedule and per source host, shared: every run of the
  schedule on one host (a pool, project or cluster schedule's VMs, two runs at
  once) moves at the limit in total.
- It paces every byte a run sends to its target: the full copy, the
  incremental extents, and the top-level copy written for hosts on an older
  build.
- A container schedule's sends are also paced by the owner's `backup_bwlimits`
  entry for its repo; the lower limit wins.
- Re-adding a schedule without `--bwlimit` keeps its stored limit; `--bwlimit 0`
  removes it. Removing the schedule removes its limit, and a schedule added
  again later without `--bwlimit` starts unlimited.
- A daemon on an older build ignores `--bwlimit`: the command then fails, saying
  the schedule was added without a limit. Re-run it once every host is
  upgraded. A changed limit takes
  effect from the next run; a run already going keeps the limit it started
  with.
- A replication into a pool on the source host itself, or into a shared pool
  it writes directly, is not paced.
- A low limit makes each run take longer, so the newest replica is older when
  a failover promotes it.
- The limit is the `replication_rate` release feature: it is refused until
  every host runs this release (`lv cluster upgrade-status`).

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
lv replication promote web-1 --accept-not-point-in-time   # a replica recorded as not point-in-time
```

A split-brain guard refuses to take over the name unless the original's host
is proven fenced, or proven off after it was removed: its newest fence is
proof-grade (an IPMI power-off, or `lv host fence-confirm <host>` once it is
powered off). Any other host may still run it: one fenced without proof
(`lv host fence <host>`), and one removed (`lv host rm`) or not yet known
here, since removing a host does not power it off (`--force` overrides). The same action is on the VM detail page
("Promote replica").

**Every disk with a replica is recovered**, manual or automatic: the root from
the chosen replica, and each other disk from the replica of the same run, or,
when that run did not copy it, its newest replica from before it (never a
newer one: a root replica named with `--replica` sets the point in time). A
root replica with no run time in its name (an admin-named file) takes no
other disk's replica at all: its file's time is not its data's time, so the
promotion is partial.
Automatic promotion takes another disk's replica only within the same age
bound as the root's (below); an older one is not attached. A not
point-in-time replica of another disk is taken only where the root's would be
(with `--accept-not-point-in-time`, or the VM's label for automatic
promotion). Each disk comes back on its own bus and controller, at its stored
target device unless that collides with the root's (`vda` on virtio) or an
earlier disk's, in which case it gets the next free one.

A disk on **shared storage** is never rebuilt from a replica. A takeover
promotion reattaches it as-is, at its own path, with its row unchanged, only
when its old owner provably no longer writes it:

- when the promoting host itself verified a proof-grade fence of the old
  owner for this promotion: the promotion carries a proof (failover's, under
  enforcement), `enforcement.shared_storage_fence` is enforced, and the
  proof's fence is proof-grade (IPMI, or `lv host fence-confirm`);
- failover's own promotion without such a verified fence: never — a
  best-effort fence can leave a partitioned host's qemu writing the disk;
- any other promotion — an operator's, whether the CLI reaches the replica
  host directly or through another node, local-root `lv`, or a relay from a
  coordinator on an older build — only when the disk's own row names the
  promoting host, or its owner is fenced, removed or no longer a member
  **and proven powered off**: the newest fence on record for it is
  proof-grade (a verified IPMI power-off, or `lv host fence-confirm`), the
  same assurance the shared-storage fence and recovery claims trust. For a
  host that is no longer a member, only a fence of its last life counts: one
  recorded before it was last re-added or returned to service is about an
  earlier life of the name and proves nothing. A host
  recorded fenced by an SSH, watchdog or best-effort fence, or with no fence
  record, may still be writing the disk, and so may a removed one:
  `lv host rm --force` asks for no fence, and a host whose daemon died may
  still be running its qemu. Such a disk is left unattached and the promotion reported
  partial. Not merely not active either: maintenance, offline or active is
  not enough, and `--force` does not change any of this;
- an owner whose state or fence record cannot be read, or a disk whose row
  names no host on a VM the promoting host already owns: never.

The owner judged is the host the **disk's own row** names, and the VM's owner
too when that is another host: each must pass. After a partial promotion the
VM belongs to the promoting host while its shared disk's row still names the
old owner, so a second promotion of the same VM is judged by that old owner,
exactly as the first was; and a row left naming a host the VM has since left
does not excuse the host the VM was running on.

The remedy is to prove the owner off: once it is powered off,
`lv host fence-confirm <host>` (a removed host is accepted, see
docs/migration-failover.md), or an IPMI fence. A promotion made after that
reattaches the disk, and so does the next start of a VM already promoted
without it: `lv restart <vm>`. Confirming a removed host also lets the failover
coordinator, with recovery claims enforced, recover every workload still
recorded on it, possibly before your promotion runs. A node still on an older
build answers "not found" for a removed host, so set `LV_HOST` to an upgraded
node. Re-running `lv replication promote <vm> --force` over a partial
promotion is not a remedy: it is refused. The promoted VM runs from live
disks that promotion built and has written to them since, which no replica on
that host holds, so a same-name promotion over a VM whose disk rows name such
a live disk there is refused, `--force` or not, rather than rebuild them from
a replica and discard those writes. To have both, promote the replica under
another name (`--new-name`). Every refusal of a promotion comes before the
domain already defined under the name is destroyed: a `--force` promotion
replaces that domain only once nothing is left to refuse.

A partial promotion leaves the unattached shared disk's row naming its old
owner, and every domain built from a VM's disk rows judges such a row the
same way: the reconciler's start (onboot, or the restart of a VM whose domain
is gone), an operator's `lv start` or `lv restart` of a VM with a shared disk
whose row names another host (the domain is redefined from the rows first),
and a redefine by `lv update` or a device hot-plug. A shared disk whose row
names another host is attached only when that host is proven powered off,
as above; otherwise the domain is built without it, the VM starts anyway, and
the VM records a `vm.shared_disk_withheld` event, a `vm.shared_disk_withheld`
notification and a durable condition (`vm.shared_disk_withheld`, evaluator
`shared_disk_start`) that `lv inspect <vm>` shows as `sharedDiskWithheld`
until a build withholds nothing. It names each disk, why, and the remedy:
`lv host fence-confirm <host>` once the host is powered off, then
`lv restart <vm>`. A disk whose row names this host or no host, or that is
not on shared storage, is attached as before. A withheld boot disk (the disk
named `root`, or the one at `vda`, `sda` or `hda`) is different: a domain
without it boots nothing, so the VM is not started at all until its host is
proven off (a recovery retries; a local start records the VM in error with
the same text, and `lv start` after the confirmation builds it again). An
operator's `lv start` of a VM that is already running leaves its definition
alone. Leaving a disk out can change how the guest numbers the disks after it
(a domain built from the rows gives them consecutive devices), so a guest
that mounts by `/dev/vdX` rather than by label or UUID may find a different
filesystem there until the disk is attached again.

Such a row keeps naming its host through every move of the VM until that
host is proven off: a failover reschedule, a migration's ownership commit,
failover's move of a stopped VM, and an owner repair re-point every other
disk row to the VM's new host, but not a shared disk's row that names a
third host — neither the one the VM leaves nor the one it goes to — that is
not proven off. Re-pointed, it would read as the new host's own at the next
start and be attached unjudged. `lv doctor repair-owner` re-homes such a row
only when the host it names is active, reachable, and attests that no domain
defined on it, running or not, uses the disk — the case of a migration whose
ownership commit declined, whose rows name the source, still in service. The
host attests under its start lock and records the release, and from then on
refuses to start any domain using that disk until the VM's own row for it
names that host again (the VM moved back). Otherwise — the host fenced,
offline, removed, unreachable, on a build without the attestation, or with a
domain still using the disk — repair-owner refuses and names
`lv host fence-confirm <host>`. A `move-volume` of such a disk is refused
the same way: copying it while its host may still write it would move a
disk two hosts write.

"Shared" here is one definition, used by this rule and by every shared-disk
fence check (failover's decision, the promoting host's, the host that starts
a rescheduled VM, and failover's move of a stopped VM), and by the
point-in-time overlay sweep: a disk whose storage type is nfs, ceph, rbd or
iscsi, or whose pool has a shared driver on its own host or the deciding
host.

It must also be reachable from the promoting host within a few seconds (a
hung NFS mount is given up on, and the root is promoted without it). A
renamed promotion never attaches it: the disk belongs to the original VM.
Whenever it is not attached the VM is promoted exactly as main promoted it,
and the partial report names it as shared at its path, with why, and either
the remedy above (`lv host fence-confirm <host>` once it is powered off, then
`lv restart <vm>`, and not to re-run the promotion over this one), with the
confirmation's side effect: it may also let the failover coordinator recover
every workload still recorded on that host, or, for a
renamed promotion, that it belongs to the original and must not be attached
to the copy.

The `vm.promoted` event is the recovery manifest: every disk and the replica
it came from, that it was reattached as-is, or why it was not recovered.

A promotion never fails for a disk it cannot recover. Automatic promotion
recovers at least the root, as it always did. A domain that fails to define
or start with the other disks is retried with the root alone. When the set is
incomplete the VM is marked **partial**:

- the set is incomplete when a disk has no replica (or none within the bound),
  is on storage replication does not copy, has a replica that could not be
  built, failed the domain, or comes from an earlier run than the root's;
- a `vm.promoted_partial` event and a `replication.promoted_partial`
  notification name each such disk and where its real disk is (on the failed
  host, whose record still names it, or on shared storage);
- the marker is durable: the health condition `vm.promoted_partial` (evaluator
  `replica_set`), shown by `lv inspect <vm>` as `promotedPartial` until a later
  promotion recovers the whole set or the VM is deleted (a VM re-created
  under the name never inherits it). `lv health resolve` does not resolve
  `vm.promoted_partial`.

A disk not recovered is not attached; attach or restore it once its host is
back. Each live disk a promotion builds is a new file in the target pool,
`<vm>-promoted-<replica stem>-<random>.qcow2`, under a name no file has had:
the name an earlier build used, without the random part, can be the missing
base of a disk kept by `lv rm --keep-disks` after an earlier promotion from
the same replica, and a file built there would become that kept disk's base.
A promotion never refuses for a kept disk, so failover does not wait on
`kept-disks.json`, and a file already at any name is never replaced. The
name is recorded on the host before the file is created
(`<data_dir>/promote-disks/<vm>.json`), so a promotion retried after a crash
or a failure, with the same proof, a new one or none, reuses the live disk the
earlier attempt built from the same replica instead of building another
beside it. The record belongs to one promotion in progress: it is read only
while that promotion's promote marker is there (written just before the
domain starts), and is removed, before the marker, once the attempt ends. A
promotion that starts with no marker drops it, and a file an earlier attempt
built is then left alone, as is one built from another replica. A recorded
file is never reused when a disk row, a kept-disk note or `kept-disks.json`
names it; when the kept-disk records cannot be read, a fresh live disk is
built instead, so failover does not wait on them. A crash-recovered promotion counts
another disk only when the domain it adopts has that disk.

After a successful automatic promotion the failover coordinator records the
disks the VM ran on, on the failed host — the real, newer data of every disk —
as it does for a reschedule (`vm.failover.disk_stranded`, condition
`vm_disk_stranded`): that host sets them aside when it returns and keeps them
while the VM exists (`lv host superseded-disks <host>`).

During a rolling upgrade a promotion executed by a host on an older build
recovers the root disk alone, as that build always did.

**Automatic promotion** (`--auto-promote` on the schedule): after the failover
coordinator **confirms a fence**, it promotes the freshest replica for opted-in
VMs onto a healthy peer (so a VM on lost local storage resumes), falling back to
a bare reschedule on failure. Default off. Promotion uses the newest
point-in-time replica, which is lagging by up to one schedule interval. Enable
only where a small lag window is acceptable.

**Replicas that are not point-in-time** (the last-resort copy above) are the
last choice:

- Automatic promotion never uses one while any point-in-time replica of the
  VM exists, even an older one.
- When a VM's only replicas are not point-in-time (or its point-in-time ones
  are all too old and a newer one is not point-in-time), automatic promotion
  **holds the VM down** by default: the replica is left untouched, and a
  `vm.failover.held` event and a `replication.promote_held` notification give
  the reason and the exact commands that promote it by hand: when the failed
  host is not proven powered off, `lv host fence-confirm <host>` (once it is
  off) and then the promote; when it is, the promote alone. A VM with any
  disk that is not on shared storage is not rescheduled either — its record
  stays on its failed host, `lv inspect <vm>` shows the hold as `failoverHeld`,
  and the printed commands work as printed, in order. A VM whose disks are all on shared
  storage is restarted from its own disk by its `on_host_failure` policy, as
  before (a `vm.failover.restart_shared` event says so).
- A VM can opt in, one VM at a time, to automatic promotion of such a replica
  when no point-in-time one exists: give it the label
  `litevirt.auto_promote_not_point_in_time=true` in its spec's `labels`. There is
  no cluster-wide switch, and a build that does not know the label ignores it
  (default off). When it fires, a `vm.promoted_not_point_in_time` event and a
  `replication.promoted_not_point_in_time` notification say a NOT point-in-time
  copy was promoted.
- A manual `lv replication promote` of one is refused with a warning unless
  `--accept-not-point-in-time` is given, whatever the label says.

During a rolling upgrade, a host on an older build does not know the mark. A
failover it coordinates promotes the newest replica as before when the replica
is on that host or another older one; when the replica host is upgraded, that
host refuses the marked replica and holds the VM with the same event and
notification, but the older coordinator then falls back to its reschedule. A
replica sent to a receiver on an older build is recorded without the mark, and
the `disk.replica_not_point_in_time` event says so. An `lv` older than the
daemon has no `--accept-not-point-in-time` flag: upgrade it to promote a marked
replica by hand. A `lv replicate-volume` copy made with `-U` is recorded as not
point-in-time too, and promoting it by name needs the same flag. On shared
storage that copy's mark is also kept in its host's replicated pool record.
Each host rewrites only its own records, so no peer on an older build can drop
a mark; a host rolled back to an older build drops the marks of the copies it
recorded (local and replicated) the next time it rewrites those records.

**Older builds and `.lv-pit` overlays.** A build older than this one knows
nothing of overlays: one that started a VM whose window was open would start
it on the bare disk and drop the window's writes. So no overlay is made until
every host serving the pool holds the `pit_overlay` release feature: until
then the external-snapshot step is skipped, which refuses nothing earlier
builds did. A host below the feature — one whose release token has not
latched yet — settles no overlay it finds automatically, not even one it
could verify: it holds the VM (the `pit_overlay.held` condition says why, and
gives the full verdict) rather than start it on that disk, and a binding
written by a newer build than itself is never settled either. An admin can
still decide such a hold with `lv resolve-pit-overlay` on its verdict.

Once `pit_overlay` is used, a rollback below the release quarantines that
host (WAL quarantine: it emits no replicated writes), and every rollback to a
build older than `release_2026_11_v1` quarantines anyway. Peers then record
it as isolated, and while `pit_overlay` is in use the failover coordinator restarts
no VM on a host that is isolated, whose own Ping reports it WAL-quarantined,
or that does not answer (all candidates are asked at once at recovery time,
under one two-second deadline, so from the rollback's first answer, before
the isolation is recorded; a host that did not answer is not asked again for
ten seconds). A host the coordinator cannot reach therefore takes no VM
recovery while `pit_overlay` is in use. A VM whose host died mid window is restarted on
an upgraded host, which commits the overlay first.

Once `pit_overlay` has been used, `lv host upgrade` (and a host's pull
self-upgrade) refuses to install a binary that does not know it — a build
older than `release_2026_11_v1`, asked with `litevirt --release-features` —
while any overlay exists on that host (in the data directory's `disks/`, a
pool directory, or the directory of any disk recorded on it), naming the
files: settle each (start or replicate its VM on this build, or `lv
resolve-pit-overlay`) or drain the host first. A directory that does not
answer within ten seconds (a hung mount) refuses it too, naming the
directory: fix the mount and retry. `--force` overrides either, and is then
logged and audited (`host.upgrade.force_pit_overlay`) with the overlays it
skipped. `lv host preflight-upgrade` lists them as `pit-overlay-present` (and
an unanswering directory as `pit-overlay-unscanned`). Before `pit_overlay` is
used nothing is scanned, and an upgrade to a build that knows it is never
scanned or refused for them. A host rolled back some
other way (a package manager, a copied binary) is not stopped, so then check
by hand: `find <dir> -name '.*.lv-pit'` over every pool directory and
`disks/` must find none, and keep the host drained, because such a build has
no hold of its own and would start a VM it still owns on the bare disk. An older build shows the `pit_overlay.held`
condition in `lv health` like any other, but never raises or resolves it, and
an `lv` older than the daemon has none of `--force-commit`,
`--accept-torn-disk` or `--overwrite-newer-writes`: upgrade it to resolve a
hold.

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

### Container replication

`lv replication schedule add <container> --container` replicates a container
the way a VM schedule replicates a disk. A container has no storage pool, so
`--target-host` names the peer that holds the replica and `--target-pool` the
backup repo on it: a logical repo name that peer has in its `backup_repos`
config (or a repo registered cluster-wide). A run is paced by the owner's
`backup_bwlimits` entry for that repo name, if it has one (see
[Bandwidth limits](#bandwidth-limits)); an entry on the target host does not
apply to it.

```bash
lv replication schedule add web --container --cron "0 * * * *" \
    --target-host hostB --target-pool dr --keep 3 --auto-promote
lv replication schedule ls            # a container shows as ct:web
lv replication schedule rm web --container --target-pool dr
lv replication replicas web --host hostB --target-pool dr   # what hostB holds
```

**Release gate.** Container replication is release feature
`container_replication` of the release token (`lv cluster upgrade-status`): a
schedule is created, a run replicates and a schedule switches direction only
once every host runs a release that has it (the release token has latched).
Until then each is refused with "the cluster upgrade must finish first
(container_replication needs release_2026_11_v1)", naming the hosts still to
upgrade; a switch that is refused is reported like any other switch that could
not be made. The first schedule marks the feature used, so from then on a
rollback below the release quarantines (docs/upgrades.md, "Rolling back after a
release token latched"). An older daemon would otherwise skip a
container schedule without a word, keep its replicas without pruning them, or
take its name for a VM's. The CLI sends a container schedule's key
(`@ct:<project>/<name>`), never the bare name, so even an older daemon that is
asked to remove one never matches a VM's schedule.

A schedule is keyed by the container's **project and name**: a container name is
unique per project, so the same name in two projects is two schedules, and
adding one never replaces the other's. `--project-name` picks the container when
the name exists in more than one project.

**Where a replica lives.** Not among backups: in a **replica namespace** of
the repo, a chunk store of its own at `<repo>/.ct-replicas/<project>`. Backup
retention, `keep_last`, `lv backup repo prune` and a restore's search for a
backup never see a replica, and a replica never counts as one. A peer on an
older release cannot resolve the namespace, so it refuses the push rather than
store a replica among its backups. The namespace's chunks are reclaimed by its
own GC after each run that removes a replica.

**A run.** Each run archives the container on its host, frozen while it is
archived (a freeze that is unavailable leaves the replica crash-consistent, as
for a backup), and streams it over the chunk store container backups,
migrations and failover relocations already use, so only chunks the peer does
not hold cross the wire. A replica archive is cut into **content-defined
chunks**: a chunk ends where the bytes say so, not every 4 MiB, so a file that
grew in the middle of the rootfs (which shifts every later byte of the tar)
changes only the chunks around it, and the next replica sends those and little
else. The archive is written in name order with each member's modification
time and no access or change time, and a restore, migrate or promotion lays
every member down with its archived modification time, so an unchanged tree
archives to the same bytes before and after a move. (GNU tar sorts with
`--sort=name` from 1.28; on an older one the export hands tar the same order as
a list, so no export fails where it did not before.) (A container whose files
did change sends those; the first run into a repo that holds no replica of the
container sends it whole.) Only the container's owner pushes: the run refuses on a host that has
self-fenced, is not an active member, or whose owner-epoch marker is ahead of
its own row, and the **target** checks again against its own view, refusing a
replica from a host it knows is fenced. When the container's row there is on
another host, is another placement, or has moved past the replica's owner epoch,
the push is refused too, as "moving": a warning, since the owner's next run
lands. A stale owner coming back from a partition therefore adds nothing that
could later be promoted.

**Keeping the newest copy.** Each replica records the segment of the
container's history it was taken in: the host and the container's **placement
id**, a random id minted every time the container's row is put on a host (a
create, clone, restore, migrate, relocation or re-key), so a container that
returns to a host it ran on before is a new segment there. It records when it
was **captured** (after the freeze), as opposed to its name, which is only the
scheduler's tick. And it records the points of earlier history its data
descends from (a restore records the archive it laid down; a migrate carries its
source's chain), each by capture instant. A replica of the same placement is a
snapshot of one linear history, so `--keep` trims the oldest of those, and never
a set-aside one or one whose capture is not known. A replica of another
placement is removed only when the new replica's data provably descends from a
point of that placement captured at or after it. Anything else is **set
aside**: kept, never pruned by the schedule,
never promoted by failover, reported once (`replication.replica_set_aside`, warn,
and an audit row), and listed by `lv replication replicas` with the reason. That
is what a failover that did not restore from the replica leaves behind (the
container came back from its image or a backup, or on a host placement chose
over the replica host): the set-aside replica may be the newest copy of the
data. An operator can restore it, stopped, as the container, or remove it;
removal asks first. It may be entered on any node. A restore is refused unless
each of these positively says it holds and sees no live copy of the container,
so there is never a second runnable copy:

- the replica host;
- the host the replica was taken on, which is asked even when the replica host
  has no row of the container at all;
- every host the replica host holds a row of the container for, deleted rows
  included;
- every other member of the cluster that has not been removed, voter or not.

Each host answers from its own rows and from its own runtime. A live row of the
container, on any host, refuses the restore. So does a container of that name
in a host's runtime with no live row of it: an orphaned runtime
(`ct_orphan_runtime`, see [diagnostics.md](diagnostics.md)), left by a stale
delete or an interrupted create or migrate, which may hold newer data than the
replica. Deal with that copy first; do not discard it unread. Runtime names are
per host, not per project, so a container of that name under another project's
live row on the same host is that project's, unless the container's own owner
record says it is this project's (then it is an orphan of ours under a stale
row, and refuses), or the record cannot be read (then the host cannot vouch). A
host whose lxc tooling is gone but which still holds the container's directory
on disk holds a copy too, and refuses, and so does a host with tooling holding
a directory of that name that `lxc-ls` does not list (no config). Each host
answers for its containers only: it lists them and reads the one asked about,
so a slow libvirt, an unreadable VM marker or another container's broken probe
neither delays its answer nor stops it from proving absence. A host that cannot
be asked, or whose container listing or reading of that container fails, cannot
vouch: the refusal names the host, and the remedy is to bring it back or remove
it from the cluster (`lv host rm`). That is the cost of the check: while any
one member is unreachable, no replica restore goes through. A host this cluster
has no record of cannot be removed either, so a replica taken on one cannot be
restored until it rejoins. A replica no schedule settles any more (the schedule
was deleted, re-targeted or reversed away) is listed as orphaned and may be
removed too:

```bash
lv replication replicas web --host hostB --target-pool dr
lv replication replicas web --host hostB --target-pool dr --restore 2026-10-10T08:00:00Z
lv replication replicas web --host hostB --target-pool dr --remove 2026-10-10T08:00:00Z
```

A replica older than one the target holds of the same segment, or one a held
replica's data descends from, is refused, so the newer copy is never replaced by
an older one; a replica already held is never written over. The command refuses
a target that is the container's own host, is not active, cannot run
containers, or cannot open the repo's namespace; `--auto-promote` additionally
needs the container to have a host-failure policy (`on_host_failure`), since
failover never moves one without it. `--incremental` is for VM disks and is
refused.

**Reporting.** A run that fails is reported when it starts failing, when the
failure changes (another cause, another target), and when it recovers
(`replication.recovered`); while the same failure continues it is re-notified
at most hourly and writes no further audit row. A target host that is down is a
warning, not an error. The schedule's `LAST ERR` always shows the latest run.

**Promotion.** When a container's host is fenced, the failover coordinator
places a container whose schedule has `--auto-promote` on the replica host when
placement accepts it, and restores the newest replica there that was taken from
the very container row being relocated (its host and placement) and is not set
aside, through the same restore-relocation as a restore from backup: the same
relocation proof, recovery claim and single-use token, so one copy exists at
every moment. It restores the replica unless the newest backup it can reach was
taken in the same placement and captured after it: capture instants are only
ever compared on one host's clock, so a backup taken in another placement, or
whose capture is not known, does not outrank the replica. A replica becomes a live copy only this way or through
`lv replication replicas --restore`; a plain restore or a cold migrate of a
replica is refused.
Like a VM, a replica older than two of the schedule's longest intervals plus an
hour is not promoted automatically; the container then falls back to the
backup or image-recreate path as if there were no replica.

### Reverse replication

After a replicated workload moves onto the host that holds its replica, the
schedule replicates the other way: the host it left becomes the target. Every
path that moves a workload switches it: a promotion from its replica (by
failover or `lv replication promote`), a failover reschedule of a VM, a live,
cold or health-driven migration, a drain, an owner repair (`lv doctor repair-owner`)
or an owner reclaim by the reconciler, and for a container a failover
relocation, a migrate or an owner re-key; and again when the workload moves back
(failback), so the direction follows the workload. The `replication.reversed`
event (and a `replication.reverse` audit row) records each switch.

Only a schedule with an **explicit `--target-host` equal to the host the
workload moved onto** is switched. A schedule with no target host (a shared
pool, or an auto-selected peer) already replicates away from wherever the
workload runs; a schedule that targets a third host stays as it is. A pool,
project or cluster schedule is shared by many workloads, so none is re-pointed
for one of them.

**Never onto its own host after a move.** An explicit `--target-host` equal to
the VM's own host is an operator's same-host copy and works as it always has. But
a run that finds the workload on its replica target because it MOVED there (a
container's schedule never targets its own host; a VM's replicas there were
written by another host) never replicates: the replica would be lost with the
workload. It is not reported as a success either. While the switch made by the
move is still on its way to this host (it replicates from the host that
committed the move), the run is skipped quietly; after 15 minutes it is reported
as `replication.suspended` (warn), once and then hourly, with the reason in the
schedule's `LAST ERR`. A pool, project or cluster schedule is never switched for
one of its VMs, so a VM that moves onto such a schedule's explicit target keeps
replicating into the pool there, as it always has.

**Never from a witness.** A VM promoted onto a witness is stopped there until it
is moved to a worker (`lv migrate <vm> <worker> --cold`), and the promote
switches its schedule to replicate from the witness back to the host it left. A
witness runs no workloads and refuses to act for the VM, so the schedule is
paused: the first run reports it once, as one audit entry (`vm.replicate`, with
the reason and the command) and one `replication.suspended` notification, and
later runs do nothing and are not logged as errors. The schedule keeps the reason
as its `LAST ERR` (`schedule paused: ...`), so it never reads as healthy, and the
notification is repeated hourly, as above. The schedule resumes by itself once
the VM is on a worker, whose scheduler then runs it and reports
`replication.recovered` on its first good run.

The switch changes only the target host: once the release token has latched,
as a compare-and-set of that one column, so an operator's concurrent edit of the
schedule on another node survives it; before that (a VM's switch only), by
re-reading the row just before re-writing it. A container's switch is always
the compare-and-set, since it only runs past the release gate. (A container's
re-key mints its new placement id with a statement of the same kind, under the
same condition.) The latch is read on the host making the switch and is not a
use of the feature: a cluster that only moves VMs can still roll back below the
release.

**If a member is rolled back.** The release token's latch is monotone: it says
every host ran this release when it formed, not that every host still does. A
member rolled back below the release after the latch cannot apply the next such
statement: it refuses it, and replication from the sending host to that member
stops at it (back-pressure) until the member runs this release again. Nothing is
applied in part and nothing is corrupted; other members are not affected, and
anti-entropy still merges the rows. A member that had latched the token itself
is in WAL quarantine on the earlier build anyway. The remedy is to upgrade the
member again (or remove it from the cluster); replication then resumes from
where it stopped. For a VM the incremental checkpoint of
the old direction is dropped, and an incremental run forks only from the replica
its own checkpoint continues (a checkpoint names the run that made it, as does
that run's replica): when the target does not hold that replica (after a
reversal, or when another period left a newer one there), the run is a full
push, never increments grafted onto another run's file. A container needs no
such step: a reversed run over a target that still holds its earlier replicas
sends only the chunks that changed (see "A run" above; the first run into a repo
that holds none sends the container whole). Nothing on the old host
is read, written or removed by the switch: replicas are only ever added there as
new files, written without replacing an existing one, and a replica that a disk
copy set aside by a failover is layered on (a `--no-localize` promotion's
overlay) is never pruned.

When the old host cannot be the target (it has no pool of that name, cannot run
containers, or is gone), the schedule is left as it was and
`replication.reverse_skipped` (warn) says so; its runs are then suspended, as
above, until the schedule is replaced. When the old host is simply down after a
failover, the schedule is switched anyway and its runs report the missing target
(a warning when it goes down and when it is back, at most hourly in between).

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

With `--auto-start`, the backed-up VM's PCI passthrough devices are attached
from this host's inventory, as `lv run` attaches them. A device the host cannot
provide refuses the restore. `--without-devices` starts the VM without them
instead: they are removed from the restored VM's spec, the progress names them,
and the audit log records a `vm.devices_dropped` entry (degraded). If the
restore fails after the devices were attached and before the VM runs, they are
released at once.

If you prefer to drive it manually, omit `--auto-start`/`--blockpull` and
`virsh define && virsh start` against the overlay, then blockpull. Use
`--from-existing` to source the domain spec from the existing `vms` record
when the manifest has none.

The NBD server is read-only and rejects writes with `EPERM` — guests
that try to write straight to the backing source get a clear error
rather than silent corruption. All writes land in the qcow2 overlay.

## Single-file restore

Browse a backup and pull files out of it without restoring the disk:

```bash
# The backup's volumes: partitions (vda1, vda2, …), the whole disk (vda),
# or rootfs for a container.
lv backup file-ls --repo main --vm postgres-1 --timestamp 2026-05-11T02:15:00Z
lv backup file-ls --repo main --vm postgres-1 --timestamp 2026-05-11T02:15:00Z /vda1/etc

# Extract as a tar archive (a new file; - for stdout).
lv backup file-restore --repo main --vm postgres-1 --timestamp 2026-05-11T02:15:00Z \
    /vda1/etc/postgresql /vda1/home/app/.env -o files.tar

# Containers: --ct, and the volume is rootfs.
lv backup file-restore --repo main --ct web --timestamp 2026-05-11T03:00:00Z /rootfs/etc/nginx -o nginx.tar
```

**The host never mounts the backup.** A malformed filesystem is a kernel
attack surface whatever the mount options, and a backup holds whatever its
guest wrote. The daemon boots a throwaway **restore VM** instead: this host's
own kernel and an initramfs whose init is the litevirt binary itself, the
backup attached read-only as its only disk (served from the repo over a local
NBD socket), no network, vsock as its only channel, one vCPU and 512 MiB. The
guest kernel parses the partition table and mounts each filesystem read-only
inside the VM. Each restore VM's qemu runs as its own uid from a reserved
range — so two sessions (possibly two tenants) cannot signal, trace or reach
each other — with only the `litevirt-restore` group and a group of its own slot
(never `kvm`: KVM is given to that slot group alone by an ACL group entry on
`/dev/kvm`, checked again just before the VM starts and removed when the
session ends — a group entry rather than a user one because udev drops every
named-user entry on `/dev/kvm` whenever any KVM VM starts or stops; the
reserved range must hold no account or group NSS knows), in a network namespace of its own (no UDP, TCP or abstract
sockets of the host), its seccomp sandbox on and, where AppArmor is enabled, confined by the
`litevirt-restore-qemu` profile (its boot files, its session's export socket
and nonce, `/dev/kvm` and vsock; no IP, no abstract sockets, nothing under
`/var/lib/litevirt`), and — on every host whose kernel has it — inside a
**Landlock** ruleset that allows qemu its own binary and libraries, its boot
files, its session's directory and `/dev/kvm`, and no other file: no VM
disk (even a world-readable one), nothing under `/var/lib/litevirt` or
`data_dir`, no writes, and, with Linux 6.7+, no TCP; with 6.12+, no abstract
sockets and no signals out. Landlock does not cover UDP or `connect()` to a
pathname unix socket on any kernel: the network namespace takes away the
first, and the uid's lack of any shared group (DAC) the second. On a host
without AppArmor and a kernel older than 6.7, TCP is held back by the
network namespace alone; the audit row's `landlock=` (below 4) shows it,
but such a VM is not reported as missing a barrier. The reserved uids are checked to be no one
else's (not the containers' id-map range, `/etc/subuid`/`subgid`, or any
account NSS knows). Its disk export accepts exactly one connection, from
that qemu (checked by its socket credentials, process group and, under
AppArmor, its confinement), and the socket is unlinked the moment qemu has
it. The daemon must run as root for this; a non-root daemon refuses file
restore. On a host without AppArmor (SELinux, or no LSM), Landlock is the
barrier between an escaped qemu and the host's files and network, alongside
the per-VM uid, the seccomp sandbox and the single-peer export; **a host
with neither AppArmor nor Landlock refuses file restore** (the uid alone does
not keep an escaped qemu from world-readable VM disks or the host's
network). Its kernel copy and
initramfs are root-owned and read-only to that user
(`/var/cache/litevirt-restore`), and re-verified against a recorded digest
before every boot. It dies with the daemon, a restarted daemon kills any it
left, and the agent inside powers off on its own when no one talks to it.
The VM's console stays in a small in-memory buffer. Everything the VM
returns is untrusted: it sends simple records, not tar, and the daemon builds
the archive itself entry by entry — relative names inside what you selected,
only directories, regular files and symlinks, nothing under a symlink (also
compared case-insensitively), no owners, setuid bits or extended attributes,
bounded sizes, counts and memory — and streams it to you. A symlink is kept
only when its target is relative, any `..` in it comes first, and it stays
inside the archive; any other is left out and counted. Nothing is written on
the daemon's host.

**Extract each archive into a new, empty directory**, and use your tar's
protections (GNU tar: `tar -xf files.tar --no-overwrite-dir -C <new dir>`).
Extracting two archives from the same backup into one directory lets a
symlink from the first meet a path in the second. The architecture,
limits and threat model are in
[design/backup-file-restore.md](design/backup-file-restore.md).

- **Permission:** the same as a full restore of that VM or container
  (`backup.restore` on the backup's project). Every extraction is audited as
  `backup.file_restore`, with the paths, what was extracted, and what
  isolated its restore VM (`sandbox=… apparmor=… landlock=… uid=…`). A restore
  VM started without one of its barriers — browsing included — is also
  audited as `backup.file_restore_unsandboxed`.
- **Sessions:** browsing reuses one restore VM per backup, killed after five
  idle minutes; each extraction runs on a VM of its own, killed when it
  completes, when you cancel, or at its wall-clock limit (10 minutes, or the
  byte limit at 1 MiB/s if longer); two VMs and one extraction at a time per
  host (`file_restore:` in the daemon config tunes all of it).
- **Filesystems:** ext2/3/4, xfs, btrfs, vfat and iso9660, on a disk or its
  partitions. Not LVM, LUKS, ZFS or md-raid inside the backup, and not a
  stopped linked clone's disk-file backup (it is only the delta over its base)
  — restore the disk for those.
- **Requirements:** KVM (`/dev/kvm` on a filesystem with POSIX ACLs, as
  devtmpfs is, or world read-write), `/dev/vhost-vsock` (the `vhost_vsock`
  module), `qemu_fw_cfg` in the kernel's modules (on Ubuntu it is in
  `linux-modules-extra-$(uname -r)`), a qemu with seccomp support, AppArmor or
  Landlock (`landlock` in `/sys/kernel/security/lsm`; Ubuntu, Debian 12+,
  Fedora and RHEL 9+ kernels have it), a root daemon, and a kernel the
  daemon can read (its own by default). Without them file restore is refused
  naming what is missing; a full restore keeps working. There is no fallback
  to mounting on the host. Whether qemu can install its seccomp sandbox is
  asked of qemu itself before each restore VM starts.
- **`file_restore.allow_unsandboxed` is dangerous.** It names the barriers a
  restore VM may run without, one at a time: `seccomp` (qemu's seccomp
  sandbox), `mac` (any MAC barrier, on a host with neither a loadable
  AppArmor profile nor Landlock; AppArmor on without `apparmor_parser` but
  with Landlock runs under Landlock and needs no key), and
  `root` (a non-root daemon, which runs qemu as itself, the user that owns
  `data_dir` and its keys) — for example `allow_unsandboxed: [seccomp]`.
  `true` lifts all three. Each removes a barrier between a malicious backup
  and the host. Install a qemu with seccomp and `apparmor_parser`, use a
  kernel with Landlock, and run the daemon as root, instead.
  **`file_restore.allow_shared_run_as`** separately permits `run_as` to be root
  or a shared qemu user, which then runs the VM itself — equally dangerous.
  While either key is set the host carries an informational
  `file_restore_unsandboxed` health condition
  ([diagnostics](diagnostics.md#file-restore-without-a-barrier-file_restore_unsandboxed)).

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
    the bytes. A VM an earlier build promoted with `--no-localize` has no
    record of its replica (raw or qcow2, in its pool's directory or the
    default pool's `<data_dir>/disks`): there the layout the promotion made
    stands in for one — the overlay named `<vm>-promoted-<replica stem>`, the
    replica named by that stem and the format it declares, of the row's own
    disk, unclaimed by any disk row and by any other project's record — the
    same test a start of that VM passes. The base must be the one the backup was taken on: a backup
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
  for an admin too, naming `--in-place`. A path in the daemon's own state is
  refused to an admin too, before anything is created — the same rule as for a
  pool directory (`state.db`, `pki`, `vms/`, `pending-audit/`, the capability
  and audit markers, …; see [storage.md](storage.md)), also for
  `restore-live` and `replicate-volume`. The one exception is `restore-from`
  with exactly the file the VM's own record names for that disk (as earlier
  releases allowed): that restore is `--in-place`, with every check and the
  rebuild above.

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
through four RPCs (and a fifth for compression, below). Each is checked at `/` with its own verb. A repo holds
every project's backups, so a project-scoped grant or token cannot reach
it. Each RPC writes one audit row: the caller, the repo, the outcome, and
what the operation counted.

| RPC | Verb | Audit action | Detail |
|---|---|---|---|
| `VerifyBackupRepo` | `backup.verify` | `backup.repo.verify` | `chunks_checked mismatched missing` |
| `GarbageCollectBackupRepo` | `backup.gc` | `backup.repo.gc` | `manifests_scanned chunks_deleted bytes_reclaimed retained_young manifests_invalid` |
| `PruneBackupRepo` | `backup.prune` | `backup.repo.prune` | the `keep_*` policy, `kept`, `deleted` |
| `SyncBackupRepo` | `backup.sync` | `backup.repo.sync` (target `src -> dst`) | `manifests_copied chunks_copied chunks_skipped bytes_copied` |

A fifth RPC, `SetBackupRepoCompression` (verb `backup.compression`, audit
action `backup.repo.compression`; detail `init compression schema`), creates a
zstd repo or turns zstd on for one, through the release token's `backup_zstd`
gate. It refuses until the token has latched and records the use first.

All of them sit in `backup.*`, which Operator and BackupOperator hold and
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
