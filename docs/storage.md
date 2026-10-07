# Storage

litevirt provisions VM disks through a pluggable Driver interface. Each
*pool* is a (driver, source, target, options) tuple declared in compose
or the host config; every VM disk references a pool by name.

## Drivers

| Driver | Source | Target | Notes |
|---|---|---|---|
| `local` (default) | unused | dir override | qcow2 files under `<dataDir>/disks` |
| `dir` | unused | required | qcow2 files in an arbitrary directory (e.g. an externally-mounted SAN LUN) |
| `nfs` | `host:/export` | mountpoint override | mounted lazily by the daemon; survives restarts |
| `iscsi` | IQN | unused | LUNs are pre-provisioned on the SAN; we discover and login |
| `ceph` | pool name | unused | `rbd` CLI shell-out; CGO-free build supported |
| `zfs` | parent dataset (`tank/litevirt`) | unused | zvol per disk; `volblocksize` tunable via options |
| `btrfs` | absolute path on btrfs | unused | one subvolume per disk; qcow2 inside |
| `lvm-thin` | volume group | unused | `options.thinpool` is required; one thin LV per disk |

`SupportedDrivers` in `internal/storage/storage.go` is the authoritative
list; adding a new backend is one entry there plus a per-driver file
implementing the `Driver` interface.

## Pool management

Pools can be declared statically in `/etc/litevirt/config.yaml` under
`storage_pools:` (see [configuration.md](configuration.md)) OR added
at runtime via the `lv pool` CLI:

```bash
# Register a new NFS pool — the daemon runs Prepare() (mount, ping,
# fs check) before persisting, so a misconfigured pool fails fast
# instead of at first VM create.
lv pool create warm \
    --driver nfs \
    --source nas.internal:/srv/exports/litevirt \
    --target /mnt/litevirt-warm \
    --option options=vers=4.2,hard,intr

lv pool ls
# HOST       NAME    DRIVER  SOURCE                                  TARGET                  STATE
# host-a     warm    nfs     nas.internal:/srv/exports/litevirt      /mnt/litevirt-warm      active
# host-a     default local                                           /var/lib/litevirt/disks active

lv pool inspect warm
lv pool delete warm
```

`--option k=v` is repeatable for driver-specific flags (Ceph keyring
paths, ZFS volblocksize, iSCSI portal addresses, …). The full
schema lives in `internal/storage/storage.go`'s `Config.Options` —
each driver pulls its own keys out of the map.

`--project <name>` makes a pool **owned** by a tenancy project: only that
project's workloads (or a root operator) may place, move, replicate, import, or
promote disks onto it. Omit it for a **global** pool (the default, and every
pre-existing pool) usable by all projects. Enforcement is at use time, across
create and the day-2 storage paths. See [tenancy.md](tenancy.md).

`lv pool delete` soft-deletes the row from cluster state. The
driver is asked to tear down (unmount NFS, log out of iSCSI) on a
best-effort basis but failure does not block the delete — operators
who hit "rm" likely want the pool gone regardless. The underlying
mount, if any, stays until manually cleaned up.

## Installer ISOs

A VM's installer ISO is a file on the target host that the guest reads as a
CD-ROM. A VM names it from an **ISO library**, by pool and file name, never by
host path:

```yaml
vms:
  win-1:
    iso: isos/virtio-win.iso        # the global library
  build-1:
    iso: acme-isos/debian-12.iso    # project acme's own library
```

The host resolves the reference to the file of that name directly in the
pool's directory, when the VM is created and again at every start (restart
policy, health restarts, a snapshot restore, a replace cutover, and a
migration target before the VM lands there). The file must be a plain file:
not a symlink, not a second hard link to some other file, and not anywhere
`storage.CheckReadFile` refuses (below). The last check before the VM starts
opens the file without following a link and confirms it is the same file at
the same path; qemu then opens the path itself (see the known limits below). The daemon writes every file a library holds — an upload, a
pull, a sync — so a link there is never one of them, and a library write never
replaces a file already there (remove it first with `lv iso rm`).

Pools are per host, and two hosts can each have a pool of the same name. So
the authority is judged wherever the reference is resolved, not only where the
VM was created:

- The create records which kind of pool the ISO is in (`VMSpec.iso_scope`):
  the global library, another pool with no project, or a pool the VM's project
  owns (or, for an Admin's host path, that). On any host where the reference
  resolves to a pool of another kind, the VM does not start there.
- On every host, every pool mapping that directory must be global or the VM's
  project's. Directories are compared as the file is opened — with symlinks
  resolved, and by the directory's identity — so neither a pool whose target
  is a link (or `/proc/self/root/…`) to another pool's directory nor a bind
  mount of it gets past the check. The pool the reference names must be
  global or the VM's project's on that host, file or no file: a same-named
  pool of another project on the host a VM moved to is not its library.
- Reading another pool's directory can block (an NFS server that stopped
  answering, on a hard mount). The daemon's own NFS mount directories are
  never read for this. A directory on a network filesystem other than the
  one the ISO's directory is on is told apart by `/proc/self/mountinfo`
  without being read (unless a link above its mount point leads elsewhere),
  so another project's dead NFS server does not stop this VM. Any other
  directory is read under a 3-second deadline, one read per directory at a
  time; one that does not answer, or answers with an error other than "no
  such directory", refuses the start (or create, or move) saying which pool
  did not answer. Until a read that timed out returns, the next question
  about that directory is answered at once, so a dead directory holds one
  blocked thread, not one per start.
- Each time a host judges the ISO by that full rule and it passes — at the
  create, at a start, as a migration target — the host records which file it
  was (in `<data_dir>/iso-identity`, by the VM's uuid and project: resolved
  path, inode, size and mtime; not the device number, which a ZFS, btrfs, NFS
  or LVM mount can renumber across a reboot). A later start of that unchanged
  file on that host keeps working even if another project's pool has since
  come to share the directory — another project's ordinary `lv pool create`
  cannot stop a VM that started before, on the host it was created on or one
  it moved to. A file put there since is judged by the full rule. On a VM's
  first arrival by migration on a host where the directory is already shared,
  the source sends the sha256 of the file it judged for the VM, and the
  target admits a file with those very bytes (the guest gets what it already
  had) and records it; any other file there is refused. The hash is computed
  once per file version (device, inode, size, mtime). A VM that arrives
  without a source to ask (a failover) is judged by the full rule until
  per-file ownership comes with the storage pools change. A host's records
  go when the VM is deleted or its create fails, and a sweep every five
  minutes removes those of VMs that no longer exist. No pool may be created
  in `<data_dir>/iso-identity`.
- A **running** VM's live migration (`lv migrate`, or a drain) lands on the
  target's own file: the target resolves the VM's ISO on its own filesystem
  — through its pool, or an Admin's host path resolved there, so a
  `virtio-win.iso` link that names another version on the target, or a
  library in another directory, is followed there — judges it, and returns
  it, and the source hands libvirt a destination definition whose CD-ROM is
  that file. A target where it does not resolve, or where the file it
  resolves to is refused, refuses the move. A **stopped** VM may move to a host that does not
  have its ISO or library yet: the move is accepted with a warning, and the VM
  will not start there until the ISO is present (upload or pull it, or wait for
  the library to sync); the warning is logged and recorded as a VM event
  (`vm.migrate.iso_warning`, in `lv events`). A stopped VM's domain is pointed
  at the target's file when it starts. A target where the pool of that name is
  another project's, or of another kind, refuses the move, file or no file.
  The source lists the CD-ROMs of the running domain for a running VM, and a
  migration whose running domain cannot be read stops.

### The global library

Every host has a pool named `isos` with no project, at `<data_dir>/pools/isos`,
which the daemon creates when the host has none. Every project may boot from
it. Only an Admin writes it (`storage.library.write` at `/`): an upload in the
UI's Browse dialog or `lv iso pull` (below).

The global library is not just any pool called `isos`. In sync mode it is the
daemon's pool at `<data_dir>/pools/isos`; in shared mode it is the global
`isos` pool the Admin put on shared storage — setting the mode to `shared` is
the designation. Creating, replacing, retargeting or deleting a global `isos`
pool needs `storage.hostpath` at `/` (Admin), not `storage.pool.write`. No
other pool may be created in, above or below its directory, and an `isos` pool
may not be put on a directory another pool maps.

Where its files live is the cluster setting `iso_library_mode`, shown and
changed with `lv cluster iso-library-mode`:

- **`sync`**: every host keeps a local copy. An upload or pull
  to one host records the file's sha256 in replicated state, and every other
  host copies it from a host that has it and keeps it only if it hashes to
  that record (every 30 seconds). A VM starts from a global-library ISO only
  on a host whose copy matches; elsewhere the start fails with
  `FailedPrecondition` until it has synced. `lv iso ls --host <h>` shows the
  state of each file on `<h>`. Removing a file records the removal, and every
  host removes its copy.
- **`shared`**: the `isos` pool is on storage every host mounts, so every host
  sees the same files and nothing is copied. Set it up by creating the pool
  over the built-in one on every host, with the same export:
  `lv pool create isos --driver nfs --source nas:/export/isos --option content=iso --host <h>`.

With the setting never set, a cluster where some host already has an `isos`
pool the daemon did not make (an NFS share, say) is in **`shared`** mode, so
its files keep working as they are; any other cluster is in **`sync`** mode.
An Admin's absolute host path (below) is never subject to the mode.

Switching:

- **to `shared`**: create the shared `isos` pool on every host (above), copy
  the files you need into it, then run `lv cluster iso-library-mode shared`.
- **to `sync`**: run `lv cluster iso-library-mode sync` against a host whose
  library holds the files you want. Setting the mode starts a new generation
  of library records: the earlier records, removals included, stop counting,
  and every host records the ISOs its own library holds that the new
  generation has no record of — the connected host at once, the others on
  their next sync pass. So the records describe the files as they are. A file
  two hosts hold under one name with different content ends up recorded as
  whichever host's record replicates last (last writer wins), and every other
  host's copy is then replaced by that one.

Changing the mode needs the admin role and refuses until every host runs a
release that knows it (`failover_scope_v1` latched). In sync mode an upload or
pull to the global library is refused for the same reason until then.

The records live in the replicated `cluster_policies` table, beside the
failover scope:

- `iso_library_mode` — the mode; its update time is the record generation.
- `iso_library/<file>` — a file's sha256 and size, or its removal (a
  tombstone, so a host that was down when the file was removed deletes its
  copy rather than offering it back), stamped with its generation. A file
  added again replaces its tombstone.
- `iso_library_host/<host>` — the generation and the newest record a host has
  applied.

A tombstone every host holding the library has applied — that exact version,
by each host's per-record ack — and every record of an earlier generation, is
collected by the host that wrote it: it becomes an empty row (the table has no
replicated delete, and adding one would be a new statement shape for every
peer to decode). The key is read again just before, and left alone if it
changed, so a file added again in the meantime keeps its record. The first
time an Admin creates, replaces or deletes a global `isos` pool with no mode
ever set, the mode in force is written first (pinned), so the change cannot
flip it silently; a pin keeps the records made while the mode was implicit,
so no start is refused meanwhile. Every sync pass also records the library
files a host holds that have no current record (a tombstone is collected only
once every host has removed the file, so such a file was added again).

### Project libraries

A project library is any file-based pool a project owns with the option
`content=iso`:

```bash
lv pool create acme-isos --driver dir --target /srv/acme-isos --project acme --option content=iso
```

The project's operators upload to it (`storage.content.write`) and may pull
into it from a URL, and only that project's VMs may boot from it, on any host.
Only `.iso` files go into a library. A library whose directory another
project's pool also maps lists nothing from it (the files may be that
project's); give a library a directory of its own.

A library on NFS relies on the pool being mounted `nosymfollow` (with
`nodev,nosuid`), so the NFS server cannot answer the open with a link; see the
hardened-mount rule for directory pools on NFS.

### Filling a library

- **Upload**: the UI's Browse dialog, or `UploadStoragePoolContent`.
- **From a URL**: `lv iso pull isos/debian-12.iso --url https://… --checksum <sha256>`,
  under the image-pull limits (http/https only, the redirect checks,
  `max_image_bytes`, `image_pull_timeout_sec` and the
  `image_pull_blocked_cidrs` policy).
- **From a host path** (Admin, `storage.hostpath` at `/`, since it reads that
  file): `lv iso pull isos/virtio-win.iso --from-host-path /usr/share/virtio-win/virtio-win.iso`.
  The file is copied, never linked, so naming a symlink is fine; the source is
  judged like any file a guest could be given.

`lv iso ls` lists what a caller may name on a host: its projects' libraries
first, then the global library. A library whose directory does not answer
within the 3-second deadline (a dead NFS server) is listed as `<pool>/` with
the state `unavailable`, rather than holding the listing up; the same goes
for the UI's Browse dialog, and a sync pass gives up on it the same way.
`lv iso rm <pool>/<file>.iso` removes one.

### Host paths and earlier specs

- An **Admin** may still name an absolute host path (`storage.hostpath` at
  `/`). It may be a link or pass through one — virtio-win ships
  `/usr/share/virtio-win/virtio-win.iso` as a link to a versioned file, and
  `/var/lib/libvirt/images` is often a link to a data disk. The path is
  resolved once, at create and again at every start, the file it names is
  judged (not in a refused place, as named or as resolved; a regular file; no
  link left in the resolved path), and the domain is given the resolved file,
  so qemu never follows a link. The spec keeps the path as named, so an
  updated package's new versioned file is picked up at the next start. A hard
  link is accepted where `fs.protected_hardlinks=1` (the kernel then stops a
  user linking a file they do not own; systemd's sysctl defaults set it, the
  kernel's own default is 0, so check it on hosts without systemd, such as
  Alpine), and refused, saying so, where it is 0.
- A **non-admin** may not. An absolute path that names a `.iso` directly in a
  pool directory — what earlier specs stored — is taken as that pool's
  reference, provided the caller may read the pool and the VM's project may
  use it (every pool sharing that directory included). It is stored as
  written and resolved through its pool, with the same per-host checks as a
  reference, the library record included. A VM created before `iso_scope` was
  recorded is treated as a host path (above), as it was before: it keeps
  starting, links and all.
- A reference may also name a pool that is not a library (a global pool, or
  one the VM's project owns), as earlier pool paths could; it is not listed by
  `lv iso ls`, and the same checks apply.

Some files are refused to everyone, Admin included, judged as written and after
resolving symlinks: the PKI directory, anything in the data directory outside
`disks/`, `mounts/` and `pools/isos/` (`state.db`, `cloudinit/`, `nvram/`, …), and
anything under `/boot`, `/dev`, `/etc`, `/proc`, `/root`, `/sys`,
`/var/backups`, `/var/spool`, `/var/lib/lxc`, `/var/lib/libvirt/qemu` or
`/var/lib/libvirt/swtpm`.

Under `/home` and `/run` (`/var/run`) — where an ISO downloaded into a home
directory, or a USB stick udisks mounts under `/run/media`, lives next to
`~/.ssh` and runtime secrets — a file is given to a guest only when it is an
optical disc image: a regular file carrying an ISO 9660 or UDF volume
signature (read from the opened file, not judged by its name), with no path
component, as named or as resolved, starting with a dot. So
`/home/u/isos/virtio-win.iso` and `/run/media/u/STICK/win11.iso` work, and
`~/.ssh/id_rsa`, a key renamed `.iso`, or an ISO inside `~/.cache` do not.

A refusal at start fails with `FailedPrecondition` and an ERROR log naming the
VM and the file, and the VM stays down. What is judged is the CD-ROM the VM's
domain actually carries, so a VM whose domain was redefined without its
installer CD-ROM starts even after the ISO is gone. When a library file lives
at a different path on the starting host than where the domain was defined
(a library pool on another directory), the domain is pointed at this host's
file.

The entry node checks authority before forwarding; the owning host resolves
the file against its own filesystem.

### Known limits

- **qemu reopens the path.** The last check opens the file without following a
  link, then closes it; qemu opens the path again when the VM starts. In a
  local library only the daemon (root) writes, so nothing else can swap the
  file in between. A library on NFS needs the pool mounted `nosymfollow`
  (the hardened-mount rule for directory pools on NFS), or the NFS server can
  answer qemu's lookup with a link.
- **Mixed versions fail open, as before this release.** Until every host runs
  this build: an entry node on an older build forwards without the authority
  check (a non-admin's absolute path then arrives as the peer's and is
  recorded as a host path); an older migration target ignores the CD-ROM paths
  the source lists and judges nothing, and an older source lists none, so the
  target skips the running-VM path check; an older owner rewriting a spec
  drops `iso_scope`, which makes the VM's ISO a legacy, file-only one. None of
  these is weaker than a release without these checks (as with the other
  content checks in [auth.md](auth.md)).
- **VMs created before `iso_scope`** with an absolute path are judged as the
  file they name on every host, as before.
- **A memory snapshot's restore** reopens the CD-ROM path its saved image
  holds. For a snapshot taken on this release that is the resolved file the
  start judged; for one taken before, it may be the link the VM was given.
- **A live migration from an older source** carries the source's domain as
  it is: the target judges what it would open, and refuses a pool ISO it
  cannot resolve there.

## Compose example

```yaml
volumes:
  hot:
    driver: zfs
    source: tank/litevirt
    options:
      volblocksize: 16k
      compression: lz4

  warm:
    driver: nfs
    source: nas.internal:/srv/exports/litevirt
    target: /mnt/litevirt-warm
    options:
      options: vers=4.2,hard,intr

vms:
  web-1:
    image: ubuntu-24.04
    disks:
      root: { size: 40G, storage: hot }
      data: { size: 200G, storage: warm }
```

## Storage motion

Move a VM's disk to a different pool on the same host:

```
lv move-volume web-1 root warm --delete-source
```

**Stopped VMs** — `qemu-img convert` from source to destination, then the inactive
libvirt domain's disk source is repointed and the disk record is updated in a single
atomic write (host, path, driver, and pool together). The redefine happens *before*
the DB commit, so a mid-move failure rolls back cleanly; if a prior attempt already
repointed the domain at the destination, the copy is skipped so a newer destination is
never clobbered.

**Running VMs** — libvirt `BlockCopy` mirrors writes into the destination while the VM
keeps running. The persistent domain config and the disk record are moved to the
destination **before** the `BlockJobAbort PIVOT` that swaps the live disk — the pivot is
the irreversible commit, so durable state never lags behind a pivoted guest and no
acknowledged write is lost. Operator-visible downtime: zero. The orchestrator
preallocates the destination, polls progress every ~250 ms, and cancels/rolls back on
context-cancel or pivot failure.

> **Note:** `lv replicate-volume`'s copy step uses `qemu-img convert`, which
> needs the source disk quiescent — replicate a **stopped** VM (or a disk no
> running VM holds open), otherwise the convert fails on the disk lock. Online
> `move-volume` has no such restriction: it mirrors via libvirt `BlockCopy`
> while the VM keeps running.

Both paths support file-based pools (local / nfs / dir / btrfs).
Block backends use Replication below.

### Migrating a whole stack

`lv stack migrate-volumes` moves every disk of every VM in a stack to a
different pool. It orchestrates the per-disk `move-volume` primitive: it
enumerates the stack's VMs, resolves a target pool per disk, runs a
preflight, then rolls the moves out **one VM at a time** by default so a
stateful service (e.g. a 3-node postgres cluster) keeps serving. Each per-disk
move is dispatched to the VM's owning host, so a stack spread across hosts is
handled in one command.

```
# Whole stack to one pool:
lv stack migrate-volumes postgres --to fast

# Per-VM / per-disk overrides (most-specific wins: vm/disk > vm > --to):
lv stack migrate-volumes postgres --to fast \
    --map pg-1/data=archive --map pg-2=warm

# Preview the resolved plan without moving anything:
lv stack migrate-volumes postgres --to fast --dry-run
```

- **Online by default** — running VMs migrate via blockdev-mirror (no
  downtime); stopped VMs use the offline convert path. The choice is per VM,
  based on its state.
- **Rolling** — `--parallel 1` (default) migrates one VM at a time and
  health-gates between VMs; raise `--parallel N` for stateless stacks. Use
  `--order replica-1,replica-2,primary` to fix the sequence.
- **Preflight** validates, before any data moves, that each target pool exists
  on the VM's owning host and that source + target are file-based pools;
  capacity shortfalls are surfaced as warnings. Block-driver pools
  (ceph/zfs/iscsi/lvm-thin) are rejected — use Replication below.
- **Resumable** — disks already on their target pool are skipped, so a run that
  stops on an error can simply be re-run to completion.
- `--delete-source` reaps each original after its successful cutover — but
  only if no other disk still references that file (a disk shared with another
  VM, or a base/backing image). If something else depends on it the source is
  kept and the reason is reported; the delete is never the thing that breaks
  another VM.

The same operation is available in the web UI (stack detail → **Migrate
volumes**) and over REST (`POST /api/v1/stacks/{name}/migrate-volumes`, SSE).

## Replication

```
lv replicate-volume web-1 root dr-pool
```

**Native send/recv** — when the source driver implements the
`Replicator` interface, replication uses the backend's native
primitive instead of qemu-img convert:

- **ZFS** — `zfs snapshot` then `zfs send | zfs recv`. Incremental
  (`-I` since the prior `litevirt-replicate-prev` snapshot) when
  `Incremental: true`.
- **Ceph RBD** — `rbd export-diff | rbd import-diff`. Incremental
  uses `--from-snap`. Cross-cluster via SSH wrap on the receive side.
- **BTRFS** — `btrfs send | btrfs receive`. Incremental via `-p` against
  the prior replicate snapshot.

Cross-host replication wraps the receive in `ssh <user@host>` so the
sender pipes straight into the remote CLI. Same-host uses a local pipe.

Crash-consistent by default; quiesce-via-guest-agent for application
consistency is a planned follow-up.

## Backend matrix

|  | local | nfs | dir | btrfs | zfs | ceph | iscsi | lvm-thin |
|---|---|---|---|---|---|---|---|---|
| Snapshots | qcow2 | qcow2 | qcow2 | atomic (subvol) | atomic (zvol) | atomic (rbd snap) | external | atomic (LV snap) |
| Move (offline) | ✓ | ✓ | ✓ | ✓ | — | — | — | — |
| Move (live) | ✓ | ✓ | ✓ | ✓ | — | — | — | — |
| Replicate via qemu-img | ✓ | ✓ | ✓ | ✓ | fallback | fallback | — | — |
| Native send / receive | n/a | n/a | n/a | btrfs s/r | zfs s/r | rbd export-diff | n/a | n/a |
| HA-friendly cluster store | no | yes | depends | no (host-local) | no (host-local) | yes | yes | no |

The **Snapshots** row describes each backend's *native* snapshot capability
(what the driver could do). It is not the `lv snapshot create` code path: that
command always goes through libvirt — an external qcow2 overlay for disk
snapshots, plus `DomainSaveFlags` for the RAM state of a `--memory` snapshot —
regardless of the underlying pool driver.

For HA scenarios use NFS, Ceph RBD, or iSCSI — the disk must survive any
single host failing.
