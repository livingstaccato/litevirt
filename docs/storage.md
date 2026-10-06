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
# host-a     default local                                           /var/lib/litevirt/pools/default active

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

## Host paths

### Who may name one

A pool that names a place on the host's own filesystem makes the daemon write
there as root: VM disks, uploaded content, an NFS mount laid over the
directory. Naming one is therefore root on that host, and takes the
`storage.hostpath` verb at the cluster root `/` — which only the `Admin` role
holds. An `Operator` binding does not carry it, not even at `/`, and neither
does an `Admin` binding scoped to a project. What counts as a host path:

| Driver | Host path |
|---|---|
| `local` | `--target` (with no target the pool gets its own `<data_dir>/pools/<name>`) |
| `dir` | `--target` (always) |
| `nfs` | always: the export's server decides what the daemon finds there (files, and symlinks it would follow as root); also `--target` and `--option options=…` |
| `ceph` | always (the cluster is remote storage), plus `--option conf=…` and `--option keyring=…` |
| `iscsi` | always (the target's server decides what block devices appear) |
| `btrfs` | `--source` |
| `zfs` | always: the dataset is host storage (naming the host's root pool would let a pool fill it) |
| `lvm-thin` | always: the volume group and thin pool are host storage |

Only a `local` pool with no target names no host path, so it is the one pool an
operator with `storage.pool.write` on the pool's path may create.

Every source is checked against its driver's form before any tool sees it —
`server:/export` for nfs, a pool, dataset or volume-group name for ceph, zfs
and lvm-thin, an `iqn.`/`eui.`/`naa.` name and `host[:port]` portal for iscsi,
an absolute path for btrfs, nothing for local and dir — so no value can reach
`mount`, `rbd`, `zfs`, `lvs` or `iscsiadm` as an option. The drivers also put
`--` before positional arguments.

NFS pools are always mounted `nosuid,nodev,noexec,nosymfollow`, whatever
`options=` says. `nosymfollow` needs Linux 5.10+ and a mount.nfs that passes
it on; where it is missing the mount is refused, with an error saying so, rather
than made weaker. An export that is already mounted without these flags — mounted
by hand, or by an earlier build — is never remounted: the pool is refused
(nothing lists, reads or writes it) and the daemon logs an ERROR at start and
on each refusal, until the export is unmounted and litevirt mounts it again. Disk files the daemon creates in a pool
are created exclusively and never through a symlink. Pool names may not start
with `-`.

Some directories are refused to everyone, `Admin` included: the filesystem
root; anything under `/bin`, `/boot`, `/dev`, `/etc`, `/home`, `/lib*`,
`/proc`, `/root`, `/run`, `/sbin`, `/sys`, `/usr`, `/var/lib/libvirt`,
`/var/run` or `/var/spool`; `/var/lib/litevirt` and any `/var/lib/litevirt-*`;
the daemon's PKI directory; the data directory and any directory containing
it; and anything inside the data directory other than its `mounts/` and
`pools/` areas (`disks/` included). The list is a backstop, not exhaustive: `/opt`, `/srv`,
`/var/log` and `/var/tmp` are left to the admin who names them. A target
is judged both as written and after resolving symlinks, so a link at an
innocent name does not reach a refused directory. Authority is checked on the
node the request enters, so during a rolling upgrade an entry node on an older
build does not check it; the directory check runs there and again on the
pool's host.

The same rules apply to compose `volumes:`, which are pools by another name,
and a compose `backup-repos:` path needs the same authority (see
[compose.md](compose.md#backup-repositories)).

### Uploads

`UploadStoragePoolContent` (the UI's ISO upload) writes only a plain file name
with an image-like extension — `.iso .img .qcow2 .qcow .raw .vmdk .vdi .vhd
.vhdx .ova .ovf`, or one of those compressed as `.gz .xz .zst .bz2` — that does
not start with `.`. It never replaces anything already at the name, file or
symlink: delete the old file first.

Every pool has a directory of its own. A target-less `local` pool — the
built-in `default` pool included — gets `<data_dir>/pools/<name>`, never
`<data_dir>/disks`, which holds every VM's local disks across projects.
Deleting the pool removes that directory, and is refused while it still holds
files (the error names them). Creating a pool whose `<data_dir>/pools/<name>`
already holds files left by an earlier pool is refused until an admin removes
them; the error says how many files, not their names. A pool is never created
on storage another pool on the host already uses — the same directory, a
symlink alias of it, a directory inside it or containing it, or the same NFS
export mounted elsewhere — and the roots `<data_dir>/pools` and
`<data_dir>/mounts` are not pools. A pool row that shares its storage with
another, or sits on `<data_dir>/disks`, is refused for everything — listing
included — with `FailedPrecondition` saying to recreate it; the error does not
name the other pool, which may be another project's.

Creating a disk never replaces a file. A VM's disk is named
`<vm>-<disk>.qcow2`, which is ambiguous across hyphens — VM `a` with disk
`b-root` is the same file as VM `a-b` with disk `root` — and a pool, like
`<data_dir>/disks`, may hold every project's disks. VM create, clone, and every
image the daemon creates are published exclusively: a file already at the name
is refused (`FailedPrecondition` for a create or clone), never overwritten and
never cleaned up by the failed create. Choose another VM or disk name.

Reading a disk's backing chain — a full clone, an image built from a VM, a
cold migration's flatten, a move or copy with qemu-img — follows each layer's
DECLARED backing format, never a guess: a backing declared `raw` (a
`--no-localize` promoted VM's replica, which is guest content) is read as
raw and never parsed for a header the guest may have written; a backing with
no declared format, or declared twice, is refused. Every backing, resolved
through symlinks, must lie in the image store or the disk's own pool
directory, and a raw one must be the disk record's own `backing_disk`.
A move that flattens a disk clears its record's backing fields.

Content operations never reach a file a live VM disk uses: a listing leaves
out files a live disk of another pool uses, and a content delete refuses any
file a live disk uses, as its own file or as a backing file.

A pool created before these checks whose directory or source is now refused
is refused for everything — listing, reads and writes: uploads, content deletes, new VM disks,
volume moves and replicas onto it (native send/recv included), replica
increments, promotes and VM imports are refused with `FailedPrecondition`, it
is never re-mounted for them, and the daemon logs an ERROR naming the pool.
Nothing is moved or deleted for you: recreate the pool somewhere allowed and
move its disks there.

During a rolling upgrade, a request that enters through a node still on an
older build reaches the pool's host as a cluster peer, which is trusted; the
authority checks above hold only once every node runs this release.

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

The copy is always a **new** file in the target pool, named by the daemon —
`<vm>-<disk>-copy-<time>-<id>.qcow2` — and reported on the DONE line. A pool
can be shared by every project, so the old fixed `<vm>-<disk>.qcow2` could be
another VM's disk (VM `a` disk `b-root` against VM `a-b` disk `root`), and the
copy wrote over it. `--target-path` names the file instead; it requires the
**admin** role (`storage.hostpath`), and an existing file there is refused with
`AlreadyExists`, never replaced.

**Native send/recv** — a zfs disk replicated into a zfs pool, or a ceph disk
into a ceph pool, uses the backend's native primitive instead of qemu-img.
The destination is a **new** dataset or image the daemon names under the
target pool — `<pool source>/<vm>-<disk>-copy-<time>-<id>`, or, for an admin,
`--target-path` as the leaf name — never the pool itself and never one that
exists: the driver checks first (`zfs list` / `rbd info`) and refuses with
`AlreadyExists` before anything is sent, `zfs recv` runs without `-F`, and a
ceph full copy is `rbd export | rbd import`, which creates the image. Every
command keeps `--` before its positional arguments. The copy carries its
owner record — project, VM, disk — as zfs user properties (`litevirt:*`) or
rbd image metadata (`litevirt.*`). A ceph copy runs its source side
(snapshot, export) with the SOURCE pool's own `conf`, `keyring` and `id`, and
its destination side (check, import, metadata) with the destination pool's,
so a copy between two ceph clusters uses each cluster's own credentials. The
per-copy source snapshot is removed afterwards, and a copy that fails after it
was received is removed rather than left unrecorded. A btrfs disk takes the
file copy. What the drivers implement:

- **ZFS** — `zfs snapshot` then `zfs send | zfs recv`. Incremental
  (`-I` since the prior `litevirt-replicate-prev` snapshot) when
  `Incremental: true`.
- **Ceph RBD** — a full copy is `rbd export | rbd import` (creating);
  an incremental is `rbd export-diff --from-snap | rbd import-diff` onto an
  image the replication created. Cross-cluster via SSH wrap on the receive
  side.
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
| Native send / receive (`replicate-volume`) | n/a | n/a | n/a | file copy | zfs s/r | rbd export/import | n/a | n/a |
| HA-friendly cluster store | no | yes | depends | no (host-local) | no (host-local) | yes | yes | no |

The **Snapshots** row describes each backend's *native* snapshot capability
(what the driver could do). It is not the `lv snapshot create` code path: that
command always goes through libvirt — an external qcow2 overlay for disk
snapshots, plus `DomainSaveFlags` for the RAM state of a `--memory` snapshot —
regardless of the underlying pool driver.

For HA scenarios use NFS, Ceph RBD, or iSCSI — the disk must survive any
single host failing.
