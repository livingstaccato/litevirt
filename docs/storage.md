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

Creating a pool is the admin's act; using one is not. As in Proxmox, an admin
creates the `zfs`, `lvm-thin`, `nfs`, `dir` and other pools, assigns each to a
project (or leaves it global), and the project's operators then use it in full
with their ordinary VM and disk permissions: they create VMs with disks on it,
resize and delete those disks, snapshot the VMs, and replicate and move disks
onto it. A `zfs` or `lvm-thin` pool is used exactly like a file pool — the
disks become zvols (`<dataset>/<vm>-<disk>`) or thin LVs (`<vg>/<vm>-<disk>`).
Resizing such a disk grows the volume itself (`zfs set volsize=`, `lvextend`;
the size is rounded up to whole MiB, at most 16 PiB), and a running VM's qemu
is then told the new size. Disks only grow, and a volume whose size litevirt
has not recorded is not resized, since a grow could not be told from a shrink.

Every source is checked against its driver's form before any tool sees it —
`server:/export` for nfs, a pool, dataset or volume-group name for ceph, zfs
and lvm-thin, an `iqn.`/`eui.`/`naa.` name and `host[:port]` portal for iscsi,
an absolute path for btrfs, nothing for local and dir — so no value can reach
`mount`, `rbd`, `zfs`, `lvs` or `iscsiadm` as an option. The drivers also put
`--` before positional arguments.

NFS pools are always mounted `nosuid,nodev,noexec,nosharecache,nosymfollow`,
whatever `options=` says. `nosharecache` gives each pool's mount its own
superblock, so two pools on one server each report their own export as the
mount source. `nosymfollow` needs Linux 5.10+ and a mount.nfs that passes
it on; where it is missing the mount is refused, with an error saying so, rather
than made weaker. An export that is already mounted without these flags — mounted
by hand, or by an earlier build — is never remounted: the pool is refused
(nothing lists, reads or writes it) and the daemon logs an ERROR at start and
on each refusal, until the export is unmounted and litevirt mounts it again.
The same holds when the pool's mount point holds anything but the pool's own
export (compared in canonical form) — another export left there by a deleted
pool (deleting a pool with `--target` never unmounts it), the same server's
parent export, or a mount made by hand. Disk files the daemon creates in a pool
are created exclusively and never through a symlink. Pool names may not start
with `-`.

Some directories are refused to everyone, `Admin` included: the filesystem
root; anything under `/bin`, `/boot`, `/dev`, `/etc`, `/home`, `/lib*`,
`/proc`, `/root`, `/run`, `/sbin`, `/sys`, `/usr`, `/var/lib/libvirt`,
`/var/run` or `/var/spool`; `/var/lib/litevirt` and any `/var/lib/litevirt-*`;
the daemon's PKI directory; the data directory and any directory containing
it; and anything inside the data directory other than a directory under its
`mounts/` or `pools/` areas, or `disks/` itself. The list is a backstop, not exhaustive: `/opt`, `/srv`,
`/var/log` and `/var/tmp` are left to the admin who names them. A target
is judged both as written and after resolving symlinks, so a link at an
innocent name does not reach a refused directory. Authority is checked on the
node the request enters, so during a rolling upgrade an entry node on an older
build does not check it; the directory check runs there and again on the
pool's host.

### Directory pools on NFS

A `local`, `dir` or `btrfs` pool may sit on an NFS mount the host makes itself
— an fstab mount, a data directory on NFS (the built-in `default` pool then
lives on it), an NFS-root host — when that mount is hardened: mounted
`nosuid,nodev,noexec,nosymfollow`, as litevirt mounts its own `nfs` pools. The
export's server decides what is on it, so nothing there may be a setuid
binary, a device node, an executable, or a symlink the daemon follows as root.
Add the four options to the fstab entry, for example:

```
nas:/srv/vms  /mnt/vms  nfs4  rw,hard,nosuid,nodev,noexec,nosymfollow  0 0
```

A pool on a mount without them is refused at create and at every use, and
the error names the mount point and the options it lacks. On an NFS-root host
whose root cannot carry them, give the pool directory (or the data directory)
its own hardened NFS mount.

Such a pool's storage is the export under it: the mount's export plus the
directory's path below the mount point (`/mnt/vms/acme` on a mount of
`nas:/srv/vms` is `nas:/srv/vms/acme`). It is compared with every other pool's
exactly as two `nfs` pools are (below): it collides with an `nfs` pool on the
same export, one inside it or one containing it, and with another directory
pool on the same export, on any host — except the same pool, the same name
and project, defined on several hosts, which is how one fstab-mounted
directory is shared for migration. The pool row records that export in its
options (`nfs_export`) so other hosts, which cannot see this host's mounts,
compare against it; the daemon sets it, at create and again at every start
(so a pool made by an older build, or whose fstab mount changed, is compared
by what it is now), and a request that sets it is refused. The exception for
the same pool on several hosts holds only for the exact same export and the
same kind of pool (two `nfs` pools, or two directory pools), never between an
`nfs` pool and a directory pool, and never for a directory whose content is
confined (`<data_dir>/disks`, or one several pools share).

A host whose data directory is on NFS records the export its
`<data_dir>/disks` is on (`data_disks_nfs_export`, on the pool rows it
registers at start). Every VM's local disks on that host are there: no pool
on any host may use that export, or one inside or around it.

The same rules apply to compose `volumes:`, which are pools by another name,
and a compose `backup-repos:` path needs the same authority (see
[compose.md](compose.md#backup-repositories)).

### Uploads

`UploadStoragePoolContent` (the UI's ISO upload) writes only a plain file name
with an image-like extension — `.iso .img .qcow2 .qcow .raw .vmdk .vdi .vhd
.vhdx .ova .ovf`, or one of those compressed as `.gz .xz .zst .bz2` — that does
not start with `.`. It never replaces anything already at the name, file or
symlink: delete the old file first.

A new target-less `local` pool gets a directory of its own,
`<data_dir>/pools/<name>`. Deleting the pool removes that directory, and is
refused while it still holds files (the error names them). Creating a pool
whose `<data_dir>/pools/<name>` already holds files left by an earlier pool is
refused until an admin removes them; the error says how many files, not their
names. The roots `<data_dir>/pools` and `<data_dir>/mounts` are not pools.

The built-in `default` pool of a new host is `<data_dir>/pools/default`. A host
whose `default` pool is already `<data_dir>/disks` — every host of an older
cluster — keeps it there: nothing is moved. Pools made before pools got their
own directories (a target-less `local` pool is `<data_dir>/disks`) keep
working too, and an admin may still put several pools on one directory, or a
pool on `<data_dir>/disks` itself (not a directory inside it).

Such a directory is not one pool's own: `<data_dir>/disks` holds every VM's
local disks across projects, and a shared directory holds every pool's files.
VM disks, moves, replicas, imports and promotes use these pools as before; only
what their content operations — listing, upload, delete, the UI's ISO browser —
show and touch is confined, per file, to what the caller's project owns by
record:

- the disks of the caller's VMs on this host (as their own file or as a
  backing file), including disks kept after the VM was deleted;
- replicas of those disks, by their replica record: each replica the daemon
  places (replication's copy, upload or incremental push) is recorded on the
  pool's host with the VM, disk and project it is a replica of. A file merely
  named like a replica (`<vm>-<disk>-<time>.qcow2`) is never owned through its
  name; listing and deleting it needs `storage.hostpath` at the root;
- files uploaded into this pool while it belonged to its current project (a
  global pool's uploads are visible to everyone who may use the pool).

The caller is the user who made the call, on whichever node it entered: a
listing, upload or delete forwarded to the pool's host carries the user's
identity there and is confined as that user (a session minted a moment ago on
the entry node is waited for briefly while it replicates). A caller with a
host certificate and no bearer — the daemon itself, a node not yet upgraded,
or root on the node using the mTLS-as-admin fallback — sees and changes every
file, as before: every identity that is not an admin carries a bearer, and a
forwarded call always carries it.

Replication and promotion act for one VM in one project. Their content calls
say so, and the pool's host answers with that VM's replicas only: those whose
record names the VM, disk and project, and a replica made before records (no
record) only when its name is exactly `<vm>-<disk>-<YYYYMMDD-HHMMSS>` and no VM
of another project could have written the same name — `bvm` + `root-20261006`
and `bvm-root` + `20261006` both write `bvm-root-20261006-…`, so neither is
taken for the other. Promotion boots, and pruning deletes, nothing else. When
the replica promotion picked is missing or unreadable on its host, it tries
the next-older one there; a replica the operator named is never swapped.

A user's upload into a pool on `<data_dir>/disks` lands in
`<data_dir>/disks/uploads/` and is listed with the pool's other content: the VM
disks' own names (`<vm>-<disk>.qcow2`) are never taken by an upload, so
creating, deleting or migrating a VM never meets one, and the VM-disk debris
sweep never removes a recorded upload. A name in both directories is the
upload, to the listing and to a delete alike. Replicas are not uploads in this
sense: they land in `<data_dir>/disks` itself, where promotion reads them.
Files uploaded there by an older build stay where they are.

Installer media — an `.iso`, plain or compressed (`.iso.gz`, `.iso.xz`,
`.iso.zst`, `.iso.bz2`) — that no record refers to (no VM disk row on any
host, live or kept after its VM was deleted; no replica record; no upload) is library content, as before pools were confined:
everyone who may read the pool sees it and can attach it, in a global pool
every reader and in a project's pool that project's readers. A disk kept
after its VM was deleted, or detached from it, stays its VM's project's: its
deleted row still says whose it is, on any host. A delete touches only the
caller's own uploads and replicas; unowned library content is deleted only by
a caller with `storage.hostpath` at the cluster root, and an upload never
replaces anything. Any other file no record refers to — a disk image
(`.qcow2`, `.raw`, `.img`, `.vmdk`, …), a failover's set-aside copy, a
restore — may be any project's, and is listed and deletable only by such a
caller.
Another project's file is reported as not there. Uploads are recorded in
`<data_dir>/pool-uploads.json` on the pool's host, bound to the file itself
(device, inode, size and modification time), so a file put at an uploaded name
afterwards, or the upload rewritten, is nobody's.
A pool whose directory is its own is not confined: its project sees
everything in it.

An NFS export is the same storage from every host. Two exports are the same
storage when their servers are the same and their export paths are the same or
one is inside the other (`nas:/tenants` contains `nas:/tenants/acme`; `nas:/`,
an NFSv4 pseudo-root, contains every export of `nas`). Servers are compared in
canonical form (case, IPv6 brackets and zero compression, trailing slashes do
not matter) and, at create, by address: each server name is resolved, and two
servers that share any address are one server (`nas`, `nas.corp.lan` and
`10.0.0.5` can all be one). A create whose server does not resolve is refused,
and so is one whose export path overlaps another pool's whose server no longer
resolves. The only pool that may share an export is the same pool — the same
name and project — defined on several hosts. At use the comparison is by
canonical form only, without lookups, so a later DNS change is not re-checked
there. An NFSv4 path relative to the pseudo-root (`nas:/acme`) and the NFSv3
path of the same directory (`nas:/srv/nfs/acme`) cannot be told apart from the
client: do not mix the two forms for one server.

Content operations never reach a file a live VM disk uses: a listing leaves
out files a live disk of another pool uses, and a content delete refuses any
file a live disk uses, as its own file or as a backing file.

A pool created before these checks whose directory or source is now refused
(a system directory, the daemon's own state, a malformed source, an unhardened
NFS mount) is refused for everything — listing, reads and writes: uploads, content deletes, new VM disks,
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
