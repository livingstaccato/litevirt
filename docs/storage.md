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
mount source. `nosymfollow` needs Linux 5.10+ and a mount (mount.nfs,
util-linux) that passes it on. Where it is not available — a kernel before
5.10 (RHEL 8, Ubuntu 20.04, Debian 10), or a mount that refuses or drops the
option — the pool is mounted (or hardened) with the other options and used,
the daemon logs a WARN once per mount point, and
every open litevirt itself makes of the pool's content (records, uploads,
replicas, temps) follows no symlink on the export — `openat2`
`RESOLVE_NO_SYMLINKS`, or a component-by-component `O_NOFOLLOW` walk on a
kernel without it — and a pool path is not handed to `qemu-img` through one.
An export that is already mounted without these flags — mounted by an earlier
build (`vers=4,hard,intr`), or by hand — is hardened in place, at daemon start
and at the pool's first use: `mount -o remount,bind,<its flags plus
nosuid,nodev,noexec,nosymfollow> -- <mount point>` changes only that mount's
flags, so nothing is unmounted and VMs running from the pool are untouched
(the remount keeps the mount's own flags, so a read-only mount stays
read-only). Only when that remount fails, or leaves a flag missing, is the
pool refused (nothing lists, reads or writes it), with an ERROR at start and
on each refusal, until it is remounted with them or unmounted and mounted again
by litevirt. A pool whose mount point holds anything but the pool's own
export (compared in canonical form) is refused the same way and never
remounted — another export left there by a deleted
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
- replicas of those disks, by their replica record. Replication runs write
  every replica into the pool's replica area with a record beside it
  ([backups.md](backups.md#where-replicas-live-and-how-they-are-selected)),
  and a listing shows the caller the replicas of the VMs it may read. A
  replica at the pool's top level — written before runs used the area, or an
  older node's replica upload — is recorded on the pool's host with the VM,
  disk and project it is a replica of. A file merely named like a replica
  (`<vm>-<disk>-<time>.qcow2`) is never owned through its name; listing and
  deleting it needs `storage.hostpath` at the root;
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

Replication and promotion act for one VM in one project. Promotion and
failover choose from the VM's records in the replica area and from the
replicas at the pool's top level; pruning keeps `keep_replicas` across both,
the area's first. For the top-level ones their content calls say whose they
are, and the pool's host answers with that VM's replicas only: those whose
record names the VM, disk and project, and a replica made before records (no
record) only when its name is exactly `<vm>-<disk>-<YYYYMMDD-HHMMSS>`, its stamp
is not in the future, and no VM of another project has a disk that writes the
same name — `bvm` with a disk `root-20261006` and `bvm-root` with a disk
`20261006` both write `bvm-root-20261006-…`, so neither is taken for the other,
while another project's VM `web` without a disk `prod-root` does not stop
`web-prod`'s `web-prod-root-…` replicas from being `web-prod`'s. Promotion
boots, and pruning deletes, nothing else; pruning never deletes a replica a
live disk uses (on shared storage, a live disk on any host — matched by the
file's name, since another host may mount the store at another path). Replicas are
ordered by the run time in their names, newest last: the newest is the one
failover promotes, pruning keeps the newest `keep_replicas`, and an incremental
replica forks from the newest raw one. When the replica promotion picked is
missing or unreadable on its host, it tries the next-older one there; a
replica the operator named is never swapped. A replication run whose replica
cannot be recorded in the area removes it and fails, raising
`replication.failed`, and the next run retries; the area's records live on
the store beside the replicas, so a shared store's other hosts read them with
no replicated row. A `replicate-volume` copy that cannot be recorded stays,
and the command's final status says so.

Records only ever add proof. A record bound to a file that has since changed
(rewritten, or replaced by hand) no longer says whose it is, and the file is
matched by its name as if it had none. A record is bound to its path, size
and modification time only, so a reboot, a remount (CIFS `noserverino`, FUSE)
or a copy of the data directory and its pools (`rsync -a`, `cp -a`, a
restore) keeps every upload its project's. A copy that keeps the modification
time only to the second (GNU `tar` in its default format, `scp -p`, an older
`rsync`), or to the millisecond, microsecond or 100 ns (the target
filesystem's granularity), still matches: the file's time is the record's
truncated to that unit.

A replica an operator names for a manual promotion (`--replica`) may also be
a file the VM's project owns by record — an upload into one of its pools, or
into a global pool by a user who may create the VM (judged by that user's
roles now: an upload whose uploader has since been deleted is named by an
admin) — or a file from before
records named `<vm>-<disk>-<anything>.qcow2|.raw` (no stamp needed) that no
other project's VM and disk could have written. A `replicate-volume` copy into
a pool is recorded as the operator's copy of that VM's disk, whatever it is
named: its project's, and promotable by naming it, but never a replica a run
made — never pruned, never the newest replica failover promotes, never an
incremental replica's base. An admin (`storage.hostpath` at the root) may
name any file in the pool, as before. When that file is another project's
alone — its upload or replica by record, a disk of its VM, or a name only its
VM disk's runs write — the promotion goes ahead, a warning is logged, and the
VM's events (`replica.foreign`) name the owning project.

On shared storage — a pool directory on an NFS, CephFS, GlusterFS or CIFS/SMB
mount other hosts mount too — the record of each upload and replica is also
kept cluster-wide (in the replicated `cluster_policies` table, once
`failover_scope_v1` has latched), so every host matches a file the same way.
The records are keyed by the storage's identity: an NFS or CIFS export by the
server as the mount names it (lower-cased; never the address it resolved to,
which round-robin DNS or a re-IP changes) and the path below the export, a
CephFS directory by the cluster's filesystem id and its path, a GlusterFS one
by its volume name and path. Each host writes only its own rows — one per
store for its uploads, one per VM disk (keyed by the VM's project and uuid,
never its name) for its replicas — and readers take every host's. A VM name
reused in another project therefore inherits nothing. A row holds only files
that exist, so the rows do not grow with history; on a `keep_replicas: 0`
schedule a VM disk's row lists every replica kept.

Each host notes when it began recording, and which store each of its pools
is on now and since when, rewriting that whenever it changes (a remount, a
re-IP, a kernel upgrade that changes the CephFS id); a host retries these
until the replicated rows are writable, so a new cluster needs no restart.
Once every host has, and every host holding a pool on a store is on that
store under the same identity now, a file there with no record that was modified after
the last of those moves was not put there by any host's daemon: it is never
taken for a replica by its name. While any host holding the pool is on
another identity (mid re-IP, or spelling the server differently), files are
matched by name. Everywhere else — a local directory, a network
filesystem whose identity cannot be told (OCFS2, GFS2, virtiofs, other FUSE
mounts), an export two hosts spell differently, a store some host has not noted yet, or while `failover_scope_v1` has
not latched — files with no record are matched by name as described above.
Spell an NFS server the same on every host to keep its records shared.

A replica's record on shared storage reaches another host as fast as the
cluster replicates. A host cut off from the others (a partition) may keep
writing replicas to the store whose records never arrive. Failover still
takes such a replica when its name is exactly the VM disk's runner name, no
record this host holds names it, the upload API did not place it, the VM's
host is fenced or no longer answering, that host has recorded replicas of
this disk on the store, and the file is newer than every one of them and no
newer than the moment that host was last seen answering (plus ten minutes of
clock skew); the VM's events then name the replica as promoted without its
record. Every upload into a directory on such a store leaves a marker on the
store itself (`.litevirt-uploads/<name>` beside it, written before the upload
is published, removed with it), which every host sees together with the file
even when the upload's record has not arrived: an upload, through any host
and whenever made, is never taken this way. What remains takeable is a file
put on the store directly — not through litevirt — at the VM disk's next
runner name, by someone with write access to the export, inside that window.

On a store without an identity, a file recorded on another host has no
record here: a project's own disk-image upload made through one host is
listed for the project only through that host.

Deleting a VM sweeps its leftover `<vm>-<disk>.qcow2` files from
`<data_dir>/disks` as before, a default-named `replicate-volume` copy
(`<vm>-<disk>.qcow2`) among them; a user's upload of that shape is kept.
A replication run's replicas (`<vm>-<disk>-<time>.qcow2`) were never among
what the sweep removes: they are kept when their VM is deleted. Remove them
with a delete of the pool content (the VM's project's operators, or an admin)
once the VM is gone. That holds for a replica in the pool's replica area too
(`<pool>/.replicas/<owner>/<disk>-<time>.<ext>`): a listing shows it, under
its file name with the VM beside it (`replica_vm`), to whoever reads the VM —
a deleted VM's too, whose tombstone still says whose it was — and a delete of
that name removes the file and its record. When replicas of several VMs share
the name (one schedule's fan-out run writes them at one time), the delete
names the VM as well (`replica_vm` on `DeleteStoragePoolContent`) and is
refused without it. Only the VM's project's readers (holding
`storage.content.write` on the pool) or an admin delete one, and never one a
disk on any host uses (a `--no-localize` promotion's backing).

Deleting a pool on its own directory (`<data_dir>/pools/<name>`) removes the
daemon's own directories in it first: the replica area's empty directories,
and the upload markers (`.litevirt-uploads`) of uploads no longer there. A
pool still holding replicas or files is refused, naming them; with `--force`
it is deleted anyway, as it always was: the replicas in its area go with it
(not one a disk uses), and any other file stays where it is, in the
directory, which is then kept — and a new pool of that name is refused the
directory until it is emptied.

A user's upload into a pool on `<data_dir>/disks` lands in
`<data_dir>/disks/uploads/` and is listed with the pool's other content: the VM
disks' own names (`<vm>-<disk>.qcow2`) are never taken by an upload, so
creating, deleting or migrating a VM never meets one, and the VM-disk debris
sweep never removes a recorded upload. A name in both directories is the
upload, to the listing and to a delete alike. Replicas are not uploads in this
sense: replication runs write them into the pool's replica area, and older
replicas stay in `<data_dir>/disks` itself, where promotion reads them too.
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
(inode, size and modification time — not the device number, which a reboot or
remount may change), so a file put at an uploaded name afterwards, or the
upload rewritten, is nobody's.
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
no declared format, or declared twice, is refused. Every backing is judged,
resolved through symlinks, before anything opens it, and is accepted only as:

- a file in the image store with no external data file, whose own backing,
  if any, is another file in the image store (a layered image) — an image is
  a base, never a way to name any other file;
- the `backing_disk` recorded on the layer naming it — the disk's own record,
  or the record of whichever disk that layer is: a linked clone's template
  disk, in whatever pool it lives in, and a `--no-localize` promoted VM's
  replica. A backing declared `raw` is accepted only this way, so a linked
  clone of a promoted VM (clone → promoted overlay → raw replica) copies too —
  or, for a VM an earlier build promoted with `--no-localize` (which recorded
  no `backing_disk`), as the replica its overlay was built from: in the pool
  directory, the overlay `<vm>-promoted-<source>-<disk>-<ts>.qcow2` beside
  exactly `<source>-<disk>-<ts>.raw` (the replica's own name, of the disk's
  own name and a `YYYYMMDD-HHMMSS` replica timestamp), or in the VM's own
  replica directory, claimed by no disk row and no other project's record.
  A snapshot overlay that took the disk's place (`<stem>.<snapshot>`, after
  the snapshot is reverted or deleted) is judged by its stem the same way,
  and a layer of the disk's own — same directory, same stem, no row of its
  own — answers to the disk's record;
- a file in the directory of a file-based pool on this host that the VM's
  project may use (global, or owned by that project), or the disk's own pool;
- in `<data_dir>/disks` (which holds every project's disks) or the disk's own
  directory, only a file the VM's project owns by record — a disk of one of
  its VMs, or its recorded replica — or the base an external snapshot of the
  VM left beside its overlay: same directory, the disk's own `<vm>-<disk>`
  stem, claimed by no other VM's row. This holds after the snapshot is
  reverted or deleted too, when the disk stays on an overlay named after it.

Another project's file is refused wherever it sits, unless a record ties it
to the layer naming it. A move, a restore or a copy that leaves a disk
standalone clears its record's backing fields.

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
  without being read, when it is that filesystem's mount point or the mount
  is `nosymfollow` (and no link above the mount point leads elsewhere), so
  another project's dead NFS server does not stop this VM. Any other
  directory is read under a 3-second deadline, one read per directory at a
  time; one that does not answer, or answers with an error other than "no
  such directory", refuses the start (or create, or move) saying which pool
  did not answer. A read that blocks holds a thread until the filesystem
  answers, so they are bounded, and in shares no project can spend for
  another: at most 4 reads at a time on one network mount (and none once one
  there has timed out, until it returns), at most 16 for one project (or for
  the daemon's own sync), at most 64 in all of which 16 are kept for
  directories not on a network mount. Past a bound the read is refused at
  once, saying which bound. A non-admin's absolute path whose directory is
  not, as written, a pool's directory is refused before anything is read.
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
  had) and records it. Wherever the directory is shared — a first arrival, a
  start with no record of the file here — a file the pools' upload records
  give to the pool the reference names (an upload into that library, its
  project's) is that library's, and is admitted and recorded; any other file
  there is refused. The hash is computed once per file version (device,
  inode, size, mtime). A VM restored from a
  backup, or failed over, is defined without its installer CD-ROM (as before
  this release: only a create attaches one), so it starts whatever another
  project's pools map. A host's records
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
  resolves to is refused, refuses the move. A target on an older release
  judges nothing and returns nothing; the source then hands it the path the
  VM was given (an Admin's link), which its qemu follows there, as before.
  A stopped or cold move (`--cold`, every Secure Boot or vTPM VM, a drain of
  a VM with a host-local disk) always ships an Admin's host-path ISO as the
  path the VM was given: a target on this release resolves and judges it at
  its start, and one on an older release follows the link, as before.
  A **stopped** VM may move to a host that does not
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
`pools/`, `mounts/` and `disks/uploads/` (`state.db`, the VM disks in
`disks/`, `cloudinit/`, `nvram/`, …; the global library `pools/isos/` is under
`pools/`), and anything under `/boot`,
`/dev`, `/etc`, `/proc`, `/root`, `/sys`, `/var/backups`, `/var/spool`,
`/var/lib/lxc`, `/var/lib/libvirt/qemu` or `/var/lib/libvirt/swtpm`. `/usr` is
allowed (`virtio-win` installs there).

Under `/home` and `/run` (`/var/run`) — where an ISO downloaded into a home
directory, or a USB stick udisks mounts under `/run/media`, lives next to
`~/.ssh` and runtime secrets — a file is given to a guest only when it is an
optical disc image: a regular file carrying an ISO 9660 or UDF volume
signature (read from the opened file, not judged by its name), not reached
through a link into a dot-directory the path does not name itself. So
`/home/u/isos/virtio-win.iso`, `/run/media/u/STICK/win11.iso` and libvirt's
session pool `~/.local/share/libvirt/images/x.iso` work, and `~/.ssh/id_rsa`,
a key renamed `.iso`, or `~/isos/x.iso` linking into `~/.ssh` do not. The rule
keeps keys and tokens out, not secrets packaged as ISOs: a cloud-init seed or
an `autounattend` ISO in a home directory is a file the Admin names on
purpose.

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
  link, then closes it; qemu opens the path again when the VM starts (and a
  memory snapshot's revert reopens the file its saved image names, which is
  judged the same way first). In a
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
- **A file the directory's owner can replace.** The checks judge the file
  they open; libvirt (which relabels the file for qemu) and qemu then open
  the path again. Whoever owns the directory — a local user under `/home`,
  say — can swap the name for a link to another file in between, and that
  start then gets whatever it names, past the refused places, as with any
  path before these checks. A library directory only the daemon writes, and
  `/run/media` on vfat or exfat (no links), are not exposed. Handing qemu the
  judged file itself (libvirt's fd passing) is the fix that removes the
  window.
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
ceph full copy is `rbd export | rbd import` into a fresh name of its own,
renamed into place only once it is recorded (`rbd rename` refuses an existing
name). Every
command keeps `--` before its positional arguments. The copy carries its
owner record — project, VM, disk — as zfs user properties (`litevirt:*`) or
rbd image metadata (`litevirt.*`). A ceph copy runs its source side
(snapshot, export) with the SOURCE pool's own `conf`, `keyring` and `id`, and
its destination side (check, import, metadata) with the destination pool's,
so a copy between two ceph clusters uses each cluster's own credentials. The
per-copy source snapshot is removed afterwards, and a copy that fails after it
was received is removed rather than left unrecorded — only the image the copy
itself created, never the destination name, which an image created in the
meantime may hold. A btrfs disk takes the
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
