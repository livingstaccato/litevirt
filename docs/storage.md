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
| `iscsi` | IQN | unused | **one pre-provisioned LUN per pool, and so one disk** — see [iSCSI: one LUN, one disk](#iscsi-one-lun-one-disk) |
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
driver is asked to tear down (unmount NFS; for iSCSI, log out of the target
and remove its open-iscsi node record at the pool's portal, so iscsid does not
log in to it again at its next start) on a best-effort basis but failure does not block the delete — operators
who hit "rm" likely want the pool gone regardless. The underlying
mount, if any, stays until manually cleaned up.

### Which pool rows a host acts on

Pool rows are cluster state: every host holds every host's rows, and a row
reaches a host by replication whichever member wrote it. A host therefore acts
on a row naming it only when it stands behind that row. A row naming a place on
the host's filesystem (a `local` or `dir` target, a `btrfs` source) or an `nfs`
export (with or without a target: its mount point is the target, or
`<data_dir>/mounts/<source>`) is used only when it is one of these, with the
same driver, source, target and, for `nfs`, mount options:

- **in the host's `config.yaml`** (`storage_pools:`; with none configured, the
  implicit default pool);
- **created on that host**: `lv pool create` (also with `--host`, through the
  UI, the REST API or another node) runs on the pool's host, which records the
  pool in its local ledger `<data_dir>/pool-trust.json` (mode 0600, never
  replicated) before it writes the row. The daemon's own default pool and
  global ISO library are recorded there as the daemon writes them;
- **confirmed on that host** with `lv pool trust`, recorded in the same ledger;
- **in the daemon's own pool areas**: a `local` or `dir` pool whose directory is
  `<data_dir>/disks` or a directory inside `<data_dir>/pools/` or
  `<data_dir>/mounts/`, as written and with symlinks resolved. The areas are
  taken as this host resolves them, so a `pools/` or `disks/` that is itself a
  symlink to a bigger volume is still the daemon's; a symlink inside `pools/`
  pointing elsewhere is not. A resolved area outside the data directory counts
  only where a pool could be: not the filesystem root, a system directory, the
  PKI directory, or a parent of the data directory (a `pools/` linked to
  `/var/lib` does not make every directory under it the daemon's).

An `nfs` pool's mount options are compared in their order, as mount takes them
(of two conflicting options the last wins), with spacing, exact repeats and the
`nosuid,nodev,noexec,nosymfollow,nosharecache` every mount sets, in any case,
not counting; a quoted value (`context="a,b"`) is one option. A config `nfs`
pool, with or without a target, mounts with the options in `config.yaml` only,
never those on its row. Rows of `ceph`, `iscsi`, `zfs` and `lvm-thin` pools,
which name no host directory, are not affected.

Any other row is **untrusted**. The host does not use it for anything: it is
not a disk root for a migration receive or a disk create, it is not mounted,
nothing is uploaded to, deleted from or listed in it, the staging and replica
sweeps and the upgrade preflight's overlay scan skip it, and the capacity
refresh does not rewrite it. The host raises `pool_row_untrusted` naming it
(see
[diagnostics.md](diagnostics.md#a-host-has-pool-rows-it-does-not-trust-pool_row_untrusted)).
A content call or write that names it is refused with the command that
confirms it; a disk placed by pool name finds no such pool on the host.

```bash
lv pool trust vmstore --host host-b            # shows host-b's row, asks y/N
lv pool trust vmstore --host host-b \
    --expect-driver dir --expect-target /srv/vmstore   # without a terminal
lv pool delete vmstore --host host-b           # or remove a row you did not make
```

`lv pool trust` asks the pool's host for its row and prints its driver, source,
target and mount options, and why the host does not trust it. On a terminal it
then asks y/N — unless a value is not plain printable text (a control, format,
separator, invisible or filler character), is longer than 1024 bytes, or the
target is not in clean form (it names the clean form it would be used as):
such a row is shown escaped and cut, and is not confirmed interactively, since
what a terminal shows would not be exactly the row; without a terminal it needs
the values you checked, `--expect-driver`
and `--expect-target`, plus `--expect-source` and `--expect-mount-options` when
the row has them, and refuses on any difference. What is sent is what you
confirmed, never a fresh read of the row: the host records it only when its row
is exactly that, and refuses if the row changed after it was shown.

Once confirmed, the daemon writes in that directory as root, so trusting needs
what naming the path in a create needs: `storage.hostpath` at `/` (the Admin
role), judged on the exact values sent, and the system and litevirt-internal
directories are refused to everyone. Each confirmation of a valid pool name is
audited as `storage.pool.trust` under the operator who made it, refusals
included, on the node it entered and on the pool's host, with the values it
carried quoted. A pool create is audited the same way as
`storage.pool.create`, refusals included, here or on both nodes when it is
forwarded.

Deleting an untrusted row removes the row only: nothing at the place it names
is unmounted, logged out of or removed. Deleting a pool also takes it out of
the host's ledger, so a row of that name that comes back is not trusted on
the strength of the old one.

This guards against rows that arrive by replication. A cluster member's own
host certificate can still call a pool create or confirmation on another host
directly, as every forwarded call between hosts can.

**Upgrading.** The first time a build with the ledger starts on a host, it
adopts the host's existing pools into the ledger, logged as `storage pool
trust: upgrade adoption ran`. It runs until the ledger records that it has run
(not merely until a ledger file exists), so the daemon recording its own
default pool and ISO library does not stop it. See also
[upgrades.md](upgrades.md#pool-trust-after-upgrade). A row is adopted when the host's own disk shows it
in use, and the guard is the disk itself: a file recorded on the pool is a
qcow2 image (a regular file, not a symlink) whose directory, with symlinks
resolved, IS the pool's directory, resolved — a parent of a real pool's
directory, or a directory with the disk deeper down, is not that. The disk and
VM rows that name the file are replicated, so they only point at candidates. An
`nfs` pool mounted under `<data_dir>/mounts/` is also adopted when its export is
mounted there. An `nfs` pool whose export is not mounted at that start (an
upgrade together with a reboot) is judged once more, by the same rule, the
first time its export mounts: the daemon mounts it hardened at a staging point
in `<data_dir>/mounts/` — never at the target the untrusted row names — reads
the disk there, and unmounts it. A directory that merely exists, or a row naming a file that is
not a qcow2 image directly in it, is not enough, so a forged row written before
the upgrade is not adopted. Pools that are not adopted (an empty pool
outside the pool areas, a pool of raw images or ISOs only, a pool whose disks
are in subdirectories, a pool created while the host was rolled back to a build
without the ledger) are held untrusted until confirmed with `lv pool trust`. The adoption runs once; a row arriving later is trusted only
through a create or a confirmation on its host.

A ledger that cannot be read is kept as `pool-trust.json.corrupt-<time>` before
anything is written, none of its entries is trusted, no adoption runs over it,
and `pool_row_untrusted` names the kept copy until it is removed. Its pools are
held until confirmed again.

The ledger is local, so a rolling upgrade needs no coordination: a host on an
older build acts on every row naming it, as before, and `lv pool trust`
against it is refused as having nothing to confirm.

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
`/var/run` or `/var/spool`; `/var/lib/litevirt-gitops` (the gitops working
tree's default home); the daemon's PKI directory; the data directory and any
directory containing it; and, inside the data directory, the daemon's own state: every child the daemon creates
there (`state.db` and its WAL, `pki`, `vms`, `images`, `imports`,
`cloudinit`, `nvram`, `iso-identity`, the audit and capability markers, any
dot-name, … — `dataDirOwned` in `internal/storage/hostpath.go` is the list)
and anything in one, anything inside `disks/` (a pool may be `disks/`
itself), and the roots of the `mounts/` and `pools/` areas (a pool is a
directory inside one). Any other directory in the data directory —
`/var/lib/litevirt/fastpool`, as earlier releases allowed — is an ordinary
host path: an admin may name it, and nobody else. `/var/lib/litevirt`, the
default data directory, is judged the same way even when `data_dir` is
elsewhere (the backup session keeps its scratch there). The data directory
is compared by whole path components, so a sibling such as
`/var/lib/litevirt-labtest` is an ordinary host path too. The list is a backstop, not exhaustive: `/opt`, `/srv`,
`/var/log` and `/var/tmp` are left to the admin who names them. A target
is judged both as written and after resolving symlinks, so a link at an
innocent name does not reach a refused directory. Authority is checked on the
node the request enters, so during a rolling upgrade an entry node on an older
build does not check it; the directory check runs there and again on the
pool's host.

### File modes

A disk file is the guest's data, so every one litevirt writes is readable and
writable by its owner only (`0600`): a new disk, an overlay, a clone, an image
made from a VM's disk, a restore, a promoted replica, the copy a migration or a
replication writes on its target, a cloud-init seed (it carries the user-data)
and a snapshot's firmware bundle. qemu, which runs as the distro's qemu user,
opens a disk as its owner: libvirt's default `dynamic_ownership` chowns every
image of a disk's chain to that user when the domain starts. Pulled base images
were already `0600`. Snapshot overlays and memory images libvirt makes itself
are narrowed to their owner once the snapshot is taken.

A directory litevirt makes to hold disks — the data directory's `disks`,
`images` and `cloudinit` on a new host, a pool directory (made for a disk, an
import, a clone, a restore, a replica, a hotplugged disk, an upload, or the
destination of a migration or a live move), a btrfs disk's subvolume, an NVRAM
or snapshot directory — is `0711`: every user can reach a
file in it by name, which qemu needs (libvirt labels files, never the
directories above them), and nobody but root can list it.

Nothing that already exists is changed: a disk or directory an earlier release
made keeps its mode. A copy of one — a migration's, a restore's — is a new file
and is `0600`. Installer ISOs in a library stay `0644`: they are shared,
read-only install media.

A host where libvirt does not chown disks (`dynamic_ownership = 0`) and qemu is
not root could not open a writable `0644` disk either; it runs qemu as root, for
which `0600` is the same. On a root-squashed NFS export, the daemon's files
belong to the export's anonymous user, so qemu opens them as their owner only
when that user is qemu's (`anonuid`), which a writable disk needed before too.
Read-only files are the one change there: a cloud-init seed or a backing file
the daemon writes onto a plain root-squashed export (anonymous user not qemu's)
was readable by qemu as "other" and no longer is, and libvirt cannot chown it.
Put the data directory and image-backed disks on such an export only with
`anonuid` set to qemu's user, or with `no_root_squash`.

A narrowing is never what fails an operation: on a filesystem that refuses
chmod, the file keeps the mode it was made with — already `0600` for every disk
litevirt makes — and the daemon logs a warning naming it.

The cluster database, `<data_dir>/state.db`, is `0600` and root's, as are the
`state.db-wal` and `state.db-shm` files SQLite keeps beside it (they take the
database's mode). It holds every credential the cluster has: password hashes,
API tokens, the credential tables. It is the one existing file that is
narrowed in place. Earlier releases made it `0644`, readable by any local
user, so the daemon narrows it and its `-wal`, `-shm` and `-journal` files at
every start. Nothing else in the data directory is touched. Nothing but root
opens the database: the daemon, `lv user reset-admin`, the `lv sg ls`
fallback, and `litevirt schema-migrate` all run as root. If the narrowing
fails, the daemon logs a warning naming the file and starts anyway.

A backup session (a backup, a replication, or a point-in-time volume copy of a
running VM) makes a new directory of its own in each of
`/var/lib/litevirt/backup-scratch` and `/var/lib/litevirt/backup-sock`: qemu
creates the fleecing scratch image in one and binds the NBD socket in the
other, and the daemon reads the disk through that socket. Each name ends in a
random 16-character suffix and is made with a mkdir that fails if the name
exists, so a session never uses a directory that was already there. Each
belongs to the user qemu runs as for that VM (libvirt's DAC label, resolved by
name when it is one) and is `0700`, so no other local user can reach the socket
or the scratch. If that user cannot be read from the domain, or the chown is
refused, the session directory is `01733` instead: every local user may create
entries in it, so it is made one level further down, inside a fresh root-owned
`0711` directory that the session makes with its own unguessable name. Nobody
but root can list either directory, and the fresh one was never readable by
anyone else, so nobody else can find the session directory, not even a process
that opened the parent while an earlier release left it `0777`. Both parent
directories must be root's own `0711` directories. Earlier releases set them to
`0777` at every session; at daemon start and at every session, root's own directory with
another mode is narrowed to `0711` in place (safe, because a session never uses
an entry that was already there). A parent that is another user's, a symlink
or not a directory is renamed aside to `.backup-scratch.aside-<time>-<id>` (or
`.backup-sock…`) beside it, kept with everything in it, and made afresh, with a
warning naming both; remove the set-aside copy once you have looked at it. A
session's directories are removed when it ends, and a crashed session's
scratch, or an earlier release's `<vm>-<disk>.scratch`, is removed by the next
backup of the same disk; that backup's own live session is never touched.

### NFS pools after a reboot

litevirt mounts an `nfs` pool's export itself: at pool create, and at every VM
disk create, move or replicate on the pool. A host reboot unmounts it. Each
host therefore checks the mount of each of its `nfs` pools, at daemon start
and every 30 s after. The check reads the mount table
(`/proc/self/mountinfo`) and does not touch the export. Whether the mount
point lies inside another NFS mount is judged from its path as written. Only
when that finds none does the check resolve the symlinks of the mount point's
parent, which can reach an NFS mount, and that is given up on after 5 s. A
check holds no lock, except the re-check right before a mount, which is bounded
the same way. So a server that does not answer delays a pass by at most 5 s
per such pool, and hangs nothing. A pool create or delete, or a VM start that
needs a mount, waits only for a mount in progress on the host, which is
bounded by that mount's timeout (30 s by default), and gives up when its own
deadline ends. A start whose check gives up goes ahead, as it did before this
check.

**A server that stops answering while its export is mounted.** A hard NFS
mount then blocks every stat, open or listing under it until the server
answers again. litevirt keeps that from holding anything else:

- **Daemon start.** Nothing before the daemon serves gRPC waits on it: the
  sweeps of stale staging and scratch files run in the background or give up
  on a directory after 5 s, a pool's statfs gives up after 5 s (the pool reads
  `error` until it answers, keeping its last capacity), and a step that runs
  a command against storage (`mount -o remount`, libvirt's pool refresh) is
  waited for at most 5 s. A daemon (re)start while a server does not answer
  therefore serves, and its peers do not fence the host.
- **Daemon stop.** A graceful stop (`systemctl restart` or `stop`, an
  upgrade) gives the requests in flight 5 s, then stops the gRPC server
  forcibly. A request stuck on the dead mount is not waited for past a
  further 5 s: the daemon exits within about 35 s of the SIGTERM, well inside
  the 2 minutes its peers skip an `upgrading` host, while requests are still
  stuck in an NFS RPC wait (a killable wait, as on lab 2). A thread stuck in
  an uninterruptible wait (writeback, an unmount) can still hold the exit
  until the kernel lets it go.
- **Pool create.** Whether a new pool overlaps an nfs pool is decided from the
  mount table first: a mount point names its own directory, with no call on
  the export. A dir or local pool beside a hung nfs pool is created as usual.
  An overlap that can only be decided by resolving a path on the hung mount (a
  pool inside a parent export mounted by hand, say) is refused with
  `Unavailable` and "cannot verify that the pool does not overlap another
  pool", never allowed because the check timed out. Try again once the server
  answers.
- **VM start.** A start resolves the pool directories of the host to judge
  the VM's disk chain. A mount point is judged from the mount table, so a VM
  on local storage starts while an nfs pool's server does not answer. The
  other pool directories are resolved all at once, each under its own 5 s
  bound, so several pools on dead mounts delay a start by about 5 s in all,
  not 5 s each. A VM whose disk is on the dead pool is refused with
  `Unavailable` ("its storage does not answer") instead of holding the VM's
  lock (and a stop of it) for as long as the server does not answer. The
  first refusal can take up to 20 s, the start check's own bound, because
  reading the disk's header waits that long; while that mount is known not
  to answer, later ones are immediate. The first thing a start (and a
  define, move, migrate, backup, copy or delete) does is look for the disk's
  point-in-time overlay, under the VM's lock; that look gives up after 5 s
  too. Whether an overlay is there is then unknown, and the start is refused
  with `Unavailable` rather than made on a disk that may lack the guest's
  newest writes. The reconciler's start of such a VM (a failover, an onboot
  autostart, a restart of a VM whose domain died) is deferred instead: the VM
  waits in `starting` (a failover in `pending`, its proof kept) and the next
  pass starts it once the storage answers, and the overlay sweep at daemon start passes the VM over
  instead of holding its lock.
- **A start libvirt does not answer.** These checks cannot see storage that
  stops answering after they have passed, while libvirt starts the domain. If
  libvirt has not answered within 5 minutes, `lv start` answers `Unavailable`
  ("libvirt has not answered the start"). The start is not cancelled: it
  keeps the VM's lock and start lease, the VM's row says `starting` (on every
  host), and its outcome (`running`, or the row put back) is recorded and
  shown in `lv events` when libvirt answers. If the daemon restarts first,
  the reconciler records the VM `running`, and the start in `lv events`,
  once libvirt has started the domain; while the domain does not run, the
  start lease stands until it runs out (10 minutes), and the reconciler then
  starts the VM itself. Meanwhile `lv stop` and
  `lv restart` answer `Unavailable` at once; `lv stop --force` cancels the
  start (the VM is recorded stopped now, and a domain libvirt starts for it
  is destroyed when it answers; the cancel is kept in
  `<data_dir>/cancelled-starts.json`, so this holds across a daemon restart,
  unless the VM was started again since). A VM in `error` stays in `error`
  (its set-aside disk copies stay held), and a domain libvirt starts for it is
  destroyed the same way. A kept cancel ends once its domain has run (seen
  running, or libvirt answered the start) and does not run any more, or the VM
  is started, deleted or moved, or the host has booted, or the libvirt daemon
  (`libvirtd` or `virtqemud`, when exactly one runs on the host) has
  restarted since; it is not ended by its age.
  While it is kept, a VM in `error` is neither recorded running from a domain
  that runs nor restarted by its restart policy; `lv start` ends it. A cancel
  kept longer than an hour raises `cancelled_start_kept` on the host, and a
  `cancelled-starts.json` that cannot be read raises
  `cancelled_starts_unreadable` (see [diagnostics.md](diagnostics.md)). Other calls on the VM, `lv rm` among them,
  wait for the start. `lv ls` and `lv inspect` on that host report a VM
  libvirt does not answer for as `VM_UNKNOWN` within a few seconds, and the
  other VMs there as usual. `lv inspect` of a running VM whose VNC console
  libvirt does not answer for says so (`vnc_unknown`, which `lv vnc` prints)
  rather than reporting no console or no password. The host's background
  passes (the reconcile walk and its sweeps, the restart-policy pass) skip a
  VM libvirt does not answer for, deciding and changing nothing about it
  until it answers, and reconcile the other VMs; a sweep over all of the
  host's domains (self-fence, ownership repair, orphan report) is skipped
  while libvirt does not answer the domain list, which a domain it hangs on
  holds.
- **The reconcile pass.** One pass on a host serves all of its VMs, so no
  look it makes at a disk file waits on the server. The check that each disk
  of a VM it starts is there, the set-aside of an old copy at a host-local
  disk's path on a failover onto the host, the define of a stopped VM a
  failover moved to the host, and the set-aside of a disk a failover left on
  the host each give up after 5 s. A disk that does not answer is never
  taken as missing: no start is refused as "disk missing" and no disk is
  rebuilt from its image for it. The start is deferred as above, and nothing
  is defined or renamed until a later pass gets an answer. The VMs after it
  in the pass are reconciled as usual, so one dead pool costs the pass about
  5 s, not the length of the outage, when the disks' paths lie under the
  pool's mount as written: the first look that goes unanswered marks the
  mount, and every later look under it gives up at once. A disk reached
  through a symlink into the mount is not recognised as on it, so each such
  path costs its own 5 s the first time it is looked at (N of them, about
  5·N s in that pass); later passes give up on them at once while those
  looks are still stuck.
- **Image prune and snapshot delete or revert.** Whether a file is in use is
  never decided on a guess. When resolving a path in the image store or a
  disk's chain does not answer, or listing the image store (a store whose
  directory is a link onto an NFS mount, say) or a pool directory does not
  answer within 5 s, the prune fails with "nothing is pruned", and
  a snapshot delete or revert is refused with `Unavailable`. Retry once the
  server answers. A snapshot delete or revert reads the header chain of
  every VM disk on the host, each disk's under a 5 s bound, and so does a
  prune's scan, one header at a time. While another VM's disk is on a mount
  whose server does not answer, the delete or revert is refused with
  `Unavailable` (that disk counts as a user of the file, never as "not built
  on it"), and the prune fails with "nothing is pruned". A VM delete whose
  kept disk's chain does not answer keeps every file.
- **Superseded disk copies.** The hourly sweep and `lv host superseded-disks`
  list the copies in every host-local disk directory, and each listing,
  lookup, removal and rename of a copy (the set-aside on a failover onto the
  host, on a host's return, and on `--restore`) gives up after 5 s. A
  directory or copy that does not answer is never taken as empty or gone:
  the sweep removes nothing under it, sweeps the directories that answered,
  and logs `superseded disk sweep` with the no-answer; `lv host
  superseded-disks` (a list, `--purge`, `--remove` or `--restore`) fails with
  it rather than show a list missing those copies. A rename that gave up may
  still land once the server answers: the copy then sits under its
  set-aside name, where the listing finds it and the retention keeps it
  while its VM exists.
- After one call under a mount has gone unanswered for 5 s, further calls
  under the same mount fail at once until it returns.

- **Not mounted since the daemon started** (the reboot case): the export is
  mounted, with the pool's mount options and the hardening a create uses
  (`nosuid,nodev,noexec`, plus `nosymfollow` where the kernel has it). The
  journal says `NFS pool's export was not mounted since the daemon started;
  mounted`. A mount that fails is retried every 30 s. A mount still running
  after 5 s (its server does not answer) marks the pool `degraded` with that
  reason while it runs; it is given up at its timeout, and `mount`'s whole
  process group (`mount.nfs` included) is killed then, so a mount cannot
  finish after litevirt reported it failed.
- **Unmounted while the daemon ran** (`umount <mount point>`): left unmounted.
  A hard NFS mount of a server that does not answer stays in the mount table,
  so an export that disappears from it was unmounted, and litevirt takes that
  as deliberate. To mount it again, restart the daemon on the host. A VM disk
  create, move or replicate on the pool also mounts it, as it always did, and
  so does a reboot. (A pool create cannot: the pool already exists.) This
  holds for a lazy unmount too: `umount -l` of a mount whose server does not
  answer is an operator's unmount, and the 30 s check does **not** mount the
  export again — mount it by hand (or restart the daemon). Once it is mounted
  again, the pool reads `active` at the next check, and calls that are still
  stuck on the old, detached mount hold nothing on the new one: the
  per-mount fail-fast below is keyed by the mount itself, not its directory.
- **Never over anything.** A mount point that is a symlink, is not a
  directory, or holds any file is not mounted over: the mount would hide what
  is there, or land somewhere else. Files in an unmounted mount point were
  written while the export was not mounted, so they are not on it. Move them
  out; the next check mounts the export. The mount point is opened (following
  no symlink) and judged through that descriptor, which is kept across the
  mount. A file written into it while the mount is made is found under the
  mount afterwards, and the export is unmounted again and the mount refused.
  `mount` takes a path, so a mount point replaced by a symlink between the
  check and the mount is caught only after it: the mount point then holds no
  mount, and the refusal says so (`findmnt -S <source>` shows where it
  landed).
- **Another NFS mount at the mount point** counts as mounted: the export
  mounted by hand, or spelled another way (a host name where the pool has the
  address). Its files are there. The pool's own check at use then judges
  whether it is the pool's export (see "Host paths" above). A mount whose
  source differs from the pool's spelling is logged once as a warning.
- **A mount at the mount point that is not NFS** is left alone. Unmount it,
  and the next check mounts the pool's export there.
- **A pool whose directory lies inside another NFS mount** (a parent export
  mounted by hand) is left as it is: its files are reachable.

This covers a pool with a `--target` too, since litevirt mounts that one
itself as well. Pool delete unmounts the export unless another pool of the
host uses it; a `--target` pool's mount is not unmounted at delete, as before
(it may be shared with something else). No check or start mounts a deleted
pool back.

While a pool's export is not mounted, its row's state is `degraded` (`lv pool
ls`, `lv pool inspect`), not `active`, and its host raises `nfs_mount_missing`
with the reason
([diagnostics.md](diagnostics.md#an-nfs-pool-is-not-mounted-nfs_mount_missing)).
Both clear on the first check that finds it mounted. An older build shows the
state as it is recorded, and does not mount anything after a reboot. The
daemon's periodic pool registration can briefly write `active` over a fresh
`degraded` (or the reverse); the next check, within 30 s, corrects it.

**Starting a VM.** Every start path checks the mount of each of the VM's disks
on an `nfs` pool first: `lv start`, `lv restart`, onboot, an HA restart, a
failover and a promotion. An export not mounted since the daemon started is
mounted, as above. Otherwise the start is refused with the reason:

```
start "web-1": disk root is on nfs pool "shared", whose export is not mounted on this host: ...
```

Such a start failed before this check too, at qemu's open of the disk (`Cannot
access storage file … No such file or directory`). Worse, a file of the
disk's name left in the empty mount point would have started the guest on
that local file instead of the export's. The refusal is answered as
`Unavailable`, as that failure was. The reconciler (onboot, HA restart,
failover) tries the start again on its later passes. The VM checker's
restarts (a guest that stopped, a restart policy) set the VM to `error`, as a
failed start always did there. Automated refusals are counted in
`litevirt_runtime_action_refused_total{reason="storage_not_mounted"}`, not
under `hardware_blocked`. A start does not retry a mount that failed within the last
30 s, and gives up waiting for another mount on the host when its own deadline
ends.

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

Deleting a `local` pool on its own directory (`<data_dir>/pools/<name>`, which
the daemon makes for a target-less one) removes the
daemon's own directories in it first: the replica area's empty directories,
and the upload markers (`.litevirt-uploads`) of uploads no longer there. A
pool still holding replicas or files is refused, naming them; with `--force`
it is deleted anyway, as it always was, and no file is deleted: the replicas
in its area (which may be a VM's only copy while its host is down) and any
other file stay where they are, the log names them, and the directory is
kept — a new pool of that name is refused the directory until it is emptied.
Delete the replicas you no longer want by name (`DeleteStoragePoolContent`) first.

Any other pool on a directory — every `dir` pool, even one at
`<data_dir>/pools/<name>`, and a `local` pool with another `--target` — is
not refused for the replicas or files it holds (references to it, such as a
replication schedule, still need `--force`): its directory is the
operator's, so deleting the pool touches nothing in it, and every file and
replica stays where it is.

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

A failed create or clone removes the disks and cloud-init seed it made, and
only those: each is held open from when it is made, so a file put at the same
path since is never mistaken for it. On a btrfs pool it then removes the
subvolume the disk was made in, only while that subvolume is empty, so a retry
of the name can make it again. One it could not hold open (an open
refused by the file limit or the file's mode), or could not remove, is left
where it is, and the create's or clone's error names each such file and why
(`the failed create left what it made: ...`). Remove it once nothing uses it,
or a retry of the same name may be refused as above.

Reading a disk's backing chain — a full clone, an image built from a VM, a
cold migration's flatten, a move or copy with qemu-img, and every VM start
(qemu and libvirt follow the chain too) — follows each layer's
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
  its VMs, its recorded replica, or a file one of its users uploaded — or the
  base an external snapshot of the VM left beside its overlay: same
  directory, the disk's own `<vm>-<disk>` stem, claimed by no other VM's row.
  This holds after the snapshot is reverted or deleted too, when the disk
  stays on an overlay named after it. A pool root disk an earlier build made
  names its image by the relative name the VM was created from (recorded as
  its `backing_image`), which qemu finds beside the disk: that file is
  accepted too, when no upload or replica record and no other project's VM
  disk claims it.

A layer a user uploaded into a pool is the uploader's to write, header
included: what it names is accepted only as an image or a file the VM's
project owns by record, never for the directory it is in. Another project's
file is refused wherever it sits, unless a record ties it to the layer naming
it. At a start, a backing that is missing or refused refuses the start
(`FailedPrecondition`), naming the disk and the layer. A move, a restore or a copy that leaves a disk
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
  A stopped or cold move (`--cold`, a stopped Secure Boot or vTPM VM, a drain of
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
resolving symlinks: the PKI directory, the daemon's own state in the data
directory (`state.db`, `cloudinit/`, `nvram/`, …, as for pools above) and
anything in `disks/` other than `disks/uploads/` and the ISO images directly
in `disks/` (the global library `pools/isos/` is under `pools/`; another
directory in the data directory is an ordinary host path), and anything under `/boot`,
`/dev`, `/etc`, `/proc`, `/sys`, `/var/backups`, `/var/spool`,
`/var/lib/lxc`, `/var/lib/libvirt/qemu` or `/var/lib/libvirt/swtpm`. `/usr` is
allowed (`virtio-win` installs there).

An older cluster's default pool is `<data_dir>/disks` itself, and uploads into
it used to land there, beside every project's VM disks: the UI offered them as
`/var/lib/litevirt/disks/<name>.iso`. Such a file is given to a guest only when
it is an optical disc image (as below) with a single hard link, and no VM disk
row on any host names it — as its file, a backing image or a linked clone's
base — and no replica record gives it to a VM. A VM created with that path
keeps starting, an Admin may name it, and a non-admin names it through the
pool (`default/<name>.iso`, or the path, which is taken as that reference),
where another project's pool mapping the same directory is judged as for any
shared pool directory.

Under `/home`, `/root` and `/run` (`/var/run`) — where an ISO downloaded into
a home directory (root's included), or a USB stick udisks mounts under
`/run/media`, lives next to `~/.ssh` and runtime secrets — a file is given to
a guest only when it is an
optical disc image: a regular file carrying an ISO 9660 or UDF volume
signature (read from the opened file, not judged by its name), not reached
through a link into a dot-directory the path does not name itself. So
`/home/u/isos/virtio-win.iso`, `/run/media/u/STICK/win11.iso` and libvirt's
session pool `~/.local/share/libvirt/images/x.iso` work (so does
`/root/debian-12.iso`, for `lv iso pull --from-host-path` too), and
`~/.ssh/id_rsa`,
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

`lv rebuild <vm>` and a recreate-class rolling update create the VM again
from its spec, and keep its installer ISO as it was classified at its create:
a host path (an Admin's, or one stored before `iso_scope`) stays one, judged
on the host as at every start, whoever runs the rebuild; a pool ISO is judged
again as its recorded kind. Anything the new create would refuse that the
teardown does not change — the ISO included — is refused first, and the VM is
left as it was. A VM with an installer ISO is placed before the teardown, by
the same placement rules a create uses (its spec's pin and labels included,
the VM's own share released), so it lands where it would have after the
teardown — on another host when its own is in maintenance or full, and never
on the node running a rollout for that reason alone. The host chosen then
judges the ISO as its create will, for the same caller and with the same
classification; if it would refuse (it does not have the file, say), the
rebuild is refused before anything is torn down. A chosen host on an older
build, which judges no installer ISO at its create, is not asked.

Any rebuild or recreate, with an ISO or without, may create the VM on a host
whose replica has not yet applied the tombstone of the VM it replaces — the
pinned or chosen host, or the node running a rollout. The create carries that
VM as its delete saw it (name, incarnation, host, owner epoch, spec
generation and identity; for a rolling recreate, as the VM's own host
reports the row it deleted, not as the node running the rollout last heard),
and that host does not refuse the create for a
stale copy the delete kills: it waits up to ten seconds for the tombstone to
arrive and, if it does not, retires the copy itself, releasing its addresses
as a delete does. Everything else is still refused as before: a live VM of
the same name that is another incarnation, a copy that has moved past what
the delete saw (a failover the deleting node had not heard of), and any VM of
that name while the host has a domain of it. A recreate whose delete found
the VM already gone names nothing. A host on an older build ignores the
identity; the node that forwards the create then retries it for the same ten
seconds.

If the create fails after the teardown for any reason, the error says what was
torn down and where, and the spec the create was given is kept on that node
under `<data_dir>/recreate-failed/`, one file per failure, readable by root
only, to re-create the VM from. Guard settings on a NIC that cannot be guarded
(a direct or SR-IOV NIC, docs/firewall.md) are left out of it, as the create
left them out. The directory keeps the newest 50 files and
none older than 30 days; copy out a spec you still need.

A disk on an iSCSI LUN is not torn down: the LUN keeps the guest's data. Create
the VM again under the **same name**, in the same project, on the same pools (`lv compose up`, or
`lv run`) and it takes its own LUN over as it is — nothing is written over it,
and no `overwrite` is needed, even for a root disk built on an image (see
[iSCSI: one LUN, one disk](#iscsi-one-lun-one-disk)).

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

## Ceph RBD pools

A `ceph` pool puts VM disks in an RBD pool of an existing Ceph cluster (one
litevirt deployed with `lv host ceph`, or any other). Every host that runs
the pool's VMs authenticates with a **restricted client key** — never
`client.admin`, and no admin keyring on any node.

### Setting one up

On the Ceph cluster, create the RBD pool and a client that can use only it:

```bash
ceph osd pool create lv
rbd pool init lv
ceph auth get-or-create client.litevirt mon 'profile rbd' osd 'profile rbd pool=lv' \
    > ceph.client.litevirt.keyring
```

On every litevirt host, install the client tools and the qemu RBD driver
(`ceph-common` and, on Debian/Ubuntu, `qemu-block-extra`), copy the cluster's
`/etc/ceph/ceph.conf`, and install the keyring as
`/etc/ceph/ceph.client.litevirt.keyring`, mode 0600, **at the same path on
every host. Then create the pool, under the same name, on each host:

```bash
lv pool create ceph --driver ceph --source lv --host host-a \
    --option id=litevirt \
    --option conf=/etc/ceph/ceph.conf \
    --option keyring=/etc/ceph/ceph.client.litevirt.keyring
```

`--option id=` is the client name without `client.`; a keyring with no id is
`client.admin`'s, as for the `rbd` CLI. With an id and no `keyring` option,
`/etc/ceph/ceph.client.<id>.keyring` is used when it exists. `--option
mon_host=` lists the monitors explicitly; otherwise they are read from the
conf's `mon_host` (cephadm's `[v2:…,v1:…]` form is understood, and the v1
address is used). A conf other than `/etc/ceph/ceph.conf` must name
`mon_host`, or a VM disk on the pool is refused: qemu reads only the default
conf by itself. A conf or keyring path may not contain `:`, `\`, `;` or `=`.

### How a VM disk authenticates

qemu opens an RBD disk itself, and a libvirt domain cannot name a keyring
file. So for each ceph pool on a host, the daemon defines a **libvirt ceph
secret** holding the pool's client's key, read from the keyring the host's
pool names:

- The secret's UUID is derived from the pool's name and the client id
  (UUIDv5) — not from the keyring's path — so every host with the pool names
  the same secret, wherever it keeps the keyring. Its usage name is
  `litevirt/ceph/<uuid>`.
- It is **ephemeral** (never written under `/etc/libvirt`) and **private**
  (libvirt will not hand the value back). The key never appears in a log, an
  event or an error.
- It is defined when the pool is created, when the daemon starts, every 30
  seconds after (a secret libvirtd lost on a restart is put back, and a value
  is re-set when the keyring on disk changed), before every start of a VM with
  a ceph disk (including failover restarts and promotes), and on a live
  migration's target when the source prepares it — the target refuses the
  migration, with the reason, if it cannot.
- It is removed once no ceph pool on the host and no disk recorded on the host
  uses it — not while a disk still does, even after its pool was deleted; such
  a disk's secret is defined from the keyring its own recorded path names.

**Every host's keyring must hold the same key.** Each host records a short
fingerprint of its key (one-way, `ceph_key_fp`) on its own row of the pool.
A host whose key differs from another host's raises the degraded condition
`ceph_keyring_mismatch` (see [diagnostics.md](diagnostics.md)), naming the
host. It is a diagnostic: rows of hosts that are down, removed or mid key
rotation cannot vouch for anyone, so no start is refused by it. Instead every
start of a VM with a ceph disk (failover restarts included) first proves the
host's own key with `rbd info` as the pool's client. A VM's disks are probed
at the same time, bounded together by 8 s and by rbd's own 5 s monitor and OSD
timeouts (rbd runs under the C locale, so its messages are read the same on
any host). A key a probe proved is taken as proven for 2 minutes for every
disk of that pool and client — until its keyring changes — so the VMs a
failover starts after the first on a pool need no probe; an image that is
gone is still reported, by qemu, when the domain starts. The start refuses for
good, with the reason, only when Ceph is unambiguous that an operator must
act: permission denied (naming the keyring), or the image not in a pool that
answers. Anything else — Ceph not answering in time, a cluster re-electing
its monitors, an ambiguous error — is transient. A failover, onboot autostart
or restart of a VM whose domain died is then **deferred**, never put in
`error`: it waits in `starting` (a failover in `pending`, its proof kept) and
the next reconcile pass starts it. A start the reconcile pass has no time
left to probe for is deferred before anything is done for it — except the
pass's first probe, which runs on whatever time is left (from 2 s), so every
pass makes progress. A probe Ceph did not answer is remembered for 15 s
(about one pass): the reconcile pass defers the other VMs on that pool at
once, without a probe each (an operator's `lv start` always probes). The next
pass takes the deferred VMs first: those deferred for time, then those whose
pool did not answer, the VM whose own probe failed last of them. So a pool
that is down never holds up the VMs on a healthy pool. A live migration onto a host
whose recorded key differs from the source host's is refused before libvirt
is asked.

Each disk's domain definition is a network disk with the monitors as `<host>`
elements and an `<auth username='litevirt'>` naming that secret:

```xml
<disk type='network' device='disk'>
  <driver name='qemu' type='raw'/>
  <source protocol='rbd' name='lv/web-1-root'>
    <host name='10.78.0.22' port='6789'/>
    <auth username='litevirt'>
      <secret type='ceph' uuid='…'/>
    </auth>
  </source>
  <target dev='vda' bus='virtio'/>
</disk>
```

The disk's recorded path (`rbd:lv/web-1-root:id=litevirt:keyring=…:conf=…:lvpool=ceph`)
names the image, the client and the litevirt pool. The **monitors are looked
up each time the domain is defined** (a create, a start, a failover restart):
from the pool on that host — its `mon_host` option, else its conf's — so after
the monitors are re-addressed, updating `/etc/ceph/ceph.conf` (or the pool's
`mon_host`) on the hosts is all a stopped VM needs to start. Only a pool with
a `mon_host` option also writes that list into the path, as the fallback for
a host that does not have the pool. Every start also rewrites the
domain's persistent definition with the monitors its pool resolves to then,
when they differ from the ones it names (a disk recorded before litevirt
named its pool and client in the path is left as it is). A
disk whose pool does not resolve (or resolves to no monitors) keeps the
`<host>` list it has; an empty list is never written. A running VM keeps working (librbd
follows the cluster's monitor map), and a live migration hands the
destination the monitors its pool resolves to at that moment, not the ones the
running domain was defined with, so a re-addressed cluster's VMs migrate
without a restart.

`lv rebuild <vm>` stops and replaces a domain of the VM's name only when it
is the VM's own: it carries the VM's uuid, or it runs on a disk the VM's row
records on that host. An rbd disk counts as the recorded one only on the
same Ceph cluster, meaning the domain's `<host>` monitors and the pool's
share a monitor. The pool's monitors are the one source a domain defined now
is given: its current ones on that host (read from the host's pool table
when the daemon has not loaded the pool yet), else the disk's `mon_host`,
else its conf's; a source behind the one used never counts. A pool of that
name on the host that gives no monitors (not a ceph pool, or its conf cannot
be read) leaves the disk on no cluster that can be told. A domain with no
`<host>` uses the default `/etc/ceph/ceph.conf`, and one that names a
`<config file>` of its own and no monitor is on a cluster that cannot be
told, as is a disk whose conf cannot be read or names no monitor, or that
carries an option a domain cannot be given. Otherwise the rebuild is refused
with nothing changed, and the refusal names the domain's monitors. A domain
defined under a uuid libvirt chose (an older promotion or restore) that
still names monitors that were all replaced is refused this way: undefine
it, or give it the current monitors, then run `lv rebuild <vm>` again.

A pool with neither an id nor a keyring gives its disks no `<auth>`: qemu
then uses Ceph's own defaults, which means `client.admin` and its keyring on
every host. That is how such pools behaved before and is not recommended.

### Disks

- **Data disks** are `rbd create --image-feature layering` images of the
  requested size, named `<vm>-<disk>`.
- **Root disks from an image.** The image is fetched into the host's image
  store by name, as for any pool (auto-pulled from a peer when missing), then
  imported into the RBD pool **once per image content**: converted to raw,
  `rbd import`ed as `lvimage+<image>+<sha256 prefix>`, given a protected
  snapshot `@base`. Each VM's root disk is an `rbd clone` of that snapshot
  (copy-on-write, as Proxmox does for templates on RBD), grown to the size
  asked for (never shrunk). Concurrent imports of the same image on several
  hosts are safe: each imports under a private name and only one rename wins.
  A refreshed image has a new digest and becomes a new base; the old base
  stays while clones of it exist.
- **A failed create** removes every RBD image it created, whatever step failed.
- **Clone** (`lv clone`) copies a ceph disk inside its pool with `rbd deep cp`
  — nothing passes through the host, and a root disk's copy stays a clone of
  the same base. The copy lands in the same pool, which the clone's project
  must be allowed to use, and its size is admitted against that pool's free
  space as a create's disk is. A target pool (`--pool`) places only the VM's
  file disks: a ceph disk is still copied inside its own pool, and is counted
  neither against the target pool nor against the host's filesystem.
  `--mode linked` is refused for a VM with a ceph disk
  (there is no file a qcow2 overlay could back on); auto mode copies.
- **Delete** (`lv rm`) removes the VM's own images. It never removes an
  imported base (`lvimage+…`), an image outside the pool, one that has
  snapshots (as `rbd rm` refuses one, so a clone made from one is never
  orphaned), or one another VM's disk row still names. An image is removed in
  two steps, as `rbd rm` itself does: `rbd trash mv` — quick whatever the
  image's size, and the delete succeeds then — and a background
  `rbd trash rm <pool>/<id>` that deletes its objects (minutes for a large
  image), retried until done and resumed after a daemon restart (the queue is
  kept in `<data_dir>/ceph-trash-purges.json`). A purge that keeps failing is
  named by `ceph_trash_leftover` (see [diagnostics.md](diagnostics.md)).
  An image a client still has open is never moved: a delete waits up to 45 s
  (a killed client's watch lapses in about 30) and then refuses it as
  **in use**, naming the watcher; a rollback of litevirt's own copy waits up
  to a minute. An `rbd status` answer that cannot be read counts as in use.
  A VM's ceph disks wait together, so a VM with several disks a client
  still holds is refused in about 45 s, not 45 s per disk, and the wait never
  outlasts the request's own deadline. `rbd trash mv` does not refuse an image a client
  has open (Ceph 19.2.3), so after the move the image's watchers are listed
  again by id (`rados -p <pool> listwatchers rbd_header.<id>`, from
  `ceph-common` like `rbd`). An image a client opened in between is put back
  under its name with `rbd trash restore` and the delete refused as in use.
  If its watchers cannot be listed, the purge is the guard: `rbd trash rm`
  refuses an image a client has open (exit 16), and such an image is
  **held**: it is never purged automatically, and `ceph_trash_leftover` names
  it with `rbd trash restore <pool>/<id>`. A move is recorded by the image's
  id before it runs. A move that fails, or that a crash interrupts, is
  settled by id: it is purged if the image went to the trash, forgotten if it
  never moved, and held and named if it is in the trash and still under its
  name. A queue file that cannot be read is moved aside
  (`ceph-trash-purges.json.unreadable-<time>`) and named. The pools' trash is
  scanned every 5 minutes for litevirt images no purge on the host tracks,
  and those are named too. An image already gone is not an error —
  but only once the pool itself answers: a delete that cannot reach the
  cluster (a missing keyring or conf) fails instead of reporting success.
  If an interrupted `rbd rm` left the image in the trash, that leftover is
  purged too; an image of that name someone moved to the trash by hand is
  left for them.
- **Clone copies** are made under a private staging name and renamed into
  place, so a failed clone removes only its own copy, never an image that
  already had the destination's name.
- **Not supported on ceph disks yet**: `lv resize-disk`, `lv snapshot create`
  and `lv backup snapshot` refuse a ceph disk up front with that reason.

Unused bases are not removed automatically. To reclaim one, check that it has
no clones and then remove it by hand:

```bash
rbd --id litevirt children --all lv/lvimage+cirros+0123456789abcdef@base   # must print nothing (--all includes clones in the trash)
rbd --id litevirt snap unprotect lv/lvimage+cirros+0123456789abcdef@base
rbd --id litevirt snap purge lv/lvimage+cirros+0123456789abcdef
rbd --id litevirt rm lv/lvimage+cirros+0123456789abcdef
```

### Live migration

A ceph disk is shared storage: a live migration moves only the guest's
memory. The source always asks the target to prepare first (`EnsureDisks`):
the target defines the secret the incoming domain names — the pool's, so the
target needs a ceph pool of the **same name** and client — from its own
keyring, proves that key opens each disk (`rbd info`), and refuses the
migration with the reason when it cannot read its keyring, the key does not
open the disk, its recorded key differs from the source's, or the disk's
storage name is a different pool there. A target that does not have the pool
at all serves the disk from the client and keyring the disk's recorded path
names — if that keyring is readable there and opens the disk — and refuses
otherwise; a target that cannot read its own pool list refuses. An older
target build does not do this: the migration then fails when the target's qemu
opens the disk, and the VM keeps running on the source.

**Rolling upgrades.** A host on a build before ceph VM disks cannot start or
receive one: a failover onto it parks the VM in `error` (it refuses, rather
than rebuilding the disk), and a migration onto it fails with the VM left on
the source. Upgrade every host before relying on ceph HA.

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

**Shut-off VMs** (as libvirt reports them, whatever the VM's record says) —
`qemu-img convert` (without `-U`, so a VM that is in fact still running fails
the copy on qemu's image lock) from source to destination, then the inactive
libvirt domain's disk source is repointed and the disk record is updated in a single
atomic write (host, path, driver, and pool together). The redefine happens *before*
the DB commit, so a mid-move failure rolls back cleanly; if a prior attempt already
repointed the domain at the destination, the copy is skipped so a newer destination is
never clobbered.

**Running, paused or otherwise not shut-off VMs** — libvirt `BlockCopy` mirrors writes into the destination while the VM
keeps running. The persistent domain config and the disk record are moved to the
destination **before** the `BlockJobAbort PIVOT` that swaps the live disk — the pivot is
the irreversible commit, so durable state never lags behind a pivoted guest and no
acknowledged write is lost. Operator-visible downtime: zero. The orchestrator
preallocates the destination, polls progress every ~250 ms, and cancels/rolls back on
context-cancel or pivot failure.

**A move that cannot be rolled back.** When a cutover step fails and the persistent
config cannot be pointed back at the source, a running VM's mirror is left running
(nothing is cancelled or deleted) and the error names both files and the `virsh
blockjob … --pivot` or `--abort` to run. The host keeps a record of such a move, and of
one whose daemon stopped mid-cutover, under `<data_dir>/move-unresolved`, and the VM
carries a `vm.move_unresolved` health condition while it lasts. Before the VM next
starts on that host (`lv start`, an HA, onboot or health-check restart), and before a
cold or live migration, a replication, a clone, an image build or a backup reads its
disk, the disk record is pointed at the file the persistent config names and the record
is removed. The operation is refused instead, with an error naming both files and the
next step, when the config cannot be read or names neither file, when the guest was
writing the source under a mirror and was not pivoted but the config names the
destination, or when the guest was pivoted but the config names the source. A retried
`lv move-volume` settles it the same way and is refused in the same cases; it is never
reported as "nothing to do" while the record remains. Another host (a failover onto
shared storage) honours the condition by what it can prove: when the guest was
pivoted, a start there points the disk record at the destination on a shared pool both
hosts define alike only when the VM's domain there is shut off and its persistent config
names the destination. It is refused when the domain is running, when its config names
the source, and when there is no domain there (a start would rebuild it from the disk
record): the VM may then have run on the source since a failover, so each file may hold
writes the other lacks, and the refusal names both `--accept` exits (docs/diagnostics.md,
"A forked history"). A disk record naming the destination is refused too once the VM
changed hands since the move began; when no pivot was recorded, it is refused whichever file the disk
record names, since the record commit and the pivot may have happened before the holding
host stopped. A refused VM whose holding host is gone is released with `lv health resolve
vm.move_unresolved vm/<vm> --reason "…" --accept <path>`, naming the file to keep of each
such disk, once that host is proven powered off; `lv health` lists each move's files
first (docs/diagnostics.md).

> **Note:** `lv replicate-volume` copies a shut-off VM's disk plainly and a
> running or paused one point-in-time — through a full backup session, or an
> external disk-only snapshot committed back afterwards. Only when neither can
> be made does it fall back to `qemu-img convert -U`, and its final status says
> that copy is NOT point-in-time. See [Backups](backups.md), "How a full replica
> is copied".

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
  downtime); shut-off VMs use the offline convert path. The choice is per VM,
  based on its state as libvirt reports it (a paused VM is mirrored).
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
meantime may hold.

A **btrfs** disk replicated into a btrfs pool is sent natively when it is
alone in its own subvolume directly under its btrfs pool (as the btrfs driver
creates every disk), **standalone** — no backing file, no external data file —
and both pools pass the pool write check (the native path also writes into the
source pool: its send snapshot). A copy never depends on a file outside itself,
so a disk built on a base image takes the qemu-img copy, which flattens it. The
copy is the same new file a qemu-img copy makes, in the target pool's
directory — `<vm>-<disk>-copy-<time>-<id>.qcow2`, or an admin's `--target-path`
there — with the same mode (0600), and it is recorded the same way, so
promotion by name, listings, pruning and deletion treat it like any other copy.
The source subvolume is snapshotted read-only into a private directory beside
it and received into a private directory in the target pool. The received
disk file is checked again (it must be standalone), cloned inside that private
directory (a reflink: no data is copied; a plain copy where the filesystem
cannot) and placed with a rename that refuses an existing name
(`renameat2(RENAME_NOREPLACE)`), so a file created meanwhile is never
replaced; an existing name is refused before anything is sent. A native copy
that fails for any other reason — a read-only or full source pool, a receive or
clone that does not work, a received copy that is not standalone — places
nothing and is logged, and the qemu-img copy is made instead, as for any btrfs
disk before. Everything staged is removed when the copy ends, whether it
succeeded, failed or its client went away. Every private directory
(`.litevirt-send-<time>-<id>`, `.litevirt-recv-<time>-<id>`) carries a marker
file from the moment it is made; one a daemon that died mid-copy left is
removed by the next btrfs copy when it carries that marker, is older than a
day, holds nothing but what the copy puts there, is not a running copy's, and
no disk or pool record uses a file in it. No file in a pool is ever swept,
whatever its name. A btrfs disk anywhere else — a file in the pool's directory
(storage motion puts it there), a disk with no pool, a subvolume that holds
other files, a disk on a base image — and every copy between different
drivers, or to a `--target-path` outside the pool's directory, take the file
copy. What the drivers implement:

- **ZFS** — `zfs snapshot` then `zfs send | zfs recv`. Incremental
  (`-I` since the prior `litevirt-replicate-prev` snapshot) when
  `Incremental: true`.
- **Ceph RBD** — a full copy is `rbd export | rbd import` (creating);
  an incremental is `rbd export-diff --from-snap | rbd import-diff` onto an
  image the replication created. Cross-cluster via SSH wrap on the receive
  side.
- **BTRFS** — `btrfs subvolume snapshot -r`, then `btrfs send | btrfs
  receive`, always a full send (no snapshot is kept between copies), the disk
  file cloned out of what was received; same host only, as the copy is placed
  by a local rename.

Cross-host replication wraps the receive in `ssh <user@host>` so the
sender pipes straight into the remote CLI. Same-host uses a local pipe.

Crash-consistent by default; quiesce-via-guest-agent for application
consistency is a planned follow-up.

## iSCSI: one LUN, one disk

An `iscsi` pool is **one LUN** of one target: the LUN the operator created on
the SAN, named by the pool's `lun` option (default `0`). litevirt does not
carve it up. Every disk created on the pool *is* that LUN — the driver
allocates nothing and hands each disk the same
`/dev/disk/by-path/ip-<portal>-iscsi-<iqn>-lun-<n>` device. Two disks on one
LUN are one block device written by two guests (or twice by one), and corrupt
each other silently.

A LUN is named by its target and LUN number: the same target and LUN reached
through two portals — one per storage subnet, or multipath — is one LUN.

**A create takes a LUN by a voter claim.** The LUN's allocations are decided
one at a time by the cluster's voters — the same single-decree claims recovery
uses ([design/recovery-claims.md](design/recovery-claims.md)), at key
`lun/<target>/lun<n>@<allocation>`. The decided value names the VM (by its
uuid), the disk and the host that ran the create. So:

- two disks of one VM on the same LUN — through one pool or two pools that
  name the same target and LUN — are refused before anything is created;
- a disk on an iscsi pool may not share its name with another disk of the VM
  (`InvalidArgument`, before anything is created): a VM's disks are recorded
  by name, and a LUN with no disk record of its own would be held by nothing
  once the create is done. Two disks of one name on other storage are each
  created on their own storage, as before;
- two creates on two hosts at the same moment cannot both take a LUN: only one
  value is ever decided per allocation. The other is refused naming the VM —
  `Aborted` while that create is still running (retry once it has finished),
  `FailedPrecondition` once it holds the LUN;
- a host cut off from the voters allocates no LUN at all; its create is
  refused `Unavailable`, with each voter's reason;
- a LUN is free again only on **positive evidence** that what took it is gone:
  the host that ran that create, asked by name (an answer from any other host
  does not count), shows the LUN in none of its in-flight creates, its VM rows,
  or its libvirt domains — a guest running with no row still holds it — or
  that host's removal is recorded (its tombstone after `lv host rm`, or a voter
  generation that dropped it). A host this node merely has no row for, or
  cannot reach, holds what it took: `Unavailable`, naming it, until it answers
  or is removed;
- no live VM may use the LUN as a disk or as a **linked clone's base**: a clone
  made from an iscsi VM reads its source's LUN, so deleting the source with
  `--keep-disks` does not free the LUN while the clone exists;
- a create whose VM row cannot be written is undone (domain destroyed), rather
  than leaving a guest on the LUN that no claim can see; a create that fails
  releases its allocation itself.

**Cost.** Each LUN keeps a checkpoint (`lun_resolved/<LUN>` in the replicated
cluster policies): every allocation below it is decided and gone. A create
checks with the voters that an allocation was proposed just below the
checkpoint, then starts its walk at that allocation — deciding it too, since
a value there proves only what came before it — so a checkpoint that is wrong
by any amount is never trusted past a live holder. Every allocation the walk
steps past is decided, never only read. A create therefore pays for the
allocations still open (normally one: the current holder), not for the LUN's
history.

**Which voters.** The adopted voter generation's members decide, a majority of
them. There is no fallback: a cluster with no member generation — automatic
genesis is pending because a host is offline, fenced or in maintenance (see
the `ha.voter.genesis_pending` health condition), or the voters were reset —
allocates no iscsi LUN, and the create is refused (`FailedPrecondition`) until
a generation is adopted: run `lv cluster voter init`, or bring the missing
hosts back so automatic genesis completes.

**Rebuild and rolling recreate.** A VM that is rebuilt (`lv rebuild`) or
re-created by a compose update keeps its LUN **exactly as it is** — nothing is
written to it — but its claim **moves**: before the teardown, the host doing
the rebuild or running the update decides the LUN's next allocation for the
VM, after proving every earlier allocation but the VM's own gone. The new
allocation names two hosts: that host, which holds the claim, and the host
the VM is re-created on (placed before the teardown, so the create goes
exactly there). A LUN is free again only when **both** show nothing; either
one that cannot be asked holds it (`Unavailable`, naming it) until it answers
or is removed (`lv host rm`). So a create that races the teardown, or comes
after the re-create returned but before the VM's rows reached every host, is
refused, whichever host created the VM originally or runs it now. Everything
about the claim is judged before the teardown — no voter majority, a LUN
another create is taking, an image the root disk could not take — and the new
allocation is decided only after all of it passed, so a refused rebuild moves
nothing and nothing about the claim can refuse after the VM is torn down. A
recreate that changes only the VM's image cannot reach a kept root LUN: it is
refused before the teardown unless the root disk sets `overwrite`, which
writes the new image over the old system. The previous incarnation is
recognised by its rows' name and creation time, and its claim by the VM's name
and disk with nothing else holding the LUN — never by a name alone.

The storage of every disk is judged before the teardown, on the host running
the rebuild or update, and must be readable there: a storage that cannot be
read refuses (nothing is deleted), never counts as "no LUN". A storage that is
not a pool on that host is judged where the VM is created — unless the VM's
current disk of that name is an iSCSI LUN, whose claim must move from here:
then the update or rebuild is refused, naming the pool; run it from a host with
that pool. A create, likewise, refuses a disk whose storage does not resolve,
and puts the disk on exactly the storage its claim resolved.

**Re-creating a VM whose re-create was torn down.** If the re-created VM's
create fails after the teardown (a fault), the LUN keeps the guest's disk, and
the moved allocation records that it was kept, for that VM's project and the
incarnation it replaced. A create of the **same VM name and disk, in the same
project**, that takes the LUN next — the documented recovery, `lv compose up`
or `lv run` with the same pools — takes it over **as it is**: a root disk built
on an image is not refused for holding data, and nothing is written over it.
Set `overwrite` on the disk to write the image instead.

Only that VM's own kept LUN is taken over this way. VM names are cluster-wide,
so the check is not the name alone:

- a VM of another name, or of the same name in **another project**, meets a
  LUN that holds data and needs `overwrite`;
- a VM **deleted** gives the LUN up: a plain delete (`lv rm`, a stack
  teardown — not a rebuild's or recreate's own teardown) is recorded on each
  of its LUNs (`lun_plain_delete/<LUN>` in the replicated cluster policies),
  and a later VM of the same name, even in the same project, is a new disk
  that needs `overwrite` — whether or not the deleted VM was ever rebuilt or
  re-created.

The holding host keeps a **durable hold** on the LUN, a record in
`<data_dir>/iscsi-lun-holds/`: it survives a daemon restart, and nothing
releases it on a timer or because the re-create returned, with or without an
error. It is released only on evidence — the re-created incarnation's own rows
(by creation time) have reached that host, or the host the VM was re-created
on shows nothing holding the LUN, or that host is recorded removed. While that
host cannot be asked, the hold stays, however long. The re-created VM's create
takes the LUN over only after confirming the hold still stands, so a create
still on its way when the hold was released (its rebuild given up, or the
holding host restarted) is refused before it starts anything. A rebuild or
recreate of the same VM while an earlier one's hold stands is refused
(`Aborted`) until that hold is released, normally seconds after the earlier
re-create.

A rebuild or recreate that ends **before its create runs** — its delete was
refused (a journaled operation such as a backup holds the VM, its host cannot
be reached, the delete is not allowed) or failed — leaves **no hold**: no guest
was started under the moved claim, and the VM, which still runs, holds its LUN
as it did. Run it again once the cause is gone. The LUN's checkpoint moves to
the moved allocation only once the re-created VM's create has committed, so
refused re-creates, however many, never walk it past the VM that still runs.

**Seeing and clearing holds.** `lv host lun-holds [host]` lists the holds a
host keeps (every host without one): the VM, its LUNs, the host it is
re-created on, since when, and whether its re-create is still running. A hold
that has stood for more than five minutes raises the
`iscsi_lun_hold_standing` warning on its host, naming the VM, its LUNs and the
host it waits for ([diagnostics.md](diagnostics.md#iscsi-lun-holds-iscsi_lun_hold_unreadable-iscsi_lun_hold_standing)).

A hold record that cannot be read fails that host closed: it answers no LUN
question, so every iSCSI create on it, and every create elsewhere that must
ask it, is refused. A read error is retried on the next question; a record
that does not parse (it was edited by hand, or the disk was damaged — records
are written whole, by a rename) stays until it is discarded. Either raises the
critical `iscsi_lun_hold_unreadable` condition on that host, naming the file.

Do not edit or delete a record by hand. `lv host lun-hold discard <lun> --yes`
(admin, audited) moves every record that names `<lun>` — the LUN key the list
shows (`iscsi:<target>/lun<n>`), a hold's token, or a record's file name — to
`<data_dir>/iscsi-lun-holds/discarded/` on that host, where it is kept, and
reloads the host's holds at once, with no restart. Without `--host`, the one
host holding it is found; a hold whose re-create is still running is refused.
A hold is what keeps a second VM off the LUN while the re-created VM's rows
travel, so discard one only once it is safe:

- the VM it names shows running in `lv ls`, on the host the hold names as its
  run host, and its row has reached the hold's own host; or
- that VM no longer exists, and no domain of it is defined on any host.

A record that does not parse names no VM. Identify it from the LUN: the VM
whose pool is that LUN, its rebuild or recreate around the record's time
(`lv events`), and the host that ran it — then check the same two things.

**Upgrading.** Allocation on an iscsi pool needs the release feature
`iscsi_lun_claim` of the release token `release_2026_11_v1`, which opens only
once the whole cluster runs a build that knows LUN claims: an older voter
cannot decide a LUN key, and an older host allocates without asking. Until it
is open every create, rebuild or recreate with a disk on an iscsi pool is
refused with "the cluster upgrade must finish first (iscsi_lun_claim needs
release_2026_11_v1)", naming the hosts still to upgrade (`lv cluster
upgrade-status`). Running VMs, and deleting them, are not affected. Refusing is
safer than the silent sharing older builds allowed. The first iscsi allocation
after the upgrade records the feature as used, cluster-wide, before any LUN
claim exists; from then on a host rolled back below the release is
WAL-quarantined rather than allocating LUNs without claims (see
[upgrades.md](upgrades.md)). That first allocation waits up to 30 seconds for
every host to acknowledge the record, and meanwhile another create of the same
LUN or VM is refused as in flight (`Aborted`; retry once the first has
finished). A voter whose replica does not hold the record yet — one added
since, not caught up — refuses every LUN allocation
(`recovery_claim_feature_unrecorded`) until it does, so it never holds LUN
state a rollback below the release could not see; enough such voters make an
allocation `Unavailable` for as long as replication takes.

A compose file that would put two instances of a VM on one iscsi volume or pool
at once — `replicas` above 1, or an `update: strategy` of `blue-green` or
`snapshot-and-replace`, which create the new instance beside the old — is
refused when the stack is deployed, where the disk is written.

A cluster that already has two VMs on one LUN — an older build allowed it —
is left as it is: litevirt does not touch those disks or refuse to start those
VMs. It raises the `shared_lun` health condition naming them (see
[diagnostics.md](diagnostics.md#shared-iscsi-lun-shared_lun)) and a
`storage.lun_shared` notification; stop all but one and move the others'
disks to LUNs of their own. The claim is the prevention; `shared_lun` only
detects.

**What it does not cover.** Claims order litevirt's own creates. They do not
stop something outside litevirt — another cluster, a host attaching the LUN by
hand — from writing it. The storage-side guarantee is SCSI-3 persistent
reservations on the LUN, which litevirt does not take (yet).

**A root disk from an image is written onto the LUN.** The driver allocates
nothing, so a root disk on an iscsi pool built on an image (`image:` in
compose, `lv run --image … --storage <pool>`) has the image's guest contents
written onto the LUN with `qemu-img convert` before the VM is first defined —
never a blank LUN booting to the firmware shell. The image store's images are
qcow2, and the image is opened as qcow2 with no backing chain; anything else
(raw bytes, VDI, VHDX, VMDK) is refused, never copied over as raw — a raw
image in the store cannot be the root of an iscsi VM (convert it to qcow2). Before writing:

- the LUN is not any VM's disk (the claim above, held for the whole write);
- the LUN is at least the image's virtual size, or the create is refused with
  both sizes. The disk's requested `size` is not applied: the disk is the LUN,
  at the size the SAN gave it;
- the LUN is blank — zeros in its first and last MiB (partition tables: MBR,
  GPT and its backup; LVM labels), in the 128 KiB from 1 MiB (where a first
  partition's filesystem starts even when the partition table was wiped), and
  in 64 KiB samples every GiB across the device (at most 256) — read past the
  page cache. Otherwise the disk must set `overwrite` (compose
  `overwrite: true`, `lv run --overwrite`), a one-shot acknowledgement for that
  create that is never stored in the VM's spec. An overwrite is audited, after
  the write, with its outcome.

The probe is a sample. Data that lies only between the probed regions — a
blank-looking LUN reused without being wiped — reaches the new guest when it
grows its filesystem; litevirt does not wipe a LUN when a VM is deleted. A
write that fails part-way (the write runs on, detached, even if the client
gives up) leaves the LUN partly written, so a retry needs `overwrite`.

`overwrite` is an accident interlock, not a permission boundary: whoever may
create the VM on the pool may also attach the LUN as a data disk and write
anything to it from the guest.

A data disk on an iscsi pool, and a root disk with no image, is the LUN as it
is: nothing is written.

To give each disk its own LUN, create the LUNs on the SAN and one pool per
LUN, then name the pool on the disk:

```bash
lv pool create san-vm1-root --driver iscsi --source iqn.2003-01.org.example:store \
    --option portal=10.0.0.5:3260 --option lun=1
lv pool create san-vm1-data --driver iscsi --source iqn.2003-01.org.example:store \
    --option portal=10.0.0.5:3260 --option lun=2
```

```yaml
vms:
  vm1:
    disks:
      root: { size: "40G", storage: san-vm1-root }
      data: { size: "200G", storage: san-vm1-data }
```

A new iscsi pool records its portal as `host:port`, adding `:3260` when no
port is given and resolving a host name to its IPv4 address (with a warning,
or keeping the name when it does not resolve): the device path is spelled from
the option, and udev names the device `ip-<address>:<port>-iscsi-…`. Pools
created before keep the spelling their disks were recorded with.

**Sessions after a reboot.** A LUN's device exists only while the host has a
session to the pool's target, and a reboot drops every session; node records
are usually `node.startup = manual`, so open-iscsi does not log back in. The
daemon does, for every iscsi pool of its host: at start and every 30 s it
lists the sessions (`iscsiadm -m session`) and, for a pool whose target has
had no session through its portal **since the daemon started**, logs in with
`iscsiadm -m node -T <target> -p <portal> --login`. Pools from the daemon
config use the portal of their config entry. A pool counts as having its
session when `iscsiadm -m session` lists one, including a session iscsid is
still recovering after the portal dropped; a pool whose portal is a host name
counts any session to its target.

**A logout while the daemon runs is left alone.** A session the daemon has
seen up and that then disappears was logged out on purpose (SAN maintenance, a
LUN re-mapped on the array, a path taken down before an ACL change), so the
periodic check does not log it back in. The pool is reported `degraded` with
the reason "logged out while the daemon ran; `lv start` of a VM using it or a
daemon restart logs it back in". To bring it back: start a VM that uses the
LUN, restart the daemon, or log in by hand (`iscsiadm -m node -T <target> -p
<portal> --login`). The cost: a session lost mid-run to a fault rather than a
logout also stays down until one of those (iscsid normally keeps a session
whose connection dropped, recovering it in place, so this is rare).

A start of a VM whose iSCSI device is missing logs its session in first, the
deliberately logged-out one included, and, when it made a login, waits up to
10 s for udev to create the device. It does not retry a login the periodic
check saw fail within the last 30 s. It refuses nothing: a disk whose device
is still missing fails the start, as before.

**What the re-login does to node records.** The check and the start's login go
through the node record as it is: the record holds the session's settings,
CHAP credentials included, so no secret is put on a command line or in a log.
The re-login never rewrites, deletes or logs out of a record, and leaves
`node.startup` as it is. A target with no record at all gets one for that
target alone, `iscsiadm -m node -o new -T <target> -p <portal>`, from
iscsid.conf's defaults.

**What a pool or disk create does to node records.** Pool create, and every
VM disk create, move or replicate on the pool (the driver's Prepare), also log
in through the record as it is. Per-record settings made by hand, such as CHAP
(`iscsiadm -m node -o update -n node.session.auth.…`) or `node.startup`,
survive it. In order:

1. It logs in with `iscsiadm -m node -T <target> -p <portal> --login`. When
   the record works, or a session is already there, nothing else runs.
2. When that fails, an add-only discovery runs, `iscsiadm -m discovery -t st
   -p <portal> -o new`. It adds a record for each target the portal returns
   that has none, and changes or deletes no existing record. Then it logs in
   again. This covers a new target, a target on a new portal, and a target
   that now answers with a new portal group tag (the new record sits beside
   the stale one, which is left as it was). A session listed after this login
   counts.
3. When the target **refused** the existing record (iscsiadm's authorization
   failure, 24, or a non-retryable login failure, 19), that one record is
   refreshed from iscsid.conf: it is deleted, made again by the add-only
   discovery, and logged in through. This keeps a create working after CHAP
   was rotated in iscsid.conf while the record still held the old secret.
   Before the delete, the target's records **at this portal** are saved (from
   `/etc/iscsi/nodes` or `/var/lib/iscsi/nodes`, in memory only). If the
   target refuses the refreshed record too, they are put back as they were,
   anything added at that portal in the meantime is removed, and the create
   fails with both reasons. Each file is put back atomically (a temporary
   file, synced, renamed over the record), so a concurrent login reads the
   old record or the saved one, never a partial one. The target's records at
   other portals are neither saved nor put back. The refresh is logged as a
   warning. When it is kept, settings made on that record by hand are
   iscsid.conf's from then on.

The daemon runs one of these per target at a time: Prepares of the same
target (two pools on two LUNs of it, for example) and the periodic and
start-time re-login wait for each other, so no login reads a record while a
refresh has it deleted, and no refresh saves another's half-done one. An
`iscsiadm` run by hand at the same moment is not covered.

So a record is changed only when the target refused it and accepted
iscsid.conf's settings. Existing records of other targets on the portal are
never changed. On a host whose node database is in neither directory, or a
pool whose portal is a host name (the database names records by address), the
record cannot be saved: a refused record is still refreshed, so the create
succeeds as it did before, but a refused refresh leaves it as iscsid.conf's.
The saved copy is kept only in memory, so a daemon killed between the delete
and the put-back also leaves it as iscsid.conf's.

What differs from builds before this one:

- **Only a refusal refreshes a record.** A login that fails for another
  reason (a portal that does not answer, a timeout) changes nothing, even
  when the cause is a setting on the record: a `node.conn[0].timeo.login_timeout`
  set too short by hand, for example, used to be reset by the create's
  discovery and now fails the create with the timeout. Fix the setting on the
  record (`iscsiadm -m node -T <target> -p <portal> -o update -n <name> -v
  <value>`), or delete the record so the next create makes it from
  iscsid.conf.
- **The add-only discovery still adds records for other targets.** A
  sendtargets discovery returns every target the portal advertises to this
  initiator, and step 2 makes a record, from iscsid.conf's defaults, for each
  one that has none. If iscsid.conf sets `node.startup = automatic`, the host
  logs in to those targets at its next boot. Earlier builds did the same, on
  every create.
- **A working record logs in without a discovery.** A target the array no
  longer advertises but still lets this initiator log in to is used through
  its existing record, where the old discovery deleted the record and the
  create failed. Access is the target's CHAP and ACL either way; the
  advertisement never was.
- **Records the portal no longer returns are no longer deleted.** A record
  left with a stale portal group tag stays beside the current one. Each
  `--login` of the target tries it and it fails; a login that opened the
  session through the other record still counts, here and in the re-login.

**Pool delete** logs the host out of the pool's target and portal, unless
another pool of the host uses the same pair.

While a pool's session is missing, its row's state is `degraded` (`lv pool
ls`, `lv pool inspect`), not `active`, and its host raises
`iscsi_session_missing` with the reason
([diagnostics.md](diagnostics.md#an-iscsi-pool-has-no-session-iscsi_session_missing)).
Both clear on the first check that finds the session. A degraded pool refuses
nothing; the state is a diagnostic. An older build shows the state as it is
recorded.

**Not implemented: LVM on an iSCSI LUN.** Proxmox's usual shared-SAN layout is
one big LUN with a shared LVM volume group on it, carved into one logical
volume per disk. litevirt has no such driver — `lvm-thin` is a host-local
volume group, not a shared one — so a LUN holds exactly one disk (see "Disks
per pool" in the backend matrix below).

## Backend matrix

|  | local | nfs | dir | btrfs | zfs | ceph | iscsi | lvm-thin |
|---|---|---|---|---|---|---|---|---|
| Disks per pool | many | many | many | many | many | many | **one** (the LUN; no LVM-on-LUN) | many |
| Snapshots | qcow2 | qcow2 | qcow2 | atomic (subvol) | atomic (zvol) | atomic (rbd snap) | external | atomic (LV snap) |
| Move (offline) | ✓ | ✓ | ✓ | ✓ | — | — | — | — |
| Move (live) | ✓ | ✓ | ✓ | ✓ | — | — | — | — |
| Replicate via qemu-img | ✓ | ✓ | ✓ | ✓ | fallback | fallback | — | — |
| Native send / receive (`replicate-volume`) | n/a | n/a | n/a | btrfs s/r | zfs s/r | rbd export/import | n/a | n/a |
| HA-friendly cluster store | no | yes | depends | no (host-local) | no (host-local) | yes | yes | no |

**Discard (TRIM).** A new VM's disk gets `discard=unmap` by default on `local`,
`dir`, `btrfs`, `zfs`, `lvm-thin` and `ceph` (on a virtio, scsi or sata bus), so a
guest's `fstrim` returns the space to the pool. It is not defaulted on `nfs` or `iscsi`
(whether a TRIM frees anything there depends on the server), nor for an existing VM; set `discard:` on a compose
disk to choose either way (see [compose.md](compose.md)).

The **Snapshots** row describes each backend's *native* snapshot capability
(what the driver could do). It is not the `lv snapshot create` code path: that
command always goes through libvirt — an external qcow2 overlay for disk
snapshots, plus libvirt's external memory snapshot (RAM written by the running
QEMU, see [configuration](configuration.md#memory-snapshots)) for a `--memory`
snapshot — regardless of the underlying pool driver.

For HA scenarios use NFS, Ceph RBD, or iSCSI — the disk must survive any
single host failing.
