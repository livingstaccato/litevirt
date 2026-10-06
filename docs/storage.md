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
`storage.CheckReadFile` refuses (below). The daemon writes every file a
library holds — an upload, a pull, a sync — so a link there is never one of
them.

### The global library

Every host has a pool named `isos` with no project, at `<data_dir>/isos`,
which the daemon creates when the host has none. Every project may boot from
it. Only an Admin writes it (`storage.library.write` at `/`): an upload in the
UI's Browse dialog or `lv iso pull` (below). No other pool may be created in,
above or below its directory.

Where its files live is the cluster setting `iso_library_mode`, shown and
changed with `lv cluster iso-library-mode`:

- **`sync`** (the default): every host keeps a local copy. An upload or pull
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

Switching:

- **to `shared`**: create the shared `isos` pool on every host (above), copy
  the files you need into it, then run `lv cluster iso-library-mode shared`.
- **to `sync`**: run `lv cluster iso-library-mode sync` against a host whose
  library holds the files you want. The switch records every ISO in that
  host's library, and the other hosts copy them. A file another host holds
  under the same name but with other content is replaced by that copy, and a
  file only another host holds is not recorded (upload or pull it again).
  The pools can stay on shared storage; then every host's copy already
  matches.

Changing the mode needs the admin role and refuses until every host runs a
release that knows it (`failover_scope_v1` latched). In sync mode an upload or
pull to the global library is refused for the same reason until then.

### Project libraries

A project library is any file-based pool a project owns with the option
`content=iso`:

```bash
lv pool create acme-isos --driver dir --target /srv/acme-isos --project acme --option content=iso
```

The project's operators upload to it (`storage.content.write`), and only that
project's VMs may boot from it. Only `.iso` files go into a library.

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
first, then the global library. `lv iso rm <pool>/<file>.iso` removes one.

### Host paths and earlier specs

- An **Admin** may still name an absolute host path (`storage.hostpath` at
  `/`). It is judged as itself, at create and at every start, with the same
  plain-file rules.
- A **non-admin** may not. An absolute path that names a `.iso` directly in a
  pool directory — what earlier specs stored — is taken as that pool's
  reference, provided the caller may read the pool and the VM's project may
  use it (every pool sharing that directory included). A VM created earlier
  that way keeps starting, and is resolved through its pool.

Some files are refused to everyone, Admin included, judged as written and after
resolving symlinks: the PKI directory, anything in the data directory outside
`disks/`, `mounts/` and `isos/` (`state.db`, `cloudinit/`, `nvram/`, …), and
anything under `/boot`, `/dev`, `/etc`, `/home`, `/proc`, `/root`, `/run`,
`/sys`, `/var/backups`, `/var/run`, `/var/spool`, `/var/lib/lxc`,
`/var/lib/libvirt/qemu` or `/var/lib/libvirt/swtpm`.

A refusal at start fails with `FailedPrecondition` and an ERROR log naming the
VM and the file, and the VM stays down. What is judged is the CD-ROM the VM's
domain actually carries, so a VM whose domain was redefined without its
installer CD-ROM starts even after the ISO is gone. When a library file lives
at a different path on the starting host than where the domain was defined
(a library pool on another directory), the domain is pointed at this host's
file. A live migration opens the source's path on the target, so give the
library pool the same directory on every host if VMs migrate live with their
installer attached.

The entry node checks authority before forwarding; the owning host resolves
the file against its own filesystem. An entry node on an older build forwards
without the authority check, so the library route is only as strong as the
oldest host involved until every host runs this build (as with the other
content checks in [auth.md](auth.md)).

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
