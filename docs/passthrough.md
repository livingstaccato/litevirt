# USB passthrough, memory hot-add, and container host mounts

Three Proxmox VE features that change what a workload can reach on its host.

The three are one feature of the release, `usb_mounts_memory`, under the
cluster's shared release token `release_2026_11_v1`. Setting any of them is
refused — "the cluster upgrade must finish first (usb_mounts_memory needs
release_2026_11_v1)", followed by the hosts still to upgrade — until that
token has latched, which proves every host runs this release: the fields live
in a VM's or container's stored spec, and a host on an older release would
drop them from any spec it rewrites, or place, fail over or recreate the
workload without them. Once the upgrade finishes they are on, as on Proxmox
VE. Clearing them is never gated, and a workload without them is unaffected.

Once `release_2026_11_v1` has latched, rolling a host back below this
release quarantines it whether or not this feature was ever used: every build
below the token predates rollback rules, so `lv cluster upgrade-status` shows
`BLOCKS ROLLBACK: yes` for it (see upgrades.md, *Rolling back after a release
token latched*). The first time any of the three is set, the cluster also
records `usb_mounts_memory` as used (`lv cluster upgrade-status` shows it);
that record is what a rule-aware build below a later release token reads. The
record is written before the data it covers, so a request that fails after
it — a create its project quota or host admission then refuses, a restore
whose id-range move or row write then fails — can leave the feature recorded
as used with nothing set. It never errs the other way.

## USB passthrough (VMs)

A VM names each USB device one of three ways:

| Form | Flag | Who may | Where it can run |
|---|---|---|---|
| vendor:product | `--usb 046d:c52b` | admin role | only the host it was created on (pin it with `--host`) |
| bus-port | `--usb-port 1-2` | admin role | only that host |
| resource mapping | `--usb-mapping dongle` | `resourcemap.use` on `/mappings/dongle` (admin role with no role bindings) | any host the mapping lists |

A raw device (the first two forms) is one of the host's own devices, so it is
the admin role's to hand out, as on Proxmox VE (`Sys.Modify` on `/`); a mapped
one needs the mapping's use permission (Proxmox `Mapping.Use`). Both are judged
on the node that takes the request, before it forwards anything.

Changing a **USB mapping's devices** — `lv mapping add-device` of a USB
device, `lv mapping rm-device` on a mapping that holds USB devices, `lv mapping
rm` of one — needs the **admin role**: the devices are what every VM holding
the mapping's use permission receives at its next start, so whoever edits them
hands out host USB. Neither `resourcemap.write` (the Operator role's) nor
`resourcemap.use` changes a USB mapping, and a mapping another tenant's VMs use
is changed only by an admin. PCI mappings keep `resourcemap.write`.

A raw device binds the VM to its host: placement, failover, drain and
rebalance consider that host alone, and a VM whose host is lost stays down
rather than starting without its device. A **USB mapping** is the portable
form — the Proxmox "USB mapping":

```bash
lv mapping create dongle
lv mapping add-device dongle usb:096e:0006 --host node-1   # by id on node-1
lv mapping add-device dongle usb:3-1.4    --host node-2   # by port on node-2
lv run --name lic --image ubuntu --usb-mapping dongle
```

A mapping holds PCI devices or USB devices, never both. The check is made
against the mapping as the node sees it, so two `add-device` calls of
different kinds racing on two nodes can still produce a mixed mapping; a VM
naming one is refused (and placement finds no host), so fix it with
`lv mapping rm-device`.

Placement and failover consider only hosts the mapping lists. Each host
resolves the device from its own row when it defines the domain, and again
before every start; it refuses the define or start if it has no such row, or
— for a bus-port — nothing is plugged into that port. A vendor:product device
that is not present is refused by libvirt when the guest starts.

**Migration.** As on Proxmox VE, a running VM with a USB device is not
live-migrated: `lv migrate` refuses and names `--cold`, and a drain moves it
cold. A cold migration is allowed when every device is mapped and the target
holds each mapping; the target re-resolves the devices from its own rows
before it defines the domain. A raw device cannot leave its host. A clone
carries no USB device.

**Changing devices.** `lv update <vm> --usb … / --usb-port … / --usb-mapping …`
replaces the list and `--clear-usb` empties it — like the other definition
changes, with the VM stopped or `--restart-if-needed`. USB devices are not
hot-plugged: device attach/detach is journaled (`enforcement.operation_protocol`)
and has no un-journaled path, and USB has no journaled kind yet.

A bus/device address is not stable across a re-plug, so the bus-port form is
never stored: it is read from the host's sysfs at every define and again
before every start, which rewrites the definition with the device the port
holds now.

## Memory hot-add (VMs)

`--memory-hotplug-max N` boots the guest with one NUMA cell holding its
`--memory` and a virtio-mem device covering the rest up to `N`:

```bash
lv run --name db --image ubuntu --memory 2048 --memory-hotplug-max 16384
lv set-memory db 8192          # plug 6 GiB into the running guest
lv update db --memory 4096     # unplug back to 4 GiB (the guest cooperates)
```

The boot memory (the NUMA cell) is fixed for the life of the definition and
cannot be unplugged; changes are in 2 MiB blocks. A change is applied to the
persistent definition first, then live, through the same coordinator as a
vCPU grow, so it survives a restart and a crash mid-change is resumed. Every
definer carries the band — create, update, a failover or promote restart, a
clone, a live restore from the cluster's own row — and live migration carries
the device with its plugged size. A VM whose running definition has no region
(an older one) refuses a change up front instead of holding its operation.

Quota, placement and host admission count the VM's memory as the boot cell
plus the LARGER of what was requested and what the guest actually has
plugged (libvirt's `<current>`): an unplug the guest cannot complete leaves
the memory with QEMU, and it stays counted until the two agree.

Hot-add cannot be combined with a balloon band (`--min-mem` / `--max-mem`) or
with hugepages. The guest needs a virtio-mem driver (Linux 5.8+, Windows with
the virtio-win virtio-mem driver). `--memory-hotplug-max 0` on a stopped VM
turns it off; the VM keeps its memory as fixed memory. A live restore from a
manifest or a `--spec` restores fixed memory and no USB device (set them again
with `lv update`); one `--from-existing` keeps them, judged as a create is.
A promotion is never refused for them: it keeps the hot-add band once the
release token has latched and the feature's gate grants it, and otherwise
promotes with fixed memory (audited as `vm.release_features_dropped`). A
renamed promotion (`--new-name`) is a second VM and, like a clone, does not
carry the source's USB devices; CPU and NIC limits follow the same rule as the
band.

## Container host mounts and devices

```bash
lv ct create web --mount /srv/shared:/data            # read-only
lv ct create web --mount /srv/www:/var/www:rw         # read-write
lv ct create pos --device /dev/ttyUSB0                # a serial adapter
lv ct convert web --mount /srv/shared:/data           # set them on an existing (stopped) container
lv ct convert web --clear-host-access                 # remove them
```

A host path inside a container is access to the host. On Proxmox VE only
`root@pam` may add one; here it needs the **admin role** — judged on the node
that takes the request, before it forwards anything — and so does cloning a
container that has one. A non-admin's clone of a **privileged or
legacy-confined** container is never refused: the clone lands unprivileged, in
an id range of its own (its files shifted), with default confinement, and the
audit (`ct.clone`) says so. An admin's clone keeps the source's mode. A
source with an unfinished conversion is not cloned until the conversion is
finished (`lv ct convert <name>`), and neither is one whose security settings
cannot be read (the refusal names the error). A clone's NICs are admitted as
what they now are: a raw bridge that has since become the rendered bridge of a
managed network is that network's NIC, so a clone onto another project's
network is refused. Then the host itself decides what it allows:

```yaml
containers:
  bind_mount_paths: ["/srv/shared", "/srv/www"]
  device_paths: ["/dev/ttyUSB0"]
```

- Each mount's host path is **resolved on the host, symlinks followed**, and
  the resolved path must lie under one of that host's prefixes. Empty lists
  (the default) allow nothing.
- **Protected trees** are never mounted, whatever the prefixes say: a
  source whose resolved path is, lies in, or CONTAINS one is refused, and so
  is a configured prefix (at config load) whose path is, lies in or contains
  one of the fixed trees below: `/`, `/etc`, `/root`, `/boot`, `/proc`, `/sys`, `/dev`, `/run`,
  `/var/run`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, the LXC store,
  `/var/lib/libvirt`, litevirt's data and PKI directories, and **every store
  the host serves**: each storage pool's source and target on this host, every
  backup repo (configured or registered), the image and disk stores, the
  restore cache, and litevirt's own binary (the start hook LXC runs as root).
  Each is compared in its resolved, canonical form, on every start, and by
  **filesystem identity** as well: the filesystem a tree is on (its device
  number in `/proc/self/mountinfo`) and the path within that filesystem. The
  same tree mounted again somewhere else — `/var/lib/litevirt` bound under an
  allowed prefix, or a second mount of the NFS export a pool lives on — is
  therefore refused too, beneath the prefix or not. On NFS the path within the
  filesystem is the export path the mount names (`srv:/export/share`), not
  mountinfo's root column: on NFSv3, mounts of two exports of one server
  filesystem can share a superblock, and their root column reads `/` until the
  kernel splices the dentry, so it depends on the dentry cache. A share beside
  a pool's export passes and one inside it is refused, the same way every
  time. Where the path within the filesystem is still not certain (an NFS
  source that names no export path, or a bind of a subdirectory on such a
  shared superblock), identity is not used and the resolved-path check alone
  decides. Identity does not recognise an overlay whose lower or upper
  directory is a protected tree, a btrfs snapshot of one, or a mount of the
  same NFS export that does not share a superblock (`nosharecache`, other
  mount options): do not build those beneath an allowed prefix. A store list
  or a mount table that cannot be read refuses every mount. A configured
  prefix that reaches a protected tree only by filesystem identity — a prefix
  on the disk that also holds `data_dir`, say — does not stop the daemon
  starting (such a config loaded before identity was checked): it is logged
  and raised as the warning condition `container_mount_prefix_overlap` about
  the host, and the sources in the protected tree are refused when they are
  resolved, as above. A store created beneath an
  allowed prefix refuses only the sources in it or containing it: `/srv/share`
  keeps working when a pool appears at `/srv/pools/x`. A container with no
  mounts never reads the store list.
- **Devices are listed exactly**: each `device_paths` entry is one device
  node (never a directory such as `/dev`), and only character or block nodes
  pass. Physical and kernel memory (`/dev/mem`, `/dev/kmem`), I/O ports,
  `/dev/kvm`, `/dev/vhost-*`, the raw-disk character nodes — SCSI generic
  (`/dev/sg*`), block SCSI generic (`/dev/bsg/*`), NVMe generic namespaces
  (`/dev/ng*`) and NVMe controllers (`/dev/nvme0`) — and the host's console
  and input — virtual terminals (`/dev/tty`, `/dev/tty0`–`/dev/tty63`),
  `/dev/console`, `/dev/vcs*`, `/dev/uinput`, `/dev/input/*` and
  `/dev/watchdog*` — and device-mapper control (`/dev/mapper/control`, which
  builds a dm target over any host disk), the CPU MSRs (`/dev/cpu/*/msr`) and
  the hibernation image (`/dev/snapshot`, host RAM) are never passed through,
  by name or by device number. Serial ports (`/dev/ttyS*`, `/dev/ttyUSB*`,
  `/dev/ttyACM*`) pass. The list is not exhaustive: other host-trust nodes —
  `/dev/kmsg`, `/dev/nvram`, `/dev/hpet`, `/dev/ipmi*`, `/dev/mtd*`,
  `/dev/mei*`, `/dev/tpm*`, `/dev/vfio/vfio` — are not refused by litevirt and
  must never be listed in `device_paths`. A block device is judged **by its device
  number**, with its partitions and the disk it belongs to: it is refused when
  any of them holds a mounted filesystem, is swap, has a device built on it
  (LVM, md, dm-crypt), is a loop device with a backing file or a connected nbd
  device, is held open by any process (qemu's VM disks), is refused an
  exclusive open by the kernel (btrfs and ZFS members), or is the disk of any
  VM in the cluster by number, whatever path names it (a shared LUN backing a
  VM on another host included). Only block devices count: a character node
  with the same numbers does not. Who holds a device — a mount, swap, a
  process, the exclusive-open probe — is judged when the container is NOT
  running: at create, at `lv ct convert`, at every start the daemon drives,
  and by the start hook before every start, a reboot from inside the
  container included (when no process of the container is left). The
  once-a-minute policy refresh does not judge it, so a running container
  whose own process holds its granted block device open keeps it, and its
  next in-container reboot is judged by the hook as above.
- Paths may hold letters, digits and `. _ @ + / -` only.
- Mounts are **read-only unless `:rw`**, and always `nosuid,nodev`.
  Read-only is a boundary only for an **unprivileged** container, where the
  kernel locks the flag. Root in a privileged or legacy-confined container
  (both admin-only) can remount the tree read-write.
- **The config never names the tree.** LXC binds a staging path under
  `/var/lib/lxc/.litevirt+staging` (root's, mode 0711 — traverse only, so
  an unprivileged container's mapped root reaches its own staged mounts and
  nobody but root can list, create or rename there — private propagation, no
  symlink followed). Permissions on the directories above a mount's source do
  not apply to its staged copy: only the source tree's own modes do, so a
  source readable by local users only because a parent directory is closed
  becomes reachable through the staging path; allow only sources whose own
  modes say who may read them. It lies beneath LXC's store because that is the one tree
  the stock AppArmor profile of `lxc-start` lets a start hook mount on
  (Ubuntu's `abstractions/lxc/start-container`), so no host policy change is
  needed. A host whose
  refresh of one container hangs (a mount source that stops answering)
  refuses that container's start and host-access changes with a retryable
  error naming the stuck refresh after 15 s, rather than waiting on it. Litevirt's start hook,
  which LXC runs on **every** start — a reboot from inside the container
  included — opens each source beneath its allowed prefix with
  `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`, then judges what it opened
  by the path the kernel resolved it to and by the filesystem identity of the
  mount the opened fd is on (still beneath the prefix, sharing no files with a
  protected tree), clones exactly that tree, sets read-only/nosuid/nodev on it
  and moves it onto the staging path. A symlink swapped into the tree at any
  time is refused by the kernel, not followed. A filesystem mounted beneath an
  allowed prefix (a NAS share) is a source like any other; a store or
  protected tree mounted there, or reached there through another mount of its
  filesystem, is refused. The hook runs
  for a container with devices and no mounts too, and judges every mount and
  device again against a policy the daemon keeps per container
  (`/run/litevirt/lxc-hook-policy/<name>.json`): the host's policy and the
  container's own authorized record, as resolved now. The daemon writes it at
  every start it drives and whenever the record changes, and rewrites every
  container's at daemon start and once a minute, so a pool created, or a
  prefix withdrawn, reaches a reboot from inside the container within a
  minute; a container whose directory is gone (deleted, migrated away) has its
  policy removed then. A refresh that cannot judge a container's grant now — a
  read or a lookup failed (the database, the mount table, an NFS source that
  does not answer) — keeps the policy it last wrote and logs it, rather than
  stopping the container's next reboot over a transient error; a definite
  refusal (a prefix withdrawn, a device no longer listed) empties it. The
  refresh and every change of a container's host access take that
  container's lock, so a refresh never writes an older policy over a newer
  one; a container whose lock is held (a start judging it now) is skipped and
  refreshed at the next run, so one container never holds up the others.
  Nor does one whose own refresh hangs (a hard-mounted NFS source that stops
  answering): after 10 s the refresh moves on to the next container and logs
  the one it left, which keeps the policy it last wrote and is skipped until
  that lookup returns. With no policy the hook stages nothing, and it stages only what the
  record authorizes. A refusal is logged
  to the system log under the tag `litevirt-lxc-hook`. A failed start takes
  down what it staged, and the stop removes each staging entry by itself.
  This needs Linux 5.12+; on an older kernel mounts are refused.
- **Every start judges the container again**: the mounts and devices an admin
  authorized are recorded in its directory, and the managed config block is
  rendered from that record on every start. A block that says anything else —
  other mount options, another `devices.allow` line, an entry nobody
  authorized — is replaced by the rendering and the difference logged, never
  kept. A record that cannot be read refuses the start, as does a path the
  host no longer allows. A container migrated, restored or relocated
  to a host that does not allow its paths does not start there.
- **Archives grant nothing.** A restore, import, migration or snapshot revert
  rebuilds the container's config from litevirt's own renderers: only the
  keys litevirt writes survive (rootfs, hostname, resource limits, and only
  the includes create writes: LXC's `common.conf` and `userns.conf`, generic
  or per distro), and security and host access are rendered from the
  authorized spec. A restore renders the **network** from the spec as well:
  every `lxc.net.*` line in the archive is dropped (a `phys`, `macvlan` or
  `none` NIC, a router-mode veth, another project's bridge) and the spec's
  NICs are written as create writes them; what was dropped is audited
  (`ct.restore`). No bridge or network is taken from the archive's spec on its
  word either; each NIC is admitted as create admits it. A raw bridge that is
  the rendered bridge of a managed network IS that network's NIC. A managed
  NIC is kept when its network exists, is of a type containers use (not
  `direct` or `sriov`), and the restoring project may attach to it; it lands
  on that network's own bridge, whatever bridge the spec names. A NIC naming
  a network that does not exist is dropped — never placed on a host bridge
  that happens to carry the name. A raw-bridge NIC is kept only for a caller
  who may attach raw bridges (as at create). Every other NIC is dropped,
  audited, and the restore proceeds. A spec that records no NICs at all (a
  backup from before the create spec) is restored onto the default bridge,
  and the archive's network lines dropped are audited.

  A **cold migration or failover relocation** re-homes an existing container,
  so its NICs are the ones its **source row** records, by NIC name — never the
  archive's. Each keeps the row's address and MAC; a managed NIC lands on its
  network's bridge, or, when the network's record is gone (`lv network rm
  --force`, or not replicated to the target yet), on the bridge the row
  records, as before; a raw-bridge NIC keeps its bridge. A network its project
  may not use is kept and audited (`allowed-foreign-network`). A NIC the
  archive adds that the row does not record is dropped and audited, wherever
  it points. The moving host sends the row with the move (the target's own
  replica need not have it yet). A target that was sent no row (a move from
  an earlier build) waits up to 20 s for the row to replicate. If it still
  has none, a cold migration refuses before it writes anything — the source
  rolls back, the container intact, and the move is retried — and a failover
  relocation restores as earlier builds did, so its backed-up data is never
  given up for an image re-create: each managed NIC is kept when its network
  exists, is a container's type and is one the project may use, a raw NIC or
  another project's is dropped, host mounts, devices and privilege are not
  carried, and all of it is audited. A row from before the create
  spec records no NICs: a move keeps the archive's veth-on-bridge NICs and
  drops every other kind, audited (`ct.restore`). Litevirt never renders a
  `phys`, `macvlan`, `ipvlan`, router-mode or `none` NIC, so one exists only
  in a hand-edited config; re-add it by hand on the new host. The bridge NICs
  kept this way are not admitted against network records (as on earlier
  builds, which kept every archive NIC on a move), so a container that old
  takes whatever bridge its archive names; recreate it to give it a row
  that records its NICs. A network record or list that cannot be read fails
  the restore, to be retried. A restore keeps the backup's mounts and devices only for an
  admin (a cold migration or failover relocation keeps them only when they are
  exactly what the source's row records); otherwise they are stripped, the
  strip is audited, and an admin re-applies them with `lv ct convert`.
  Keeping them writes this feature's data, so an admin's restore takes the
  release gate's grant: before `release_2026_11_v1` latches they are stripped
  as above, and after it a gate that refuses (the first use not acknowledged
  by every host yet, a host rolled back) refuses the restore — the imported
  container is removed, nothing is recorded, and the refusal is audited —
  rather than drop what the admin asked to keep. While that refusal lasts (a
  host down for good, or in release probation — the refusal names it), an
  admin restores the container now with `lv ct restore <name> --repo <dir>
  --timestamp <ts> --without-host-access`: its mounts and devices are left
  out, no grant is asked, and the audit (`ct.restore`) records the request
  and what was left out; re-apply them later with `lv ct convert --mount` and `--device`.
  A cold migration or failover relocation ignores the option.
  **Privileged mode and legacy confinement** recorded in a backup are the same
  class and are decided the same way: an operator's restore of a privileged or
  legacy container lands unprivileged, in an id range of its own (its files
  shifted), with default confinement, and the audit says so. An admin
  re-applies legacy confinement with `lv ct convert --confinement legacy`, and
  a privileged mode by restoring the container as admin.
- An unprivileged container **keeps its id map**: a mounted tree's files
  appear owned by the ids they map to (anything unmapped as `nobody`), so a
  read-write tree must be owned by ids in the container's range. A device node
  is usable only as far as its owner and mode let those ids use it: there are
  no `uid=`/`gid=`/`mode=` options (Proxmox `devN: …,uid=,gid=,mode=`), so for
  an unprivileged container give the node a mode or group that covers the
  container's range on the host (a udev rule), or use a privileged container.
