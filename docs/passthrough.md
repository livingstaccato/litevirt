# USB passthrough, memory hot-add, and container host mounts

Three Proxmox VE features that change what a workload can reach on its host.

Setting any of them is refused — "the cluster upgrade must finish first" —
until the cluster's shared release token proves every host runs this
release: the fields live in a VM's or container's stored spec, and a host on
an older release would drop them from any spec it rewrites, or place, fail
over or recreate the workload without them. Until that gate is wired the
features stay refused (they fail closed); once the upgrade finishes they are
on, as on Proxmox VE. Clearing them is never gated, and a workload without
them is unaffected.

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
container that has one. Then the host itself decides what it allows:

```yaml
containers:
  bind_mount_paths: ["/srv/shared", "/srv/www"]
  device_paths: ["/dev/ttyUSB0"]
```

- Each mount's host path is **resolved on the host, symlinks followed**, and
  the resolved path must lie under one of that host's prefixes. Empty lists
  (the default) allow nothing.
- **Protected trees** are never mounted, whatever the prefixes say, and a
  prefix or source that is, lies in, or CONTAINS one is refused (at config
  load too): `/`, `/etc`, `/root`, `/boot`, `/proc`, `/sys`, `/dev`, `/run`,
  `/var/run`, `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, the LXC store,
  `/var/lib/libvirt`, litevirt's data and PKI directories. A path a VM disk
  or a storage pool uses is refused too.
- **Devices are listed exactly**: each `device_paths` entry is one device
  node (never a directory such as `/dev`), and only character or block nodes
  pass. Physical and kernel memory (`/dev/mem`, `/dev/kmem`), I/O ports,
  `/dev/kvm` and `/dev/vhost-*` are never passed through, and neither is a
  block device that holds a mounted filesystem, has a device built on it, or
  is a VM's disk.
- Paths may hold letters, digits and `. _ @ + / -` only.
- Mounts are **read-only unless `:rw`**, and always `nosuid,nodev`.
- **The config never names the tree.** LXC binds a staging path under
  `/run/litevirt/ct` (root-only, private propagation). Litevirt's start hook,
  which LXC runs on **every** start — a reboot from inside the container
  included — opens each source beneath its allowed prefix with
  `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`, clones exactly that tree,
  sets read-only/nosuid/nodev on it and moves it onto the staging path. A
  symlink swapped into the tree at any time is refused by the kernel, not
  followed. This needs Linux 5.12+; on an older kernel mounts are refused.
- **Every start judges the container again**: the mounts and devices an admin
  authorized are recorded in its directory, the managed config block is
  rendered from that record, and a config whose block is anything else —
  other mount options, another `devices.allow` line, an entry nobody
  authorized, a record that cannot be read — refuses the start, as does a
  path the host no longer allows. A container migrated, restored or relocated
  to a host that does not allow its paths does not start there.
- **Archives grant nothing.** A restore, import, migration or snapshot revert
  rebuilds the container's config from litevirt's own renderers: only the
  keys litevirt writes survive (rootfs, hostname, network, resource limits,
  LXC's own includes), and security and host access are rendered from the
  authorized spec. A restore keeps the backup's mounts and devices only for an
  admin (a cold migration or failover relocation keeps them only when they are
  exactly what the source's row records); otherwise they are stripped, the
  strip is audited, and an admin re-applies them with `lv ct convert`.
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
