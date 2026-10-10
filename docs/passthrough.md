# USB passthrough, memory hot-add, and container host mounts

Three Proxmox VE features that change what a workload can reach on its host.
All three are gated the same way: setting one is refused until the
`usb_mounts_memory_v1` capability has latched cluster-wide **and**
`enforcement.usb_mounts_memory: true` is set on the node that takes the
request (docs/configuration.md). The fields live in a VM's or container's
stored spec, and a node on an older build would drop them from any spec it
rewrites — or place, fail over or recreate the workload without them — so the
latch is the proof that no such node is left. Turning the flag off stops new
settings; a workload that already has them keeps them, and clearing them is
never gated.

## USB passthrough (VMs)

A VM names each USB device one of three ways:

| Form | Flag | Where it can run |
|---|---|---|
| vendor:product | `--usb 046d:c52b` | only the host it was created on (pin it with `--host`) |
| bus-port | `--usb-port 1-2` | only that host; the port is read from the host's sysfs at each define |
| resource mapping | `--usb-mapping dongle` | any host the mapping lists |

A raw device (the first two forms) is plugged into one host, so it binds the
VM there: placement, failover, drain and rebalance consider that host alone,
and a VM whose host is lost stays down rather than starting without its
device. A **USB mapping** is the portable form — the Proxmox "USB mapping":

```bash
lv mapping create dongle
lv mapping add-device dongle usb:096e:0006 --host node-1   # by id on node-1
lv mapping add-device dongle usb:3-1.4    --host node-2   # by port on node-2
lv run --name lic --image ubuntu --usb-mapping dongle
```

A mapping holds PCI devices or USB devices, never both. Placement and failover
consider only hosts the mapping lists; each host resolves the device from its
own row when it defines the domain, and refuses the define if it has none.

**Migration.** As on Proxmox VE, a running VM with a USB device is not
live-migrated: `lv migrate` refuses and names `--cold`. A cold migration is
allowed when every device is mapped and the target holds each mapping; the
target re-resolves the devices from its own rows before it defines the
domain. A raw device cannot leave its host.

**Changing devices.** `lv update <vm> --usb … / --usb-port … / --usb-mapping …`
replaces the list and `--clear-usb` empties it — like the other definition
changes, with the VM stopped or `--restart-if-needed`. USB devices are not
hot-plugged: device attach/detach is journaled (`enforcement.operation_protocol`)
and has no un-journaled path, and USB has no journaled kind yet.

A bus/device address is not stable across a re-plug, so the bus-port form is
never stored: it is resolved from the host's sysfs at every define (create,
update, reconcile, cold-migration target) and again before every start, which
rewrites the definition with the device the port holds now. Every start
re-resolves a mapped device the same way. A device the host cannot find
refuses the start — the guest never boots without it, nor with whatever has
since taken its old number.

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
vCPU grow, so it survives a restart and a crash mid-change is resumed. Live
migration carries the device with its plugged size. Quota, placement and host
admission count the VM's current memory, as for ballooning.

Hot-add and a balloon band (`--min-mem` / `--max-mem`) cannot be combined.
The guest needs a virtio-mem driver (Linux 5.8+, Windows with the virtio-win
virtio-mem driver). `--memory-hotplug-max 0` on a stopped VM turns it off; the
VM keeps its memory as fixed memory.

## Container host mounts and devices

```bash
lv ct create web --mount /srv/shared:/data            # read-only
lv ct create web --mount /srv/www:/var/www:rw         # read-write
lv ct create pos --device /dev/ttyUSB0                # a serial adapter
```

A host path inside a container is access to the host. On Proxmox VE only
`root@pam` may add one; here it needs the **admin role** (and so does cloning
a container that has one). Then the host itself decides what it allows:

```yaml
containers:
  bind_mount_paths: ["/srv/shared", "/srv/www"]
  device_paths: ["/dev/ttyUSB0"]
```

- Each host path is **resolved on the host, symlinks followed**, and the
  resolved path must lie under one of that host's prefixes. A symlink inside
  an allowed tree that points out of it is refused, not followed. Empty lists
  (the default) allow nothing.
- A mount is never the root, `/proc`, `/sys` or `/dev`; a device must be a
  character or block node. Paths may hold letters, digits and `. _ @ + / -`
  only — nothing that could break out of the LXC config line.
- Mounts are **read-only unless `:rw`**, and always `nosuid,nodev`.
- **Every start judges them again**, as the host is now. A path that has
  become a symlink, left the allowed tree or changed kind, a device whose
  major:minor changed, or a container migrated, restored or relocated to a
  host that does not allow its paths, is refused before `lxc-start`.
- An unprivileged container **keeps its id map**: a mounted tree's files
  appear owned by the ids they map to (anything unmapped as `nobody`), so a
  read-write tree must be owned by ids in the container's range, and a device
  node is usable only as far as its mode lets those ids use it.

What remains is the window between the start check and `lxc-start`'s own
mount: whoever can rename entries inside an allowed tree in that window can
swap a symlink in. Allow only trees that untrusted users — including other
containers with read-write mounts — cannot write.
