# GPU & PCI Passthrough

litevirt supports assigning PCI devices (GPUs, NICs, NVMe drives) directly to VMs for near-native hardware performance.

## Prerequisites

1. **IOMMU enabled** in firmware and kernel:

- **Intel:** enable VT-d in the firmware and add `intel_iommu=on` to the kernel command line:

  ```bash
  GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"
  ```

- **AMD:** enable IOMMU / AMD-Vi in the firmware. The kernel turns AMD-Vi on by default, so no parameter is needed. Make sure neither `amd_iommu=off` nor `iommu=off` is on the kernel command line.

Update GRUB and reboot after changes, then run `lv host rescan` so the inventory records each device's IOMMU group.

litevirt refuses to pass through a device whose IOMMU group it cannot establish, because it cannot tell whether the device shares a group with another VM's device. This covers devices chosen by address, mapping or type; create, start, attach and restore all refuse, with the reason, when:

- the IOMMU is off: the kernel lists no groups under `/sys/kernel/iommu_groups`. The refusal names the kernel parameter to set;
- the device has no IOMMU group link (`/sys/bus/pci/devices/<address>/iommu_group`), or the inventory was scanned before the IOMMU was turned on. Run `lv host rescan`;
- the device is not in the host's inventory. Run `lv host rescan`;
- the host's PCI inventory cannot be read. Retry once the local database is readable.

2. **vfio-pci module loaded:**

```bash
modprobe vfio-pci
echo "vfio-pci" >> /etc/modules-load.d/vfio.conf
```

3. **Device not bound to host driver** — litevirt handles binding/unbinding automatically.

### How binding and release work

- **Bind.** litevirt claims a device for vfio-pci with `driver_override` only; it never adds a vfio-pci ID. Before it touches the device, it records the driver the device was on in the data directory (`vfio-host-drivers.json`, local to the host and not replicated).
- **Release.** On detach, stop or delete, the device is bound back to that recorded driver explicitly, so neither driver load order nor a vfio-pci ID can send it back to vfio-pci.
- **Devices you give vfio-pci yourself.** These stay on vfio-pci when they are released:
  - a device on vfio-pci with no `driver_override` before litevirt binds it, for example by your `vfio-pci.ids=`;
  - a device pinned to vfio-pci with driverctl (`/etc/driverctl.d/pci-<address>`).
- **Your configuration wins over the record.** Say litevirt recorded a host driver for a device, and you have since added that device's ID to `vfio-pci.ids=` (on the kernel command line or in modprobe.d). The device then stays on vfio-pci when it is released.
- **vfio-pci IDs.** A released device that lands back on vfio-pci by a vfio-pci ID stays there: litevirt never adds or removes a vfio-pci ID.
- **Devices that are gone.** A released device no longer present in sysfs, such as a VF that did not come back after a reboot, is released without error.
- **Paused guests.** A detach refuses a guest that is paused or suspended, because it cannot acknowledge the unplug. The device stays with its VM until a retry once the guest runs.
- **Devices still open.** The kernel will not let a device leave vfio-pci while any process has it open, such as a QEMU that has not exited. The unbind would block until that process lets go.
  - **Before the unbind.** The release looks for a process holding the device's `/dev/vfio/<group>` or `/dev/vfio/devices/vfioN`. If one still does after two seconds, the release is refused with the process's pid and name.
  - **During the unbind.** If the kernel still blocks it, the release gives up after 20 seconds.
  - **Either way.** The device stays bound and owned by its VM. Until the blocked unbind returns, further operations on that device fail at once instead of waiting behind it. Retry once the holder has exited.
  - **Stopping the daemon.** A blocked unbind cannot be cancelled, so while one is pending the daemon cannot exit. A stop or restart waits until the holder lets go. On shutdown the daemon logs each such device, and `dmesg` shows the blocked write ("Device is currently in use"). Find the process holding the device with `lsof /dev/vfio/*` or by looking for vfio entries under `/proc/*/fd`, and stop it to let the daemon exit.
- **Failed SR-IOV attaches.** A failed attach releases every VF it allocated. On an upgraded host, VFs that an older build's failed attach left owned are released at startup and on `lv host rescan`. A VF is only released this way when nothing could still be using it: its VM holds it in neither copy of the domain, has no operation in progress and no PCI intents, and the VF is off vfio-pci. A VM that does not meet these conditions is skipped without a message. A warning, with the `lv detach-pci` command that releases the VF, is logged only for a VF that is in neither copy of the domain but still cannot be released, for example because it is still bound to vfio-pci.

## Discovering devices

List PCI devices on a host:

```bash
lv host devices host-a
lv host devices host-a --type gpu
lv host devices host-a --type network
lv host devices host-a --type nvme
```

Rescan to detect newly added devices:

```bash
lv host rescan host-a
```

litevirt tracks PCI topology including IOMMU groups, NUMA nodes, PCIe root ports, and NVLink cliques.

## Assigning devices in compose

### By type and vendor

```yaml
vms:
  ml-worker:
    image: "ubuntu-cuda"
    cpu: 16
    memory: "64G"
    devices:
      - type: "gpu"
        vendor: "10de"          # NVIDIA
        count: 2                # Request 2 GPUs
```

The placement engine selects a host with enough free devices matching the criteria. It prefers devices in the same NUMA node as the VM's CPU allocation and in the same NVLink clique for multi-GPU workloads.

Once a start has given the VM its devices on a host, a restart there
(`lv start`, or the restart after a guest crash) runs it with the same devices.
It does not need a free device of the kind, and it does not take one beside
those it has. This holds for the devices a start recorded for the VM on that host.
A device the VM holds that no start there recorded, such as one claimed before
the hardware_v2 latch and never adopted, is not kept this way: the restart
looks for a free device of the kind instead.

### By exact PCI address

```yaml
    devices:
      - address: "0000:41:00.0"
```

Name the address alone. The VM is placed on the host that has that device free
(with no other member of its IOMMU group held by another VM), and takes exactly
that device. Add a `placement.host` when more than one host has a device at
that address. After a failover the address is not carried over: see
[Failover with PCI devices](#failover-with-pci-devices).

The other devices in that device's IOMMU group are passed through with it. You
can also name them, as a GPU and its audio function are often named, each by
its address: each device is then passed through once.

A device's selector is read in a fixed order: `mapping`, then `sriov`, then
`type` / `vendor`, then `address`. The first one set decides, and the fields
after it are ignored. So `type: "gpu"` with an `address` is a request for any
free GPU, not for that address.

### Common vendor IDs

| Vendor | ID | Common devices |
|--------|----|----------------|
| NVIDIA | `10de` | GPUs (A100, H100, RTX) |
| AMD | `1002` | GPUs (MI300, Instinct) |
| Intel | `8086` | NICs, QAT accelerators |
| Mellanox | `15b3` | ConnectX NICs, InfiniBand HCAs |

## SR-IOV virtual functions

SR-IOV lets a single physical NIC present multiple virtual functions (VFs), each assignable to a different VM.

### Compose configuration

```yaml
networks:
  fast-net:
    type: "sriov"
    pf: "eth1"
    spoof-check: true

vms:
  worker:
    devices:
      - type: "network"
        sriov: true
        parent: "eth1"
        count: 1
```

### Daemon configuration

```yaml
pci:
  sriov:
    managed: true                    # litevirt may CREATE a VF pool on an adopted PF
    max_vfs_per_pf: 8                # pool size, clamped to the PF's hardware max
    managed_pfs: ["0000:41:00.0"]    # PFs litevirt may create VFs on (allowlist)
```

VF allocation follows a strict policy:

- **Reuse first, on any PF.** litevirt claims a free VF (one present on the host and
  unassigned in inventory) via an atomic compare-and-set. This works whether or not
  the PF is managed, and it **never writes `sriov_numvfs`**.
- **Create only on an adopted, empty PF.** When `managed: true` and the PF is in
  `managed_pfs` and its VF pool is currently empty, litevirt creates a pool of
  `min(max_vfs_per_pf, hardware sriov_totalvfs)` VFs **once**, then claims exactly what
  the request needs. A request larger than that cap is rejected up front.
- **Never resizes.** litevirt does not grow, shrink, or destroy a VF pool. A PF that
  already has more VFs than `max_vfs_per_pf` is marked degraded
  (`litevirt_sriov_degraded{reason="vfs_over_cap"}`); its existing free VFs can still be
  reused, but litevirt refuses to (re)create its pool. A PF with a non-empty pool short
  of free VFs fails the request with **no sysfs write**.

With `managed: false` (default), the operator provisions VFs; litevirt reuses the free
ones but never creates any:

```bash
echo 8 > /sys/class/net/eth1/device/sriov_numvfs
```

Configured-but-broken managed PFs surface as `litevirt_sriov_degraded` with
`reason="pf_not_found"` (malformed/absent BDF) or `reason="pf_not_sriov"` (not SR-IOV
capable); the gauge is aggregated across all PFs, so a reason stays set while any PF
still has it.

> Mixed-version note: SR-IOV policy is enforced by the host that owns the hardware. Do
> not set `managed: true` on a PF until its owning host runs a build that supports this
> policy — an older daemon ignores the allowlist and cap.

## Hot-plug

Attach a GPU to a running VM:

```bash
lv attach-pci my-vm --type gpu --vendor 10de
```

Detach a device:

```bash
lv detach-pci my-vm 0000:41:00.0
```

Hot-plug is supported for most PCI devices. Some devices (particularly GPUs with active CUDA contexts) may require the VM to be stopped first.

### Spare PCIe root ports

A q35 guest (the default machine type) attaches every hot-plugged device — a
disk, a NIC, or a PCI device — to a free `pcie-root-port`. A domain with no
spare root port left fails the attach with libvirt's "No more available PCI
slots", which litevirt reports as `FailedPrecondition` (an operator fix) rather
than a generic internal error, and names what can be done about it:

```
attach disk: no free PCI slot on this q35 guest (detach another device first;
raising pci.spare_pcie_root_ports gives more spare ports only to a newly defined
domain, such as one made with `lv clone` — see docs/pci-passthrough.md, "Spare
PCIe root ports"): internal error: No more available PCI slots
```

`pci.spare_pcie_root_ports` (default 4, see configuration.md) is the number of
root ports a NEWLY-DEFINED q35 domain is left with that none of its own devices
sit on — headroom for later hot-plugs. A rolled-back attach is as clean as any
other failed attach: nothing is left partially attached and the VM's mutation
barrier is released.

**The spares are added after libvirt has placed the domain's devices.** libvirt
puts every device that has no PCI address — including the USB and
virtio-serial controllers it adds by itself — on the first free root port, and
only creates new ports for what is still unplaced. Root ports declared in the
generated XML would just be filled by the VM's own disk, NIC and balloon. So
litevirt defines the domain without any, reads back what libvirt assigned
(`virsh dumpxml --inactive`), and redefines it with as many new, empty ports
as it is short of the configured number. On libvirt 10, a VM with one disk
and one NIC uses five ports; libvirt leaves one free on its own, and the
top-up adds three. The top-up is best effort: if it fails, the VM is still
created, with the one spare libvirt left, and a warning is logged.

A cold attach (to a stopped VM) also takes a free root port, so it uses up a
spare just as a live attach does; detaching a device frees its port again.

**This does not retroactively change an existing VM.** The value is daemon
config, not part of a VM's persisted spec. A redefine that preserves the
existing domain XML in place (device hot-plug on a stopped VM, most reconciler
sweeps, migration) never touches the controller list, so an existing VM keeps
exactly the root ports it has. Only a FULL regenerate — create, import, clone,
promote, live-restore, a failover start, or the rarer update/reconcile paths
that can't patch in place — tops up to the node's current value. There is no
backfill command. In practice:

- a VM created before spare ports existed has the one free port libvirt
  left it;
- a VM created by a build that declared the spares in its generated XML
  (the first version of this feature) has none free: its first hot-plug
  fails with `FailedPrecondition` until a device is detached;
- either kind gets the configured spares only when its definition is fully
  regenerated, or by making a new domain from it with `lv clone`.

**This is a non-issue for migration.** Neither live nor cold migration ever
regenerates a domain's XML from spec: live migration streams the source's
actual live definition to the target, and cold migration dumps the source's
XML and defines that verbatim on the target. Either way the migrated domain
keeps exactly the root-port controllers it already had — a cluster where nodes
disagree on `pci.spare_pcie_root_ports` cannot produce a migration-incompatible
domain, because migration never consults this config on either side.

## Placement intelligence

When a VM requests PCI devices, the placement engine considers:

- **IOMMU groups** — all devices in a group must be assigned together
- **NUMA locality** — prefers devices on the same NUMA node as the VM's CPUs
- **NVLink topology** — for multi-GPU requests, prefers GPUs connected via NVLink
- **PCIe root port** — tracks which devices share PCIe bandwidth

## Migration with PCI devices

No migration, live or cold, carries a passthrough device, and a stopped VM
cannot be cold-migrated while it holds one either, whatever its disks. Once
`hardware_v2` is active, the route that works is to release the device from the
VM, move the VM, and attach a device on the target:

1. Stop the VM.
2. `lv detach-pci <vm> <pci-address>`
3. `lv migrate <vm> <host> --cold`
4. `lv attach-pci <vm> --address <pci-address on the target>`; find a free one
   with `lv host devices <host>`.

The target needs its own free device: the source's address is not reused, and
the device's ROM, multifunction and vGPU settings are not carried over, so
re-attach them as you did the first time. `lv attach-pci <vm> --address` is the
form that works on a stopped VM; the `--type` form attaches to a running VM only.

Before `hardware_v2` is active, detaching and attaching on a stopped VM are
refused, so there is no supported way to move a VM that holds a device.

A migration of a VM that still holds a device is refused up front, naming the
device and (once `hardware_v2` is active) this route, before anything is done on
the target. This covers `--cold` of a running VM with a PF, a live migration,
and `--cold` of a stopped VM. Once the cluster has latched `hardware_v2`, any VM
holding PCI intent is refused this way.

SR-IOV VFs are hot-detached from the guest just before the copy starts. The VM
keeps owning them on the source until the cutover commits, so no other VM can
claim one mid-move. Then they are released, and the target allocates its own.
If the migration fails, they go back into the guest. A host-local device lease
records them before the first detach. If the daemon restarts in the middle of
the move, startup recovery reads that lease and puts the VFs back into a guest
still running on the source, or releases them if the guest has moved.

## Failover with PCI devices

When a host fails, a VM with PCI passthrough devices is recovered only onto a
host that has a free device of the kind each of its devices needs: a `type`,
`vendor`, `model`, `mapping` or SR-IOV selector as it is written, and a device
named by `address` as the vendor and device id that the failed host's
inventory records at that address. The address itself is not carried over. The
device at the same address on another host is whatever that host has there,
and it is never bound. The new host starts the VM with a matching device of
its own, at whatever address that device has, and records it: from then on
that device, not the failed host's inventory, says what kind the VM needs.
A VM moved while stopped gets its device the same way at `lv start`, which
refuses when the host has none.

When no surviving host has a free device of that kind, the VM stays on its
failed host and is not started anywhere without its devices. Failover records
the condition `vm_failover_held` (subject `vm/<name>@<host>`, a warning), a
`vm.failover.held` event and a `failover.skip` audit entry, each naming the
device it waits for and what you can do. Each failover pass tries again, so
freeing a device of that kind on a surviving host, or adding a host with one,
recovers the VM there. When the failed host comes back, it starts the VM there
with its own devices. Either way the record clears.

To recover such a VM without its devices, give it the label
`litevirt.failover_without_devices=true` in its spec's `labels`. The next
failover pass then recovers it like any other VM. Its new host starts it with
its devices if it has all of them, and otherwise without any. The VM's state
detail reads `running without its PCI passthrough devices: ...`, and a
`vm.passthrough_dropped` event and audit entry are recorded. A host that rebuilds a VM's domain
for any other reason (a guest that died under a running row) also starts it
only with its devices, or under the same label.

These guarantees hold once every node runs a build that has them: during a
rolling upgrade, an older coordinator or host can still recover the VM
without its devices, or with whatever device sits at its old address, as
earlier releases did.

## Snapshots and restores with PCI devices

A memory snapshot (`lv snapshot create --memory`) saves the guest's RAM and
device state, and libvirt cannot save the state of a PCI passthrough device
(nor of an mdev, an `<interface type='hostdev'>` or an `<interface type='vdpa'>`;
a USB device is fine). Such a snapshot is refused with `FailedPrecondition`
before the guest is paused or its disks are touched. A disk-only snapshot
(without `--memory`) is still taken. A running Secure Boot or vTPM VM, which needs `--memory`, must be
stopped for its snapshot.

`lv backup restore-live --auto-start` attaches the backed-up VM's PCI devices
the way `lv run` does, resolving them against the restoring host's
inventory. If the host cannot provide one, the restore is refused rather than
starting the VM without it. Add `--without-devices` to start it without them:
they are removed from its spec and the drop is audited. `lv clone` never
copies PCI devices.

When a create or a live restore fails after its devices were attached, and its
domain is not running, the devices are released and unbound from vfio-pci
straight away.

## Resource mappings

A **resource mapping** is a cluster-wide alias for an equivalent passthrough device
that exists (at possibly different PCI addresses) on more than one host. A VM that
requests a device *by mapping name* can be placed on — or migrated to — any host
registered under that mapping; litevirt resolves the name to the concrete PCI
address on the target host at allocation time. This is the litevirt analog of
Proxmox 8 "resource mappings".

```bash
lv mapping create gpu-a100 --description "NVIDIA A100 pool"
lv mapping add-device gpu-a100 0000:41:00.0 --host kvm-01 --vendor 10de --device A100
lv mapping add-device gpu-a100 0000:81:00.0 --host kvm-02 --vendor 10de --device A100
lv mapping ls
```

Reference it from a VM via the compose device spec:

```yaml
    devices:
      - mapping: "gpu-a100"
```

Mappings are CRDT-replicated (the `resource_mappings` table), so every daemon and the
`/resource-mappings` UI page see a consistent view. Placement/migration eligibility
checks that a candidate host has a device registered under each mapping the VM needs.

On a host with more than one device under a mapping, the mapping resolves to
its **lowest** address there, and that device must be free. A VM keeps the
device it took when it was created: an update applied to the running VM (a
live change, or a reconfigure and restart) does not resolve its mapping again.
A recreate does, so after adding a lower address that another VM holds, a
recreate on that host is refused, before anything is deleted, until the
mapping is changed back or the device is freed.

Every mapping change goes through the daemon, which checks `resourcemap.write` at
`/` and writes one signed audit row naming the caller, the mapping, and the state
before and after:

```
resourcemap.device.add   gpu-a100   before=none after={host=kvm-01 address=0000:41:00.0 vendor="10de" device="A100"}
resourcemap.device.rm    gpu-a100   before={host=kvm-01 address=0000:41:00.0 vendor="10de" device="A100"} after=none
```

`lv mapping rm` and `lv mapping rm-device` fail with not found when the mapping or
device is not there, rather than reporting a removal that changed nothing. The
actions are listed in [audit-log.md](audit-log.md#reading).
