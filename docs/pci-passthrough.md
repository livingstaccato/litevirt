# GPU & PCI Passthrough

litevirt supports assigning PCI devices (GPUs, NICs, NVMe drives) directly to VMs for near-native hardware performance.

## Prerequisites

1. **IOMMU enabled** in BIOS and kernel:

```bash
# Intel
GRUB_CMDLINE_LINUX="intel_iommu=on iommu=pt"

# AMD
GRUB_CMDLINE_LINUX="amd_iommu=on iommu=pt"
```

Update GRUB and reboot after changes.

2. **vfio-pci module loaded:**

```bash
modprobe vfio-pci
echo "vfio-pci" >> /etc/modules-load.d/vfio.conf
```

3. **Device not bound to host driver** — litevirt handles binding/unbinding automatically.

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

### By exact PCI address

```yaml
    devices:
      - type: "gpu"
        address: "0000:41:00.0"
```

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

PCI passthrough devices cannot be live-migrated. Options:

1. Hot-detach the device, migrate, hot-attach on the new host
2. Cold migrate (stops the VM)
3. Use SR-IOV VFs which can be detached/reattached more gracefully

The migration command will fail with an error if the VM has PCI devices attached and `--cold` is not specified.

SR-IOV VFs are hot-detached from the guest just before the copy starts. The VM
keeps owning them on the source until the cutover commits, so no other VM can
claim one mid-move. Then they are released, and the target allocates its own.
If the migration fails, they go back into the guest. A host-local device lease
records them before the first detach. If the daemon restarts in the middle of
the move, startup recovery reads that lease and puts the VFs back into a guest
still running on the source, or releases them if the guest has moved.

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
