# Compose Stacks

litevirt uses a Docker Compose-inspired YAML format to define multi-VM stacks. Deploy with `lv compose up`.

## Example

```yaml
name: "web-app"

images:
  ubuntu:
    source: "https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img"
    format: "qcow2"

networks:
  frontend:
    type: "vxlan"
    vni: 1000
    subnet: "10.0.100.0/24"
    host-isolation: true              # VMs can't reach the hypervisor
    dns: ["1.1.1.1", "8.8.8.8"]      # DNS for isolated VMs (optional, these are defaults)
  lan:
    type: "bridge"
    interface: "br0"
    subnet: "192.168.10.0/24"
    gateway: "192.168.10.254"         # the upstream router, when it is not litevirt's
    reserved-addresses: ["192.168.10.253"]   # other infrastructure no guest may claim
    allowed-vlans: [100, 101]         # the VLANs a trunk: NIC on this network may carry

vms:
  base-vm:
    image: "ubuntu"
    cpu: 2
    memory: "4G"
    replicas: 0                       # Don't deploy the base itself

  db:
    extends: "base-vm"
    cpu: 4
    memory: "8G"
    disks:
      root: "20G"
      data:
        size: "100G"
        bus: "virtio"
    network:
      - name: "frontend"
    placement:
      anti-affinity: ["web"]
    restart:
      condition: "on-failure"
      delay: "10s"
      max-attempts: 5
      window: "1h"

  web:
    extends: "base-vm"
    replicas: 3
    stop-grace-period: "30s"
    disks:
      root: "20G"
    network:
      - name: "frontend"
    cloud-init:
      userdata: |
        #cloud-config
        packages: [nginx]
        runcmd:
          - systemctl enable --now nginx
    placement:
      anti-affinity: ["db"]
      spread: true
      max-per-node: 1
    depends-on:
      db:
        condition: vm_healthy
    loadbalancer:
      vip: "10.0.100.50/24"
      snat: true                    # Outbound VM traffic SNATted to VIP
      ports:
        - listen: 80
          target: 80
    healthcheck:
      type: "http"
      target: "http://localhost:80/"
      interval: "10s"
      retries: 3
      action: "restart"
```

## Images

An `images:` entry's `source` is downloaded at deploy time only when no host in the cluster holds a ready copy of the image. When one does — on the host serving the deploy or on a peer — that copy is used: the VM's host pulls it from the peer when the VM is created. A `checksum` in the entry must then match the checksum recorded for that copy; a mismatch, or a copy with no recorded checksum, fails the deploy with both checksums named, and the source is never downloaded over it. Correct the checksum, or remove the image with `lv image rm` so the source is downloaded again.

## Deploy and manage

```bash
lv compose up                    # Deploy (reads litevirt-compose.yaml)
lv compose up -f mystack.yaml    # Deploy from specific file
lv compose diff                  # Preview what would change
lv compose ps                    # List VMs in the stack
lv compose down                  # Tear down
```

`compose up` prints the plan and asks for confirmation; `-y` skips the prompt.
`up` and `down` refuse to prompt when stdin is not a terminal (ssh without
`-t`, CI, a pipe) and exit non-zero instead of waiting — pass `-y` in scripts.

VM names are cluster-wide, not per stack. A workload the plan would create —
replica names such as `web-1` included — whose name a VM of another stack, or
of no stack, already holds is refused before anything runs: `compose up`'s plan,
`compose diff` and the deploy itself fail with `pre-deploy validation failed:`
and a line such as `vm "v1" already exists in stack "app" — rename it in this
file or delete it there` (`... already exists outside any stack ...` for a VM
created outside compose). A VM of the same stack is not a collision; the plan
updates it. Container names are per host, so a container collides only with a
container of that name on the host the plan places it on (`container "web"
already exists on host "node-1" in stack "app" ...`), and VMs and containers do
not collide with each other. `compose diff` prints the server's plan, the
one `compose up` applies, so it reports container collisions too.

`compose up` ends with `Stack "<name>" deployed.` and exit status 0 only when
every action in the plan succeeded. If any VM action fails, each failure is
printed as it happens, the success line is withheld, and the command exits
non-zero with a summary such as `stack "web": 1 of 3 actions failed (web-2)`.
The actions that did succeed are not rolled back; fix the cause and re-run
`compose up` to converge the rest.

A failed action is any create, update or delete the daemon could not carry
out — including a scale-down delete, the delete half of a recreate (the
recreate then stops rather than create over a VM that was never torn down),
a `depends-on` wait that timed out, a VM held back because a `depends-on`
dependency of it was not met (see [Boot ordering](#boot-ordering-depends-on)), a `blue-green` old (blue) VM that could not
be removed after its `-green` replacement came up, and a `snapshot-and-replace`
`-next` VM that could not be created or did not become healthy. After such a deploy the stack is
recorded as `degraded` rather than `active` (the STATE column of
`lv compose ls`), and the `stack.deploy` audit entry has result `error` and
names the failed VMs. The new compose file is still stored: it is the desired
state, and the next `compose up` plans against the live VMs, so it retries
exactly the actions that failed and the stack returns to `active` once they
all succeed.

`compose down` deletes only the VMs the stack created: a VM is the stack's when
its record names the stack, as the stack's `compose up` records it. A VM that
merely has a member's name — created on its own (by the UI, by hand or by another
stack) after a failed `compose up` left that name in the stored file — is left
alone, logged at WARN, and reported as `kept <name>: ...`, naming the stack it
belongs to. Such a VM is not counted as a deletion. A stack network that such a VM (or a
container the stack did not create) is attached to is kept too, reported as
`kept network <name>: used by ...`, so it is not pulled out from under it.
In a stack whose last deploy failed (`degraded`), a member the stored file
names that no host has, because its create failed, is reported as
`absent <name>: never created; nothing to delete`, and is neither a deletion
nor a failure. It is taken as absent only when this host has no record of it
and every other host was asked and answered that it has none.

`compose down` follows the same rule. It ends with `Stack "<name>" torn down.`
and exit status 0 only when every VM and container was deleted, every stack
network deprovisioned, and the stack's firewall rows and backup repos removed.
If any could not be — or the stack's containers could
not even be listed — each failure is printed, named for what was left (a VM or
container name, `network <name>`, `containers (list failed)`, `firewall rows`
or `backup repos`), the success line is withheld, and the command
exits non-zero with a summary such as `stack "web": 1 of 3 deletions failed
(web-2)`. A member VM that another delete removed first (`lv rm`, or the
background retry) counts as deleted. The stack is then left in state
`deleting`, the daemon keeps retrying the teardown in the background (it takes
a teardown up no sooner than a minute after it began, leaving a `compose down`
still running to finish, and keeps the VMs' disks when the teardown was asked
to keep them, `keep_disks` on the REST or gRPC stack delete, or was begun by a
host that did not record whether it was; disks kept for that last reason are
named by `disk_leftover`), and
the `stack.delete` audit entry has result
`error` and names what was not removed. A `compose up` of a stack in state
`deleting` is refused until the teardown has finished: wait until
`lv compose ls` no longer lists it, then run `lv compose up` again. If the
teardown does not finish, `lv compose down --name <stack>` retries it, and
`lv rm <vm> --force` clears a member that is stuck. While any of the stack's VMs or
containers is left, none of its networks is deprovisioned: a deleted network
is torn down on every host, and would be pulled out from under that workload.
The background retry deletes the remaining VMs and containers first, and
removes the networks only once they are all gone; when it finishes, the stack's
security groups, ip sets, cluster rules and backup repos go with it. A host keeps
the firewall it holds of the stack, and the stack `deleting`, when the teardown's
caller did not hold `sg.write` at `/` (the `stack.firewall_teardown_held` health
condition, see [diagnostics.md](diagnostics.md)). A first
`compose up` of a stack that fails before it issues any workload action removes
the security groups, ip sets and cluster rules it had just written; the
cluster default-deny and backup repo registrations stay, and its error says
when the default-deny it set stays on. A `default-deny: true`
in a file leaves a cluster default-deny that an operator or another stack set
as it is, owned by them. When the stack that owns the cluster default-deny goes
down, or is redeployed without it, the deny passes to another stack whose file
asks for it, and is removed only when none does; while another stack's stored
file cannot be read, it stays. A deploy asking for default-deny sets it again
once its record is written if the cluster no longer denies, and the background
stack reconciler sets it for a stack that asks for it whenever the cluster has
no default in force, whatever removed it (a redeploy by a caller with
`sg.write` that drops default-deny is not undone: it records that before it
removes the deny; for a stack with no recorded intent it can be, and the deny
is then reported as below). A deny a live stack owns and nothing asks for any more is
kept, never removed by the reconciler, and raises the
`stack.firewall_deny_unasked` health condition; `lv firewall default-deny off`
turns it off. Stacks going down
at the same time never hand the deny or a repo to each other: a stack that
went down is passed over. The background reconciler hands a deny or repo a
torn-down stack still holds to a live stack that asks for it. Otherwise it
unregisters such a repo, unless a backup schedule names it, and keeps such a
deny: it never turns the cluster default-allow on its own, and raises the
`firewall.default_deny_orphaned` health condition instead (see
[diagnostics.md](diagnostics.md)). The web UI's stack **Destroy** action
reports the same way: it says the stack was destroyed only after a complete
teardown, and otherwise shows an error naming each failure and stays on the
page.

## VM definition

```yaml
vms:
  <name>:
    image: "ubuntu"           # Base image name (required unless iso is set)
    iso: "isos/debian-12.iso" # Installer ISO, attached as a CD-ROM and booted first: <pool>/<file>.iso, or (Admin) a host path — judged as any create's ISO (storage.md, "Installer ISOs"). A bare name with no '/' keeps its older meaning: an image-store name used as the boot image instead of image
    kind: "vm"                # vm (default) | lxc | oci — see "Workloads" below
    cpu: 2                    # vCPUs (default 2)
    max-cpu: 8                # vCPU hotplug ceiling (> cpu); with live_resize, cpu grows live up to it
    cpu-mode: "host-model"    # host-passthrough | host-model | custom (default host-model)
    cpu-model: "x86-64-v3"    # required by cpu-mode: custom; invalid for any other mode
    cpu-limit: 2.5            # Cap on the VM's TOTAL CPU, in host cores (fractions ok; 0/unset = unlimited; at most cpu). Live
    cpu-shares: 200           # CPU weight under contention: cgroup v2 cpu.weight, Proxmox cpuunits (1-10000, default 100). Live
    memory: "4G"              # Memory: "4G", "4096M", or 4096 (MiB) — boot allocation
    min-memory: "1G"          # Ballooning floor the host may reclaim to (0 = none)
    max-memory: "8G"          # Ballooning ceiling the guest may inflate to (0 = fixed at memory)
    machine: "q35"            # Machine type: q35 (default) or pc
    firmware: "uefi"          # Firmware: uefi (default) or bios
    secure-boot: false        # UEFI Secure Boot, as lv run --secure-boot (uefi + q35; default false)
    tpm: false                # vTPM, as lv run --tpm (default false)
    replicas: 1               # Number of instances (default 1)
    guest-agent: true         # QEMU guest agent (default true for images)
    ip-hint: "10.0.1.50"     # IP hint for non-cloud-init VMs (used by DHCP reservation)
    onboot: true              # Autostart when the host boots (default false)
    startup-order: 10         # Lower starts first among onboot VMs (default 0)
    start-delay: 5            # Seconds to wait after starting this VM before the next
    stop-delay: 0             # Seconds to wait after stopping this VM in an ordered shutdown
```

When `max-memory` exceeds `memory`, the VM gets a virtio memory balloon and can be
inflated/deflated at runtime (`lv set-memory <vm> <MiB>`); `min-memory` is the floor.
`onboot` VMs are started in `startup-order` when their host boots — a plain daemon
restart is a no-op (running VMs are left alone), only an actual host reboot triggers it.
A host boot starts every `onboot` VM that is not running, including one its operator
stopped (`lv stop`) before the reboot; a plain daemon restart leaves such a VM stopped.
The daemon tells the two apart by the kernel's boot ID. It records the boot in its data
directory (`onboot-boot-id`) as soon as it decides, together with each VM whose operator
stop the boot still has to override. A daemon restart later in the same boot starts only
those VMs, and only while their row still carries that stop; once the boot's start of a
VM is under way, a stop made after it is kept, across restarts too. With no record (the
first start of a build that keeps it), or a record that cannot be read or is damaged, a
VM its operator stopped is left stopped, and the daemon logs why. A stop made by a host
drain, or a stopped VM a failover moved to the host, is not started at boot either.
The start waits through the daemon's warm-up and any loss of quorum. While it waits, it
is dropped if `onboot` is turned off or the VM's stop is replaced by a different one (a
drain's, say). A second `lv stop` of the still-stopped VM records the same stop, so it
does not cancel the boot's start. Nor does an `lv start` then `lv stop` made before the
boot reaches the VM: a VM behind earlier VMs' `start-delay`s waits the sum of those
delays, and a stop made in that wait reads exactly like the one the boot found, so the
boot (or a daemon restart in that wait) still starts it. Turn `onboot` off to cancel a
boot start. If the daemon cannot write its record, it removes the old one and logs an
error: a restart later in that boot then honours every operator stop, so an onboot VM
the boot had not started yet stays stopped until started by hand. Likewise, if the
daemon cannot read its VM list at boot (retried 4 times over about 0.6 s), it starts no
`onboot` VM, logs an error, and records the boot owing nothing: a VM its operator
stopped stays stopped on that boot.

A VM whose `lv rm` failed after its stop step (an undefine or a device release that
failed) is recorded as stopped by its operator, the same as `lv stop`, so a host boot
starts it again if it is `onboot`. Its disks are intact; retry the delete.

`stop-delay` is the mirror of `start-delay` for an **orderly host shutdown**: running
`lv host shutdown-workloads <host>` stops that host's VMs in *reverse* `startup-order`
(highest first), waiting each VM's `stop-delay` before the next. It is an explicit
operator action — a normal daemon restart/upgrade leaves VMs running, so `stop-delay`
is consumed only by that command, never by routine daemon lifecycle.

`cpu-mode` controls how the guest CPU is exposed: `host-model` (the default — the
closest named model the host supports plus its feature flags, so the guest gets the
host's SSE4.2/AVX/AVX2 and stays migratable to an equal-or-richer host),
`host-passthrough` (expose the host CPU verbatim — marginally faster and the only
mode carrying nested virtualization, but it pins live migration to identical
hardware), or `custom`, which requires `cpu-model`.

Left unset, `cpu-mode` takes the cluster-wide `vm.default_cpu_mode`. It is not left
empty: an empty mode emits no `<cpu>` element and drops the guest onto QEMU's
`qemu64`, which has no AVX at all. Changing either field is restart-class — the CPU
bakes into the domain XML — so a deploy reconfigures and restarts the same VM
(disks kept), and an update under `strategy: in-place` (set in the VM's `update:`
block) refuses it: in-place never restarts a VM.

### Noisy-neighbour limits

Three settings keep one guest from starving its neighbours. They are the
counterparts of Proxmox's `cpulimit`, `cpuunits` and the NIC `rate=`:

- `cpu-limit` caps the VM's **total** CPU in host cores, across all its vCPUs:
  `2.5` lets a 4-vCPU guest burn at most two and a half cores in total, so one busy
  thread can use a full core, exactly as Proxmox's `cpulimit` behaves. It must be at
  most `cpu` (a cap above the vCPU count could never be reached) and at least `0.01`.
  It is applied as libvirt's whole-domain `global_period`/`global_quota` (the
  domain cgroup's `cpu.max`), so it does not depend on the vCPU count and a vCPU
  change leaves it alone.
- `cpu-shares` is the VM's weight when the host is contended: Proxmox's `cpuunits`,
  the cgroup v2 `cpu.weight` scale (1-10000, default 100), and that number is what
  is stored and what `lv inspect` shows. `200` is twice the default, so the Proxmox
  numbers carry over unchanged. Each host renders the value its own cgroup version
  wants when it defines the domain: unchanged on cgroup v2, scaled by 1024/100
  (minimum 2) on cgroup v1, whose default `cpu.shares` is 1024. A cluster that mixes
  v1 and v2 hosts therefore renders per host, and a failover rebuild re-renders for
  the new host. A migration does the same: a cold move defines the domain on the
  target at the target's scale, and a live move hands libvirt a destination
  definition rendered for the target's cgroup version, which the target reports
  (a v1 to v2 move of a VM with weight 977 or more is not refused). litevirt owns the domain definition, so a `<shares>` it finds there, even one it did not write (set with `virsh schedinfo --config`, say), is rewritten to the stored weight, or to the default when none is stored, on every migration. Clearing it (`0`, or dropping the key) writes the default weight
  back. It only matters under contention: an idle host lets every guest run flat out.
- `rate` on a `network:` entry caps that NIC in MB/s (10^6 bytes), the same in
  each direction, rendered as libvirt `<bandwidth>` (whose `average` is in kilobytes
  of 1000 bytes, so `rate: 10` is `average='10000'`). It is set per NIC, so a
  VM's management NIC can stay unthrottled.

All three **apply to a running VM with no restart**: a deploy that changes them is
an in-place update (`~ update`, `applied in place`), as is `lv update`'s
`--cpu-limit`, `--cpu-shares` and `--nic-rate` — to the persistent definition as
well as the running domain, so the value survives a reboot and a stopped VM takes
it at its next start. They are carried through live and cold migration and rebuilt
on failover from the stored spec. Dropping a key from the file removes that limit.

`cpu-limit`, `cpu-shares` and `rate` apply to VMs only; setting one on an `lxc` or `oci` entry is an error.

A capped VM is still **placed and charged for its full vCPU count**: the cap bounds
how much CPU the guest may take, not how many cores it needs scheduled onto, and it
can be raised or removed live, so placement and project quota never count a capped
VM as smaller than its `cpu`. `lv inspect <vm>` shows the stored values as
`cpuLimit`, `cpuShares` and each network's `rateMbSec`.

During a rolling upgrade a limit cannot be set until every host runs a build
that understands it: setting `cpu-limit`, `cpu-shares` or a NIC `rate` is refused
("the cluster upgrade must finish first") until the release token
`release_2026_11_v1` has latched, because an older host would ignore the fields, and
an older owner that rewrites a VM's stored spec would drop them. The request is refused
early, without recording anything, while the token has not latched (an entry node
checks this before forwarding an update, so an older owner is never handed a limit it
would drop). The host that performs the write (for an update, the VM's owner) runs
the full gate after permission and validation checks, and the first use is recorded
cluster-wide immediately before the limit's first data (the `vm_limits` feature
in `lv cluster upgrade-status`). Files and updates without limits are not affected,
and clearing a limit (`0`) is always allowed. Once a limit has been set, rolling back
below the release puts each node into WAL quarantine until it is upgraded again;
a cluster that never sets one can still roll back. A promotion of a replica, or a
live restore, whose spec carries limits is never refused for them: they are kept
once the gate grants them; a value a create would refuse is dropped by itself, the
valid ones kept; and all of them are dropped before the latch or when the gate
refuses after it. Each drop is logged by name and audited
(`vm.release_features_dropped`).

With `replicas: 3`, VMs are named `web-1`, `web-2`, `web-3`. With `replicas: 1`, the base name is used directly.

## Workloads (VMs and containers)

The unified `workloads:` map holds VMs *and* containers; the `kind:`
discriminator selects the runtime. Entries without `kind:` (or `kind: vm`)
behave exactly like a `vms:` entry. The legacy `vms:` map is accepted and is
folded into `workloads` with `kind: vm` at parse time.

```yaml
workloads:
  app-vm:
    kind: vm                  # default; a libvirt-managed VM
    image: "ubuntu"
    cpu: 2

  sidecar:
    kind: lxc                 # a system container (LXC)
    image: "ubuntu"

  nginx:
    kind: oci                 # pull an OCI image and run it as an LXC container
    image: "docker.io/library/nginx:latest"
```

`kind: lxc` and `kind: oci` route to the container runtime (see
[`docs/containers.md`](containers.md)) and are full compose citizens: `lv compose
up` creates **and starts** them, re-apply is idempotent (unchanged containers are
left alone), a changed spec recreates the container (the plan says `recreate —
the container is replaced`: containers have no in-place reconfigure), and `lv compose down`
removes them. Placement is **LXC-aware** — containers are only scheduled onto
hosts that advertise the container runtime, so they never land on a node that
can't run them. Image forms: `kind: lxc` takes a download template (`image:
"alpine:3.21"`) or a rootfs path; an OCI **registry ref** must be pre-pulled
today (`lv ct pull <ref> --dest <name>`, then set `image:` to the library item
`<data_dir>/oci/<name>`; any other rootfs path is a host path the deploying
caller needs the Admin role to name — see "Host paths a container is given" in
[containers.md](containers.md)). A container workload may set `privileged: true` (no user namespace) and
`confinement: legacy` (AppArmor nesting, the template's seccomp and
capabilities); deploying either needs the Admin role, and changing either on a
deployed container changes nothing until `lv ct convert` (see "Security" in
[containers.md](containers.md)). A recreate of an existing member (an image,
cpu or memory change) keeps that container's current privilege mode and
confinement when the stack file states none — a member deployed by an earlier
release stays privileged with legacy confinement — and only a brand-new member
gets the unprivileged, confined defaults. A privileged or legacy-confined
member recreated with the **same image** (a cpu, memory or network change)
is carried over for whoever may deploy the stack, as before this release, and
never given a silently unprivileged replacement; when the deployer is not an
Admin, the daemon logs a WARN naming `lv ct convert` and, once the new
container exists, records a `ct.recreate-security` audit event. A recreate
that **changes the image** of such a member runs a rootfs of the deployer's
choosing as root on the host, so it needs what exec in that member needs:
the Admin role or the `ContainerRoot` role on it (`ct.exec` is not
enough; see [auth.md](auth.md)). So does a recreate from the same OCI
library item path after an Admin's `lv ct pull --project` replaced the
item's content: the member's host checks the item is still the pull the
member was built from, and copies that pull aside before the delete; the
member is rebuilt from that copy, whatever becomes of the item meanwhile.
Any recreate from a rootfs path takes such a copy, so the member's host
needs room for the rootfs beside the running member, or the recreate is
refused with the member kept. The copy serves that recreate's own create
only: a redeploy after a host or deploy died between the delete and the
create creates the member anew from the item as it is then. An opt-out the member did not already have
needs the Admin role. A recreate judges only the member on the host it
targets, and only one that carries this stack's label; another stack's
container of the same name is refused, not replaced. These refusals, and the
create's own checks — `ct.create`, the host-path authority a rootfs-path
`image:` needs, and the protected-place and image-owner checks of that path
on the member's host — come before anything is deleted, whichever host the
deploy entered on: the member keeps running as it was. So does the fetch of
the new image: the member's host downloads and verifies it (or, for a
rootfs path, checks that it is a root filesystem there) first, and an image
it cannot fetch refuses the recreate with the member left as it is. (When the member is
on another host, that host runs its checks when it is asked to delete the
member, and refuses the delete; a host still on an earlier release runs
them at the create, after the delete.) A member redeployed from the rootfs
path it already uses keeps it, as before this release. A member built from
an OCI library item passes the image-owner check when the item on the
member's host has no owner or is the member's project's, as before this
release; when it belongs to another project (an Admin claimed it for that
project, or the member was moved to a host where that project pulled its
own item of the name), a redeploy by a caller without the Admin role is
refused. `privileged: false` in a stack file is the same as leaving it out:
to move a member over, use `lv ct convert`. Each container is given its own
copy of the rootfs, so one pull backs any number of containers and `compose
down` leaves the pulled template untouched.
Remaining follow-ups: OCI registry-ref auto-pull; in-place reconfigure
(cpu/mem changes recreate the container rather than live-tuning); and full
network/IPAM/security-group provisioning for container NICs (a container sharing
a stack network with a VM uses the bridge the VM path provisions).

## Service inheritance

Use `extends` to inherit fields from a base VM definition, reducing duplication across similar VMs:

```yaml
vms:
  base:
    image: "ubuntu"
    cpu: 2
    memory: "4G"
    replicas: 0               # Don't deploy the base itself

  web:
    extends: "base"
    memory: "8G"              # Override memory
    replicas: 3

  worker:
    extends: "base"
    cpu: 4                    # Override CPU
    labels:
      role: "worker"
```

Merge rules:

- **Scalars** (image, cpu, memory, firmware, etc.) — child wins if non-zero; zero-value inherits from parent.
- **Maps** (labels, disks) — keys are merged, child wins on collision.
- **Slices** (network, devices) — child replaces entirely.
- **Pointer structs** (placement, migrate, healthcheck, etc.) — child `nil` inherits parent; child non-nil replaces the entire struct.

Chained inheritance works: `top extends mid extends base`. Cycles are detected and rejected. Set `replicas: 0` on the base to prevent deploying it.

## Shutdown timeout

```yaml
    stop-grace-period: "30s"  # ACPI shutdown timeout before force-kill
```

When a VM is stopped (via `lv stop`, stack delete, or rolling update), litevirt sends an ACPI shutdown signal and waits up to the specified duration. If the VM hasn't shut down by then, it is force-killed.

Supports `s` (seconds), `m` (minutes), `h` (hours). Defaults to 30 seconds if not set.

## Disks

```yaml
    disks:
      root: "50G"                   # Shorthand: name + size
      data:                         # Full form
        size: "100G"
        bus: "virtio"               # virtio | scsi | sata
        cache: "writeback"          # writeback | writethrough
        storage: "nfs-volume"       # Reference a volume
        cluster_size: "2M"          # qcow2 cluster size (default 64K)
        refcount_bits: 16           # qcow2 refcount width (default 16)
        overwrite: false            # iscsi root disk from an image: write it over a non-blank LUN
        discard: unmap              # unmap (or on) | ignore (or off); see below
        detect_zeroes: unmap        # off | on | unmap (unmap needs discard unmap)
        iotune:                     # I/O throttle, live-changeable; see below
          read_bytes_sec: 100M
          write_iops_sec: 2000
```

`overwrite` matters only for a root disk built on an image in an `iscsi` pool:
the image is written onto the LUN, and a LUN that is not blank is refused
unless the disk sets `overwrite: true` — see
[storage.md](storage.md#iscsi-one-lun-one-disk). `overwrite` applies to the
create that carries it and is never stored: a later rebuild or recreate keeps
the LUN as it is. A VM with a disk on an iscsi volume or pool may have only one
replica, and may not update by `blue-green` or `snapshot-and-replace`: both put
two instances on the one LUN, and the deploy refuses them.

### Discard (TRIM)

`discard: unmap` passes the guest's TRIM down to the storage, so a thin
backend (qcow2 on a filesystem, ZFS, thin LVM, Ceph RBD) gets back the space the
guest freed; `ignore` drops it. **A new VM's disk with no `discard:` gets `unmap`
on the local store, btrfs, ZFS, thin LVM and Ceph, on a virtio, scsi or sata bus**,
and nothing on NFS or iSCSI (whether a TRIM frees anything there depends on the server's own space accounting, so it is left to you; a `dir` pool that sits on NFS gets the default too) or
on an IDE disk. The default is written into the VM's spec when it is created: a VM
created before it keeps rendering no discard, and applying a file that leaves
`discard:` out never changes a disk. The root disk a VM gets when `disks:` names
none gets the default too, and is then listed in the spec as `root`. The default is
written only once the whole cluster keeps these settings (see below); before
that, a create renders exactly what an earlier release did.
`detect_zeroes: unmap` additionally turns a guest write of zeroes into a discard; it
is off unless you set it, because it costs CPU on every write. Changing either on an
existing VM needs a restart: the deploy reconfigures and restarts the same VM, disks
kept. Run `fstrim` in the guest (most distributions schedule it weekly) to reclaim
space it freed before the setting was on.

### Upgrading a cluster

`discard`, `detect_zeroes`, `iotune` and `queues` are kept in the VM's spec, and a
host on an older release would drop them when it rewrites a spec (a failover onto it
would rebuild the VM without its throttle). So they are accepted only once the
release token (`release_2026_11_v1`, feature `vm_disk_nic_io`) has latched, which needs
every host, one in maintenance included, to be on a release that keeps them. Until then
a create, update, compose deploy, recreate or `lv disk-io` that sets any of them is
refused with `the cluster upgrade must finish first (vm_disk_nic_io needs
release_2026_11_v1)`, and nothing about a VM that sets none of them changes: a restore
or promotion of a spec that carries them still works, with the tuning dropped. Once the
token has latched, the first write of any of them (an unset discard becomes the
storage default on a new disk only once the feature is already in use, so a plain create never waits on a first use) records the feature as used; see upgrades.md, *Rolling back after a release token
latched*, for what a rollback does. A restore whose tuning the gate refuses after the latch
still completes, with the tuning dropped, a warning and an audit row. So does a restore
or promotion whose spec carries a value a create would refuse (queues above the limit, a
total throttle beside a read one): that disk's tuning, or that NIC's queues, is dropped
with a warning naming each key and an audit row (`vm.tuning_dropped`), and the rest is
kept.
The gate has no config flag and, once open, stays open; to stop using the feature, clear
the settings (`lv disk-io <vm> --clear`, or drop the keys).

### I/O limits

`iotune:` throttles one disk (libvirt `<iotune>`). Rates are bytes per second (a
number, or with a `K`, `M` or `G` suffix) and operations per second; unset or `0` is
unlimited:

| Key | Meaning |
|---|---|
| `total_bytes_sec`, `read_bytes_sec`, `write_bytes_sec` | sustained bytes per second |
| `total_iops_sec`, `read_iops_sec`, `write_iops_sec` | sustained operations per second |
| `total_bytes_sec_max`, `read_bytes_sec_max`, `write_bytes_sec_max`, `total_iops_sec_max`, `read_iops_sec_max`, `write_iops_sec_max` | burst ceiling above the sustained rate; needs it |
| `burst_seconds` | how long a burst lasts (default 1) |

A `total_*` key cannot be combined with the `read_*` / `write_*` of the same kind.
Changing `iotune:` in the file throttles the **running** disk in place (no restart)
and updates the definition; `iotune: {}` removes every limit. The same can be done
without the file: [`lv disk-io`](cli-reference.md). The limits are kept in the VM's
spec, so a restart, a failover start and a migration carry them. A disk the spec does
not list yet (the root disk a VM got before disks were recorded, a hot-plugged one) is
throttled too: its entry is made in the spec when the limits are set. The limits are
per VM: a disk shared by several VMs is throttled separately in each, so the aggregate
is not bounded (libvirt's `group_name` is not supported).

## Networks

```yaml
    network:
      - name: "production"
        model: "virtio"             # virtio | e1000
        ip: "10.0.1.10"             # Static IPv4 (optional)
        mac: "52:54:00:12:34:56"    # Fixed MAC (optional)
        gateway: "10.0.1.1"
        security-groups: ["web"]    # Per-NIC firewall (see "Firewall" below)
        queues: 4                   # virtio-net multiqueue (1-64, or auto)
        mtu: 9000                   # guest MTU (576-65520, or bridge); must equal the bridge's
        rate: 12.5                  # Bandwidth cap in MB/s, both directions (0/unset = unlimited). Live
        # NIC guard (anti-spoofing, docs/firewall.md "NIC guards"). A new NIC
        # is guarded by default; anything below but the default needs
        # network.update on the network at deploy.
        spoof-guard: "on"           # on (default) | off
        allowed-addresses: ["10.0.1.250"]   # extra sources the guest may use (a VIP)
        allow-dhcp-server: false
        allow-router-advertisement: false
        allow-vlan-tags: false      # true: the guest may send and receive any tags (a VLAN-aware guest)
      - name: "core"
        trunk: [100, 101]           # VLAN trunk mode: the guest carries VLANs 100 and 101 tagged
```

A NIC with `trunk:` (two or more VLANs) carries those of its VLANs its
network's `allowed-vlans:` lists, single tagged, and its per-NIC rules still
judge the packet inside the tag; it is guarded like any other new NIC. A trunk
that existed when the cluster upgraded keeps its VLANs (they are recorded into
the network's list during the roll, and a re-deploy of the network keeps them
there unless an operator took them off with `lv network set`). A re-create — a rolling update, a
rebuild — that adds a VLAN to a trunk that predates guards makes it a new NIC:
guarded, its new VLAN the network's to allow. A trunk change alone is not a
topology change and does not re-create the VM. `allow-vlan-tags: true` is for a
VLAN-aware guest outside the `trunk:` feature (docs/firewall.md, "VLAN tags").

A network's `gateway:` names its router when the router is not litevirt's — the
upstream router of an external or VLAN bridge, often not the subnet's first
host — and `reserved-addresses:` its other infrastructure addresses. No guest
NIC may claim either, and a guest whose guard is confined to the subnet may not
use them (docs/firewall.md, "NIC guards").

`queues:` gives a virtio NIC that many queue pairs (`<driver queues='N'/>`; libvirt
uses vhost-net when the host has it and qemu's userspace backend when it does not,
so a migration or failover onto a host without vhost-net still works), so a guest with several vCPUs spreads network interrupts and
packets across them. It is off unless set (one queue); `queues: auto` is one per
vCPU up to 8, none for a single-vCPU guest. Only the virtio model takes it. Inside
the guest, enable the queues with `ethtool -L <nic> combined N`. A change needs a
restart: the deploy reconfigures and restarts the same VM, disks kept. An unset
`queues:` inherits what the VM has, so removing the key from the file does not turn
multiqueue off: write `queues: 1`. `queues: auto` is resolved from `cpu:` when the file
is read, so changing `cpu:` in the file changes the queue count with it (which makes a
vCPU grow a restart), and `lv update --cpu` never re-resolves it; write a number to pin it.

`mtu:` sets the guest NIC's MTU (`<mtu size='N'/>`); see
[networking](networking.md#per-nic-mtu). `mtu: bridge` takes the bridge's own MTU
when the VM is defined. An explicit value must equal the bridge's MTU on the host
that defines the VM, or the create, start or migration is refused. Virtio NICs on
a bridged network of a VM only. A change needs a restart, as `queues:` does. An
unset `mtu:` and `mtu: 0` are the same: a deploy leaves the MTU the VM has, so
removing the key does not remove it. Remove it with `lv update <vm> --nic-mtu
<nic>=0` (the VM stopped, or `--restart-if-needed`). A re-create builds the VM
from the file, so an MTU set only with `lv update` is dropped then. It is
accepted once the release token has latched (feature `nic_mtu`), as the tuning
above is.

IPv6 can be set either by putting a v6 address in the `ip`/`gateway` fields, or
via the dedicated `ipv6:` / `ipv6-gateway:` fields (which also enable dual-stack
when paired with `ip:`):

```yaml
    network:
      - name: "v6lan"
        ip: "10.0.1.10"             # IPv4
        gateway: "10.0.1.1"
        ipv6: "2001:db8:1::42"      # /64 default if no prefix supplied
        ipv6-gateway: "2001:db8:1::1"
```

An empty `ipv6:` uses SLAAC (router advertisement) or DHCPv6 if the network is
configured for it. See [`docs/networking.md`](networking.md) for IPv6 specifics
(RA, dual-stack).

## Graphics

Console devices attached to the VM. Default: VNC enabled, SPICE off.

```yaml
    graphics:
      vnc: true       # default; set false to run headless
      spice: true     # add SPICE alongside (or instead of) VNC
```

Connect with:

```bash
lv vnc <vm>           # VNC connection info
lv spice <vm>         # SPICE connection info
lv spice <vm> --launch  # open remote-viewer, carried through the daemon
```

Both consoles listen on the VM host's `127.0.0.1` only. `lv vnc --listen`
and `lv spice --launch` / `--listen` carry them through the daemon to a
local port, so no SSH to the host is needed. Both consoles carry a per-VM
password (`--launch` and the UI's `.vv` file pass the SPICE one; see
[`docs/ui.md`](ui.md#console-passwords)). See [`docs/ui.md`](ui.md) for the in-browser console
options (VNC via noVNC; SPICE-in-browser is on the roadmap).

## Cloud-init

```yaml
    cloud-init:
      userdata: |
        #cloud-config
        users:
          - name: ubuntu
            sudo: ALL=(ALL) NOPASSWD:ALL
            ssh_authorized_keys:
              - ssh-rsa AAAA...
      networkconfig: |
        version: 2
        ethernets:
          eth0:
            dhcp4: true
```

## Placement

```yaml
    placement:
      # ── Hard constraints ──
      host: "host-a"                # Pin to specific host
      anti-affinity: ["db"]         # Don't co-locate with these VMs
      affinity: ["cache"]           # Co-locate with these VMs
      max-per-node: 1               # Max replicas on a single host (0 = unlimited)
      require:                      # Host MUST have these labels
        gpu: "true"
      prefer:                       # Host preferably has these labels (+5 score per match)
        zone: "us-east-1a"
      no-migrate: false             # Opt this VM out of all rebalancer-driven moves
      failback: false               # Move back by live migration after the host it was drained from is undrained

      # ── Initial-placement scoring ──
      policy: balance               # balance | bin-pack | spread-strict | cost-aware
                                    # Or use named-mode aliases:
      mode: ha-critical             # performance | savings | ha-critical | spot-cheap

      # ── Day-2 reconciliation ──
      rebalance:
        mode: dry-run               # off | dry-run | auto
        threshold: 15               # min % score gain to trigger a proposal (default 15)
        cooldown: 5m                # min interval per VM (default 5m)
        budget:
          max-concurrent: 2         # simultaneous live migrations cluster-wide (default 2)
          max-per-hour: 10
          window: off-hours         # named cluster time-window (planned)

      # Legacy form (translates to policy=spread-strict):
      spread: true
```

### Policy axes

litevirt's placement engine has two orthogonal axes (see
[placement.md](placement.md) for the full model):

1. **Policy** — initial-placement scoring strategy:
   - `balance` (cluster default): weighted-sum scorer over CPU/RAM/NUMA/host-gen, spreads via concave pressure curves.
   - `bin-pack`: invert; concentrate to free hosts for maintenance.
   - `spread-strict`: hard 50% per-dim pressure cap; hosts above are excluded entirely.
   - `cost-aware`: divide score by host `cost.hourly` label.

2. **Rebalancer mode** — day-2 reconciliation:
   - `off`: never propose moves.
   - `dry-run` (cluster default): write proposals; nothing moves until an operator reviews them via `lv rebalance list` and runs `lv rebalance approve <id>`.
   - `auto`: write proposals + immediately approve (subject to budget).

The two compose freely; the rebalancer evaluates each VM under **its own** resolved policy, so a single cluster can mix bin-pack batch jobs with spread-strict prod VMs without one's policy influencing the other.

### Named-mode bundles

For the 80% case, named modes expand at parse time:

| Mode | Expands to |
|---|---|
| `performance` | `policy: balance` + `rebalance.mode: dry-run` |
| `savings` | `policy: bin-pack` + `rebalance.mode: auto` (off-hours window, generous budget) |
| `ha-critical` | `policy: spread-strict` + `rebalance.mode: dry-run` |
| `spot-cheap` | `policy: cost-aware` + `rebalance.mode: auto` |

Explicit `policy:` or `rebalance:` fields on the same `placement` block override the alias defaults.

`rebalance.mode: on-demand` is an alias of `dry-run`: it always behaved exactly
like it, and the two were folded into one mode. A compose file that still names
it deploys, the VM's mode is stored as `dry-run`, and a WARN says so. Write
`dry-run` in new files.

### Hard constraints

`max-per-node` is a hard constraint: the placement engine will not place more than this many replicas of the same VM group on a single host. Use `max-per-node: 1` to ensure each replica runs on a separate host.

`no-migrate: true` opts the VM out of all rebalancer-driven moves and (planned) storage-motion. Set automatically by admission for VMs with non-migratable PCI passthrough.

`failback: true` opts the VM in to returning after maintenance: when a host drain moves it away and that host is later undrained, it is live-migrated back (see [failback](migration-failover.md#failback-after-maintenance)). Only a VM the drain moved, and that nothing has moved since, returns.

See [`docs/placement.md`](placement.md) for the cost function, troubleshooting, and worked examples.

## Boot ordering (depends-on)

Control the order workloads are created and updated during deployment. A workload that is created or updated by a deploy does not start until each of its dependencies meets the specified condition, whatever the deploy does to the dependency:

- a dependency **created or recreated** by the deploy is created first and waited on right after;
- a dependency **updated by the rolling engine** is updated first, and the dependent waits on it before its own create or update starts — for the dependency's `health-wait` when its update strategy sets one, else the condition's default timeout;
- a dependency the deploy leaves **unchanged** is still a dependency: it is waited on before the dependent starts (so a re-run does not create `app` while `db` is still unhealthy).

Creates and updates are ordered together: a new VM that depends on a VM being updated runs after that update. A workload that the deploy leaves unchanged waits on nothing, even when its dependency is not in the state it once needed. Workloads with no ordering between them run in name order (a failed replica's update first, #32), so an unchanged file always deploys in the same order; deletes run where they always have, after the creates and updates.

```yaml
vms:
  db:
    image: "postgres"

  cache:
    image: "redis"

  app:
    image: "myapp"
    depends-on:
      db:
        condition: vm_healthy     # Wait for DB healthcheck to pass
      cache:
        condition: vm_started     # Wait for Redis to be running
```

A dependency is named by its compose name: `db` means the workload `db` and, if it is replicated, every replica (`db-1`, `db-2`, …) — never a different workload whose name merely starts with `db-`, such as `db-backup`.

Shorthand form (all conditions default to `vm_started`):

```yaml
    depends-on: [db, cache]
```

Conditions:

- `vm_started` — VM is in "running" state (default). Timeout: 5 minutes.
- `vm_healthy` — the VM's `healthcheck` has **passed**. Timeout: 10 minutes.
  - The probe runs on the host that owns the VM, which publishes its verdict (`healthy`, `unhealthy` or `unknown`) to the cluster whenever it changes. The wait is met only by a `healthy` verdict for the VM **as it is now**: a pass recorded before the VM was restarted, recreated or migrated does not count, and neither does one from an owner host that is `offline`, `fenced` or in `maintenance` — a host that is down cannot take back its last pass, so the wait keeps waiting (the VM may yet fail over and pass on its new host).
  - A VM with **no** `healthcheck` is healthy once it is running.
  - A wait that times out says which VM and the last thing it saw, for example `timeout after 10m0s waiting for vm_healthy on db: healthcheck verdict unhealthy: tcp probe failing (3 consecutive): tcp 10.0.0.5:5432: connection refused`, or `... the last verdict (healthy) is from a previous incarnation of the VM; no probe of this one has passed yet`.
  - `lv inspect <vm>` shows the same verdict as `health` / `healthDetail`.
  - Mixed versions: the node serving the deploy decides what `vm_healthy` means, and the VM's owner publishes the verdict. An older node serving a deploy treats running as healthy; a newer one waiting on a VM with a `healthcheck` whose owner runs an older build sees no verdict and times out. Upgrade every node before relying on it.

Containers (`kind: lxc` / `kind: oci`) take part in `depends-on` both ways — a VM can depend on a container and a container on a VM. For a container, `vm_started` means the container is running. A container has no probe verdict (a container `healthcheck` is not probed), so `vm_healthy` on a container also means running — the rule for a VM without a `healthcheck` — and a file that asks for `vm_healthy` on a container that **declares** a `healthcheck` is refused at validation (`... is a container (kind lxc) and container healthchecks are not probed — use condition vm_started, or remove the container's healthcheck`), because that promise could not be kept.

If a dependency's condition is not met — its wait times out, or its create (or the recreate of an update) fails — the dependency is reported as a failed action (an `error` line naming it), and **its dependents are held back**: they are neither created nor updated (an existing dependent keeps running as it is), and each is reported as a failed action of its own, naming the dependency, the condition and why it was not met, for example `blocked: depends-on db (condition vm_healthy) was not met: depends-on wait for vm_healthy: timeout after 10m0s waiting for vm_healthy on db: ...`. The block is transitive — whatever depends on a held-back VM is held back too, with `blocked: depends-on app (condition vm_started) was not met: blocked: ...`. VMs that do not depend on the failed one are deployed as usual. The stack ends `degraded`, `compose up` exits non-zero, and the next `compose up` creates the held-back VMs once their dependency meets its condition — until then the re-run holds them back the same way, with the same `blocked: depends-on ...` line. For a replicated dependency, one failed replica holds its dependents back.

Cycles are detected at parse time and rejected.

## Load balancer

Defining a `loadbalancer` section automatically provisions HAProxy + keepalived on the
designated hosts. The VIP floats between hosts using VRRP (keepalived), and HAProxy
handles traffic distribution to backend VMs.

Standalone load balancers (not tied to a stack) can also be created with `lv lb create`. Its `--snat` flag is this section's `snat:`, off unless given (see [SNAT via VIP](#snat-via-vip)).

```yaml
    loadbalancer:
      enabled: true                     # default false; auto-enabled if vip is set
      vip: "10.0.100.50/24"            # Virtual IP with CIDR (required)
      algorithm: "roundrobin"           # roundrobin | leastconn | source
      sticky-sessions: false            # Source IP sticky sessions
      snat: false                       # SNAT outbound VM traffic to VIP (see below)
      hosts:                            # Hosts to run HAProxy+keepalived on (optional)
        - "node1"                       # First host = VRRP master (priority 100)
        - "node2"                       # Additional hosts = VRRP backup (priority 50)
                                        # Omit to auto-detect: runs on hosts with stack VMs
      ports:
        - listen: 80                    # VIP listener port
          target: 8080                  # Backend VM port
          protocol: "tcp"               # tcp | http
          redirect-https: false         # Redirect HTTP to HTTPS (see below)
        - listen: 443
          target: 8443
          protocol: "tcp"
          tls:                          # TLS termination (optional; see below)
            cert: "/etc/litevirt/lb-certs/web.crt"
            key: "/etc/litevirt/lb-certs/web.key"
      health:
        use-vm-healthcheck: true        # Reuse VM healthcheck for backend health
        type: "http"                    # tcp | http
        path: "/health"                 # HTTP health check path
        interval-ms: 2000               # Check interval in milliseconds
```

A stack has one load balancer. Copies of one definition, from a base the VMs `extends` or a YAML anchor, are that one load balancer; two different definitions are refused. The stack's `name` must use only letters, digits, `_`, `.` and `-`.

Values are checked before anything is deployed:

- `algorithm` is `roundrobin`, `leastconn` or `source`.
- `protocol` and `health.type` are `tcp` or `http`.
- `health.path` is one absolute path of visible ASCII, without spaces, quotes, `#`, `\` or braces, at most 512 characters.
- `redirect-https` needs `protocol: http`, no `tls` on the same port, and a `tls` port on the same load balancer to redirect to. A spec stored before this check with any other redirect is served without that redirect, and a `lb.redirect_ignored` event says so.

**TLS files** are read as root on every LB host, from `/etc/litevirt/lb-certs/`. Naming a file anywhere else needs the admin role. A symlink is followed (Let's Encrypt's `live/` names work, for example a symlink in `/etc/litevirt/lb-certs/` to them), and every check applies to the file it reaches: a regular file of at most 1 MiB, never under the PKI directory, the data directory or `/etc/litevirt/lb`. A path in `/etc/litevirt/lb-certs/` is read only while that directory, and every directory below it on the way to the file, is a real directory owned by root and writable by no one else. A file that is not a regular file is refused without being opened for reading, including one swapped in after the path was checked. An LB stored before this rule with files elsewhere keeps working, and each apply raises a `lb.tls_outside_cert_dir` event that names the file.

**Where the VIP goes**: a VIP inside a network's subnet is put on that network's
bridge on each LB host (a stack LB considers only its own stack's networks and
networks of no stack; when several subnets hold it: its own stack's network
first, then the most specific subnet), whether
or not the bridge carries an address in the subnet. A stack's `bridge` network
may be on its scoped name (`<stack>_<name>`) or on its own name on a given host;
the scoped name is tried first, and the own name is taken only when no other
network may be on it, or when it carries an address in the network's subnet.
If that bridge is not on the host, or which network a shared name belongs to
cannot be told, the LB is refused there with the network and bridge named. The
LB's VIP ports and SNAT are recorded for that same network. A VIP in no network's subnet goes on the host device
whose subnet holds it, else on the default-route device.

All VMs in the stack automatically become backends. Backend IPs are discovered via
ARP/DHCP after boot and persisted in the cluster database. **Containers in the stack
are backends too** — a single LB can front a mix of VMs and containers; give a
container NIC a static `ip:` (resolved cluster-wide) or, when the container runs on
the LB's own host, a DHCP address is resolved locally.

**Drain vs disable**: `lv lb drain` puts a backend in drain mode — it stops accepting
new connections but finishes existing ones. `lv lb disable` immediately removes the
backend from rotation. Use drain for graceful maintenance.

**Health & observability**: `lv lb inspect <name>` reports each backend's **real
HAProxy health** (`active`/`down`/`maint`/`draining`), not merely whether the
workload is running — a started VM with nothing listening on the target port shows
`down`. An LB whose VIP isn't actually assigned (keepalived not running on a host
that should run it) is reported as `state: degraded` instead of `active`; this is
checked across the LB's hosts, so `lv lb inspect` is accurate from any node. The
`litevirt_lb_keepalived_up{lb}` gauge (1 = VIP assignable on this host, 0 = not)
exposes the same signal for alerting — see [operating model](operating-model.md).

### SNAT via VIP

On host-isolated networks, VMs have no outbound internet access by default (no MASQUERADE rule). Setting `snat: true` on the load balancer enables outbound NAT: VM traffic destined for external IPs is source-NATted to the VIP address.

```yaml
networks:
  overlay:
    type: "vxlan"
    vni: 1000
    subnet: "10.100.0.0/24"
    host-isolation: true

vms:
  web:
    network:
      - name: "overlay"
    replicas: 3
    loadbalancer:
      vip: "192.168.1.50/24"
      snat: true                    # Outbound VM traffic SNATted to VIP
      ports:
        - listen: 80
          target: 8080
```

How it works:

1. VM sends a packet to an external IP (e.g., `apt update`)
2. The VM's default gateway is the IRB anycast gateway on the bridge (e.g., `10.100.0.1`)
3. The host forwards the packet out the default route interface
4. An nftables SNAT rule rewrites the source from the VM IP to the VIP
5. Return traffic arrives at the VIP → keepalived ensures it lands on the MASTER → conntrack maps it back to the VM

Requirements:

- `snat:` applies on every LB host; with it unset or `false`, no LB host rewrites the network's egress
- A load balancer made with `lv lb create` SNATs only with `--snat`, and `lv lb update <name> --snat` or `--snat=false` changes it later; `lv lb inspect` shows the setting and `lv lb ls`, inspect and the web UI show it as on, off, or unknown when the daemon could not read it (the LB may be SNATting). The web UI's create form has a "SNAT (outbound NAT via the VIP)" checkbox, unticked by default. One created before this setting existed keeps SNATting until it is set. Until every host runs a release with this setting (`failover_scope_v1` latched, as `lv cluster upgrade-status` shows), `lv lb create` without `--snat` is refused, `lv lb create --snat` works, and `lv lb update --snat` is refused. An LB host on an earlier build SNATs for every load balancer it serves, so during a rolling upgrade inspect shows the setting, not what each LB host applied. A host rolled back below this release does the same ([upgrades.md](upgrades.md#manual-rollback-anytime))
- The VIP must be routable from the upstream network
- IP forwarding is enabled automatically
- The network's bridge carries the VMs' gateway (see [Host isolation](#host-isolation)): a `vxlan` network, or a `bridge` network on a bridge litevirt created, with no `vlan`
- It does not apply to an `isolated` network: nothing is routed off its bridge

**VRRP transport**: once every host runs a release with `vrrp_unicast_v1`, each LB
host sends its VRRP adverts as unicast from its recorded address to the other LB
hosts' recorded addresses, over the device that holds its own, and accepts adverts
only from them. The VIP stays on its network's bridge; nothing VRRP is sent on that
bridge, and there is no password for a guest to read. Before that, the adverts are
multicast on the VIP's bridge with a password derived from the LB's name, as on
earlier releases, and any guest on that bridge can read them.

The transport is one value for the whole cluster, read by every LB host from the
replicated `cluster_policies` table, whatever its own configuration or latch: what an
admin sets with `lv cluster vrrp-transport unicast` or
`lv cluster vrrp-transport multicast`, else unicast once the latch has been
recorded there, else multicast. The first host whose `vrrp_unicast_v1` latch is
durable records it, which also needs `failover_scope_v1` latched on that host
(the table is not writable before), so on an upgrade the switch waits for both
tokens. Until the record exists every host stays multicast. Each host re-applies
its LBs within 2 seconds of the record (or an admin's change) reaching it, so an
LB is held by both its hosts for about as long as the record takes to replicate
between them plus 2 seconds — seconds on a healthy cluster, longer only while
replication to one of them is lagging. `lv cluster vrrp-transport` with no
argument shows what the connected host renders.

Requirements and edges of the unicast transport:

- Hosts must pass IP protocol 112 between their recorded addresses. Where something
  between them does not, run `lv cluster vrrp-transport multicast`.
- A host must hold its recorded address (`advertise_address`) on a local device
  that is up and is not loopback. Otherwise it cannot render unicast for its LBs:
  it raises the critical health condition `lb.vrrp.transport_refused` naming each
  LB. When another host of the LB reports serving it on unicast, it stops its own
  keepalived for the LB, so that host holds the VIP alone; when none does (they
  are refused too, down, unreachable, or cannot hold the VIP because its device
  is down or has no carrier), it runs the LB on multicast, so the LB always keeps
  a holder, and stops it again once one serves. Fix the address or the device; where
  the address cannot be on a local device — 1:1 NAT, an address routed to `lo` —
  run `lv cluster vrrp-transport multicast`. A failed read of the policy or an
  address is not a refusal: what runs is kept, and the next pass retries.
- A host in an LB's `hosts` that has no recorded address (it was removed with
  `lv host rm`) is not a VRRP peer, and the event `lb.vrrp_peer_dropped` names it.
  With no peer left the remaining host serves the VIP alone. Correct the list with
  `lv lb update <name> --host <host>` (repeated for each host).
- An LB host on an earlier build (or rolled back) that is back in the cluster
  renders multicast, and both hold the VIP. Each LB host that renders unicast
  raises the critical health condition `lb.vrrp.transport_split`, naming the LB and
  the host. Upgrade that host, or run `lv cluster vrrp-transport multicast` until
  it is.
- keepalived 2.1 or later. On 2.0 the instance's source check and a single LB
  host's TTL range are ignored (litevirt also renders the global
  `vrrp_check_unicast_src`, which 2.0 honours).

A guest's VRRP to its own host is dropped either way ([firewall.md](firewall.md)).

**Conntrackd for failover**: When `snat: true` is set and the LB has two or more `hosts`, litevirt automatically runs `conntrackd` alongside keepalived to replicate conntrack state between VRRP peers, over the hosts' recorded addresses. Each LB host syncs with the first other host in `hosts`. On failover, the new MASTER imports synced entries so existing SNAT'd connections survive. This is managed automatically — no additional configuration is needed.

## Health checks

```yaml
    healthcheck:
      type: "http"          # tcp | http | https | ping | exec
      target: "http://localhost:8080/health"   # localhost = the VM, see below
      interval: "10s"
      timeout: "5s"
      retries: 3
      action: "restart"     # restart | migrate | alert
```

**Targets are resolved relative to the VM.** The probe runs on the VM's owning *host*, not inside the guest, so a target that names a place on the VM — a bare port, an empty host, `localhost` or any loopback address (`127.0.0.0/8`, `::1`) — is sent to the VM's address. A target that names another host is probed as given.

| `type` | `target` | Probes |
|---|---|---|
| `tcp` | `"22"`, `":22"`, `"localhost:22"`, `"127.0.0.1:22"` | TCP connect to `<vm-address>:22` |
| `tcp` | `"db.internal:5432"` | `db.internal:5432`, as given |
| `http` / `https` | `"http://localhost:8080/health"`, `":8080/health"` | `GET http://<vm-address>:8080/health` |
| `http` / `https` | `"8080"`, `"8080/health"`, `"/health"` | `GET http://<vm-address>:8080`, `GET http://<vm-address>:8080/health`, `GET http://<vm-address>/health` (scheme from `type`) |
| `http` / `https` | `"http://example.com/health"` | that URL, as given |
| `ping` | omitted, or `"localhost"` | one ICMP echo to `<vm-address>` |
| `ping` | `"10.0.0.1"` | `10.0.0.1`, as given |
| `exec` | `"systemctl is-active nginx"` | the command, run inside the guest by the guest agent (`guest-agent` must be on) |

An `http` probe passes on any status below 500. Ports are numbers (`1`–`65535`); a service name such as `ssh` is refused, and for a well-known name (`ssh`, `http`, `https`, `postgres`, `mysql`, `redis`, `dns`, `smtp` and a few more) the error gives the number: `"ssh" is not a port number — use 22`. The table of names is fixed and never read from the host's `/etc/services`, which differs from host to host.

**`type` can be left out when the target settles it**: an `http://` or `https://` URL is that type, and a port, `:port` or `host:port` is `tcp`. A `type` that is written always wins (`type: http` with `target: "8080"` probes HTTP). `ping` and `exec` are never inferred, and neither is anything else — an empty target, a bare path such as `/health`, a bare host — so those need a `type`, and the error says which types there are.

**The VM's address** is its NIC's recorded address — the one `lv ls` shows, lowest-ordinal NIC first — unless the owning host sees a *different* address for that NIC's MAC in its ARP cache or in an unexpired dnsmasq lease on the bridge that NIC's network uses, in which case the probe goes to the live one: a DHCP address is recorded once and not updated, so after the guest reboots onto a new lease the recorded address is stale (`lv ls`, DNS and the load balancer keep showing it until it is changed). When the host sees nothing for the MAC — a static or NetBox-assigned address — the recorded address is used. When no address is recorded yet, the probe uses what the host sees for the NIC's MAC.

**When no address is known** (the VM has no NIC, or no lease yet), the probe cannot run, and that is not a failure: the verdict is **unknown** with the reason `no address known for VM yet: …`, and the `action` never fires on it. A `vm_healthy` wait keeps waiting and, if the VM never gets an address, times out saying so. The same holds for a stored target that cannot be interpreted (a VM created before targets were validated): `unknown`, with the reason, and no action.

A target that cannot be interpreted — a `tcp` target that is not a port or `host:port`, a URL that is not `http`/`https`, a host made only of digits (`"http://8080/health"`, `"8080:22"`: a port written where the host goes), an unknown `type` or `action` — is refused when the compose file is parsed, so `lv compose up` fails, with a non-zero exit, before anything is deployed. Every problem in the file is reported at once — healthcheck or not, in one format — each as `file:line:col: field.path: problem — fix`, the fix given where there is one:

```
compose validation errors:
  - stack.yaml:7:15: vms.db.healthcheck.target: "postgres" is not a port number — use 5432
  - stack.yaml:8:15: vms.db.healthcheck.action: unknown healthcheck action "reboot" — want restart | migrate | alert
```

A field the file does not have — in a healthcheck or anywhere else: the top level, a VM or workload, a network, a disk, a depends-on entry — is refused, with the field it most likely meant, so a misspelling never leaves a default silently in force:

```
  - stack.yaml:9:7: vms.db.healthcheck: unknown field "retires" — did you mean "retries"?
```

Keys starting `x-` (extension fields, free for your own use, at the top level or inside any block) and YAML merge keys (`<<: *anchor`) are allowed; the keys an anchor merges in are checked like any other. A file whose aliases expand it past what can be checked — an anchor reused inside another anchor, over and over, so a few kilobytes stand for millions of nodes — is refused as a whole (`document contains excessive aliasing`, or `the file expands to too many nodes to check`), before any of it is deployed. The shorthand forms stay valid: a disk as `root: 20G`, memory as `4G`, `depends-on` as a list.

`interval` and `timeout` are durations with a unit (`"10s"`, `"1m"`) greater than zero; a `timeout` must not exceed the `interval` (written, or its default), since a probe must finish before the next is due; and `retries`, when written, is at least `1`. A field that is left out takes its default:

| Field | Default |
|---|---|
| `type` | inferred from `target` (see above), otherwise required |
| `interval` | `10s` (also the floor: the checker sweeps every 10 seconds) |
| `timeout` | `5s` |
| `retries` | `3` |
| `action` | `restart` |

```
  - stack.yaml:7:17: vms.db.healthcheck.interval: interval "10" is not a duration — add a unit, e.g. "10s"
  - stack.yaml:9:16: vms.db.healthcheck.retries: retries must be at least 1 — omit it for the default, 3
```

A `timeout` of `30s` with no `interval` is refused as `timeout 30s exceeds interval 10s (the default) — lower timeout or raise interval`. The default `timeout` is never held against a short `interval`.

**The plan shows what will be probed.** `lv compose up` prints, under each VM it creates or updates, the healthcheck as the checker will run it: the resolved target (`<vm address>` for a VM-relative one), whether the type was inferred, and every default filled in:

```
  + create db
      healthcheck: tcp (inferred) <vm address>:5432 every 10s, timeout 5s, 3 retries, then restart
```

An `interval` below the checker's 10-second sweep is shown as `every 10s (1ms is below the checker's 10s sweep)`.

The VM's owning host probes it every `interval` (default, and floor, the checker's 10-second sweep; a probe still running is never started twice, and a probe that was still running when the VM restarted, moved or was redefined is discarded rather than counted against the new one) with a `timeout` of its own (default `5s`). The verdict follows the fields the schema has, Docker-style:

- one passing probe makes the VM **healthy**;
- `retries` consecutive failures (default `3`) make it **unhealthy**; fewer leave the verdict where it was;
- a VM that has not been probed since it last started — or was recreated or migrated — is **unknown**, and so is a stopped VM;
- a VM whose probe cannot run — no address known for it yet, or a target that cannot be interpreted — is **unknown**, with the reason; it resets the run of consecutive failures and never counts toward the `action`.

There is no `start-period`. Instead, for the first 5 minutes after a VM **starts** its failures do not count toward the healthcheck's `action`, so a VM still booting is not restarted; it is still probed, and its verdict is still published, because a `depends-on` or rolling-update wait needs its first pass. "Starts" is every start the owning host sees, measured from when it saw it:

- the VM was created;
- its healthcheck restarted it, its restart policy started it, or the daemon started or restarted it (`lv start`, `lv restart` — including on a running VM — a reconfigure that restarts it, an `onboot` start when the host boots, and the start of a VM failed over or rescheduled to the host);
- it went from not running to running (an operator start, a redefine and start);
- it arrived on the host — migrated or failed over there — or began a new ownership generation.

Failures from before a start do not carry over — a probe already in flight when the VM started does not count either: after the grace the VM needs `retries` failures of its own before the `action` runs. Not covered: a VM the host first sees just after its daemon starts that the daemon did not start itself — it cannot tell a VM that has run for weeks from one that just started.

**Repeated actions back off.** When the `action` has run and the VM still has not passed a probe, the next action on it waits at least 1 minute after the last one, doubling with each further action — 2, 4, 8, 16 minutes — up to a cap of **32 minutes**, where it stays until the VM passes a probe (which resets the backoff). With `action: restart` the 5-minute start grace comes first, so a VM that never passes is restarted at most about every 5 minutes plus `retries` × `interval` at first, and no more often than every 32 minutes once the backoff has grown. Failed probes that arrive while the backoff is holding the action back keep counting — the log shows `consecutive` still rising next to `action backoff active` — so the action runs on the first failed probe after the backoff ends, not after another `retries` failures.

The verdict is replicated state, written only when it changes (never once per probe), and it is what `vm_healthy` waits for (see `depends-on`). A failing verdict appears in `lv health` as a `vm_probe_failing` condition at **info** severity: visible, but it neither degrades the cluster's overall state nor blocks admission — see [Diagnostics](diagnostics.md#vm-probe-failing-vm_probe_failing).

## Restart policy

Auto-restart VMs that crash or stop unexpectedly. This is distinct from healthcheck actions: healthcheck `action: restart` restarts a *running* VM that fails probes, while restart policy restarts a *stopped or crashed* VM.

```yaml
    restart:
      condition: "on-failure"     # none | on-failure | always
      delay: "10s"                # Wait before restarting
      max-attempts: 5             # Give up after 5 restarts (0 = unlimited)
      window: "1h"                # Reset attempt counter after this duration
```

litevirt decides whether to restart from *why* the workload stopped (the libvirt
shutoff reason), not merely that it is stopped:

- `none` — never auto-restart (default).
- `on-failure` — restart on an **unexpected** stop: a crash, a failed start, or a
  fence/external `destroy`. A clean guest-initiated shutdown (ACPI poweroff from
  inside the guest) or an operator `lv stop` is **never** restarted.
- `always` — same triggers as `on-failure` in litevirt: a clean guest shutdown
  and an operator stop always "stick". This is the **guest-stick** rule — unlike
  literal Docker `always`, litevirt will not fight a guest that asked to power off.
  Only an unexpected stop is restarted.

A suspended VM (managed-save / RAM snapshot) or a paused VM is never cold-booted
by the restart engine — it would discard saved RAM; resume it instead.

The attempt counter tracks restarts within the sliding `window`. Once `max-attempts`
is reached, the VM stays stopped until the window elapses (resetting the counter)
or an operator intervenes.

The same policy applies to **containers** (`lv ct create --restart …`), with one
caveat: LXC reports no stop *reason*, so a container cannot distinguish a clean
in-guest shutdown from a crash. Only an operator `lv ct stop` is guaranteed-stick;
any other stop is treated as unexpected and restarted per policy. A frozen
(paused) container is treated as running and never restarted.

## Update strategy

Control how VMs are updated when a compose file changes.

**Every update is applied with the least destructive mechanism the change allows, whatever the strategy** — the plan names the mechanism on each `~ update` line:

- **in place** (`applied in place, no restart`) — the running VM is changed with no restart: a cpu grow within the `max-cpu` hotplug ceiling, a memory change within the `[min-memory, max-memory]` balloon band (the new size is also the VM's next-boot size), and spec settings read when they are used: restart policy, onboot, ordering, labels, placement, migrate, `healthcheck`, `hooks`, `stop-grace-period`; and the noisy-neighbour limits `cpu-limit`, `cpu-shares` and each NIC's `rate`, which libvirt applies to the running domain;
- **restart** (`restart — the same VM is reconfigured and restarted, disks kept`) — a change that bakes into the domain (a cpu shrink or grow beyond the ceiling, an out-of-band memory size, `max-cpu`, memory bounds, `cpu-mode`/`cpu-model`, `machine`, `firmware`, `guest-agent`, VNC graphics, `secure-boot`, `tpm`) reconfigures and restarts the **same** VM: same disks, same MACs, same identity. A stopped VM is reconfigured and left stopped. Toggling `secure-boot` or `tpm` on a VM that already has firmware state is refused, as `lv update` refuses it without `--force`;
- **recreate** (`recreate — disks are replaced (<why>)`) — only a change of VM identity (`image`, `iso`, disk or network topology, `cloud-init`) deletes the VM and creates it again, **which replaces its disks**. So does a change that needs only a redefine but that no reconfigure path can apply to an existing VM yet (SPICE graphics, resource tuning, passthrough devices), and a VM whose stored spec cannot be read. Disks are not carried over to the new VM. The plan says so on the VM's line, and `compose up` asks for confirmation before applying it (as it does for every plan, unless `-y`).

What the file is compared with is the spec each VM was deployed from, not what its host reports it using now: a guest whose balloon has not reached its size yet, or with a vCPU taken offline, is not a change, and a VM is planned as `~ update` only when there is something to apply to it. Once an update is applied, deploying the same file again plans no change. A field left out of the file keeps what the VM has. That includes `cloud-init`: removing it from a VM's definition plans no change, with a warning that the VM keeps the cloud-init it was created with. cloud-init ran at the VM's first boot and is not run again for the same VM, so removing it changes nothing in the guest, and only a new VM starts without it.

A VM left in `error` (or mid-create, -start, -stop or -rebuild) by an operation that did not finish is **retried** by the next deploy, and a retry never replaces disks that exist:

- **`retry — repaired in place, disks kept`** — disks are recorded for the VM: its domain is redefined from the desired spec over those disks (whether or not the domain is still defined) and started. Same disks, same MACs, same identity. The start is checked like `lv start`: it is refused without split-brain quorum, when the host has no room for the whole VM, or while the VM backs linked clones. A VM another operation is working on — one with a pending action, or one a failover or restart holds the start lease for — is not touched, and neither is one whose domain cannot be asked whether it runs. The repair takes that start lease itself and holds it until its start is done, so a failover or restart cannot start the VM alongside it; the refusal names the lease's holder. A refused repair changes nothing. A repair that fails is reported as a failed action and leaves the VM as it was; it never falls back to a recreate.
- **`retry — created again (nothing was made)`** — no disks were made (the create failed before them), so the VM is created from scratch.

A retry whose compose change is itself a change of identity (an image change, say) is a `recreate — disks are replaced` like any other.

An update of a VM stays on the host it runs on, and is placed as a **replacement** of what that VM holds there: its current cpu and memory are released and the updated request is charged in their place, so a VM that fills most of its host can still be shrunk, relabelled or otherwise updated. An update that no longer fits its host is refused before anything is touched, and the error names the resource and the numbers:

```
planner: batch placement failed: no eligible host for VM "db":
node-2: memory (needs 4224 MiB incl. 128 qemu overhead, 1947 free after db's current 1024 is released)
```

The exception is a VM that has to be replaced under `blue-green` or `snapshot-and-replace`: those create the new VM beside the running one until the cutover, so the new VM is charged **in addition** to what the old one holds, on the same host, and the plan is refused when the host cannot hold both. A change applied to the same VM (in place, or reconfigured and restarted) is still placed as a replacement under those strategies.

A container update is placed the same way, against the container's current memory limit. A container is charged its memory limit only — no qemu overhead and no vCPU for its `cpu`, which caps the container at that many cores rather than reserving them (see [containers.md](containers.md#resource-limits)).

The strategy decides how a change that needs a **new** VM is rolled out — `recreate` means "replace such a VM by deleting and creating it", not "recreate on any change":

```yaml
    update:
      strategy: "rolling"          # in-place | recreate | rolling | all-at-once | blue-green
      max-unavailable: 1
      max-surge: 1
      order: "start-first"         # start-first | stop-first
      health-wait: "30s"
      rollback-on-failure: true
      pause-between: "5s"          # Delay between instances during rolling updates
```

Strategies:

- `recreate` — (default) Delete then create each VM that needs replacing, one after another. Simple but has downtime, and the replaced VM's disks are destroyed. Before it deletes a VM, it makes every check the create will make that the delete does not change (authority, NIC addresses and guards, devices, networks, pools); a refusal fails that VM's update with "nothing was deleted" and leaves the VM as it was. The deploy may run on any node: a node whose replica has not yet applied the delete does not refuse the create for the deleted VM's own row (another VM of the same name is still refused).
- `rolling` / `stop-first` — Replace VMs one at a time: stop old, create new, wait for health check, continue.
- `start-first` — Create new VM first, wait for health check, then stop old. Minimizes downtime.
- `all-at-once` — Replace all VMs that need it simultaneously. Fast but risky.
- `blue-green` — Create a parallel set of new VMs ("-green" suffix), then cut over by deleting the old (blue) VMs. A green that cannot be created aborts the deploy and removes the greens already made. A blue that cannot be deleted once its green is up is not a failed cutover — the green is serving — but it is reported as a failed action for that VM (the old VM is still there), and the stack ends `degraded`.
- `in-place` — **Live-or-fail: it applies in-place changes only and NEVER restarts or deletes a VM.** Any change that would need a restart or a recreate (see the lists above) — or a VM that has to be replaced for another reason (its stored spec cannot be read, say) — is **refused when the plan is made, with an error naming the VM and the reason — nothing is deleted or partially applied.** Use another strategy (or stop the VM and `lv update`) for those. A VM a previous deploy left half-made is still repaired (`retry — repaired in place, disks kept`), as under every strategy.

Under any strategy but `in-place`, in-place and restart changes are applied to each VM before the strategy replaces the VMs that need it; a restarted VM is waited on for `health-wait` like a replaced one.

The health wait of `rolling`, `stop-first`, `start-first` and `snapshot-and-replace` is the `vm_healthy` condition of `depends-on` (see above), bounded by `health-wait` (default `30s`). For a VM with a `healthcheck` that means the recreated VM's own probe must pass within `health-wait` — the previous VM's pass does not carry over — so leave room for at least one probe `interval` plus boot time. A VM without a `healthcheck` passes as soon as it is running. A VM that is not healthy by then fails with `<vm> did not become healthy within health-wait <d>: ...` followed by the last verdict and the probe's failure reason; under `rolling`, `stop-first` and `start-first` that aborts the deploy at that VM: the stream ends in error, later VMs are not touched, and the stack record keeps the last successful deploy (see the fail-fast note below).

`in-place` is safe to run against a running production VM: the worst case is a refused deployment that leaves the VM and its disks exactly as they were. Under the other strategies a VM's disks are replaced only for a change the plan names as `recreate — disks are replaced`.

During a rolling update, creates (scale-up) execute first, then updates are processed according to the strategy, then deletes (scale-down) execute last. With `depends-on` between them, the creates and updates run in dependency waves — each wave's creates, then its updates — so a dependent's create or update starts only after its dependency's has finished and met its condition. A rolling update fails fast: if any VM update errors, the deploy stops **before** any later dependency wave and the scale-down step and the stack's stored desired state is left unchanged, so a failed update never deletes a VM the change didn't intend to and never records a half-applied stack.

> Mixed-version note: `in-place`'s non-destructive behavior is enforced by the entry node serving the deploy. Do not rely on the `in-place` strategy until every mutation-serving node in the cluster runs a build that supports it.

## Migration policy

```yaml
    migrate:
      strategy: "live"              # live | cold | none
      max-downtime: "100ms"
      auto-converge: true
      with-storage: false           # Copy local disks during live migration
      on-host-failure: "restart-any"  # restart-any | restart-same (waits for its host when a disk is host-local) | none (a VM stopped on purpose is never restarted)
      fence-strategy: "best-effort" # best-effort | ipmi | manual | watchdog
      priority: 0                   # Higher priority VMs are migrated/rescued first
      bandwidth-mib-sec: 0          # Migration bandwidth limit (0 = unlimited)
      timeout-sec: 0                # Migration timeout (0 = no timeout)
```

`priority` is a whole number from -2147483648 to 2147483647, default `0`;
a value outside that range is clamped to the nearest bound, with a warning, and
still deploys. **Higher goes first.** It orders three things, each among one
host's VMs:

- **Failover.** When a host is fenced, its VMs are recovered highest priority
  first: placement and each reschedule run in that order, and placement charges
  each VM's CPU and memory before the next is placed, so when the survivors
  cannot hold every VM, the higher-priority ones get the room. A VM that does
  not fit is left on the fenced host and reported, as any VM without a place
  is, and is not recovered later on its own: it waits for its host or an
  operator. Auto-promotion runs ahead of every placement, so a promoted VM
  takes its replica host's room whatever its priority; priority orders
  promotions only among themselves.
- **Drain.** `lv host drain` starts the moves in priority order, so with
  `--parallel N` the N highest go first. Targets are chosen per VM without
  reserving room, so a later VM can still find its target full.
- **Starts on the new host.** A host starts the VMs failover sent it, and any
  other VM it has to start, highest priority first within each pass; a start
  deferred from the last pass still goes ahead of new ones.

VMs of equal priority go in name order. Priority only orders work that is
already allowed: quorum, fencing, recovery claims, capacity and every
placement constraint still decide each VM on its own, and a high priority never
lets a VM past one of them. It does not order recovery across two hosts that
fail at once (each host's VMs are recovered in turn), `onboot` starts at host
boot (those follow `startup-order`), failback, or the rebalancer. See
[Recovery priority](migration-failover.md#recovery-priority).

## Backup

Attach a VM to the backup scheduler. The scheduler ticks every minute and
pushes a PBS-equivalent dedup snapshot on the `schedule` cron, then applies
`retention`.

```yaml
    backup:
      repo: "main"                # logical repo name (see "Backup repositories" below)
      schedule: "0 2 * * *"       # 5-field cron
      encryption: "aes256gcm"     # "" | "aes256gcm" | "tenant-key"
      retention:
        keep-last: 7
        keep-daily: 14
        keep-weekly: 8
        keep-monthly: 12
        keep-yearly: 3
```

When `backup:` is unset the VM is not backed up by the scheduler — operators can
still take ad-hoc snapshots via `lv backup`. See [`docs/backups.md`](backups.md).

## PCI device passthrough

```yaml
    devices:
      - type: "gpu"
        vendor: "10de"              # NVIDIA vendor ID
        count: 1
      - type: "network"
        sriov: true
        parent: "0000:41:00.0"      # SR-IOV: PF PCI address (BDF) to draw a VF from
      - mapping: "gpu-a100"         # cluster-wide resource mapping (see below)
```

An `sriov: true` device requests an SR-IOV virtual function. Placement only requires
the target host to have a matching SR-IOV-capable PF (optionally the one named by
`parent`); the actual VF is **allocated on-demand at create time** — reused if one is
free, or created on an adopted PF per the host's `pci.sriov` policy (see
[pci-passthrough.md](pci-passthrough.md#sr-iov-virtual-functions)). It is never pinned
to a fixed VF address at plan time. `parent` is a PF **PCI address (BDF)**, not a
NIC name. The same is available ad-hoc via `lv attach-pci <vm> --sriov --parent <BDF>`.

A `mapping` references a cluster-wide **resource mapping** (`lv mapping`) — a named
alias for an equivalent passthrough device registered on one or more hosts. At
placement/start time litevirt resolves the mapping to the concrete PCI address on
the target host, so a passthrough VM can land on (or migrate to) any host that has a
device under that mapping. See [pci-passthrough.md](pci-passthrough.md#resource-mappings).

## Resource tuning

```yaml
    resources:
      hugepages: true               # Use huge pages for VM memory
      cpu-pinning: [0, 1, 2, 3]    # Pin vCPUs to specific host CPUs
      io-threads: 2                 # Number of I/O threads for disk operations
```

## Lifecycle hooks

```yaml
    hooks:
      pre-start: "#!/bin/bash\necho starting"
      post-start: "#!/bin/bash\ncurl -X POST http://webhook/started"
      pre-stop: "#!/bin/bash\necho stopping"
      post-stop: "#!/bin/bash\necho stopped"
      pre-migrate: "#!/bin/bash\necho migrating"
      post-migrate: "#!/bin/bash\necho migrated"
```

> **Security:** lifecycle hooks run as **root** on whichever host the VM is
> placed on, and re-run on every start/stop/migrate (including system-driven
> events like failover). Because that is effectively host-root authority that
> ignores the project/tenant boundary, **defining** a hook requires the
> `admin` role — creating a VM with a `hooks:` block as a mere `operator` is
> rejected. (Hook *execution* is not gated on the caller's role, so already-
> defined hooks keep firing on automated events.)

## Network definitions

```yaml
networks:
  production:
    type: "bridge"          # bridge | vxlan | isolated | sriov | direct
    interface: "br0"        # For bridge type
    vni: 1000               # For VXLAN type
    subnet: "10.0.1.0/24"
    dhcp: true
    nat: true               # Enable outbound NAT/masquerade (default true)
    learning: true          # MAC learning on bridge (default false)

  overlay:
    type: "vxlan"
    vni: 2000
    subnet: "10.200.0.0/24"
    host-isolation: true              # Block VM→host management traffic
    dns: ["1.1.1.1", "8.8.8.8"]      # DNS resolvers for isolated VMs

  mgmt:
    type: "direct"
    interface: "bond0.206"        # Host interface to attach VMs to via macvtap

  existing-bridge:
    external: true          # Use pre-existing network, don't create/destroy
```

A stack `bridge` network with no `interface` is on its scoped bridge
`<stack>_<name>` (the hashed `lvf-<11 hex>` form when that is over 15
characters), the same on every host, so two stacks that each declare a bridge
network of one name are never on one bridge. A network already deployed keeps
the bridge its record names. A network named after a bridge the deploying host
already has, which litevirt did not create and no stack network is on, is put
on that bridge; to attach to a host bridge in any other case, name it with
`interface:`. A NIC, bond or VLAN of the network's name is not a bridge and is
not used. A host bridge a stack network (of another stack or of this one) is
already on is not shared by name: the network gets its scoped bridge and the
deploy warns, naming what is on it (event `network.host_bridge_not_shared`); to
share it, set `interface:` to it and redeploy. A `direct` network with no `interface` uses the host NIC of its
own name. When a stack's bridge network is on the same bridge as another
stack's network, the deploy warns, naming both stacks and the bridge (the entry
host also publishes a `network.bridge_shared` event); if that is not intended,
set `interface:` to the scoped name and redeploy to move the network to its own
bridge.

### `netbox-prefix-id` is parsed and refused

`netbox-prefix-id` is a real key on a compose network definition — the parser
accepts it — but a deploy that sets it is **refused**:

```
network "production": NetBox prefix bindings are created with
`lv network create --netbox-prefix-id`, not from a compose file
```

That is deliberate, not a gap. Binding a prefix is a claim on an external
authority: it validates that the prefix exists, that its VRF enforces address
uniqueness, and that nothing else already holds it, and then it RESERVES the
prefix for one litevirt network. A compose deploy creates its networks
directly and runs none of that, so it would persist a network whose config names
a prefix nothing reserved — and every VM create on that network then fails,
because litevirt refuses to allocate across an address space it believes is
externally managed but never claimed. Stack networks are also scoped, torn down
and recreated with the stack, and a prefix binding does not follow that
lifecycle.

Bind the network first with `lv network create --netbox-prefix-id`, then
reference it from the stack as `external: true`. See
[networking.md](networking.md#binding-a-network-to-netbox).

### Host isolation

Setting `host-isolation: true` on a network blocks all traffic from VMs to the hypervisor's management plane (SSH, gRPC, metrics, etc.) while preserving VM-to-VM communication, including across hosts via VXLAN.

This follows the cloud provider model (AWS, DigitalOcean, GCP): the hypervisor is invisible to VMs. When host isolation is enabled:

- **No dnsmasq** — DHCP/DNS does not run on the bridge. No host process listens.
- **Static IPs via cloud-init** — IPAM still allocates IPs, but they are delivered via cloud-init network-config (MAC-matched, distro-agnostic: works on Ubuntu, CentOS, Debian, Arch, Alpine). A VM NIC that names no `ip:` is given a free address in the network's IPv4 subnet; never the gateway, a `reserved-addresses` entry, a live load balancer's VIP, or a VIP named by the VM's own `loadbalancer:` or by a VM of its stack created before it. A VIP named by a VM of the stack that is created later is not known yet: list it in `reserved-addresses`. The address is recorded on the NIC (`lv inspect`). Each host starts its search at a different point of the subnet. Two VMs created on two hosts at the same instant can still be given the same address; each host then records a `network.duplicate_address` event on its VMs that hold it (`lv events`). Name `ip:` explicitly where that matters. A network without a subnet, or with an IPv6 one, gives no address: name one with `ip:`.
- **DNS from config** — resolvers come from the `dns` field (defaults to `["1.1.1.1", "8.8.8.8"]`).
- **Gateway stays** — the host keeps the subnet's first address on the bridge as the VMs' gateway, for routing (FORWARD): always on a `vxlan` network (its IRB anycast gateway), and on a `bridge` network when litevirt created the bridge on that host and the network has no `vlan`. A bridge litevirt did not create, a VLAN bridge, and a host-isolated `isolated` network get no gateway address; so does a bridge an earlier build created (litevirt keeps no record of it), until the bridge is created again, for example at a reboot. Either way no host *services* are reachable (INPUT is dropped), the gateway address included. Forwarding through the gateway to the host's other networks is not blocked: host isolation keeps guests off the host, not off other networks.
- **No implicit NAT** — outbound internet access requires explicit `snat: true` on a load balancer, or `--snat` on one made with `lv lb create` (see below; one made before that flag existed SNATs until it is set).

Under the hood, litevirt creates a per-bridge nftables chain on the `input` hook that drops all traffic from the bridge interface. VM-to-VM traffic uses the `forward` hook and is unaffected. VXLAN underlay (UDP 4789) arrives on the physical NIC, not the bridge, so it is also unaffected.

```yaml
networks:
  secure-overlay:
    type: "vxlan"
    vni: 1000
    subnet: "10.100.0.0/24"
    host-isolation: true
    dns: ["1.1.1.1", "8.8.8.8"]
```

Host isolation is optional and defaults to `false`. Existing behavior (DHCP, DNS, NAT from host) is unchanged when not set.

#### Host isolation with load balancers

When a load balancer VIP lives on an isolated network, litevirt automatically adds exceptions for:

- **VRRP** (IP protocol 112) — keepalived peer communication
- **VIP ports** — only the declared listener ports on the VIP address

Replies to connections the host opens onto the bridge (HAProxy's health checks and proxied connections to backends there) are accepted too; a reply to any other connection of the host's is not. All other traffic from VMs to the host remains blocked. These exceptions are managed automatically when LBs are applied or removed.

### External networks

Mark a network as `external: true` to reference a network that already exists in the cluster. litevirt will verify the network exists during deployment but will not create or destroy it.

External networks must not set `subnet`, `dhcp`, `vni`, or `type` — these are properties of the existing network.

This is useful for shared infrastructure networks managed outside of compose stacks, or for connecting VMs in different stacks to the same network.

A VM or container NIC that names a network the file does not declare at all is
treated the same way: it attaches to the cluster network of that name, made with
`lv network create`. The deploy is refused if no such network exists:

```
network "hc" (used by db) is not declared under networks: and no cluster network by that name exists
```

Stacks deployed before this rule stored such a NIC on `<stack>_<name>`, a name
with no network behind it, so the VM sat on an empty bridge of that name with
no gateway and no DHCP. Deploying the same file again moves the NIC onto the
cluster network in place: same VM, same MAC, same disks. It is not a recreate.
The VM's host re-plugs the NIC at once when the deploy ran there, and otherwise
on its next network pass (within 30 seconds). Once no NIC uses the old
`<stack>_<name>` bridge, the host removes it. If `<stack>_<name>` is a real
network, the move is refused for that VM and the VM is left as it is.

Networks the file declares belong to the stack. They are stored as
`<stack>_<name>`, so two stacks can each have a network called `lan`.
Deleting a stack removes the networks recorded as that stack's. A network
record that names no stack is matched by its `<stack>_` prefix, and goes to the
longest stack name that fits: deleting stack `app` leaves `app_v2_lan` to stack
`app_v2`.

## Volume definitions

```yaml
volumes:
  shared-storage:
    driver: "nfs"           # local | nfs | ceph | iscsi
    source: "10.0.10.1:/exports/vms"
    target: "/var/lib/litevirt/mounts/shared"  # override disk directory path
    options:
      vers: "3"
```

A disk with no `storage:` uses the default local driver. A disk's `storage:` name resolves to a compose volume first, then to a storage pool of the VM's host (declared in `config.yaml` or created with `lv pool create`). A name that is neither is refused, never placed on the local driver: `lv compose up` refuses it before anything is deployed when no host in the cluster has a pool by that name, with the name it most likely meant,

```
  - 7:35: vms.web.disks.data.storage: storage "wram" is neither a volume of this file nor a storage pool — did you mean "warm"?
```

and creating the VM fails with `storage "fast" is neither a volume of stack "shop" nor a storage pool on host "node-2"` when the pool exists on other hosts but not the one the VM is placed on. See [storage.md](storage.md) for host-level pool configuration.

A volume that names a host path (a `target`, a `dir` or `btrfs` volume, NFS
mount `options`, a Ceph `conf` or `keyring`), attaches network storage
(`nfs`, `ceph`, `iscsi`) or allocates from host block storage (`zfs`,
`lvm-thin`) follows the same rule as a pool:
`lv compose up` needs `storage.hostpath` at `/` (the Admin role) to add or
change one, and refuses system and litevirt-internal directories to everyone
([storage.md](storage.md#host-paths)). Re-deploying
a volume exactly as the stored stack already has it needs no new authority, so
an operator can re-deploy a stack an admin wrote.
A disk whose `storage:` names a pool an admin already created — a `zfs` or
`lvm-thin` pool included — needs no such authority: using a pool takes only
the project's ordinary VM permissions.

## Stack-level settings

### DNS

Override the DNS domain for VMs in this stack. VM DNS records are registered as `<vm>.<stack>.<domain>`.

```yaml
dns:
  domain: "myapp.internal"
```

### Notifications

Send webhook notifications on stack lifecycle events (deploy, update, teardown):

```yaml
notifications:
  webhook: "https://hooks.example.com/litevirt"
```

### Backup repositories

Register logical backup-repo name → on-disk path mappings for the cluster, so a
VM's `backup: { repo: <name> }` resolves without editing daemon config. These
are CRDT-replicated and removed when the stack is deleted. A repo of the same
name in the daemon config (`backup_repos:`) takes precedence.

Registering a repo writes a host path the daemon later writes backups into as
root, so adding one, or changing an existing name's path, needs
`storage.hostpath` at `/` (the Admin role) — the same rule as passing a custom
absolute `repo_path` to a backup RPC. Re-deploying a stack whose repos are
already registered by it, unchanged, needs nothing more.

A repo name another stack registered is used as it is: a deploy naming it does
not take it over or change its path (it warns when its file names a different
one), and its `compose down` leaves it registered. When the stack that
registered it goes down, the repo passes, at its path, to another stack whose
file defines it or backs a workload up to it, and is unregistered only when
none does; while another stack's stored file cannot be read, it stays.

```yaml
backup-repos:
  main:
    path: /srv/backup/main
  offsite:
    path: /mnt/dr/offsite
```

### Firewall

litevirt's distributed firewall is driven from compose: top-level
`security-groups:` and `ipsets:` define reusable rule sets and named CIDR lists,
`firewall:` sets cluster-tier rules and the default policy, and a NIC references
security groups by name. All of this is persisted on deploy and enforced by the
per-host reconciler.

```yaml
# Reusable rule bundles referenced per-NIC by name.
security-groups:
  web:
    description: "public web tier"
    rules:
      - direction: ingress
        proto: tcp
        port: "80"
        cidr: "0.0.0.0/0"
        action: accept
      - direction: ingress
        proto: tcp
        port: "443"
        action: accept

# Named CIDR lists; reference one from a rule with cidr: "@office".
ipsets:
  office:
    description: "corporate egress ranges"
    cidrs: ["203.0.113.0/24", "198.51.100.0/24"]

# Cluster-tier rules + default policy for this stack.
firewall:
  default-deny: true            # drop anything not explicitly accepted
  cluster-rules:                # applied before per-NIC rules, on every NIC
    - direction: ingress
      proto: icmp
      action: accept
    - direction: ingress
      proto: tcp
      port: "22"
      cidr: "@office"
      action: accept

vms:
  web:
    network:
      - name: "frontend"
        security-groups: ["web"]   # attach the SG to this NIC
```

A redeploy replaces the stack's firewall rows, and keeps its `default-deny` in
force throughout: a default-deny the new file asks for is set before the old
rows go, and the stack's default is removed only once the new rows are written
and only when the new file drops it. A redeploy that fails part way leaves the
cluster denying, with fewer accepts, until the next one succeeds.

A security-group rule or a `firewall.cluster-rules` entry takes
`cidr: "tag:<group>"`, naming a tag group (`lv firewall tag-group set`). The
group must already exist, and a stack deploy that holds one is refused until
the cluster upgrade has finished. A group's members come from firewall tags,
which a compose file does not set (`lv firewall tag set`, docs/firewall.md,
"Tag groups"). `lv compose up` asks the daemon first and refuses against one
that does not know tag groups.

A rule with `log: true` logs each packet it matches to the firewall log
(`lv firewall log`; docs/firewall.md, "Logging"):

```yaml
- { direction: ingress, proto: tcp, port: "22", action: drop, log: true }
```

On a `macro:` rule every row the macro expands to logs. A stack deploy that
holds one is refused until the cluster upgrade has finished, and is refused
before the stack's old rows are touched. `lv compose up` (and `lv gitops`)
asks the daemon first and refuses against one that predates logging. The
action stays the plain verdict; `drop+log` is not an action.

Per-NIC security groups can also be bound at runtime with
`lv sg bind <vm> --network <name> --sg <name>`. See
[`docs/firewall.md`](firewall.md) for the three-tier model and CLI surface.

#### Security groups and guards a file does not declare

A NIC's security groups and its guard can be changed at runtime, with
`lv sg bind` and `lv firewall nic-guard set`. Those write the rows the firewall
enforces from, not the VM's stored spec, so `lv compose diff` and
`lv compose up` compare the file with those rows: the NIC row's binding, and
the guard record of the VM's current incarnation (no record is an unguarded
NIC). The file owns only what it declares:

- **Security groups.** A NIC whose entry has a non-empty `security-groups:`
  owns its binding. A binding that differs from it is drift, shown as
  `nic_sg_<n> [old]→[new]`. A NIC whose entry names no groups keeps whatever
  it is bound to, and `up` never changes it.
- **Guards.** A NIC whose entry names any guard setting (`spoof-guard`,
  `allowed-addresses`, `allow-dhcp-server`, `allow-router-advertisement` or
  `allow-vlan-tags`) owns its whole guard. Its mode is on unless the file says
  `off`, and the settings it leaves out are off. A guard that differs is drift,
  shown as `nic_guard_<n> {old}→{new}`. A NIC whose entry names none keeps the
  guard it has, including one an operator turned off. To have `up` keep a NIC
  guarded, write `spoof-guard: "on"`.

**What `up` restores, and what it withholds.** A restore is made in place, with
no restart. Some restores can take away protection an operator put on at
runtime, such as an isolation group bound during an incident. `up` withholds
those unless it is run with `--allow-weaken`. A withheld restore is not an
error: the rest of the VM's update is applied, `up` succeeds, and the plan
prints a warning that names what was withheld and why. For example:
`web: nic 0 (lan) security groups not restored: it may remove protection set
outside the file — nic 0 (lan): rebinds security groups [isolate]→[web]
(unbinds isolate, bound now; binds web); re-run with --allow-weaken to apply
it`. Without the flag, `up` withholds:

- **every security-group rebind.** Per-NIC rules are first-match across the
  bound groups, and with `default-deny` a bound group opens what it accepts.
  So adding, removing or reordering a group can each widen access.
- **a guard restore that loosens the guard enforced now.** That is one that
  turns it off, or adds an allowed source address the live guard does not
  already cover, a DHCP-server or router-advertisement allowance, or VLAN tags.

A guard restore that only tightens is applied without `--allow-weaken`. It
needs the same authority as creating the NIC with that guard would: none for
a plain `spoof-guard: "on"`, and `network.update` on the NIC's network for a
declared guard that is `off` or has any allowance, whatever the guard enforced
now. A restore the caller lacks that authority for is withheld with the rest
below.

With `--allow-weaken`, those restores are applied, and the plan still names
each one. They are written through the same calls as `lv sg bind` and
`lv firewall nic-guard set`, with the deploying caller's authority, and are
audited the same way.

The plan also withholds, with a warning, any restore the deploy cannot make:

- **The caller's permissions.** A rebind needs `network.update` on the VM, and
  a declared guard that is `off` or has allowances needs it on the NIC's
  network.
- **The cluster upgrade.** Until it finishes (the `nic_guards` release), no
  guard record can be written.
- **Two NICs on one network.** A security-group binding is written per
  network, so when a VM has two NICs on one network, a rebind is made only if
  the file declares the same groups for every one of them.

`lv compose diff` shows the server's plan for the caller, the same one `up`
would apply (pass `--allow-weaken` to see what `up --allow-weaken` would do).
**A guard on a direct or SR-IOV NIC is not enforced.** Such a NIC bypasses
the bridge where guards are enforced, so it has no guard record. A file that
declares a guard on one is not refused. Instead, every plan says so (`nic 0
(wan) declares a guard that is not enforced: a direct (macvtap) network
bypasses the bridge where guards are enforced; the NIC has no guard`).
Creating the VM leaves the settings out, and redeploying the unchanged file
plans no change. `lv run`, `lv attach-nic` and `lv firewall nic-guard set` refuse guard
settings on such a NIC outright. A declared guard that create would refuse,
such as a `spoof-guard:` other than `on` or `off`, an `allowed-addresses:`
entry that is not an address or prefix, or more than 64 distinct allowed
addresses, is withheld from a restore with that reason.

The plan and the deploy decide by the same rules. When `up` comes to restore
a VM's NIC security, it checks every restore again against the rows as they
are then, before it writes any. If one is refused (the rows changed since the
plan so that it would now weaken without `--allow-weaken`, or the caller's
permissions changed), none is written, and the VM's update fails with the
reason. The warnings are also sent when the deploy runs, so callers that do not ask
for the plan first see them too: the UI shows them in its toast, the REST
deploy answer has a `warnings` list, and `lv gitops` logs them.

**A recreate makes the NICs from the file**, as it always has. A change of
identity, or a strategy that replaces the VM, applies the file's declared
groups and guard with no `--allow-weaken` gate. The plan prints a warning when
that changes what is enforced now. A NIC whose file declares no groups keeps
its live binding through the recreate (`nic 0 (lan) keeps the security groups
[isolate] its NIC (52:54:00:…) has now through the recreate`), but only when
it is known which new NIC is that NIC:

- A NIC whose entry names a `mac:` is the NIC with that MAC.
- Otherwise, on a network where the file has as many NICs as the VM has now,
  the first NIC on that network is the first NIC, and so on. Inserting or
  removing a NIC on another network does not change this.
- When the file adds or removes a NIC on a network, it is not known which new
  NIC is which, so no binding is carried there. Each binding is dropped with
  its NIC, and the plan names it. To keep a binding through such a change,
  declare `security-groups:` on the NICs, or name their `mac:`. The guards of undeclared NICs are carried as
before (docs/firewall.md, "A re-create keeps each NIC's guard").

Containers are out of scope. Compose neither reports nor restores a runtime
change to a container NIC's security groups or guard.
