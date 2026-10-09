# Containers (LXC + OCI)

litevirt's container subsystem runs Linux containers via the
LXC family of tools. OCI images (Docker registries, etc.) are pulled via
`skopeo` and converted to an LXC rootfs via `umoci`. Both binaries are
host bootstrap dependencies.

The runtime API mirrors the VM lifecycle (Create / Start / Stop / Delete
/ Exec / List) so a single scheduler hosts both kinds of
workload — that's the structural advantage compared to running
Kubernetes alongside a VM platform.

## Why LXC, not OCI as a first-class runtime

Three reasons:

1. **System containers** (LXC) are the natural fit alongside VMs:
   they share the same lifecycle vocabulary (start, stop, snapshot,
   migrate), the same networking primitives (veth into a bridge), and
   the same scheduler placement decisions. OCI's "one process per
   container" model needs a separate runtime layer to host long-lived
   services.
2. **OCI images run inside LXC** via umoci-extracted rootfs. So we
   support OCI images without giving up LXC's system-container model.
3. **CGO-free**: shelling out to `lxc-*` keeps litevirt a single
   static binary, exactly like the libvirt VM path.

## CLI quickstart

```
# Pull an image into the daemon's OCI library. A bare --dest name stages the
# image under <data_dir>/oci/<name> on the host that unpacks it.
# (add --local to unpack on the host you're on, without the daemon)
lv ct pull docker.io/library/nginx:1.27 --dest nginx

# Create the container from the library item. --template accepts the bundle
# dir (descends into rootfs/) or a rootfs path; the LXC config is generated.
# The template rootfs is COPIED into the container's own <lxcpath>/<name>/rootfs,
# so the pulled template stays intact — reuse it for many containers, and
# `lv ct rm` only removes that container's copy, never the template.
lv ct create web --template /var/lib/litevirt/oci/nginx

# Start, exec, stop, delete
lv ct start web
lv ct exec web -- nginx -t
lv ct stop web --timeout 10
lv ct rm web
```

`lv ct rm` deletes a stopped container. A running one is refused with a
message naming `lv ct stop`; `lv ct rm --force` stops it and deletes it.
`compose down`, a compose recreate and the web UI's delete (behind its
confirmation) delete a running container as before.

### Host paths a container is given

A rootfs template is copied whole into the new container, and a local
`oci:<dir>` source is unpacked by root, so naming either is reading a host
directory as root. Container inputs follow the same rules as a VM's host
paths:

- Anyone with `ct.create` may name an **OCI library item**: exactly
  `<data_dir>/oci/<name>` or its `rootfs/`, the directory `lv ct pull --dest
  <name>` staged. A deeper path, or a library name that is a link out of the
  library, is not an item.
- `lv ct pull --project <p>` makes a library item **that project's**, recorded
  on the pulling host in `<data_dir>/oci-owners/<name>`; `<p>` must be a
  project the caller may create containers in. A caller without the Admin
  role may then create a container from it, or pull over it, only in that
  project; through a forwarding node too. A pull **without** `--project`
  records no owner, and the image is everyone's, as on earlier releases — as
  is every image pulled before owners were recorded (nothing is backfilled).
  The Admin may use any image.
- Any other host path (`--template /srv/rootfs`, `rootfs:<path>`, a relative
  path, an absolute `lv ct pull --dest`, a local `oci:` source) needs
  `storage.hostpath` at the cluster root — the Admin role.
- Whoever asks, a template or OCI source may not be under, or contain, a
  directory that holds host secrets or live state (`/etc`, `/boot`, `/dev`,
  `/proc`, `/sys`, `/var/backups`, `/var/spool`, `/var/lib/lxc` (but see below), libvirt's
  per-domain state), the daemon's PKI directory, or its data directory apart
  from `pools/`, `mounts/`, `disks/uploads/` and `oci/`. `/home`, `/root` and
  `/run` themselves, a whole home directory, and a link into a dot-directory
  are refused too. An absolute pull `--dest` follows the pool rule for a
  directory the daemon writes into, except that the OCI library itself is the
  daemon's own. A template name (`download`, `busybox`) may not contain `/`;
  name a path as `rootfs:<path>`.
- **Inside the LXC store** (`/var/lib/lxc`) an Admin's template is read as on
  earlier releases — LXC's template cache, or another container's rootfs
  (`--template /var/lib/lxc/base/rootfs`) — and a host-loss recreate of a
  container made that way reads it again. The store itself, anything
  containing it, and the directory of the container being made are refused. A
  VM is still never given a file there as a CD-ROM.
- A host-loss relocation that recreates a container from its template judges
  the template again on the recreating host. A refused template leaves the
  container pending, with a `ct.relocate.failed` event, and copies nothing.

For a download-template container (no OCI image required):

```
lv ct create alpine-1 --distro alpine --release 3.21
lv ct start alpine-1
```

### Naming a container on a specific host

Container names are unique **per host**, not cluster-wide, so the same name may
legitimately exist on two hosts. `lv ct start|stop|rm <name>` without `--host`
resolves the owner by name, which works whenever the name is unique. When it is
not, the command is refused and lists the candidates rather than picking one:

```
$ lv ct rm web
Error: container "web" exists on 2 hosts (node-a, node-b); pass --host to name the one you mean

$ lv ct rm web --host node-b
```

`--host` is always exact, so it is the unambiguous form in scripts.

### Inspecting a container

`lv ct inspect <name>` is the container counterpart of `lv inspect <vm>`: host,
state, image or template, project, CPU and memory limits, the privilege mode,
each NIC with its network and address, the rootfs, snapshots, backups, and when
it was created and last updated. `--size` also measures the rootfs (a walk of
the tree on its host, reused for a minute); `-o json` prints the same detail as
JSON; `--host` names the owner when the name is on two hosts.

```
$ lv ct inspect web --size
Name:       web
Host:       node-3
State:      running
Privilege:  privileged
Rootfs:     /var/lib/lxc/web/rootfs (412.3 MiB)
...
Backups:
  REPO          SIZE     UPDATED               STATUS
  /srv/backups  2.1 MiB  2026-10-08T12:48:39Z  available on node-3
  offsite       2.1 MiB  2026-10-08T13:02:11Z  available on node-1
```

The privilege mode is read from the container's LXC config on its host: a
config with an `lxc.idmap` is unprivileged, one without is privileged. If that
host does not answer, the cluster's view is shown and the host-local fields
read unknown.

Each backup entry is checked where it lives. A backup taken through another
host's repository (a sink) or before a migration is not on the container's
current host, so every host is asked whether it holds a backup of this
container (same name and project) in that repository. The entry is then:

- **available on `<host>`**: that host holds it;
- **not found**: every host answered and none holds it (the repository was
  deleted, moved or unmounted everywhere);
- **unknown**: no host holds it, but some host could not be asked, or could
  not read the repository;
- **another project's**: the repository only holds backups of a same-named
  container in another project.

An available entry's size and time are those of this container's own newest
backup in that repository, read from its manifest, so a same-named container in
another project that uses the same repository never shows through.

Without the admin role you see only the entries that are available for this
container, and no host paths: no reasons, no rootfs path, and an absolute
repository path reads `(host path)`. The others are shown to an admin. An
entry is never removed by inspect, and it still counts toward the project's
`backup_gib`, as a VM backup in a vanished repository does.

### Asking one node about a container on another

Every node serves `lv ct ls` from its own copy of the cluster state, and a
container's create and start run on its owning host. When the node you are
connected to is not the owner, `lv ct create` returns once that node lists the
new container, `lv ct start` once it lists it `running`, `lv ct stop` once it no
longer lists it `running`, and `lv ct rm` once it no longer lists it at all — so
an `lv ct ls` straight after any of them shows the result, not the state before
it. `lv compose up` and `lv compose down` report a container done on the same
terms. If replication is slow to bring
the owner's write across, the command still succeeds after waiting up to 15
seconds, and the daemon logs `container operation succeeded on its owner, but
this node's replica has not caught up`.

## Private registry credentials

Pulling a private image (a private Docker Hub repo, `ghcr.io`, a self-hosted
registry) needs a registry login. Credentials are stored cluster-wide and come
in two scopes:

- **Per-user** — owned by the authenticated caller; only used for that user's
  pulls.
- **Global** — cluster-wide, operator-managed; applies to anyone.

At pull time the daemon resolves the credential for the image's registry with
this precedence: **the caller's per-user credential wins → else the global
credential → else an anonymous pull** (unchanged behaviour). Resolution happens
on the node you're connected to (the only place your identity is known) and the
resolved secret is carried along if the pull is forwarded to another host.

```
# Store a per-user credential (prefer --password-stdin so the token never
# lands in your shell history or the process arg list)
echo "$GHCR_TOKEN" | lv registry add ghcr.io --username me --password-stdin

# Store a global, cluster-wide credential (operator-only)
echo "$ORG_TOKEN" | lv registry add ghcr.io --username org --password-stdin --global

# List credentials — your own + global (secrets are never shown);
# --all shows every user's (operator-only); --global shows global only
lv registry ls

# Remove one (your own by default; --global for the cluster-wide one)
lv registry rm ghcr.io

# Pull a private image — credentials are resolved automatically
lv ct pull ghcr.io/acme/api:1.4 --dest api
```

The registry argument is a host (`docker.io`, `ghcr.io`,
`registry.example.com:5000`); Docker Hub short names like `alpine` resolve to
`docker.io`, so a credential stored against `docker.io` covers them.

For a one-off authenticated pull without storing anything, pass the credential
inline — this is also the only way to authenticate under `--local`, where there
is no daemon to resolve a stored credential:

```
echo "$TOKEN" | lv ct pull ghcr.io/acme/api:1.4 \
    --dest api --username me --password-stdin
```

Credentials can also be managed from the web UI at **Account → Registry
Credentials** (the global section is shown to operators). Secrets are stored in
the cluster database; the wire/API and UI never return them after they're set.

## Compose integration

The new unified `workloads:` map carries a `kind:` discriminator. Stacks
can mix VMs and containers freely, with the same network attachments,
labels, and placement strategy.

```yaml
networks:
  prod:
    type: bridge
    interface: br0

workloads:
  web-vm:
    kind: vm
    image: ubuntu-24.04
    cpu: 4
    memory: 4G
    network: [{ name: prod, ip: 10.0.0.5 }]

  web-ct:
    kind: lxc
    image: alpine:3.21          # download template (distro:release) or a rootfs path
    cpu: 2
    memory: 512
    network: [{ name: prod, ip: 10.0.0.6 }]
```

Containers are full compose citizens: `lv compose up` creates **and starts** each
container on an LXC-capable host (placement is capability-aware: a container
lands only on a host labelled `litevirt.lxc=true`, see
[Host-loss relocation](#host-loss-relocation)); re-apply is idempotent (unchanged
containers are left alone, a changed spec recreates); and `lv compose down`
removes them and every trace they created (rootfs, the stack's network bridge +
dnsmasq, and any load balancer processes). The legacy `vms:` map is accepted —
every entry there gets `kind: vm` applied implicitly so existing stacks need no
changes.

Containers attach to a stack's networks the same way VMs do — give the NIC a
static `ip:` (litevirt assigns it and writes the guest's `/etc/network/interfaces`),
or omit it for DHCP off the network's dnsmasq.

**Load balancer backends.** A stack `loadbalancer:` discovers containers as
backends alongside VMs, so a single LB can front a mix of both. Use a static NIC
`ip:` for the container (recorded cluster-wide); a DHCP-assigned address is also
resolved when the container runs on the LB's own host. (A DHCP container on a
*different* host than the LB isn't auto-discovered yet — a follow-up.)

Current limits: an OCI **registry ref** (`kind: oci`, `image:
docker.io/library/nginx:1.27`) isn't auto-pulled by compose yet — pre-pull it
(`lv ct pull <ref> --dest <dir>`) and set `image:` to that rootfs path. Each
container gets its own copy of that rootfs, so one pull backs any number of
containers and `compose down` never disturbs the pulled template. A cpu/mem
change recreates the container (no in-place reconfigure). `lv compose ps` lists
VMs only. Containers have no **live/CRIU** migration; **cold migration**
(`lv ct migrate`, stop → transfer → start) exists — see the Cold migration
section below. Per-NIC security-group provisioning for containers is a follow-up.

## Networking

LXC's native `veth` driver attaches into a bridge. Containers inherit the same
network primitives the VM side uses (bridge, vxlan, isolated), so a container can
sit on a VXLAN-overlaid VNet alongside VMs.

A NIC is attached one of two ways:

- **`network=<managed-net>`** — a *managed* NIC on a litevirt logical network. It
  gets a tracked `container_interfaces` row, a deterministic host veth and MAC, an
  IPAM lease, DNS, and security-group enforcement (see below). This is the
  first-class path and the one tenants use.
- **`bridge=<br>`** — a *raw* NIC straight onto a host bridge, with no managed
  state. The legacy/admin escape hatch (see *Project isolation* below).

```
# Managed NIC on logical network "app-net", with security groups:
lv ct create web --distro alpine --release 3.21 \
    --network network=app-net,name=eth0,security-groups=web;db \
    --cpu 2 --memory 512

# Raw bridge NIC with a static IP:
lv ct create edge --distro alpine --release 3.21 \
    --network bridge=br0,name=eth0,ip=10.0.0.6/24
```

Stacks attach the same way: a compose `kind: lxc` workload's `network:` names a
managed network. With no `--network`, the container gets a single raw veth on the
host's default `lxcbr0` bridge (NAT to the outside).

When `ip=` is given (or a managed network assigns a static address), litevirt also
writes the guest's `/etc/network/interfaces` (ifupdown) so the address survives
boot — otherwise the stock image's DHCP client would flush it. `internal/lxc/
network.go` renders the config snippet, emitting the deterministic veth pair so the
host side is trackable:

```
lxc.net.0.type = veth
lxc.net.0.link = br-app-net
lxc.net.0.veth.pair = lvc1a2b3c4d5e6f
lxc.net.0.hwaddr = 52:1a:2b:3c:4d:5e
lxc.net.0.flags = up
lxc.net.0.name = eth0
lxc.net.0.ipv4.address = 10.0.0.6/24
lxc.net.0.ipv4.gateway = 10.0.0.1
```

On a managed network with a subnet, the address in the container's config
always carries the subnet's prefix, and the first such NIC gets the subnet's
first host as its gateway — in the config and in the guest's interfaces file
(`gateway 10.0.0.1`). That holds for an auto-allocated address, for a bare
static `ip=10.0.0.6`, and for a host-loss recreate. LXC reads a bare address
classfully, so without the prefix `172.16.77.2` became a `/8` route over all of
`172.0.0.0/8`, with no default route. The interface row and the IPAM lease keep
the address as allocated.

### Managed-NIC identity, IPAM, DNS, security groups, load balancing

A managed NIC (one naming a `network=`) reaches **VM parity**:

- **Interface row + deterministic identity.** Every managed NIC gets a
  `container_interfaces` row keyed `(host, ct, ordinal)`, a deterministic host veth
  (`lvc` + a hash, ≤15 bytes / IFNAMSIZ) and a generated locally-administered MAC
  (`52:` + a 40-bit host-scoped hash, so two same-named containers on different
  hosts sharing an L2 don't collide). The veth/MAC are stable across
  restart/restore/migrate/clone.
- **IPAM.** A static IP reserves that exact address; a subnet-backed network
  auto-allocates one; a subnet-less network is DHCP (the IP is discovered later).
  Leases are non-aliasing across VMs and same-named containers. An address is
  one lease however it is written: `ip=10.0.0.5/24` and `ip=10.0.0.5` are the
  same address, and the second request is refused.
- **Addresses shared before this release.** Earlier releases keyed a lease on
  the text you gave, so two containers could hold `10.0.0.5/24` and `10.0.0.5`
  at once. Such a pair keeps working: when one of them is restored or
  relocated it keeps its address, with a WARN naming the other holder, so you
  can reassign one. It keeps it only when the lease history proves it already
  held that exact address in its own project, and no one took the address
  after it let go. Otherwise the shared address is refused and the NIC fails
  safe: a restore leaves the NIC without an address and the container stopped
  (`operator-stop`), and a relocation falls back to DHCP. The address stays in
  the container's spec. This happens when:
  - the other holder re-acquired its lease after this container released its
    own (its own restore or relocation, a lease rekey, a network rescope);
  - this container's old lease record is gone (tombstone garbage collection,
    or a rescope that moved the live leases but not the released one);
  - the container is a copy of the other holder: the same name on another
    host;
  - a same-named container in another project holds the history.

  Free the address (or give one container a new one) and start it again.
- **DNS.** A managed container with a known IP is resolvable at
  `ct.stack.domain` (the container analogue of VM DNS). The per-host IP scanner
  discovers a DHCP address, persists it, and (re)writes the record; delete/migrate
  remove it.
- **Security groups.** `security-groups=` binds SGs to the container's veth with
  the same per-NIC nftables enforcement VMs get on their tap. (Bound at
  create/recreate time; a day-2 CT-aware rebind API is a follow-up.)
- **Load balancing.** A stack's `loadbalancer:` resolves managed containers as
  backends, including a container running on a **remote** host (resolved via a
  peer lookup).

### Project isolation

A container in a tenancy project may attach only to a network that is **global**
(unowned) or **owned by its own project** — attaching to another project's network
is denied. A *raw* bridge (`bridge=`) is outside isolation, so it requires
cluster-root network authority: a **project-scoped** caller must use a managed
`network=`; a cluster admin keeps the raw-bridge escape hatch. See
[tenancy.md](tenancy.md) and [networking.md](networking.md).

## Resource limits

`lv ct create --cpu <cores> --memory <MiB>` (and compose `cpu:`/`memory:`, and
the UI's create form) translate to cgroup limits written into the container's
config at create time. `--cpu N` caps the container at N whole cores — the same
meaning as a VM's cpu count and Docker's `cpus` — and `0` leaves it uncapped.
It is a limit, not a reservation: placement and host admission charge a
container its memory only. Cores are whole numbers. We emit both v1 and v2 keys
so the same config works on either kernel — irrelevant keys are simply ignored.
For `--cpu 2 --memory 512`:

```
lxc.cgroup2.cpu.max = 200000 100000
lxc.cgroup.cpu.shares = 2048
lxc.cgroup2.memory.max = 512M
lxc.cgroup.memory.limit_in_bytes = 512M
```

`--memory 0` means "no cap", and litevirt expresses that by **omitting** the
key rather than writing a zero. That distinction matters when the limits are
read back, because the config is root-editable and cgroup2 accepts both
spellings of a very different thing:

| In the config | Read back as |
|---|---|
| key absent | unlimited |
| `memory.max = max` | unlimited |
| `memory.max = 0` | a **finite** zero-byte cap |
| `memory.max = 512M` | a 512 MiB cap |

A hand-written `memory.max = 0` is a legal cgroup2 value and the most
restrictive cap there is, so it is read as finite rather than rejected or
treated as unlimited. Reading it as unlimited would flag the container as
uncapped, which trips the uncapped gate and blocks new admission on the host.

Every container also gets a **pids limit** (`lxc.cgroup2.pids.max`),
`containers.default_pids_max` (4096) unless its config already sets one. A new
container gets it at create. An **existing container gets it at its next
start**, and only then: the daemon never changes a running container's limits,
and a container whose config already sets `pids.max` keeps its own value. `0`
turns the default off. The `cpu`/`memory` limits are cgroup v2 `cpu.max` and
`memory.max`; the v1 keys beside them are ignored on a unified host (LXC warns
"Ignoring legacy cgroup limits").

A container created by an earlier release keeps the cgroup limits it was created
with until it is recreated (a compose update, a restore, a relocation or a
clone writes a fresh config): those releases wrote `cpu.max` as `N*1000 100000`,
N/100 of a core. Its recorded `cpu` is read as N cores everywhere else — quota,
`lv ct ls`, `litevirt_container_cpu_limit` — as it always was.

## Restart policy

`lv ct create --restart {none|on-failure|always}` (and compose `restart:`) makes a
container auto-restart when it stops **unexpectedly**:

```
lv ct create web --distro alpine --release 3.21 \
    --restart on-failure --restart-max-attempts 5 --restart-delay 5s
```

A per-host reconciler reconciles each container's cluster-state row against the LXC
runtime every ~15s and restarts a down container per its policy, honouring
`max-attempts`/`window`/`delay`. The cluster row is also synced to the runtime's
reality, so `lv ct ls` and the detail view never disagree.

A container that has been created and never started has not stopped, so the
restart policy does not apply to it: it stays stopped until `lv ct start` (or
the start `lv compose up` makes right after the create). The same holds for a
container made by `lv ct clone` or `lv ct restore` without starting it: it keeps
the restart policy it was made with, but stays stopped until it is started (a
restore of a backup taken of a stopped container keeps that container's stop
intent instead). The reconciler also
takes the same per-container lock as `lv ct create`, `start`, `stop` and `rm`
on that host, and reads the row again once it holds it, so a sweep never acts
on a container while one of those is changing it — a `lv ct stop` that lands
mid-sweep stays stopped. The reconciler does not wait for that lock: a
container that an operation holds — a `lv ct backup`, `lv ct migrate`,
`lv ct snapshot`, `lv ct restore` or `lv ct clone` holds it for its whole run —
is skipped for that sweep and reconciled by the next one, so one long operation
never delays the reconcile of the host's other containers.

**Caveat (coarser than VMs):** LXC reports only `RUNNING`/`STOPPED`/`FROZEN` — no
stop *reason*. A container therefore cannot distinguish a clean in-guest shutdown
from a crash. Only an operator `lv ct stop` is guaranteed-stick (it records
`operator-stop`); any other stop is treated as unexpected and restarted per policy.
A `FROZEN` (paused) container maps to running and is never restarted.

> On-host restart-policy handles a container that stops while its host is alive.
> If the whole host is fenced, **host-loss relocation** (see below) rebuilds the
> container on a surviving peer when it carries an `on_host_failure` policy.

## Tenancy, audit & metrics

Containers are first-class tenancy citizens, at parity with VMs:

- **Project** — `lv ct create --project <name>` places a container in a tenancy
  project (default `_default`); per-container RBAC and quota use it. Set once at
  create; shown in `lv ct ls`.
- **Quota** — container creation is admitted against the project's quota and
  **shares the same vCPU/memory budget as VMs** (one joint tenant limit). A
  container created with `--cpu`/`--memory` counts toward the budget whether
  running or stopped; an unlimited container (no `--cpu`/`--memory`) contributes
  nothing to that dimension. Exceeding the budget fails with `ResourceExhausted`.
- **Audit** — `create / start / stop / delete / exec` are written to the
  tamper-evident audit hash-chain (`ct.*` actions, with the project and result);
  permission-denied attempts are recorded too. View with `lv audit`.
- **Metrics** — the Prometheus exporter emits `litevirt_container_state` (1=running),
  `litevirt_container_cpu_limit`, `litevirt_container_memory_limit_mib`, and
  `litevirt_host_container_count`; running containers also count toward
  `litevirt_host_pressure`. For **live cgroup usage**, running containers also emit
  `litevirt_container_cpu_seconds_total` (cumulative CPU seconds, cgroup-v2
  `cpu.stat`) and `litevirt_container_memory_bytes` (cgroup-v2 `memory.current`).
  Usage metrics require cgroup-v2 (the modern default); on a cgroup-v1-only host
  they are quietly omitted (limits/state are still reported).

## Backup & restore

Containers back up to the same PBS-equivalent chunk store as VMs (BLAKE3
content-addressed dedup), so re-running a backup only writes what changed.

```bash
# Freeze the container, archive its rootfs + LXC config, and push to a repo.
lv ct backup web --repo /srv/backups

# Rebuild it later from the repo alone — even after `lv ct rm web` and even
# if the original image/template is gone. --start brings it up.
lv ct restore web --repo /srv/backups --timestamp 2026-06-23T10:00:00Z --start
```

How it works and what to expect:

- **Full, crash-/app-consistent.** A *running* container is frozen
  (`lxc-freeze`) for the duration of the read so the archive is a consistent
  point-in-time, then unfrozen — always, even if the backup fails midway. A
  stopped container is archived as-is. There is no dirty-bitmap incremental
  (containers are full-only); the chunk store's dedup gives storage-side
  incrementality, so the second backup of an unchanged rootfs writes almost
  nothing.
- **Self-contained manifest.** The manifest embeds the container's spec
  (cpu/memory/labels/restart-policy/project/image) alongside the archived
  rootfs **and** its LXC config, so restore needs only the repo — not the source
  cluster, and not the original OCI image or download template.
- **Restore is non-destructive.** It refuses to overwrite a live container of
  the same name (`AlreadyExists`) — `lv ct rm` it first, or restore onto a host
  that doesn't have it. The restored container comes up `stopped` unless you
  pass `--start`.
- **Host-local, like VM backup.** A container is archived on its owning host;
  run `lv ct backup`/`restore` against that host (`LV_HOST`). Restore runs on
  the **target** host (where the container will live). Running `lv` as root
  on that host itself works too: with no CLI bundle it presents the host
  certificate over loopback, which is local root, and its restore is an
  operator restore like any other. Only another node's daemon is taken for a
  failover coordinator, which must carry a relocation proof once the
  split-brain gate is enforced.
- **No rename.** The name selects the backup in the repo, so a restore keeps
  it: restore onto another host (`--host`) to keep both.
- **Faithful file metadata.** The archive is made with `tar --numeric-owner
  --xattrs --xattrs-include='*' --acls`, and a restore, migrate or snapshot
  revert lays back setuid, setgid and sticky bits, file capabilities
  (`security.capability`), ACLs, SELinux labels and `user.*` attributes, after
  each file's owner (a chown clears setuid and capabilities). An unprivileged
  container's archive carries its shifted owners and re-rooted capabilities, so
  it comes back in the same range. `trusted.*` attributes are not taken from an
  archive. An attribute the target cannot store does not fail the restore or
  migrate, as on earlier releases: no support for it (ZFS with `acltype=off`,
  NFS), no room for it (`ENOSPC`, `E2BIG`, `ERANGE`: ext4 keeps a file's
  attributes in one block), an SELinux label the target's policy does not
  know, or IMA/EVM appraisal refusing a foreign signature. What it takes is
  applied and what it cannot store is dropped, listed
  in a `ct.attrs.dropped` event, the audit log and a warning. A dropped ACL
  never widens access: the file's group bits narrow to the ACL's own group
  entry. A dropped capability or label only removes privilege. A dropped
  *default* ACL cannot be narrowed: files later created in that directory get
  the umask's permissions, as on earlier releases. Any other failure — an I/O
  error, or `EPERM` setting a file capability — still fails the restore. A directory's metadata
  (its default ACL included) is applied after its contents, so files do not
  inherit an ACL the archive did not record for them.
- **Laid down privately.** The archive is extracted into a `0700` staging
  directory beside the container store and moved into place once its
  directory is closed to other users, so its setuid binaries are never
  reachable on the way. The host it lands on gets root's subordinate range
  for an unprivileged container then (and again at every start).
- **The container's directory is closed to other host users.** A restored
  rootfs carries its setuid binaries and capabilities back onto the host's disk
  under `<lxcpath>/<name>/rootfs`, the same exposure the source host had. So
  every create, clone, restore, migrate and convert leaves `<lxcpath>/<name>`
  mode `0770` — owned by the container's mapped root when it is unprivileged
  (the container reaches its rootfs through it, as LXC itself arranges), and by
  root otherwise — and no other host user can reach the rootfs.
- **Quota.** A container's backup footprint draws down the **same `backup_gib`
  project budget** as VM backups.

## Security

A new container is **unprivileged** and **confined** by default.

- **Unprivileged.** It gets a range of 65536 host ids of its own
  (`lxc.idmap = u 0 <base> 65536`, and `g` likewise): root in the container is
  an unprivileged id on the host. Ranges come from `containers.idmap_base` /
  `containers.idmap_ranges` and are allocated **cluster-wide without overlap**:
  a create avoids every range any container row in the cluster records, every
  range this host handed out in the last day (a host-local ledger, for creates
  still in flight or rows still replicating), and every range a container on
  this host's disk is configured with. Hosts start their search at different
  points, so two hosts allocating at the same instant almost never collide; if
  they do and a migrate later brings both containers to one host, `lv ct start`
  refuses the second with `lv ct convert --unprivileged <name>` as the fix.
- **The rootfs is mapped**, by an idmapped mount (`lxc.rootfs.options =
  idmap=container`) where the host supports one (`containers.idmapped_rootfs`),
  otherwise by shifting every file into the range at create: owner and group,
  POSIX ACL entries, and file capabilities (re-rooted as v3). setuid and setgid
  bits are kept. A container mapped by a mount that later starts on a host
  without idmapped mounts (a migrate) is shifted at that start.
- **Confinement `default`**: LXC's generated AppArmor profile with nesting off,
  LXC's common seccomp policy, and the standard capability drop list
  (`mac_admin mac_override sys_time sys_module sys_rawio`), written explicitly in
  a litevirt-owned block of the container's config rather than left to the
  template or its includes. An unprivileged container also includes LXC's
  `userns.conf` (before the drop list, which it would otherwise reset).

- **Root's subordinate ranges.** When the host hands out subordinate ids
  (`newuidmap` is installed) LXC insists that root's mappings lie inside root's
  ranges in `/etc/subuid` and `/etc/subgid`. When no `root:` line covers a new
  container's range, the daemon appends one line, `root:<idmap_base>:<span>`
  (the whole configured span, so it is added once). The append never rewrites
  or removes a line, its own or anyone's (a last line without a newline gets
  one first); it checks again under the lock, so racing creates and daemons
  add the line once; and it takes the lock shadow's own tools use
  (`/etc/subuid.lock`, created exclusively and removed afterwards), waiting up
  to ten seconds for `usermod` or `useradd` and never removing their lock. A
  host with no subordinate-id tooling and no files is not touched.

The opt-outs restore what earlier releases did, and are the **Admin's**:

```bash
lv ct create build --privileged                 # no user namespace
lv ct create dind  --confinement legacy         # AppArmor nesting allowed, template seccomp/caps
```

Compose takes the same per workload (`privileged: true`, `confinement: legacy`),
so a stack that needs them says so; deploying it then needs the Admin role.

**Existing containers keep their settings.** A container created before this
release is privileged with legacy confinement and keeps running exactly as it
is; nothing rewrites its config. `lv ct inspect <name>` shows a container's
privilege mode, range and confinement, and `lv doctor privileged-containers`
lists every privileged or legacy-confined one. To move one over, stop it and:

```bash
lv ct convert web --unprivileged --confinement default
```

The convert runs offline on the owning host. It shifts the rootfs into a fresh
range in place — nothing is copied or deleted — then rewrites the config's
security block and records the new settings. A marker in the container's
directory is written first and removed last, so a convert that is interrupted
(a crash, a full disk) leaves a container that `lv ct start` refuses, naming
`lv ct convert <name>`: run with no flags, a convert finishes the recorded
target (any caller who may convert the container may run it), and with
flags it finishes the recorded target first and then applies them (it only
moves ids still in the old range). The re-run finishes to the range the interrupted convert
recorded, whatever range it would otherwise be given, so the rootfs never ends
up split across two ranges. `--confinement` alone changes the profile and touches no file;
`--confinement legacy` is the Admin's.

**Every move keeps the mode.** Migrate, backup, restore and host-loss
relocation carry the container's config — and so its range and confinement —
unchanged; a relocation recreate rebuilds the same range and profile from the
create spec, and one from an earlier release is recreated privileged and
legacy, as it was. A clone keeps its source's mode: an unprivileged source's
clone is moved to a fresh range of its own, a privileged one stays privileged.
An operator restore of an unprivileged backup whose range another live
container now holds (its original still exists) is moved to a fresh range.

## Owner records

A container's name is unique per host only, and reusable: delete `web` in
project `acme`, create `web` in project `beta`, and every file keyed by host and
name — the snapshot tars and their rows, the backups in a repo — reads as
beta's. Container files are therefore chosen by their **owner record**: the
project plus an `owner_id` in the container's create spec.

- `owner_id` is minted when a container is created or cloned (a clone is a new
  lineage), and kept by `lv ct migrate`, host-loss relocation and restore. A
  restore of a backup from an earlier release, which carries none, gets one.
- It is stamped on disk as `<lxcpath>/<name>/litevirt-owner` (re-stamped after
  every restore and migrate, whatever the archive held), beside each snapshot
  tar as `<snapshot>.tar.owner`, and it rides in every backup manifest inside
  the create spec.
- A snapshot taken of an earlier container in another project is not listed
  to, reverted or deleted by a caller without the Admin role (also through a
  forwarding node, which marks the call). Within one project a snapshot stays
  usable as before.
- Host-loss restore picks the relocating container's own newest backup:
  manifests of another project, or of another lineage of the name, are skipped.
- A host-loss recreate adopts a container already on the survivor ("made by a
  previous sweep") only when its owner record names the row's project and
  lineage; otherwise the row stays pending with a `ct.relocate.failed` event.
- A file or container with **no** owner record (made by an earlier release) is
  matched by name, exactly as before: records only add proof.

## Snapshots

```bash
lv ct snapshot create web before-upgrade   # point-in-time snapshot
lv ct snapshot ls web
lv ct snapshot revert web before-upgrade    # roll back to it
lv ct snapshot rm web before-upgrade
```

A snapshot freezes a running container (for a consistent point-in-time), tars
its on-disk dir, and stores it **host-local** under `{dataDir}/ct-snapshots`.

- **Revert keeps the container's current security.** A snapshot taken before
  `lv ct convert` carries the old privileged config; the revert converts the
  restored copy back to the privilege mode, range and confinement the
  container has now (its record), so it never silently runs privileged again.
  The restart refuses an overlapping id range like `lv ct start`. The restored copy is
  marked converting before it is swapped in, so a crash between the swap and
  the convert leaves a container that refuses to start, naming
  `lv ct convert <name>`, which finishes it to the recorded range and
  confinement — never one running with the snapshot's older mode. Do not
  revert again to recover: that rolls the rootfs back.
- **Revert** stops the container (replacing the rootfs requires it stopped),
  restores the snapshot in place, and restarts it if it had been running. The
  restore is **crash-safe** — the live dir is set aside and rolled back if the
  snapshot extract fails, so a corrupt snapshot can never lose the container.
- **Host-local**, like the container itself; snapshot ops run on the owning host
  (the daemon forwards there automatically).
- **Private to root.** A snapshot is the container's whole rootfs, its
  `/etc/shadow` included, so the tar is written `0600` in `0700` directories
  (`ct-snapshots/` and `ct-snapshots/<container>/`). A snapshot an earlier
  release wrote world-readable is narrowed the next time it is listed, reverted
  or snapshotted beside; nothing sweeps the others.
- Snapshots are full copies today (no dedup); **COW acceleration** on
  btrfs/zfs/lvm-thin rootfs is a planned follow-up. For space-efficient,
  off-host point-in-time copies use `lv ct backup` (dedup chunk store).

## Templates & clones

```bash
lv ct template ubuntu-base            # mark a stopped container a clone template
lv ct clone ubuntu-base web-01        # full-copy clone with a fresh identity
lv ct clone ubuntu-base web-02 --start
lv ct template ubuntu-base --revert   # back to a normal container
```

A **template** is a stopped container that can't start — a golden clone source.
A **clone** is a full copy (`cp -a`) of a template or stopped container with a
**fresh identity**: new `lxc.uts.name`, a regenerated NIC MAC, and a reset
`/etc/machine-id` + `/etc/hostname`, so it boots clean and doesn't collide with
its source. Clones are created on the source's host (its rootfs lives there) and
admitted against the project quota; they inherit the source's project unless
`--project` overrides. Unlike VMs there are no linked clones (no qcow2 backing) —
every container clone is independent, so reverting a template is always safe.

## Host-loss relocation

Opt a container in at create time: `lv ct create web --on-host-failure
image-recreate` (default is `none` — left in place). If a host is fenced, the
failover coordinator relocates its containers that carry that policy onto a
healthy host (chosen via the placement engine), preferring the most faithful
option available:

1. **Restore from the latest backup** (`ct.relocate.restored`) — when a valid
   backup manifest exists in a repo the survivor can reach and the survivor is
   schema-compatible. The container is restored over peer mTLS (rootfs + the
   create-time spec, so litevirt-managed **networking is preserved**). This is
   driven idempotently: the coordinator marks the source row `relocating` (it
   never pre-creates a target row), and only tombstones the source once the
   restore lands — so a coordinator crash mid-restore re-derives correctly and
   never double-restores or strands the container.
2. **Recreate from image** (`ct.relocate.recreate`) — the fallback when no usable
   backup exists (or the restore failed / the survivor is mid-upgrade). The
   container is re-keyed and the target's reconciler rebuilds it from its
   re-pullable image, reconstructing managed NICs from the persisted create spec.
3. **Skip** (`ct.relocate.skipped`) — when neither is possible (e.g. a hand-built
   rootfs with no re-pullable image and no backup), or when no active host has a
   container runtime. Loudly audited so an operator knows to recover it manually.

A relocation target must have a container runtime. Each daemon records whether
its host has one in the `litevirt.lxc` host label: it probes for `lxc-create`
at start and re-checks every minute, writing `true` or `false`. The rule is
strict: every container placement (compose, failover relocation, restore) uses
only a host labelled exactly `litevirt.lxc=true`. A host labelled `false`, or
with no label at all, never gets a container. A relocation that reached such a
host anyway, for example one decided before the host recorded the label, fails
there for good. The container goes to `error` with the cause, its relocation
proof is failed, and the host stops retrying the rebuild.

If a host that has LXC installed refuses containers with `no container runtime
(litevirt.lxc unset)`, its daemon has not written the label yet. The daemon logs
`set LXC capability host label failed` and retries every minute. `lv host label
ls <host>` shows the label.

Restore-from-backup requires a backup repo reachable from the survivor (a
registered repo name / shared NFS). `container_restore_timeout_sec`
(default 10m) bounds how long a relocate-restore is treated as in-flight before
the coordinator gives up and image-recreates. The create-time networking spec is
persisted from schema **v34** — containers created/backed-up before v34 fall back
to image-recreate (without managed-NIC reconstruction).

## Cold migration

Before the source is stopped, a migrate asks the target to give root the
subordinate range for an unprivileged container's id range (the peer-only
`PrepareContainerTarget`). The target takes only a container-shaped range —
65536 ids above the host's own ids, a slot of its `containers.idmap_*` span
when it lies inside it — that overlaps no range another container records or
runs with there — an unfinished convert's recorded range counts as held. A
range that overlaps the target's span must be exactly one of its slots. A range
outside the span (a backup restored from another cluster, nodes configured
differently) is taken when it is free and overlaps no other user's entry in
`/etc/subuid` or `/etc/subgid`. Root's lines there stay bounded: one per
distinct range, never repeated. A target that cannot — its `/etc/subuid` is locked or not
writable — refuses the migrate while the source still runs, untouched.
A target older than this release cannot be asked; the migrate proceeds and the
target's own start ensures the range.

```bash
# Move a container to another host. The repo must be reachable from BOTH hosts.
lv ct migrate web docker-02 --repo /srv/shared/backups
```

Migration **reuses the backup→restore data path** (one tested transport): the
source stops the container, archives its rootfs+config into the staging repo,
the target rebuilds from it, and the source copy is removed. If the container
was running it's restarted on the target.

- **Cold only** — the container is stopped for the transfer (no CRIU / live
  migration). This is the same model as VM cold migration.
- **Atomic re-key.** The owner moves to the target only after the restore
  succeeds; exactly one live row survives the window. **A failure before cutover
  leaves the container intact on the source** (restarted if it had been running).
- **No shared repo required.** The source archives into `--repo` locally and
  **streams the manifest to the target over peer mTLS** (into a per-transfer
  staging repo), so `--repo` need only exist on the source. (An older target
  predating peer streaming falls back to re-opening `--repo` by name, which then
  must be shared/reachable from both hosts.) Run against the source host
  (`LV_HOST`).
- Refuses to migrate onto a host that already has a container of that name.

## gRPC + WebUI

- **gRPC `Containers` service** — `Create / Start / Stop / Delete /
  Exec / List / PullOCIImage / BackupContainer / RestoreContainer /
  MigrateContainer` RPCs. `lv ct …` defaults to gRPC;
  cross-host requests forward via `peerClient` to the named host.
  `--local` flag forces the host-local lxc-* path for bootstrap /
  debug. The `containers` cluster-state table backs cluster-wide
  `lv ct ls`.
- **WebUI `/containers`** — full lifecycle: a create modal (download-template
  distro/release/arch, CPU/memory, bridge, auto-restart policy), per-row
  Start/Stop/Delete + Exec (one-shot command modal), a host filter, and a bulk
  toolbar (start/stop/delete) with select-all.

## What's still in flight

- COW snapshot acceleration — snapshots have shipped (freeze+tar, see above);
  instant copy-on-write snapshots on a btrfs/zfs/lvm-thin rootfs are a follow-up
  (containers have no pool association today, so the rootfs filesystem would be
  detected at snapshot time).
- Cross-host container backup/restore streaming — today, like VM backup,
  a container is archived on its owning host (run against `LV_HOST`); a
  relay so any entry node can drive it is a follow-up.
- Live migration (CRIU). **Cold** migration has shipped (`lv ct migrate`, see
  above — stop → transfer → start, reusing the backup transport); live migration
  with in-flight process state (CRIU) is a follow-up.
- Cross-host backup/restore/migrate today require a repo reachable from the
  hosts involved (run against `LV_HOST`); a peer-streaming relay so any entry
  node can drive them without shared storage is a follow-up.
- OCI image cache reuse — each `lv ct pull` re-fetches from the
  registry; the backup chunk store will eventually absorb image
  layers.
- Compose `workloads:` → Containers RPC dispatch **(shipped)**: `lv compose up`
  routes `kind: lxc` (download template or rootfs path) workloads through
  CreateContainer + StartContainer on the planner-resolved host, so a stack can
  mix VMs and containers.
- Managed container networking **(shipped)**: interface rows, IPAM, deterministic
  veth/MAC, DNS, security-group enforcement on veths, cross-host LB resolution, and
  project-scoped attach isolation — see *Networking* above. Remaining: auto-pull of
  OCI **registry** refs (pre-pull required today); a day-2 CT-aware security-group
  rebind API; a dataplane cross-project L2 firewall deny (admission already enforces
  the isolation invariant).
