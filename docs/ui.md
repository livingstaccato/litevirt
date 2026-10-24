# Web UI

The litevirt web UI runs on port 7445. It is built with Go templates and HTMX -- there is no JavaScript framework. All requests require authentication via a session cookie.

## TLS

The UI listens on `127.0.0.1` by default. A node installed by `lv host init` /
`lv host add` gets `ui_tls: on`, so its UI speaks **HTTPS** from the start (with
the cluster certificate until you install your own). A node whose config predates
the key runs under `ui_tls: auto` and speaks plain HTTP — meant for an SSH tunnel
or a TLS-terminating proxy — until a certificate source exists. The sources:

| Source | How | Precedence |
|---|---|---|
| Custom certificate from your own PKI | `lv host ui-cert set <host> --cert chain.pem --key key.pem` | first |
| ACME (step-ca, Let's Encrypt) | `acme:` in the config, `challenge: http-01` or `dns-01` | second |
| The host's cluster certificate (cluster CA) | `ui_tls: on` | fallback |

Under the default `ui_tls: auto` the UI is HTTPS while a custom certificate is
installed or ACME is configured, and plain HTTP otherwise; `ui_tls: on` makes it
HTTPS always. The decision is re-made while running, so installing, replacing or
clearing a custom certificate takes effect within seconds without a restart.

`lv host ui-cert set` checks the chain before sending anything — the key matches
the certificate, the chain is in order (server certificate first, each followed
by its issuer), nothing in it is expired or not yet valid, it is a server
certificate, and its names cover the host's litevirt name or address (or every
`--name` you pass) — and refuses with the reason. The key is installed as
`/etc/litevirt/pki/ui.key`, mode `0600`, like the host's own key, and is never
printed or logged. The daemon applies the same checks before serving a pair, so
a hand-edited file that fails them is not served (the next source answers), and
it stops serving an expired custom certificate. Its expiry is exported as
`litevirt_certificate_expiry_timestamp_seconds{cert="ui"}` and notified like the
host certificate (`certificate.expiring`, notifications.md). `lv host ui-cert
clear` removes it; `lv acme status <host>` shows what is being served.

The daemon logs a warning at startup when it serves plain HTTP on a
non-loopback `ui_bind`, since logins then cross the network in clear unless a
proxy is in front.

## VM Management

### Creating VMs

The "New VM" form accepts the following fields:

- Name
- Image (including a **"— none (blank disk)"** option for installing from an ISO)
- CPU count
- Memory
- Disk size
- **Installer ISO** (`pool/file.iso`) with a **Browse…** button that lists the
  ISO libraries the caller may use — its projects' libraries first, then the
  global library `isos` — and fills in the reference, plus a **Boot from**
  selector (auto / disk / CD-ROM / network). Typing an absolute host path
  needs the Admin role (see [storage.md](storage.md#installer-isos))
- Host
- **Headless** (disables VNC) and **Enable SPICE console**
- **Tags** (`key=value` or bare `key`, comma-separated)
- **Cloud-init** (collapsible): login user, password, SSH authorized keys,
  packages, "upgrade on first boot", and a raw `#cloud-config` override
- Networks, optimization profile, resource-tuning knobs, and PCI devices
- **Memory ballooning & startup** (collapsible): min/max memory (a max above the
  boot allocation enables the virtio balloon), plus **onboot** + startup-order and
  start/stop delays
- Per-device **Mapping** field on PCI devices (cluster-portable passthrough — see
  the Resource Mappings page)

### Lifecycle Actions

VMs can be started, stopped, restarted, and deleted directly from the UI.

### Editing VMs

An edit modal is accessible from the VM detail page for resource and lifecycle
settings -- **Resources** (CPU, memory, disable VNC; requires the VM to be
stopped) and **Lifecycle & Boot** (restart policy, onboot, startup order, boot
order). It links to the VM's **Hardware** tab for disks, NICs, and PCI
devices rather than editing them itself.

### Hardware Tab

The per-VM Hardware tab (`/vms/{name}?tab=hardware`) is the single place to
add, remove, or inspect disks, NICs, and PCI passthrough devices, on running
and stopped VMs alike. Hotplug works for disks and NICs on running VMs. If PCI adoption for the VM is blocked, the tab shows the reason
and hides the add/detach forms until it resolves.

## VNC Console

An in-browser VNC viewer is available using noVNC (vendored as a static asset under `internal/ui/static/`, served by the daemon — no external CDN). It opens in a new tab at `/vms/{name}/vnc` and is only available for running VMs that have VNC enabled (not headless).

Cross-host routing path:

    browser -> WebSocket -> UI server -> gRPC ProxyVNC -> daemon on VM's host -> local VNC port

Daemon-to-daemon forwarding uses mTLS, so the UI server does not need direct network access to every host.

When the console has a password (see [Console passwords](#console-passwords)),
the daemon on the VM's host authenticates to the VNC port itself and offers the
viewer an unauthenticated handshake, so noVNC never sees or asks for the
password.

## Console passwords

A VM's VNC and SPICE consoles listen on its host's `127.0.0.1`. That keeps them
off the network, but not away from other processes and users on the host. Each
console therefore gets a per-VM password, which only litevirt presents:

- **VNC**: the daemon on the VM's own host reads the password from the running
  domain and authenticates to the listener. The browser, the UI server and
  any daemon that only relays the stream never see it.
- **SPICE**: the client has to present the password. `lv spice` carries the
  SPICE stream through the daemon unchanged (`ProxySpice`), and a SPICE
  password travels encrypted to a key the listener makes for each
  connection, so no relay can present it for the client the way the daemon
  does for VNC. `GetSpiceInfo` returns it to a caller that holds
  `vm.console` on the VM, and never logs it. The UI's **Download .vv** file
  carries it (the modal page itself does not). `lv spice <vm> --launch` hands
  it to `remote-viewer` in a private (0600) connection file rather than on
  the command line. `lv spice <vm> --show-password` prints it for a client
  you start yourself.

The password is stored in libvirt's domain definition (`<graphics
passwd='...'>`, readable only by root). Libvirt sends it to QEMU over the
monitor, never on QEMU's command line, and leaves it out of every XML dump that
does not ask for `VIR_DOMAIN_XML_SECURE`. litevirt does not write it to the
cluster database. A live migration carries it: libvirt hands the destination
the secure migratable definition, so the guest keeps its password and the
destination's daemon reads it from there.

Every define of a domain sets a **fresh** password: a create, a redefine on
update, a restore, a clone, a failover define, or the target of a cold
migration. A redefine of a domain from its own definition (a snapshot revert, a
point-in-time snapshot repair, a boot-order change) keeps the password it has.
The running guest keeps the password it started with, and the new one takes
effect at its next start. A VM that is already running when
passwords come into force has none until its next define or start. Until then
its console is open as before, and the proxy relays it unchanged.

Passwords are set only when `enforcement.console_password` is on (the default)
**and** the `console_password_v1` capability has latched. Until it latches,
litevirt neither sets nor removes a console password (one an operator gave an
imported domain stays as it was). It latches once every
host, including a maintenance host still receiving replication, runs a build
that can present a password. An older daemon relays the RFB stream raw, so a
passworded guest migrated onto it would have a console nobody could open. A
console opened through an older host acting only as a relay keeps working,
because the VM's own host does the authentication. Setting
`console_password: false` on a host (after the latch) makes its next define of
each domain drop the passwords, the redefines above included.

**A host that cannot do VNC passwords.** VNC authentication is DES, which a
FIPS-mode host's QEMU does not have, so QEMU refuses to start a guest whose VNC
console has a password. litevirt never lets that fail a start, a failover or a
migration:

- At startup the daemon asks its own QEMU: it starts a password-protected
  display on a private socket (`-machine none`), sets a password over QMP and
  authenticates to it, as the console proxy would. Only a successful VNC
  authentication counts (a display that asks for no password at all does not
  enforce one, and counts as unable): current QEMU starts such a display on a
  FIPS host and fails only at authentication. A kernel in FIPS mode
  (`/proc/sys/crypto/fips_enabled` = 1) counts as unable whatever QEMU says. A
  host that cannot sets no VNC passwords; SPICE keeps its own. It logs why, and
  reports `console_password_v1` in `PingResponse.not_enforcing`.
- A live migration onto such a host moves the guest without its VNC password
  (the target says so when the source prepares it); the guest arrives with an
  open VNC console. A target whose daemon has only just started waits up to 5
  s for its probe before answering; one that still has not answered (or whose
  probe was inconclusive) is taken as able, and if its QEMU then refuses, the
  migration fails cleanly and the guest stays on the source.
- If a start still fails over a console password litevirt set (QEMU says so,
  or the kernel is in FIPS mode and QEMU's failure is about its console), the
  daemon redefines the domain without its console passwords, starts it once
  more, logs it, and sets no VNC passwords from then on. Before the latch it
  never does this: a password then is an operator's, and that start fails as
  it always did.

Treating a FIPS-mode kernel as unable is **conservative**. On the QEMU tested
(8.2.2), VNC password authentication still works under FIPS, so such a host
gives up VNC passwords it could have had. It is kept that way because whether
DES is available under FIPS differs between QEMU builds and crypto backends.

**SPICE does not work at all on a FIPS-mode host.** spice-server makes an
RSA-1024 key for every SPICE link, which FIPS refuses ("Failed to generate 1024
bits RSA key"), so every SPICE connection is closed, with or without a
password. The guest still runs and its VNC console still works; nothing is
refused because of it. The daemon logs a warning at startup ("SPICE consoles
cannot connect on this host"), and `lv spice` and the UI's SPICE dialog show
the reason for a VM on such a host.

Limits:

- **VNC authentication uses only the first 8 characters** of a password. That
  comes from the protocol (DES keyed from 8 bytes), so the VNC password is 8
  random alphanumeric characters (about 47 bits). The protection is the
  loopback bind and the password together. It is not a defence against root
  on the host, who can read the domain definition anyway. SPICE passwords are
  24 characters.
- A direct VNC client over an SSH tunnel (`ssh -L ...:127.0.0.1:<port>`) now
  meets a password prompt. Use `lv vnc <vm> --listen 127.0.0.1:5900` instead:
  it opens that port on your machine, carries each connection to the console
  through the daemon (the web UI's path, authorized as you with `vm.console`),
  and your viewer needs no password and no SSH to the host. `lv vnc <vm>` says
  when a password is required. **Any other user on the machine where you run
  it can connect to that port while it runs, and gets the console with your
  credentials**: use it on a machine only you use, never on a shared jump host.
  Root on the VM's host can also read the password with
  `virsh dumpxml --security-info <vm>`.
- A VNC console configured with TLS or SASL in `qemu.conf` (`vnc_tls`,
  `vnc_sasl`) cannot be opened through the console proxy; the error names it.
- An `lv` binary older than this release does not print or pass on the SPICE
  password, so `lv spice` from it opens a client that prompts for a password.
  Upgrade the CLI.

## SPICE Console

VMs configured with `graphics: { spice: true }` in compose expose a SPICE
device alongside (or instead of) VNC. SPICE delivers higher-fidelity
graphics (better video, USB redirection, audio) and works with external
clients like `remote-viewer`, virt-manager, or the GTK SPICE client.

Enable SPICE at VM-create time (the "Enable SPICE console" checkbox) or via
`graphics: { spice: true }` in compose. A **SPICE** button then appears on the
detail page of a running SPICE-enabled VM.

Like VNC, the SPICE listener is bound to the VM host's `127.0.0.1`, so no
client can reach it at the host's address. There are two ways in:

- **Through litevirt** (from anywhere `lv` reaches the cluster): `lv spice
  <vm> --launch` opens a loopback port on your machine, carries each SPICE
  channel from it to the VM's host over `ProxySpice` (the daemon you entered
  on forwards it to the VM's own host), and starts `remote-viewer` on it
  with the console's password in a private connection file. It runs until
  remote-viewer exits. `lv spice <vm> --listen 127.0.0.1:5930` does the same
  for a SPICE client you start yourself (with `--show-password`), until
  Ctrl+C; the address must be a loopback one. Each channel is authorized as
  you (`vm.console` on the VM) and ends when your session does. Unlike `lv
  vnc --listen`, a local user who connects to that port still needs the
  console's password, when the console has one. A console with no password
  (console passwords not in force, or one that could not be read) is open
  to anyone on your machine who reaches that port, with your credentials, as
  with `lv vnc --listen`; `lv spice` warns when that is the case.
- **Directly**, on the VM's host or through an SSH tunnel to its loopback.
  The modal shows the tunnel command (with `ExitOnForwardFailure=yes`, so
  ssh stops rather than run on when the local port is already taken), and its **Download .vv** button gives
  a virt-viewer connection file for `127.0.0.1:<port>`, carrying the
  password, that `remote-viewer`/`virt-viewer` opens at the tunnel's end:

      ssh -o ExitOnForwardFailure=yes -L <port>:127.0.0.1:<port> <user>@<host>
      remote-viewer <vm>.vv     # or spice://127.0.0.1:<port>, with the password

  Opened on a machine with no such tunnel, the file connects to whatever
  listens on that machine's `127.0.0.1:<port>`, if anything, and a process
  listening there would be handed the console's password. Open it only at
  the end of the tunnel, or on the VM's host.

The browser cannot open a TCP port, so the UI itself carries no SPICE
stream; the web gateway serves only VNC (noVNC over `ProxyVNC`).

A bundled in-browser SPICE client (spice-html5) is on the long-term roadmap.

## VM Tags

Tag VMs with `key=value` pairs (or bare keys) for organization. Set them in the
create form or via an **Edit tags** button on the VM detail header; chips render
next to the VM name in the list and on the detail page. Backed by `SetVMLabels`,
which is metadata-only — it applies to **running** VMs without a redefine.

## Clone & Templates

From a stopped VM's detail page: **Clone** (linked on shared storage, full
copy otherwise) and **Convert to template** (an immutable, unstartable clone
source; **Revert to VM** undoes it). Templates clone with a fresh identity.

Every VNC and text console the UI opens is recorded in the audit log under
the signed-in user, refused attempts included, and so is every SPICE dialog or
`.vv` download, since it hands out the SPICE password
([audit-log.md](audit-log.md#console-sessions)).

## Text Console

An in-browser terminal is available using xterm.js (vendored as a static asset under `internal/ui/static/`, served by the daemon — no external CDN). It opens as a modal overlay on the VM detail page and is available for any running VM.

Cross-host routing path:

    browser -> WebSocket -> UI server -> gRPC ConsoleVM -> daemon -> serial PTY

This uses the same daemon-to-daemon mTLS forwarding pattern as VNC.

## Migration

The migrate modal shows host compatibility information for VMs with PCI devices. PCI pre-flight validation checks that the target host has enough free devices of each required type. SR-IOV VFs are hot-detached before migration and reattached on the target host.

## Authentication

The UI requires login via username and password. Sessions are maintained with a cookie. Users are managed via `lv user create` (see [cli-reference.md](cli-reference.md#authentication)).

## VM Exec

Run commands inside a running VM via the guest agent. Available from the VM detail page as a modal with a command input and output display showing exit code, stdout, and stderr.

## VM Logs

Stream VM console output in real-time. Available from the VM detail page via a "Logs" button. Uses Server-Sent Events (SSE) to stream log chunks from the `GetVMLogs` gRPC call. Features auto-scroll with a "Follow" toggle and a "Clear" button.

Stack-level logs are accessible from the stack detail page, showing a tabbed view with one tab per VM, each streaming its own log output.

## Snapshots & live memory

- **Snapshots**: the snapshot modal (VM detail) has an **"Include memory (live
  snapshot)"** checkbox — when set, the revert resumes the running VM at the exact
  snapshot instant; otherwise it's disk-only. The snapshot list shows a TYPE
  (disk/memory) column.
- **Memory balloon**: for a VM with a max-memory ceiling, the Memory card on the VM
  detail page shows an inline setter to change the live balloon target (within the
  configured min/max).

## Notifications

The **Notifications** page (Observability nav) manages alerting **targets**
(webhook / Slack) and **routes** (event-pattern + min-severity → target), with a
per-target **Test** button that sends a live test notification. Mirrors the
`lv notify` CLI; writes are CRDT-replicated. See
[notifications.md](notifications.md).

## Resource Mappings

The **Resource Mappings** page (admin nav) manages cluster-wide aliases for
equivalent passthrough devices: create a mapping, then add one device per host
(host + PCI address + optional vendor/device). VMs reference a mapping by name so
they can run on / migrate to any host registered under it. CRDT-replicated; mirrors
the `lv mapping` CLI.

## VM Backup & Restore

- **Backup**: VM detail page → "Backup" opens a modal that takes a snapshot backup
  into a backup repo. It includes a **"Skip in-guest fs-freeze"** option;
  by default a VM with a guest agent is frozen briefly for an application-consistent
  backup.
- **Restore**: each backup listed on the VM detail page or the `/backups` page has
  "Restore" (materialize the disk from the backup, `RestoreFromBackup`) and "Live
  restore" (boot against it while it streams in, `RestoreLive`).
- **Promote replica**: VM detail page → "Promote replica" opens a modal to bring the VM up from its newest replica (disaster recovery). Options: new name (take over vs. alongside), explicit pool/host, force (split-brain override), and a fast overlay mode. Drives the `PromoteReplica` stream and redirects to the recovered VM. Replication schedules (incremental + auto-promote toggles) are managed under `/schedules`.

## Boot Order

Configure VM boot order (disk, CD-ROM, network/PXE) from the VM edit modal.

## Dashboard

Cluster dashboard at `/` with:

- Summary cards (hosts active/total, VMs running/total, CPU/memory/disk utilization bars)
- Per-host resource table with CPU, memory, and disk progress bars (color-coded: green <70%, yellow <90%, red ≥90%)
- Recent VMs table
- Cluster events and active alerts
- Auto-refreshes every 5 seconds

## Storage Page

Storage pool inventory at `/storage`:

- All pools across all hosts with driver badge (local/nfs/ceph/iscsi)
- Per-pool capacity bar and used/total
- Pool state (active/error), create/delete pool
- Auto-refreshes every 10 seconds

### Content browser + ISO upload

The VM-create **Browse…** button opens the ISO picker. Its top half is
`ListISOs`: every ISO the caller may name on the host, as `pool/file.iso`, its
projects' libraries first and then the global library (with each file's sync
state when the library is in sync mode). Below it, a content browser lists the
files in any file-based pool — `ListStoragePoolContents`, forwarded to the
pool's owning host. Picking a `.iso` there fills in its `pool/file.iso`
reference, or **upload** a file straight into the pool: the browser streams it
to `UploadStoragePoolContent` (1 MiB chunks; written to a temp file then
published without replacing anything already at the name) so nobody needs to
`scp` ISOs onto hosts. Only image-like names are accepted; see
[storage.md](storage.md#uploads). The global library takes uploads from an
Admin only; a project library (a pool the project owns with `content=iso`)
from the project's operators.

## Load Balancer Management

Full LB lifecycle from the UI:

- **Create**: Multi-section form (name, VIP, algorithm, ports, backends, host selection). Dynamic rows for ports and backends.
- **Edit**: Pre-populated form from current LB config. Modify VIP, algorithm, add/remove backends.
- **Backend control**: Per-backend enable/disable/drain buttons on the LB detail page.

## Health Timeline

Unified health view at `/health` combining:

- **Health matrix**: Host-to-host health grid (observer × target) with colored status dots (green=healthy, yellow=suspect, red=failed)
- **Active alerts**: Severity-badged alert list from cluster status
- **Recent events**: Audit log timeline with timestamps, actions, targets, and usernames
- Auto-refreshes every 5 seconds

## Network Topology

Visual network topology at `/topology` showing:

- Each network as a section with type badge (bridge=blue, vxlan=purple, isolated=green, sriov=orange)
- Network metadata (subnet, gateway, VNI)
- Connected VMs displayed as clickable cards with IP addresses

## Cluster Diagnostics

State health inspection at `/diagnostics`:

- Per-table row count and hash display
- Drift detection (consistent vs drifted state)
- "Force Sync" button to kick an immediate anti-entropy pass on the connected
  host, the same as `lv cluster converge` (the UI never reads the state dump —
  see [Who can read the state dump](auth.md#who-can-read-the-state-dump))
- Auto-refreshes every 10 seconds

## Mass Operations

The VMs and Hosts list pages have a checkbox column. Selecting any rows
reveals a sticky toolbar with bulk actions:

- **VMs**: start, stop, restart, delete (with confirmation).
- **Hosts**: drain, undrain.
- **Containers**: start, stop, delete.

Bulk actions fan-out concurrently (bounded at 8 in flight) and surface a
per-row partial-failure dialog if any operation fails — the failures don't
stop other rows from completing. Master-checkbox in the table header
selects/deselects the visible rows. The list's 5s auto-refresh pauses while a
selection is active so it doesn't clear your checkboxes mid-selection.

A drain — from the host page or the bulk toolbar — answers once the daemon
confirms it, or after 10 seconds if the daemon has not reported yet. The first
report comes only once the first VM has migrated, so a host with a large VM
usually answers "Drain started … (no progress reported yet)"; the drain keeps
running on the server either way, and a refusal that arrives within those 10
seconds is shown as a failure. Follow the drain on the host page.

## Containers

`/containers` lists cluster-wide LXC/OCI workloads with full lifecycle from the
UI: **Create** (download-template distro/release/arch, CPU/memory, bridge),
per-row **Start/Stop/Delete** and **Exec** (a one-shot command modal), plus the
bulk toolbar above. Requires the LXC userspace tools on the target host.
Containers are a lightweight, host-local workload — migration, snapshots,
backup, clone, tags, and load-balancing are VM-only.

## Rebalance Proposals

The cluster page links to a rebalance section that shows pending placement-
engine proposals. Each row shows source host → target host, expected score
gain percentage, the VM's resolved policy, and per-row approve / reject
buttons. The rebalancer runs every 60 s on the leader-elected daemon;
proposals expire if neither approved nor applied within 30 minutes.
See [placement.md](placement.md) for the policy/mode matrix.

## Global Search

Keyboard-accessible search bar in the navigation. Searches across all resource types (VMs, hosts, networks, stacks, images, load balancers) by name substring match. Results appear in a dropdown with categorized links. Debounced at 300ms.

## Image Operations

- **Build from VM**: Create an image from an existing VM. Available from the images page.
- **Push to Host**: Push an image to a specific host. Available from the images page.

## Stack Export

Download a stack's compose YAML as a file. Available from the stack detail page via an "Export YAML" button.

## Stack Destroy

"Destroy" on the stack detail page waits for the whole teardown and then
reports it: "destroyed" only when every VM, container and network was removed,
otherwise a "not fully destroyed" error naming each resource that was not (the
stack stays `deleting` and the daemon retries the teardown). The wait has no
time limit — a large stack can take minutes — and the teardown runs on the
server whatever the browser does: navigating away or closing the tab loses only
the toast, not the teardown.

## Host Upgrade

Upload a new litevirt binary to upgrade a host. Available from the host detail page via an "Upgrade" button. Features upload progress tracking and automatic daemon restart.

The upgrade flow runs `PreflightUpgrade` first; if any blocking findings
(active migrations, pending fences, replication backlog, clock skew, witness-
host risk) are detected, the upload is refused unless the operator explicitly
overrides. The host transitions to state `upgrading` before re-exec so peer
coordinators don't fence it during the restart window. If the new binary
panic-loops past the systemd `StartLimitBurst` threshold, the
`litevirt-rollback.service` companion unit automatically restores the
previous binary. See [upgrades.md](upgrades.md) for the full upgrade-safety
contract.

## Page index

The full set of routes mounted by `internal/ui/server.go`:

| Path | What |
|---|---|
| `/` | Cluster dashboard |
| `/hosts`, `/hosts/{name}` | Host list + detail |
| `/vms`, `/vms/{name}` | VM list + detail |
| `/stacks`, `/stacks/{name}` | Compose stack list + detail |
| `/networks` | Network list |
| `/lb`, `/lb/{name}` | Load-balancer list + detail |
| `/images` | Image inventory |
| `/events` | Cluster Events — recent operation history (vm_events) seeded server-side + a live SSE tail prepending new events. (`/activity` redirects here.) |
| `/audit` | Audit log (filterable by `?target=…&action=…`) |
| `/users` | User and token management |
| `/account/2fa` | Per-user TOTP + WebAuthn enrolment |
| `/storage` | Storage pool inventory |
| `/storage/ceph` | Ceph health + CRUSH tree (read-only) |
| `/security-groups` | Security-group definitions + NIC bindings |
| `/firewall` | Cluster/host-tier firewall rules, ipsets, and default-deny policy |
| `/notifications` | Alerting targets (webhook/Slack) + routes |
| `/resource-mappings` | Cluster-wide passthrough-device alias management (needs `resourcemap.read` at `/`, so a project-scoped grant gets 403) |
| `/containers` | Cluster-wide LXC/OCI containers + lifecycle |
| `/backups` | Backup repos and snapshot manifests |
| `/schedules` | Backup **and replication** schedules |
| `/rebalance` | Pending rebalance proposals (approve / reject) |
| `/rbac` | Path-rooted role-binding tree. An admin sees every binding; anyone else sees only the bindings that name them, as with `lv role ls` |
| `/projects` | Tenancy: project tree, quotas, and usage |
| `/dashboards` | Bundled Grafana JSON dashboards (download links) |
| `/metrics-viewer` | Embedded Prometheus scrape, grouped by metric family |
| `/health` | Health matrix + active alerts + audit timeline |
| `/topology` | Network topology graph |
| `/diagnostics` | Per-table state hash + drift detection |
| `/pci` | PCI topology and device assignments |

## Keyboard + theme

- **⌘K / Ctrl-K** (or `/`) opens a command palette: fuzzy-matches every page
  client-side and folds in live resource hits via `/ui/search`; arrow keys move,
  Enter opens.
- `g` + key navigation: `g d` = dashboard, `g h` = hosts, `g v` = vms,
  `g s` = stacks, `g c` = containers, `g n` = networks, `g l` = LBs,
  `g i` = images, `g b` = backups, `g e` = events.
- Theme toggle in the navbar (sun/moon icon); persists in localStorage.

## Themed confirmation dialogs

Destructive actions (`hx-confirm`) are intercepted at the global `htmx:confirm`
event and rendered as an in-theme modal (Enter confirms, Esc/backdrop cancels;
the confirm button is danger-styled for deletes) instead of the browser's
native `confirm()`.

## Console & VNC

Each running VM exposes two in-app consoles from its detail page:

- **Terminal** — the guest serial console (xterm.js over a WebSocket bridged to
  the daemon's `ConsoleVM` stream).
- **VNC** — the graphical console (noVNC over `ProxyVNC`). Opens in an in-app
  modal; "Full screen" opens the standalone viewer in a new tab.

Both work across hosts: if the VM runs on a different host than the one serving
the UI, the daemon forwards the stream to the owning host. When a session can't
start, the console shows the **reason**
and a **Retry** button:

| Message | Cause / fix |
| --- | --- |
| `VM "x" is not running` | Start the VM first. |
| `VNC is not enabled for VM "x"` | The VM was created headless (`--disable-vnc` / `disable_vnc: true`). Recreate or edit the VM with VNC enabled. |
| `serial console not available for VM "x"` | No serial/pty device in the domain. |
| `host <h> unreachable: …` | The host running the VM is down or unreachable. Check the host's state and network. |

**Blank terminal on a running VM** is a different condition: the WebSocket
connects (no error banner) but nothing prints. The guest most likely has no
login getty on `ttyS0` — press Enter, or enable `serial-getty@ttyS0` in the
guest. The console modal shows this hint in its footer.
