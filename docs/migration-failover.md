# Migration & Failover

## Live migration

Move a running VM to another host with near-zero downtime:

```bash
lv migrate my-vm host-b
```

litevirt uses QEMU's pre-copy memory migration:

1. **Validating** — checks VM state, target host capacity, storage compatibility
2. **Preparing** — sets up target host (network, disks)
3. **Copying** — iterates dirty memory pages to target
4. **Converging** — auto-converge reduces page dirtying rate if needed
5. **Cutover** — brief pause, final state transfer, VM resumes on target
6. **Completing** — updates cluster state, cleans up source

Progress is streamed to the CLI in real-time.

### Requirements

- VM must be in `running` state
- Target host must be `active` and have sufficient resources
- All disks must be on shared storage (NFS/Ceph/iSCSI), OR use `with-storage: true`
- PCI passthrough devices block live migration (hot-detach first)
- The target's CPU must be able to run the guest (see below)

### CPU compatibility

A guest whose CPU is derived from its host — `cpu-mode: host-model` (the create
default) or `host-passthrough` — may be executing instructions the destination
host does not have. litevirt checks this **before** provisioning anything on the
target: the source reads the guest's CPU requirement from its live domain XML (for
a `host-model` guest libvirt has already expanded that to a concrete model plus
feature list; for `host-passthrough` the requirement is the source host's own CPU)
and asks the target host whether it can satisfy it.

A target that positively cannot refuses the migration up front:

```
target host "..." cannot run VM "...": its CPU does not provide what the guest is
running on (cpu_mode=host-model, verdict=incompatible)
```

Migrate to a host with an equal-or-newer CPU, or stop the VM and pin a baseline
both hosts support with `lv update <vm> --cpu-mode custom --cpu-model <model>`.

The check is deliberately advisory in one direction only. It refuses **only** on a
positive "cannot run" from the target; a target that cannot answer — a peer
mid-rolling-upgrade that does not have the check yet, or one whose libvirt is
briefly unhappy — is treated as *unverified*, not as incompatible, and the
migration proceeds to libvirt's own check at cutover. A VM with an empty
`cpu_mode` (QEMU's `qemu64`, identical on every host — see
[`lv doctor cpu-mode`](diagnostics.md)) is not checked at all.

A **cold** move is not checked either: a stopped VM migrated with `--cold`, a
Secure Boot / vTPM VM, and a running VM that `lv host drain` moves cold (it has a
host-local disk) all boot fresh on the target, where `host-model` and
`host-passthrough` expand to the target's own CPU. Moving such a VM to a host of
another CPU generation is therefore allowed; a target that cannot run the guest's
machine type still refuses it when the domain is defined there.

### Migration with local disks

For VMs whose disks are on local (non-shared) pools, the disk content is
copied to the target during migration. Pass `--with-storage` on the CLI for a
**live** migration:

```bash
lv migrate my-vm host-b --with-storage
```

The disk is streamed to the target over libvirt's block-copy / NBD channel
while the VM keeps running; the source is undefined after a successful cutover.

**Encryption.** This copy cannot be tunnelled through libvirt's TLS connection,
because QEMU opens its own migration stream and disk copy to the target. litevirt
encrypts those (libvirt's `VIR_MIGRATE_TLS`) when **both** hosts hold
migration-TLS credentials:

- They come from a **separate migration CA**, never the cluster CA. QEMU reads
  them inside its own unprivileged process, and a guest that escapes into QEMU
  must not get the node's cluster identity.
- `lv host init` and `lv host add` issue them. On an older cluster, run
  `lv host install-migration-tls` once from the machine that holds the cluster CA.
- The migration CA lives only on the machine that minted it. `lv host add` and
  `lv host install-migration-tls` refuse to mint a second one while a cluster
  host already holds credentials: certificates from it would not verify against
  the first, and every storage migration with the new host would fail its TLS
  handshake. Copy `migration-ca.crt` and `migration-ca.key` (mode 0600) from the
  machine that holds them, or run the command there.
- Each daemon installs its host's credentials into `/etc/pki/qemu`, with the key
  readable only by the QEMU user, at start and again before each storage
  migration, so no restart is needed. It refuses to touch `/etc/pki/qemu` if
  that directory already holds files litevirt did not put there.

If either host has no credentials, the copy would cross the network in
plaintext, and the source refuses it unless its config sets
`migration.allow_unencrypted_storage: true` (see
[configuration](configuration.md#migration)). Set that only where the network
between hosts is trusted. Migrations of VMs on shared storage are tunnelled over
libvirt's TLS and need neither.

Only the host-local disks (`local` and `dir` pools) are copied. A disk on
shared storage (NFS, Ceph, iSCSI, a volume manager) is already the same disk on
the target, so it stays where it is; copying it would mirror the disk onto
itself. A VM with no host-local disk is migrated without a storage copy, even
with `--with-storage`.

Before the copy, the source checks each disk against its record and the target
creates an empty file for each disk to be copied into. The migration is refused,
before anything is copied, when:

- a disk's size differs from its recorded size. Make the disk and its record
  agree first.
- the target already has a file at a disk's path that this migration did not
  create, for example a copy of the VM's disk left from an earlier stay on that
  host. Copying onto it would overwrite it. The error names the file and the
  host. Check whether the file is still needed, move it aside or remove it, then
  migrate again.
- the target cannot create the files at all.

If a copy fails, the target removes only the files it created for that attempt.
It decides that from its own record, whatever the source asks it to remove.

You can also set it as a per-VM default in compose:

```yaml
# In compose
    migrate:
      with-storage: true
```

## Cold migration

`--cold` migrates a VM without moving a running guest live:

```bash
lv stop my-vm
lv migrate my-vm host-b --cold
```

A **stopped** VM moves stopped. Libvirt is not involved, because there is no
guest running for it to migrate:

1. Each host-local disk (`local` and `dir` storage) is copied to the same path
   on the target over the cluster's mTLS connection. Disks on shared storage
   stay where they are. A disk's format is read from the VM's domain
   definition, never from the file. A qcow2 disk created from an image or as a
   linked clone is an overlay over a backing file. It arrives flattened, as a
   standalone image, because the backing file is not part of the copy. A raw
   disk is copied byte for byte.
2. The VM's domain is defined on the target, shut off.
3. The VM and all of its disk records move to the target in one transaction.
   The VM's state stays `stopped`. Start it there with `lv start my-vm`.
4. After that commit, the source undefines its domain and removes its copy of
   each disk it sent.

Until the commit in step 3 the source keeps its disks, its domain and
ownership of the VM. If any step before it fails, or the client goes away,
the VM stays on the source, stopped. The target removes the disk copies and
the domain that this attempt created there, and nothing else. A file the target
already has at a disk's path, which this migration did not create, is refused
rather than overwritten, as for `--with-storage`.

A stopped VM is refused when:

- libvirt reports its domain active, although its record says stopped;
- a disk is not in its domain definition, so its format is unknown;
- a filesystem would be left with less free space than 5% of its size, with a
  minimum of 1 GiB and a maximum of 64 GiB. The target checks this for each
  disk it receives, and the source checks it before flattening an overlay. The
  disks on a host's filesystem are thin-provisioned, and a full filesystem
  pauses every guest writing to one. The check counts the data a copy actually
  writes, not the disk's apparent or virtual size: a sparse disk stays sparse
  on the target, and a flatten writes only allocated clusters. The target checks
  its free space again as the data arrives;
- a disk file is larger than its recorded size allows, plus qcow2 metadata;
- it has snapshots and a host-local disk;
- it holds a PCI passthrough device;
- the target is a build from before stopped-VM cold migration. The error says
  so and names the target to upgrade.

A copy in flight writes to a hidden scratch file beside the disk:
`.<disk>.receiving-<number>` on the target, or `.<disk>.coldmig-<uuid>` (and
`.<disk>.coldmig-<uuid>.tmp`) on the source while it flattens an overlay. A
daemon that stops mid-copy removes files of exactly these shapes from its
host-local disk directories when it next starts. Any other file is left alone.

`--with-storage` has no effect on a stopped VM, whose host-local disks are
always copied.

A **running** VM given `--cold` is paused for the move instead of migrated
live. Libvirt still migrates it, so a host-local disk needs `--with-storage`,
or stop the VM first. A stopped VM migrated live is refused, with a message
pointing to `--cold`.

Secure Boot / vTPM VMs are always migrated stopped and cold. Their host-local
disks are copied as any stopped VM's are, and their firmware state (UEFI vars
and vTPM) is carried with them; see [cli-reference.md](cli-reference.md).

## Host drain

Evacuate all VMs from a host before maintenance:

```bash
lv host drain host-a
lv host drain host-a --parallel 4    # Migrate 4 VMs at a time
```

Drain live-migrates a running VM whose disks are all on shared storage. Every
other VM moves the way `lv migrate <vm> <target> --cold` moves a stopped VM
(see [Cold migration](#cold-migration)): its host-local disks (`local` and
`dir` storage) are copied to the target, its domain is defined there, and the
VM and its disk records move in one transaction. It is refused for the same
reasons. A Secure Boot / vTPM VM drains only while stopped, with its
host-local disks and its firmware; a running one is reported with the commands
to stop it and move it.

- A **stopped** VM stays stopped on the target.
- A **running** VM with a host-local disk is checked first, while it still
  runs: everything the cold move checks, including the target's capacity, a
  disk whose backing image cannot be flattened, free space on both hosts, and
  a file already at a disk's path on the target. Only then is it shut down.
  Drain waits for its domain to shut off, up to the VM's stop timeout
  (`stop_timeout_sec`, 30 seconds by default), and does not force it off. It
  is then moved with its disks and started on the target.
- A running VM on shared storage whose live migration fails is moved the same
  way.

A VM that drain cannot move stays on the host with its disks; a failed attempt
removes what it put on the target. It is never moved without its disks:

- refused before the shutdown, it keeps running;
- a move that fails after the shutdown starts it again on the host, once its
  domain has shut off. A guest slower than its stop timeout is waited for, up
  to 5 more minutes; the ACPI shutdown request cannot be withdrawn, so the VM
  is started again only after the guest has powered off. A guest still running
  after that is reported as an error that says so: its shutdown was requested
  and it is still running, and it will power off if the guest completes the
  shutdown. Start it then, as below;
- if the start fails, drain reports it as an error naming the VM, which is
  then stopped on the host.

`lv start` is refused on a host while it is `draining` (see below), so a VM
left stopped there is started with `lv host undrain <host>` and then
`lv start <vm>`, or moved off with `lv migrate <vm> <target-host> --cold` and
started on its new host.

The move of a running VM is journaled before anything is done to it (an
operation of kind `drain_cold_move`). If the drained host's daemon dies in the
middle, it finishes the move when it starts again, and the VM ends running on
exactly one host: on the drained host if it had not been handed over yet
(started again, or its record put back to running if its domain never stopped),
or on the target if it had. It does so only while the VM is still exactly as
the drain left it: owned by the same host at the same owner epoch, and stopped
by the drain itself (its state detail then reads `drain-cold-move:<operation>`,
which counts as an operator stop everywhere). A VM started, stopped, moved or
deleted since is left as it is, and a VM event says the move was not finished.
A move that still cannot be finished after about ten minutes of retries is
closed as failed, with a VM event naming the VM and how to start it; a later
restart does not take it up again.

Drain reports each VM it did not move with the reason, finishes the other VMs,
and then fails with `drain incomplete: N VM(s) remain on host ...`. The host
stays `draining`. Fix what the message names and run the drain again: a drain
of a host that is already `draining` moves what is left. You can also move a
VM off yourself with `lv migrate`. A VM that moved but did not start on the target is
reported too, with a VM event saying why; it is stopped there, and the drain
also ends with `drain incomplete`, naming it.

A drain needs the drained host to hold quorum, as every move does (the
split-brain gate, `split_brain_gate_v1`, which latches on every cluster).
Once the host is `draining`, the gate lets through only what takes VMs away
from it: the drain's moves, live or cold, an `lv migrate` of a VM off the
host, and starting again a VM whose cold move failed after the drain shut it
down. Anything else that would run a VM there is refused with
`local_not_active_worker`, as on any host that is not `active`: `lv start`
of a VM on it, for one. On a host that is `draining` or in `maintenance`,
`lv start` and `lv restart` add the host's state and what to do: undrain it
first (`lv host undrain <host>`), or, on a `draining` host, move the VM off
with `lv migrate <vm> <target-host> --cold` (after `lv stop <vm>`, for a
running one) and start it there. A host in `maintenance` lets no VM leave it
either: a migration off it is refused, naming the state and
`lv host undrain <host>`, as are a replica promote, a container restore and a
load-balancer apply there. A migration onto it is refused because its target is
not `active`. A VM moved by a drain is started on its target, which is
`active`.

### A VM with no domain

A drain by a build from before this behaviour moved a stopped VM by its record
alone: the record names the new host, but the domain was never defined there
and its host-local disk files stayed on the host it came from. Such a VM
cannot be drained or migrated cold again; both refuse with `VM "<vm>" has no
domain defined on <host>`. Its host-local disk files are still on the host it
came from, at the paths `lv inspect <vm>` lists. To recover it, copy them to
the same paths on the host its record names and recreate the VM there over
them, or `lv rm <vm> --keep-disks` to remove the record without touching any
disk file. A VM with only shared disks lost nothing but its domain.

When done:

```bash
# Perform maintenance...
lv host undrain host-a
```

## Health checking

### Host health

Hosts probe each other via TLS connection to the gRPC port (7443) every 2 seconds. Results are stored in the `host_health` table.

A voter probes every host that is not in `maintenance`. A non-voter probes
every voter plus three other non-voters (its successors in name order), so
every host is observed by every voter, which is whose rows the fence and
recovery quorums count. A non-voter's view of a peer it does not probe is
taken by probing it on demand wherever a decision reads "is this host down".
With today's voter set every host that is not `offline`, `maintenance` or
`fenced` votes, so the probe mesh is still full.

A host transitions to `suspect` after 3 consecutive probe failures. The failover coordinator takes action after quorum confirmation.

Rows are written on **transition**, not on every probe, so a steadily healthy
peer costs no replication traffic. The one exception is a host in `offline` or
`fenced`: its healthy row is rewritten every 10 seconds even when nothing has
changed, because auto-recovery only counts rows younger than 30 seconds and a
recovered host produces no further transitions to write one. Without that
heartbeat a host that genuinely came back would sit `offline` until someone ran
`lv host undrain` by hand. The heartbeat is deliberately limited to those two
states — rewriting every healthy row on a timer would be N*(N-1) writes per
interval across the cluster, for a reader that only ever looks at hosts
awaiting recovery.

#### An observer that stopped running is not a witness

A failed probe counts against the peer only if the observer was running while it
waited for the answer. A host that suspends, swaps out or starves the node
running litevirt stops the whole daemon. The node's clocks keep moving (inside a
VM they follow the hypervisor), so each probe the node had in flight runs out its
deadline without the daemon ever waiting for a reply. The probe reports
"unreachable" about a peer that answered the whole time. If every observer runs
on one overloaded host, they can all build up failures against a live peer at
the same moment and reach fencing quorum.

Each health checker therefore runs a heartbeat that measures only its own
scheduling. It beats every 250 ms. A gap between beats longer than the 2 s probe
interval means this node was not running for that long. The gap is measured on
both the monotonic and the wall clock, because on bare metal the monotonic clock
does not advance across a system suspend. After a gap:

- **The failure count this node had built against every peer is discarded.** A
  verdict against a peer is made only of probes attempted after the node resumed.
  The probe that straddled the gap is never one of them.
- **For the stall grace window, an unreachable probe is not counted.** The window
  is the time a normal fence verdict takes to build — 5 failed probes at the 2 s
  probe interval, 10 s — and it is derived from those two numbers, not tuned
  separately, so it moves with them. There is no setting for it. No
  row is written for it, so a previously published `suspect` row is not refreshed
  and ages out of fencing quorum's 30 s freshness window. A successful probe still
  counts, and so does a peer's explicit not-ready answer.
- **This node's failover coordinator decides no new fence for the same window.** It
  logs `quorum reached, but this node was itself not running moments ago` and
  counts `litevirt_failover_attempts_total{phase="skip",error_class="local_stall"}`.
  Resuming a recovery from a fence that is already recorded is not a new decision,
  and it is not held back.

**Seeing it.** The node records an `observer_stalled` condition about itself for
the length of the window — `lv health` lists it, and `lv doctor fence` names the
node with how long it was paused and until when its votes are withheld. See
[Diagnostics](diagnostics.md#observer-stalled-observer_stalled).

A host that really is dead is still fenced. After a stall its observers need the
grace window plus the usual 5 failed probes, about 20 s from resume instead of
about 10 s. That bound holds once the observer has stayed running through it. An
observer that stalls again and again keeps withholding its vote, and while it
does so it does not count toward fencing.

The guard does not cover a **peer** that stalls. To every observer that kept
running, a peer that answers no probe for about 10 s cannot be told apart from a
dead one, and it is fenced as a dead host would be. That is the case fencing exists
for: the peer may come back with its workloads still running. Pausing an entire
cluster at once and resuming it does not fence anything, with or without the
guard. Rows written before the pause are stale against the resumed clocks, and
no failure is counted for time that merely passed. What the guard adds is that
failure debt from before the pause, together with a probe caught by the pause,
cannot add up to a quorum.

Clock skew between hosts is also monitored — warnings are logged if skew exceeds 1 second.

### VM health

VMs with a `healthcheck` defined in their compose spec are periodically checked:

```yaml
    healthcheck:
      type: "http"                # tcp | http | exec
      target: "http://localhost:8080/health"
      interval: "10s"
      timeout: "5s"
      retries: 3
      action: "restart"           # restart | migrate | alert
```

| Type | What it checks |
|------|----------------|
| `http` | HTTP GET, healthy if 2xx/3xx status |
| `tcp` | TCP connection succeeds |
| `exec` | Command exits 0 via guest agent |

**Correlated failure detection:** If 3+ VMs fail health checks simultaneously, litevirt suppresses automatic restarts (likely a shared dependency failure, not individual VM issues). A VM whose next action is still held back by its action backoff does not count toward the 3 — it has already been acted on — and a suppressed action is not counted toward the VM's backoff, so once the event is over the first failed probe acts without a backoff built up during it.

**The verdict is cluster state.** The owning host publishes each VM's verdict — `healthy`, `unhealthy` or `unknown` — whenever it changes, bound to the VM's current incarnation. That is what compose `vm_healthy` waits for, what `lv inspect` shows, and what `lv health` lists as `vm_probe_failing` (info severity). When the owner goes down nobody is left to retract a pass, so readers treat any verdict from an `offline`, `fenced` or `maintenance` owner as `unknown`; after failover the VM is a new incarnation on its new host and needs a fresh pass there. The action (`restart` / `migrate` / `alert`) is unchanged, and still waits out the first 5 minutes after a VM is created. See [Diagnostics](diagnostics.md#vm-probe-failing-vm_probe_failing).

## Automatic failover

When a host goes offline, the failover coordinator:

1. **Detects failure** — quorum of observers must agree the host is unreachable (floor(n/2) + 1). Only fresh observations count: a `host_health` row older than 30s, or dated more than 30s ahead of the coordinator's own clock (a skewed observer), is not evidence. Both halves of that count come from one **voter set**. Until the cluster has a voter generation it is derived: every host not removed from the cluster whose state is not `offline`, `maintenance` or `fenced` (witnesses, `draining` and `upgrading` hosts vote). Once automatic genesis has run it is the adopted generation's members, whatever their state — a fenced member keeps counting until `lv cluster voter rm` removes it (see [Operating model](operating-model.md) → "The voter set is explicit once genesis has run"). n is the size of that set, and an observation counts only if its observer is in it and is not the host being judged — a fenced host that is still running, a removed host whose daemon was never stopped, or a name no host carries cannot supply a vote. Bringing a host back to `active` counts the same way. It is the same set `DecisionGate` counts its locally-probed quorum over, and if the coordinator cannot read it, it does not fence
2. **Acquires leader lease** — suppresses concurrent coordinators (45s TTL lease; a fence needs 30s of it still to run before it may begin). Best-effort, not exclusive: a CRDT lease can be held on both sides of a partition, so the decide site also requires a locally-probed quorum (`DecisionGate`) and the minority side fails closed there. See [Operating model](operating-model.md) → "Leader-gated recovery". A node taking over the lease first confirms with a quorum of peers that none of them has already recorded the term it is about to claim, so a node that has just restarted or reconnected waits until replication catches it up (one health-probe cycle after a start, then until any newer term row arrives) instead of claiming from its stale view. See [Operating model](operating-model.md) → "A node that was away does not claim a term from a stale ledger".
3. **Fences the failed host** — prevents split-brain by ensuring the failed host cannot access shared resources
4. **Claims the recovery** — with `enforcement.recovery_claim` on every host (the default; see *Recovery claims* below), a majority of the voter set certifies one destination per workload before any proof is minted, so two coordinators that both believe they lead cannot both recover it
5. **Reschedules VMs** — based on each VM's `on-host-failure` policy. A VM
   stopped on purpose is never started; see *Stopped workloads* below

### Fencing methods

| Method | How it works |
|--------|-------------|
| `ipmi` | Power cycle via IPMI/BMC (requires `ipmi_address`, `ipmi_user`, `ipmi_pass` on host). Verified post-fence by polling `chassis power status`. |
| `ssh` | Forced, immediate power-off over SSH: `systemctl poweroff --force --force`, falling back to `echo o > /proc/sysrq-trigger`. Not a graceful shutdown — no units are stopped, so `libvirt-guests` does not get to shut guests down cleanly first; the host stops now, as if its power were pulled. The session dies with the host, and that is reported as success only when the remote shell had already confirmed it was issuing the power-off. Reports failure if the host is unreachable or both power-off commands fail. |
| `watchdog` | Local watchdog self-fence (the host writes its own watchdog timer dead). Requires `watchdog_dev` in config. When `watchdog_dev` is set the daemon validates the device at startup and refuses to start if it's absent, so a broken watchdog is caught before it's needed rather than at fence time (override: `LITEVIRT_UNSAFE_SKIP_WATCHDOG_CHECK=1`). On a graceful daemon shutdown the watchdog is disarmed only when this host owns no running VMs or containers; while it owns any, the device stays armed — a restarting daemon resumes petting well inside the timeout, and a daemon stopped for good with workloads left behind lets the watchdog reboot the host into a safely fenced state. Drain (or `lv host shutdown-workloads`) before planned maintenance. |
| `manual` | Coordinator does NOT auto-reschedule; operator must run `lv host fence-confirm <host>` after physically powering it off. Required when shared storage would corrupt under split-brain. |
| `best-effort` | Tries the same forced SSH power-off as `ssh`; succeeds regardless. Used in homelabs / single-tenant clusters that explicitly opt out of split-brain protection. |

Configure per-host:

```bash
lv host config host-b \
  --fence-strategy ipmi \
  --ipmi-address 10.0.50.111 \
  --ipmi-user admin \
  --ipmi-pass <secret>
```

An empty `--ipmi-*` flag leaves the setting alone. To remove a host's IPMI
address, user and password, use `--clear-ipmi`; a host that fences by `ipmi`
needs another strategy in the same command, since it would have nothing to
authenticate with:

```bash
lv host config host-b --fence-strategy ssh --clear-ipmi
```

The clear writes both copies of the password, the `host_fence_credentials`
row and the old `hosts.ipmi_pass` column, so it is refused until
`credentials_split_v1` has latched on the node that takes it. A server that
predates the flag ignores it; the CLI reports an error when the host it gets
back still has an IPMI address.

### Manual fence confirmation flow

Under `manual` strategy, the failover coordinator records the failure but
refuses to reschedule VMs until an operator confirms the host is genuinely
powered off:

```bash
# Quorum has detected host-b unreachable. VMs on host-b are NOT
# automatically restarted yet (which would be split-brain on shared NFS).
# Operator powers off host-b out of band, then:
lv host fence-confirm host-b
# Next coordinator cycle reschedules the VMs.
```

The coordinator marks the host `fenced` once `lv host fence-confirm`
records a `manual-confirmed` row in `fencing_log`. This gate prevents
the coordinator from rescheduling a manually-fenced host's VMs before
an operator has actually confirmed the fence.

### Shared-disk fence gating (host-fence-gated shared storage)

A VM whose disk lives on **shared** storage (NFS/Ceph/RBD/iSCSI) is a special
split-brain hazard: the same bytes are writable from any host, so starting the VM
on a second host while the original owner may still be writing corrupts the disk.
A local-disk replica is a *different* image, so promoting it carries no such hazard.

When `enforcement.shared_storage_fence` is enabled (and the cluster has latched the
`shared_storage_fence_v1` capability), an **ownership transfer** — auto-promote or
reschedule — of a VM with a writable shared disk starts only once the old owner is
**proven powered off**:

- Accepted: a confirmed power-off (`ipmi`), or an operator `lv host fence-confirm`
  (`manual-confirmed`).
- Rejected: a `best-effort`/`ssh` fence — a lenient SSH poweroff reports success but
  never confirms the host is down.

The proof is bound to the specific fence in the failover proof's `fence_epoch`, and
the executing host re-verifies it against the append-only `fencing_log` (never a
stale `fenced` host state). If the proof reference hasn't replicated to the executor
yet the transfer retries on the next cycle; a missing or non-proof-grade fence is
refused with the `storage_unverified` reason.

Enforcement is fail-closed at **both** ends. The coordinator refuses to *create* a
shared-disk transfer at the source when it has no proof-grade fence (a best-effort
fence yields an empty `fence_epoch`), so a target that is a mixed-rollout laggard
(has the capability but not yet the config flag) or a regressed binary can never
receive an *unfenced* shared-disk transfer. When a proof-grade fence does exist the
owner is provably powered off, so the transfer is safe even if the target hasn't
enabled the flag. The executor re-verifies as defense-in-depth.

This is **host-fence-gated shared storage, not storage-level exclusivity** — litevirt
does not (yet) take storage-side locks (RBD blocklist, iSCSI PR keys). It is a
config kill-switch (`enforcement.shared_storage_fence`) plus the capability latch, so
an UPGRADE is behavior-neutral until the flag is enabled fleet-uniformly, and disabling
it turns the fence gate off. The flag is false when absent — but a cluster created
with `lv host init` starts with it on, because there is no prior behavior to preserve
and the unguarded outcome is two hosts writing one disk. Hosts joining an existing
cluster inherit that cluster's setting, never this default.

**Requiring a verified fence, per host.** By default a successful SSH fence is
enough for the coordinator that ran it to reschedule the host's local-disk VMs.
An SSH success only means a shell accepted a forced power-off; nothing checks the
host went down. To refuse that on a particular host:

```bash
lv host label set <host> litevirt.fence_requires_confirmation=true
```

With the label, a fence that did not **verify** the power-off — `ssh`, and
`best-effort` in both its forms — does not reschedule anything, and it does not
record the host as `fenced`; it is left `offline`. (Once `fence_state_v1` has
latched, no unverified fence records `fenced`, label or not — see
[What a fence records](#what-a-fence-records).) An IPMI fence, which does
verify, is unaffected. The fence's assurance is shown by `lv doctor fence` and
`lv host fence` (see [Diagnostics](diagnostics.md)).

It is a label rather than a config flag because only one place acts on it — the
coordinator creating the recovery — so no peer needs to honour it, and a
coordinator on an older binary ignores it and acts as if it were absent. Roll
the binary out before relying on it.

**Getting past the refusal.** Confirm the host is powered off, then run
`lv host fence-confirm <host>`. The coordinator resumes the recovery on its next
cycle — see [Resuming a recovery from a confirmation](#resuming-a-recovery-from-a-confirmation).

### What a fence records

A fence writes a `fencing_log` row and, when it succeeds, the host's state, in
one replicated entry. The state says what the fence **proved**:

| Fence | Host state |
|---|---|
| `ipmi`, powered off and observed off | `fenced` |
| `ssh`, `watchdog`, or `best-effort` that succeeded | `offline` once `fence_state_v1` has latched; `fenced` before |
| any fence that failed | `offline` |
| `lv host fence-confirm` | `fenced` |

`fenced` is the cluster's statement that the host is **off**, and only a
verified power-off or an operator's confirmation makes it
(colonelpanik/litevirt#253). An SSH success means a shell accepted a forced
power-off; nothing looked afterwards. Such a fence keeps every bit of the
authority it had: the coordinator that ran it reschedules on it (subject to the
safe-fence policy and `litevirt.fence_requires_confirmation`), a successor
resumes from it (below), and the host is not put back in service behind the
workloads that moved off it — it is `offline`, and a host whose newest fence
succeeded is treated exactly like a `fenced` one: only `lv host undrain` brings
it back, unless the coordinator that fenced it moved nothing off it.

Before `fence_state_v1` latches — while any host the cluster replicates to,
a `maintenance` host included, runs an older build — an unverified fence still
records `fenced`, because an older successor resumes only from that state.
Nothing that takes a host to be **off** reads the state alone, on any build of
this release: owner-assert, `lv host rm --dead`, the voter-loss condition and
late-replica matching each require the host's newest fence to be proof-grade,
so a `fenced` state an older leader wrote for an SSH fence is not taken as
proof.

### Resuming a recovery from a recorded fence

A leader can fence a host and then stop before it moves the host's workloads:
its lease runs out mid-fence, or it dies. The fence is already recorded — a
`fencing_log` row and the state it records — and whichever coordinator holds
the lease next takes the recovery over from that record. It needs:

1. **The host is still recorded `fenced` or `offline`.** `lv host undrain`
   records it `active`, which ends the fence's authority. So does the host's
   own daemon starting up again, but that write can be lost (a failed startup
   write, or a last-writer-wins loss under clock skew), so nothing below
   relies on it.
2. **The newest fence attempt succeeded.** That covers a verified `ipmi`
   power-off and an `ssh` or `best-effort` success. A host left `offline` by a
   failed fence has a failed newest attempt and is not resumed from. The
   resumed recovery passes the same safe-fence policy and
   `litevirt.fence_requires_confirmation` check the leader's would have.

What happens next depends on the fence:

- **A verified (`ipmi`) fence** is resumed from directly only while it is under
  5 minutes old **and** still stands (below). Otherwise the successor powers the
  host off again with the recorded method first. A verified power-off of a host
  that is already off is harmless, and a fresh one is authority on its own,
  whatever happened to the host in between. The recovery then proceeds on the
  fresh fence, and a shared-disk VM is bound to it. If the re-fence fails,
  nothing is recovered. The failed attempt is now the newest on record, so the
  host is not re-fenced every cycle; it is left `offline` for an operator,
  counted as `phase=recovery, error_class=refence_failed` and raised as the
  `refence_failed` health condition. Confirm it is off and run
  `lv host fence-confirm <host>`, and the recovery resumes from the
  confirmation.
- **An unverified (`ssh`, `best-effort`) fence** is resumed from directly while
  it still stands, and never re-fenced: an SSH power-off of a host that is
  already off cannot connect and reports a failed fence. A fence that no longer
  stands is logged once, as "the recorded fence of this host no longer stands",
  and the workloads stay where they are. If the host really is down,
  `lv host undrain <host>` lets the coordinator fence it again for the outage in
  progress.

**A fence still stands** when some observer has probed the host and failed
without a break since before the fence, and no observer's latest verdict shows
the host answering (healthy or unready) since. The first holds however recent
the fence is. A genuine fence follows a quorum of failing runs, so it always has
one. A host that answered after its fence and then failed again has had the
verdict that it answered overwritten, and only the failing runs' start shows the
return.

**When a failing run started** is read from the verdict: an observer's failing
`host_health` row carries the time of its run's first failed probe in
`last_seen`. A verdict from an older build carries none, and its run is taken to
span one probe interval (2 s) per failure, a lower bound: a probe of a
powered-off host runs out its dial timeout, so its runs advance more slowly, and
the bound puts their start later than it was. It never counts an earlier outage
as this one, but it can refuse a fence or confirmation made minutes into a long
outage until an observer on the current build reports the host.

**Clock skew.** The fence's time is the leader's clock and each observation is
its observer's, so both comparisons give 5 seconds, the clock-skew alert
threshold, to the safe side. A failing run must have begun at least 5 seconds
before the fence, and an answer counts from 5 seconds before it. Greater skew
makes the checks refuse more, except in one direction: an observer whose clock
runs more than 5 seconds **behind** the leader's can make a run look older than
it is. Keep `litevirt_cluster_clock_skew_seconds` under 5 (see
[Time](operating-model.md#time)). For a verified fence the margin matters less,
because the successor re-fences whenever there is doubt.

The resumed recovery applies the same safe-fence policy and the same label as
the leader would have, so a host whose recovery needs `lv host fence-confirm`
still needs it. The safe-fence policy is decided by the recorded fence, not by
the host's current strategy: an `ssh` fence on record is treated as best-effort
under the policy, even if the host has since been switched to `ipmi`.

The `fencing_log` row and the state it records are written as one replicated
entry, so every peer holds both or neither. A leader on an older release writes
them separately, and a successor can then hold the row while the host still
reads `active`. It treats that as "the state has not arrived yet": it neither
fences the host nor stops looking, and it resumes once the state lands. If that
older leader died between its two writes, the state never arrives. The host is
then fenced again once the row is 5 minutes old, as before.

A shared-disk VM is still moved only on a proof-grade fence under 5 minutes old
(see above), which a resume from a verified fence always has: a fresh one when
the recorded one was older.

**A fence row belongs to the host's life it was written in.** A `fencing_log`
row older than the moment the host last turned `active` (its own boot write,
or a recovery) is about an earlier life: the machine removed under the name
before `lv host add` gave it to a new one, or the same machine before it booted
again. Such a row does not make the host "recently fenced", does not confirm
it off, and is not the proof-grade fence a shared-disk VM is moved on. A host
that fails again after coming back is fenced anew, without waiting out the
5 minutes. A row newer than the host's last activation still counts, which is
the race the window exists for. Likewise, a health observation older than the
moment a host turned active does not count toward fencing it: a host that just
turned active is counted down afresh, and a host `lv host add` admitted is not
probed at all until its daemon's first boot records it `active`.

The same holds for the proof-grade fence `lv host rm --dead` rests on, which
counts at any age, and for the one a lost voter's removal and a superseded
claim rest on. A proof-grade row from before the host was last recorded as it
is now — admitted (`joining`), booted (`active`), lost unfenced (`offline`),
drained — is about an earlier life and does not count, so a machine `lv host
add` put under a removed host's name is not removed on the old machine's
confirmation: `lv host fence-confirm` it once it is powered off. A host
recorded `fenced` is exempt, since that write is itself its fence. Rows within
5 seconds of the state write still count, for the clock between them.

### Resuming a recovery from a confirmation

A recovery refused for want of a confirmation — a `manual` fence, a
`best-effort` fence under the safe-fence policy, or a host labelled
`litevirt.fence_requires_confirmation` — resumes once an operator runs
`lv host fence-confirm <host>`.

The resume requires four things, not the confirmation alone:

1. **The cluster itself fenced the host** — a `fencing_log` row with result
   `fenced` or `partial`, which only a fence that ran writes.
2. **That fence belongs to this outage.** It is either under 5 minutes old, or
   some observer has probed the host and failed without a break since before
   it — so the host has not been seen up at any point after the fence. A fence
   from an earlier outage the host has since recovered from authorises nothing,
   and the coordinator logs "the newest fence attempt predates this outage".
3. **The confirmation is newer than that fence**, so it attests to this outage
   and not an earlier one.
4. **The host is still down now** — a fresh quorum observes it failing. A host
   that has come back, or that an operator has put into `maintenance`, is never
   resumed.

An observer's unbroken run of failed probes restarts when that observer's
daemon restarts, so after every observer has restarted a genuine confirmation
of an older fence is refused too. Run `lv host undrain <host>`: the coordinator
then fences the host for the outage in progress, refuses for want of a
confirmation, and resumes once you confirm again.

`fence-confirm` has no precondition and runs no fence, so on its own a mistyped
hostname could otherwise authorise a recovery. With all three required, a
mistype can only reach a host the cluster already fenced and still sees down.

**A confirmation before any fence of this outage fences the host afresh.**
`fence-confirm` records the host `fenced`, and a host recorded terminal is not
fenced by the coordinator. A confirmation written before the cluster fenced
the host for the outage in progress therefore used to leave it where nothing
would ever fence or recover it. That order is not a mistake you can always
avoid: `lv cluster voter force-reconfigure` requires a confirmation of every
lost host, and with a majority of the voters gone no fence quorum can form to
fence them first. Now, when all of these hold:

- the host is `fenced` or `offline` (never `maintenance`) and a fresh quorum
  observes it down;
- no fence attempt is at or after the confirmation, and no earlier attempt
  belongs to this outage;
- the confirmation belongs to this outage: some observer has probed the host
  and failed without a break since at least 5 seconds before it,

the coordinator fences the host itself, as it would an `active` one, and logs
"an operator confirmed this host off during the outage in progress, and no
fence has run for it; fencing it afresh" (`phase=recovery,
error_class=confirmation_fence`). The confirmation authorises that fence, not
the recovery: the recovery follows from the fresh fence under every gate a
fence applies, and where one of them needs a confirmation (`manual`,
`best-effort` under the safe-fence policy, the confirmation label) it accepts
one under 5 minutes old. An older one leaves the host `offline` after the fence
with the usual refusal in the log; confirm again and the recovery resumes from
it. A confirmation older than the outage, of a host that has answered since,
still authorises nothing, and the coordinator logs "the newest fence attempt
and the confirmation both predate this outage".

Outside that flow, **confirm after the fence, not before**: wait for the refusal
in the coordinator log, then confirm.

**The failover leader resumes it.** Every coordinator reads the same
`fencing_log`, but only the one holding the failover lease acts on it. The check
is the same one fencing uses, run once per cycle and again for each host before
anything is decided. A coordinator that is not the leader does nothing and does
not spend the confirmation. If the leader that refused the recovery dies before
the confirmation arrives, the coordinator that takes over the lease finds the
confirmation in `fencing_log` and resumes the recovery. The lease is best-effort,
not exclusive (see
[Leader-gated recovery](operating-model.md#ha--failover)). If two
coordinators each believe they hold it, both can resume, just as both can fence.

The resume also takes the decision gate, like every other ownership decision: a
coordinator without quorum refuses, and does not spend the confirmation, so the
resume happens once quorum returns. One confirmation resumes one recovery. It is
counted as `phase=recovery, error_class=confirmation_resumed`. A shared-disk VM
still needs a proof-grade fence reference, which a confirmation under 5 minutes
old provides; a resume long after the confirmation (a daemon restart hours
later) moves local-disk VMs and refuses shared-disk ones, which is the safe
direction.

**Per-host implication:** a host whose fence strategy is `best-effort`/`ssh`/`manual`
(anything but `ipmi`) gives its shared-disk VMs *manual-confirm-only* automated
failover once this is enforced. `lv host inspect <host>` prints a note when a host's
fence strategy can't prove a power-off. Give shared-disk hosts an IPMI fence strategy,
or expect to run `lv host fence-confirm` for their failover.

Local-disk VMs are unaffected: their transfers keep the existing quorum/proof gate
(a `best-effort` fence is sufficient — no shared-write hazard).

### Recovery claims (single-winner recovery)

The leader lease cannot stop two coordinators that both believe they hold it,
and each could otherwise mint a valid proof for its own destination: two
writable owners of one VM (colonelpanik/litevirt#250). With
`enforcement.recovery_claim` on for **every** host (witnesses included; it
defaults on, so a config without the key counts) and the `recovery_claim_v1`
token latched, a recovery is a claim decided by the explicit voter set before
anything is minted ([design/recovery-claims.md](design/recovery-claims.md)).
The token latches by itself once every host advertises it — by default on
this build, only with an explicit `true` on an older one — and enforcement
starts once voter genesis has run (docs/upgrades.md). A host rolled back to an
older build after the latch is not WAL-quarantined and reads a missing key as
false, so write the key explicitly before a rollback. An explicit
`enforcement.recovery_claim: false` on every host is the stand-down:

- **Claim before mint.** After the fence, the coordinator proposes the
  reschedule, promote or container-relocate proof it would mint as the value of
  a claim keyed by the workload, its owner epoch and an attempt number, and
  writes a proof only once a majority of voters has signed an accept for one
  value — its own, or another coordinator's, which it writes instead, with the
  other destination. A claim that forms no certificate mints nothing and is
  retried on the next tick. A promote is claimed once the replica's host is
  known; a container relocation takes one decision for both the restore and
  its image-recreate fallback.
- **Verify before execute.** The destination starts a recovered workload only
  with a certificate that verifies against its own adopted voter set and the
  cluster CA; otherwise it refuses with `recovery_claim_unproven` and the row
  stays pending. It asks no voter to decide.
- **The owner probe.** Each voter probes the workload's recorded owner itself
  before it accepts, and refuses with `recovery_claim_owner_reachable` if it can
  reach it; a voter whose settled row names a different owner refuses with
  `recovery_claim_source_mismatch`. A host most voters can still reach is never
  certified evicted, whatever the coordinator's own health view says. The
  coordinator retries such a claim at the same round.
- **A destination that dies before it acts** strands the recovery: no other
  destination may be authorized while it might come back and execute its
  certificate. `ha.claim.stranded` names the workload and the command. If the
  destination is gone for good, fence it proof-grade and run
  `lv host rm --dead <host>` (try `--dry-run` first): the voters then accept
  "fenced, removed and revoked" as evidence and the recovery retries at the
  next attempt. A promote that fails before `StartDomain` is abandoned by its
  destination, which signs that it never started it, and the coordinator's
  fallback reschedule moves on with that evidence.
- **Diagnosis.** `lv cluster claim vm/<name>` shows every voter's promised and
  accepted ballot, the value's destination and source, and its last refusal.

Enforcement needs the flag, the latch **and** an adopted voter generation
(`lv cluster voter ls`). The token is advertised only while the flag is on, so a
latched token means every host opted in. Standing down is the flag off on every
host and a restart; a host with the flag off while others enforce is the
uncertified second owner the claims exist to prevent — it reports
`recovery_claim_v1` in `PingResponse.not_enforcing`, and its peers raise
`ha_degraded`. See [Operating model](operating-model.md) → "Recovery is a
decided claim when recovery claims are enforced".

### Witness hosts (even-N quorum)

For 2-node or 4-node deployments, add a vote-only witness host to break
ties cleanly:

```bash
lv host config witness-1 --role witness
```

Witnesses participate in failover quorum but never run workloads. The
placement engine refuses to schedule any VM onto them. See
[operating-model.md](operating-model.md) for sizing guidance.

Without a witness, a cluster left with exactly two voting-eligible workers
refuses every failover decision with `missing_witness`, **unless a voter
generation is adopted** (`lv cluster voter ls`). Without one, the voter set is
derived from host state, which one side of a split can shrink, so neither side
may decide. With one, the generation's majority decides. Two voters each see
one of two on either side of a split, which is below a majority, so both sides
are refused `no_quorum`. So a three-voter cluster that has lost and fenced one
host recovers its workloads, and so do the two survivors of
`lv cluster voter force-reconfigure`.

### VM failure policies

Set in compose `migrate` section:

```yaml
    migrate:
      on-host-failure: "restart-any"
```

| Policy | Behavior |
|--------|----------|
| `restart-any` | Restart on any available healthy host |
| `restart-same` | With any host-local disk: wait for the original host, which starts it there on its real disk when it is back. With every disk on shared storage: restart on any available healthy host, like `restart-any`, on its real disks |
| `none` | Do not reschedule |

A policy applies to every VM on the failed host except a stopped one, which
is never started by failover: see *Stopped workloads* below.

A `restart-same` VM with a host-local disk is not restarted anywhere else,
because that would start it on a disk rebuilt blank from its image. It stays
on its host, and failover records why: the condition `vm_failover_held`
(subject `vm/<name>@<host>`, a warning), a `vm.failover.held` event, a
`failover.skip` audit entry and a `vm.disk.stranded` notification, each naming
the host and what you can do. When the host is back and active, it starts the
VM on its real disk (the domain a power-off fence leaves shut off there is
started, not recorded stopped), and the record clears. A host comes back
`fenced` when failover moved any other workload off it: run
`lv host undrain <host>`. A removed host does not block this: adding the
machine back under its name (`lv host add`) brings the held VM back with it.
If the host is gone for good, its data is gone with it: promote a replica if
there is one (`lv replication promote <vm>`), or remove the host first
(`lv host rm --dead <host>`, try `--dry-run`) and then the VM (`lv rm <vm>`),
and create it again; `lv rm` cannot reach a VM on a host that is fenced but
not removed. The coordinator decides the hold once per fence, so changing the
policy afterwards takes effect only at the next failover decision for that
host. There is no
command that moves it elsewhere onto a blank disk. It counts in the failover metrics with error class `held_for_host`. Before this
release a `restart-same` VM was restarted on any healthy host whatever its
disks, because the original host is never available while it is fenced.

A VM with a local disk that is restarted on another host does not get its disk
back, because the disk stayed on the failed host. The new host rebuilds the disk
from the VM's image at the disk's recorded size. That is the cost
`restart-any` accepts for a local disk (`lv compose` warns about it when it
plans such a VM); a VM whose data matters more than its uptime has no failure
policy (`none`) and waits for its host. The new host might still have an old
copy of the disk from an earlier stay there. The restart never boots that
copy. It renames the copy to `<disk path>.superseded-<time>` next to the new
disk. Each failover rebuilds the disk from the image, so each copy holds its
own data and not an older version of the current disk.

#### The real disk a restart leaves behind

The restart is not silent, and the real disk is not lost:

- The coordinator records the disk it left on the failed host: the condition
  `vm_disk_stranded` (subject `vm/<name>@<host>`, a warning, see
  [diagnostics](diagnostics.md)), a `vm.failover.disk_stranded` event in the
  VM's history, a `failover.disk-stranded` audit entry and a
  `vm.disk.stranded` notification. `lv inspect <vm>` lists it under
  `strandedDisks`, with the host and the path.
- When the failed host is back, it renames the disk to
  `<disk path>.superseded-<time>`, so nothing that later moves the VM onto that
  host can take its place, and records the new name (`lv inspect` shows it as
  `copy`). It does this only for a host the record names, while the VM's
  record names another host, and never under a domain of that name that is
  running there or holds a saved state.
- An old copy that a restart sets aside, as above, is recorded the same way on
  the host that holds it.

A copy is retained while the VM it came from exists, in any state: the host
never removes it on its own. While that VM is in `error`, `pending` or
`starting` it is also held, because a restart that failed may need it put
back. Once the VM is deleted, its copies are removed by their host when they
are older than `superseded_disk_retention_days` (default 7 days; `0` keeps
every copy). The host checks hourly; the age comes from the time in the file
name. Before this rule a copy was held only while its VM was in `error`,
`pending` or `starting`, so seven days after the VM was running again on a
rebuilt disk the only copy of its data from before the failover was deleted.

To see the copies on a host, with the VM each came from, when it was set aside
and whether it is retained or held, run `lv host superseded-disks <host>`.
These need the admin role and are audited:

- `--purge` removes every copy that is neither retained nor held, whatever its
  age; `--older-than <duration>` narrows it (`host.superseded_disks.purge`).
- `--remove <copy>` removes exactly the named copy, retained or not, never a
  held one; repeat it to name more (`host.superseded_disks.remove`).
- `--restore <copy>` puts the copy back as its VM's disk
  (`host.superseded_disks.restore`). The VM must be stopped on that host. The
  file it replaces is not deleted: it is set aside and retained in turn.

To run a VM on the real disk a failover left on a host, once that host is
back:

```bash
lv host undrain <host>               # it comes back fenced; a migration onto it needs it active
lv stop <vm>
lv migrate <vm> <host> --cold        # the stopped VM moves there with its current disk
lv host superseded-disks <host>      # find the copy
lv host superseded-disks <host> --restore <copy>
lv start <vm>
```

The disk the VM ran on since the failover is kept beside it as another copy;
remove it with `--remove` once it is not needed. The check finds copies next to
the disk paths the cluster records and in the data directory's `disks/` folder.

During a rolling upgrade a host on the previous release keeps copies by the
old rule, from the VM's state alone; nothing this release writes changes a
VM's state, so it removes nothing it would not have removed before. Two
consequences follow. A failed host that comes back on the previous release
does not set the real disk aside, so a cold migration back onto it is refused
on the occupied path: rename the file there to
`<disk path>.superseded-<time>` yourself (never delete it), or upgrade the host
first. And a later failover back onto a host on the previous release sets the
disk aside by the old rule, and that host's sweep removes it after
`superseded_disk_retention_days`: upgrade a host before it takes failovers
back. Ask a host
on this release for `--remove` and `--restore`: a host on the previous release
answers with the listing and removes nothing, and the command says so.

Containers are not on this path. A container relocated off a failed host is
recreated from its image (or restored from a backup) on another host, and its
own container directory stays on the failed host: nothing sets it aside or
removes it automatically, and a relocation back onto that host adopts it. It
is recorded the same way, though: the coordinator raises `ct_rootfs_stranded`
(evaluator `ct_rootfs`, subject `container/<name>@<host>`, a warning), writes a
`failover.rootfs-stranded` audit entry and sends a `ct.rootfs.stranded`
notification; the host, once back, adds the rootfs path; `lv ct inspect <name>`
shows it ("Left on <host>"). A relocation back onto that host that adopts the
old rootfs writes a `ct.relocate.adopted` audit entry saying the container runs
on that data, not a fresh image, and the record clears.

The restart of a VM on its own host never rebuilds a missing disk. That case
is `vm_disk_missing` in [diagnostics](diagnostics.md).

### Stopped workloads

Failover recovers what was running. A VM **stopped on purpose** is never
started by failover, as in a drain: it is not rescheduled, promoted from a
replica or restarted anywhere, whatever its `on-host-failure` policy or
auto-promote enrolment says.

A stop is on purpose unless the VM's record says otherwise. `lv stop`
records `operator-stop`, and a drain records its own stop. A stop that nobody
asked for is recorded by the host that saw it: `guest-shutdown` (a clean
poweroff from inside the guest, which is also what a host shutting down
produces), `out-of-band-destroy`, or `stopped out-of-band` (also what `lv ls`
records when it finds a VM shut off that the record says is running). These
are written only while the record still says running, so a stop recorded by
`lv stop` is never replaced by one of them. A stopped VM with any other
record, or none, counts as stopped on purpose.

What failover does with a stopped VM on a failed host:

| The VM | Its disks | Failover |
|---|---|---|
| stopped on purpose | all on shared storage | moves it to a healthy host, still stopped; that host defines its domain, shut off, and `lv start` starts it there. Only when the VM has a failure policy or auto-promote enrolment, no Secure Boot / vTPM state and no ownership dispute, and, while `enforcement.shared_storage_fence` is on, the failed host has a proof-grade fence. Otherwise it is left on the failed host |
| stopped on purpose | any host-local disk | leaves it on the failed host with its disks |
| stopped without anyone asking | all on shared storage | recovers it like a running VM, on its real disks |
| stopped without anyone asking | any host-local disk | leaves it on the failed host with its disks |

With recovery claims on (the default), the move is claimed like a recovery,
so two coordinators that both believe they lead agree on one destination, and
it advances the VM's ownership generation as a completed recovery does, so the
VM's next failover is claimed afresh. Without them, two coordinators can move
it to two hosts; the VM's record ends naming one, that host defines it, and
the other removes the definition it made. One case is not covered with claims
off: if an operator starts the VM on one of the two hosts before the other
move has reached it, the hosts' records can disagree about where the VM is,
and that is not repaired automatically. Leave recovery claims on, or wait
until `lv inspect <vm>` shows the same host from every node before starting
it.

While the host defines the domain it holds the VM's start lease, and an
`lv start` that arrives meanwhile is refused with a message to retry. The move keeps its marker (`failover-rekey-stopped:<host>`) on the VM
until it is started, and the host the record names defines the domain afresh
from the VM's current spec, never reusing an older definition it finds.

During a rolling upgrade, a VM moved this way onto a host still running the
previous release cannot be started there until that host is upgraded: the
older release does not define it. It stays stopped and safe meanwhile.

A VM left on the failed host is exactly as it was when the host comes back:
start it there with `lv start`. A stopped container is always left in place
and is not relocated.

Restarting a VM that has a host-local disk somewhere else costs the VM its
data until an operator puts it back. The new host rebuilds the disk blank from
the image, and the real disk stays on the failed host, recorded and kept (see
*The real disk a restart leaves behind* above). A running VM's failure policy
accepts that cost; a stopped VM's never does.

The rule is enforced twice. The coordinator decides a stopped VM before
anything else, before auto-promote. Its write then re-reads the VM's state in
the same transaction and refuses a VM stopped on purpose, so a stop that lands
while the coordinator is deciding still wins. Each VM left in place gets a
`failover.skip` audit entry and a `vm.failover.skipped` event (a container,
`ct.failover.skipped`) naming it and why. A VM moved still stopped gets a
`failover.rekey-stopped` audit entry and a `vm.failover.rekeyed` event. A
VM's event is also kept in its event history. Both count in the failover
metrics with error class `stopped`. A VM left in place is not counted as
stranded, because failover would not move it.

`lv host rm --dead` on a host that still holds a stopped workload lists it in
the plan, with the choices for its data. Removing the host does not move a
stopped VM with a host-local disk; one stopped on purpose on shared storage
may still be moved, stopped, by the pass that recovers a removed host's
workloads, and the plan says so. The removal is not refused. A stopped workload does not block the name
either: if the machine is added again under its name (`lv host add`), the
workload comes back with it. Another way to keep the data is to promote a
replica onto a live host (`lv replication promote <vm>`). If the data is lost
for good, remove the workload (`lv rm <vm>`, `lv ct rm <name> --host <host>`)
and create it again.

## Containers

**Cold migration** — `lv ct migrate <name> <target> --repo <dir>` moves a
container to another host by reusing the backup→restore transport (stop →
archive → restore on target → restart if it was running). The source archives
into `--repo` locally and **streams the manifest to the target over peer mTLS**
(into a per-transfer staging repo), so `--repo` does not need to be reachable
from both hosts. If the target predates peer streaming it falls back to
re-opening `--repo` by name, which then must be shared. No live/CRIU migration.

**Host-loss relocation** — when a host is fenced, the failover coordinator
relocates its containers that carry an `on_host_failure` policy (set with
`lv ct create --on-host-failure image-recreate`) onto a placement-chosen healthy
host, preferring the most faithful option: **restore from the latest backup**
(`ct.relocate.restored` — preserves networking + non-image state, when a
reachable repo holds a valid manifest and the survivor is schema-compatible),
falling back to **recreate from image** (`ct.relocate.recreate` — managed NICs
reconstructed from the persisted create spec), and finally **skip** a container
that's neither restorable nor re-pullable (`ct.relocate.skipped`, left visible for
operator recovery). A **stopped** container is not relocated: it stays on the
failed host, stopped (see [Stopped workloads](#stopped-workloads)). The restore path is idempotent + crash-recoverable (source
marker `relocate-restore:<target>:<token>`, where the attempt token is stamped on
the restored target row so the coordinator only completes the handoff against a
row proven to be its own restore; `container_restore_timeout_sec`). See
[containers.md](containers.md#host-loss-relocation).

## Monitoring

### Prometheus metrics

Scrape `http://<host>:7444/metrics` for:

> That endpoint has **no authentication and no TLS**, and `metrics_bind`
> defaults to all interfaces. Scraping it across a network means the cluster
> inventory and this node's hardening posture are readable by anything that can
> reach the port — see
> [configuration.md → Metrics endpoint exposure](configuration.md#metrics-endpoint-exposure).


- `litevirt_host_cpu_total`, `litevirt_host_memory_total_mib` — host resources
- `litevirt_host_vm_count` — VMs per host
- `litevirt_vm_state` — `1` if the VM is running, `0` otherwise
- `litevirt_migration_duration_seconds` — histogram of migration end-to-end wall time (labels: `strategy`, `result`)
- `litevirt_migration_downtime_ms` — histogram of guest-visible downtime during the cutover
- `litevirt_fence_failures_total` — cumulative non-success rows in `fencing_log`; pages should fire on any non-zero increase
- `litevirt_failover_leader` — `1` on the host currently holding the failover lease, `0` elsewhere
- `litevirt_failover_attempts_total{phase,result,error_class}` — failover decision points, counted by
  `phase` (`lease`, `quorum`, `health-query`, `skip`, `fence`, `split-brain-guard`, `recovery`,
  and `claim` for a recovery claim, whose results are `ok`, `lost`, `no_majority`,
  `owner_reachable`, `source_mismatch` and `superseded`),
  `result` (`ok`/`skipped`/`success`/`partial`/`refused`/`error`/`recovered`), and a bounded
  `error_class` (e.g. `no_quorum`, `upgrading`, `already_fenced`, `no_candidates`, `manual_unconfirmed`,
  `db_error`, `fence_log_write_failed`, `recovery_resumed`, `refence_failed`, `confirmation_resumed`,
  `confirmation_fence` (a host confirmed off during this outage, fenced afresh), `local_stall`,
  `joining` (a host `lv host add` admitted whose daemon has not started, never fenced),
  `partition_pause_wait` (recovery waiting out a partitioned host's pause, design/partition-pause.md),
  `quorum_regain` (a fence deferred because this node itself regained the voter majority moments ago),
  and under region-scoped failover `region_too_small` / `region_scoped` — see
  [federation.md](federation.md#region-scoped-failover)). A skip is `result=skipped` with the reason in `error_class`
- `litevirt_failover_vm_actions_total{action,result,error_class}` — per-VM failover actions
  (`action` = `promote`/`reschedule`)
- `litevirt_failover_container_actions_total{action,result,error_class}` — per-container failover actions
  (`action` = `relocate`)
- `litevirt_failover_stranded_workloads` — GAUGE: workloads still assigned to a host in state
  `fenced`/`offline` that failover would move off a dead host. This node's view, so it reads `0`
  unless the node holds the failover lease — alert on `max()` across instances, never `avg()`.
  Zero is normal; the remedy for a sustained non-zero depends on why the host is down (see
  [operating-model.md](operating-model.md))
- `litevirt_failover_regions_without_quorum` — GAUGE: under region-scoped failover
  (`lv cluster failover-scope region`), the regions that hold at least one worker but have fewer
  than three voters, so cannot fence one of their own hosts. The lease holder's view, like the
  gauge above; always `0` under the default cluster scope
- `litevirt_peer_healthy` — `1` if a peer host is reachable, `0` otherwise (one series per peer)
- `litevirt_hlc_rejected_total` — count of remote HLC timestamps clamped due to clock skew
- `litevirt_replication_min_watermark_seq` — minimum `last_seq` across recently-acked peers; a value that stops advancing means some peer has stopped acknowledging. It is not the compaction floor: the prune additionally skips peers whose pushes are currently failing, so it can reclaim past a seq this gauge still sits on
- `litevirt_mutation_log_rows` — total rows in `mutation_log`; coupled with the watermark above this gives backlog visibility
- `litevirt_replication_pending_entries` — `mutation_log` entries written but not yet acknowledged by the slowest **live** peer (`MAX(seq) − MIN(live last_seq)`); reads `0` when there are no live peers. A sustained climb means one peer is falling behind even though replication itself is healthy
- `litevirt_replication_backlog_age_seconds` — how long the oldest entry the slowest **live** peer has not acknowledged has been waiting on this node; `0` when caught up or when there are no live peers. **The one to alert on.** `pending_entries` measures volume, which is the wrong quantity for a threshold — a thousand entries a second behind is healthy, three entries an hour behind is a peer that has stopped acknowledging. The age is measured on this hop: a relay's forwarded entries are stamped when they land in the relay's log
- `litevirt_replication_peer_pending_entries` — per-peer backlog (`MAX(seq) − peer last_seq`), one series per live peer; a single series climbing while the others stay flat pinpoints the lagging peer. The daemon also logs a warning when a peer stays maxed-out for several rounds

### Event stream

```bash
lv events                  # Stream all events
lv events --type vm        # Filter by type
```

### Cluster status

```bash
lv status                  # JSON cluster summary
lv top                     # Live dashboard
```
