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

Once a live migration completes, the target host sends gratuitous ARPs for the
gateway of each network the VM has a NIC on (the first address of the
network's IPv4 subnet), out of the bridge it serves that network on (after a
network move it refused, the previous one) and from that bridge's MAC, when it
holds that address there, the network is not on a VLAN and the bridge has
no uplink. It needs no `arping`.

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
Secure Boot / vTPM VM moved cold, and a running VM that `lv host drain` moves cold (it has a
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
- Before the copy, the source compares the fingerprint of the migration CA its
  credentials chain to with the target's, and refuses a mismatch, naming both
  hosts and both fingerprints, instead of failing at the TLS handshake
  mid-copy. `migration.allow_unencrypted_storage` does not excuse it. Reissue
  every host's credentials from one CA with
  `lv host install-migration-tls --reissue`. A target on an older build does
  not report its CA, and nothing is compared. A source that cannot read its
  own migration CA refuses the copy, naming the error and the same command.
- A host whose credentials cannot be used (a CA that is not a certificate or
  not a file, a host certificate the CA did not issue, a key that is not the
  certificate's, or an incomplete set: some but not all of `ca.crt`,
  `host.crt` and `host.key`) is not ready for migration TLS, and its daemon
  installs nothing for QEMU. A storage copy from or to it is refused before it
  starts, naming the host and why, whatever
  `migration.allow_unencrypted_storage` says. An incomplete set is usually a
  credential push in flight or cut short: let it finish, or re-run
  `lv host install-migration-tls`. A damaged set is replaced with
  `lv host install-migration-tls --reissue`. A target in that state refuses
  a storage copy that asks for TLS outright, so a source on an older build
  fails closed rather than falling back to plaintext. Every certificate of
  the CA file is read (an old and a new CA during a rotation), and an expired
  or not-yet-valid certificate counts as unusable. The source and the target
  compare their CA files as sets: a rotation bundle listed in another order on
  another host compares equal, and a CA listed twice counts once; hosts with
  different sets of CAs are refused as holding different migration CAs.
  During a rotation, a host that holds the old and the new CA and one that
  still holds only the old hold different sets: storage copies between them
  are refused, and memory-only moves stay in libvirt's tunnel. Storage copies
  work again once every host holds the same CA file: the same bundle on every
  host, or credentials reissued on every host from one CA with
  `lv host install-migration-tls --reissue`.
- Each daemon installs its host's credentials into `/etc/pki/qemu`, with the key
  readable only by the QEMU user, at start and again before each storage
  migration, so no restart is needed. It refuses to touch `/etc/pki/qemu` if
  that directory already holds files litevirt did not put there.

If either host has no credentials (none of the three files; an incomplete set
is not "no credentials" and is refused as above), the copy would cross the
network in plaintext, and the source refuses it unless its config sets
`migration.allow_unencrypted_storage: true` (see
[configuration](configuration.md#migration)). Set that only where the network
between hosts is trusted. Migrations of VMs on shared storage copy no disks, so
they need neither.

**Checking migration credentials.** `lv doctor migration-tls [--json]` asks
every host which migration CA(s) it trusts, which CA issued its certificate,
and when each expires — read-only, and non-zero on an unreachable host, an
install-blocking problem, an expiring credential, a plaintext fallback, or a
CA-set split across hosts with no rotation running from the operator machine.
Each host also warns in its own log 90 days before a migration credential
expires, whether or not anyone runs the doctor command.

**Rotating the migration CA.** `lv host rotate-migration-ca [--no-overlap]
[--force] [--ssh-user root]` replaces the migration CA on every host, run from
the machine that holds it. By default it walks three phases, checking every
host's daemon between them:

1. **trust-both** — every host trusts the old CA and the new one.
2. **reissue** — every host gets a certificate from the new CA.
3. **drop-old** — every host trusts the new CA alone; the operator machine
   retires the old one.

No host needs a restart. While trust-both or drop-old is being pushed, a
host already updated and one not yet updated hold different CA files, so a
storage copy between them is refused (never sent in plaintext) and a
memory-only move stays in libvirt's tunnel; once every host has the phase,
storage copies work again. Throughout reissue every host holds the same
two-CA file, so storage copies keep working.
Before it starts, the command asks every host's daemon for its migration
credentials and refuses, changing nothing, unless each holds a complete, valid
set its daemon can install, trusting this machine's migration CA. A host with
none needs `lv host install-migration-tls` first; one with an incomplete or
invalid set, `lv host install-migration-tls --reissue`. A host that cannot
answer refuses the start too, unless you pass `--force`.

If the command stops partway (a host is unreachable), its progress is saved
beside the CA; running it again resumes from where it left off rather than
starting over. That state lives in `pki_dir` alongside the current CA:
`migration-ca.next.crt` / `migration-ca.next.key` (the new CA, key mode 0600)
and `migration-ca.bundle.crt` (the two-certificate trust bundle pushed during
trust-both) exist only while a rotation is in progress;
`migration-rotation.json` (phase and per-host progress) remains after a
rotation finishes, recording the last one with phase `done`, and is
overwritten by the next rotation; and `migration-ca.retired-YYYYMMDD.crt`
(`-2`, `-3`, … for further rotations the same day) is the old CA certificate,
kept for audit once a rotation finishes; its key is deleted.

`--no-overlap` skips the overlap window entirely: it cuts every host straight
to the new CA alone in one pass. Use it only when the migration CA key is
compromised or the CA has already expired — there is no window where both CAs
are trusted, so migrations between a host already rotated and one not yet
rotated are refused, never sent in plaintext, until every host is done. `--force` leaves an unreachable host
behind instead of stopping the whole run; it keeps the old CA's credentials,
so migrations with it are refused until you run
`lv host install-migration-tls --reissue` once it is back.

If the migration CA has already expired, every host's credentials fail
validation, so storage migrations are refused until you run
`lv host rotate-migration-ca --no-overlap`. The overlapping rotation refuses
an expired CA, because hosts can no longer trust the old CA through the
overlap; `--no-overlap` accepts invalid or incomplete sets, since it replaces
all three files on every host, but still requires each host to answer, to have
credentials, and to trust this machine's migration CA. Reissuing first does
not help: `--reissue` issues from the same expired CA.

A rotation already in progress cannot switch to `--no-overlap`: re-run it the
way it was started and let it finish. If the key is found compromised during
an overlap rotation, finish that rotation, then immediately run
`lv host rotate-migration-ca --no-overlap`.

While a rotation is in progress, `lv host add` issues the new node's migration
credentials from the rotation's new CA. A run of `lv host rotate-migration-ca`
that is executing when a host joins stops at its next check, naming the host;
run it again and it brings that host through the remaining phases. Only one
run at a time: a second one on the same machine refuses. `lv host install-migration-tls`
refuses to run at all (reissuing from the old CA would hand out credentials
the rotation is retiring).

*If the migration CA key is compromised:*

1. `lv host rotate-migration-ca --no-overlap`
2. `lv doctor migration-tls` until it reports no problem other than ones
   you accept (for example, a host deliberately allowed to fall back to
   plaintext with `migration.allow_unencrypted_storage`, which keeps it
   non-zero)
3. For any host the rotation skipped, `lv host install-migration-tls
   --reissue` once it is back.

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

### A dedicated migration network

By default a live migration's data goes to the target host's cluster address,
the one its record names and peers dial. Set `migration.network` in the
source's config to move it onto another network, as Proxmox's
`migration: network=<CIDR>` does:

```yaml
migration:
  network: 10.20.0.0/24
  # address: 10.20.0.7          # this host's own address there, when it holds several
  # allow_any_network: false    # accept a network that is not private, or that holds the cluster address
```

The source asks the target, in the request that already prepares the move, for
the address of its own inside that network, and sends the data there. Set it on
every host that sends migrations, which is every host; nothing is stored in the
cluster, so a host with no address in the network is found out at the move, not
at start.

**What it carries.** A live move's guest memory, the disk blocks of a
`--with-storage` copy, and the disk stream of a cold move: a stopped VM's
`lv migrate --cold`, a drain's cold move and the copy of a clone made with
`--host`. The cold stream is the cluster's mTLS connection and is dialed at the
migration address. It is checked against the host certificate exactly as before,
so no certificate is reissued. Everything else (libvirt's control connection,
ownership commits) stays on the cluster address.

**Certificates.** The host certificate libvirt presents and the migration
certificate QEMU presents carry the host's cluster address as their only IP
name, so the network's address is in neither. The data channel goes to the
migration address while the certificate is still checked against the cluster
address (libvirt's `tls.destination`, gRPC's authority), which needs no new
trust.

**Encryption.** Nothing travels the migration network that a main build kept
off it in the clear:

- A memory-only move normally rides inside libvirt's tunnel on the cluster
  address. To use the migration network it leaves the tunnel for QEMU's own
  stream, which is used only when both hosts hold migration-TLS credentials
  (`lv host install-migration-tls`) from the same migration CA; otherwise the
  move stays in the tunnel. A target on an older build does not report its
  CA, and nothing is compared.
- A storage copy uses the network only when it is encrypted (migration TLS on
  both hosts). A copy you allowed unencrypted with
  `migration.allow_unencrypted_storage` stays on the cluster address, as it
  always did.

**Which address a target answers.** `migration.address` if you set one (inside
the network). Otherwise the lowest address inside the network that is not
loopback, link-local, a load-balancer VIP, or on a bridge litevirt made or a
libvirt, container or guest interface: a floating address would send one host's
data to another. Set `migration.address` where a host holds several.

**Which networks are accepted.** The daemon refuses to start with a network
that is not inside a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16),
or that contains this host's cluster address or its default-route source
address: such a network would send migration data out the uplink or the cluster
interface. `migration.allow_any_network: true` overrides both rules.

**Fallback.** A move falls back to the cluster address, and is never refused for
it, when the source has no address in the network (its data would leave by the
default route), the target has none, the target runs a build that predates the
setting, it answers with an address outside the network, a cold move's
migration address does not answer, or the move would be unencrypted. Each time
the source logs a warning and records a `vm.migrate.network_fallback` event on
the VM (`lv events <vm>`) naming the address used. The same applies to drain's
live moves. A live migration that was sent over the network and then cannot
connect (the migration ports 49152-49215 on the migration address must be
reachable from the source) fails; the fallback is decided before the move.

### Secure Boot / vTPM VMs

`lv migrate <vm> <host>` moves a running Secure Boot or vTPM VM live. Its UEFI
variables (NVRAM) and its vTPM state travel in the migration stream. The guest
arrives on the target paused and is resumed there only after the target's
vTPM state has been checked against the source's final copy and the VM's
ownership has moved to the target. The source's copy is deleted only after
that, and, for a UEFI VM, once the target's NVRAM equals the source's final
NVRAM.

**What the move needs.** Each item is checked when the move starts, on the
host it is about. A refusal names the item and ends with the cold move instead:
`lv stop <vm>`, then `lv migrate <vm> <host> --cold`.

- `migration.live_firmware` on both hosts (the default), and each host meets
  the conditions of the `litevirt.fw_live_migrate` label (see
  [configuration](configuration.md#migration)), read again at the move. The
  target must carry `litevirt.fw_live_migrate=true`, and `litevirt.tpm` /
  `litevirt.secureboot` as the VM needs.
- Equal firmware code on both hosts: the same libvirt, QEMU, swtpm and libtpms
  versions, the same OVMF layout and the same OVMF file content. On the source
  these are the versions the guest's running QEMU and swtpm processes were
  started from, not the installed packages: after QEMU, swtpm, libtpms or OVMF
  is upgraded on the source, the VM moves live again only after a restart
  (`lv stop <vm>`, `lv start <vm>`). The refusal names the first field that
  differs and both values. The source reads the guest's processes under
  `/proc`; a daemon that cannot (not root, or in another pid namespace) refuses.
- The guest runs. A guest paused by partition pause or by an operator is not
  moved live.
- The running vTPM keeps its state across the move (`persistent_state`). A VM
  defined by an older build is refused with `lv stop <vm>`, `lv start <vm>` to
  redefine it.
- No snapshot of the VM keeps a firmware sidecar. Remove those snapshots first
  (`lv snapshot rm <vm> <name>`).
- No live firmware move already names the VM on either host.
- A target on a build without live firmware migration refuses ("target
  <host> runs a build without live firmware migration"). Nothing is written
  there.

**Routes.** The disks decide how the move travels. `migration.network` is not
used for these moves.

| Disks | Move |
|---|---|
| all on shared storage | memory only, tunnelled through libvirt's TLS connection to the target's cluster address |
| all host-local | needs `--with-storage`: a storage copy to the target's cluster address, encrypted. Both hosts need migration-TLS credentials (`lv host install-migration-tls`); `migration.allow_unencrypted_storage` does not apply |
| shared and host-local | refused: move the host-local disks to shared storage, or migrate cold |

**While the move runs.** Each host keeps a record of it: the source under
`<data_dir>/fwmig-inflight/<vm>.json`, the target under
`<data_dir>/fwmig-hold/<vm>.json`. While a record names the VM on a host,
these are refused there with a `FailedPrecondition` naming the host, the
attempt, the other host and the phase: start, stop, restart, delete, rebuild,
update, disk resize, snapshot create and restore, clone (of the VM or to its
name), create or import under its name, backup, and an in-place backup
restore. Scheduled backups and replication skip the VM with a log line.
`lv host shutdown-workloads` reports the VM and goes on with the others. The
rebalancer, the health-check `migrate` action and `lv region migrate` never
move a Secure Boot / vTPM VM live. `lv events <vm>` shows the move's
`vm.migrate.firmware` events.

**After the move.** The source's firmware state is kept as
`<data_dir>/fwmig-retained/<vm>-<attempt>.tar` for 24 hours, then removed. If
the source cleanup stops, `firmware_migration_cleanup_failed` is raised and the
cleanup is retried.

**When a move fails.**

- Before the guest left the source: the target's state for the attempt is
  removed and the VM keeps running on the source. A target that already holds
  a domain that is not running has it discarded automatically.
- The target's vTPM state did not match, after the source's guest stopped for
  the migration: the target's copy is quarantined
  (`<data_dir>/fwmig-quarantine/<vm>-<attempt>/` on the target), and the VM is
  `stopped` on the source with its firmware state. `lv start <vm>` runs it
  there. `firmware_migration_unverified` is raised.
- The guest never arrived on the target: the VM is `stopped` on the source with
  its firmware state; `lv start <vm>`.
- The held guest's host went down after its state was verified: the VM is
  `stopped` on the target with the source's final NVRAM and its verified vTPM
  state, detail "stopped on <host> before release; firmware verified;
  `lv start`".
- Anything else parks the move. `lv migrate` answers "live firmware migration
  <attempt> to <host> is parked as <phase>: ...; both copies of its firmware
  state are kept". Both records stay, nothing is deleted on either host, and a
  `firmware_migration_*` condition names the VM, the attempt, both hosts, the
  hashes and the paths (see
  [diagnostics](diagnostics.md#live-firmware-migration-firmware_migration_)).

A source daemon that restarts during a move takes the VM's lock at start-up,
before its other loops start, and resumes, parks or aborts the move from where
its record says it was.

**Partition pause.** The partition pauser resumes a source guest it paused only
while the move is in progress before its cutover. Under a parked move it does
not: the guest stays paused after the partition heals. For a move parked
`target_unreachable`, the move's own recovery resumes the guest once the target
answers that it holds no domain of the VM. A move parked `target_ran` leaves it
paused.

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
rather than overwritten, as for `--with-storage`. Until every host runs a release
that keeps the VM's placement generation (a cluster mid-upgrade), the target
cannot tell a copy this attempt made from a file an earlier move left there:
it treats every file at a disk's path as one it did not create, so a failed
attempt's copies stay on the target and a retry is refused naming each one.
Move each aside as the refusal says, then migrate again.

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

A stopped Secure Boot / vTPM VM moves cold. Its host-local disks are copied as
any stopped VM's are, and its firmware state (UEFI vars and vTPM) is carried
with it; see [cli-reference.md](cli-reference.md). A running one moves live
(see [Secure Boot / vTPM VMs](#secure-boot--vtpm-vms)) or, with `--cold`, is
refused until it is stopped.

## Host drain

Evacuate all VMs from a host before maintenance:

```bash
lv host drain host-a
lv host drain host-a --parallel 4    # Migrate 4 VMs at a time
```

Drain starts the moves highest compose `migrate.priority` first, ties in name
order (see [Recovery priority](#recovery-priority)).

Drain live-migrates a running VM whose disks are all on shared storage. Every
other VM moves the way `lv migrate <vm> <target> --cold` moves a stopped VM
(see [Cold migration](#cold-migration)): its host-local disks (`local` and
`dir` storage) are copied to the target, its domain is defined there, and the
VM and its disk records move in one transaction. It is refused for the same
reasons. A stopped Secure Boot / vTPM VM drains this way, with its host-local
disks and its firmware.

A running Secure Boot / vTPM VM is drained by the live firmware move (see
[Secure Boot / vTPM VMs](#secure-boot--vtpm-vms)) when all its disks are on
shared storage, it has no USB device, and both hosts carry
`litevirt.fw_live_migrate=true`; drain prefers a target with that label. It is
never moved cold. Otherwise, or when the move is refused before the guest
leaves (a target on a build without live firmware migration included), it is
`skipped` and keeps running, and the frame gives the reason with the commands
to stop it and move it. A move that fails or parks is an `error` for that VM;
the drain goes on with the others.

A drain reports the host drained only when no VM names it any more and every
move ended clean. Otherwise it ends incomplete (`lv host drain` exits
non-zero) and names each VM still on the host with its state, whatever that
state is: one skipped or refused, one in `error`, or one still `migrating`
because its move is parked or continues in the background. Do not power such
a host off; `lv events <vm>` shows what happened to each.

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
- While drain waits for a guest to shut down, the VM's record already says
  stopped (so nothing reads the power-off as a crash), but `lv inspect` and
  `lv ls` on its host show it `stopping` for as long as its domain still runs.

A live drain prepares the target exactly as `lv migrate` does: the VM's
networks and its cloud-init ISO are put there first, the VM's migration
policy (bandwidth, auto-converge, maximum downtime) applies, and the
`pre_migrate`/`post_migrate` hooks run: `post_migrate` runs once, naming the
host the VM ended on — the target after the live move or after a cold move
that a failed live attempt fell back to, or the drained host when the VM
stayed there. A live move that outlives the VM's migration policy
`timeout-sec` is aborted, as `lv migrate` aborts one, and is not followed by a
cold move: the VM keeps running on the drained host, its result says so, and
the drain goes on with the other VMs and ends incomplete, naming it. The host
carries `drain_move_timed_out` (see [Diagnostics](diagnostics.md)) until a
drain of it has no such move or `lv host undrain` runs. A Secure Boot / vTPM
VM's live firmware move is `lv migrate`'s move, and applies `timeout-sec` as
`lv migrate` does. A move that libvirt
completed before the abort took is recorded on the target, as any completed
move. While a live move runs, the VM's record says `migrating`, as for
`lv migrate`, and `lv start`, `lv restart` or `lv update --restart-if-needed`
of a VM recorded `migrating` is refused on its source. A live move that ends without libvirt's answer while
the guest is not running on the drained host leaves the record `migrating` and
raises `vm.migration_unresolved` (see [Diagnostics](diagnostics.md)). If
libvirt does not answer the abort within 2 minutes, the drain goes on without
it: the move is finished in the background, which keeps the
VM's lock and the target's capacity reservation until libvirt ends it, then
records the VM on whichever host it ended on and runs `post_migrate` naming
it. No cold move is tried while the move can still complete, and a drain run
meanwhile skips the VM. A move that completes in the background is recorded
for failback like any other. Watch it with `lv events <vm>`. A drain whose
client goes away (Ctrl-C) does not stop a move it has started: a live or cold
move runs to its end, moved or rolled back, and one that completes afterwards
is recorded on its target. VMs not yet started are left where they are. The
drained host's audit log records the drain as `cancelled` with each VM's
outcome (`lv audit`), and each VM gets a `vm.drain` event. A VM whose lock
another operation holds (a scheduled snapshot, a replication run) is waited
for, up to 10 minutes, then skipped, naming the operation that holds it.

Parts of a started move are bounded. A cold move's disk copy that the target
stops taking (alive but wedged) for 5 minutes is aborted, and so is its check
of the target that goes unanswered as long, and so is a copy whose target does
not answer within 5 minutes of the last of the disk. The target syncs the disk
every 64 MiB as it writes, so its sync after the last frame is no larger than
one during the copy. An aborted copy rolls the move back: the VM is started
again on the drained host, where its record still names it. Peers also detect
a host that stops answering during a call within about 6 minutes (gRPC
keepalive). The move's other calls to the target (its firmware state, the
hand-over) are not bounded by a timeout. To end any drain move without
restarting the daemon, run `lv operation abort <vm> --force` (on any host; it
is forwarded to the VM's host): it cancels the move. A cold move rolls back
the same way. A live move's libvirt migration job is aborted, with or without
a migration policy timeout, and the VM keeps running on the drained host,
never followed by a cold move; if libvirt had already cut the VM over, it runs
on the target only and is recorded there. A move the daemon recovers after a
restart copies nothing: it starts the VM on the target when the hand-over had
committed, and otherwise leaves it running, or starts it again, here. So it is
not in that registry and needs no abort.

After the cut-over the source's cloud-init ISO is removed and DNS,
load-balancer backends and VXLAN forwarding entries follow the VM, as for a
migration. A live attempt that
fails takes back the cloud-init ISO and any disk stubs it put on the target
before the cold move is tried. (Builds before this put no ISO on the target,
so every cloud-init VM's live drain failed and fell back to the cold move.)

During a rolling upgrade, until every host runs a release that keeps the
VM's placement generation, the target cannot prove that a file is this
attempt's, so it takes nothing back: the ISO and any disk stub stay on the
target. The ISO is written again by the next attempt, but a disk stub is not:
the cold move that follows is refused at it, naming the file, and the VM
stays on the drained host. Move each named file aside as the refusal says,
then run `lv host drain` again. A failed `lv migrate --with-storage` or
`lv migrate --cold` leaves its files the same way, and its retry is refused
the same way.

A VM that drain cannot move stays on the host with its disks; a failed attempt
removes what it put on the target (during a rolling upgrade, see above). It is
never moved without its disks:

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

### Failback after maintenance

`lv host undrain` returns a host to scheduling (draining, maintenance, and also
fenced or offline, which ends the fence) and moves nothing back. A host
recorded `upgrading` is recorded `active` only if its daemon answers a Ping
from the node handling the undrain. One that does not answer is restarting,
and the undrain is refused (FailedPrecondition) with its state unchanged: it
turns `active` by itself once its daemon serves. The write is made only from
the state the undrain read; if the state changes under it three times, the
undrain is refused (Aborted) and can be run again. Failback
is the opt-in that does, as Proxmox's HA failback property does: after the
undrain, the VMs the drain moved away return by live migration, at a bounded
rate.

A drain records, for every VM it moves, the host it left and the host it went
to, with the VM's creation time, ownership epoch and **placement generation** at
that moment. The records are replicated, so any node can run the failback. The
placement generation is a per-VM counter that every writer that changes a VM's
host (a live or cold migration, a failover, a drain) advances in the same batch
as the host change, so whichever host owns the VM has the generation of the move
that made it the owner. A drained host's record can be the last thing it wrote
before it was powered off, and may reach nobody until it returns, so failback
does not rely on the record for this: the owner compares its own current
generation with the recorded one, and any placement change since the drain, a
hand move out and back included, stops the VM from being moved. Records, and the
generation, are written only while cluster-wide policy writes are allowed
(failover_scope_v1).

**The release gate.** Failback needs every host to run a release that
advances the generation and checks a failback move's preconditions. It is the
`drain_failback` feature of the release token (`lv cluster upgrade-status`;
see upgrades.md, "Rolling back after a release token latched"). Until that
token has latched on every host (and every host in maintenance), no record is
written, `lv cluster failback on` refuses, and `lv host failback` refuses ("the
cluster upgrade must finish first (drain_failback needs ...): failback waits for
the upgrade"); an undrain behaves exactly as it always has, and says so when the
cluster policy is on. Every drain after the latch records the VMs it moved, so
the first drain marks `drain_failback` used: from then on a host rolled back
below the release is quarantined rather than left to move VMs without advancing
their generation. The placement generation itself is not behind the feature: it
is kept from the moment cluster-wide policy writes are allowed.

A drain never waits for its records. Each is written after the VM's progress
line, bounded to 3 seconds; one that is refused or times out (the first use
waits for every host to acknowledge the feature, and a host that is down cannot)
is skipped, put on the VM's events (`vm.failback`) and audited, and further
records are skipped without asking again for a backoff of 5 seconds doubling
to 5 minutes. The backoff is lifted as soon as this host holds an acknowledged
use of the feature (another host completed the first use), since the record is
then a plain local write. A VM whose record was skipped is not failed back;
`lv migrate` moves it by hand.

The records may land a moment after the drain returns, so stopping the daemon
at once can lose them: a stopping daemon waits up to 3 seconds for the records
still queued, then gives up on the rest, logs each VM whose record it
abandoned at Warn and puts it on the VM's events (`vm.failback`). Those VMs are
not failed back. A record describes the drain's own move, read as the move
finishes: a VM moved again (say out and back by hand) before its record was
written gets none, and its events say so (`vm.failback`). Only if that read
fails (the host's replica cannot be read) is the record built from the VM's
row at the moment it is written.

A VM returns only while its record still describes it exactly. One that an
operator has since moved by hand, that a failover recovered, that was deleted
and created again, or that a later drain moved again stays where it is, and the
run says so. The check is made twice: by the daemon that decides, and again by
the VM's owner under the VM's lock, on its own replica, just before the move
(host, owner epoch and placement generation). An owner on a release that cannot make that check (it says so in its Ping) has its VMs skipped, never moved. A
node that serves the failback from a replica that has not yet heard of an
operator's move therefore cannot move that VM back; the owner refuses. A VM no
drain moved is never touched.

Opting in, any one of:

- the VM: `placement.failback: true` in compose (see [compose](compose.md));
- the cluster: `lv cluster failback on` returns every drained VM on undrain
  (`lv cluster failback off`, the default, turns it off; admin role);
- this run: `lv host failback <host> --all`, which moves every VM the drain
  moved and prints each result.

With the policy on, or with a VM that opted in, `lv host undrain` starts the
failback in the background on the daemon that served it and says so in its
reply (how many VMs, on which daemon). `lv host undrain <host> --failback` waits
for that run and prints each VM's result; it is the same run, not a second one,
and moves only the VMs that opted in. `lv host failback <host> --follow`
attaches to that run later. A second `lv host failback` while a run is going is
refused with that hint. `lv host failback <host>` otherwise runs in the
foreground; `--dry-run` shows what would move without moving anything.

The background run belongs to the daemon, not to the undrain's caller: it runs
as the system, so a session that expires during a long run does not fail its
later moves. **A restart of that daemon ends the run.** The records persist;
`lv host failback <host>` finishes what is left. Every VM it skips is recorded
on that VM's events (`vm.failback`), not only in the daemon's log.

Each move is an ordinary live migration (`lv migrate`), so all of that move's
checks hold, including the destination host's capacity admission and the
split-brain gate. Before it, the returning host is checked as a placement target
through the same hard filters as initial placement: capacity, required labels,
devices, anti-affinity and per-node limits, and a VM pinned to another host
stays there. A VM that fails any check is reported with the reason and left with
its record. VMs move one at a time, with a pause between moves (20 seconds), so
a returning host is not hit by every migration at once.

Failback moves a running VM live. A VM that is stopped, or has a disk on
host-local storage (local, dir or btrfs) that a live move would have to copy, is
reported and left; move it with `lv migrate <vm> <host> --cold`. A running
Secure Boot / vTPM VM returns by the live firmware move under drain's
conditions, and is skipped with the reason otherwise. The host must
be `active`. A cancelled record stays in the replicated table as an empty row
(a later release can delete them); the same VM name reuses its row.

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
3. **Fences the failed host** — prevents split-brain by ensuring the failed host cannot access shared resources. A host with nothing on it to recover (every workload `on_host_failure: none`, stopped on a host-local disk, or otherwise left in place, and nothing mid-transfer) is not fenced: it is recorded `offline`, its workloads keep running, and the `ha.fence_held` health condition says so. Every cycle checks again, and the host is fenced as soon as something recoverable is recorded on it (see [Diagnostics](diagnostics.md))
4. **Claims the recovery** — with `enforcement.recovery_claim` on every host (the default; see *Recovery claims* below), a majority of the voter set certifies one destination per workload before any proof is minted, so two coordinators that both believe they lead cannot both recover it
5. **Reschedules VMs** — based on each VM's `on-host-failure` policy. A VM
   stopped on purpose is never started; see *Stopped workloads* below

### Fencing methods

| Method | How it works |
|--------|-------------|
| `ipmi` | Power cycle via IPMI/BMC (requires `ipmi_address`, `ipmi_user`, `ipmi_pass` on host). Verified post-fence by polling `chassis power status`. |
| `redfish` | Power-off through the BMC's Redfish service over HTTPS: a `ComputerSystem.Reset` with `ForceOff`, then `PowerState` polled until it reads `Off`. Same weight as `ipmi`: the fence succeeds, and is verified, only once `Off` is observed. Requires `redfish_endpoint`, `redfish_user` and `redfish_pass` on the host. See [Redfish](#redfish) below. |
| `ssh` | Forced, immediate power-off over SSH: `systemctl poweroff --force --force`, falling back to `echo o > /proc/sysrq-trigger`. Not a graceful shutdown — no units are stopped, so `libvirt-guests` does not get to shut guests down cleanly first; the host stops now, as if its power were pulled. The session dies with the host, and that is reported as success only when the remote shell had already confirmed it was issuing the power-off. Reports failure if the host is unreachable or both power-off commands fail. How the session reaches the host — the managed fence key, root's own ssh setup, and whether the host's sshd key is pinned — is [Managed fence SSH](#managed-fence-ssh). |
| `watchdog` | Local watchdog self-fence (the host writes its own watchdog timer dead). Requires `watchdog_dev` in config. When `watchdog_dev` is set the daemon validates the device at startup and refuses to start if it's absent, so a broken watchdog is caught before it's needed rather than at fence time (override: `LITEVIRT_UNSAFE_SKIP_WATCHDOG_CHECK=1`). On a graceful daemon shutdown the watchdog is disarmed only when this host owns no running VMs or containers; while it owns any, the device stays armed — a restarting daemon resumes petting well inside the timeout, and a daemon stopped for good with workloads left behind lets the watchdog reboot the host into a safely fenced state. A timer left running this way, or by a crash, is petted by the next daemon before it opens its state and through the rest of its startup, so a slow or failing startup that systemd keeps restarting does not reboot the host; one the previous daemon disarmed is not opened until the usual point of startup. That petting is bounded: each startup pets for at most `watchdog.boot_keeper_max_sec` (default 120 s), and startups that never reach the heartbeat stop being petted after `watchdog.boot_keeper_max_boots` (default 5) or once the first of them is `watchdog.boot_keeper_streak_window_sec` (default 300 s) old, so a host whose daemon cannot come back reboots within about 6 minutes. With `watchdog_dev` set and the device verified as a counting hardware watchdog, a running daemon stops petting, and self-fences, when neither a state-store round trip nor the partition pauser has made progress for `watchdog.liveness_stale_sec` (default 120 s; 0 turns it off): a wedged daemon must not keep its workloads behind a petted watchdog. Progress is timed on the monotonic clock, so a wall-clock step is not a wedge, and a long pass that keeps moving (settling many containers after a heal) is not one either. In auto mode (`watchdog_dev` empty), or on a device that is not verified, the daemon never stops petting for this. A self-fence writes `/run/litevirt/self-fenced`; while it exists no later daemon pets the watchdog, and each one starts fenced (it refuses ownership work), so restarting the daemon cannot cancel the reboot. Only the reboot clears it (there is no operator command to do so). On a host whose watchdog did not reboot it (a watchdog that never fires), the marker keeps the host fenced in software until it is rebooted: its workloads keep running, but it takes on no ownership work. Reboot the host; do not remove the file. Drain (or `lv host shutdown-workloads`) before planned maintenance. |
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

`lv host rm` and a re-admission by `lv host add` retire the host's IPMI
password, and it never falls back to a password from before the removal.
Until it is set again with `lv host config <host> --ipmi-pass`, an `ipmi`
fence of that host fails at once with `no IPMI password` and sends nothing to
the BMC. A password that was never set is sent empty, for a BMC user with no
password, and the fence result says so.

A password set with `lv host config <host> --ipmi-pass` after the removal or
re-admission reaches every node, by replication or by anti-entropy. A copy of
the old password, from any node, never replaces the retired one. On a node
that has not yet received the host's re-admission, `lv host config <host>
--ipmi-pass` is refused with "this node's hosts row predates the host's
current admission" and sets nothing: run it against a node that shows the
re-admission in `lv host inspect <host>`, or retry once replication has
caught up.

A password only beats a retirement if this build recorded it as set after
that retirement. The upgrade gives every existing password no such record,
and a node still on the previous build records none with the passwords it
writes. So any password set after a host's removal or re-admission before
every node ran this build can lose to that retirement: a node that still
holds the retirement (it was down when the password was set, or applies the
removal late) retires the password on every node, and an `ipmi` fence of the
host then fails with `no IPMI password`. If you removed or re-admitted a host
and set its password again before or during the roll, set it again with
`lv host config <host> --ipmi-pass` once the roll completes and every node
is up. Passwords for hosts that were never removed or re-admitted replicate
as before.

### Redfish

A host whose BMC speaks Redfish (DMTF DSP0266) can be fenced through it
instead of IPMI:

```bash
lv host config host-b \
  --fence-strategy redfish \
  --redfish-endpoint https://10.0.50.111 \
  --redfish-user admin \
  --redfish-pass-file /root/bmc-pass \
  --redfish-ca-file /etc/litevirt/bmc-ca.pem
```

`--redfish-pass-file` (a path, or `-` for stdin) is the preferred way to give
the password: `--redfish-pass <secret>` also works, as `--ipmi-pass` does, but
leaves the password in `ps` and the shell history.

The fence:

1. reads the service root (`/redfish/v1/`) and, with `--redfish-auth session`
   (the default), logs in through the SessionService and sends the
   `X-Auth-Token` it returns; `--redfish-auth basic` sends HTTP basic auth on
   every request instead;
2. finds the ComputerSystem in `/redfish/v1/Systems`: the member whose Id is
   `--redfish-system-id`, or the only member when no id is set. A BMC that
   lists several and no id is configured is refused rather than guessed at;
3. reads it (its body's `Id` must be the configured system id) and always
   posts a `ComputerSystem.Reset` with `ResetType` `ForceOff`, as `ipmi` always
   sends its power-off: a `PowerState` read can be stale, so it never stands in
   for the command. A BMC that refuses the reset (a 4xx) fails the fence,
   unless the read before it said `Off` — some BMCs refuse a `ForceOff` of a
   system that is already off. A BMC whose reset action does not offer
   `ForceOff` is refused, never reset with something gentler;
4. polls `PowerState` until it reads `Off`, for up to 15 seconds. Only `Off`
   counts: `PoweringOff`, an empty value or an error is not off, and a fence
   that never observes `Off` has failed;
5. deletes its session — also when the fence was cut short, on a detached
   2-second deadline, since some BMCs allow only a handful of sessions.

A fence that succeeded is `verified`, exactly like an IPMI power-off: it
records the host `fenced`, it satisfies the shared-disk fence gate, a
successor resumes from it while it is fresh and renews it with a fresh Redfish
power-off otherwise (a second `ForceOff`, then a read of `Off`), and a failed
one is retried on the backoff below.
Its time budget is IPMI's, so the leader's lease floor covers both.

**TLS is always verified**: against the PEM bundle given with
`--redfish-ca-file`, or the system roots when none is given. The BMC's
certificate must name the endpoint's host (a DNS or IP SAN). There is no
option to skip verification, and an `http://` endpoint is refused, since the
login carries the BMC password. The fence never follows a redirect, and never a
reference the BMC returns to another host: either would hand that host the
credentials. Each request is bounded (4 s), and everything up to the reset by
6 s in all.

**Where the settings live.** The endpoint, user, password, system id, auth mode
and CA bundle are one row of `host_fence_redfish`, on the sensitive lane next to
the IPMI credential, never on the `hosts` row and never in an operator-readable
state dump. `lv host inspect` shows the endpoint, system id and auth mode,
never the user, password or CA (it says whether a CA bundle is set). An omitted
`--redfish-*` flag leaves that setting alone, so `--redfish-pass-file` alone
rotates the password. Two settings can be unset on their own, keeping the
rest: `--redfish-system-id=""` (back to the BMC's only ComputerSystem) and
`--clear-redfish-ca` (back to the system roots). `--clear-redfish`
removes them all; a host that fences by `redfish` needs another strategy in the
same command:

```bash
lv host config host-b --fence-strategy ipmi --clear-redfish
```

A host set to `redfish` without an endpoint, user and password, or with an
endpoint that is not `https://host[:port]`, is refused when it is configured,
not at its first fence.

**Rolling upgrades.** A host on a build before this one cannot decode
`host_fence_redfish`, and reads `fence_strategy = redfish` as an unknown
strategy, which falls back to best-effort SSH. So the strategy and its
settings are the release feature `redfish_fence` of `release_2026_11_v1`:
`lv host config` refuses them with "the cluster upgrade must finish first
(redfish_fence needs release_2026_11_v1)" until every host runs this build, and
the first one records the feature as used. From then on a host rolled back
below the release quarantines itself rather than fence a Redfish host over SSH
(see [upgrades.md](upgrades.md)). Every other setting, and `--clear-redfish` on
a host with no Redfish settings, is accepted throughout. A server that predates
the flags ignores them; the CLI reports an error when the host it gets back has
no Redfish endpoint.

### Managed fence SSH

An `ssh` or `best-effort` fence logs in to the target as root. litevirt
provisions that login itself, per host, so a fence key can do one thing — power
its target off — and a machine answering at the wrong address cannot be powered
off in the target's place.

**What each host holds.** Once the cluster runs `release_2026_12_v1`, each
host's daemon generates a fence key of its own (`/etc/litevirt/ssh/fence_ed25519`,
0600, never leaving the host) and publishes, in the replicated `host_fence_ssh`
row, its public half and the host's sshd host keys, signed with the host's
cluster certificate. Every daemon verifies every peer's row against the cluster
CA and the CRL (the certificate must name the row's host and not be revoked) and
renders the verified ones every 30 seconds, leaving out a peer whose certificate
has expired:

| File | Contents |
|---|---|
| `/etc/litevirt/ssh/authorized_keys` | one line per peer: `restrict,from="<the peer's certificate address>",command="/etc/litevirt/ssh/fence-command"` and its key |
| `/etc/litevirt/ssh/known_hosts` | each peer's sshd host keys, pinned under `litevirt-fence.<hex of its name>`; an expired peer is not listed, though a fence of it still carries its pin |
| `/etc/litevirt/ssh/fence-command` | the forced command: powers this host off only for a request naming it (`litevirt-fence v1 poweroff <hex name>`), answers a probe's `check` without arming, refuses anything else with exit 3 |

The address a key is accepted from is the one IPv4 address the peer's
certificate names besides 127.0.0.1 — what `lv host init` and `lv host add`
put in it — never a field of the row. A host whose certificate names no such
address, or more than one, or is not valid now, publishes no row: it cannot
fence over the managed key, and its peers fence it the legacy way, unpinned,
which `lv doctor fence` warns of. Every file sshd
reads at fence time is static, so a frozen or dead daemon does not stop its host
being fenced. A host whose own certificate is revoked, or whose host row is
removed, renders no peer at all.

**sshd.** `lv host init` and `lv host add` add
`/etc/ssh/sshd_config.d/60-litevirt-fence.conf`:

```
Match User root
    AuthorizedKeysCommand /usr/bin/cat /etc/litevirt/ssh/authorized_keys
    AuthorizedKeysCommandUser nobody
```

sshd reads an `AuthorizedKeysCommand`'s keys in addition to its
`AuthorizedKeysFile`, so every file sshd read for root, from every address and
under every `Match` rule of yours, is still read, and a host added later is
accepted from like any other. Where your configuration already sets an
`AuthorizedKeysCommand` anywhere, no drop-in is written (sshd keeps the first one
it reads, so it would replace yours): have yours also print
`/etc/litevirt/ssh/authorized_keys`. The drop-in is validated with `sshd -t` and
rolled back on a refusal, never overrides `PermitRootLogin no` — such a host
reports that it does not accept the managed key — and a failed sshd reload is
reported loudly. `--no-fence-ssh` skips the drop-in, for an sshd configured
elsewhere: have it read `/etc/litevirt/ssh/authorized_keys` for root (an
`AuthorizedKeysFile` entry or a command like the one above).

Each daemon evaluates its sshd every minute: `sshd -T` for a connection from
each peer's address, then a login of its own over the managed key to its own
sshd (its own key, rendered for its own address, and a `check` request). It
publishes that it accepts the managed key only when both pass, so the claim is
about the running sshd, not its files. An `sshd -T` that cannot run changes
nothing it published. A host that accepted the managed key before and does not
now raises the `fence_ssh_not_accepting` health condition (warning) for itself:
its peers still fence it over the managed key, which its sshd may refuse.

**How a fence reaches its target** (`enforcement.fence_ssh`, per host; the
fencing node's setting decides, so no host relies on another's):

| The target's row | `auto` (default) | `managed` | `legacy` |
|---|---|---|---|
| none (it has not published) | today's command, unpinned, with a warning | refused | today's command, unpinned |
| does not verify (forged, revoked, retired) | refused | refused | refused |
| verified, sshd accepts the managed key | managed | managed | legacy, pinned |
| verified, accepted it before and does not now | managed | managed | legacy, pinned |
| verified, never accepted it | legacy, pinned | refused | legacy, pinned |

- **managed**: `ssh -F /dev/null` with the host's own fence key, no agent, no
  configuration of root's, `StrictHostKeyChecking=yes` against the target's
  pinned sshd keys, `BindAddress` = the fencing host's certificate address, and
  the request naming the target.
- **legacy, pinned**: the command fences always ran — root's own identity and ssh
  configuration, so a hand-made fence key keeps working — with the target's
  published sshd keys pinned.
- A target's `accepting` is its own evaluation, for every peer at once, so one
  false answer (an address it was not evaluated for, a failed evaluation) never
  makes it unfenceable: trying the managed key is never less safe than refusing,
  since the pin, the restricted key, `from=` and the forced command all still
  apply.
- A host that cannot use the managed key itself (no fence key yet, or a
  certificate with no fence address) fences a host that accepts it pinned in
  `auto`, and refuses in `managed`.
- The pinned path is refused toward a host whose sshd host keys another host
  also publishes (a cloned image): the pin cannot tell the two apart. Regenerate
  the sshd host keys on one of them. The managed path is not affected; its
  forced command checks the name. (Host keys are public, so a compromised member
  can publish another host's in its own row and hold the pinned path toward that
  host off in the same way; it cannot make a fence reach the wrong machine.)
- A row whose certificate has expired still pins its host's keys (`lv doctor
  fence` says it expired): renew the certificate with `lv host renew-cert`.
- A host that has published is never fenced without its pin, in any mode, and a
  managed fence that fails is never retried down another path. A refused fence
  fails. A `best-effort` fence keeps its contract and reports a refused or failed
  fence as an assumed success: it gains no pin guarantee. `fencing_log`'s detail records the path: `[path=managed]`,
  `[path=legacy-pinned]` or `[path=legacy-unpinned]`.
- A new cluster's `lv host init` writes `fence_ssh: managed`, and `lv host add`
  copies it with the enforcement block. An upgraded cluster stays `auto`.
- A host in `legacy` publishes no row of its own. It still fences every host that
  has published pinned, and every other host unpinned, as before.

**Every member fences.** Any host can hold the failover lease and any host
answers `lv host fence`, so every admitted host's key is rendered on every
other host.

**The probe.** Every `fence_ssh_probe_interval_sec` (default 900; 0 disables)
each host runs the managed path's `check` against every peer whose fence strategy
is `ssh` or `best-effort` (an `ipmi`, `redfish`, `manual` or `watchdog` host is
never logged in to): pin, key, source address and forced command, without arming
anything. The result is `litevirt_fence_ssh_probe_ok{peer}`, and a warning in the
log when a managed path fails its check. A check does not prove the power-off
itself works. The probe runs apart from rendering and publishing, so a peer that
does not answer does not hold them back. It is a root login on every such peer
each interval, and shows in their auth logs.

**`lv doctor fence`** prints the pair matrix — how a fence from each host reaches
each other host, and its last probe — and each row as the queried host holds it.
It warns of every pair fenced without a pinned key and every host that does not
accept the managed key. Its exit code is unchanged.

**Migrating an existing cluster.**

1. Upgrade with a normal rolling upgrade. `release_2026_12_v1` latches once every
   host the cluster replicates to runs this build; until then nothing is published
   and fences run exactly as before. Every host then publishes its row, which pins
   its sshd keys for every fence toward it, the legacy path included.
2. Run `lv host install-fence-ssh` (from the machine `lv` runs on, as root on each
   host, or `--ssh-user`). It writes the drop-in on every host and waits until each
   reports accepting the managed key; from then on, fences toward it take the
   managed path.
3. Check `lv doctor fence`: every pair `managed`, every probe `ok`.
4. Set `enforcement.fence_ssh: managed` on each host.
5. Remove any hand-made fence keys and `Host` stanzas from `/root/.ssh` yourself;
   litevirt never edits it.

**Removal and renewal.** `lv host rm` and `lv host rm --dead` retire the host's
row on every node, so its key leaves every authorized_keys and its pin every
known_hosts; its revoked certificate would refuse the row anyway. A partitioned
node keeps the stale line until it heals; that line still only powers the host
off, and only from the removed host's address. `lv host renew-cert` does not
revoke the replaced certificate until the host's daemon has re-signed its row
with the renewed one (see [auth.md](auth.md)). `lv uninstall` removes the
drop-in and `/etc/litevirt/ssh`; `lv host install-fence-ssh --remove` removes
only the drop-in.

**Rolling back.** Every host not in `legacy` publishes as soon as
`release_2026_12_v1` latches, so the feature `fence_ssh` is used from then on, and
a host rolled back below the release quarantines (see [upgrades.md](upgrades.md)).
To keep that rollback possible, set `enforcement.fence_ssh: legacy` on every host
before the last one upgrades. A rolled-back binary
leaves the drop-in and the rendered files in place: they keep accepting peers'
fences, and are not updated when a host is removed until it is upgraded again.

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

**A host that is still answering is refused.** The confirmation fails with
`FailedPrecondition` ("Power it off first") while another host's latest
health verdict about it, healthy or unready, is under 30 seconds old, or while
the node serving the request reaches it now, or when it names that node
itself. Power the host off and run it again once it no longer answers. There is
no override.

**A removed host can be confirmed too.** Removing a host does not power it
off: `lv host rm --force` asks for no fence, and a host whose daemon died may
still be running its qemu. So a replica promotion treats a removed owner of a
shared disk like a fenced one, and reattaches the disk only when the newest
fence on record for it is proof-grade (docs/backups.md).
`lv host fence-confirm <host>` accepts a host that has been removed, and
records only the `manual-confirmed` row in `fencing_log`: the host is not
brought back and no membership state is written. Only the confirmation is
accepted (`lv host fence <host>` refuses a removed host, since there is
nothing left to fence it by), and a name the cluster holds no hosts row for
at all is still not found.

Only a fence of the removed host's **last life** counts. A removal writes no
fence row, so an IPMI fence or a confirmation recorded before the host last
came back (the same machine before it returned to service, or the machine
removed under the name before `lv host add` gave it to a new one) proves
nothing about the machine behind the name now. The boundary is the same one
`lv host rm --dead` uses: the host's membership row, which outlives the
removal, dates its last life. A confirmation recorded after the removal
always counts.

The confirmation is not only for the promotion. It is also the proof-grade
fence that `lv host rm --dead` would have required, so with recovery claims
enforced the failover coordinator may now recover **every workload still
recorded on the removed host** under its failure policy, by the same claim
path as after `lv host rm --dead`, once the removal and the host's certificate
revocation have replicated. That can happen before a promotion you run next,
so confirm a removed host only when you want its workloads recovered.

**An operator's promotion and failover's recovery of the same VM never both
start it.** With recovery claims enforced, a same-name `lv replication promote`
of a VM recorded on another host claims the VM's recovery at its current owner
epoch just before it starts the VM (docs/design/recovery-claims.md §10 item
43). Whichever is decided first runs the VM. A promotion that comes second is
refused with the decision it lost to, `<action> to <host> by <coordinator>
(proof <id>)`, and what to wait for (`lv inspect <vm>` shows where it runs,
`lv cluster claim vm/<vm>` the decision); a coordinator that comes second
stands down. The promotion goes ahead unclaimed only when a majority of voters
still reach the VM's owner, where no recovery can be certified either. Without
claims, a promotion refuses while this host's replica holds a reschedule or
promote proof of the VM in flight at its current owner epoch (written within
the last hour, or with a start recorded): best effort, as a replica can lag.

The confirmation of a removed host needs a node on a build that has it. A
node still on an older build answers `host "<host>" not found` for a removed
host, as it always did; during a rolling upgrade, point `lv` at an upgraded
node (set `LV_HOST` to it).

### Shared-disk fence gating (host-fence-gated shared storage)

A VM whose disk lives on **shared** storage (NFS/Ceph/RBD/iSCSI) is a special
split-brain hazard: the same bytes are writable from any host, so starting the VM
on a second host while the original owner may still be writing corrupts the disk.
A local-disk replica is a *different* image, so promoting it carries no such hazard.

When `enforcement.shared_storage_fence` is enabled (and the cluster has latched the
`shared_storage_fence_v1` capability), an **ownership transfer** — auto-promote or
reschedule — of a VM with a writable shared disk starts only once the old owner is
**proven powered off**:

- Accepted: a confirmed power-off (`ipmi` or `redfish`), or an operator `lv host fence-confirm`
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
| `ipmi` or `redfish`, powered off and observed off | `fenced` |
| `ssh`, `watchdog`, or `best-effort` that succeeded | `offline` once `fence_state_v1` has latched; `fenced` before |
| any fence that failed | `offline` |
| `lv host fence-confirm` | `fenced` |

`fenced` is the cluster's statement that the host is **off**, and only a
verified power-off or an operator's confirmation makes it
(colonelpanik/litevirt#253). An SSH success means a shell accepted a forced
power-off; nothing looked afterwards. Such a fence keeps every bit of the
authority it had: the coordinator that ran it reschedules on it (subject to the
safe-fence policy and `litevirt.fence_requires_confirmation`), a successor
resumes from it (below), and the coordinator does not put the host back in
service behind the workloads that moved off it — it is `offline`, and a host
whose newest fence succeeded is treated exactly like a `fenced` one: once a
quorum sees it healthy again, it stays out of service until
`lv host undrain <host>`, unless the coordinator that fenced it moved nothing
off it.

That covers a host that answers again **without having restarted**: the host
an unverified fence may never have powered off, or one cut off by a partition.
A host whose daemon starts again — the machine booting after a power-off, or
its daemon restarted — turns `active` on its own, whatever the cluster
recorded for it, and needs no `lv host undrain` ([upgrades](upgrades.md) says
the same). Its boot write records it `upgrading`, and the daemon records it
`active` once it serves, as after a graceful restart. It does not run the
workloads that
moved off it: they are recorded on their new hosts, and the copies of their
disks it still holds are set aside as superseded (`lv host superseded-disks`).

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
2. **The newest fence attempt succeeded.** That covers a verified `ipmi` or
   `redfish` power-off and an `ssh` or `best-effort` success. A host left `offline` by a
   failed fence has a failed newest attempt and is not resumed from; while a
   quorum sees it down, the leader fences it again on a backoff (30 s,
   doubling to 5 minutes), and a later successful fence by anyone — an
   operator's `lv host fence` included — is resumed from on the leader's next
   cycle. The
   resumed recovery passes the same safe-fence policy and
   `litevirt.fence_requires_confirmation` check the leader's would have.

What happens next depends on the fence:

- **A verified (`ipmi` or `redfish`) fence** is resumed from directly only while it is under
  5 minutes old **and** still stands (below). Otherwise the successor powers the
  host off again with the recorded method first. A verified power-off of a host
  that is already off is harmless, and a fresh one is authority on its own,
  whatever happened to the host in between. The recovery then proceeds on the
  fresh fence, and a shared-disk VM is bound to it. If the re-fence fails,
  nothing is recovered. The failed attempt is now the newest on record, so the
  host is not re-fenced every cycle, only on the failed-fence retry backoff
  (30 s, doubling to 5 minutes, with the host's current strategy when that is
  `ipmi`, `redfish` or `ssh` and the method that failed otherwise, and never once any
  observer has seen the host answer since the failed attempt); it is left
  `offline`, counted as `phase=recovery, error_class=refence_failed` and
  raised as the `refence_failed` health condition. Confirm it is off and run
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
without a break since before the fence, no observer's latest verdict shows
the host answering (healthy or unready) since, and no observer's failing run
began after the fence. The first holds however recent the fence is. A genuine
fence follows a quorum of failing runs, so it always has one. A host that
answered after its fence and then failed again has had the verdict that it
answered overwritten, and only the failing runs' start shows the return: a run
that began more than 5 seconds after the fence counts as an answer. An observer
that restarted, or began probing the host only after the fence, starts such a
run too, and the fence then no longer stands. An observer whose own process
was stopped (frozen, suspended) across the fence starts one as well, once it
resumes. If it has not seen the host answer since it stopped, it records that
run in its `observer_stalled` condition (`silent_runs` in the evidence), and
the run does not count as an answer when the stall began more than 5 seconds
before the fence.

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
before the fence, an answer counts from 5 seconds before it, and a run begun
more than 5 seconds after it counts as an answer. The last has no slack beyond the
threshold: a run reported by an observer whose clock runs behind by up to 5
seconds is missed when it began within 5 seconds plus that skew after the
fence, so a host that answered for less than that and failed again is seen
only by an observer's latest verdict or the coordinator's own probes. Greater skew
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
5 minutes. If that fence fails, its retries keep to the failed-fence backoff
(30 s, doubling to 5 minutes) too: the failed fence records the host
`offline`, so its activation no longer dates its life, and a retry counts
only a fence row newer than the attempt it repeats. Before this, the previous
outage's fence held every retry back until it was 5 minutes old. A row newer
than the host's last activation still counts, which is the race the window
exists for. Likewise, a health observation older than the
moment a host turned active does not count toward fencing it: a host that just
turned active is counted down afresh, and a host `lv host add` admitted is not
probed at all until its daemon's first boot write ends `joining`. A newer
observation counts only if its failing run began after the activation, or once
the host has been failing for a whole run since it: 5 probes (8 s) plus the 5 s
clock-skew margin. Observers keep counting through a restart, and where a
daemon's boot write records it `active` (the boots listed below that still
do), it does so a few seconds before it answers probes, so without this a host
that restarted (recorded `upgrading` while it was down) was fenced the moment
its boot write landed, on the count from its restart.
The rule is the failover leader's: until the leader runs a build with it, a
restarted host can still be fenced in that gap.

**A graceful restart stays `upgrading` until it serves.** A daemon stopped by
SIGTERM (`systemctl restart`, a reboot) records its host `upgrading` and
leaves a `restart-pending` marker in its `data_dir`. Its next boot consumes
the marker and records the host `upgrading` again, and the daemon records it
`active` only once it answers its own Ping, however long its startup takes.
The coordinator skips an `upgrading` host for 2 minutes, counted from the
state write itself and not from the host's version or resource reports, and
fences it after that. A daemon that never serves is therefore fenced 2 minutes
after its boot write, which re-arms that window once: a host held unfenced
by a SIGTERM is fenced 2 minutes after its next boot write if it has not
served by then. A daemon that serves late, past
`upgrade_health_deadline_sec`, logs an error at the deadline and keeps
checking, and is recorded `active` once it answers. A write that records it
`active` and fails is retried until it lands. A host still `upgrading` 2
minutes on while its daemon runs raises `upgrading_unconfirmed`
([diagnostics.md](diagnostics.md)): peers that reach it never fence it.
A failing run that began while the host was `upgrading` keeps the rest of
those 2 minutes however the host is recorded `active` (an undrain handled by
a node on an older build, for one), and
the host is fenced when they end if it still does not answer. The failover
leader knows of the `upgrading` state only if it saw it: a leader that took
over after the host was recorded `active` gives such a run 13 s, as above.

A boot with no marker (a crash, a kill, or a stop whose `upgrading` write
failed, as every write of a WAL-quarantined daemon does) does the same for a
host recorded `active` or `upgrading`: it records the host `upgrading` and
turns it `active` once it answers its own Ping. Such a boot leaves a
`boot-awaiting-serving` file in its `data_dir` until a daemon serves.

No boot of a host recorded `active` or `upgrading` records it `active` before
its daemon serves. A boot's `upgrading` write is made only while the host is
still recorded as the boot read it, checked in the write's own transaction,
so a fence, drain or offline recorded in between is kept; the boot's version
and resources are then written once the daemon serves, leaving that state.

- A host recorded `upgrading` for 2 minutes or more (with or without the
  marker), which the coordinator would treat as stuck and fence on its
  failure count before it serves, gets a fresh `upgrading` write, once per
  boot. A fence the coordinator records after that write is kept; one it
  recorded before it, that this node had not received, is judged afresh from
  the write, as below.
- A boot without the marker that finds `boot-awaiting-serving` (the daemon
  before it never served; a post-upgrade boot leaves the file too) of a host
  recorded `upgrading` less than 2 minutes ago makes no write. The host keeps
  its recorded state, so a daemon that crash-loops is `upgrading` once and is
  fenced 2 minutes after that write.
- A boot without the marker that follows 3 others within 10 minutes, counted
  in `boot-unclean-history` in its `data_dir`, makes no write either for a
  host recorded `upgrading`, or `active` when the daemon before it served: a
  flapping daemon is judged on its failure count. Recorded `active` after a
  daemon that never served (its `upgrading` write did not land, as with a
  WAL-quarantined daemon), it records the host `upgrading` until it serves.
- After a boot that made no write, the daemon records `active` with its
  version and resources once it serves, only while the host is still
  recorded as the boot found it. A host undrained, drained or put in
  maintenance meanwhile keeps that state and still gets the version and
  resources; a fenced or offline one gets nothing.
- A daemon that cannot build its own local gRPC client keeps retrying and
  does not record the host `active` until it can confirm it serves; past 2
  minutes `upgrading` it raises `upgrading_unconfirmed`.
- A boot without the marker that cannot write `boot-unclean-history` or
  `boot-awaiting-serving` (a full or read-only disk) could not bound a crash
  loop, and one that cannot read the host's record (read twice) could not
  judge it: each makes no write. This covers a host recorded `active` or
  `upgrading` at boot, one whose record was unreadable, and one recorded
  `fenced` or `offline` that cannot write `boot-unclean-history`; a host
  recorded `maintenance`, `draining` or `joining` at boot is returning (below)
  and is written. Once the daemon serves it records a host recorded `active`
  or `upgrading` `active`, with its version and resources, only while it is
  still recorded so; a fenced or offline host keeps that state and gets
  nothing, and a draining or maintenance one (found so once it serves) keeps
  its state and gets its version and resources. A graceful boot that cannot read the
  record still leaves `boot-awaiting-serving`; if that cannot be written
  either, a crash before it serves leaves the next boot nothing to show it
  never served, and that boot may write one fresh `upgrading` (bounded by the
  3-in-10-minutes count).
- A report that fails once the daemon serves is retried until it lands.

A host recorded `fenced`, `offline`, `maintenance`, `draining` or `joining`
when it boots, with or without the marker, whatever its earlier boots, is
returning to service. The one exception is a fenced or offline host whose boot
cannot write `boot-unclean-history`: it keeps the fence, makes no write and
is not recorded `active` once it serves, until `lv host undrain`. It logs that
at warning level and raises `boot_kept_fence`
([diagnostics.md](diagnostics.md)). Once the `returning_boot` feature of
`release_2026_11_v1` is in use ([upgrades.md](upgrades.md)), its boot write
records it `upgrading`, only while it is still recorded as the boot read it,
and the daemon records it `active` once it serves, so it is not fenced before
it serves on failures counted since its boot write. Until then, or when the
boot cannot use the feature, its boot write records it `active`, as before:
a failover leader on the previous release clears a fenced host from what it
has handled only once the host is `active`. Either write ends the recorded
state and keeps the host's isolation. The `upgrading` write is made once per
return: a crash of that boot finds the host `upgrading`. A fenced, offline or
maintenance host keeps that state through a SIGTERM, and a draining one is
recorded `upgrading` for the restart, as before.

Each of these boots `active`, as before:

- a boot with no `data_dir`;
- the first start of a host with no record yet, or one re-admitted under its
  name: registering it inserts it `active` before its daemon serves. Its
  boot write then follows the rules above.

Recording the host `active` once it serves changes only an `upgrading` host
(after a boot that made no write, only a host still recorded as that boot
found it), and never its isolation.

A host the coordinator has already fenced that then records itself
`upgrading` (it rebooted, and its boot write was made from a replica that still
read it `active`) is judged afresh from that write, as an `active` boot write
is: it is skipped for 2 minutes and fenced again if it has not served. A fence
row older than the host's own `upgrading` write does not hold that fence back.

The same holds for the proof-grade fence `lv host rm --dead` rests on, which
counts at any age, and for the one a lost voter's removal, a superseded claim
and the coordinator's recovery of a removed host's workloads rest on. A
proof-grade row from before the host was last recorded as it is now —
admitted (`joining`), booted (`active`), lost unfenced (`offline`), drained —
is about an earlier life and does not count, so a machine `lv host add` put
under a removed host's name is not removed on the old machine's confirmation:
`lv host fence-confirm` it once it is powered off. A host recorded `fenced` is
exempt, since that write is itself its fence. Rows within 5 seconds of the
state write still count, for the clock between them.

This holds after the host is removed too. The membership row outlives the
removal, so a removed name's fence from an earlier life is not taken as the
proof that its workloads may be recovered, or that a claim decided for it may
move on; it used to be, at any age, once the live hosts row was gone. The
remedy is `lv host fence-confirm <host>` once it is powered off, which a
removed host accepts.

### Resuming a recovery from a confirmation

A recovery refused for want of a confirmation — a `manual` fence, a
`best-effort` fence under the safe-fence policy, or a host labelled
`litevirt.fence_requires_confirmation` — resumes once an operator runs
`lv host fence-confirm <host>`.

The resume requires five things, not the confirmation alone:

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
5. **Nobody has seen the host answer since the confirmation.** Some observer
   has failed it without a break since at least 5 seconds before the
   confirmation. No observer's latest verdict is an answer newer than 5
   seconds before it, and no observer's failing run began more than 5 seconds
   after it. The coordinator's own node has not probed the host healthy since
   5 seconds before it. Otherwise the coordinator logs "the operator
   confirmation does not stand for this outage, NOT acting on it" once per
   confirmation (`phase=recovery, error_class=manual_unconfirmed`).
   The host's stall reason names the confirmation and the remedy. Power the
   host off, then run `lv host fence-confirm <host>` again. A confirmation
   typed before the power-off, while a bridge still sees the host, is refused
   the same way. A failing run begun after the confirmation is named in the
   reason as "it saw the host answer, or its own daemon restarted": a
   restart of that observer's daemon, the coordinator's own included, also
   refuses. A refusal on the coordinator's own probe answer does not clear by
   itself; confirm again.

An observer's unbroken run of failed probes restarts when that observer's
daemon restarts, so after every observer has restarted a genuine confirmation
of an older fence is refused too. Run `lv host undrain <host>`: the coordinator
then fences the host for the outage in progress, refuses for want of a
confirmation, and resumes once you confirm again.

`fence-confirm` has no precondition and runs no fence, so on its own a mistyped
hostname could otherwise authorise a recovery. With all of these required, a
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
  and failed without a break since at least 5 seconds before it, and nobody
  has seen the host answer since it (item 5 above; a refusal is logged and
  held the same way),

the coordinator fences the host itself, as it would an `active` one, and logs
"an operator confirmed this host off during the outage in progress, and no
fence has run for it; fencing it afresh" (`phase=recovery,
error_class=confirmation_fence`). The confirmation authorises that fence, not
the recovery: the recovery follows from the fresh fence under every gate a
fence applies, and where one of them needs a confirmation (`manual`,
`best-effort` under the safe-fence policy, the confirmation label) it accepts
one under 5 minutes old that still stands (item 5) and was written since the
host last turned active. An older one leaves the host `offline` after the fence
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
(anything but `ipmi` or `redfish`) gives its shared-disk VMs *manual-confirm-only* automated
failover once this is enforced. `lv host inspect <host>` prints a note when a host's
fence strategy can't prove a power-off. Give shared-disk hosts an IPMI or Redfish fence strategy,
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

### Disarming HA for planned maintenance

`lv cluster ha disarm` holds every automatic fence and recovery cluster-wide
until `lv cluster ha arm`, for planned work that would otherwise look like a
failure (a core switch replacement, a storage firmware update):

```bash
lv cluster ha disarm --reason "core switch replacement, CHG-1234"
lv cluster ha                       # state, who set it and why, each voter's answer
lv cluster ha arm                   # refused while a host is reported down
lv cluster ha arm --fence-down-hosts
```

| Held while disarmed | Kept |
|---|---|
| Every new fence, fence retry and re-fence | Health probes, `host_health` rows, `suspect` |
| Every recovery: reschedule, promote, container relocation, the re-key of a stopped VM | Re-admitting a host that answers again |
| Resuming from a recorded fence or from `lv host fence-confirm` (the confirmation is recorded; the recovery waits for arm) | Relay-health demotion |
| Recovery-claim retries and partition-pause waits (kept, and run after arm) | Partition pause, VIP self-demotion, watchdogs |
| A VM healthcheck's `restart` and `migrate` actions, which become an alert (`vm.health.downgraded`) | A VM's restart policy restarting it on its own host after a crash |
| | Operator actions: start, stop, migrate, drain, `lv replication promote` |

A proof already minted before the disarm completes; nothing new is minted.
Partition pause still pauses: a planned whole-cluster network outage pauses
and resumes every VM while disarmed, and nothing is fenced. The coordinator
logs `failover: HA disarmed; not fencing <host> (quorum reports it down)` once
per host, counts the skip as `error_class="ha_disarmed"`, and the stall alert
for a held host says `recovery held: HA disarmed`. A host that fails while
disarmed is held before any fence, so nothing records it down: `lv host ls`
keeps showing it active and `lv ls` its VMs running. `lv cluster ha` lists it
under the hosts arming would fence, and 60 s after the hold began the stall
alert (`host.recovery.stalled`) names it, held by the disarm. There is no
automatic re-arm.

**Changing it.** Both directions need the admin role and the connected host's
voter majority, and wait until a majority of the voters (under region scope, a
majority of every region that holds a voter) answers with the new row, then a
further 20 s; the call can take up to 80 s. A newer change seen meanwhile
returns `Aborted`. On a timeout the call returns `Unavailable` naming who has
not confirmed, and the row stays: the change may still take effect as it
replicates, so check `lv cluster ha`. A host whose policy row cannot be read
reads it as disarmed and raises `ha_policy_unreadable`.

**Arm.** Arm refuses while any host is reported down by the quorum (voters,
non-voters and witnesses alike) that the coordinator would fence, listing
them: those hosts would be fenced on the next cycle. Hosts in maintenance,
hosts still joining, hosts whose state this node cannot read, and hosts
restarting within the upgrade timeout are not listed, because the coordinator
does not fence them. Bring them back, remove one that is
never coming back with `lv host rm --dead <host>`, or pass
`--fence-down-hosts`. The list is a snapshot: a host that goes down after the
arm is fenced like any other.

**Region scope.** A disarm holds a region only once a majority of that region's
voters holds it; `lv cluster ha` lists the regions that have not confirmed. A
region cut off before then keeps its coordinator's behaviour.

**First use.** The first disarm ever needs every host, maintenance hosts
included, to acknowledge the `ha_disarm` release feature. Once the release
token has latched, the failover lease holder pays this in the background;
until it has, `lv cluster ha` says `first use pending`.

**Armed, too.** Once the `ha_disarm` feature is in use — automatically, soon
after the release token latches — a coordinator decides no fence and no
recovery for a scope (the cluster, or the host's region) in which it counts
fewer than a majority of the voters live at that moment; the skip is counted
as `no_quorum`, and the stall alert points at `lv cluster ha`, which shows the
voters `not counted live`.

**Limitation.** With recovery claims enforced, an operator promotion that
must re-propose an automatic recovery value already accepted by a minority of
voters is refused while disarmed: `the workload has an automatic recovery claim
in flight; HA is disarmed — run lv cluster ha arm, or wait`.

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
started, not recorded stopped), and the record clears. It does so once:
a VM that crashes after that follows its own restart policy. A stop recorded
after the host read the VM as running (an `lv stop`, say) wins, and a held VM
with saved state (a managed-save image) is never cold-booted: it stays held,
a `vm.failover.held_saved_state` event says so, and `lv start <vm>` resumes
it. A host comes back
`fenced` when failover moved any other workload off it: run
`lv host undrain <host>`. A removed host does not block this: adding the
machine back under its name (`lv host add`) brings the held VM back with it.
If the host is gone for good, its data is gone with it: promote a replica if
there is one (once the host is powered off, `lv host fence-confirm <host>`,
then `lv replication promote <vm>`), or remove the host first
(`lv host rm --dead <host>`, try `--dry-run`) and then the VM (`lv rm <vm>`),
and create it again; `lv rm` cannot reach a VM on a host that is fenced but
not removed. The coordinator decides the hold once per fence, so changing the
policy afterwards takes effect only at the next failover decision for that
host. There is no
command that moves it elsewhere onto a blank disk. It counts in the failover metrics with error class `held_for_host`. Before this
release a `restart-same` VM was restarted on any healthy host whatever its
disks, because the original host is never available while it is fenced.

A VM with PCI passthrough devices is held the same way, with the same
condition, when no surviving host has a free device of the kind it needs.
Unlike a `restart-same` hold, it is placed again on every failover pass. See
[Failover with PCI devices](pci-passthrough.md#failover-with-pci-devices),
which also covers the `litevirt.failover_without_devices` label that recovers
it without them.

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
- When the VM is deleted (`lv rm`, with or without `--keep-disks`), the host
  that holds its disk clears the record on its next pass, or once it is back
  if it was down then. After `lv rm`, a disk still at its path is renamed to
  `<disk path>.superseded-<time>` first, so it is kept like any other copy;
  this waits while a domain of the VM's name runs on that host. After
  `lv rm --keep-disks`, and for a disk recorded `delete_with_vm=false`, the
  disk stays at its path. It also stays there when the record does not say
  what the delete decided: a delete by an earlier release, or one whose mark
  on the record was lost to a later write of it. The host also removes the
  VM's cloud-init seed there (`cloudinit/<vm>.iso`) if this release wrote it,
  except in these cases, where the seed stays: after `lv rm --keep-disks`,
  whether or not a disk is still at its path (one set aside before the delete
  is not); when a disk stays at its path for one of the other reasons above;
  and for a seed from an earlier release. A seed that stays can hold
  user-data, and nothing removes it but an operator: while no VM of the name
  exists, `lv host superseded-disks <host>` lists it as `kept`. A shut-off domain of the VM still
  defined on that host, from an owner epoch older than the deleted record's,
  is undefined there (disks and TPM state kept, UEFI vars renamed to
  `<vars>.superseded-<time>`) and its owner-epoch marker removed (orphaned runtimes in
  [diagnostics](diagnostics.md)).
- A VM of the same name created on that host before then clears
  `<data_dir>/disks/<vm>-<disk>.qcow2` files the earlier VM left. Of those, a
  disk that a failover left at its path is first renamed to
  `<disk path>.superseded-<time>`. One the delete kept is first renamed to
  `<disk path>.kept-<time>`, which no sweep removes. A file that another VM
  uses, as its disk or as the base of a linked clone, stays where it is.
  Each rename is a `vm.disk.set_aside` or `vm.disk.kept` event of the VM.
  The create is refused, and nothing is created, while that host's replica
  has not caught up with the cluster and such a file is there, while what is
  at one of those paths cannot be read, or when a rename fails. The message
  names the path and the cause. Retry once the replica has caught up or the
  storage answers, or place the VM on another host. A path that does not
  exist does not refuse the create. When the record lists a path that does
  not exist and its directory is absent, empty or cannot be listed, as a
  volume not mounted yet reads, the create goes ahead, the record stays open,
  and a `vm.disk.path_missing` event of the VM names the path.

A cloud-init seed is used only by the VM it was written for: a host that
holds the seed of a deleted VM writes a new one from the VM's own settings
when another VM of that name starts there, fails over to it or migrates to it.

A copy is retained while the VM it came from exists, in any state: the host
never removes it on its own. While that VM is in `error`, `pending` or
`starting` it is also held, because a restart that failed may need it put
back. Once the VM is deleted, its copies are removed by their host when they
are older than `superseded_disk_retention_days` (default 7 days; `0` keeps
every copy). The host checks hourly; the age comes from the time in the file
name. Until then `lv host superseded-disks <host>` lists a deleted VM's
copy with its VM shown as `<vm> (deleted)`, a copy in a directory only
deleted VMs' disks used (a pool directory, say) included, and `--remove
<copy>` removes it. Before this rule a copy was held only while its VM was in `error`,
`pending` or `starting`, so seven days after the VM was running again on a
rebuilt disk the only copy of its data from before the failover was deleted.

To see the copies on a host, with the VM each came from, when it was set aside
and whether it is retained or held, run `lv host superseded-disks <host>`.
It also lists each `.kept-` file there, marked `kept`, and each `.kept-`
cloud-init seed in `<data_dir>/cloudinit`, which can hold user-data; none of
the options below takes one. The options need the admin role and are audited:

- `--purge` removes every copy that is neither retained nor held, whatever its
  age; `--older-than <duration>` narrows it (`host.superseded_disks.purge`).
- `--remove <copy>` removes exactly the named copy, retained or not, never a
  held one; repeat it to name more (`host.superseded_disks.remove`).
- `--restore <copy>` puts the copy back as its VM's disk
  (`host.superseded_disks.restore`). The VM must be stopped on that host. The
  file it replaces is not deleted: it is set aside and retained in turn.

To run a VM on the real disk a failover left on a host, once that host is
back and `active` — a host that booted again turns `active` on its own
(after `upgrading`, once its daemon serves); one that
answered again without restarting stays `fenced` or `offline` until
`lv host undrain <host>`, and a migration onto it needs it active:

```bash
lv host ls                           # the host must read HOST_ACTIVE
lv host undrain <host>               # only if it does not: it answered again without restarting
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

### Recovery priority

Set `migrate.priority` in compose (a whole number, default `0`; **higher goes
first**) to say which VMs matter most when there is not room for all of them:

```yaml
    migrate:
      on-host-failure: "restart-any"
      priority: 100
```

When a host is fenced, the coordinator recovers its VMs highest priority
first, ties in name order. The placement of every VM that needs one and each
reschedule's recovery claim and proof follow that order, and placement charges
each VM's CPU and memory before it places the next. So when the survivors can
hold only some of the failed host's VMs, the higher-priority ones are placed.

**The rest are not recovered later on their own.** They stay recorded on the
fenced host, reported like any VM no host can take: a `failover.skip` audit
entry naming the reason, and the `host.recovery.stalled` notification, which
names the VM and why. The coordinator decides a fenced host's recovery once,
so freeing capacity afterwards does not re-run it. Such a VM stays down until
one of these happens:

- the host comes back. A host whose daemon starts again — it boots after the
  fence powered it off, or its daemon is restarted — turns `active` on its
  own (after `upgrading`, once its daemon serves), with no
  `lv host undrain`. One that answers again without having restarted
  stays `fenced` or `offline` if failover moved anything off it, and
  `lv host undrain <host>` makes it active again;
- an operator promotes a replica of it, `lv replication promote <vm>`, once
  the host is proven powered off (`lv host fence-confirm <host>`);
- the host is gone for good, is fenced proof-grade, and is removed with
  `lv host rm --dead <host>` (try `--dry-run` first). With recovery claims on
  (the default), the coordinator then recovers the VMs still recorded on the
  removed host on every cycle, in the same priority order, so make room first
  and they are placed as it frees.

**Auto-promotion is not ordered against placement.** A VM enrolled in
auto-promote replication is promoted on the host holding its replica during the
same pass, before any VM is placed, and takes that host's memory whatever its
priority. Priority orders promotions among themselves, not against
reschedules: a priority-0 DR VM promoted onto a survivor can take room a
higher-priority VM would otherwise have been placed in.

Priority only orders work that is already allowed. Quorum, fencing, recovery
claims, capacity, placement constraints and the failure policy still decide
each VM on its own: a high-priority VM with `on-host-failure: none` is still
not restarted, and one whose proof a gate refuses is still refused.

The same order applies to `lv host drain`, which starts the moves highest
priority first, so `--parallel N` starts the N highest. Drain chooses every
VM's target before any move, each on its own, without reserving room for the
VMs chosen before it, so priority decides which move reaches a target first,
not which target a VM gets: a later VM can still find its target full and be
refused there. The order also applies to how a host starts the VMs failover
sends it; a start deferred from the host's last pass still goes ahead of new
ones.

A host's start pass has a time budget. A start that is still waiting when the
budget runs out is retried on a later pass, but only a start that was deferred
(its storage did not answer in time) is moved to the front of the next pass.
So a slow start that uses up the budget on every pass can keep the VMs after it
waiting, and with priority ordering those are the lowest-priority ones. This
predates priority ordering (before, it was whichever VMs the replica held
last) and is a tracked follow-up.

It does not order recovery
across hosts that fail together (each fenced host is recovered in turn),
`onboot` starts at host boot (`startup-order` does), failback or the
rebalancer.

Equal-priority VMs, which is every VM until you set one, are now recovered in
name order. Before this release they went in the order the coordinator's own
database replica held them, which was not always the same on every node, and
`migrate.priority` was stored but read by nothing.

**Mixed versions.** The value lives in the VM's stored spec, which every build
already replicates; no column, statement or protocol field was added. Only a
coordinator (or a draining or starting host) on this release orders by it. An
older one ignores it and recovers in its database order, as before, and the
safety checks are the same either way. Rely on the ordering once every host
that can hold the failover lease runs this release.

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
operator recovery). A container replicated on a schedule with `--auto-promote`
is placed on its **replica host** when placement accepts it and restored from
the newest replica there taken from the container being relocated, ahead of the
backup path above when the replica is newer (see
[backups.md](backups.md#container-replication)); when it comes back without its
replica (from a backup, its image, or on another host), the replicas it left are
set aside, never deleted by the next run; once it has moved,
its replication schedule replicates back to the host it left
([Reverse replication](backups.md#reverse-replication)). A **stopped** container is not relocated: it stays on the
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
  `nothing_recoverable` (a failed host with nothing on it to recover, recorded offline and not fenced),
  `confirmation_fence` (a host confirmed off during this outage, fenced afresh), `local_stall`,
  `joining` (a host `lv host add` admitted whose daemon has not started, never fenced),
  `partition_pause_wait` (recovery waiting out a partitioned host's pause, design/partition-pause.md),
  `quorum_regain` (a fence deferred because this node itself regained the voter majority moments ago),
  `retry_host_answered` (a failed fence not retried because an observer saw the host answer after it),
  `ha_disarmed` (a fence or recovery held because cluster HA is disarmed, or its policy cannot be read),
  `ha_peer_veto` (one held because a live voter's answer says HA is disarmed, or is stale or unknown),
  `no_quorum` with `phase="quorum"` and `result="refused"` (a fence or recovery held because this
  coordinator counted fewer than a majority of the decision's voters live at that moment; a lost
  lease is `lease_lost`),
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
- `litevirt_ha_disarmed` — `1` on every host whose replica says cluster HA is disarmed
  (`lv cluster ha`), or holds an HA policy it cannot read; `0` when armed
- `litevirt_ha_peer_veto` — `1` on the failover lease holder while its own replica says armed and a
  live voter's answer held a fence or a recovery back (condition `ha_disarm_peer_veto`); `0` otherwise
- `litevirt_peer_healthy` — `1` if a peer host is reachable, `0` otherwise (one series per peer)
- `litevirt_hlc_rejected_total` — count of remote HLC timestamps clamped due to clock skew
- `litevirt_replication_min_watermark_seq` — minimum `last_seq` across recently-acked peers; a value that stops advancing means some peer has stopped acknowledging. It is not the compaction floor: the prune additionally skips peers whose pushes are currently failing, so it can reclaim past a seq this gauge still sits on
- `litevirt_relay_role` — this node's relay election, one series per member (`member` label): `1` for a relay, `0` for a leaf. Every node elects from replicated state, so the series agree across nodes; a host the failover lease holder demoted for failing probes reads `0` everywhere until it is restored ([operating-model.md](operating-model.md#replication))
- `litevirt_relay_demoted` — `1` for each host (`member` label) the failover lease holder has demoted from relay duty for failing probes; absent for a host that is not demoted. `lv cluster relay-restore` lists the same with the reason
- `litevirt_relay_hold_seconds` — seconds left on each operator hold (`lv cluster relay-restore <host> --hold`); while it runs, the lease holder will not demote that host
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
