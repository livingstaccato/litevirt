# Design: single-file restore from backups

| | |
|---|---|
| Status | **Implemented** (`internal/filerestore`, `internal/grpcapi/file_restore.go`). |
| Reference | Proxmox Backup Server's `proxmox-file-restore` (a restore VM per session). |
| Surfaces | `lv backup file-ls`, `lv backup file-restore`; RPCs `ListBackupFiles`, `RestoreBackupFiles`. |

An operator who needs one file out of last night's backup should not have to
restore a 200 GiB disk to get it. This document is how litevirt reads files
out of a backup without the host ever mounting or parsing the backed-up
filesystem.

## 1. The rule

**The host never mounts or parses a guest filesystem or partition table.**
Not with `ro,nodev,nosuid,noexec`, not through a loop device or `qemu-nbd`,
not with libguestfs outside its appliance. A backup holds guest-controlled
bytes, and a malformed filesystem image is a known kernel attack surface:
mount options govern what the mounted tree may do, not what the kernel's
filesystem driver does while it parses the image.

So the filesystem is read where a parser bug costs nothing: inside a
throwaway VM. And what the VM sends back is treated as hostile, because a
guest kernel exploited by a malicious filesystem controls the agent.

## 2. The restore VM

```
 daemon (host, root)                             restore VM (qemu as its own per-session uid, seccomp, AppArmor)
 ───────────────────                             ──────────────────────────────────────────
 repo ── pbsstore.ManifestReader                   host kernel copy, initramfs:
    │      (decrypts, decompresses, verifies)        /init = this litevirt binary
    ▼                                                /modules/*.ko
 nbd.Server, unix socket in /run/litevirt/         ──► /dev/vda (read-only)
   file-restore/s-*/ (0711 dir, socket 0600            │ guest kernel parses the partition
   owned by the qemu user)                             │ table, mounts each fs read-only
 /dev/vhost-vsock, opened by the daemon ──fd 3──►  vhost-vsock ◄──── agent ◄─┘
 filerestore.Client ◄──────── vsock (hello: nonce) ────┘
  rebuilds a tar from the agent's records, bounded
    │
    ▼
 gRPC stream to the caller (tar)
```

- **Kernel.** The host's own (`/boot/vmlinuz-<release>`; `file_restore.kernel`).
  That image is usually root-only, so the daemon gives qemu a copy in its
  cache.
- **Boot files.** The kernel copy and the initramfs live in
  `/var/cache/litevirt-restore` — outside `/var/lib/litevirt`, which `lv host
  init`'s shared AppArmor abstraction lets every production qemu write —
  a directory that is `0750 root:litevirt-restore`. Each file is
  `0440 root:litevirt-restore`: qemu reads it through its group and can never
  write it. Beside each, a root-only `0600` sidecar records the sha256 the
  daemon wrote; every reuse re-hashes the file against it (and checks owner,
  group, mode and link count), and a file that does not match is reported
  (`file_restore.tampered` notification, an error log) and rebuilt before any
  restore VM boots it.
- **Initramfs.** Built by the daemon from the litevirt binary it runs
  (`/proc/self/exe`, a static `CGO_ENABLED=0` build — preflight refuses a
  dynamically linked one, naming it) plus the kernel modules the agent may
  need, resolved through `modules.dep` (`virtio_blk`, `vsock`,
  `vmw_vsock_virtio_transport`, `ext4`, `xfs`, `btrfs`, `vfat`, `isofs`, NLS)
  and decompressed on the host. It is cached under
  the boot-file cache above, keyed by a hash of every byte that goes into it
  (the whole binary, each module file, `modules.dep`). The binary becomes the
  agent only as PID 1 with `litevirt_filerestore=1` on the kernel command
  line.
- **Disk.** The backup, served by the in-process NBD server over a unix
  socket, attached as the VM's only disk, read-only at both the NBD client
  node and the format node.
- **No network.** `-nodefaults -nic none -display none`: no NIC, no default
  devices, no monitor. The only channel is one `vhost-vsock-pci` device, on a
  file descriptor the daemon opened and hands qemu, with a random CID.
- **Fixed resources.** One vCPU, `file_restore.memory_mib` (512 MiB default:
  the initramfs carries the litevirt binary).
- **qemu's identity.** File restore needs a root daemon; a non-root one
  refuses it (unless `allow_unsandboxed: [root]`: qemu would run as the
  daemon's own user, which owns `data_dir` and its keys). Each restore VM runs
  as **its own uid**, taken from 64 reserved ones (`file_restore.uid_base`,
  default 3800000000), with the group `litevirt-restore` only — never an
  account's supplementary groups, and never `kvm`. KVM is given to the
  session's uid by a POSIX ACL entry on `/dev/kvm`, set when the uid is
  handed out and removed when it is released; a starting daemon removes any
  a daemon that died left behind. Not `kvm`, because libvirt's qemu creates
  group-writable sockets as `libvirt-qemu:kvm` — among them the pull-mode
  backup's NBD export of a live guest disk (`0775` in a `0777` directory) and
  each domain's monitor — and Landlock does not mediate `connect()` to a
  pathname unix socket: DAC is what keeps a restore qemu out of them. So
  concurrent sessions, which may be different tenants' backups, cannot
  signal, trace or open each other's files whatever the LSM. The reserved
  uids are checked, before sessions start, to be no one else's: not in the
  containers' id-map range (`containers.idmap_base`, `idmap_ranges`; an
  explicit `uid_base` there refuses to load the config), not in any
  `/etc/subuid` or `/etc/subgid` range (Incus, podman, LXC), and no account
  NSS knows (`getent passwd`, so LDAP, sssd and systemd's dynamic users count;
  a lookup that fails refuses). A uid is handed to a session only when no
  process runs as it: one left over from an earlier session (a qemu that
  left its process group) is killed and the uid skipped. Closing a session
  kills anything still running as its uid. The
  `litevirt-restore` account exists for its group (which reads the boot files)
  and is created at daemon start (`useradd --system --user-group`, nologin,
  no other group); an existing account of that name is used only if it is a
  system uid with a nologin shell, a uid no one else has and no group but its
  own and `kvm` (which earlier builds gave it; no restore VM gets it). `libvirt-qemu`, `qemu`, `nobody` and root as `run_as` are refused unless
  `allow_shared_run_as`, which then runs qemu as that user. The credential is
  set in the child before exec; qemu never switches users itself, so its
  seccomp sandbox (`elevateprivileges=deny`) and the drop do not conflict.
- **The disk export is single-peer.** Each start attempt gets its own NBD
  socket in the session directory, chowned to the VM's uid. The server vets
  the first connection — `SO_PEERCRED`: the VM's uid, the VM's process group,
  and under AppArmor the restore profile in enforce mode — and only then
  serves it; it closes its listener and unlinks the socket at once, so no
  second client (another session's qemu included) can ever connect. qemu's
  NBD client has `reconnect-delay: 0`. The nonce file (the VM's uid, 0400) is
  unlinked once the agent has answered.
- **AppArmor, failing closed.** Where AppArmor is enabled, the daemon loads
  the `litevirt-restore-qemu` profile from memory (`apparmor_parser -r`,
  nothing under `/etc`, verified loaded in enforce mode). Enabled but no
  parser loads nothing, so the host has exactly the barriers of one with
  AppArmor off: with Landlock it runs under Landlock (a warning names the
  missing parser), without Landlock it is refused unless
  `allow_unsandboxed: [mac]`. The profile grants qemu's binary,
  libraries and firmware, `/dev/kvm`, `/dev/vhost-vsock` (needed: AppArmor
  revalidates the inherited vhost fd at exec against the new profile), the
  boot files, the sessions' sockets and nonce files (DAC narrows them to its
  own uid, and both are gone once qemu has them), a few of its own `/proc`
  files (owner: only its own session's uid), stream unix sockets to the
  unconfined daemon — no abstract sockets, no IP networking, no ptrace, no
  mount, nothing of `/var/lib/litevirt` or any VM disk. qemu starts through a
  trampoline in the litevirt binary (`litevirt __file-restore-exec`, as the
  VM's uid): its parent stage stays as qemu's parent; its exec stage locks its
  OS thread, writes the on-exec profile to `/proc/thread-self/attr`, sets
  no_new_privs, applies the Landlock ruleset (below) and execs qemu, which
  starts confined. The daemon checks the
  result twice — the NBD peer must carry the profile before it is served, and
  the qemu holding the disk must still carry it after the hello — and kills
  and refuses otherwise. Two stages because AppArmor's on-exec profile is per
  thread and not inherited by a forked child, and because the exec into a new
  profile is a secure exec, across which the kernel clears the parent-death
  signal: the parent stage keeps its own (SIGTERM from the daemon's death) and
  kills qemu on it; on qemu 9.1+ qemu also gets `-run-with
  exit-with-parent=on`.
  The profile does not separate one session from another by itself (every
  restore qemu carries it, and `abstractions/base` lets processes of one
  profile signal each other): the per-session uid does that.
- **Landlock, on every host that has it.** The trampoline's exec stage, after
  no_new_privs, restricts itself with a Landlock ruleset and then execs qemu,
  so qemu starts inside it and cannot leave it. Landlock is unprivileged and
  stacks with AppArmor and SELinux, so it applies whatever the host's LSM.
  It handles every filesystem right the kernel's ABI knows and grants only:
  read and execute of qemu's binary, `/usr`, `/lib*`, `/bin`, `/sbin`; read of
  `/etc/ld.so.cache`, the boot files and their cache, the session's own
  directory, qemu's own `/proc/<pid>`, a few `/proc/sys` and `/sys` files and
  `/dev/urandom`; read-write of `/dev/kvm` and `/dev/null`. No other file:
  not `/var/lib/litevirt` or any VM disk — which `lv` and libvirt may leave
  world-readable — not `data_dir`, not another session's directory, no
  writes anywhere. With Landlock ABI 4 (Linux 6.7) every TCP bind and connect
  is refused; with ABI 6 (Linux 6.12) abstract unix sockets and signals to
  processes outside the ruleset are refused too; older ABIs give the
  filesystem part only. Three things are outside every Landlock ABI:
  - **`connect()` to a pathname unix socket.** It is a filesystem object
    Landlock does not mediate; DAC governs it, which is why the restore
    qemu's uid holds no group but `litevirt-restore` (above). AppArmor's
    profile also allows unix connects only to the unconfined daemon.
  - **UDP.** qemu's seccomp sandbox filters no socket calls. Under a root
    daemon qemu runs in a network namespace of its own (below), which has no
    interface but a down loopback; AppArmor's `deny network` covers it too.
  - **The inherited vhost-vsock fd**, opened by the daemon before the
    ruleset: the VM's one channel to the host, by design.

  The exec stage checks
  the ruleset took (the root directory must be unreadable) and exits
  otherwise, so qemu never starts unrestricted. The vhost-vsock fd qemu
  inherits was opened before the ruleset and is unaffected. The
  `landlock=<abi>` in each audit row says which ABI applied.
- **A network namespace of its own.** Under a root daemon the restore qemu
  (with its trampoline) is started in a new network namespace, created as
  root before the credential change. It holds only a loopback interface, which
  is down: no UDP, TCP or abstract unix socket of the host is reachable,
  whatever the Landlock ABI. Pathname unix sockets (the session's NBD export)
  are filesystem objects and still connect, and the vhost-vsock fd belongs
  to the daemon's namespace.
- **Hosts without AppArmor** (SELinux, or no LSM): Landlock is the MAC
  barrier. What isolates a restore VM there is its own uid (DAC between
  sessions), the Landlock ruleset (against every host file outside its
  allowlist, world-readable or not, and TCP as the ABI allows), its network
  namespace (UDP and the rest of the network, on every ABI), its seccomp
  sandbox (`elevateprivileges`, `spawn`, `obsolete`,
  `resourcecontrol` denied), the single-peer export, and the absence of any
  NIC. **With neither AppArmor nor Landlock** (a kernel without
  `CONFIG_SECURITY_LANDLOCK`, or `landlock` missing from `lsm=`), nothing but
  DAC would stand between an escaped qemu and world-readable VM disks, so
  file restore is refused unless
  `allow_unsandboxed: [mac]`. A restore qemu inherits the daemon's SELinux
  domain; no SELinux policy is shipped.
- **Seccomp, asked of qemu.** Before each restore VM, the daemon starts the
  qemu binary with the sandbox and no machine (`-machine none -S`), as the
  restore user. A qemu that cannot install the sandbox exits at once with its
  own message; one that can is still running after a moment and is killed.
  Without the sandbox, file restore is refused with qemu's message, unless
  `file_restore.allow_unsandboxed: [seccomp]` — **dangerous**: it removes the barrier
  between an escaped guest and every syscall the qemu user has; install a qemu
  with seccomp instead — decided for each VM, never remembered.
- **Console.** The guest's serial console goes to qemu's stdout, into a
  64 KiB in-memory ring. Nothing the guest writes lands on the host's disk;
  its escaped tail only ever reaches an error message.
- **Lifetime.**
  - qemu is started with a parent-death SIGKILL, which Go applies after the
    credential change, in its own process group: it dies with the daemon.
  - Each session has a pidfile (pid and uid) in `/run/litevirt/file-restore/s-*/`
    (outside `data_dir`). A starting daemon holds each named process by a
    pidfd, kills it — and its process group — only if it still runs as that
    uid with the restore VM's command line for that very session (`-name
    litevirt-file-restore` and that session's socket path), never a recycled
    pid, and removes the directories. It also kills any process running as one
    of the reserved per-session uids, whatever its command line says (a
    process can rewrite its own argv), which finds a qemu whose trampoline —
    and so its pidfile record — is gone. The range sessions last used is
    recorded in the run directory and swept too, so changing `uid_base`
    leaves no survivor in the old one. A range that is not verified exclusive
    (see qemu's identity above) is swept only for processes with a restore
    VM's command line, and the conflict is logged.
  - The agent powers the VM off on its own after `idle_timeout_sec + 60`
    seconds without a request (`litevirt_fr_idle` on the command line), the
    backstop for a host that went away.
  - A browsing session (`file-ls`) keeps its VM for
    `file_restore.idle_timeout_sec` (300 s) after its last use. Each
    extraction boots a VM of its own — never the cached browsing one, which
    another caller may be using — killed when it completes, when the caller
    goes away, or at its wall clock (ten minutes, or the byte limit at
    1 MiB/s if longer).
  - At most `file_restore.max_sessions` (2) VMs run per host, at most
    `file_restore.max_extractions` (1) of them extracting. A slot is reserved
    before a boot and no lock is held while a VM boots; concurrent callers for
    one backup share one boot.
- **The right VM.** A random nonce, handed to the guest over fw_cfg from a
  file only the restore user can read (never on qemu's command line, which
  every host user can read), must come back from the agent's hello before
  anything else is sent, so a foreign VM that happened to hold the CID is
  never mistaken for the session's own. A hello that does not answer within
  5 s (or the boot deadline) is dropped.

Inside the VM the agent mounts `proc`, `sys` and `devtmpfs`, loads the
modules, waits for `/dev/vda`, sets it read-only, and mounts each partition
the guest kernel found — or the whole disk when there is no partition table —
read-only with `nosuid,nodev,noexec` and no journal replay (`noload`,
`norecovery`, `rescue=nologreplay`). It then serves the protocol below on
vsock port 5000.

## 3. What the restore VM is given

| Backup | qemu reads it as | Agent |
|---|---|---|
| VM, guest content (a running VM, read over NBD) | `raw` | mounts partitions / whole disk |
| VM, disk file (a stopped VM's qcow2) | `qcow2` with `backing: null` | same |
| Container (`lv ct backup`) | `raw` | indexes the tar archive |

A disk-file backup is judged on the host first, from its first 64 KiB (the
same header check every image import gets: `qcow2.AssertStandaloneHeader`).
Only a standalone qcow2 is accepted, so qemu never opens a file the header
names, and `backing: null` makes that hold even if the check were wrong. An
overlay's backup (`base_identity` set) is refused with "restore the disk
instead". Guest bytes that look like a qcow2 header in a guest-content
backup change nothing: its format comes from the manifest.

A container backup is the tar archive `lv ct backup` wrote. The agent — in
the VM — indexes it once (headers only: it seeks past file data) and reads
each file in place; `/rootfs` is the container's root filesystem.

## 4. Protocol (`internal/filerestore/wire`)

One JSON request per line, one JSON response per line: `hello` (returns the
nonce), `volumes`, `list`, `tar`, `shutdown`. Paths are `/<volume>/<path>`;
`/` lists the volumes.

A listing reply is decoded entry by entry, keeping at most 10 000: what a
hostile agent packs into the (8 MiB) line beyond that is skipped while
decoding, never materialized.

An extraction is **not** sent as tar. The agent sends records: one JSON line
(name, type, size, mode, mtime, link target; at most 16 KiB) followed by
exactly `size` bytes for a regular file, and an end record. tar's extensions
— PAX records, GNU sparse maps whose holes a tar reader synthesizes as zeros,
long-name headers — are parsing surface and expansion a hostile agent could
use, so no tar reader runs on the host; the daemon writes the tar itself.

The agent never follows a symlink: a symlink is listed and sent as a
symlink, and a path through one is refused. It sends only directories,
regular files and symlinks, and stops at the byte and entry limits the host
sends.

## 5. Everything that comes back is untrusted

The host (`filerestore/sanitize.go`) treats every response as hostile:

- **Listings**: names must be a single valid component (no `/`, NUL, `.`,
  `..`), UTF-8, at most 255 bytes, unique; at most 10 000 entries; unknown types
  become `other`; mode is permission bits only; a symlink target is bounded
  and shown, never followed.
- **Extractions**, record by record:
  - a name must be relative, already clean, without `..`, at most 256
    components, every component valid, UTF-8 with no control, bidi or
    invisible character, bounded, and inside one of the paths the caller
    selected;
  - only directories, regular files and symlinks;
  - a symlink only with a relative target whose `..` components, if any, all
    come first, and that, resolved against the link's directory, stays inside
    the archive; any other is left out and counted (`links_dropped` in the
    audit row and the status). The leading-`..` rule is what makes the check
    hold physically: the kernel resolves a symlink component before a `..`
    after it, so `up/../../..` through a link `up` climbs further than its
    spelling; with `..` only first, the climb starts at the link's own
    directory (never under a link), and by induction no chain of links leaves
    the archive;
  - no entry below a symlink the archive already holds and no name twice —
    both compared with Unicode case folding and NFC normalization ("ſ" is "s",
    "ς" is "σ"), so extracting the archive on a case-insensitive or
    normalizing filesystem (macOS, Windows) cannot write through a link either;
    each name is folded once and walked down a trie of the archive's symlink
    paths, so the check costs the name's length, whatever the depths of the
    links. The trie is one flat map from (parent node, hash of component) to
    a node, holding no string of the guest's, capped at 65 536 nodes and
    16 384 links (about 3 MB); past either cap the extraction stops at the
    limit, as for bytes. A hash collision can only make a name look as if it
    were under a link and be refused, never the reverse;
  - each tar header is built from scratch: permission bits without setuid,
    setgid or sticky, no owner, no extended attributes;
  - bounded: the whole archive's bytes, headers included
    (`file_restore.max_extract_bytes`, 16 GiB; a request may only lower it) —
    a size is compared against what is left, never added, so it cannot
    overflow, and the bytes counted are the bytes written; refused entries' bytes (read to stay in step) under the same
    cap; entries (200 000); records read, refused ones included; the names
    remembered for the checks above, each as a fixed 16-byte key, so an
    extraction's memory does not grow with name length; each record line;
  - a stream that ends inside a file is an error, not a short file passed
    off as whole; every read must make progress within 60 s.
- **Text** — names printed by the CLI, agent errors, console tails — is
  escaped: C0 and C1 controls, DEL, bidi and invisible formatting characters,
  invalid UTF-8.
- **Output** is streamed to the caller as a tar archive over gRPC. The daemon
  writes nothing to any host path the guest's data named; the CLI writes only
  the archive file the operator named with `-o`, and only if it does not exist
  yet.

## 6. Permission and audit

`ListBackupFiles` and `RestoreBackupFiles` authorize exactly as a full
restore of the same backup does (`authorizeVMRestore`,
`authorizeContainerRestore`): `backup.restore` on the backup's own project as
its manifest records it (legacy floor `operator`), the admin role for a
custom absolute repo path. Every extraction writes one audit row,
`backup.file_restore`, with the project, repo, timestamp, disk, selected paths
and what was extracted (entries, bytes, refused entries, whether a limit cut
it short), and what isolated its restore VM (`sandbox=on|off
apparmor=on|off|absent landlock=<abi>|off uid=<n>`). The row is written
once the extraction has ended, whether or not the client is still connected
(it usually closes its stream as soon as it has the archive). A refused one
is audited `denied`. Listing is a read and is not audited, as for
`ListBackupRepoSnapshots` — except that any restore VM started without one of
its barriers (no seccomp sandbox, no MAC, or a shared or the daemon's own
uid), for browsing or extracting, writes a `backup.file_restore_unsandboxed`
row with the same barrier summary. While `file_restore.allow_unsandboxed` or
`allow_shared_run_as` is set, the host also carries an informational
`file_restore_unsandboxed` health condition
([diagnostics](../diagnostics.md#file-restore-unsandboxed-file_restore_unsandboxed)).

## 7. When it cannot run

Before every session the daemon checks: `/dev/kvm` grantable to the
per-session uids (it takes POSIX ACLs, or is world read-write already),
`/dev/vhost-vsock` openable, the kernel readable, its `modules.dep` present
with a virtio disk, a vsock transport and `qemu_fw_cfg` (built in or as
modules; Ubuntu ships `qemu_fw_cfg` in `linux-modules-extra-<release>`, which
the refusal names), a qemu binary, and a statically linked agent. A failure
refuses file restore with `FailedPrecondition` naming the cause, e.g. `kernel
modules in /lib/modules/6.8.0-139-generic have no qemu_fw_cfg … (on Ubuntu:
linux-modules-extra-6.8.0-139-generic)`, or
`this qemu has no seccomp sandbox … file_restore.allow_unsandboxed: [seccomp]
permits it`.
There is no fallback to a host mount. A full restore (`restore-from`,
`restore-live`, `lv ct restore`) is unaffected. `file_restore.enabled: false`
turns the feature off.

Extract each archive into a new, empty directory: the checks above hold
within one archive, and two archives of one backup extracted into the same
directory could otherwise meet a symlink of the first with a path of the
second (only in-archive relative links pass, which narrows it to the
directory itself).

## 8. Not supported

- LVM, LUKS, ZFS, md-raid and multi-device btrfs inside a backup: the agent
  mounts plain filesystems on a disk or its partitions.
- An overlay disk-file backup (a linked clone or image-backed disk backed up
  while stopped): it holds only the delta.
- Windows filesystems (NTFS) are not in the module list.
- Browsing through the WebUI; the CLI and RPCs only.

## 9. Testing

- `internal/filerestore`: the sanitizer against hostile record streams
  (unsafe names, types, writes through a symlink — case- and
  normalization-folded — setuid, a size that would overflow the cap,
  unbounded refused data, a sparse tar sent instead of records, the
  name-tracking bound, malformed and truncated streams, record floods); the
  client (stalls, the nonce, escaped errors); the initramfs (parsed back as
  the kernel does; the key covers every byte; 0400 files, 0711 directory,
  rebuilt when tampered); qemu's command line (no NIC, read-only, no backing,
  vsock on fd 3, console on stdio, sandbox, no user switch); the launcher
  against a fake qemu (seccomp refusal, per-attempt unsandboxed fallback, CID
  retries, the console flood stays in memory, nothing left behind); the
  stale-VM sweep (kills only a verified restore VM); qemu's credential and
  death signal.
- `vm_boot_linux_test.go` boots real restore VMs (GPT ext4, whole-disk xfs as
  qcow2, a container archive), checks from `/proc` that qemu is the
  unprivileged qemu user with a seccomp filter (as root), that the host's
  mounts of nbd/loop/virtio devices did not change, and that no VM or session
  directory is left. Without its environment it skips with a message saying
  what is missing; `make test-filerestore-vm` runs it.
- `internal/grpcapi/file_restore_test.go`: RBAC and audit, the refusals, the
  format decisions, browse-session reuse, fresh extraction VMs, the idle
  timeout, session and extraction caps, boots not serializing, the
  extraction wall clock, cancellation.
- `tests/e2e/backup_file_restore_test.go`: a real VM's backup on the lab,
  including qemu's user and seccomp on the node and a daemon restart in the
  middle of a session.
