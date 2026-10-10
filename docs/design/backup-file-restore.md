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
 daemon (host, root)                             restore VM (qemu as libvirt-qemu, seccomp)
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
  cache, mode 0400, owned by the qemu user.
- **Initramfs.** Built by the daemon from the litevirt binary it runs
  (`/proc/self/exe`, a static `CGO_ENABLED=0` build — preflight refuses a
  dynamically linked one, naming it) plus the kernel modules the agent may
  need, resolved through `modules.dep` (`virtio_blk`, `vsock`,
  `vmw_vsock_virtio_transport`, `ext4`, `xfs`, `btrfs`, `vfat`, `isofs`, NLS)
  and decompressed on the host. It is cached under
  `<data_dir>/file-restore/cache` (0711 directory; file 0400, owned by the
  qemu user), keyed by a hash of every byte that goes into it (the whole
  binary, each module file, `modules.dep`), and rebuilt whenever the file on
  disk is not exactly as written (owner, mode, link count). The binary
  becomes the agent only as PID 1 with `litevirt_filerestore=1` on the kernel
  command line.
- **Disk.** The backup, served by the in-process NBD server over a unix
  socket, attached as the VM's only disk, read-only at both the NBD client
  node and the format node.
- **No network.** `-nodefaults -nic none -display none`: no NIC, no default
  devices, no monitor. The only channel is one `vhost-vsock-pci` device, on a
  file descriptor the daemon opened and hands qemu, with a random CID.
- **Fixed resources.** One vCPU, `file_restore.memory_mib` (512 MiB default:
  the initramfs carries the litevirt binary).
- **qemu's confinement.** As root, the daemon starts qemu already as the
  unprivileged qemu user (`file_restore.run_as`: `libvirt-qemu`, `qemu` or
  `nobody`; never root) with that user's groups — the credential is set in the
  child before exec. qemu never switches users itself, so its seccomp sandbox
  (`-sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,
  resourcecontrol=deny`) and the user drop do not conflict. The qemu user needs
  only read-write `/dev/kvm` (normally via the `kvm` group); preflight checks
  it by mode bits and names the gap.
- **Console.** The guest's serial console goes to qemu's stdout, into a
  64 KiB in-memory ring. Nothing the guest writes lands on the host's disk;
  its escaped tail only ever reaches an error message.
- **Lifetime.**
  - qemu is started with a parent-death SIGKILL, which Go applies after the
    credential change, in its own process group: it dies with the daemon.
  - Each session has a pidfile in `/run/litevirt/file-restore/s-*/` (outside
    `data_dir`). A starting daemon kills any process named in one whose
    command line is the restore VM of that very session (`-name
    litevirt-file-restore` and that session's socket path) — never a
    recycled pid — and removes the directories.
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
- **The right VM.** A random nonce on the kernel command line must come back
  from the agent's hello before anything else is sent, so a foreign VM that
  happened to hold the CID is never mistaken for the session's own.
- **No seccomp.** A qemu built without seccomp is refused, naming the cause,
  unless `file_restore.allow_unsandboxed: true`; that is decided for each VM,
  never remembered.

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
  - a name must be relative, already clean, without `..`, every component
    valid, UTF-8, bounded, and inside one of the paths the caller selected;
  - only directories, regular files and symlinks;
  - no entry below a symlink the archive already holds and no name twice —
    both compared case-folded and NFC-normalized, so extracting the archive on
    a case-insensitive or normalizing filesystem (macOS) cannot write through a
    link either;
  - each tar header is built from scratch: permission bits without setuid,
    setgid or sticky, no owner, no extended attributes;
  - bounded: file bytes (`file_restore.max_extract_bytes`, 16 GiB; a request
    may only lower it) — a size is compared against what is left, never
    added, so it cannot overflow, and the bytes counted are the bytes
    written; refused entries' bytes (read to stay in step) under the same
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
it short); a refused one is audited `denied`. Listing is a read and is not
audited, as for `ListBackupRepoSnapshots`.

## 7. When it cannot run

Before every session the daemon checks: `/dev/kvm` read-write for the qemu
user, `/dev/vhost-vsock` openable, the kernel readable, its `modules.dep`
present with a virtio disk and a vsock transport (built in or as modules), a
qemu binary, and a statically linked agent. A failure refuses file restore
with `FailedPrecondition` naming the cause, e.g. `no usable KVM for qemu user
libvirt-qemu: /dev/kvm (mode 600, owner 0:0) is not read-write`, or
`this qemu has no seccomp sandbox … set file_restore.allow_unsandboxed`.
There is no fallback to a host mount. A full restore (`restore-from`,
`restore-live`, `lv ct restore`) is unaffected. `file_restore.enabled: false`
turns the feature off.

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
