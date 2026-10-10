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
filesystem driver does while it parses the image. A guest that has been
compromised controls its own disk, and with it what a host that mounts that
disk would parse.

So the filesystem is read where a parser bug costs nothing: inside a
throwaway VM.

## 2. The restore VM

```
 daemon (host)                                  restore VM
 ─────────────                                  ──────────
 repo ── pbsstore.ManifestReader                 host kernel, initramfs:
    │      (decrypts, decompresses, verifies)      /init = this litevirt binary
    ▼                                              /modules/*.ko
 nbd.Server on a unix socket ──► qemu ──► /dev/vda (read-only)
  (0700 session dir, 0600 socket)                    │ guest kernel parses the
                                                     │ partition table and mounts
 filerestore.Client ◄──── vsock ────► agent ◄────────┘ each filesystem read-only
  sanitizes every answer
    │
    ▼
 gRPC stream to the caller (tar)
```

- **Kernel.** The host's own (`/boot/vmlinuz-<release>`), so nothing has to be
  installed or kept in step. `file_restore.kernel` overrides it.
- **Initramfs.** Built by the daemon from the litevirt binary it is running
  (`/proc/self/exe`, a static `CGO_ENABLED=0` build) plus the kernel modules
  the agent may need, resolved through `modules.dep` (`virtio_blk`, `vsock`,
  `vmw_vsock_virtio_transport`, `ext4`, `xfs`, `btrfs`, `vfat`, `isofs`, NLS
  tables) and decompressed on the host, so the guest does not depend on
  in-kernel module decompression. It is cached under
  `<data_dir>/file-restore/cache` (0600) and rebuilt when the binary, the
  kernel or the module list changes. The binary decides it is the agent only
  as PID 1 with `litevirt_filerestore=1` on the kernel command line (the
  kernel passes unknown `name=value` parameters to init as environment).
- **Disk.** The backup, served by the in-process NBD server over a unix
  socket inside a 0700 per-session directory, attached as the VM's only disk,
  read-only at both the NBD client node and the format node.
- **No network.** `-nodefaults -nic none`: no NIC, no default devices, no
  monitor, no display. The only channel is one `vhost-vsock-pci` device with a
  random CID.
- **Fixed resources.** One vCPU, `file_restore.memory_mib` (512 MiB default:
  the initramfs carries the litevirt binary).
- **qemu's own confinement.** `-sandbox on,obsolete=deny,elevateprivileges=deny,
  spawn=deny,resourcecontrol=deny`, and when the daemon runs as root, qemu
  drops to `libvirt-qemu` / `qemu` / `nobody` (`file_restore.run_as`) once its
  files are open. qemu is started with `Pdeathsig=SIGKILL` in its own process
  group, so it dies with the daemon.
- **Lifetime.** A browsing session (`file-ls`) keeps its VM for
  `file_restore.idle_timeout_sec` (300 s) after its last use, so walking a
  tree boots once; an extraction kills its VM when it completes. At most
  `file_restore.max_sessions` (2) run per host. A daemon restart sweeps the
  session directories of VMs that died with the previous process.

Inside the VM the agent mounts `proc`, `sys` and `devtmpfs`, loads the
modules, waits for `/dev/vda`, sets it read-only, and mounts each partition
the guest kernel found — or the whole disk when there is no partition table —
read-only with `nosuid,nodev,noexec` and no journal replay (`noload`,
`norecovery`, `rescue=nologreplay`). It then serves the protocol below on
vsock port 5000 and powers off when the host asks or when anything fails.

## 3. What the restore VM is given

| Backup | qemu reads it as | Agent |
|---|---|---|
| VM, guest content (a running VM, read over NBD) | `raw` | mounts partitions / whole disk |
| VM, disk file (a stopped VM's qcow2) | `qcow2` with `backing: null` | same |
| Container (`lv ct backup`) | `raw` | indexes the tar archive |

A disk-file backup is judged on the host first, from its first 64 KiB (the
same header check every image import gets: `qcow2.AssertStandaloneHeader`).
Only a standalone qcow2 is accepted: one naming a backing file or an
external data file is refused, so qemu never opens a file the header names,
and `backing: null` makes that hold even if the check were wrong. An overlay's
backup (`base_identity` set) holds only the delta over its base and is refused
with "restore the disk instead". Guest bytes that happen to look like a qcow2
header in a guest-content backup change nothing: its format comes from the
manifest, never from the bytes.

A container backup is the tar archive `lv ct backup` wrote. The agent indexes
it once (headers only: it seeks past file data) and reads each file in place;
`/rootfs` is the container's root filesystem.

## 4. Protocol

One JSON request per line, one JSON response per line (`volumes`, `list`,
`tar`, `shutdown`). A successful `tar` response is followed by one tar archive.
Paths are `/<volume>/<path>`; `/` lists the volumes.

The agent never follows a symlink: a symlink is listed and archived as a
symlink, and a path through one is refused. It writes only directories,
regular files and symlinks, and stops at the byte and entry limits the host
sends.

## 5. Everything that comes back is untrusted

A compromised guest kernel or agent can answer anything, so the host
(`filerestore/sanitize.go`) treats every response as hostile:

- **Listings**: names must be a single valid component (no `/`, NUL, `.`,
  `..`), UTF-8, at most 255 bytes, unique; at most 10 000 entries; unknown types
  become `other`; mode is permission bits only; a symlink target is bounded
  and shown, never followed.
- **Archives** are not passed through, they are re-encoded entry by entry:
  - a name must be relative, already clean, without `..`, every component
    valid, UTF-8, bounded, and inside one of the paths the caller selected;
  - only directories, regular files and symlinks — no hard links, devices or
    fifos;
  - no entry below a symlink the archive already holds and no name twice, so
    extracting the result cannot write through a link the backup carried;
  - each header is rebuilt from scratch: permission bits without setuid,
    setgid or sticky, no owner, no xattrs or PAX records from the guest;
  - total bytes (`file_restore.max_extract_bytes`, 16 GiB; a request may only
    lower it), entries (200 000) and headers read, refused ones included, are
    bounded; an archive cut short is an error, not a short file passed off
    as whole.
- **Protocol lines** are bounded (8 MiB); an agent error string is bounded
  and stripped of control characters before it reaches the caller.
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

The daemon checks, before anything starts: `/dev/kvm` openable,
`/dev/vhost-vsock` present, the kernel readable, its `modules.dep`
present with a virtio disk and a vsock transport (built in or as modules),
and a qemu binary. A failure refuses file restore with `FailedPrecondition`
naming the cause, e.g. `no usable KVM (/dev/kvm: …)` or `no /dev/vhost-vsock
(load the vhost_vsock kernel module)`. There is no fallback to a host mount.
A full restore (`restore-from`, `restore-live`, `lv ct restore`) is unaffected.
`file_restore.enabled: false` turns the feature off.

## 8. Not supported

- LVM, LUKS, ZFS, md-raid and multi-device btrfs inside a backup: the agent
  mounts plain filesystems on a disk or its partitions. They are listed as
  missing volumes; restore the disk instead.
- An overlay disk-file backup (a linked clone or image-backed disk backed up
  while stopped): it holds only the delta. A running VM's backup of the same
  disk is guest content and works.
- Windows filesystems (NTFS) are not in the module list.
- Browsing through the WebUI; the CLI and RPCs only.

## 9. Testing

- `internal/filerestore`: the protocol in-process against directories and
  archives (no symlink followed, container offsets, limits), the sanitizer
  against hostile archives (absolute and `..` names, links, devices, setuid,
  xattrs, writes through a symlink, truncation, header floods), the initramfs
  (parsed back as the kernel does: `/init`, `/dev/console`, module order),
  qemu's command line (no NIC, read-only, no backing, vsock, sandbox).
- `vm_boot_linux_test.go` boots real restore VMs (GPT ext4, whole-disk xfs as
  qcow2, a container archive) and checks the host's mount table did not
  change and no VM or session directory is left. It needs KVM and a readable
  kernel, so it runs only with `LITEVIRT_FR_KERNEL` and `LITEVIRT_FR_AGENT`.
- `internal/grpcapi/file_restore_test.go`: RBAC and audit, the refusals, the
  format decisions, session reuse, the idle timeout and the session cap.
- `tests/e2e/backup_file_restore_test.go`: a real VM's backup on the lab.
