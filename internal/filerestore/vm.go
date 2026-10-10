package filerestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
)

// ErrUnavailable wraps every reason a restore VM cannot be started on this
// host (no KVM, no kernel, no qemu, no vhost-vsock, no seccomp sandbox).
// File restore is then refused with that reason; a full restore is
// unaffected.
var ErrUnavailable = errors.New("file restore unavailable on this host")

// BlockDevice is what a session exposes to the restore VM as its disk.
type BlockDevice interface {
	io.ReaderAt
	Size() int64
}

// TamperFunc is told about a boot file in the cache that no longer matches
// what was written (path, and why); the file is rebuilt before use.
type TamperFunc func(path, why string)

// DefaultRestoreUser is the dedicated user restore VMs run as: it owns
// nothing — no VM disk, no key — and is in the kvm group only.
const DefaultRestoreUser = "litevirt-restore"

// DefaultUIDBase is the first of the reserved uids restore VMs run as, one
// per session (UIDSlots of them): above the container id-map ranges, below
// the 32-bit limit, and never in /etc/passwd.
const DefaultUIDBase = 3_800_000_000

// UIDSlots is how many per-session uids are reserved from the base.
const UIDSlots = 64

// AppArmorProfile is the profile a restore VM's qemu is confined by where
// AppArmor is enabled.
const AppArmorProfile = "litevirt-restore-qemu"

// TrampolineArg is the hidden first argument with which the litevirt binary
// sets its AppArmor exec profile and execs qemu (agent.RunTrampoline).
const TrampolineArg = "__file-restore-exec"

// Config is the host side of file restore (daemon config `file_restore:`).
type Config struct {
	// QEMU is the qemu system emulator ("" = search the usual names).
	QEMU string
	// Kernel is the kernel the restore VM boots ("" = this host's own,
	// /boot/vmlinuz-<release>).
	Kernel string
	// ModulesDir holds that kernel's modules ("" = /lib/modules/<release>).
	ModulesDir string
	// MemoryMiB is the restore VM's memory (0 = 512). The initramfs holds
	// the litevirt binary, so this cannot go much lower.
	MemoryMiB int
	// RunAs is the restore account ("" = DefaultRestoreUser): a system
	// account with no shell whose group reads the boot files. Each restore VM
	// runs as its own uid from the reserved range (UIDBase), with that group
	// and kvm only, so concurrent sessions cannot reach each other. root,
	// libvirt-qemu, qemu and nobody are refused unless AllowSharedRunAs, which
	// then runs qemu as that user itself.
	RunAs string
	// UIDBase is the first reserved per-session uid (0 = DefaultUIDBase).
	UIDBase uint32
	// AllowSharedRunAs permits RunAs to be root or a shared qemu user.
	// DANGEROUS: the restore VM then shares an identity with production VMs
	// or with everything.
	AllowSharedRunAs bool
	// CacheDir holds the initramfs and kernel copy: root-owned, group the
	// restore user's, 0440, re-verified on every use
	// (/var/cache/litevirt-restore).
	CacheDir string
	// OnTamper is told about a cache file that failed verification.
	OnTamper TamperFunc
	// RunDir holds each session's NBD socket and pidfile — outside
	// data_dir (/run/litevirt/file-restore for a root daemon). Nothing the
	// guest writes lands in it.
	RunDir string
	// BootTimeout bounds boot until the agent answers (0 = 60s).
	BootTimeout time.Duration
	// AgentIdle is how long the agent in the VM waits for a request before
	// it powers off on its own (0 = 10 minutes): the backstop when the
	// daemon that started it is gone.
	AgentIdle time.Duration
	// AllowUnsandboxed lets a restore VM run without one of its barriers:
	// qemu's seccomp sandbox, the AppArmor profile on a host that has
	// AppArmor enabled but cannot load it, or a root daemon (a non-root
	// daemon runs qemu as itself). DANGEROUS: each removes a barrier between a
	// malicious backup and the host. Off by default: file restore is refused.
	AllowUnsandboxed bool
	// Agent is the binary run as the agent ("" = this running binary).
	Agent string
}

func (c Config) memory() int {
	if c.MemoryMiB <= 0 {
		return 512
	}
	return c.MemoryMiB
}

func (c Config) bootTimeout() time.Duration {
	if c.BootTimeout <= 0 {
		return 60 * time.Second
	}
	return c.BootTimeout
}

func (c Config) agentIdle() time.Duration {
	if c.AgentIdle <= 0 {
		return 10 * time.Minute
	}
	return c.AgentIdle
}

// VMSpec is one restore VM.
type VMSpec struct {
	QEMU, Kernel, Initrd string
	MemoryMiB            int
	NBDSocket, Export    string
	// DiskFormat is how qemu reads the export: "raw" (guest content or a
	// container archive) or "qcow2" (a stopped VM's image file, judged
	// standalone by the caller; opened with no backing regardless).
	DiskFormat string
	Kind       string
	CID        uint32
	// VhostFD is the inherited fd of /dev/vhost-vsock (opened by the
	// daemon), so qemu needs no access to the device node.
	VhostFD int
	Arch    string // GOARCH
	// NonceFile holds the nonce the agent's hello must echo, handed to the
	// guest over fw_cfg (never on the command line, which any host user can
	// read in /proc). AgentIdleSec is the agent's own idle timeout.
	NonceFile    string
	AgentIdleSec int
	// Sandbox enables qemu's seccomp sandbox.
	Sandbox bool
	// ExitWithParent asks qemu (9.1+) to exit when its parent does.
	ExitWithParent bool
}

// qemuArgs builds the restore VM's command line. The VM has:
//   - no NIC, no default devices, no display, no monitor, no reboot;
//   - its console on qemu's stdout (into a bounded in-memory buffer), never
//     a file;
//   - one disk, read-only at both the NBD client and the format node, and
//     for qcow2 no backing file (backing: null), so qemu opens nothing the
//     image header names;
//   - one vhost-vsock device on an inherited fd, its only channel to the
//     host;
//   - fixed small memory and one vCPU;
//   - qemu's seccomp sandbox, including elevateprivileges=deny: qemu never
//     changes user itself (it is started as its user).
func qemuArgs(s VMSpec) ([]string, error) {
	if s.DiskFormat != "raw" && s.DiskFormat != "qcow2" {
		return nil, fmt.Errorf("disk format %q", s.DiskFormat)
	}
	if s.Kind != KindFS && s.Kind != KindArchive {
		return nil, fmt.Errorf("kind %q", s.Kind)
	}
	if s.CID < 3 {
		return nil, fmt.Errorf("vsock cid %d", s.CID)
	}
	if s.VhostFD < 3 {
		return nil, fmt.Errorf("vhost fd %d", s.VhostFD)
	}
	if s.NonceFile == "" || strings.ContainsAny(s.NonceFile, ", \t\n") {
		return nil, fmt.Errorf("nonce file %q", s.NonceFile)
	}
	machine, console := "q35,accel=kvm", "ttyS0"
	if s.Arch == "arm64" {
		machine, console = "virt,accel=kvm,gic-version=host", "ttyAMA0"
	}
	src, err := json.Marshal(map[string]any{
		"driver":    "nbd",
		"node-name": "src",
		"server":    map[string]string{"type": "unix", "path": s.NBDSocket},
		"export":    s.Export,
		"read-only": true,
		// One connection, never re-made: the export is single-peer and its
		// socket is gone once qemu has it.
		"reconnect-delay": 0,
	})
	if err != nil {
		return nil, err
	}
	fmtNode := map[string]any{"driver": s.DiskFormat, "node-name": "disk", "file": "src", "read-only": true}
	if s.DiskFormat == "qcow2" {
		fmtNode["backing"] = nil
	}
	disk, err := json.Marshal(fmtNode)
	if err != nil {
		return nil, err
	}
	idle := s.AgentIdleSec
	if idle <= 0 {
		idle = 600
	}
	args := []string{
		"-name", "litevirt-file-restore",
		"-nodefaults", "-no-user-config", "-display", "none", "-no-reboot",
		"-machine", machine,
		"-cpu", "host",
		"-smp", "1",
		"-m", strconv.Itoa(s.MemoryMiB),
		"-kernel", s.Kernel,
		"-initrd", s.Initrd,
		"-append", strings.Join([]string{
			"console=" + console, "panic=-1", "loglevel=4", "rdinit=/init",
			wire.EnvAgent + "=1", wire.EnvKind + "=" + s.Kind, wire.EnvIdle + "=" + strconv.Itoa(idle),
		}, " "),
		"-fw_cfg", "name=" + wire.FwCfgNonce + ",file=" + s.NonceFile,
		"-serial", "stdio",
		"-nic", "none",
		"-blockdev", string(src),
		"-blockdev", string(disk),
		"-device", "virtio-blk-pci,drive=disk",
		"-device", "vhost-vsock-pci,guest-cid=" + strconv.FormatUint(uint64(s.CID), 10) + ",vhostfd=" + strconv.Itoa(s.VhostFD),
	}
	if s.Sandbox {
		args = append(args, "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny")
	}
	if s.ExitWithParent {
		args = append(args, "-run-with", "exit-with-parent=on")
	}
	return args, nil
}

// consoleRing keeps the last cap bytes of the restore VM's console, in
// memory. The guest controls every byte, so nothing of it is written to the
// host's disk; its tail only ever reaches an error message, escaped.
type consoleRing struct {
	mu   sync.Mutex
	buf  []byte
	cap  int
	seen int64
}

func newConsoleRing(capacity int) *consoleRing { return &consoleRing{cap: capacity} }

func (r *consoleRing) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen += int64(len(p))
	if len(p) >= r.cap {
		r.buf = append(r.buf[:0], p[len(p)-r.cap:]...)
		return len(p), nil
	}
	if over := len(r.buf) + len(p) - r.cap; over > 0 {
		r.buf = append(r.buf[:0], r.buf[over:]...)
	}
	r.buf = append(r.buf, p...)
	return len(p), nil
}

// Tail returns the last n bytes, one line, escaped.
func (r *consoleRing) Tail(n int) string {
	r.mu.Lock()
	b := r.buf
	if len(b) > n {
		b = b[len(b)-n:]
	}
	s := strings.ReplaceAll(string(b), "\r", "")
	r.mu.Unlock()
	return strings.TrimSpace(wire.Escape(strings.ReplaceAll(s, "\n", " ")))
}

// noSeccompMessages are what a real qemu prints when its -sandbox cannot
// be installed: built without seccomp (qemu's vl.c), or the kernel or
// libseccomp refusing the filter (qemu's system/qemu-seccomp.c; the strings
// of qemu-system-x86_64 10.2.1).
var noSeccompMessages = []string{
	"-sandbox support is not enabled in this QEMU binary",
	"failed to initialize seccomp context",
	"failed to set seccomp rawrc attribute",
	"failed to set seccomp thread synchronization",
	"failed to add seccomp denylist rules",
	"failed to load seccomp syscall filter in kernel",
}

// stderrSaysNoSeccomp reports a qemu that could not install its seccomp
// sandbox.
func stderrSaysNoSeccomp(s string) bool {
	for _, m := range noSeccompMessages {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// stderrSaysCIDInUse reports a vsock CID another VM holds.
func stderrSaysCIDInUse(s string) bool {
	return strings.Contains(s, "guest cid") || strings.Contains(s, "Address already in use")
}
