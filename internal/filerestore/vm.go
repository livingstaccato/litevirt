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
	// RunAs is the user qemu runs as when the daemon is root ("" = the
	// first of libvirt-qemu, qemu, nobody that exists). qemu is started as
	// that user; it never switches users itself.
	RunAs string
	// CacheDir holds the cached initramfs and kernel copy (the daemon's
	// <data_dir>/file-restore/cache: trusted, host-built files).
	CacheDir string
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
	// AllowUnsandboxed lets a restore VM run when this qemu has no seccomp
	// sandbox. Off by default: without it, file restore is refused.
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
	// Nonce is echoed by the agent's hello; AgentIdleSec its own timeout.
	Nonce        string
	AgentIdleSec int
	// Sandbox enables qemu's seccomp sandbox.
	Sandbox bool
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
	if s.Nonce == "" || strings.ContainsAny(s.Nonce, " \t\n\"") {
		return nil, fmt.Errorf("nonce %q", s.Nonce)
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
			wire.EnvAgent + "=1", wire.EnvKind + "=" + s.Kind,
			wire.EnvNonce + "=" + s.Nonce, wire.EnvIdle + "=" + strconv.Itoa(idle),
		}, " "),
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

// stderrSaysNoSeccomp reports a qemu built without seccomp.
func stderrSaysNoSeccomp(s string) bool {
	s = strings.ToLower(s)
	return strings.Contains(s, "seccomp") && (strings.Contains(s, "disabled") || strings.Contains(s, "not supported") || strings.Contains(s, "unsupported"))
}

// stderrSaysCIDInUse reports a vsock CID another VM holds.
func stderrSaysCIDInUse(s string) bool {
	return strings.Contains(s, "guest cid") || strings.Contains(s, "Address already in use")
}
