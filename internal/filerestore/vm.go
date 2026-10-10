package filerestore

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// ErrUnavailable wraps every reason a restore VM cannot be started on this
// host (no KVM, no kernel, no qemu, no vhost-vsock). File restore is then
// refused with that reason; a full restore is unaffected.
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
	// RunAs is the user qemu drops to once its files are open ("" = the
	// first of libvirt-qemu, qemu, nobody that exists).
	RunAs string
	// StateDir holds the cached initramfs and each session's sockets and
	// serial log (the daemon's <data_dir>/file-restore).
	StateDir string
	// BootTimeout bounds boot until the agent answers (0 = 60s).
	BootTimeout time.Duration
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
	SerialLog  string
	Arch       string // GOARCH
	// RunAs / RunWith: the user qemu drops to, and whether this qemu
	// spells it -run-with (9.1+) rather than -runas.
	RunAs   string
	RunWith bool
	// Sandbox enables qemu's seccomp sandbox.
	Sandbox bool
}

// qemuArgs builds the restore VM's command line. The VM has:
//   - no NIC, no default devices, no display, no reboot;
//   - one disk, read-only at both the NBD client and the format node, and
//     for qcow2 no backing file (backing: null), so qemu opens nothing the
//     image header names;
//   - one vhost-vsock device, its only channel to the host;
//   - fixed small memory and one vCPU.
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
	args := []string{
		"-name", "litevirt-file-restore",
		"-nodefaults", "-no-user-config", "-nographic", "-no-reboot",
		"-machine", machine,
		"-cpu", "host",
		"-smp", "1",
		"-m", strconv.Itoa(s.MemoryMiB),
		"-kernel", s.Kernel,
		"-initrd", s.Initrd,
		"-append", strings.Join([]string{
			"console=" + console, "panic=-1", "loglevel=4", "rdinit=/init",
			envAgent + "=1", envKind + "=" + s.Kind,
		}, " "),
		"-serial", "file:" + s.SerialLog,
		"-nic", "none",
		"-blockdev", string(src),
		"-blockdev", string(disk),
		"-device", "virtio-blk-pci,drive=disk",
		"-device", "vhost-vsock-pci,guest-cid=" + strconv.FormatUint(uint64(s.CID), 10),
	}
	if s.Sandbox {
		args = append(args, "-sandbox", "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny")
	}
	if s.RunAs != "" {
		if s.RunWith {
			args = append(args, "-run-with", "user="+s.RunAs)
		} else {
			args = append(args, "-runas", s.RunAs)
		}
	}
	return args, nil
}

// qemuSupportsRunWith reports whether a `qemu -version` banner is 9.1+.
func qemuSupportsRunWith(banner string) bool {
	i := strings.Index(banner, "version ")
	if i < 0 {
		return false
	}
	f := strings.FieldsFunc(banner[i+len("version "):], func(r rune) bool { return r == '.' || r == ' ' || r == '\n' || r == '(' })
	if len(f) < 2 {
		return false
	}
	maj, err1 := strconv.Atoi(f[0])
	mnr, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return false
	}
	return maj > 9 || maj == 9 && mnr >= 1
}

// tailClean returns the last n bytes of r with control characters replaced
// — a restore VM's console log, for an error message.
func tailClean(r io.ReadSeeker, n int64) string {
	end, err := r.Seek(0, io.SeekEnd)
	if err != nil {
		return ""
	}
	start := end - n
	if start < 0 {
		start = 0
	}
	if _, err := r.Seek(start, io.SeekStart); err != nil {
		return ""
	}
	b, _ := io.ReadAll(io.LimitReader(r, n))
	out := make([]rune, 0, len(b))
	for _, c := range string(b) {
		switch {
		case c == '\n':
			out = append(out, ' ')
		case c < 0x20 || c == 0x7f:
		default:
			out = append(out, c)
		}
	}
	return strings.TrimSpace(string(out))
}
