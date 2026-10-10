//go:build linux

package filerestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/filerestore/wire"
	"github.com/litevirt/litevirt/internal/nbd"
)

// Launcher starts restore VMs.
type Launcher struct {
	cfg Config

	aaMu     sync.Mutex
	aaLoaded string // the profile text loaded, so a change reloads it

	// Test hooks.
	kvmPath, vhostPath string
	checkAgent         func(path string) error
	appArmor           func() bool
}

// NewLauncher returns a launcher for cfg. Nothing is checked until
// Preflight or Open.
func NewLauncher(cfg Config) *Launcher {
	return &Launcher{cfg: cfg, kvmPath: "/dev/kvm", vhostPath: "/dev/vhost-vsock", checkAgent: checkStaticELF, appArmor: appArmorEnabled}
}

func unavailable(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnavailable, fmt.Sprintf(format, args...))
}

func kernelRelease() string {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return ""
	}
	return string(bytes.TrimRight(u.Release[:], "\x00"))
}

// qemuUser is who qemu runs as.
type qemuUser struct {
	name     string
	uid, gid uint32
	groups   []uint32
}

// host is the checked environment for one Open.
type host struct {
	qemu, kernel, modules, agent string
	user                         *qemuUser // nil: qemu runs as the daemon's own user
	gid                          int       // the group the boot files are readable by
	appArmor                     bool
	sandbox                      bool // this qemu installs its seccomp sandbox
	sandboxMsg                   string
}

// EnsureRestoreUser creates DefaultRestoreUser if it does not exist: a
// system user with its own group, no home and no shell, in the kvm group
// (for /dev/kvm) and nothing else. Idempotent; a no-op unless root. The
// daemon calls it at start.
func EnsureRestoreUser() error {
	if os.Geteuid() != 0 {
		return nil
	}
	if _, err := user.Lookup(DefaultRestoreUser); err == nil {
		return nil
	}
	args := []string{"--system", "--user-group", "--no-create-home", "--home-dir", "/nonexistent",
		"--shell", "/usr/sbin/nologin", "--comment", "litevirt file-restore VMs"}
	if _, err := user.LookupGroup("kvm"); err == nil {
		args = append(args, "--groups", "kvm")
	}
	out, err := exec.Command("useradd", append(args, DefaultRestoreUser)...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("create user %s: %v: %s", DefaultRestoreUser, err, strings.TrimSpace(string(out)))
	}
	return nil
}

// Preflight checks everything a restore VM needs, naming the first thing
// missing (wrapped in ErrUnavailable). It is re-run for every session.
func (l *Launcher) Preflight() error {
	_, err := l.check(context.Background(), false)
	return err
}

// check checks the host; with probe it also asks qemu whether it can
// install its sandbox (Open does, for every VM it starts).
func (l *Launcher) check(ctx context.Context, probe bool) (*host, error) {
	rel := kernelRelease()
	h := &host{qemu: l.cfg.QEMU, kernel: l.cfg.Kernel, modules: l.cfg.ModulesDir, agent: l.cfg.Agent, gid: os.Getgid()}
	if h.kernel == "" {
		h.kernel = "/boot/vmlinuz-" + rel
	}
	if h.modules == "" {
		h.modules = "/lib/modules/" + rel
	}
	if h.agent == "" {
		h.agent = "/proc/self/exe"
	}
	if os.Geteuid() == 0 {
		u, err := lookupQemuUser(l.cfg.RunAs, l.cfg.AllowUnsandboxed)
		if err != nil {
			return nil, unavailable("%v", err)
		}
		if u != nil {
			h.user, h.gid = u, int(u.gid)
			if err := accessibleTo(l.kvmPath, u); err != nil {
				return nil, unavailable("no usable KVM for qemu user %s: %v", u.name, err)
			}
		}
	} else if f, err := os.OpenFile(l.kvmPath, os.O_RDWR, 0); err != nil {
		return nil, unavailable("no usable KVM (%s: %v)", l.kvmPath, err)
	} else {
		f.Close()
	}
	// The daemon opens vhost-vsock itself and hands qemu the fd.
	if f, err := os.OpenFile(l.vhostPath, os.O_RDWR, 0); err != nil {
		return nil, unavailable("no usable %s (load the vhost_vsock kernel module): %v", l.vhostPath, err)
	} else {
		f.Close()
	}
	if f, err := os.Open(h.kernel); err != nil {
		return nil, unavailable("kernel for the restore VM: %v (set file_restore.kernel)", err)
	} else {
		f.Close()
	}
	if st, err := os.Stat(filepath.Join(h.modules, "modules.dep")); err != nil || !st.Mode().IsRegular() {
		return nil, unavailable("kernel modules for the restore VM: no %s (set file_restore.modules_dir)", filepath.Join(h.modules, "modules.dep"))
	}
	if h.qemu == "" {
		names := []string{"qemu-system-x86_64", "/usr/libexec/qemu-kvm"}
		if runtime.GOARCH == "arm64" {
			names = []string{"qemu-system-aarch64", "/usr/libexec/qemu-kvm"}
		}
		for _, n := range names {
			if p, err := exec.LookPath(n); err == nil {
				h.qemu = p
				break
			}
		}
		if h.qemu == "" {
			return nil, unavailable("no qemu system emulator found (tried %s; set file_restore.qemu)", strings.Join(names, ", "))
		}
	} else if _, err := exec.LookPath(h.qemu); err != nil {
		return nil, unavailable("qemu %q: %v", h.qemu, err)
	}
	if ms, err := loadModuleSet(h.modules); err != nil {
		return nil, unavailable("%v", err)
	} else if _, err := ms.resolve(agentModules, requiredModules); err != nil {
		return nil, unavailable("%v", err)
	}
	if err := l.checkAgent(h.agent); err != nil {
		return nil, unavailable("%v", err)
	}
	h.appArmor = os.Geteuid() == 0 && l.appArmor()
	if !probe {
		return h, nil
	}
	// Ask this qemu, as the user it will run as, whether it can install its
	// seccomp sandbox — decided now, for this VM, never remembered.
	h.sandbox, h.sandboxMsg = probeSandbox(ctx, h.qemu, h.user)
	if !h.sandbox && !l.cfg.AllowUnsandboxed {
		return nil, unavailable("this qemu cannot run with its seccomp sandbox (%s); refusing to run a restore VM without it — "+
			"file_restore.allow_unsandboxed: true permits it, which is dangerous (see docs/backups.md)", wire.EscapeBounded(h.sandboxMsg, 300))
	}
	return h, nil
}

// sandboxOpts is qemu's seccomp sandbox for a restore VM.
const sandboxOpts = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"

// probeSandbox starts qemu with the sandbox and nothing else (no machine,
// paused) as u. A qemu that cannot install it exits at once and says so; one
// that can is still running after a moment and is killed. The answer comes
// from qemu itself, not from guessing at its messages.
func probeSandbox(ctx context.Context, qemu string, u *qemuUser) (ok bool, msg string) {
	cmd := exec.CommandContext(ctx, qemu, "-sandbox", sandboxOpts, "-machine", "none", "-nodefaults",
		"-no-user-config", "-display", "none", "-S")
	var stderr bytes.Buffer
	cmd.Stderr = &limitedBuffer{b: &stderr, max: 4 << 10}
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if u != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: u.uid, Gid: u.gid, Groups: u.groups}
	}
	if err := cmd.Start(); err != nil {
		return false, err.Error()
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		out := strings.TrimSpace(stderr.String())
		if out == "" && err != nil {
			out = err.Error()
		}
		return false, out
	case <-time.After(800 * time.Millisecond):
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		<-done
		return true, ""
	}
}

// checkStaticELF refuses an agent binary that needs a dynamic loader: the
// initramfs holds no libc, so such a binary cannot run as /init.
func checkStaticELF(path string) error {
	f, err := elf.Open(path)
	if err != nil {
		return fmt.Errorf("restore VM agent %s: %v", path, err)
	}
	defer f.Close()
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			return fmt.Errorf("the litevirt binary is dynamically linked; a restore VM needs the static build (CGO_ENABLED=0)")
		}
	}
	return nil
}

// sharedQemuUsers own production VM disks and the migration-TLS key
// (libvirt's qemu user) or are shared with other daemons (nobody).
var sharedQemuUsers = []string{"libvirt-qemu", "qemu", "nobody"}

// lookupQemuUser resolves the user qemu runs as: the configured one or
// DefaultRestoreUser. root and the shared users are refused unless
// allowUnsafe; root then means no credential at all (nil).
func lookupQemuUser(name string, allowUnsafe bool) (*qemuUser, error) {
	if name == "" {
		name = DefaultRestoreUser
	}
	u, err := user.Lookup(name)
	if err != nil {
		if name == DefaultRestoreUser {
			return nil, fmt.Errorf("no user %s to run restore VMs as (the daemon creates it at start; create it with "+
				"`useradd --system --user-group --groups kvm --shell /usr/sbin/nologin %s`)", name, name)
		}
		return nil, fmt.Errorf("file_restore.run_as %q: %v", name, err)
	}
	uid, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid, _ := strconv.ParseUint(u.Gid, 10, 32)
	if uid == 0 {
		if !allowUnsafe {
			return nil, fmt.Errorf("file_restore.run_as %q is root; restore VMs run as a dedicated unprivileged user (%s)", name, DefaultRestoreUser)
		}
		return nil, nil
	}
	if !allowUnsafe {
		for _, shared := range sharedQemuUsers {
			if su, err := user.Lookup(shared); err == nil && su.Uid == u.Uid {
				return nil, fmt.Errorf("file_restore.run_as %q is %s, which owns or shares production VM disks and keys; "+
					"restore VMs run as a dedicated user (%s)", name, shared, DefaultRestoreUser)
			}
		}
	}
	qu := &qemuUser{name: name, uid: uint32(uid), gid: uint32(gid)}
	if gs, err := u.GroupIds(); err == nil {
		for _, g := range gs {
			if v, err := strconv.ParseUint(g, 10, 32); err == nil {
				qu.groups = append(qu.groups, uint32(v))
			}
		}
	}
	return qu, nil
}

// accessibleTo reports whether u may open path read-write by its mode bits.
func accessibleTo(path string, u *qemuUser) error {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return err
	}
	const rw = 0o6
	switch {
	case st.Uid == u.uid:
		if st.Mode>>6&rw == rw {
			return nil
		}
	case st.Gid == u.gid || containsU32(u.groups, st.Gid):
		if st.Mode>>3&rw == rw {
			return nil
		}
	default:
		if st.Mode&rw == rw {
			return nil
		}
	}
	return fmt.Errorf("%s (mode %o, owner %d:%d) is not read-write for %s", path, st.Mode&0o777, st.Uid, st.Gid, u.name)
}

func containsU32(s []uint32, v uint32) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// appArmorEnabled reports whether AppArmor is enabled and its parser is
// installed.
func appArmorEnabled() bool {
	if b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled"); err != nil || !strings.HasPrefix(string(b), "Y") {
		return false
	}
	_, err := exec.LookPath("apparmor_parser")
	return err == nil
}

// appArmorProfileText is the restore qemu's profile: the qemu binary and its
// libraries and firmware, /dev/kvm and the vhost-vsock fd, the boot files,
// and its own session's socket and nonce. Nothing else on the host —
// not /var/lib/litevirt, not any VM disk, not any key.
func appArmorProfileText(cacheDir, runDir string) string {
	return `abi <abi/3.0>,
include <tunables/global>

profile ` + AppArmorProfile + ` flags=(attach_disconnected) {
  include <abstractions/base>

  /usr/bin/qemu-system-* mr,
  /usr/libexec/qemu-kvm mr,
  /{usr/,}lib{,32,64}/** mr,
  /{usr/,}lib/@{multiarch}/** mr,
  /usr/share/qemu/** r,
  /usr/share/seabios/** r,
  /usr/share/ipxe/** r,
  /usr/lib/ipxe/** r,
  /usr/share/OVMF/** r,
  /etc/ld.so.cache r,
  /proc/sys/vm/overcommit_memory r,
  /proc/sys/kernel/cap_last_cap r,
  /sys/devices/system/cpu/** r,
  /sys/devices/system/node/** r,
  /sys/kernel/mm/transparent_hugepage/** r,
  /sys/module/vhost/parameters/** r,
  owner @{PROC}/@{pid}/** r,
  owner @{PROC}/@{pid}/task/*/comm rw,

  /dev/kvm rw,
  /dev/vhost-vsock rw,

  ` + filepath.Join(cacheDir, "*") + ` r,
  ` + filepath.Join(runDir, "s-*", "nbd.sock") + ` rw,
  ` + filepath.Join(runDir, "s-*", "nonce") + ` r,
  unix (connect, send, receive) type=stream,

  signal (receive) peer=unconfined,
  deny ptrace,
  deny mount,
  deny network inet,
  deny network inet6,
}
`
}

// ensureProfile loads (or reloads, if its text changed) the restore qemu's
// AppArmor profile from memory: nothing is written under /etc.
func (l *Launcher) ensureProfile() error {
	text := appArmorProfileText(l.cfg.CacheDir, l.cfg.RunDir)
	l.aaMu.Lock()
	defer l.aaMu.Unlock()
	if l.aaLoaded == text && profileLoaded() {
		return nil
	}
	cmd := exec.Command("apparmor_parser", "-r", "-W")
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("load AppArmor profile %s: %v: %s", AppArmorProfile, err, strings.TrimSpace(string(out)))
	}
	l.aaLoaded = text
	return nil
}

func profileLoaded() bool {
	b, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	return err == nil && bytes.Contains(b, []byte(AppArmorProfile+" ("))
}

// Session is one running restore VM and its connection.
type Session struct {
	*Client
	cmd     *exec.Cmd
	exited  chan struct{}
	nbd     *nbd.Server
	dir     string
	console *consoleRing
	once    sync.Once
	started time.Time
}

// Open boots a restore VM on dev and connects to its agent. kind is
// KindFS or KindArchive; format is how qemu reads dev ("raw" or "qcow2").
func (l *Launcher) Open(ctx context.Context, dev BlockDevice, kind, format string) (*Session, error) {
	h, err := l.check(ctx, true)
	if err != nil {
		return nil, err
	}
	if l.cfg.CacheDir == "" || l.cfg.RunDir == "" {
		return nil, errors.New("file restore: no cache or run directory")
	}
	if h.appArmor {
		if err := l.ensureProfile(); err != nil {
			return nil, unavailable("%v", err)
		}
	}
	initrd, err := EnsureInitramfs(l.cfg.CacheDir, InitramfsSpec{Agent: h.agent, ModulesDir: h.modules}, h.gid, l.cfg.OnTamper)
	if err != nil {
		return nil, unavailable("build the restore VM initramfs: %v", err)
	}
	kernel := h.kernel
	if h.user != nil {
		// The host's kernel image is root-only; qemu reads a group copy.
		if kernel, err = ensureKernelCopy(l.cfg.CacheDir, h.kernel, h.gid, l.cfg.OnTamper); err != nil {
			return nil, unavailable("copy the kernel for the restore VM: %v", err)
		}
	}
	if err := os.MkdirAll(l.cfg.RunDir, 0o711); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(l.cfg.RunDir, "s-")
	if err != nil {
		return nil, err
	}
	if h.user != nil {
		// qemu (another user) must reach the socket and nonce in here.
		if err := os.Chmod(dir, 0o711); err != nil {
			_ = os.RemoveAll(dir)
			return nil, err
		}
	}
	s := &Session{dir: dir, exited: make(chan struct{}), started: time.Now(), console: newConsoleRing(64 << 10)}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()

	sock := filepath.Join(dir, "nbd.sock")
	s.nbd = &nbd.Server{ExportName: "backup", Dev: dev}
	if err := s.nbd.ListenUnix(sock); err != nil {
		return nil, err
	}
	nonce := newNonce()
	nonceFile := filepath.Join(dir, "nonce")
	if err := os.WriteFile(nonceFile, []byte(nonce), 0o400); err != nil {
		return nil, err
	}
	if h.user != nil {
		for _, f := range []string{sock, nonceFile} {
			if err := os.Chown(f, int(h.user.uid), int(h.user.gid)); err != nil {
				return nil, err
			}
		}
	}
	go func() { _ = s.nbd.Serve(context.Background()) }()

	spec := VMSpec{
		QEMU: h.qemu, Kernel: kernel, Initrd: initrd, MemoryMiB: l.cfg.memory(),
		NBDSocket: sock, Export: "backup", DiskFormat: format, Kind: kind,
		Arch: runtime.GOARCH, VhostFD: 3, NonceFile: nonceFile,
		AgentIdleSec: int(l.cfg.agentIdle() / time.Second), Sandbox: h.sandbox,
	}
	if !h.sandbox {
		slog.Warn("file restore: running a restore VM WITHOUT qemu's seccomp sandbox (file_restore.allow_unsandboxed)", "qemu", h.qemu, "why", h.sandboxMsg)
	}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		spec.CID = randomCID()
		var stderr bytes.Buffer
		if err := l.start(s, spec, h, &stderr); err != nil {
			return nil, unavailable("start qemu: %v", err)
		}
		lastErr = s.dial(ctx, spec.CID, nonce, l.cfg.bootTimeout())
		if lastErr == nil {
			ok = true
			slog.Info("file restore: restore VM up", "cid", spec.CID, "boot", time.Since(s.started).Round(time.Millisecond),
				"sandbox", spec.Sandbox, "apparmor", h.appArmor)
			return s, nil
		}
		s.kill() // qemu has exited (Wait done) before its stderr is read
		out := strings.TrimSpace(stderr.String())
		switch {
		case stderrSaysCIDInUse(out):
			continue // a CID collision: pick another
		case spec.Sandbox && stderrSaysNoSeccomp(out):
			// The probe passed but the VM's sandbox failed: decide again,
			// for this attempt only.
			if !l.cfg.AllowUnsandboxed {
				return nil, unavailable("this qemu could not install its seccomp sandbox (%s); refusing to run a restore VM without it — "+
					"file_restore.allow_unsandboxed: true permits it, which is dangerous (see docs/backups.md)", wire.EscapeBounded(out, 300))
			}
			slog.Warn("file restore: this qemu could not install its seccomp sandbox; running this restore VM without it (file_restore.allow_unsandboxed)", "qemu", h.qemu)
			spec.Sandbox = false
			continue
		}
		if tail := s.console.Tail(600); tail != "" {
			out += " | console: " + tail
		}
		return nil, unavailable("the restore VM did not come up: %v (%s)", lastErr, wire.EscapeBounded(out, 900))
	}
	return nil, unavailable("the restore VM did not come up: %v", lastErr)
}

func randomCID() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	// 3..2^31: clear of the reserved CIDs and of the top of the range.
	return 3 + binary.BigEndian.Uint32(b[:])%(1<<31-3)
}

func newNonce() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// qemuCommand builds the qemu process: started as u (when the daemon is
// root) with u's groups, in its own process group, killed when the daemon
// dies. Go applies the parent-death signal AFTER the credential change, so
// it survives it (a setuid inside qemu would have cleared it). With
// profile set, the litevirt binary at trampoline runs first, as qemu's
// parent in the same process group: it starts qemu under that AppArmor
// profile and kills it on the SIGTERM the daemon's death sends it.
func qemuCommand(spec VMSpec, u *qemuUser, dir string, vhost *os.File, stdout, stderr io.Writer, trampoline, profile string) (*exec.Cmd, error) {
	args, err := qemuArgs(spec)
	if err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	if profile != "" {
		cmd = exec.Command(trampoline, append([]string{TrampolineArg, profile, spec.QEMU}, args...)...)
	} else {
		cmd = exec.Command(spec.QEMU, args...)
	}
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{vhost} // fd 3 = spec.VhostFD
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if profile != "" {
		// The trampoline turns the daemon's death into qemu's (RunTrampoline).
		cmd.SysProcAttr.Pdeathsig = syscall.SIGTERM
	}
	if u != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: u.uid, Gid: u.gid, Groups: u.groups}
	}
	return cmd, nil
}

func (l *Launcher) start(s *Session, spec VMSpec, h *host, stderr *bytes.Buffer) error {
	vhost, err := os.OpenFile(l.vhostPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer vhost.Close() // qemu holds its own copy
	profile := ""
	if h.appArmor {
		profile = AppArmorProfile
	}
	cmd, err := qemuCommand(spec, h.user, s.dir, vhost, s.console, &limitedBuffer{b: stderr, max: 16 << 10}, h.agent, profile)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.cmd = cmd
	s.exited = make(chan struct{})
	go func(c *exec.Cmd, done chan struct{}) {
		_ = c.Wait()
		close(done)
	}(cmd, s.exited)
	// The pidfile (pid and the uid it runs as) lets a later daemon find and
	// kill this VM if this one dies without doing so (SweepStale).
	uid := os.Geteuid()
	if h.user != nil {
		uid = int(h.user.uid)
	}
	return os.WriteFile(filepath.Join(s.dir, pidFile), []byte(fmt.Sprintf("%d %d\n", cmd.Process.Pid, uid)), 0o600)
}

const pidFile = "qemu.pid"

// helloTimeout bounds one hello during boot: an agent (or a foreign VM on
// the same CID) that accepts and never answers must not hold the boot past
// its deadline.
const helloTimeout = 5 * time.Second

// dial connects to the agent, retrying while the VM boots, and checks the
// agent answers with this session's nonce.
func (s *Session) dial(ctx context.Context, cid uint32, nonce string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	var last error
	for {
		select {
		case <-s.exited:
			return errors.New("qemu exited")
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		conn, err := dialVsock(cid, wire.AgentPort)
		if err == nil {
			s.Client = NewClient(conn)
			wait := helloTimeout
			if left := time.Until(deadline); left < wait {
				wait = left
			}
			if wait <= 0 {
				wait = time.Second
			}
			if err := s.Client.Hello(nonce, wait); err == nil {
				return nil
			} else {
				last = err
				s.Client.Close()
				s.Client = nil
			}
		} else {
			last = err
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no answer from the agent within %v: %v", timeout, last)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// dialVsock connects to cid:port. The fd is non-blocking so the returned
// file supports deadlines.
func dialVsock(cid, port uint32) (*os.File, error) {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	if err := unix.Connect(fd, &unix.SockaddrVM{CID: cid, Port: port}); err != nil {
		unix.Close(fd)
		return nil, err
	}
	if err := unix.SetNonblock(fd, true); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return os.NewFile(uintptr(fd), "vsock"), nil
}

func (s *Session) kill() {
	if s.Client != nil {
		s.Client.Close()
		s.Client = nil
	}
	if s.cmd != nil && s.cmd.Process != nil {
		_ = syscall.Kill(-s.cmd.Process.Pid, syscall.SIGKILL)
		select {
		case <-s.exited:
		case <-time.After(10 * time.Second):
		}
		s.cmd = nil
	}
}

// Close powers the VM off (asking first, then killing), stops the NBD
// export and removes the session directory. Idempotent.
func (s *Session) Close() {
	s.once.Do(func() {
		if s.Client != nil {
			_ = s.Client.Shutdown()
			if s.cmd != nil {
				select {
				case <-s.exited:
				case <-time.After(3 * time.Second):
				}
			}
		}
		s.kill()
		if s.nbd != nil {
			s.nbd.Stop()
		}
		if s.dir != "" {
			_ = os.RemoveAll(s.dir)
		}
	})
}

// SweepStale kills the restore VMs a previous daemon left in runDir and
// removes their session directories. A VM is killed only when its pidfile
// names a live process that runs as the uid the pidfile records and whose
// command line is the restore VM of THAT session (it names the session's
// socket); the process is held by a pidfd from before the checks to the
// kill, so a pid recycled in between is never signalled. Returns the number
// killed.
func SweepStale(runDir string) int {
	ents, err := os.ReadDir(runDir)
	if err != nil {
		return 0
	}
	killed := 0
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "s-") {
			continue
		}
		dir := filepath.Join(runDir, e.Name())
		if pid, uid := readPid(filepath.Join(dir, pidFile)); pid > 1 && killVerified(pid, uid, dir) {
			killed++
		}
		_ = os.RemoveAll(dir)
	}
	return killed
}

// killVerified SIGKILLs pid if it is still the restore VM of dir running as
// uid.
func killVerified(pid, uid int, dir string) bool {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return false // gone (or no pidfd support: never kill unverified)
	}
	defer unix.Close(pidfd)
	if !isRestoreVM(pid, dir) || procUID(pid) != uid {
		return false
	}
	// Still the process the checks read? (A dead one's pid may be reused;
	// its pidfd then fails.)
	if err := unix.PidfdSendSignal(pidfd, 0, nil, 0); err != nil {
		return false
	}
	if unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0) != nil {
		return false
	}
	// The session ran in its own process group (pgid = pid): a trampoline's
	// qemu child goes with it.
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	return true
}

func readPid(path string) (pid, uid int) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64 {
		return 0, -1
	}
	f := strings.Fields(string(b))
	if len(f) != 2 {
		return 0, -1
	}
	pid, err1 := strconv.Atoi(f[0])
	uid, err2 := strconv.Atoi(f[1])
	if err1 != nil || err2 != nil {
		return 0, -1
	}
	return pid, uid
}

// procUID is pid's real uid, or -1.
func procUID(pid int) int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "Uid:") {
			if f := strings.Fields(l); len(f) >= 2 {
				if n, err := strconv.Atoi(f[1]); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

// isRestoreVM reports whether pid's command line is the restore VM of the
// session directory dir.
func isRestoreVM(pid int, dir string) bool {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return false
	}
	args := strings.Split(string(b), "\x00")
	name, sess := false, false
	for i, a := range args {
		if a == "-name" && i+1 < len(args) && args[i+1] == "litevirt-file-restore" {
			name = true
		}
		if strings.Contains(a, `"path":"`+filepath.Join(dir, "nbd.sock")+`"`) {
			sess = true
		}
	}
	return name && sess
}

type limitedBuffer struct {
	b   *bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		if len(p) > room {
			l.b.Write(p[:room])
		} else {
			l.b.Write(p)
		}
	}
	return len(p), nil
}

// RunTrampoline is the litevirt binary run as `litevirt __file-restore-exec
// <profile> <qemu> <args...>` (already as the restore user, in the session's
// process group). It runs in two stages:
//
//   - the parent stage stays as qemu's parent: it starts the second stage,
//     and on SIGTERM (the parent-death signal the daemon gives it) or any end
//     kills it and exits with its status;
//   - the exec stage (`… __file-restore-exec --exec <profile> <qemu> …`) sets
//     its AppArmor profile for its next exec and execs qemu in place, which
//     starts confined.
//
// Two stages because AppArmor's on-exec profile applies to the task that set
// it (not to a child it forks), and because the exec into a new profile is a
// secure exec, across which the kernel clears the parent-death signal: a qemu
// exec'd straight from the daemon would no longer die with it.
func RunTrampoline(args []string) {
	if len(args) >= 1 && args[0] == "--exec" {
		runTrampolineExec(args[1:])
		return
	}
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "file-restore exec: want <profile> <qemu> [args...]")
		os.Exit(2)
	}
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	cmd := exec.Command("/proc/self/exe", append([]string{TrampolineArg, "--exec"}, args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, os.Stdout, os.Stderr
	cmd.Env = os.Environ()
	cmd.ExtraFiles = []*os.File{os.NewFile(3, "vhost-vsock")} // fd 3 stays fd 3
	if err := cmd.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "file-restore exec: start: %v\n", err)
		os.Exit(1)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-sigs:
		_ = cmd.Process.Kill()
		<-done
		os.Exit(1)
	case err := <-done:
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode() & 0xff)
		}
		if err != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
}

func runTrampolineExec(args []string) {
	if len(args) < 2 {
		os.Exit(2)
	}
	profile, qemu := args[0], args[1]
	if err := setExecProfile(profile); err != nil {
		fmt.Fprintf(os.Stderr, "file-restore exec: set AppArmor profile %s: %v\n", profile, err)
		os.Exit(1)
	}
	err := syscall.Exec(qemu, append([]string{qemu}, args[2:]...), os.Environ())
	fmt.Fprintf(os.Stderr, "file-restore exec: exec %s: %v\n", qemu, err)
	os.Exit(1)
}

// setExecProfile asks AppArmor to confine this process's next exec by
// profile (aa_change_onexec).
func setExecProfile(profile string) error {
	msg := []byte("exec " + profile)
	var err error
	for _, p := range []string{"/proc/self/attr/apparmor/exec", "/proc/self/attr/exec"} {
		var f *os.File
		if f, err = os.OpenFile(p, os.O_WRONLY, 0); err != nil {
			continue
		}
		_, err = f.Write(msg)
		f.Close()
		if err == nil {
			return nil
		}
	}
	return err
}
