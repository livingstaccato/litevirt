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

	// Test hooks: the device nodes and the agent check.
	kvmPath, vhostPath string
	checkAgent         func(path string) error
}

// NewLauncher returns a launcher for cfg. Nothing is checked until
// Preflight or Open.
func NewLauncher(cfg Config) *Launcher {
	return &Launcher{cfg: cfg, kvmPath: "/dev/kvm", vhostPath: "/dev/vhost-vsock", checkAgent: checkStaticELF}
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
	user                         *qemuUser // nil: qemu runs as the daemon's own user (not root)
}

// Preflight checks everything a restore VM needs, naming the first thing
// missing (wrapped in ErrUnavailable). It is re-run for every session.
func (l *Launcher) Preflight() error {
	_, err := l.check()
	return err
}

func (l *Launcher) check() (*host, error) {
	rel := kernelRelease()
	h := &host{qemu: l.cfg.QEMU, kernel: l.cfg.Kernel, modules: l.cfg.ModulesDir, agent: l.cfg.Agent}
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
		u, err := lookupQemuUser(l.cfg.RunAs)
		if err != nil {
			return nil, unavailable("%v", err)
		}
		h.user = u
		if err := accessibleTo(l.kvmPath, u); err != nil {
			return nil, unavailable("no usable KVM for qemu user %s: %v", u.name, err)
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
	return h, nil
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

// lookupQemuUser resolves the user qemu runs as. Never root.
func lookupQemuUser(name string) (*qemuUser, error) {
	names := []string{name}
	if name == "" {
		names = []string{"libvirt-qemu", "qemu", "nobody"}
	}
	for _, n := range names {
		u, err := user.Lookup(n)
		if err != nil {
			continue
		}
		uid, _ := strconv.ParseUint(u.Uid, 10, 32)
		gid, _ := strconv.ParseUint(u.Gid, 10, 32)
		if uid == 0 {
			return nil, fmt.Errorf("file_restore.run_as %q is root; qemu must run unprivileged", n)
		}
		qu := &qemuUser{name: n, uid: uint32(uid), gid: uint32(gid)}
		if gs, err := u.GroupIds(); err == nil {
			for _, g := range gs {
				if v, err := strconv.ParseUint(g, 10, 32); err == nil {
					qu.groups = append(qu.groups, uint32(v))
				}
			}
		}
		return qu, nil
	}
	return nil, fmt.Errorf("no user to run qemu as (tried %s; set file_restore.run_as)", strings.Join(names, ", "))
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
	h, err := l.check()
	if err != nil {
		return nil, err
	}
	if l.cfg.CacheDir == "" || l.cfg.RunDir == "" {
		return nil, errors.New("file restore: no cache or run directory")
	}
	owner := -1
	if h.user != nil {
		owner = int(h.user.uid)
	}
	initrd, err := EnsureInitramfs(l.cfg.CacheDir, InitramfsSpec{Agent: h.agent, ModulesDir: h.modules}, owner)
	if err != nil {
		return nil, unavailable("build the restore VM initramfs: %v", err)
	}
	kernel := h.kernel
	if h.user != nil {
		// The host's kernel image is root-only; qemu gets its own copy.
		if kernel, err = ensureKernelCopy(l.cfg.CacheDir, h.kernel, owner); err != nil {
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
		// qemu (another user) must reach the socket in here, and only that.
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
	if h.user != nil {
		if err := os.Chown(sock, int(h.user.uid), int(h.user.gid)); err != nil {
			return nil, err
		}
	}
	go func() { _ = s.nbd.Serve(context.Background()) }()

	spec := VMSpec{
		QEMU: h.qemu, Kernel: kernel, Initrd: initrd, MemoryMiB: l.cfg.memory(),
		NBDSocket: sock, Export: "backup", DiskFormat: format, Kind: kind,
		Arch: runtime.GOARCH, VhostFD: 3, Nonce: newNonce(),
		AgentIdleSec: int(l.cfg.agentIdle() / time.Second), Sandbox: true,
	}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		spec.CID = randomCID()
		var stderr bytes.Buffer
		if err := l.start(s, spec, h.user, &stderr); err != nil {
			return nil, unavailable("start qemu: %v", err)
		}
		lastErr = s.dial(ctx, spec.CID, spec.Nonce, l.cfg.bootTimeout())
		if lastErr == nil {
			ok = true
			slog.Info("file restore: restore VM up", "cid", spec.CID, "boot", time.Since(s.started).Round(time.Millisecond), "sandbox", spec.Sandbox)
			return s, nil
		}
		s.kill() // qemu has exited (Wait done) before its stderr is read
		out := strings.TrimSpace(stderr.String())
		switch {
		case stderrSaysCIDInUse(out):
			continue // a CID collision: pick another
		case spec.Sandbox && stderrSaysNoSeccomp(out):
			// Decided per attempt, never remembered: a later session asks again.
			if !l.cfg.AllowUnsandboxed {
				return nil, unavailable("this qemu has no seccomp sandbox (%s); refusing to run a restore VM without it — set file_restore.allow_unsandboxed: true to permit it", wire.EscapeBounded(out, 300))
			}
			slog.Warn("file restore: this qemu has no seccomp sandbox; running this restore VM without it (file_restore.allow_unsandboxed)", "qemu", h.qemu)
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
// it survives it (a setuid inside qemu would have cleared it).
func qemuCommand(spec VMSpec, u *qemuUser, dir string, vhost *os.File, stdout, stderr io.Writer) (*exec.Cmd, error) {
	args, err := qemuArgs(spec)
	if err != nil {
		return nil, err
	}
	cmd := exec.Command(spec.QEMU, args...)
	cmd.Stdin = nil
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Dir = dir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.ExtraFiles = []*os.File{vhost} // fd 3 = spec.VhostFD
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if u != nil {
		cmd.SysProcAttr.Credential = &syscall.Credential{Uid: u.uid, Gid: u.gid, Groups: u.groups}
	}
	return cmd, nil
}

func (l *Launcher) start(s *Session, spec VMSpec, u *qemuUser, stderr *bytes.Buffer) error {
	vhost, err := os.OpenFile(l.vhostPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer vhost.Close() // qemu holds its own copy
	cmd, err := qemuCommand(spec, u, s.dir, vhost, s.console, &limitedBuffer{b: stderr, max: 16 << 10})
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
	// The pidfile lets a later daemon find and kill this VM if this one
	// dies without doing so (SweepStale).
	if err := os.WriteFile(filepath.Join(s.dir, pidFile), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o600); err != nil {
		return err
	}
	return nil
}

const pidFile = "qemu.pid"

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
			if err := s.Client.Hello(nonce); err == nil {
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
// names a live process whose command line is a restore VM of THAT session
// (it names the session directory): a recycled pid is never touched.
// Returns the number killed.
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
		if pid := readPid(filepath.Join(dir, pidFile)); pid > 1 && isRestoreVM(pid, dir) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			killed++
		}
		_ = os.RemoveAll(dir)
	}
	return killed
}

func readPid(path string) int {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 32 {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil {
		return 0
	}
	return pid
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
