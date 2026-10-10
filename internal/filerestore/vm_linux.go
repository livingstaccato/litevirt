//go:build linux

package filerestore

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/litevirt/litevirt/internal/nbd"
)

// Launcher starts restore VMs.
type Launcher struct {
	cfg Config

	mu       sync.Mutex
	resolved *resolvedHost
}

// resolvedHost is Config with its defaults filled in and checked.
type resolvedHost struct {
	qemu, kernel, modules, agent, runAs string
	runWith                             bool
	sandbox                             bool
}

// NewLauncher returns a launcher for cfg. Nothing is checked until
// Preflight or Open.
func NewLauncher(cfg Config) *Launcher { return &Launcher{cfg: cfg} }

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

// Preflight checks everything a restore VM needs, naming the first thing
// missing (wrapped in ErrUnavailable).
func (l *Launcher) Preflight() error {
	_, err := l.resolve()
	return err
}

func (l *Launcher) resolve() (*resolvedHost, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.resolved != nil {
		return l.resolved, nil
	}
	rel := kernelRelease()
	r := &resolvedHost{qemu: l.cfg.QEMU, kernel: l.cfg.Kernel, modules: l.cfg.ModulesDir, agent: l.cfg.Agent, runAs: l.cfg.RunAs}
	if r.kernel == "" {
		r.kernel = "/boot/vmlinuz-" + rel
	}
	if r.modules == "" {
		r.modules = "/lib/modules/" + rel
	}
	if r.agent == "" {
		r.agent = "/proc/self/exe"
	}
	if f, err := os.OpenFile("/dev/kvm", os.O_RDWR, 0); err != nil {
		return nil, unavailable("no usable KVM (/dev/kvm: %v)", err)
	} else {
		f.Close()
	}
	if _, err := os.Stat("/dev/vhost-vsock"); err != nil {
		return nil, unavailable("no /dev/vhost-vsock (load the vhost_vsock kernel module): %v", err)
	}
	if f, err := os.Open(r.kernel); err != nil {
		return nil, unavailable("kernel for the restore VM: %v (set file_restore.kernel)", err)
	} else {
		f.Close()
	}
	if st, err := os.Stat(filepath.Join(r.modules, "modules.dep")); err != nil || !st.Mode().IsRegular() {
		return nil, unavailable("kernel modules for the restore VM: no %s (set file_restore.modules_dir)", filepath.Join(r.modules, "modules.dep"))
	}
	if r.qemu == "" {
		names := []string{"qemu-system-x86_64", "/usr/libexec/qemu-kvm"}
		if runtime.GOARCH == "arm64" {
			names = []string{"qemu-system-aarch64", "/usr/libexec/qemu-kvm"}
		}
		for _, n := range names {
			if p, err := exec.LookPath(n); err == nil {
				r.qemu = p
				break
			}
		}
		if r.qemu == "" {
			return nil, unavailable("no qemu system emulator found (tried %s; set file_restore.qemu)", strings.Join(names, ", "))
		}
	} else if _, err := exec.LookPath(r.qemu); err != nil {
		return nil, unavailable("qemu %q: %v", r.qemu, err)
	}
	if ms, err := loadModuleSet(r.modules); err != nil {
		return nil, unavailable("%v", err)
	} else if _, err := ms.resolve(agentModules, requiredModules); err != nil {
		return nil, unavailable("%v", err)
	}
	switch {
	case os.Geteuid() != 0:
		// Only root can drop to another user (an unprivileged daemon, or a
		// test, runs qemu as itself).
		r.runAs = ""
	case r.runAs == "":
		for _, u := range []string{"libvirt-qemu", "qemu", "nobody"} {
			if _, err := user.Lookup(u); err == nil {
				r.runAs = u
				break
			}
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if out, err := exec.CommandContext(ctx, r.qemu, "-version").Output(); err == nil {
		r.runWith = qemuSupportsRunWith(string(out))
	}
	r.sandbox = true
	l.resolved = r
	return r, nil
}

// Session is one running restore VM and its connection.
type Session struct {
	*Client
	cmd     *exec.Cmd
	exited  chan struct{}
	nbd     *nbd.Server
	dir     string
	once    sync.Once
	started time.Time
}

// Open boots a restore VM on dev and connects to its agent. kind is
// KindFS or KindArchive; format is how qemu reads dev ("raw" or "qcow2").
func (l *Launcher) Open(ctx context.Context, dev BlockDevice, kind, format string) (*Session, error) {
	r, err := l.resolve()
	if err != nil {
		return nil, err
	}
	if l.cfg.StateDir == "" {
		return nil, errors.New("file restore: no state directory")
	}
	initrd, err := EnsureInitramfs(filepath.Join(l.cfg.StateDir, "cache"), InitramfsSpec{Agent: r.agent, ModulesDir: r.modules})
	if err != nil {
		return nil, unavailable("build the restore VM initramfs: %v", err)
	}
	runRoot := filepath.Join(l.cfg.StateDir, "run")
	if err := os.MkdirAll(runRoot, 0o700); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(runRoot, "s-")
	if err != nil {
		return nil, err
	}
	s := &Session{dir: dir, exited: make(chan struct{}), started: time.Now()}
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
	go func() { _ = s.nbd.Serve(context.Background()) }()

	serial := filepath.Join(dir, "console.log")
	spec := VMSpec{
		QEMU: r.qemu, Kernel: r.kernel, Initrd: initrd, MemoryMiB: l.cfg.memory(),
		NBDSocket: sock, Export: "backup", DiskFormat: format, Kind: kind,
		SerialLog: serial, Arch: runtime.GOARCH, RunAs: r.runAs, RunWith: r.runWith, Sandbox: r.sandbox,
	}
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		spec.CID = randomCID()
		var stderr bytes.Buffer
		if err := s.start(spec, &stderr); err != nil {
			return nil, unavailable("start qemu: %v", err)
		}
		lastErr = s.dial(ctx, spec.CID, l.cfg.bootTimeout())
		if lastErr == nil {
			ok = true
			slog.Info("file restore: restore VM up", "cid", spec.CID, "boot", time.Since(s.started).Round(time.Millisecond))
			return s, nil
		}
		s.kill() // qemu has exited (Wait done) before its stderr is read
		out := strings.TrimSpace(stderr.String())
		if strings.Contains(out, "guest cid") || strings.Contains(out, "Address already in use") {
			continue // a CID collision: pick another
		}
		if strings.Contains(out, "seccomp") && spec.Sandbox {
			slog.Warn("file restore: this qemu has no seccomp sandbox; running the restore VM without it", "qemu", r.qemu)
			spec.Sandbox = false
			l.mu.Lock()
			r.sandbox = false
			l.mu.Unlock()
			continue
		}
		if f, err := os.Open(serial); err == nil {
			if tail := tailClean(f, 600); tail != "" {
				out += " | console: " + tail
			}
			f.Close()
		}
		if len(out) > 900 {
			out = out[len(out)-900:]
		}
		return nil, unavailable("the restore VM did not come up: %v (%s)", lastErr, out)
	}
	return nil, unavailable("the restore VM did not come up: %v", lastErr)
}

func randomCID() uint32 {
	var b [4]byte
	_, _ = rand.Read(b[:])
	// 3..2^31: clear of the reserved CIDs and of the top of the range.
	return 3 + binary.BigEndian.Uint32(b[:])%(1<<31-3)
}

func (s *Session) start(spec VMSpec, stderr *bytes.Buffer) error {
	args, err := qemuArgs(spec)
	if err != nil {
		return err
	}
	cmd := exec.Command(spec.QEMU, args...)
	cmd.Stdin = nil
	cmd.Stdout = io.Discard
	cmd.Stderr = &limitedBuffer{b: stderr, max: 16 << 10}
	cmd.Dir = s.dir
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	// The VM dies with the daemon, and is its own process group so a kill
	// takes everything qemu started.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.cmd = cmd
	s.exited = make(chan struct{})
	go func(c *exec.Cmd, done chan struct{}) {
		_ = c.Wait()
		close(done)
	}(cmd, s.exited)
	return nil
}

// dial connects to the agent, retrying while the VM boots.
func (s *Session) dial(ctx context.Context, cid uint32, timeout time.Duration) error {
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
		conn, err := dialVsock(cid, AgentPort)
		if err == nil {
			s.Client = NewClient(conn)
			// The agent answers once its volumes are mounted.
			if _, err := s.Client.Volumes(); err == nil {
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

// SweepStale removes session directories a previous daemon left (their
// VMs died with it: Pdeathsig).
func SweepStale(stateDir string) {
	_ = os.RemoveAll(filepath.Join(stateDir, "run"))
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
