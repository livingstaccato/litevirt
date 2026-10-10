//go:build linux

package filerestore

import (
	"bufio"
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
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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

	slotMu sync.Mutex
	slots  [UIDSlots]bool // per-session uids in use

	cacheMu sync.Mutex
	inUse   map[string]int // boot files a running session uses
	current map[string]bool

	probeMu    sync.Mutex
	probeCache map[string]time.Time // qemu stamp -> when its sandbox last probed fine

	// Test hooks. skipRootCheck lets the fake-qemu tests exercise the start
	// logic as a non-root user without allow_unsandboxed; production never
	// sets it.
	skipRootCheck      bool
	kvmPath, vhostPath string
	checkAgent         func(path string) error
	appArmorState      func() (enabled, parser bool)
}

// NewLauncher returns a launcher for cfg. Nothing is checked until
// Preflight or Open.
func NewLauncher(cfg Config) *Launcher {
	if cfg.UIDBase == 0 {
		cfg.UIDBase = DefaultUIDBase
	}
	return &Launcher{cfg: cfg, kvmPath: "/dev/kvm", vhostPath: "/dev/vhost-vsock", checkAgent: checkStaticELF,
		appArmorState: appArmorState, inUse: map[string]int{}, current: map[string]bool{}, probeCache: map[string]time.Time{}}
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

// qemuUser is a credential qemu runs with.
type qemuUser struct {
	name     string
	uid, gid uint32
	groups   []uint32
}

// host is the checked environment for one Open.
type host struct {
	qemu, kernel, modules, agent string
	// account is the restore account (its group reads the boot files);
	// perSession means each VM runs as its own uid from the reserved range
	// with groups {account group, kvm}. Otherwise shared is the credential
	// qemu runs with (nil: the daemon's own).
	account    *qemuUser
	perSession bool
	shared     *qemuUser
	kvmGid     uint32
	gid        int // the group the boot files are readable by
	appArmor   bool
}

// EnsureRestoreUser creates DefaultRestoreUser if it does not exist: a
// system user with its own group, no home and no shell, in the kvm group.
// Idempotent; a no-op unless root. The daemon calls it at start when file
// restore is enabled (docs/installation.md).
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
	_, err := l.check()
	return err
}

func (l *Launcher) check() (*host, error) {
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
	if os.Geteuid() != 0 {
		// Without root there is no per-VM uid, no profile: qemu would run as
		// the daemon's own user, which owns data_dir and the PKI key.
		if !l.cfg.AllowUnsandboxed && !l.skipRootCheck {
			return nil, unavailable("file restore needs a root daemon (each restore VM runs as its own unprivileged uid, " +
				"confined); file_restore.allow_unsandboxed: true runs it as the daemon's own user, which is dangerous")
		}
		if f, err := os.OpenFile(l.kvmPath, os.O_RDWR, 0); err != nil {
			return nil, unavailable("no usable KVM (%s: %v)", l.kvmPath, err)
		} else {
			f.Close()
		}
	} else {
		if err := l.checkRootIdentity(h); err != nil {
			return nil, err
		}
		use, err := appArmorDecision(l.appArmorState())(l.cfg.AllowUnsandboxed)
		if err != nil {
			return nil, err
		}
		h.appArmor = use
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

// appArmorDecision decides, from whether AppArmor is enabled and its parser
// installed, whether restore VMs are confined by the profile — failing
// closed: enabled without a parser is refused unless allowUnsandboxed. A
// host without AppArmor (SELinux, no LSM) runs without the profile; each
// VM's own uid, seccomp and the single-peer export isolate it there.
func appArmorDecision(enabled, parser bool) func(allowUnsandboxed bool) (bool, error) {
	return func(allowUnsandboxed bool) (bool, error) {
		switch {
		case enabled && parser:
			return true, nil
		case enabled:
			if !allowUnsandboxed {
				return false, unavailable("AppArmor is enabled but apparmor_parser is not installed, so the restore VM's profile " +
					"cannot be loaded (install the apparmor package); file_restore.allow_unsandboxed: true runs it unconfined, which is dangerous")
			}
			slog.Warn("file restore: AppArmor is enabled but apparmor_parser is missing; restore VMs run without their profile (file_restore.allow_unsandboxed)")
			return false, nil
		default:
			return false, nil
		}
	}
}

// checkRootIdentity resolves who qemu runs as for a root daemon.
func (l *Launcher) checkRootIdentity(h *host) error {
	name := l.cfg.RunAs
	if name == "" {
		name = DefaultRestoreUser
	}
	u, err := user.Lookup(name)
	if err != nil {
		if name == DefaultRestoreUser {
			return unavailable("no user %s (the daemon creates it at start when file restore is enabled; create it with "+
				"`useradd --system --user-group --groups kvm --no-create-home --shell /usr/sbin/nologin %s`)", name, name)
		}
		return unavailable("file_restore.run_as %q: %v", name, err)
	}
	uid64, _ := strconv.ParseUint(u.Uid, 10, 32)
	gid64, _ := strconv.ParseUint(u.Gid, 10, 32)
	uid, gid := uint32(uid64), uint32(gid64)
	var kst unix.Stat_t
	if err := unix.Stat(l.kvmPath, &kst); err != nil {
		return unavailable("no usable KVM (%s: %v)", l.kvmPath, err)
	}
	h.kvmGid = kst.Gid
	if shared := sharedIdentity(name, u.Uid, uid); shared != "" {
		if !l.cfg.AllowSharedRunAs {
			return unavailable("file_restore.run_as %q is %s; restore VMs run as a dedicated account (%s) — "+
				"file_restore.allow_shared_run_as: true permits it, which is dangerous", name, shared, DefaultRestoreUser)
		}
		if uid != 0 {
			h.shared = &qemuUser{name: name, uid: uid, gid: gid, groups: []uint32{gid, kst.Gid}}
			if err := accessibleTo(l.kvmPath, h.shared); err != nil {
				return unavailable("no usable KVM for %s: %v", name, err)
			}
		}
		h.gid = int(gid)
		return nil
	}
	if err := validateRestoreAccount(u, uid, gid, kst.Gid); err != nil {
		return unavailable("%v", err)
	}
	h.account = &qemuUser{name: name, uid: uid, gid: gid}
	h.perSession, h.gid = true, int(gid)
	probe := &qemuUser{name: "per-session uid", uid: l.cfg.UIDBase, gid: gid, groups: []uint32{gid, kst.Gid}}
	if err := accessibleTo(l.kvmPath, probe); err != nil {
		return unavailable("no usable KVM for restore VMs: %v", err)
	}
	for i := uint32(0); i < UIDSlots; i++ {
		if pu, err := user.LookupId(strconv.FormatUint(uint64(l.cfg.UIDBase+i), 10)); err == nil {
			return unavailable("uid %d, reserved for restore VMs (file_restore.uid_base), belongs to %s", l.cfg.UIDBase+i, pu.Username)
		}
	}
	return nil
}

// sharedIdentity names why a run_as identity is not a dedicated one: root,
// or a user that owns production VM disks and keys or is shared.
func sharedIdentity(name, uidStr string, uid uint32) string {
	if uid == 0 {
		return "root"
	}
	for _, s := range []string{"libvirt-qemu", "qemu", "nobody"} {
		if su, err := user.Lookup(s); err == nil && su.Uid == uidStr {
			return s + ", which owns or shares production VM disks and keys"
		}
	}
	return ""
}

// validateRestoreAccount checks the restore account is what the daemon
// would have created: a system uid, no login shell, its uid used by no other
// account, and no supplementary group but its own and kvm. qemu only ever
// gets {its group, kvm}, but an account that is more than that is someone
// else's and is refused, naming what differs.
func validateRestoreAccount(u *user.User, uid, gid, kvmGid uint32) error {
	if uid >= 1000 {
		return fmt.Errorf("restore account %s has uid %d, not a system uid (< 1000)", u.Username, uid)
	}
	shell, others, err := passwdInfo(u.Username, u.Uid)
	if err != nil {
		return fmt.Errorf("restore account %s: %v", u.Username, err)
	}
	switch shell {
	case "/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false":
	default:
		return fmt.Errorf("restore account %s has login shell %q; want /usr/sbin/nologin", u.Username, shell)
	}
	if len(others) > 0 {
		return fmt.Errorf("restore account %s shares uid %d with %s", u.Username, uid, strings.Join(others, ", "))
	}
	gids, err := groupIDs(u)
	if err != nil {
		return fmt.Errorf("restore account %s: groups: %v", u.Username, err)
	}
	for _, g := range gids {
		v, _ := strconv.ParseUint(g, 10, 32)
		if uint32(v) != gid && uint32(v) != kvmGid {
			name := g
			if gg, err := user.LookupGroupId(g); err == nil {
				name = gg.Name
			}
			return fmt.Errorf("restore account %s is in group %s; it may be in its own group and kvm only", u.Username, name)
		}
	}
	return nil
}

// groupIDs lists u's groups (a var for tests).
var groupIDs = func(u *user.User) ([]string, error) { return u.GroupIds() }

// passwdPath is the passwd file read for shells and uid uniqueness (tests).
var passwdPath = "/etc/passwd"

// passwdInfo returns name's login shell and the other accounts with its uid.
func passwdInfo(name, uid string) (shell string, others []string, err error) {
	f, err := os.Open(passwdPath)
	if err != nil {
		return "", nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	found := false
	for sc.Scan() {
		p := strings.Split(sc.Text(), ":")
		if len(p) < 7 {
			continue
		}
		if p[0] == name {
			shell, found = p[6], true
		} else if p[2] == uid {
			others = append(others, p[0])
		}
	}
	if !found {
		return "", nil, fmt.Errorf("not in %s (a directory-service account is not a dedicated one)", passwdPath)
	}
	return shell, others, sc.Err()
}

// sandboxOpts is qemu's seccomp sandbox for a restore VM.
const sandboxOpts = "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny"

// probeSandbox starts qemu with the sandbox and nothing else (no machine,
// paused) as u. A qemu that cannot install it exits at once and says so; one
// that can is still running after a moment and is killed.
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

// probeTTL bounds how long a passed sandbox probe of one qemu binary (by
// path, inode, size and times) is trusted. A failed one is never cached.
const probeTTL = 10 * time.Minute

func qemuStamp(path string) string {
	var st unix.Stat_t
	if err := unix.Stat(path, &st); err != nil {
		return ""
	}
	return fmt.Sprintf("%s|%d|%d|%d|%d|%d", path, st.Dev, st.Ino, st.Size, st.Mtim.Nano(), st.Ctim.Nano())
}

// sandboxOK asks qemu (or recalls a recent pass for the same binary).
func (l *Launcher) sandboxOK(ctx context.Context, qemu string, u *qemuUser) (bool, string) {
	stamp := qemuStamp(qemu)
	l.probeMu.Lock()
	t, ok := l.probeCache[stamp]
	l.probeMu.Unlock()
	if ok && stamp != "" && time.Since(t) < probeTTL {
		return true, ""
	}
	pass, msg := probeSandbox(ctx, qemu, u)
	if pass && stamp != "" {
		l.probeMu.Lock()
		l.probeCache[stamp] = time.Now()
		l.probeMu.Unlock()
	}
	return pass, msg
}

// supportsExitWithParent reports whether qemu knows -run-with
// exit-with-parent (9.1+).
func supportsExitWithParent(ctx context.Context, qemu string) bool {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	out, _ := exec.CommandContext(ctx, qemu, "-run-with", "help").CombinedOutput()
	return bytes.Contains(out, []byte("exit-with-parent"))
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

// appArmorState reports whether AppArmor is enabled in the kernel, and
// whether its parser is installed.
func appArmorState() (enabled, parser bool) {
	b, err := os.ReadFile("/sys/module/apparmor/parameters/enabled")
	enabled = err == nil && strings.HasPrefix(string(b), "Y")
	_, perr := exec.LookPath("apparmor_parser")
	return enabled, perr == nil
}

// appArmorProfileText is the restore qemu's profile: the qemu binary and its
// libraries and firmware, /dev/kvm, the vhost-vsock device its inherited fd
// is revalidated against at exec, the boot files, and the sessions' sockets
// and nonces (which DAC narrows to its own: each session is its own uid, and
// both are gone or unlinked once qemu has them). Its own /proc entries only
// (owner: its session's uid). No IP networking, no abstract unix sockets, no
// ptrace, no mount, nothing of /var/lib/litevirt or any VM disk.
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
  owner @{PROC}/@{pid}/{stat,statm,status,maps,auxv} r,
  owner @{PROC}/@{pid}/fd/ r,
  owner @{PROC}/@{pid}/task/ r,
  owner @{PROC}/@{pid}/task/*/{stat,comm} rw,

  /dev/kvm rw,
  /dev/vhost-vsock rw,

  ` + filepath.Join(cacheDir, "*") + ` r,
  ` + filepath.Join(runDir, "s-*", "nbd-*.sock") + ` rw,
  ` + filepath.Join(runDir, "s-*", "nonce") + ` r,
  unix (connect, send, receive) type=stream peer=(label=unconfined),
  deny unix (connect, send, receive) peer=(addr=@**),

  signal (receive) peer=unconfined,
  deny ptrace,
  deny mount,
  deny network inet,
  deny network inet6,
}
`
}

// ensureProfile loads (or reloads, if its text changed or it is not loaded
// in enforce mode) the restore qemu's AppArmor profile from memory: nothing
// is written under /etc or to a cache.
func (l *Launcher) ensureProfile() error {
	text := appArmorProfileText(l.cfg.CacheDir, l.cfg.RunDir)
	l.aaMu.Lock()
	defer l.aaMu.Unlock()
	if l.aaLoaded == text && profileEnforced() {
		return nil
	}
	cmd := exec.Command("apparmor_parser", "-r")
	cmd.Stdin = strings.NewReader(text)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("load AppArmor profile %s: %v: %s", AppArmorProfile, err, strings.TrimSpace(string(out)))
	}
	if !profileEnforced() {
		return fmt.Errorf("AppArmor profile %s is not loaded in enforce mode after loading it", AppArmorProfile)
	}
	l.aaLoaded = text
	return nil
}

func profileEnforced() bool {
	b, err := os.ReadFile("/sys/kernel/security/apparmor/profiles")
	return err == nil && bytes.Contains(b, []byte(AppArmorProfile+" (enforce)"))
}

// allocUID takes a free per-session uid.
func (l *Launcher) allocUID() (uint32, func(), error) {
	l.slotMu.Lock()
	defer l.slotMu.Unlock()
	for i := range l.slots {
		if !l.slots[i] {
			l.slots[i] = true
			return l.cfg.UIDBase + uint32(i), func() {
				l.slotMu.Lock()
				l.slots[i] = false
				l.slotMu.Unlock()
			}, nil
		}
	}
	return 0, nil, unavailable("all %d restore VM uids are in use", UIDSlots)
}

// useBootFiles marks boot files in use by a session; the returned func
// releases them. Files neither current nor in use are collected.
func (l *Launcher) useBootFiles(current bool, paths ...string) func() {
	l.cacheMu.Lock()
	if current {
		// The newest builds supersede the ones before.
		l.current = map[string]bool{}
	}
	for _, p := range paths {
		l.inUse[p]++
		if current {
			l.current[p] = true
		}
	}
	keep := func(p string) bool { return l.inUse[p] > 0 || l.current[p] }
	GCCache(l.cfg.CacheDir, keep)
	l.cacheMu.Unlock()
	return func() {
		l.cacheMu.Lock()
		for _, p := range paths {
			if l.inUse[p]--; l.inUse[p] <= 0 {
				delete(l.inUse, p)
			}
		}
		l.cacheMu.Unlock()
	}
}

// Session is one running restore VM and its connection.
type Session struct {
	*Client
	cmd       *exec.Cmd
	exited    chan struct{}
	nbd       *nbd.Server
	dir       string
	console   *consoleRing
	once      sync.Once
	started   time.Time
	pgid      atomic.Int64 // the VM's process group (0 until started)
	qemuPid   atomic.Int64 // the vetted NBD peer: qemu itself
	releasers []func()
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
	s := &Session{exited: make(chan struct{}), started: time.Now(), console: newConsoleRing(64 << 10)}
	ok := false
	defer func() {
		if !ok {
			s.Close()
		}
	}()
	// Who this VM runs as.
	var cred *qemuUser
	wantUID := uint32(os.Geteuid())
	switch {
	case h.perSession:
		uid, release, err := l.allocUID()
		if err != nil {
			return nil, err
		}
		s.releasers = append(s.releasers, release)
		cred = &qemuUser{name: fmt.Sprintf("uid %d", uid), uid: uid, gid: h.account.gid, groups: []uint32{h.account.gid, h.kvmGid}}
		wantUID = uid
	case h.shared != nil:
		cred, wantUID = h.shared, h.shared.uid
	}
	// Ask this qemu, as the VM will run, whether it can install its seccomp
	// sandbox — for this VM.
	sandbox, sandboxMsg := l.sandboxOK(ctx, h.qemu, cred)
	if !sandbox && !l.cfg.AllowUnsandboxed {
		return nil, unavailable("this qemu cannot run with its seccomp sandbox (%s); refusing to run a restore VM without it — "+
			"file_restore.allow_unsandboxed: true permits it, which is dangerous (see docs/backups.md)", wire.EscapeBounded(sandboxMsg, 300))
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
	boot := []string{initrd}
	kernel := h.kernel
	if cred != nil {
		// The host's kernel image is root-only; qemu reads a group copy.
		if kernel, err = ensureKernelCopy(l.cfg.CacheDir, h.kernel, h.gid, l.cfg.OnTamper); err != nil {
			return nil, unavailable("copy the kernel for the restore VM: %v", err)
		}
		boot = append(boot, kernel)
	}
	s.releasers = append(s.releasers, l.useBootFiles(true, boot...))

	if err := os.MkdirAll(l.cfg.RunDir, 0o711); err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp(l.cfg.RunDir, "s-")
	if err != nil {
		return nil, err
	}
	s.dir = dir
	if cred != nil {
		// qemu (another uid) must reach its socket and nonce in here.
		if err := os.Chmod(dir, 0o711); err != nil {
			return nil, err
		}
	}

	nonce := newNonce()
	nonceFile := filepath.Join(dir, "nonce")
	if err := os.WriteFile(nonceFile, []byte(nonce), 0o400); err != nil {
		return nil, err
	}
	if cred != nil {
		if err := os.Chown(nonceFile, int(cred.uid), int(cred.gid)); err != nil {
			return nil, err
		}
	}
	// Each attempt gets its own single-peer export: a qemu that took one and
	// then failed (a CID collision) has used it up.
	export := func(attempt int) (string, error) {
		if s.nbd != nil {
			s.nbd.Stop()
		}
		sock := filepath.Join(dir, fmt.Sprintf("nbd-%d.sock", attempt))
		srv := &nbd.Server{ExportName: "backup", Dev: dev, SinglePeer: true,
			PeerCheck: func(c net.Conn) error { return s.vetPeer(c, wantUID, h.appArmor) }}
		if err := srv.ListenUnix(sock); err != nil {
			return "", err
		}
		if cred != nil {
			if err := os.Chown(sock, int(cred.uid), int(cred.gid)); err != nil {
				srv.Stop()
				return "", err
			}
		}
		s.nbd = srv
		go func() { _ = srv.Serve(context.Background()) }()
		return sock, nil
	}

	spec := VMSpec{
		QEMU: h.qemu, Kernel: kernel, Initrd: initrd, MemoryMiB: l.cfg.memory(),
		Export: "backup", DiskFormat: format, Kind: kind,
		Arch: runtime.GOARCH, VhostFD: 3, NonceFile: nonceFile,
		AgentIdleSec: int(l.cfg.agentIdle() / time.Second), Sandbox: sandbox,
		ExitWithParent: supportsExitWithParent(ctx, h.qemu),
	}
	if !sandbox {
		slog.Warn("file restore: running a restore VM WITHOUT qemu's seccomp sandbox (file_restore.allow_unsandboxed)", "qemu", h.qemu, "why", sandboxMsg)
	}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		spec.CID = randomCID()
		if spec.NBDSocket, err = export(attempt); err != nil {
			return nil, err
		}
		var stderr bytes.Buffer
		if err := l.start(s, spec, h, cred, wantUID, &stderr); err != nil {
			return nil, unavailable("start qemu: %v", err)
		}
		lastErr = s.dial(ctx, spec.CID, nonce, l.cfg.bootTimeout())
		if lastErr == nil {
			// qemu has read its nonce (fw_cfg reads the file at start).
			_ = os.Remove(nonceFile)
			if err := s.verifyConfined(wantUID, h.appArmor); err != nil {
				return nil, unavailable("%v", err)
			}
			ok = true
			slog.Info("file restore: restore VM up", "cid", spec.CID, "uid", wantUID, "boot", time.Since(s.started).Round(time.Millisecond),
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

// vetPeer accepts the NBD connection only from this session's qemu: the
// peer runs as the session's uid, in the session's process group, and —
// with AppArmor — already confined by the restore profile. Only then is it
// handed the disk.
func (s *Session) vetPeer(c net.Conn, wantUID uint32, appArmor bool) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if cerr != nil {
		return cerr
	}
	if cred.Uid != wantUID {
		return fmt.Errorf("peer uid %d, want %d", cred.Uid, wantUID)
	}
	// qemu can connect before Start has returned to record the group.
	pgid := s.pgid.Load()
	for i := 0; pgid == 0 && i < 100; i++ {
		time.Sleep(20 * time.Millisecond)
		pgid = s.pgid.Load()
	}
	if pgid == 0 {
		return errors.New("the session's VM has not started")
	}
	if got, err := unix.Getpgid(int(cred.Pid)); err != nil || int64(got) != pgid {
		return fmt.Errorf("peer pid %d is not in the session's process group %d", cred.Pid, pgid)
	}
	if appArmor {
		if label := procLabel(int(cred.Pid)); !strings.HasPrefix(label, AppArmorProfile+" (enforce)") {
			return fmt.Errorf("peer pid %d is not confined by %s (%q)", cred.Pid, AppArmorProfile, label)
		}
	}
	s.qemuPid.Store(int64(cred.Pid))
	return nil
}

// verifyConfined re-checks, once the agent answered, that the qemu holding
// the disk is still the vetted, confined process.
func (s *Session) verifyConfined(wantUID uint32, appArmor bool) error {
	pid := int(s.qemuPid.Load())
	if pid == 0 {
		return errors.New("the restore VM's qemu never connected to its disk")
	}
	if uid := procUID(pid); uid != int(wantUID) {
		return fmt.Errorf("the restore VM's qemu runs as uid %d, want %d", uid, wantUID)
	}
	if appArmor {
		if label := procLabel(pid); !strings.HasPrefix(label, AppArmorProfile+" (enforce)") {
			return fmt.Errorf("the restore VM's qemu is not confined by %s (%q)", AppArmorProfile, label)
		}
	}
	return nil
}

// procLabel is pid's current LSM label (AppArmor's attr/current).
func procLabel(pid int) string {
	for _, p := range []string{"/proc/%d/attr/apparmor/current", "/proc/%d/attr/current"} {
		if b, err := os.ReadFile(fmt.Sprintf(p, pid)); err == nil {
			return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
		}
	}
	return ""
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
// root), in its own process group, killed when the daemon dies. Go applies
// the parent-death signal AFTER the credential change, so it survives it.
// With profile set, the litevirt binary at trampoline runs first, as qemu's
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

func (l *Launcher) start(s *Session, spec VMSpec, h *host, cred *qemuUser, uid uint32, stderr *bytes.Buffer) error {
	vhost, err := os.OpenFile(l.vhostPath, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer vhost.Close() // qemu holds its own copy
	profile := ""
	if h.appArmor {
		profile = AppArmorProfile
	}
	cmd, err := qemuCommand(spec, cred, s.dir, vhost, s.console, &limitedBuffer{b: stderr, max: 16 << 10}, h.agent, profile)
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	s.cmd = cmd
	s.pgid.Store(int64(cmd.Process.Pid))
	s.exited = make(chan struct{})
	go func(c *exec.Cmd, done chan struct{}) {
		_ = c.Wait()
		close(done)
	}(cmd, s.exited)
	// The pidfile (pid and uid) lets a later daemon find and kill this VM
	// if this one dies without doing so (SweepStale).
	return os.WriteFile(filepath.Join(s.dir, pidFile), []byte(fmt.Sprintf("%d %d\n", cmd.Process.Pid, uid)), 0o600)
}

const pidFile = "qemu.pid"

// helloTimeout bounds one hello during boot.
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
// export, removes the session directory and releases its uid and boot
// files. Idempotent.
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
		for i := len(s.releasers) - 1; i >= 0; i-- {
			s.releasers[i]()
		}
	})
}

// SweepStale kills the restore VMs a previous daemon left and removes their
// session directories. Two ways, each verified before any signal:
//
//   - a session's pidfile: the named process, held by a pidfd from before
//     the checks to the kill, runs as the recorded uid with the restore VM's
//     command line for THAT session; it and its process group are killed;
//   - any process running as one of the reserved per-session uids (uidBase,
//     UIDSlots of them; 0 = none) whose command line is a restore VM — which
//     finds a qemu whose trampoline, and so whose pidfile record, is gone.
//
// Returns the number killed.
func SweepStale(runDir string, uidBase uint32) int {
	killed := 0
	if ents, err := os.ReadDir(runDir); err == nil {
		for _, e := range ents {
			if !e.IsDir() || !strings.HasPrefix(e.Name(), "s-") {
				continue
			}
			dir := filepath.Join(runDir, e.Name())
			if pid, uid := readPid(filepath.Join(dir, pidFile)); pid > 1 && killVerified(pid, uid, func(p int) bool { return isRestoreVM(p, dir) }) {
				killed++
			}
			_ = os.RemoveAll(dir)
		}
	}
	if uidBase == 0 {
		return killed
	}
	procs, _ := os.ReadDir("/proc")
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid <= 1 {
			continue
		}
		uid := procUID(pid)
		if uid < int(uidBase) || uid >= int(uidBase)+UIDSlots {
			continue
		}
		if killVerified(pid, uid, isRestoreVMAny) {
			killed++
		}
	}
	return killed
}

// killVerified SIGKILLs pid (and its process group, when it leads one) if it
// still runs as uid and match says its command line is a restore VM.
func killVerified(pid, uid int, match func(pid int) bool) bool {
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return false // gone (or no pidfd support: never kill unverified)
	}
	defer unix.Close(pidfd)
	if !match(pid) || procUID(pid) != uid {
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
	if pg, err := unix.Getpgid(pid); err == nil && pg == pid {
		_ = syscall.Kill(-pid, syscall.SIGKILL)
	}
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

func procArgs(pid int) []string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid))
	if err != nil {
		return nil
	}
	return strings.Split(string(b), "\x00")
}

func hasRestoreName(args []string) bool {
	for i, a := range args {
		if a == "-name" && i+1 < len(args) && args[i+1] == "litevirt-file-restore" {
			return true
		}
	}
	return false
}

// isRestoreVM reports whether pid's command line is the restore VM of the
// session directory dir.
func isRestoreVM(pid int, dir string) bool {
	args := procArgs(pid)
	if !hasRestoreName(args) {
		return false
	}
	for _, a := range args {
		if strings.Contains(a, `"path":"`+filepath.Join(dir, "nbd-")) {
			return true
		}
	}
	return false
}

// isRestoreVMAny reports whether pid's command line is any restore VM.
func isRestoreVMAny(pid int) bool { return hasRestoreName(procArgs(pid)) }

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
// <profile> <qemu> <args...>` (already as the VM's uid, in the session's
// process group). It runs in two stages:
//
//   - the parent stage stays as qemu's parent: it starts the second stage,
//     and on SIGTERM (the parent-death signal the daemon gives it) or any end
//     kills it and exits with its status;
//   - the exec stage (`… __file-restore-exec --exec <profile> <qemu> …`)
//     locks its OS thread, sets that thread's AppArmor profile for its next
//     exec, sets no_new_privs, and execs qemu in place, which starts
//     confined.
//
// Two stages because AppArmor's on-exec profile applies to the task (thread)
// that set it, not to a child it forks, and because the exec into a new
// profile is a secure exec, across which the kernel clears the parent-death
// signal. The daemon still checks the result: the NBD peer and, after the
// hello, the qemu process must carry the profile in enforce mode.
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
	// The on-exec attribute is per thread: write it and exec from the same
	// one.
	runtime.LockOSThread()
	profile, qemu := args[0], args[1]
	if err := setExecProfile(profile); err != nil {
		fmt.Fprintf(os.Stderr, "file-restore exec: set AppArmor profile %s: %v\n", profile, err)
		os.Exit(1)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "file-restore exec: no_new_privs: %v\n", err)
		os.Exit(1)
	}
	err := syscall.Exec(qemu, append([]string{qemu}, args[2:]...), os.Environ())
	fmt.Fprintf(os.Stderr, "file-restore exec: exec %s: %v\n", qemu, err)
	os.Exit(1)
}

// setExecProfile asks AppArmor to confine this thread's next exec by profile
// (aa_change_onexec), through this thread's own attributes.
func setExecProfile(profile string) error {
	msg := []byte("exec " + profile)
	var err error
	for _, p := range []string{"/proc/thread-self/attr/apparmor/exec", "/proc/thread-self/attr/exec"} {
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
