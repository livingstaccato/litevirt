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
	"encoding/json"
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

	rangeMu      sync.Mutex
	rangeChecked time.Time // when the reserved uids were last found free

	// Test hooks. skipRootCheck lets the fake-qemu tests exercise the start
	// logic as a non-root user without allow_unsandboxed; production never
	// sets it. trampoline replaces the binary run as the trampoline ("" =
	// the agent, i.e. this litevirt binary); landlockExtra adds to the
	// restore qemu's Landlock ruleset.
	skipRootCheck      bool
	kvmPath, vhostPath string
	checkAgent         func(path string) error
	appArmorState      func() (enabled, parser bool)
	landlockABI        func() int
	trampoline         string
	landlockExtra      landlockPolicy
}

// NewLauncher returns a launcher for cfg. Nothing is checked until
// Preflight or Open.
func NewLauncher(cfg Config) *Launcher {
	if cfg.UIDBase == 0 {
		cfg.UIDBase = DefaultUIDBase
	}
	return &Launcher{cfg: cfg, kvmPath: "/dev/kvm", vhostPath: "/dev/vhost-vsock", checkAgent: checkStaticELF,
		appArmorState: appArmorState, landlockABI: landlockAvailable,
		inUse: map[string]int{}, current: map[string]bool{}, probeCache: map[string]time.Time{}}
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
	// appArmor: the profile confines qemu; aaEnabled: AppArmor is on in the
	// kernel (used or not); landlock: the Landlock ABI applied (0 = none).
	appArmor, aaEnabled bool
	landlock            int
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
		if !l.cfg.Unsandboxed.Root && !l.skipRootCheck {
			return nil, unavailable("file restore needs a root daemon (each restore VM runs as its own unprivileged uid, " +
				"confined); file_restore.allow_unsandboxed: [root] runs it as the daemon's own user, which is dangerous")
		}
		if f, err := os.OpenFile(l.kvmPath, os.O_RDWR, 0); err != nil {
			return nil, unavailable("no usable KVM (%s: %v)", l.kvmPath, err)
		} else {
			f.Close()
		}
		// A non-root daemon cannot load the AppArmor profile: Landlock is
		// its only MAC barrier.
		h.aaEnabled, _ = l.appArmorState()
		_, ll, err := confinementDecision(false, false, l.landlockABI(), l.cfg.Unsandboxed.MAC)
		if err != nil {
			return nil, err
		}
		h.landlock = ll
	} else {
		if err := l.checkRootIdentity(h); err != nil {
			return nil, err
		}
		enabled, parser := l.appArmorState()
		use, ll, err := confinementDecision(enabled, parser, l.landlockABI(), l.cfg.Unsandboxed.MAC)
		if err != nil {
			return nil, err
		}
		h.appArmor, h.aaEnabled, h.landlock = use, enabled, ll
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
	} else if p, err := exec.LookPath(h.qemu); err != nil {
		return nil, unavailable("qemu %q: %v", h.qemu, err)
	} else {
		h.qemu = p // the trampoline execs a path
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

// confinementDecision decides, from whether AppArmor is enabled and its
// parser installed and from the kernel's Landlock ABI, what confines a
// restore VM's qemu: the AppArmor profile where it can be loaded, and a
// Landlock ruleset wherever the kernel has Landlock (both, where both are
// there). It fails closed:
//   - AppArmor enabled without its parser is refused (R2-I2), even with
//     Landlock, unless the operator allowed running without a MAC barrier;
//   - a host with neither (no AppArmor, a kernel without Landlock) is refused
//     unless the same: the per-session uid alone does not keep an escaped
//     qemu from world-readable VM disks or the host's network.
func confinementDecision(aaEnabled, aaParser bool, llABI int, allowNoMAC bool) (appArmor bool, landlock int, err error) {
	if llABI < 0 {
		llABI = 0
	}
	switch {
	case aaEnabled && aaParser:
		return true, llABI, nil
	case aaEnabled:
		if !allowNoMAC {
			return false, 0, unavailable("AppArmor is enabled but apparmor_parser is not installed, so the restore VM's profile " +
				"cannot be loaded (install the apparmor package); file_restore.allow_unsandboxed: [mac] runs it without the profile, which is dangerous")
		}
		slog.Warn("file restore: AppArmor is enabled but apparmor_parser is missing; restore VMs run without their profile (file_restore.allow_unsandboxed: [mac])",
			"landlock_abi", llABI)
		return false, llABI, nil
	case llABI >= 1:
		return false, llABI, nil
	default:
		if !allowNoMAC {
			return false, 0, unavailable("neither AppArmor nor Landlock is available on this host, so nothing but its uid would confine " +
				"a restore VM's qemu (enable Landlock: a kernel with CONFIG_SECURITY_LANDLOCK and landlock in lsm=); " +
				"file_restore.allow_unsandboxed: [mac] runs it without, which is dangerous")
		}
		slog.Warn("file restore: neither AppArmor nor Landlock is available; restore VMs run without a MAC barrier (file_restore.allow_unsandboxed: [mac])")
		return false, 0, nil
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
	if err := l.checkRange(); err != nil {
		return unavailable("%v", err)
	}
	return nil
}

// checkRange runs uidRangeConflict, trusting a pass for probeTTL (it asks
// NSS, which may be a directory service).
func (l *Launcher) checkRange() error {
	l.rangeMu.Lock()
	defer l.rangeMu.Unlock()
	if !l.rangeChecked.IsZero() && time.Since(l.rangeChecked) < probeTTL {
		return nil
	}
	if err := l.uidRangeConflict(); err != nil {
		return err
	}
	l.rangeChecked = time.Now()
	return nil
}

// uidRangeConflict refuses reserved per-session uids that are anyone
// else's: inside the containers' id-map range, inside any subordinate id
// range (/etc/subuid, /etc/subgid: Incus, podman, a hand-written LXC idmap),
// or an account NSS knows (LDAP, sssd and systemd's included). A container
// process with one of those uids could signal a restore qemu, and an escaped
// qemu could reach that container's files.
func (l *Launcher) uidRangeConflict() error {
	return reservedRangeConflict(l.cfg.UIDBase, l.cfg.ContainerIDs)
}

func reservedRangeConflict(base uint32, containers [2]uint64) error {
	lo, hi := uint64(base), uint64(base)+UIDSlots
	if containers[1] > containers[0] && lo < containers[1] && containers[0] < hi {
		return fmt.Errorf("the uids reserved for restore VMs (file_restore.uid_base: %d..%d) overlap the containers' id-map range "+
			"%d..%d (containers.idmap_base, idmap_ranges); move file_restore.uid_base", lo, hi-1, containers[0], containers[1]-1)
	}
	for _, p := range subIDPaths {
		if err := subIDConflict(p, lo, hi); err != nil {
			return err
		}
	}
	uids := make([]uint32, UIDSlots)
	for i := range uids {
		uids[i] = base + uint32(i)
	}
	owners, err := uidOwners(uids)
	if err != nil {
		return fmt.Errorf("could not check that no account has a uid reserved for restore VMs (file_restore.uid_base): %v", err)
	}
	for _, u := range uids {
		if name, ok := owners[u]; ok {
			return fmt.Errorf("uid %d, reserved for restore VMs (file_restore.uid_base), belongs to %s", u, name)
		}
	}
	return nil
}

// subIDPaths are the subordinate id files checked (a var for tests).
var subIDPaths = []string{"/etc/subuid", "/etc/subgid"}

// subIDConflict reports a range in path ("owner:start:count" lines) that
// overlaps [lo, hi). A missing file is none.
func subIDConflict(path string, lo, hi uint64) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read %s: %v", path, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		p := strings.Split(line, ":")
		if len(p) != 3 {
			continue
		}
		start, err1 := strconv.ParseUint(p[1], 10, 64)
		count, err2 := strconv.ParseUint(p[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		if lo < start+count && start < hi {
			return fmt.Errorf("%s gives %s ids %d..%d, which overlap the uids reserved for restore VMs (file_restore.uid_base: %d..%d); move file_restore.uid_base",
				path, p[0], start, start+count-1, lo, hi-1)
		}
	}
	return sc.Err()
}

// uidOwners names the accounts NSS knows for uids (a var for tests).
var uidOwners = getentOwners

// getentOwners asks NSS through getent(1) — the static litevirt binary
// cannot load NSS modules itself, so os/user sees /etc/passwd only. Without
// getent it falls back to /etc/passwd.
func getentOwners(uids []uint32) (map[uint32]string, error) {
	out := map[uint32]string{}
	getent, err := exec.LookPath("getent")
	if err != nil {
		for _, u := range uids {
			if pu, err := user.LookupId(strconv.FormatUint(uint64(u), 10)); err == nil {
				out[u] = pu.Username
			}
		}
		return out, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := []string{"passwd"}
	for _, u := range uids {
		args = append(args, strconv.FormatUint(uint64(u), 10))
	}
	cmd := exec.CommandContext(ctx, getent, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	b, err := cmd.Output()
	if err != nil {
		// Exit 2: one or more keys not found — the normal answer.
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.ExitCode() != 2 {
			return nil, fmt.Errorf("getent passwd: %v", err)
		}
	}
	for _, line := range strings.Split(string(b), "\n") {
		p := strings.Split(line, ":")
		if len(p) < 3 {
			continue
		}
		if v, err := strconv.ParseUint(p[2], 10, 32); err == nil {
			out[uint32(v)] = p[0]
		}
	}
	return out, nil
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
// both are gone or unlinked once qemu has them). No IP networking, no
// abstract unix sockets, no ptrace, no mount, nothing of /var/lib/litevirt or
// any VM disk.
//
// The profile does not by itself separate one session's qemu from another's:
// every restore qemu carries the same profile, its "owner" /proc rules match
// any process of the same uid, and abstractions/base grants signals between
// processes of one profile (signal peer=@{profile_name}) and reads of any
// process's /proc/<pid>/{maps,auxv,status} (maps and auxv are still stopped
// by deny ptrace). What separates sessions is DAC: each runs as its own uid
// (and, where the kernel has it, Landlock's own domain per qemu).
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
	return err == nil && profileEnforcedIn(b)
}

// profileEnforcedIn reports whether the loaded-profiles listing b holds the
// restore profile in enforce mode, as a whole line (not a profile whose name
// merely ends in it, nor a hat or child of another).
func profileEnforcedIn(b []byte) bool {
	want := []byte(AppArmorProfile + " (enforce)")
	for _, line := range bytes.Split(b, []byte("\n")) {
		if bytes.Equal(bytes.TrimSpace(line), want) {
			return true
		}
	}
	return false
}

// allocUID takes a free per-session uid: one no session holds and no
// process runs as. A process left with a released uid (a qemu that escaped
// its process group and outlived its session) would otherwise share the next
// session's identity; it is killed, and that uid skipped for now.
func (l *Launcher) allocUID() (uint32, func(), error) {
	l.slotMu.Lock()
	defer l.slotMu.Unlock()
	busy := uidProcs(l.cfg.UIDBase, l.cfg.UIDBase+UIDSlots)
	for i := range l.slots {
		if l.slots[i] {
			continue
		}
		if pids := busy[l.cfg.UIDBase+uint32(i)]; len(pids) > 0 {
			slog.Warn("file restore: a process still runs as a released restore VM uid; killing it and using another",
				"uid", l.cfg.UIDBase+uint32(i), "pids", pids)
			for _, pid := range pids {
				killUIDProcess(pid, l.cfg.UIDBase+uint32(i), l.cfg.UIDBase+uint32(i)+1)
			}
			continue
		}
		l.slots[i] = true
		return l.cfg.UIDBase + uint32(i), func() {
			l.slotMu.Lock()
			l.slots[i] = false
			l.slotMu.Unlock()
		}, nil
	}
	return 0, nil, unavailable("all %d restore VM uids are in use", UIDSlots)
}

// uidProcs lists, by uid, the processes running with any uid (real,
// effective, saved or filesystem) in [lo, hi) (a var for tests).
var uidProcs = func(lo, hi uint32) map[uint32][]int {
	out := map[uint32][]int{}
	procs, _ := os.ReadDir("/proc")
	self := os.Getpid()
	for _, p := range procs {
		pid, err := strconv.Atoi(p.Name())
		if err != nil || pid <= 1 || pid == self {
			continue
		}
		seen := map[uint32]bool{}
		for _, u := range procStatusUIDs(pid) {
			if u >= int(lo) && u < int(hi) && !seen[uint32(u)] {
				seen[uint32(u)] = true
				out[uint32(u)] = append(out[uint32(u)], pid)
			}
		}
	}
	return out
}

// procStatusUIDs is pid's real, effective, saved and filesystem uids (nil
// when it is gone) (a var for tests).
var procStatusUIDs = func(pid int) []int {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return nil
	}
	for _, l := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(l, "Uid:") {
			var out []int
			for _, f := range strings.Fields(l)[1:] {
				if n, err := strconv.Atoi(f); err == nil {
					out = append(out, n)
				}
			}
			return out
		}
	}
	return nil
}

// killUIDProcess SIGKILLs pid, held by a pidfd from before the check to the
// kill, if any of its uids is still in [lo, hi). Whatever its command line
// says: a process can rewrite its own.
func killUIDProcess(pid int, lo, hi uint32) bool {
	if pid <= 1 || pid == os.Getpid() {
		return false
	}
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return false
	}
	defer unix.Close(pidfd)
	in := false
	for _, u := range procStatusUIDs(pid) {
		if u >= int(lo) && u < int(hi) {
			in = true
		}
	}
	if !in {
		return false
	}
	return unix.PidfdSendSignal(pidfd, unix.SIGKILL, nil, 0) == nil
}

// useBootFiles marks boot files in use by a session; the returned func
// releases them. Files neither current nor in use are collected.
func (l *Launcher) useBootFiles(current bool, paths ...string) func() {
	l.cacheMu.Lock()
	defer l.cacheMu.Unlock()
	return l.useBootFilesLocked(current, paths...)
}

// useBootFilesLocked is useBootFiles with cacheMu held — held, in Open,
// since the files were built and verified, so no other session's collection
// can remove them in between.
func (l *Launcher) useBootFilesLocked(current bool, paths ...string) func() {
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
	uid       uint32       // the per-session uid (0: none)
	releasers []func()
	// barriers says what isolates this VM (audited); reduced: one of its
	// barriers is missing.
	barriers string
	reduced  bool
}

// FileRestoreBarriers reports what isolates this restore VM —
// "sandbox=on|off apparmor=on|off|absent landlock=<abi>|off uid=<n>" — and
// whether one of its barriers is missing (no seccomp sandbox, no MAC, or no
// per-session uid).
func (s *Session) FileRestoreBarriers() (string, bool) { return s.barriers, s.reduced }

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
		s.uid = uid
		cred = &qemuUser{name: fmt.Sprintf("uid %d", uid), uid: uid, gid: h.account.gid, groups: []uint32{h.account.gid, h.kvmGid}}
		wantUID = uid
		recordUIDBase(l.cfg.RunDir, l.cfg.UIDBase)
	case h.shared != nil:
		cred, wantUID = h.shared, h.shared.uid
	}
	// Ask this qemu, as the VM will run, whether it can install its seccomp
	// sandbox — for this VM.
	sandbox, sandboxMsg := l.sandboxOK(ctx, h.qemu, cred)
	if !sandbox && !l.cfg.Unsandboxed.Seccomp {
		return nil, unavailable("this qemu cannot run with its seccomp sandbox (%s); refusing to run a restore VM without it — "+
			"file_restore.allow_unsandboxed: [seccomp] permits it, which is dangerous (see docs/backups.md)", wire.EscapeBounded(sandboxMsg, 300))
	}
	if h.appArmor {
		if err := l.ensureProfile(); err != nil {
			return nil, unavailable("%v", err)
		}
	}
	// Built, verified and marked in use under one lock: another session's
	// collection cannot remove them in between.
	l.cacheMu.Lock()
	initrd, err := EnsureInitramfs(l.cfg.CacheDir, InitramfsSpec{Agent: h.agent, ModulesDir: h.modules}, h.gid, l.cfg.OnTamper)
	if err != nil {
		l.cacheMu.Unlock()
		return nil, unavailable("build the restore VM initramfs: %v", err)
	}
	boot := []string{initrd}
	kernel := h.kernel
	if cred != nil {
		// The host's kernel image is root-only; qemu reads a group copy.
		if kernel, err = ensureKernelCopy(l.cfg.CacheDir, h.kernel, h.gid, l.cfg.OnTamper); err != nil {
			l.cacheMu.Unlock()
			return nil, unavailable("copy the kernel for the restore VM: %v", err)
		}
		boot = append(boot, kernel)
	}
	s.releasers = append(s.releasers, l.useBootFilesLocked(true, boot...))
	l.cacheMu.Unlock()

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
		slog.Warn("file restore: running a restore VM WITHOUT qemu's seccomp sandbox (file_restore.allow_unsandboxed: [seccomp])", "qemu", h.qemu, "why", sandboxMsg)
	}
	var lastErr error
	for attempt := 0; attempt < 6; attempt++ {
		spec.CID = randomCID()
		// A previous attempt's group and qemu are gone: vet and verify this
		// attempt's only.
		s.pgid.Store(0)
		s.qemuPid.Store(0)
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
			s.barriers, s.reduced = barrierSummary(spec.Sandbox, h, wantUID)
			slog.Info("file restore: restore VM up", "cid", spec.CID, "boot", time.Since(s.started).Round(time.Millisecond),
				"barriers", s.barriers)
			if s.reduced {
				slog.Warn("file restore: a restore VM runs without one of its barriers", "barriers", s.barriers)
			}
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
			if !l.cfg.Unsandboxed.Seccomp {
				return nil, unavailable("this qemu could not install its seccomp sandbox (%s); refusing to run a restore VM without it — "+
					"file_restore.allow_unsandboxed: [seccomp] permits it, which is dangerous (see docs/backups.md)", wire.EscapeBounded(out, 300))
			}
			slog.Warn("file restore: this qemu could not install its seccomp sandbox; running this restore VM without it (file_restore.allow_unsandboxed: [seccomp])", "qemu", h.qemu)
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

// barrierSummary is what isolates a restore VM, for its audit rows, and
// whether one of its barriers is missing.
func barrierSummary(sandbox bool, h *host, uid uint32) (string, bool) {
	onOff := func(b bool) string {
		if b {
			return "on"
		}
		return "off"
	}
	aa := "absent"
	if h.appArmor {
		aa = "on"
	} else if h.aaEnabled {
		aa = "off"
	}
	ll := "off"
	if h.landlock > 0 {
		ll = strconv.Itoa(h.landlock)
	}
	reduced := !sandbox || (!h.appArmor && h.landlock == 0) || !h.perSession
	return fmt.Sprintf("sandbox=%s apparmor=%s landlock=%s uid=%d", onOff(sandbox), aa, ll, uid), reduced
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
// With an AppArmor profile or a Landlock ruleset, the litevirt binary at
// trampoline runs first, as qemu's parent in the same process group: it
// starts qemu confined by them and kills it on the SIGTERM the daemon's
// death sends it.
func qemuCommand(spec VMSpec, u *qemuUser, dir string, vhost *os.File, stdout, stderr io.Writer, trampoline, profile string, ll *landlockPolicy) (*exec.Cmd, error) {
	args, err := qemuArgs(spec)
	if err != nil {
		return nil, err
	}
	var cmd *exec.Cmd
	if profile != "" || ll != nil {
		prof, rules := "-", "-"
		if profile != "" {
			prof = profile
		}
		if ll != nil {
			b, err := json.Marshal(ll)
			if err != nil {
				return nil, err
			}
			rules = string(b)
		}
		cmd = exec.Command(trampoline, append([]string{TrampolineArg, prof, rules, spec.QEMU}, args...)...)
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
	if profile != "" || ll != nil {
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
	trampoline := h.agent
	if l.trampoline != "" {
		trampoline = l.trampoline
	}
	cmd, err := qemuCommand(spec, cred, s.dir, vhost, s.console, &limitedBuffer{b: stderr, max: 16 << 10}, trampoline, profile, l.restorePolicy(h, s.dir, spec))
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
		if s.uid != 0 {
			// Anything left running as this session's uid (qemu out of its
			// process group) goes before the uid can be handed out again.
			for _, pid := range uidProcs(s.uid, s.uid+1)[s.uid] {
				killUIDProcess(pid, s.uid, s.uid+1)
			}
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
//   - every process running as one of the reserved per-session uids
//     (uidBase, UIDSlots of them; 0 = none), whatever its command line says
//     — a process can rewrite its own — which finds a qemu whose
//     trampoline, and so whose pidfile record, is gone. The range last used
//     (recorded in runDir) is swept too, so changing uid_base leaves no
//     survivor in the old one.
//
// A range is swept by uid only when it is verified exclusive
// (reservedRangeConflict: not the containers' range, no subordinate id
// range, no account); otherwise only processes with a restore VM's command
// line in it are killed, and the conflict is logged. Returns the number
// killed.
func SweepStale(runDir string, uidBase uint32, containers [2]uint64) int {
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
	bases := []uint32{uidBase}
	if prev := readUIDBase(runDir); prev != 0 && prev != uidBase {
		bases = append(bases, prev)
		_ = os.Remove(filepath.Join(runDir, uidBaseFile))
	}
	for _, base := range bases {
		if base == 0 {
			continue
		}
		byUID := true
		if err := reservedRangeConflict(base, containers); err != nil {
			slog.Warn("file restore: the reserved uid range is not exclusive; sweeping only processes with a restore VM's command line in it",
				"uid_base", base, "why", err)
			byUID = false
		}
		killed += sweepUIDRange(base, base+UIDSlots, byUID)
	}
	return killed
}

// sweepUIDRange kills the processes running as a uid in [lo, hi) — every
// one when byUID, else only those whose command line is a restore VM's — and
// repeats while it finds any (a process may fork while it is swept).
func sweepUIDRange(lo, hi uint32, byUID bool) int {
	killed := 0
	for pass := 0; pass < 5; pass++ {
		n := 0
		for _, pids := range uidProcs(lo, hi) {
			for _, pid := range pids {
				if !byUID && !isRestoreVMAny(pid) {
					continue
				}
				if killUIDProcess(pid, lo, hi) {
					n++
				}
			}
		}
		if killed += n; n == 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return killed
}

// uidBaseFile records, in the run directory, the uid_base whose uids
// sessions were given, so a later daemon with another uid_base still sweeps
// them.
const uidBaseFile = "uid-base"

func recordUIDBase(runDir string, base uint32) {
	if runDir == "" || base == 0 || readUIDBase(runDir) == base {
		return
	}
	if err := os.MkdirAll(runDir, 0o711); err == nil {
		_ = os.WriteFile(filepath.Join(runDir, uidBaseFile), []byte(strconv.FormatUint(uint64(base), 10)+"\n"), 0o600)
	}
}

func readUIDBase(runDir string) uint32 {
	b, err := os.ReadFile(filepath.Join(runDir, uidBaseFile))
	if err != nil || len(b) > 32 {
		return 0
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 32)
	if err != nil || v < 65536 || v+UIDSlots > 4294967294 {
		return 0
	}
	return uint32(v)
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
// <profile> <landlock> <qemu> <args...>` (already as the VM's uid, in the
// session's process group; "-" for no AppArmor profile or no Landlock
// ruleset, which is JSON). It runs in two stages:
//
//   - the parent stage stays as qemu's parent: it starts the second stage,
//     and on SIGTERM (the parent-death signal the daemon gives it) or any end
//     kills it and exits with its status;
//   - the exec stage (`… __file-restore-exec --exec <profile> <landlock>
//     <qemu> …`) locks its OS thread, sets that thread's AppArmor profile for
//     its next exec, sets no_new_privs, applies the Landlock ruleset to
//     itself, and execs qemu in place, which starts confined.
//
// Two stages because AppArmor's on-exec profile and a Landlock ruleset apply
// to the task (thread) that set them, and because the exec into a new
// AppArmor profile is a secure exec, across which the kernel clears the
// parent-death signal. Any step failing ends the exec stage: qemu never
// starts unconfined. The daemon also checks the result: the NBD peer and,
// after the hello, the qemu process must carry the profile in enforce mode.
func RunTrampoline(args []string) {
	if len(args) >= 1 && args[0] == "--exec" {
		runTrampolineExec(args[1:])
		return
	}
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "file-restore exec: want <profile> <landlock> <qemu> [args...]")
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
	if len(args) < 3 {
		os.Exit(2)
	}
	// The on-exec attribute, no_new_privs and the Landlock domain are per
	// thread: set them and exec from the same one.
	runtime.LockOSThread()
	profile, rules, qemu := args[0], args[1], args[2]
	if profile != "-" {
		if err := setExecProfile(profile); err != nil {
			fmt.Fprintf(os.Stderr, "file-restore exec: set AppArmor profile %s: %v\n", profile, err)
			os.Exit(1)
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		fmt.Fprintf(os.Stderr, "file-restore exec: no_new_privs: %v\n", err)
		os.Exit(1)
	}
	if rules != "-" {
		var p landlockPolicy
		if err := json.Unmarshal([]byte(rules), &p); err != nil {
			fmt.Fprintf(os.Stderr, "file-restore exec: Landlock ruleset: %v\n", err)
			os.Exit(1)
		}
		if err := p.restrictSelf(); err != nil {
			fmt.Fprintf(os.Stderr, "file-restore exec: Landlock: %v\n", err)
			os.Exit(1)
		}
	}
	err := syscall.Exec(qemu, append([]string{qemu}, args[3:]...), os.Environ())
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
