//go:build linux

package filerestore

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// aclDevice is a stand-in for /dev/kvm (mode 0660) on a filesystem that
// takes POSIX ACLs; the test fails, never skips, when it does not — the ACL
// is the only way a restore VM's uid reaches KVM.
func aclDevice(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "kvm")
	if err := os.WriteFile(p, nil, 0o660); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o660); err != nil {
		t.Fatal(err)
	}
	if _, err := unix.Getxattr(p, aclAccessXattr, nil); err != nil && !errors.Is(err, unix.ENODATA) {
		t.Fatalf("the test directory's filesystem takes no POSIX ACLs (%v); run with TMPDIR on one that does", err)
	}
	return p
}

// userACL is the permission an ACL_USER entry of path gives uid (-1: none),
// read from the xattr itself, independently of the code under test.
func userACL(t *testing.T, path string, uid uint32) int {
	t.Helper()
	return namedACL(t, path, 0x02, uid)
}

// groupACL is the same for an ACL_GROUP entry.
func groupACL(t *testing.T, path string, gid uint32) int {
	t.Helper()
	return namedACL(t, path, 0x08, gid)
}

func namedACL(t *testing.T, path string, wantTag uint16, uid uint32) int {
	t.Helper()
	b := make([]byte, 4096)
	n, err := unix.Getxattr(path, aclAccessXattr, b)
	if errors.Is(err, unix.ENODATA) {
		return -1
	}
	if err != nil {
		t.Fatal(err)
	}
	b = b[:n]
	for off := 4; off+8 <= len(b); off += 8 {
		tag := uint16(b[off]) | uint16(b[off+1])<<8
		perm := uint16(b[off+2]) | uint16(b[off+3])<<8
		id := uint32(b[off+4]) | uint32(b[off+5])<<8 | uint32(b[off+6])<<16 | uint32(b[off+7])<<24
		if tag == wantTag && id == uid {
			return int(perm)
		}
	}
	return -1
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}

// R4-I1: a restore VM's credential carries the restore group only — never
// kvm, whose group-writable sockets (libvirt's pull-backup NBD export of a
// live guest disk, 0775 libvirt-qemu:kvm) Landlock does not mediate.
func TestSessionCredential_NoKVMGroup(t *testing.T) {
	h := &host{account: &qemuUser{name: "litevirt-restore", uid: 990, gid: 988}, kvmGid: 993, perSession: true}
	c := sessionCredential(h, 3_800_000_004)
	if c.uid != 3_800_000_004 || c.gid != 988 {
		t.Fatalf("credential %+v", c)
	}
	if containsU32(c.groups, 993) || len(c.groups) != 2 || c.groups[0] != 988 || c.groups[1] != 3_800_000_004 {
		t.Fatalf("a restore VM's groups are %v; want the restore group 988 and its own slot gid, never kvm (993)", c.groups)
	}
}

// R4-I1: KVM is granted to each session's uid by a POSIX ACL entry, and
// taken back: the device's mode and any other entry are left as they were.
func TestDeviceACL_GrantAndRevoke(t *testing.T) {
	const base = 3_800_000_000
	dev := aclDevice(t)
	if err := grantDeviceACL(dev, 12345); err != nil { // someone else's entry (logind's uaccess)
		t.Fatal(err)
	}
	if err := grantDeviceACL(dev, base+3); err != nil {
		t.Fatal(err)
	}
	if p := groupACL(t, dev, base+3); p != 6 {
		t.Fatalf("uid %d has ACL perm %d on the device, want rw (6)", base+3, p)
	}
	if m := modeOf(t, dev); m != 0o660 {
		t.Fatalf("mode after the grant %o, want 0660 (mask rw)", m)
	}
	n, err := revokeDeviceACL(dev, base, base+UIDSlots)
	if err != nil || n != 1 {
		t.Fatalf("revoke: removed %d (%v), want 1", n, err)
	}
	if p := groupACL(t, dev, base+3); p != -1 {
		t.Fatalf("uid %d still has ACL perm %d after the revoke", base+3, p)
	}
	if p := groupACL(t, dev, 12345); p != 6 {
		t.Fatalf("another uid's entry was touched: perm %d", p)
	}
	if n, err := revokeDeviceACL(dev, 12345, 12346); err != nil || n != 1 {
		t.Fatalf("revoke the last named entry: %d %v", n, err)
	}
	if _, err := unix.Getxattr(dev, aclAccessXattr, nil); !errors.Is(err, unix.ENODATA) {
		t.Fatalf("an ACL is left with no named entry: %v", err)
	}
	if m := modeOf(t, dev); m != 0o660 {
		t.Fatalf("mode after the revoke %o, want 0660 back", m)
	}
	// Nothing to revoke writes nothing.
	if n, err := revokeDeviceACL(dev, base, base+UIDSlots); err != nil || n != 0 {
		t.Fatalf("revoke with no entry: %d %v", n, err)
	}
}

// R4-I1: the uid a session is given reaches KVM from the moment it is handed
// out until it is released, and not after.
func TestAllocUID_GrantsKVMUntilReleased(t *testing.T) {
	const base = 3_800_000_000
	l := NewLauncher(Config{UIDBase: base})
	l.kvmPath = aclDevice(t)
	uid, rel, err := l.allocUID()
	if err != nil {
		t.Fatal(err)
	}
	if p := groupACL(t, l.kvmPath, uid); p != 6 {
		t.Fatalf("session uid %d has ACL perm %d on KVM, want rw", uid, p)
	}
	rel()
	if p := groupACL(t, l.kvmPath, uid); p != -1 {
		t.Fatalf("released uid %d still reaches KVM (perm %d)", uid, p)
	}
}

// R4-I1: a grant a crashed daemon left behind is removed by the next one's
// startup sweep — for the current range and the one sessions last used —
// and nothing else is.
func TestSweepStale_RemovesStaleKVMGrants(t *testing.T) {
	const oldBase, base = 3_700_000_000, 3_800_000_000
	dev := aclDevice(t)
	old := staleACLDevice
	staleACLDevice = dev
	defer func() { staleACLDevice = old }()
	for _, u := range []uint32{base + 1, base + 63, oldBase + 2, 12345} {
		if err := grantDeviceACL(dev, u); err != nil {
			t.Fatal(err)
		}
	}
	run := t.TempDir()
	if err := os.WriteFile(filepath.Join(run, "uid-base"), []byte("3700000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	SweepStale(run, base, [2]uint64{})
	for _, u := range []uint32{base + 1, base + 63, oldBase + 2} {
		if p := groupACL(t, dev, u); p != -1 {
			t.Errorf("a stale grant to reserved uid %d survived the sweep (perm %d)", u, p)
		}
	}
	if p := groupACL(t, dev, 12345); p != 6 {
		t.Errorf("the sweep touched an entry outside the reserved range: perm %d", p)
	}
}

// R4-I1 (preflight): KVM must be grantable to the per-session uids — by an
// ACL, or because the device is already world read-write.
func TestDeviceACLUsable(t *testing.T) {
	if err := deviceACLUsable(aclDevice(t)); err != nil {
		t.Fatalf("an ACL-capable device: %v", err)
	}
	if err := deviceACLUsable(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("a missing device was usable")
	}
}

// Nit 1: a daemon start whose run directory does not exist (no restore VM
// ran since boot: it is under /run) asks no directory service anything.
func TestSweepStale_NoRunDirNoNSS(t *testing.T) {
	old := uidOwners
	defer func() { uidOwners = old }()
	calls := 0
	uidOwners = func(uids []uint32) (map[uint32]string, error) { calls++; return map[uint32]string{}, nil }
	SweepStale(filepath.Join(t.TempDir(), "never-created"), 3_800_000_000, [2]uint64{})
	if calls != 0 {
		t.Fatalf("a start with no run directory asked NSS %d times", calls)
	}
	SweepStale(t.TempDir(), 3_800_000_000, [2]uint64{})
	if calls == 0 {
		t.Fatal("control: a start with a run directory never checked the reserved range")
	}
}

// R4-M2 / R4-I1: under a root daemon the restore qemu (and its trampoline)
// start in a network namespace of their own: no UDP, no TCP and no abstract
// unix socket of the host is reachable whatever the Landlock ABI.
func TestQemuCommand_NetworkNamespace(t *testing.T) {
	dev, _ := os.Open(os.DevNull)
	defer dev.Close()
	u := &qemuUser{name: "uid 3800000000", uid: 3_800_000_000, gid: 988, groups: []uint32{988}}
	for _, tramp := range []string{"", "/usr/local/bin/litevirt"} {
		prof := ""
		if tramp != "" {
			prof = AppArmorProfile
		}
		cmd, err := qemuCommand(baseSpec(), u, t.TempDir(), dev, nil, nil, tramp, prof, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET == 0 {
			t.Fatalf("trampoline %q: no CLONE_NEWNET (cloneflags %#x)", tramp, cmd.SysProcAttr.Cloneflags)
		}
		cmd, _ = qemuCommand(baseSpec(), u, t.TempDir(), dev, nil, nil, tramp, prof, nil, false)
		if cmd.SysProcAttr.Cloneflags&syscall.CLONE_NEWNET != 0 {
			t.Fatalf("trampoline %q: a network namespace was asked for without root", tramp)
		}
	}
}

// R4-M2: the namespace request reaches the process that starts: without the
// privilege to create one (this test runs unprivileged), no restore VM
// starts at all — the fake qemu never runs.
func TestLaunch_NetworkNamespaceIsEntered(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root creates the namespace; the e2e checks /proc/<qemu>/ns/net")
	}
	h := newFakeHost(t, "cid", false)
	h.l.netns = func() bool { return true }
	err := h.open()
	if err == nil || !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("a netns start without privilege: %v", err)
	}
	if a := h.argv(t); len(a) != 0 {
		t.Fatalf("qemu ran outside its network namespace: %v", a)
	}
	// Control: without the namespace the same host starts the fake qemu.
	h2 := newFakeHost(t, "cid", false)
	h2.l.netns = func() bool { return false }
	_ = h2.open()
	if a := h2.argv(t); len(a) == 0 {
		t.Fatal("control: the fake qemu never ran without a namespace either")
	}
}

// Lab 2: a host without qemu_fw_cfg (Ubuntu ships it in
// linux-modules-extra) is refused naming the module and the package.
func TestInitramfs_FwCfgMissingNamesThePackage(t *testing.T) {
	mods := fakeModules(t)
	dep, _ := os.ReadFile(filepath.Join(mods, "modules.dep"))
	var keep []string
	for _, l := range strings.Split(string(dep), "\n") {
		if !strings.Contains(l, "qemu_fw_cfg") {
			keep = append(keep, l)
		}
	}
	if err := os.WriteFile(filepath.Join(mods, "modules.dep"), []byte(strings.Join(keep, "\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := EnsureInitramfs(t.TempDir(), InitramfsSpec{Agent: fakeAgent(t, "a"), ModulesDir: mods}, os.Getgid(), nil)
	if err == nil || !strings.Contains(err.Error(), "qemu_fw_cfg") || !strings.Contains(err.Error(), "linux-modules-extra") {
		t.Fatalf("want an error naming qemu_fw_cfg and linux-modules-extra, got %v", err)
	}
}

// R4-M2: the network namespace is a root daemon's (only root can create
// one before the credential change); a non-root daemon starts qemu as is.
func TestNewLauncher_NetworkNamespaceWhenRoot(t *testing.T) {
	if got, want := NewLauncher(Config{}).netns(), os.Geteuid() == 0; got != want {
		t.Fatalf("netns %v for euid %d, want %v", got, os.Geteuid(), want)
	}
}

// Lab 2: udev (systemd 255, /dev/kvm tagged uaccess) drops every named-USER
// ACL entry on /dev/kvm whenever any KVM VM is created or destroyed. The
// session's grant is a GROUP entry, which that rewrite leaves: simulate the
// wipe between the grant and the open and the access is still there. The
// grant never puts a user entry on the device.
func TestAllocUID_KVMGrantSurvivesTheUdevUserEntryWipe(t *testing.T) {
	const base = 3_800_000_000
	l := NewLauncher(Config{UIDBase: base})
	l.kvmPath = aclDevice(t)
	uid, rel, err := l.allocUID()
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	// What a uaccess change event does: rewrite the ACL without any named user.
	udevWipeUserEntries(t, l.kvmPath)
	if p := groupACL(t, l.kvmPath, uid); p != 6 {
		t.Fatalf("after udev dropped the user entries, slot group %d has ACL perm %d on KVM, want rw", uid, p)
	}
	if p := userACL(t, l.kvmPath, uid); p != -1 {
		t.Fatalf("the grant put a user entry (perm %d) on the device; udev would drop it", p)
	}
	if m := modeOf(t, l.kvmPath); m&0o060 != 0o060 {
		t.Fatalf("mode %o: the mask does not cover the group entry", m)
	}
}

// The grant is re-checked immediately before exec: an entry that something
// removed after allocUID (a flush of every named entry, say) is put back.
func TestEnsureKVMGrant_RestoresARemovedEntry(t *testing.T) {
	const base = 3_800_000_000
	l := NewLauncher(Config{UIDBase: base})
	l.kvmPath = aclDevice(t)
	uid, rel, err := l.allocUID()
	if err != nil {
		t.Fatal(err)
	}
	defer rel()
	if _, err := revokeDeviceACL(l.kvmPath, base, base+UIDSlots); err != nil {
		t.Fatal(err)
	}
	if p := groupACL(t, l.kvmPath, uid); p != -1 {
		t.Fatalf("setup: entry still there (%d)", p)
	}
	if err := l.ensureKVMGrant(&host{perSession: true}, uid); err != nil {
		t.Fatal(err)
	}
	if p := groupACL(t, l.kvmPath, uid); p != 6 {
		t.Fatalf("after the pre-exec re-check the slot group has ACL perm %d, want rw", p)
	}
	// A shared credential has no slot group to grant.
	if err := (&Launcher{kvmPath: filepath.Join(t.TempDir(), "missing")}).ensureKVMGrant(&host{}, uid); err != nil {
		t.Fatalf("a shared credential: %v", err)
	}
}

// Entries an older daemon granted by user are still removed by revoke and the
// startup sweep, and one for an id outside the range is left alone.
func TestRevokeDeviceACL_AlsoRemovesLegacyUserEntries(t *testing.T) {
	const base = 3_800_000_000
	dev := aclDevice(t)
	ents, err := readAccessACL(dev)
	if err != nil {
		t.Fatal(err)
	}
	ents = append(ents, aclEntry{aclUser, aclRW, base + 2}, aclEntry{aclUser, aclRW, 12345})
	if err := writeAccessACL(dev, ents); err != nil {
		t.Fatal(err)
	}
	if n, err := revokeDeviceACL(dev, base, base+UIDSlots); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v, want the one legacy user entry", n, err)
	}
	if userACL(t, dev, base+2) != -1 || userACL(t, dev, 12345) != 6 {
		t.Fatal("legacy entry not removed, or an entry outside the range was")
	}
}

// udevWipeUserEntries rewrites path's ACL without any ACL_USER entry, as
// udev's uaccess handling does on a KVM create/destroy uevent.
func udevWipeUserEntries(t *testing.T, path string) {
	t.Helper()
	ents, err := readAccessACL(path)
	if err != nil {
		t.Fatal(err)
	}
	var kept []aclEntry
	for _, e := range ents {
		if e.tag != aclUser {
			kept = append(kept, e)
		}
	}
	if err := writeAccessACL(path, kept); err != nil {
		t.Fatal(err)
	}
}

// The pre-exec re-check is wired into start, ahead of the exec: a per-session
// launch (which needs root, so no unit test can run one) re-grants the slot
// group's /dev/kvm entry immediately before qemu opens the device.
func TestStart_ChecksTheKVMGrantBeforeExec(t *testing.T) {
	b, err := os.ReadFile("vm_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func (l *Launcher) start(")
	if i < 0 {
		t.Fatal("start not found")
	}
	body := src[i:]
	g, e := strings.Index(body, "l.ensureKVMGrant(h, uid)"), strings.Index(body, "cmd.Start()")
	if g < 0 || e < 0 || g > e {
		t.Fatalf("start does not call ensureKVMGrant before cmd.Start (grant at %d, exec at %d)", g, e)
	}
}
