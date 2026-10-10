//go:build linux

package filerestore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type memDev struct{ b []byte }

func (d memDev) ReadAt(p []byte, off int64) (int, error) { return bytes.NewReader(d.b).ReadAt(p, off) }
func (d memDev) Size() int64                             { return int64(len(d.b)) }

// fakeQemuScript stands in for qemu. It logs its argv (and whether fd 3 —
// the vhost-vsock fd — is open), then behaves as the "mode" file says.
// noSeccompReal is what a real qemu without sandbox support prints
// (qemu's vl.c), the first of the messages stderrSaysNoSeccomp knows.
const noSeccompReal = "qemu-system-x86_64: -sandbox on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny: -sandbox support is not enabled in this QEMU binary"

const fakeQemuScript = `#!/bin/sh
d=$(dirname "$0")
mode=$(cat "$d/mode")
case "$*" in *"-machine none"*)
  # The sandbox probe.
  echo probe >> "$d/probe.log"
  if [ "$mode" = noseccomp ]; then echo "` + noSeccompReal + `" >&2; exit 1; fi
  exec sleep 5;;
esac
echo "$*" >> "$d/argv.log"
if [ -e /proc/self/fd/3 ]; then echo fd3 >> "$d/fd.log"; fi
case "$mode" in
noseccomp) echo "boot failed for another reason" >&2; exit 1;;
lateseccomp)
  case "$*" in *-sandbox*) echo "` + noSeccompReal + `" >&2; exit 1;; esac
  echo "boot failed for another reason" >&2; exit 1;;
cid) echo "qemu-system-x86_64: -device vhost-vsock-pci: vhost-vsock: unable to set guest cid: Address already in use" >&2; exit 1;;
noisy) head -c 3000000 /dev/zero | tr '\0' 'A'; echo; echo "console tail marker"; exit 1;;
esac
exit 1
`

type fakeHost struct {
	l    *Launcher
	bin  string // the fake qemu's directory
	run  string
	cach string
}

func newFakeHost(t *testing.T, mode string, allowUnsandboxed bool) *fakeHost {
	t.Helper()
	bin := t.TempDir()
	q := filepath.Join(bin, "qemu")
	if err := os.WriteFile(q, []byte(fakeQemuScript), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "mode"), []byte(mode), 0o644); err != nil {
		t.Fatal(err)
	}
	kernel := filepath.Join(t.TempDir(), "vmlinuz")
	dev := filepath.Join(t.TempDir(), "dev")
	for _, f := range []string{kernel, dev} {
		if err := os.WriteFile(f, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	h := &fakeHost{bin: bin, run: filepath.Join(t.TempDir(), "run"), cach: filepath.Join(t.TempDir(), "cache")}
	h.l = NewLauncher(Config{
		QEMU: q, Kernel: kernel, ModulesDir: fakeModules(t), Agent: fakeAgent(t, "agent"),
		CacheDir: h.cach, RunDir: h.run, BootTimeout: 2 * time.Second, AllowUnsandboxed: allowUnsandboxed,
	})
	h.l.kvmPath, h.l.vhostPath = dev, dev
	h.l.checkAgent = func(string) error { return nil }
	h.l.appArmor = func() bool { return false }
	return h
}

func (h *fakeHost) argv(t *testing.T) []string { return h.lines(t, "argv.log") }

func (h *fakeHost) lines(t *testing.T, name string) []string {
	t.Helper()
	b, _ := os.ReadFile(filepath.Join(h.bin, name))
	if strings.TrimSpace(string(b)) == "" {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func (h *fakeHost) open() error {
	_, err := h.l.Open(context.Background(), memDev{make([]byte, 4096)}, KindFS, "raw")
	return err
}

// Ruling 7 / N-5: qemu itself is asked (a sandbox probe) whether it can
// install its seccomp sandbox; one that cannot is refused before any VM
// starts, naming qemu's own message and the key.
func TestLaunch_NoSeccompRefused(t *testing.T) {
	h := newFakeHost(t, "noseccomp", false)
	err := h.open()
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "-sandbox support is not enabled in this QEMU binary") ||
		!strings.Contains(err.Error(), "allow_unsandboxed") || !strings.Contains(err.Error(), "dangerous") {
		t.Fatalf("no seccomp: %v", err)
	}
	if a := h.argv(t); len(a) != 0 {
		t.Fatalf("a restore VM was started after the probe failed: %v", a)
	}
	if p := h.lines(t, "probe.log"); len(p) != 1 {
		t.Fatalf("probes: %v", p)
	}
}

// With allow_unsandboxed, a qemu that cannot sandbox runs without it — and
// the decision is made for every VM: the next one probes again.
func TestLaunch_AllowUnsandboxedIsPerVM(t *testing.T) {
	h := newFakeHost(t, "noseccomp", true)
	for i := 0; i < 2; i++ {
		if err := h.open(); err == nil {
			t.Fatal("the fake qemu never boots; Open succeeded")
		}
	}
	if p := h.lines(t, "probe.log"); len(p) != 2 {
		t.Fatalf("probes %d, want one per VM", len(p))
	}
	for i, l := range h.argv(t) {
		if strings.Contains(l, "-sandbox") {
			t.Errorf("run %d asked for the sandbox the probe said is unavailable", i)
		}
	}
}

// A sandbox that passes the probe but fails when the VM starts is decided
// again for that attempt only: refused without the key, retried without the
// sandbox with it, and the next session starts sandboxed again.
func TestLaunch_LateSeccompFailureIsPerAttempt(t *testing.T) {
	h := newFakeHost(t, "lateseccomp", false)
	if err := h.open(); err == nil || !strings.Contains(err.Error(), "allow_unsandboxed") {
		t.Fatalf("late seccomp failure without the key: %v", err)
	}
	h = newFakeHost(t, "lateseccomp", true)
	for i := 0; i < 2; i++ {
		if err := h.open(); err == nil {
			t.Fatal("Open succeeded")
		}
	}
	a := h.argv(t)
	if len(a) != 4 {
		t.Fatalf("qemu ran %d times, want 2 per session: %v", len(a), a)
	}
	for i, wantSandbox := range []bool{true, false, true, false} {
		if strings.Contains(a[i], "-sandbox") != wantSandbox {
			t.Errorf("run %d: sandbox=%v, want %v (the unsandboxed fallback must not stick)", i, !wantSandbox, wantSandbox)
		}
	}
}

// A vsock CID another VM holds is retried with a new one.
func TestLaunch_CIDCollisionRetries(t *testing.T) {
	h := newFakeHost(t, "cid", false)
	if err := h.open(); err == nil {
		t.Fatal("Open succeeded")
	}
	a := h.argv(t)
	if len(a) != 6 {
		t.Fatalf("qemu ran %d times, want 6 attempts", len(a))
	}
	cids := map[string]bool{}
	re := regexp.MustCompile(`guest-cid=(\d+)`)
	for _, l := range a {
		if m := re.FindStringSubmatch(l); m != nil {
			cids[m[1]] = true
		}
	}
	if len(cids) < 5 {
		t.Fatalf("CIDs tried: %v — a collision must pick a new one", cids)
	}
	if fd, _ := os.ReadFile(filepath.Join(h.bin, "fd.log")); !strings.Contains(string(fd), "fd3") {
		t.Fatal("qemu was not handed the vhost-vsock fd")
	}
}

// I-3: a guest flooding its console fills a bounded in-memory buffer, not
// the host's disk; the tail reaches the error, and the session leaves
// nothing behind.
func TestLaunch_ConsoleIsBoundedAndInMemory(t *testing.T) {
	h := newFakeHost(t, "noisy", false)
	err := h.open()
	if err == nil {
		t.Fatal("Open succeeded")
	}
	if !strings.Contains(err.Error(), "console tail marker") || len(err.Error()) > 2500 {
		t.Fatalf("error %d bytes: %.200q", len(err.Error()), err.Error())
	}
	ents, _ := os.ReadDir(h.run)
	if len(ents) != 0 {
		t.Fatalf("session state left behind: %v", ents)
	}
	var total int64
	_ = filepath.Walk(filepath.Dir(h.run), func(_ string, fi os.FileInfo, _ error) error {
		if fi != nil && fi.Mode().IsRegular() {
			total += fi.Size()
		}
		return nil
	})
	if total > 1<<20 {
		t.Fatalf("%d bytes on disk after a 3 MB console flood", total)
	}
}

// I-4: a later daemon kills the restore VMs a dead one left, but only a
// process whose command line is the restore VM of that very session.
func TestSweepStale_KillsOnlyVerifiedRestoreVMs(t *testing.T) {
	run := t.TempDir()
	mk := func(name, cmdlineDir string, uid int) (*exec.Cmd, string) {
		dir := filepath.Join(run, name)
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command("sh", "-c", "sleep 300; true", "-name", "litevirt-file-restore",
			`{"driver":"nbd","server":{"path":"`+filepath.Join(cmdlineDir, "nbd.sock")+`","type":"unix"}}`)
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
		if err := os.WriteFile(filepath.Join(dir, pidFile), []byte(strconv.Itoa(cmd.Process.Pid)+" "+strconv.Itoa(uid)+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		return cmd, dir
	}
	me := os.Getuid()
	vm, _ := mk("s-mine", filepath.Join(run, "s-mine"), me)
	other, _ := mk("s-recycled", filepath.Join(run, "s-someone-else"), me)
	// The right command line, but not running as the uid the VM was started
	// as: not the restore VM.
	wronguid, _ := mk("s-wronguid", filepath.Join(run, "s-wronguid"), me+1)
	garbage := filepath.Join(run, "s-garbage")
	_ = os.MkdirAll(garbage, 0o700)
	_ = os.WriteFile(filepath.Join(garbage, pidFile), []byte("1 0\n"), 0o600)

	time.Sleep(100 * time.Millisecond) // let sh set up its argv
	if n := SweepStale(run); n != 1 {
		t.Fatalf("killed %d, want 1", n)
	}
	done := make(chan error, 1)
	go func() { done <- vm.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatalf("the session's VM ended with %v, want SIGKILL", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session's leftover VM was not killed")
	}
	if err := other.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("a process whose pidfile was recycled for another command line was killed")
	}
	if err := wronguid.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("a process running as another uid than the pidfile records was killed")
	}
	if ents, _ := os.ReadDir(run); len(ents) != 0 {
		t.Fatalf("session directories left: %v", ents)
	}
}

// I-4/I-5: qemu is started as its user (no switch inside qemu, so seccomp's
// elevateprivileges=deny holds) in its own process group, with a parent-death
// SIGKILL that Go applies after the credential change.
func TestQemuCommand_CredentialsAndDeathSignal(t *testing.T) {
	dev, _ := os.Open(os.DevNull)
	defer dev.Close()
	u := &qemuUser{name: "libvirt-qemu", uid: 64055, gid: 993, groups: []uint32{993, 64055}}
	cmd, err := qemuCommand(baseSpec(), u, t.TempDir(), dev, &bytes.Buffer{}, &bytes.Buffer{}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	sp := cmd.SysProcAttr
	if sp.Credential == nil || sp.Credential.Uid != 64055 || sp.Credential.Gid != 993 || len(sp.Credential.Groups) != 2 {
		t.Fatalf("credential %+v", sp.Credential)
	}
	if sp.Pdeathsig != syscall.SIGKILL || !sp.Setpgid {
		t.Fatalf("pdeathsig %v setpgid %v", sp.Pdeathsig, sp.Setpgid)
	}
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != dev {
		t.Fatal("the vhost fd is not fd 3")
	}
	if len(cmd.Env) != 1 || !strings.HasPrefix(cmd.Env[0], "PATH=") {
		t.Fatalf("env %v", cmd.Env)
	}
	for _, a := range cmd.Args {
		if a == "-runas" || a == "-run-with" {
			t.Fatalf("qemu is asked to switch users itself: %v", cmd.Args)
		}
	}
	cmd, _ = qemuCommand(baseSpec(), nil, t.TempDir(), dev, &bytes.Buffer{}, &bytes.Buffer{}, "", "")
	if cmd.SysProcAttr.Credential != nil {
		t.Fatal("a non-root daemon set a credential")
	}
	// N-1: with AppArmor, the litevirt binary is exec'd first, to put qemu
	// under the restore profile; the credential and death signal still apply.
	cmd, _ = qemuCommand(baseSpec(), u, t.TempDir(), dev, &bytes.Buffer{}, &bytes.Buffer{}, "/usr/local/bin/litevirt", AppArmorProfile)
	if cmd.Path != "/usr/local/bin/litevirt" || len(cmd.Args) < 4 || cmd.Args[1] != TrampolineArg || cmd.Args[2] != AppArmorProfile || cmd.Args[3] != "qemu-system-x86_64" {
		t.Fatalf("trampoline argv %v", cmd.Args)
	}
	// The trampoline gets SIGTERM, which it turns into qemu's death: the
	// exec into a new AppArmor profile clears a child's death signal.
	if cmd.SysProcAttr.Credential == nil || cmd.SysProcAttr.Pdeathsig != syscall.SIGTERM || !cmd.SysProcAttr.Setpgid {
		t.Fatal("the trampoline lost the credential, its death signal or its process group")
	}
}

// N-2: boot files are the daemon's (owner), group the restore user's, mode
// 0440, in a 0750 directory, each with a 0600 digest sidecar; a file changed
// in any way — mode, or content with the mode put back — is reported and
// rebuilt, never booted.
func TestCacheFiles_OwnedVerifiedRebuilt(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "cache")
	spec := InitramfsSpec{Agent: fakeAgent(t, "agent bytes"), ModulesDir: fakeModules(t)}
	gid := os.Getgid()
	var tampered []string
	onTamper := func(path, why string) { tampered = append(tampered, filepath.Base(path)+": "+why) }
	p, err := EnsureInitramfs(cache, spec, gid, onTamper)
	if err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	dst, _ := os.Stat(cache)
	side, _ := os.Stat(p + ".sha256")
	if st.Mode().Perm() != 0o440 || dst.Mode().Perm() != 0o750 || side == nil || side.Mode().Perm() != 0o600 {
		t.Fatalf("initramfs %v, cache dir %v, sidecar %v; want 0440, 0750, 0600", st.Mode().Perm(), dst.Mode().Perm(), side)
	}
	orig, _ := os.ReadFile(p)
	if ok, why := cachedFile(p, gid); !ok {
		t.Fatalf("a fresh cache file did not verify: %s", why)
	}
	// Rewrite the content and put the mode back, as the file's owner could.
	_ = os.Chmod(p, 0o640)
	forged := append([]byte(nil), orig...)
	forged[len(forged)-1] ^= 0xff
	_ = os.WriteFile(p, forged, 0o640)
	_ = os.Chmod(p, 0o440)
	if ok, _ := cachedFile(p, gid); ok {
		t.Fatal("a rewritten cache file with its mode put back verified")
	}
	if _, err := EnsureInitramfs(cache, spec, gid, onTamper); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(p); !bytes.Equal(got, orig) {
		t.Fatal("a tampered cache file was reused")
	}
	if len(tampered) != 1 || !strings.Contains(tampered[0], "digest") {
		t.Fatalf("tamper reports: %v", tampered)
	}
	_ = os.Chmod(p, 0o644)
	if _, err := EnsureInitramfs(cache, spec, gid, onTamper); err != nil {
		t.Fatal(err)
	}
	if len(tampered) != 2 || !strings.Contains(tampered[1], "mode") {
		t.Fatalf("tamper reports: %v", tampered)
	}
	kernel := filepath.Join(t.TempDir(), "vmlinuz")
	_ = os.WriteFile(kernel, []byte("kernel image"), 0o600)
	k, err := ensureKernelCopy(cache, kernel, gid, onTamper)
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(k); string(b) != "kernel image" {
		t.Fatalf("kernel copy %q", b)
	}
	if st, _ := os.Stat(k); st.Mode().Perm() != 0o440 {
		t.Fatalf("kernel copy mode %v", st.Mode().Perm())
	}
}

// N-1: the restore VM never runs as a user that owns production disks or
// keys, nor as root, unless allow_unsandboxed says so.
func TestLookupQemuUser_DedicatedOnly(t *testing.T) {
	for _, name := range []string{"nobody", "root"} {
		if _, err := lookupQemuUser(name, false); err == nil {
			t.Errorf("run_as %q accepted", name)
		}
	}
	if u, err := lookupQemuUser("nobody", true); err != nil || u == nil {
		t.Errorf("nobody with allow_unsandboxed: %v %v", u, err)
	}
	if u, err := lookupQemuUser("root", true); err != nil || u != nil {
		t.Errorf("root with allow_unsandboxed: %v %v (want no credential)", u, err)
	}
	if _, err := user.Lookup("libvirt-qemu"); err == nil {
		if _, err := lookupQemuUser("libvirt-qemu", false); err == nil || !strings.Contains(err.Error(), "production") {
			t.Errorf("libvirt-qemu: %v", err)
		}
	}
	u, err := lookupQemuUser("", false)
	if _, lerr := user.Lookup(DefaultRestoreUser); lerr != nil {
		if err == nil || !strings.Contains(err.Error(), "useradd") {
			t.Errorf("no %s: %v", DefaultRestoreUser, err)
		}
	} else if err != nil || u == nil || u.name != DefaultRestoreUser {
		t.Errorf("default user: %+v %v", u, err)
	}
}

// N-1: the AppArmor profile grants the restore qemu its boot files, its own
// sessions' sockets and nonces, /dev/kvm and vhost-vsock — and nothing of
// /var/lib/litevirt, and no IP networking.
func TestAppArmorProfileText(t *testing.T) {
	p := appArmorProfileText("/var/cache/litevirt-restore", "/run/litevirt/file-restore")
	for _, want := range []string{
		"profile " + AppArmorProfile,
		"/var/cache/litevirt-restore/* r,",
		"/run/litevirt/file-restore/s-*/nbd.sock rw,",
		"/run/litevirt/file-restore/s-*/nonce r,",
		"/dev/kvm rw,", "/dev/vhost-vsock rw,",
		"deny network inet,", "deny ptrace,",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("profile lacks %q", want)
		}
	}
	if strings.Contains(p, "/var/lib/litevirt") || strings.Contains(p, "/var/lib/libvirt") {
		t.Errorf("profile reaches VM storage:\n%s", p)
	}
}

// m-5: a key covering every byte: a change past the first MiB of the agent,
// or in a module file, is a new initramfs.
func TestInitramfsKey_CoversWholeFiles(t *testing.T) {
	mods := fakeModules(t)
	agent := filepath.Join(t.TempDir(), "agent")
	big := bytes.Repeat([]byte{1}, 3<<20)
	_ = os.WriteFile(agent, big, 0o755)
	k1, _ := initramfsKey(InitramfsSpec{Agent: agent, ModulesDir: mods})
	big[len(big)-1] = 2
	st, _ := os.Stat(agent)
	_ = os.WriteFile(agent, big, 0o755)
	_ = os.Chtimes(agent, st.ModTime(), st.ModTime()) // same size and mtime
	k2, _ := initramfsKey(InitramfsSpec{Agent: agent, ModulesDir: mods})
	if k1 == k2 {
		t.Fatal("a change past the first MiB of the agent kept the key")
	}
	mod := filepath.Join(mods, "kernel/net/vmw_vsock/vsock.ko")
	_ = os.WriteFile(mod, []byte("MOD vsock, patched"), 0o644)
	k3, _ := initramfsKey(InitramfsSpec{Agent: agent, ModulesDir: mods})
	if k3 == k2 {
		t.Fatal("a changed module file kept the key")
	}
}

// m-5: a dynamically linked agent cannot be /init; preflight names it.
func TestCheckStaticELF(t *testing.T) {
	if err := checkStaticELF("/bin/sh"); err == nil || !strings.Contains(err.Error(), "dynamically linked") {
		t.Fatalf("/bin/sh: %v", err)
	}
	notELF := filepath.Join(t.TempDir(), "x")
	_ = os.WriteFile(notELF, []byte("#!/bin/sh\n"), 0o755)
	if err := checkStaticELF(notELF); err == nil {
		t.Fatal("a script passed as a static ELF")
	}
}

// I-5: /dev/kvm must be read-write for qemu's user by its mode bits.
func TestAccessibleTo(t *testing.T) {
	p := filepath.Join(t.TempDir(), "kvm")
	_ = os.WriteFile(p, nil, 0o660)
	_ = os.Chmod(p, 0o660)
	gid := uint32(os.Getgid())
	if err := accessibleTo(p, &qemuUser{name: "q", uid: 99999, gid: 12345, groups: []uint32{gid}}); err != nil {
		t.Fatalf("group member: %v", err)
	}
	if err := accessibleTo(p, &qemuUser{name: "q", uid: 99999, gid: 12345}); err == nil {
		t.Fatal("a stranger was granted a 0660 device")
	}
}
