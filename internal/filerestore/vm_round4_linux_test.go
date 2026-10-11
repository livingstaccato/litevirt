//go:build linux

package filerestore

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// kernelLandlockABI asks the kernel directly (independent of the code under
// test) which Landlock ABI it has; 0 = none.
func kernelLandlockABI() int {
	r, _, e := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if e != 0 {
		return 0
	}
	return int(r)
}

func acceptForever(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		c.Close()
	}
}

// R3-I1: on any host — with or without AppArmor — the restore qemu runs
// under a Landlock ruleset the trampoline's exec stage applies. An escaped
// qemu (here, a probe started in its place through the real trampoline)
// cannot read a world-readable file outside its allowlist (a 0644 VM disk),
// connect to a TCP listener, or reach an abstract unix socket, while what it
// is allowed still works.
func TestLandlock_EscapedQemuIsFenced(t *testing.T) {
	abi := kernelLandlockABI()
	if abi < 1 {
		t.Skip("SKIPPING: this kernel has no Landlock (see /sys/kernel/security/lsm)")
	}
	h := newFakeHost(t, "cid", false)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// A production VM disk: world-readable, in a world-traversable directory.
	disk := filepath.Join(t.TempDir(), "tenant-b.qcow2")
	if err := os.WriteFile(disk, []byte("tenant B's disk"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := os.ReadFile(disk); err != nil {
		t.Fatalf("control: the disk is not readable outside the sandbox: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go acceptForever(ln)
	abstract := fmt.Sprintf("litevirt-fr-test-%d", os.Getpid())
	al, err := net.Listen("unix", "@"+abstract)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	go acceptForever(al)
	allowed, err := filepath.EvalSymlinks("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	outDir := t.TempDir()
	out := filepath.Join(outDir, "escape.log")
	script := "#!/bin/sh\n" +
		"case \"$*\" in *\"-run-with help\"*) exit 0;; esac\n" +
		"case \"$*\" in *\"-machine none\"*) exec sleep 5;; esac\n" +
		"exec " + self + " " + escapeProbeArg + " " + out + " " + disk + " " + ln.Addr().String() + " " + abstract + " " + allowed + "\n"
	if err := os.WriteFile(filepath.Join(h.bin, "qemu"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	h.l.landlockExtra.Exec = append(h.l.landlockExtra.Exec, self)
	h.l.landlockExtra.RW = append(h.l.landlockExtra.RW, outDir)
	if err := h.open(); err == nil {
		t.Fatal("Open succeeded; the probe never boots")
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the escape probe never ran: %v", err)
	}
	got := map[string]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			got[k] = v
		}
	}
	t.Logf("Landlock ABI %d; probe: %v", abi, got)
	if got["allowed"] != "ok" {
		t.Fatalf("control: the probe could not read %s, which the restore qemu is allowed: %s", allowed, got["allowed"])
	}
	if got["read"] == "ok" {
		t.Errorf("an escaped restore qemu read a world-readable file outside its allowlist (a VM disk)")
	}
	if abi >= 4 && got["tcp"] == "ok" {
		t.Errorf("an escaped restore qemu connected to a TCP listener")
	}
	if abi >= 6 && got["abstract"] == "ok" {
		t.Errorf("an escaped restore qemu connected to an abstract unix socket")
	}
}

// R3-I1: a restore VM runs confined by AppArmor or Landlock (Landlock on
// every host that has it); with neither, it is refused unless the operator
// allowed running without a MAC barrier. AppArmor enabled without its parser
// is refused only where there is no Landlock either (R4-M3: with Landlock it
// has the barriers of an AppArmor-off host, which is accepted).
func TestConfinementDecision(t *testing.T) {
	for _, c := range []struct {
		aa, parser bool
		ll         int
		allow      bool
		wantAA     bool
		wantLL     int
		wantErr    string
	}{
		{true, true, 6, false, true, 6, ""},
		{true, true, 0, false, true, 0, ""},
		{true, false, 6, false, false, 6, ""},
		{true, false, 1, false, false, 1, ""},
		{true, false, 6, true, false, 6, ""},
		{true, false, 0, false, false, 0, "apparmor_parser"},
		{true, false, 0, true, false, 0, ""},
		{false, false, 6, false, false, 6, ""},
		{false, false, 1, false, false, 1, ""},
		{false, false, 0, false, false, 0, "Landlock"},
		{false, false, 0, true, false, 0, ""},
	} {
		aa, ll, err := confinementDecision(c.aa, c.parser, c.ll, c.allow)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) || !strings.Contains(err.Error(), "allow_unsandboxed") {
				t.Errorf("%+v: err %v, want one naming %q and the key", c, err, c.wantErr)
			}
			continue
		}
		if err != nil || aa != c.wantAA || ll != c.wantLL {
			t.Errorf("%+v: got aa=%v ll=%d err=%v", c, aa, ll, err)
		}
	}
}

// R3-I1: with neither AppArmor nor Landlock, no restore VM starts.
func TestLaunch_NoMACRefused(t *testing.T) {
	h := newFakeHost(t, "cid", false)
	h.l.landlockABI = func() int { return 0 }
	err := h.open()
	if !errors.Is(err, ErrUnavailable) || !strings.Contains(err.Error(), "Landlock") || !strings.Contains(err.Error(), "allow_unsandboxed") {
		t.Fatalf("no AppArmor, no Landlock: %v", err)
	}
	if a := h.argv(t); len(a) != 0 {
		t.Fatalf("a restore VM was started without a MAC barrier: %v", a)
	}
}

// R3-M1: a uid slot is handed out only when no process of that uid is left
// — a released slot whose previous qemu escaped its process group is not
// reused.
func TestAllocUID_SkipsUIDWithLiveProcess(t *testing.T) {
	old := uidProcs
	defer func() { uidProcs = old }()
	const base = 3_800_000_000
	busy := map[uint32][]int{base: {1 << 30}}
	uidProcs = func(lo, hi uint32) map[uint32][]int { return busy }
	l := NewLauncher(Config{UIDBase: base})
	l.kvmPath = aclDevice(t)
	uid, rel, err := l.allocUID()
	if err != nil || uid != base+1 {
		t.Fatalf("got uid %d (%v), want %d: uid %d still has a process", uid, err, base+1, base)
	}
	rel()
	busy = nil
	if uid, _, err := l.allocUID(); err != nil || uid != base {
		t.Fatalf("got uid %d (%v), want %d once its process is gone", uid, err, base)
	}
}

func startSleeper(t *testing.T, arg string) *exec.Cmd {
	t.Helper()
	c := exec.Command("sleep", arg)
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Process.Kill(); _ = c.Wait() })
	return c
}

func waitKilled(t *testing.T, c *exec.Cmd, what string) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case err := <-done:
		var ee *exec.ExitError
		if !errors.As(err, &ee) || ee.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
			t.Fatalf("%s ended with %v, want SIGKILL", what, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("%s survived the sweep", what)
	}
}

// R3-M1: the sweep kills every process of a reserved uid, whatever its
// command line says (a process can rewrite its own argv).
func TestSweepStale_ByUIDWhateverTheCmdline(t *testing.T) {
	const base = 3_800_000_000
	orphan := startSleeper(t, "300") // its command line is no restore VM's
	other := startSleeper(t, "301")
	old := procStatusUIDs
	defer func() { procStatusUIDs = old }()
	procStatusUIDs = func(pid int) []int {
		if pid == orphan.Process.Pid {
			return []int{base + 5, base + 5, base + 5, base + 5}
		}
		return old(pid)
	}
	if n := SweepStale(t.TempDir(), base, [2]uint64{}); n < 1 {
		t.Fatalf("killed %d, want the process of a reserved uid", n)
	}
	waitKilled(t, orphan, "a process of a reserved uid with an innocent command line")
	if err := other.Process.Signal(syscall.Signal(0)); err != nil {
		t.Fatal("a process outside the reserved uids was killed")
	}
}

// Nit 7: after uid_base changes, survivors in the previous range are swept
// too; the run directory remembers the range sessions last used.
func TestSweepStale_PreviousUIDBase(t *testing.T) {
	const oldBase, newBase = 3_700_000_000, 3_800_000_000
	run := t.TempDir()
	if err := os.WriteFile(filepath.Join(run, "uid-base"), []byte("3700000000\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	orphan := startSleeper(t, "302")
	old := procStatusUIDs
	defer func() { procStatusUIDs = old }()
	procStatusUIDs = func(pid int) []int {
		if pid == orphan.Process.Pid {
			return []int{oldBase + 2, oldBase + 2, oldBase + 2, oldBase + 2}
		}
		return old(pid)
	}
	SweepStale(run, newBase, [2]uint64{})
	waitKilled(t, orphan, "a survivor in the previous uid_base range")
	if _, err := os.Stat(filepath.Join(run, "uid-base")); !os.IsNotExist(err) {
		t.Fatalf("the swept range is still recorded: %v", err)
	}
	// A session under the new base records it.
	recordUIDBase(run, newBase)
	if b, _ := os.ReadFile(filepath.Join(run, "uid-base")); strings.TrimSpace(string(b)) != strconv.Itoa(newBase) {
		t.Fatalf("recorded uid base %q, want %d", b, newBase)
	}
}

// R3-M3: the reserved uids must not overlap the containers' id-map range,
// any /etc/subuid or /etc/subgid range, or any account NSS knows (LDAP,
// sssd, systemd included); an NSS lookup that fails refuses.
func TestUIDRangeConflict(t *testing.T) {
	sub := filepath.Join(t.TempDir(), "subuid")
	_ = os.WriteFile(sub, nil, 0o644)
	oldP, oldO := subIDPaths, uidOwners
	defer func() { subIDPaths, uidOwners = oldP, oldO }()
	subIDPaths = []string{sub}
	owners := map[uint32]string{}
	var ownersErr error
	uidOwners = func([]uint32) (map[uint32]string, error) { return owners, ownersErr }

	l := NewLauncher(Config{UIDBase: 3_800_000_000, ContainerIDs: [2]uint64{1_000_000_000, 2_966_080_000}})
	if err := l.uidRangeConflict(); err != nil {
		t.Fatalf("the default ranges: %v", err)
	}
	l.cfg.ContainerIDs = [2]uint64{2_000_000_000, 3_966_080_000}
	if err := l.uidRangeConflict(); err == nil || !strings.Contains(err.Error(), "idmap") {
		t.Errorf("overlapping the container range: %v", err)
	}
	l.cfg.ContainerIDs = [2]uint64{1_000_000_000, 2_966_080_000}
	_ = os.WriteFile(sub, []byte("# comment\nlxd:1000000:65536\nincus:3799999990:100\n"), 0o644)
	if err := l.uidRangeConflict(); err == nil || !strings.Contains(err.Error(), sub) {
		t.Errorf("inside a subordinate id range: %v", err)
	}
	_ = os.WriteFile(sub, []byte("lxd:1000000:65536\nedge:3800000064:10\n"), 0o644)
	if err := l.uidRangeConflict(); err != nil {
		t.Errorf("a subordinate range just past the reserved ones: %v", err)
	}
	owners = map[uint32]string{3_800_000_003: "ldap-alice"}
	if err := l.uidRangeConflict(); err == nil || !strings.Contains(err.Error(), "ldap-alice") {
		t.Errorf("a uid NSS knows: %v", err)
	}
	owners, ownersErr = nil, errors.New("sssd is down")
	if err := l.uidRangeConflict(); err == nil || !strings.Contains(err.Error(), "sssd is down") {
		t.Errorf("an NSS lookup that failed: %v", err)
	}
}

// R3-M3: the NSS lookup is getent (the static binary cannot call NSS itself).
func TestUIDOwners_Getent(t *testing.T) {
	if _, err := exec.LookPath("getent"); err != nil {
		t.Skip("SKIPPING: no getent")
	}
	got, err := uidOwners([]uint32{0, 3_800_000_000})
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != "root" || got[3_800_000_000] != "" {
		t.Fatalf("owners %v, want uid 0 = root only", got)
	}
}

// Nit 3: the profile is matched as a whole line of the loaded profiles.
func TestProfileEnforcedIn(t *testing.T) {
	if !profileEnforcedIn([]byte("other (enforce)\nlitevirt-restore-qemu (enforce)\n")) {
		t.Error("the loaded profile was not recognized")
	}
	for _, s := range []string{
		"x-litevirt-restore-qemu (enforce)\n",
		"parent//litevirt-restore-qemu (enforce)\n",
		"litevirt-restore-qemu (complain)\n",
		"litevirt-restore-qemu (enforce) extra\n",
	} {
		if profileEnforcedIn([]byte(s)) {
			t.Errorf("%q read as the restore profile in enforce mode", s)
		}
	}
}

// R3-M4: the barrier summary audited for each restore VM, and when it counts
// as missing a barrier.
func TestBarrierSummary(t *testing.T) {
	full := &host{appArmor: true, aaEnabled: true, landlock: 6, perSession: true}
	if s, r := barrierSummary(true, full, 3_800_000_001); s != "sandbox=on apparmor=on landlock=6 uid=3800000001" || r {
		t.Errorf("fully confined: %q reduced=%v", s, r)
	}
	if s, r := barrierSummary(true, &host{landlock: 4, perSession: true}, 3_800_000_002); s != "sandbox=on apparmor=absent landlock=4 uid=3800000002" || r {
		t.Errorf("Landlock only: %q reduced=%v", s, r)
	}
	for name, c := range map[string]struct {
		sandbox bool
		h       *host
	}{
		"no seccomp":      {false, full},
		"no MAC":          {true, &host{aaEnabled: true, perSession: true}},
		"shared identity": {true, &host{appArmor: true, aaEnabled: true, landlock: 6}},
	} {
		if s, r := barrierSummary(c.sandbox, c.h, 7); !r {
			t.Errorf("%s: %q not reported as missing a barrier", name, s)
		}
	}
}
