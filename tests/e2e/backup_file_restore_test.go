package e2e

import (
	"encoding/base64"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Single-file restore on a real node: a running VM's backup is browsed and a
// directory extracted, read inside a restore VM. What is checked is read from
// the node: the restore VM's qemu command line while a session is open, its
// identity, groups, namespace and confinement, the host's mount table before
// and after, the /dev/kvm grants, that no restore VM is left, the extracted
// archive's contents (tar on the node), and the audit row.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_BackupFileRestore -v -timeout 30m
//
// The VM backed up is E2E_FILE_RESTORE_IMAGE (default ubuntu) with
// E2E_FILE_RESTORE_MEMORY (default 1G): its disk must hold /etc, which
// cirros's does not (its root lives in the initramfs).
//
// Needs nested KVM on the node, /dev/vhost-vsock (vhost_vsock module) and
// qemu_fw_cfg among the kernel's modules (on Ubuntu, linux-modules-extra); a
// refusal naming any of them is reported as the failure.
//
// Where the node has AppArmor enabled, the restore qemu MUST carry the
// restore profile in enforce mode (a failure, never a skip). Set
// E2E_EXPECT_APPARMOR=1 to also fail a node that has AppArmor off, so a lab
// that lost it cannot pass vacuously.
//
// Each test starts and ends with no restore VM on its node (frEndSessions):
// a browsing session is kept for five idle minutes by design, and two left
// by one test would hold both of the node's session slots for the next.
func TestLab_BackupFileRestore(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	frEndSessions(l, host)
	vm := l.createStackOf(host, "bkfr", false, fileRestoreImage(), fileRestoreMemory(), host)[host]
	repo := bkRepo(l, host, "e2e-bkfr")
	l.onRestore(func() { frEndSessions(l, host) })
	ts, _, _ := bkSnapshot(l, host, vm, repo)

	mountsBefore := l.mustSSH(host, 30*time.Second, "cat /proc/1/mountinfo")
	target := []string{"--repo", repo, "--vm", vm, "--timestamp", ts}

	out, err := l.lv(host, append([]string{"backup", "file-ls"}, target...)...)
	if err != nil {
		t.Fatalf("file-ls /: %v\n%s", err, out)
	}
	l.saveEvidence("bkfr-volumes", out)
	var vol string
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Fields(ln); len(f) >= 4 && f[0] == "dir" {
			vol = f[len(f)-1]
			if v, err := l.lv(host, append([]string{"backup", "file-ls"}, append(target, "/"+vol)...)...); err == nil && strings.Contains(v, " etc") {
				break
			}
			vol = ""
		}
	}
	if vol == "" {
		t.Fatalf("no volume of the backup of a %s VM holds /etc (E2E_FILE_RESTORE_IMAGE must keep /etc on its disk):\n%s", fileRestoreImage(), out)
	}

	// While the browsing session is open, its restore VM is running: check
	// its isolation on the node, not in litevirt.
	ps := l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true")
	l.saveEvidence("bkfr-qemu", ps)
	ps = strings.TrimSpace(ps)
	for _, want := range []string{"-nic none", "-nodefaults", `"read-only":true`, "vhost-vsock-pci", "-sandbox on"} {
		if !strings.Contains(ps, want) {
			t.Errorf("the restore VM's command line lacks %q:\n%s", want, ps)
		}
	}
	if strings.Contains(ps, "-netdev") {
		t.Errorf("the restore VM has a network device:\n%s", ps)
	}
	// qemu runs as its own per-session uid (never libvirt-qemu or root), with
	// a seccomp filter, confined by its AppArmor profile where AppArmor is
	// on. The trampoline (its parent) carries the same arguments; pick qemu.
	pid := ""
	for _, ln := range strings.Split(strings.TrimSpace(ps), "\n") {
		if f := strings.Fields(ln); len(f) > 1 && !strings.Contains(ln, "__file-restore-exec") {
			pid = f[0]
		}
	}
	if pid == "" {
		t.Fatalf("no restore VM qemu in:\n%s", ps)
	}
	uid, uidErr := frProcUID(l, host, pid)
	status := l.mustSSH(host, 30*time.Second, "grep -E '^(Uid|Gid|Groups|Seccomp|NoNewPrivs):' /proc/"+pid+"/status")
	sec := frStatusField(status, "Seccomp")
	nnp := frStatusField(status, "NoNewPrivs")
	groups := strings.Fields(frStatusField(status, "Groups"))
	kvmGid := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "getent group kvm | cut -d: -f3"))
	// Read separately: an empty attr/current must not read as anything.
	label := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "cat /proc/"+pid+"/attr/apparmor/current 2>/dev/null || cat /proc/"+pid+"/attr/current 2>/dev/null || true"))
	aaOn := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true")) == "Y"
	lsm := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "cat /sys/kernel/security/lsm 2>/dev/null || true"))
	netns := strings.Fields(l.mustSSH(host, 30*time.Second, "readlink /proc/"+pid+"/ns/net /proc/1/ns/net"))
	grants := frKVMGrants(l, host)
	l.saveEvidence("bkfr-qemu-user", fmt.Sprintf("uid %d (%v)\n%s\nkvm gid %s\nlabel %q\napparmor enabled %v\nlsm %s\nnetns %v\nkvm grants %v",
		uid, uidErr, status, kvmGid, label, aaOn, lsm, netns, grants))
	if uidErr != nil || !frReserved(uid) {
		t.Errorf("the restore VM's qemu runs as uid %d (%v), want one of the reserved per-session uids 3800000000..3800000063", uid, uidErr)
	}
	// R4-I1: not in kvm (whose 0775 sockets — libvirt's pull-backup export
	// of a live disk — Landlock does not mediate); KVM is its slot group's ACL entry.
	if kvmGid == "" {
		t.Errorf("no kvm group on %s to check against", host)
	}
	for _, g := range groups {
		if g == kvmGid {
			t.Errorf("the restore VM's qemu is in the kvm group (%s): Groups: %v", kvmGid, groups)
		}
	}
	if grants[uid] != 6 {
		t.Errorf("/dev/kvm has no read-write ACL group entry for the session's slot group %d: %v", uid, grants)
	}
	restoreGid := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "getent group litevirt-restore | cut -d: -f3"))
	wantGroups := []string{restoreGid, strconv.FormatUint(uid, 10)}
	gs := slices.Clone(groups)
	slices.Sort(gs)
	slices.Sort(wantGroups)
	if !slices.Equal(gs, wantGroups) {
		t.Errorf("the restore VM's qemu Groups are %v, want exactly the restore group and its slot group %v", groups, wantGroups)
	}
	// R4-M2: a network namespace of its own.
	if len(netns) != 2 || netns[0] == netns[1] || !strings.HasPrefix(netns[0], "net:[") {
		t.Errorf("the restore VM's qemu is not in a network namespace of its own: %v", netns)
	}
	// The single-peer export: no socket left once qemu has its disk.
	if socks := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "ls /run/litevirt/file-restore/s-*/nbd-*.sock 2>/dev/null || true")); socks != "" {
		t.Errorf("an export socket is still connectable while the VM runs: %s", socks)
	}
	if sec != "2" {
		t.Errorf("the restore VM's qemu has no seccomp filter: Seccomp: %q", sec)
	}
	if nnp != "1" {
		t.Errorf("the restore VM's qemu does not run with no_new_privs: NoNewPrivs: %q", nnp)
	}
	switch {
	case aaOn && label != "litevirt-restore-qemu (enforce)":
		t.Errorf("AppArmor is on but the restore VM's qemu is not confined by litevirt-restore-qemu in enforce mode: %q", label)
	case !aaOn && os.Getenv("E2E_EXPECT_APPARMOR") == "1":
		t.Errorf("E2E_EXPECT_APPARMOR=1 but AppArmor is off on %s: the profile checks would pass vacuously", host)
	case !aaOn:
		t.Logf("AppArmor is OFF on %s: the profile was not exercised (Landlock alone confines qemu; lsm=%s)", host, lsm)
	}
	if !aaOn && !strings.Contains(lsm, "landlock") {
		t.Errorf("neither AppArmor nor Landlock on %s, yet a restore VM started without allow_unsandboxed: [mac]", host)
	}
	// Report only (tightening them is a separate change): the mode of the
	// VM's own disks, which an escaped restore qemu on a host without a MAC
	// barrier could otherwise read.
	disks := l.mustSSH(host, 30*time.Second, "stat -c '%a %U:%G %n' /var/lib/litevirt /var/lib/litevirt/disks /var/lib/litevirt/disks/"+vm+"-* 2>&1 || true")
	l.saveEvidence("bkfr-disk-modes", disks)
	t.Logf("VM disk modes on %s:\n%s", host, disks)
	// The boot files: root-owned, read-only to the restore group, outside
	// /var/lib/litevirt.
	cache := l.mustSSH(host, 30*time.Second, "stat -c '%U:%G %a %n' /var/cache/litevirt-restore /var/cache/litevirt-restore/* | grep -v sha256")
	l.saveEvidence("bkfr-cache", cache)
	for _, ln := range strings.Split(strings.TrimSpace(cache), "\n") {
		if !strings.HasPrefix(ln, "root:litevirt-restore 440 ") && !strings.HasPrefix(ln, "root:litevirt-restore 750 ") {
			t.Errorf("restore boot file not root-owned and read-only to the restore group: %s", ln)
		}
	}

	// The browsing session's VM stays (five idle minutes, by design); the
	// extraction's own VM must be gone once it completes.
	browsing := frRestorePids(l, host)
	archive := "/var/tmp/e2e-bkfr-" + vm + ".tar"
	l.onRestore(func() { _, _ = l.ssh(host, time.Minute, "rm -f "+shellQuote(archive)) })
	if out, err := l.lv(host, append(append([]string{"backup", "file-restore"}, target...), "/"+vol+"/etc", "-o", archive)...); err != nil {
		t.Fatalf("file-restore: %v\n%s", err, out)
	}
	list := l.mustSSH(host, time.Minute, "tar -tvf "+shellQuote(archive))
	l.saveEvidence("bkfr-archive", list)
	if !strings.Contains(list, vol+"/etc/passwd") {
		t.Fatalf("the archive lacks %s/etc/passwd:\n%s", vol, list)
	}
	for _, ln := range strings.Split(list, "\n") {
		if strings.HasPrefix(ln, "h") || strings.HasPrefix(ln, "c") || strings.HasPrefix(ln, "b") || strings.HasPrefix(ln, "p") {
			t.Errorf("the archive holds a link, device or fifo entry: %s", ln)
		}
	}
	// Setuid and setgid by the entries' mode bits (read by Python's
	// tarfile), never by matching text in a listing line, whose name may
	// hold anything.
	modes := l.mustSSH(host, time.Minute, frPython(frTarModes)+" "+shellQuote(archive))
	l.saveEvidence("bkfr-archive-modes", modes)
	n := 0
	for _, ln := range strings.Split(strings.TrimSpace(modes), "\n") {
		f := strings.SplitN(ln, " ", 2)
		m, err := strconv.ParseUint(f[0], 8, 32)
		if err != nil || len(f) != 2 {
			t.Fatalf("archive mode line %q", ln)
		}
		n++
		if m&0o6000 != 0 {
			t.Errorf("the archive holds a setuid/setgid entry (mode %o): %s", m, f[1])
		}
	}
	if n == 0 {
		t.Fatal("control: no archive entry's mode was read")
	}
	passwd := l.mustSSH(host, time.Minute, "tar -xOf "+shellQuote(archive)+" "+shellQuote(vol+"/etc/passwd"))
	if !strings.HasPrefix(passwd, "root:") {
		t.Fatalf("%s/etc/passwd from the archive: %q", vol, passwd)
	}

	// The extraction ended its restore VM (only the browsing one is left)
	// and took its /dev/kvm grant back; the host mounted nothing.
	deadline := time.Now().Add(30 * time.Second)
	for {
		var extra []string
		for p := range frRestorePids(l, host) {
			if !browsing[p] {
				extra = append(extra, p)
			}
		}
		if len(extra) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the extraction's restore VM is still running (pids %v; browsing %v):\n%s", extra, browsing,
				l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true"))
		}
		time.Sleep(2 * time.Second)
	}
	if g := frReservedGrants(frKVMGrants(l, host)); len(g) != 1 || g[uid] == 0 {
		t.Errorf("after the extraction /dev/kvm grants %v to reserved uids, want only the browsing session's %d", g, uid)
	}
	if after := l.mustSSH(host, 30*time.Second, "cat /proc/1/mountinfo"); after != mountsBefore {
		t.Errorf("the node's mount table changed during file restore")
		l.saveEvidence("bkfr-mounts", mountsBefore+"\n----\n"+after)
	}
	rows := l.mustSQL(host, `SELECT result, detail FROM audit_log WHERE action = 'backup.file_restore' ORDER BY seq DESC LIMIT 1`)
	l.saveEvidence("bkfr-audit", fmt.Sprintf("%v", rows))
	if len(rows) == 0 || rows[0][0] != "ok" || !strings.Contains(rows[0][1], "/"+vol+"/etc") {
		t.Fatalf("audit row for the extraction: %v", rows)
	}
	// R4-M4: Landlock applied, as the row says, wherever the kernel has it.
	if strings.Contains(lsm, "landlock") {
		abi := 0
		if m := regexp.MustCompile(`\blandlock=(\d+)\b`).FindStringSubmatch(rows[0][1]); m != nil {
			abi, _ = strconv.Atoi(m[1])
		}
		if abi < 1 {
			t.Errorf("the kernel has Landlock (lsm=%s) but the extraction's audit row does not show it applied: %q", lsm, rows[0][1])
		}
	}

	// The browsing session ends with the daemon: its VM goes and the
	// restarted daemon's sweep removes its /dev/kvm grant.
	frEndSessions(l, host)
	frNoReservedGrants(t, l, host, "after every session ended")
}

// I-4: a daemon restart in the middle of a browsing session leaves no restore
// VM behind: it dies with the old daemon, and the new one sweeps leftovers —
// its /dev/kvm grant included.
func TestLab_BackupFileRestore_DaemonRestartKillsTheVM(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	frEndSessions(l, host)
	vm := l.createVMs(host, "bkfrr", host)[host]
	repo := bkRepo(l, host, "e2e-bkfrr")
	l.onRestore(func() { frEndSessions(l, host) })
	ts, _, _ := bkSnapshot(l, host, vm, repo)
	if out, err := l.lv(host, "backup", "file-ls", "--repo", repo, "--vm", vm, "--timestamp", ts); err != nil {
		t.Fatalf("file-ls: %v\n%s", err, out)
	}
	if ps := l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true"); strings.TrimSpace(ps) == "" {
		t.Fatal("no browsing session's restore VM is running")
	}
	if g := frReservedGrants(frKVMGrants(l, host)); len(g) != 1 {
		t.Errorf("a running session's /dev/kvm grants: %v, want one", g)
	}
	if err := l.restartDaemon(host); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := l.waitDaemon(host, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		ps := l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true")
		if strings.TrimSpace(ps) == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a restore VM survived the daemon restart:\n%s", ps)
		}
		time.Sleep(2 * time.Second)
	}
	frNoReservedGrants(t, l, host, "after the daemon restart")
}

// R2-I1: two restore VMs at once (two backups, possibly two tenants) run as
// different uids and cannot signal or read each other; neither leaves its
// export socket connectable.
func TestLab_BackupFileRestore_ConcurrentSessionsIsolated(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	frEndSessions(l, host)
	vms := l.createVMs(host, "bkfri", host)
	vm := vms[host]
	repo := bkRepo(l, host, "e2e-bkfri")
	// Both sessions stay open five idle minutes by design, holding the
	// node's two slots: they end with this test.
	l.onRestore(func() { frEndSessions(l, host) })
	tsA, _, _ := bkSnapshot(l, host, vm, repo)
	time.Sleep(2 * time.Second)
	tsB, _, _ := bkSnapshot(l, host, vm, repo)
	for _, ts := range []string{tsA, tsB} {
		if out, err := l.lv(host, "backup", "file-ls", "--repo", repo, "--vm", vm, "--timestamp", ts); err != nil {
			t.Fatalf("file-ls %s: %v\n%s", ts, err, out)
		}
	}
	ps := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true"))
	type q struct {
		pid string
		uid uint64
	}
	var qs []q
	for _, ln := range strings.Split(ps, "\n") {
		if f := strings.Fields(ln); len(f) > 1 && !strings.Contains(ln, "__file-restore-exec") {
			uid, err := frProcUID(l, host, f[0])
			if err != nil {
				t.Fatalf("uid of %s: %v", f[0], err)
			}
			qs = append(qs, q{f[0], uid})
		}
	}
	l.saveEvidence("bkfri-qemus", fmt.Sprintf("%v", qs))
	if len(qs) != 2 {
		t.Fatalf("want two restore VMs, found %v", qs)
	}
	if qs[0].uid == qs[1].uid || !frReserved(qs[0].uid) || !frReserved(qs[1].uid) {
		t.Fatalf("two sessions' uids %d and %d: want two distinct reserved uids", qs[0].uid, qs[1].uid)
	}
	// As A's uid: B must be unreachable — no signal, no /proc/<B>/environ.
	// Each negative needs its positive control (the same command as B's own
	// uid succeeds), or a missing setpriv, a wrong pid or a dead qemu would
	// pass it; and the refusal must be a permission error.
	as := func(uid uint64, cmd string) (string, error) {
		return l.ssh(host, 30*time.Second, "setpriv --reuid="+strconv.FormatUint(uid, 10)+" --regid=$(getent group litevirt-restore | cut -d: -f3) --groups=$(getent group litevirt-restore | cut -d: -f3),"+strconv.FormatUint(uid, 10)+" "+cmd+" 2>&1")
	}
	denied := func(out string) bool {
		return strings.Contains(out, "Operation not permitted") || strings.Contains(out, "Permission denied")
	}
	if out, err := as(qs[1].uid, "kill -0 "+qs[1].pid); err != nil {
		t.Fatalf("control: B's own uid cannot signal B's qemu, so the check below proves nothing: %v: %s", err, out)
	}
	if out, err := as(qs[0].uid, "kill -0 "+qs[1].pid); err == nil || !denied(out) {
		t.Errorf("session A's uid signalling session B's qemu: err %v, %q; want a permission error", err, out)
	}
	aaOn := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true")) == "Y"
	if !aaOn {
		// Under AppArmor, deny ptrace refuses environ even to B's own uid:
		// there is no positive control, and the negative is not DAC's.
		if out, err := as(qs[1].uid, "head -c 1 /proc/"+qs[1].pid+"/environ"); err != nil {
			t.Fatalf("control: B's own uid cannot read B's environ: %v: %s", err, out)
		}
	}
	if out, err := as(qs[0].uid, "head -c 1 /proc/"+qs[1].pid+"/environ"); err == nil || !denied(out) {
		t.Errorf("session A's uid reading session B's qemu environment: err %v, %q; want a permission error", err, out)
	}
	if socks := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "ls /run/litevirt/file-restore/s-*/nbd-*.sock 2>/dev/null || true")); socks != "" {
		t.Errorf("an export socket is still connectable: %s", socks)
	}
	if g := frReservedGrants(frKVMGrants(l, host)); len(g) != 2 || g[qs[0].uid] != 6 || g[qs[1].uid] != 6 {
		t.Errorf("/dev/kvm grants %v, want read-write for exactly the two sessions' uids", g)
	}
	if denied := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "dmesg 2>/dev/null | grep litevirt-restore-qemu | grep -i denied | tail -5 || true")); denied != "" {
		t.Logf("AppArmor denials for the restore profile (review):\n%s", denied)
	}
}

// R3-M1 / R2-M2: the uid-range sweep. A process running as a reserved
// restore-VM uid, whatever its command line, is killed by a starting daemon:
// here a decoy with an innocent command line (the sweep must not trust argv,
// which a process can rewrite). The browsing session's own qemu is not what
// this proves — it dies with the old daemon anyway (its trampoline's death
// signal, and exit-with-parent on qemu 9.1+).
func TestLab_BackupFileRestore_UIDRangeSweep(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	frEndSessions(l, host)
	vm := l.createVMs(host, "bkfrs", host)[host]
	repo := bkRepo(l, host, "e2e-bkfrs")
	l.onRestore(func() { frEndSessions(l, host) })
	ts, _, _ := bkSnapshot(l, host, vm, repo)
	// A session ran since boot: the run directory exists, so the starting
	// daemon sweeps the reserved range.
	if out, err := l.lv(host, "backup", "file-ls", "--repo", repo, "--vm", vm, "--timestamp", ts); err != nil {
		t.Fatalf("file-ls: %v\n%s", err, out)
	}
	// The decoy: the last reserved uid (a session takes the lowest free one).
	const decoyUID = "3800000063"
	l.onRestore(func() { _, _ = l.ssh(host, 30*time.Second, "pkill -9 -u "+decoyUID+" || true") })
	l.mustSSH(host, 30*time.Second, "setsid setpriv --reuid="+decoyUID+" --regid=65534 --clear-groups sleep 600 </dev/null >/dev/null 2>&1 &")
	before := frReservedProcs(l, host)
	l.saveEvidence("bkfrs-before", fmt.Sprintf("%v", before))
	decoy := false
	for _, p := range before {
		if strings.HasSuffix(p, " "+decoyUID) {
			decoy = true
		}
	}
	if !decoy {
		t.Fatalf("control: the decoy is not running as the reserved uid: %v", before)
	}
	if err := l.restartDaemon(host); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := l.waitDaemon(host, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		left := frReservedProcs(l, host)
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("processes of reserved restore-VM uids survived the daemon's sweep: %v", left)
		}
		time.Sleep(2 * time.Second)
	}
	frNoReservedGrants(t, l, host, "after the daemon restart")
}

// fileRestoreImage is the image of the VM the file-restore e2e backs up: its
// disk must hold /etc (cirros keeps its root in the initramfs).
func fileRestoreImage() string  { return envOr("E2E_FILE_RESTORE_IMAGE", "ubuntu") }
func fileRestoreMemory() string { return envOr("E2E_FILE_RESTORE_MEMORY", "1G") }

const frUIDBase, frUIDSlots = 3800000000, 64

func frReserved(uid uint64) bool { return uid >= frUIDBase && uid < frUIDBase+frUIDSlots }

// frStatusField is the value of one "Name:\tvalue" line of /proc/<pid>/status.
func frStatusField(status, name string) string {
	for _, ln := range strings.Split(status, "\n") {
		if v, ok := strings.CutPrefix(ln, name+":"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// frProcUID is pid's real uid as /proc/<pid>/status has it — unsigned: ps
// prints uids of 2^31 and above as negative numbers.
func frProcUID(l *lab, host, pid string) (uint64, error) {
	out, err := l.ssh(host, 30*time.Second, "awk '/^Uid:/{print $2}' /proc/"+pid+"/status")
	if err != nil {
		return 0, err
	}
	return strconv.ParseUint(strings.TrimSpace(out), 10, 32)
}

// frRestorePids is the set of pids of restore-VM processes (qemu and its
// trampoline).
func frRestorePids(l *lab, host string) map[string]bool {
	out := l.mustSSH(host, 30*time.Second, "pgrep -f '[l]itevirt-file-restore' || true")
	pids := map[string]bool{}
	for _, f := range strings.Fields(out) {
		pids[f] = true
	}
	return pids
}

// frReservedProcs lists "<pid> <uid>" for every process any of whose uids
// (real, effective, saved, filesystem) is a reserved restore-VM uid, read
// unsigned from /proc.
func frReservedProcs(l *lab, host string) []string {
	out := l.mustSSH(host, time.Minute,
		`for d in /proc/[0-9]*; do awk -v p="${d#/proc/}" '/^Uid:/{print p, $2, $3, $4, $5}' "$d/status" 2>/dev/null; done; true`)
	var procs []string
	for _, ln := range strings.Split(out, "\n") {
		f := strings.Fields(ln)
		if len(f) != 5 {
			continue
		}
		for _, u := range f[1:] {
			if v, err := strconv.ParseUint(u, 10, 32); err == nil && frReserved(v) {
				procs = append(procs, f[0]+" "+u)
				break
			}
		}
	}
	return procs
}

// frACLEntries prints the named entries ("<tag> <id> <perm>", tag 2 = user,
// 8 = group) of /dev/kvm's access ACL, read from the xattr itself. Groups, not users: udev drops every
// named-user entry whenever a KVM VM starts or stops, so a restore VM's slot
// group (gid == its reserved uid) is what holds its access.
const frACLEntries = `import os, struct
try:
    b = os.getxattr("/dev/kvm", "system.posix_acl_access")
except OSError:
    b = b""
for i in range(4, len(b) - 7, 8):
    t, p, u = struct.unpack("<HHI", b[i:i + 8])
    if t in (2, 8):
        print(t, u, p)
`

// frTarModes prints "<octal mode> <name>" for every entry of the archive.
const frTarModes = `import sys, tarfile
for m in tarfile.open(sys.argv[1]):
    print("%o %s" % (m.mode, m.name))
`

// frPython is a shell command running script with python3 (it travels
// base64-encoded, so no quoting).
func frPython(script string) string {
	return "echo " + base64.StdEncoding.EncodeToString([]byte(script)) + " | base64 -d | python3 -"
}

// frKVMEntries is id → permission of every named ACL entry of the given tag
// (2 = user, 8 = group) on /dev/kvm.
func frKVMEntries(l *lab, host string, tag int) map[uint64]int {
	out := l.mustSSH(host, 30*time.Second, frPython(frACLEntries))
	g := map[uint64]int{}
	for _, ln := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Fields(ln)
		if len(f) != 3 {
			continue
		}
		tg, err0 := strconv.Atoi(f[0])
		u, err1 := strconv.ParseUint(f[1], 10, 32)
		p, err2 := strconv.Atoi(f[2])
		if err0 == nil && err1 == nil && err2 == nil && tg == tag {
			g[u] = p
		}
	}
	return g
}

// frKVMGrants is slot gid (== the session's uid) → permission of every
// named-group ACL entry on /dev/kvm.
func frKVMGrants(l *lab, host string) map[uint64]int { return frKVMEntries(l, host, 8) }

// frNoReservedGrants fails if /dev/kvm still names a reserved restore-VM id,
// as a group (the grant) or as a user (what an older daemon granted).
func frNoReservedGrants(t *testing.T, l *lab, host, when string) {
	t.Helper()
	if g := frReservedGrants(frKVMGrants(l, host)); len(g) != 0 {
		t.Errorf("/dev/kvm still has group grants to reserved ids %s: %v", when, g)
	}
	if u := frReservedGrants(frKVMEntries(l, host, 2)); len(u) != 0 {
		t.Errorf("/dev/kvm still has per-user entries for reserved uids %s: %v", when, u)
	}
}

// frReservedGrants keeps the grants to reserved restore-VM uids.
func frReservedGrants(g map[uint64]int) map[uint64]int {
	out := map[uint64]int{}
	for u, p := range g {
		if frReserved(u) {
			out[u] = p
		}
	}
	return out
}

// frEndSessions ends every restore VM on host — browsing sessions are kept
// five idle minutes by design, and there is no call to close one — by
// restarting its daemon, and waits until none is left. A no-op when none
// runs.
func frEndSessions(l *lab, host string) {
	if len(frRestorePids(l, host)) == 0 {
		return
	}
	if err := l.restartDaemon(host); err != nil {
		l.t.Errorf("end the restore VM sessions on %s: restart: %v", host, err)
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	for len(frRestorePids(l, host)) > 0 {
		if time.Now().After(deadline) {
			l.t.Errorf("restore VMs on %s survived a daemon restart", host)
			return
		}
		time.Sleep(2 * time.Second)
	}
}
