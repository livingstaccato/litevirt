package e2e

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Single-file restore on a real node: a running VM's backup is browsed and a
// directory extracted, read inside a restore VM. What is checked is read from
// the node: the restore VM's qemu command line while a session is open, the
// host's mount table before and after, that no restore VM is left, the
// extracted archive's contents (tar on the node), and the audit row.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_BackupFileRestore -v -timeout 30m
//
// Needs nested KVM on the node and /dev/vhost-vsock (vhost_vsock module); a
// refusal naming either is reported as the failure.
//
// Where the node has AppArmor enabled, the restore qemu MUST carry the
// restore profile in enforce mode (a failure, never a skip). Set
// E2E_EXPECT_APPARMOR=1 to also fail a node that has AppArmor off, so a lab
// that lost it cannot pass vacuously.
func TestLab_BackupFileRestore(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	vm := l.createVMs(host, "bkfr", host)[host]
	repo := bkRepo(l, host, "e2e-bkfr")
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
		t.Fatalf("no volume of the backup holds /etc:\n%s", out)
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
	// qemu runs as the dedicated restore user (never libvirt-qemu or root),
	// with a seccomp filter, confined by its AppArmor profile where AppArmor
	// is on. The trampoline (its parent) carries the same arguments; pick qemu.
	pid := ""
	for _, ln := range strings.Split(strings.TrimSpace(ps), "\n") {
		if f := strings.Fields(ln); len(f) > 1 && !strings.Contains(ln, "__file-restore-exec") {
			pid = f[0]
		}
	}
	if pid == "" {
		t.Fatalf("no restore VM qemu in:\n%s", ps)
	}
	uidStr := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "ps -o uid= -p "+pid))
	sec := l.mustSSH(host, 30*time.Second, "grep -E '^Seccomp:' /proc/"+pid+"/status")
	nnp := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "grep -E '^NoNewPrivs:' /proc/"+pid+"/status"))
	// Read separately: an empty attr/current must not read as anything.
	label := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "cat /proc/"+pid+"/attr/apparmor/current 2>/dev/null || cat /proc/"+pid+"/attr/current 2>/dev/null || true"))
	aaOn := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true")) == "Y"
	lsm := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "cat /sys/kernel/security/lsm 2>/dev/null || true"))
	l.saveEvidence("bkfr-qemu-user", fmt.Sprintf("uid %s\n%s\n%s\nlabel %q\napparmor enabled %v\nlsm %s", uidStr, sec, nnp, label, aaOn, lsm))
	if uid, err := strconv.ParseUint(uidStr, 10, 32); err != nil || uid < 3800000000 || uid >= 3800000064 {
		t.Errorf("the restore VM's qemu runs as uid %q, want one of the reserved per-session uids 3800000000..3800000063", uidStr)
	}
	// The single-peer export: no socket left once qemu has its disk.
	if socks := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "ls /run/litevirt/file-restore/s-*/nbd-*.sock 2>/dev/null || true")); socks != "" {
		t.Errorf("an export socket is still connectable while the VM runs: %s", socks)
	}
	if !strings.Contains(sec, "2") {
		t.Errorf("the restore VM's qemu has no seccomp filter: %s", sec)
	}
	if f := strings.Fields(nnp); len(f) != 2 || f[1] != "1" {
		t.Errorf("the restore VM's qemu does not run with no_new_privs: %q", nnp)
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
		if strings.Contains(ln, "rws") || strings.Contains(ln, "r-s") {
			t.Errorf("the archive holds a setuid/setgid entry: %s", ln)
		}
	}
	passwd := l.mustSSH(host, time.Minute, "tar -xOf "+shellQuote(archive)+" "+shellQuote(vol+"/etc/passwd"))
	if !strings.HasPrefix(passwd, "root:") {
		t.Fatalf("%s/etc/passwd from the archive: %q", vol, passwd)
	}

	// The extraction ended its restore VM; the host mounted nothing.
	deadline := time.Now().Add(30 * time.Second)
	for {
		ps = l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true")
		if strings.TrimSpace(ps) == "" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("a restore VM is still running after the extraction:\n%s", ps)
		}
		time.Sleep(2 * time.Second)
	}
	if after := l.mustSSH(host, 30*time.Second, "cat /proc/1/mountinfo"); after != mountsBefore {
		t.Errorf("the node's mount table changed during file restore")
		l.saveEvidence("bkfr-mounts", mountsBefore+"\n----\n"+after)
	}
	rows := l.mustSQL(host, `SELECT result, detail FROM audit_log WHERE action = 'backup.file_restore' ORDER BY seq DESC LIMIT 1`)
	if len(rows) == 0 || rows[0][0] != "ok" || !strings.Contains(rows[0][1], "/"+vol+"/etc") {
		t.Fatalf("audit row for the extraction: %v", rows)
	}
}

// I-4: a daemon restart in the middle of a browsing session leaves no restore
// VM behind: it dies with the old daemon, and the new one sweeps leftovers.
func TestLab_BackupFileRestore_DaemonRestartKillsTheVM(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	vm := l.createVMs(host, "bkfrr", host)[host]
	repo := bkRepo(l, host, "e2e-bkfrr")
	ts, _, _ := bkSnapshot(l, host, vm, repo)
	if out, err := l.lv(host, "backup", "file-ls", "--repo", repo, "--vm", vm, "--timestamp", ts); err != nil {
		t.Fatalf("file-ls: %v\n%s", err, out)
	}
	if ps := l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true"); strings.TrimSpace(ps) == "" {
		t.Fatal("no browsing session's restore VM is running")
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
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("a restore VM survived the daemon restart:\n%s", ps)
		}
		time.Sleep(2 * time.Second)
	}
}

// R2-I1: two restore VMs at once (two backups, possibly two tenants) run as
// different uids and cannot signal or read each other; neither leaves its
// export socket connectable.
func TestLab_BackupFileRestore_ConcurrentSessionsIsolated(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	vms := l.createVMs(host, "bkfri", host)
	vm := vms[host]
	repo := bkRepo(l, host, "e2e-bkfri")
	tsA, _, _ := bkSnapshot(l, host, vm, repo)
	time.Sleep(2 * time.Second)
	tsB, _, _ := bkSnapshot(l, host, vm, repo)
	for _, ts := range []string{tsA, tsB} {
		if out, err := l.lv(host, "backup", "file-ls", "--repo", repo, "--vm", vm, "--timestamp", ts); err != nil {
			t.Fatalf("file-ls %s: %v\n%s", ts, err, out)
		}
	}
	ps := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true"))
	type q struct{ pid, uid string }
	var qs []q
	for _, ln := range strings.Split(ps, "\n") {
		if f := strings.Fields(ln); len(f) > 1 && !strings.Contains(ln, "__file-restore-exec") {
			uid := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "ps -o uid= -p "+f[0]))
			qs = append(qs, q{f[0], uid})
		}
	}
	l.saveEvidence("bkfri-qemus", fmt.Sprintf("%v", qs))
	if len(qs) != 2 {
		t.Fatalf("want two restore VMs, found %v", qs)
	}
	if qs[0].uid == qs[1].uid {
		t.Fatalf("two sessions share uid %s", qs[0].uid)
	}
	// As A's uid: B must be unreachable — no signal, no /proc/<B>/environ.
	// Each negative needs its positive control (the same command as B's own
	// uid succeeds), or a missing setpriv, a wrong pid or a dead qemu would
	// pass it; and the refusal must be a permission error.
	as := func(uid, cmd string) (string, error) {
		return l.ssh(host, 30*time.Second, "setpriv --reuid="+uid+" --regid=$(getent group litevirt-restore | cut -d: -f3) --clear-groups "+cmd+" 2>&1")
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
	if denied := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "dmesg 2>/dev/null | grep litevirt-restore-qemu | grep -i denied | tail -5 || true")); denied != "" {
		t.Logf("AppArmor denials for the restore profile (review):\n%s", denied)
	}
}

// R3-M1 / R2-M2: the uid-range sweep. A process running as a reserved
// restore-VM uid, whatever its command line, is killed by a starting daemon
// — here both a real restore qemu whose trampoline was SIGKILLed and a decoy
// with an innocent command line (the sweep must not trust argv, which a
// process can rewrite).
func TestLab_BackupFileRestore_UIDRangeSweep(t *testing.T) {
	l := newLab(t)
	host := labUpHosts(l, 1)[0]
	vm := l.createVMs(host, "bkfrs", host)[host]
	repo := bkRepo(l, host, "e2e-bkfrs")
	ts, _, _ := bkSnapshot(l, host, vm, repo)
	if out, err := l.lv(host, "backup", "file-ls", "--repo", repo, "--vm", vm, "--timestamp", ts); err != nil {
		t.Fatalf("file-ls: %v\n%s", err, out)
	}
	// The decoy: the last reserved uid (a session takes the lowest free one).
	const decoyUID = "3800000063"
	l.onRestore(func() { _, _ = l.ssh(host, 30*time.Second, "pkill -9 -u "+decoyUID+" || true") })
	l.mustSSH(host, 30*time.Second, "setsid setpriv --reuid="+decoyUID+" --regid=65534 --clear-groups sleep 600 </dev/null >/dev/null 2>&1 &")
	if out := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "pgrep -u "+decoyUID+" sleep || true")); out == "" {
		t.Fatal("control: the decoy is not running as the reserved uid")
	}
	// SIGKILL the trampoline (qemu's parent): the pidfile record of its qemu
	// is then no longer the way back to it.
	tramp := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "pgrep -f '[_]_file-restore-exec' | head -1"))
	if tramp == "" {
		t.Fatal("no trampoline found")
	}
	l.mustSSH(host, 30*time.Second, "kill -9 "+tramp)
	after := l.mustSSH(host, 30*time.Second, "pgrep -af '[l]itevirt-file-restore' || true")
	l.saveEvidence("bkfrs-after-trampoline-kill", after)
	if err := l.restartDaemon(host); err != nil {
		t.Fatalf("restart: %v", err)
	}
	if err := l.waitDaemon(host, 2*time.Minute); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		left := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "ps -eo pid,uid,args | awk '$2>=3800000000 && $2<3800000064' || true"))
		if left == "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("processes of reserved restore-VM uids survived the daemon's sweep:\n%s", left)
		}
		time.Sleep(2 * time.Second)
	}
}
