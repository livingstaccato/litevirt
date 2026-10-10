package e2e

import (
	"fmt"
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
	aa := l.mustSSH(host, 30*time.Second, "cat /proc/"+pid+"/attr/current 2>/dev/null; cat /sys/module/apparmor/parameters/enabled 2>/dev/null || true")
	l.saveEvidence("bkfr-qemu-user", uidStr+"\n"+sec+"\n"+aa)
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
	if strings.Contains(aa, "\nY") && !strings.Contains(aa, "litevirt-restore-qemu (enforce)") {
		t.Errorf("AppArmor is on but the restore VM's qemu is not confined: %s", aa)
	}
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
	as := func(uid, cmd string) (string, error) {
		return l.ssh(host, 30*time.Second, "setpriv --reuid="+uid+" --regid=$(getent group litevirt-restore | cut -d: -f3) --clear-groups "+cmd)
	}
	if out, err := as(qs[0].uid, "kill -0 "+qs[1].pid); err == nil {
		t.Errorf("session A's uid can signal session B's qemu: %s", out)
	}
	if out, err := as(qs[0].uid, "cat /proc/"+qs[1].pid+"/environ"); err == nil {
		t.Errorf("session A's uid can read session B's qemu environment: %s", out)
	}
	if socks := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "ls /run/litevirt/file-restore/s-*/nbd-*.sock 2>/dev/null || true")); socks != "" {
		t.Errorf("an export socket is still connectable: %s", socks)
	}
	if denied := strings.TrimSpace(l.mustSSH(host, 30*time.Second, "dmesg 2>/dev/null | grep litevirt-restore-qemu | grep -i denied | tail -5 || true")); denied != "" {
		t.Logf("AppArmor denials for the restore profile (review):\n%s", denied)
	}
}
