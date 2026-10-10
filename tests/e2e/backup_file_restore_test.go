package e2e

import (
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
	for _, want := range []string{"-nic none", "-nodefaults", `"read-only":true`, "vhost-vsock-pci", "-sandbox on"} {
		if !strings.Contains(ps, want) {
			t.Errorf("the restore VM's command line lacks %q:\n%s", want, ps)
		}
	}
	if strings.Contains(ps, "-netdev") {
		t.Errorf("the restore VM has a network device:\n%s", ps)
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
