package e2e

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A copy of a RUNNING VM's disk is point-in-time (colonelpanik/litevirt#256),
// through each of the copy's layers, on the nested lab (E2E_LAB_DIR; skipped
// without it, and the whole suite skips without LITEVIRT_E2E=1).
//
// The writer: on the node, a loop of HMP qemu-io writes into the running
// domain's disk — the same block layer a guest write goes through, finished
// before the next starts, so each is as good as a guest's fsynced record.
// Round v writes the byte v over a 64 KiB slot LOW, THEN over a 64 KiB slot
// HIGH at a higher offset. At every instant the disk therefore holds
// LOW == HIGH or LOW == HIGH+1. The region between the slots is filled first,
// so a copy spends time between reading LOW and reading HIGH. A copy smeared
// across its read (qemu-img convert -U of the live image) reads LOW early and
// HIGH late and can show HIGH > LOW — a state the disk was never in. A
// point-in-time copy never does. Every copy is also checked to have finished
// while the writer was still running, so the check cannot pass vacuously.
//
// Legs, each read back from the node with qemu-img, od and virsh:
//
//  1. Layer 1 (backup session), lv replicate-volume: point-in-time.
//  2. Layer 2 (external snapshot), forced by making the session impossible:
//     the backup scratch directory (/var/lib/litevirt/backup-scratch) is
//     replaced by a file for the leg, so BeginBackup fails before it reaches
//     libvirt. No operator knob does this; it is what a host where sessions
//     cannot open looks like. Point-in-time, and afterwards libvirt has the
//     VM on its disk, live and persistent, with no block job and no overlay.
//  3. Layer 3 (-U), forced by also making the snapshot impossible: the VM's
//     disk lives in a pool directory of its own, made immutable (chattr +i)
//     for the leg, so libvirt cannot create the overlay beside it. The copy is
//     made, reported NOT point-in-time and recorded so.
//  4. Scheduled replication (layer 1): point-in-time, recorded so.
//
// The leg-2 and leg-3 tricks have two side effects on the node: its backup
// scratch directory is replaced by a file (any backup or backup session on
// that node fails meanwhile), and this test's own pool directory is made
// immutable. So they run only on a node pinned with E2E_PIT_EXCLUSIVE_NODE
// (the operator asserting nothing else runs there), under a node-side lock
// (/run/lv-e2e-pit.lock, skipped if held), with a systemd-run watchdog armed
// first that restores both after 30 minutes even if this test is killed, and
// every restore is verified and logged.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestReplicateVolume_RunningVMIsPointInTime -v -timeout 40m
func TestReplicateVolume_RunningVMIsPointInTime(t *testing.T) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]
	if out, err := l.ssh(h, 20*time.Second, "command -v chattr"); err != nil {
		t.Skipf("%s has no chattr: %s", h, strings.TrimSpace(out))
	}

	const (
		mib     = int64(1 << 20)
		slot    = int64(64 << 10)
		diskLen = 1024 * mib
		low     = 256 * mib
		high    = diskLen - slot
		rounds  = 160 // below the fill byte 0xab, so a slot's byte says which it holds
		scratch = "/var/lib/litevirt/backup-scratch"
	)

	suffix := strings.TrimPrefix(uniqueName("pit"), "e2e-")
	srcDir := "/var/lib/litevirt/pools/pitsrc-" + suffix
	copiesDir := "/var/lib/litevirt/pools/pitcopies-" + suffix
	srcPool, copiesPool := "pitsrc-"+suffix, "pitcopies-"+suffix
	for pool, dir := range map[string]string{srcPool: srcDir, copiesPool: copiesDir} {
		l.mustSSH(h, 30*time.Second, "mkdir -p "+shellQuote(dir))
		l.mustLV(h, "pool", "create", pool, "--driver", "dir", "--source", dir, "--host", h)
		pool, dir := pool, dir
		t.Cleanup(func() {
			l.ssh(h, 30*time.Second, "chattr -i "+shellQuote(dir))
			l.lv(h, "pool", "delete", pool, "--host", h, "--force")
			l.ssh(h, 60*time.Second, "rm -rf "+shellQuote(dir))
		})
	}

	stack := uniqueName("pitrep")
	vm := stack + "-1"
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      root:\n        size: \"1G\"\n        storage: %q\n    placement:\n      host: %s\n",
		stack, vm, drillImage(), drillMemory(), srcPool, h)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(h, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	t.Cleanup(func() { l.deleteVMs(stack, map[string]string{h: vm}) })
	if out, err := l.lv(h, "compose", "up", "-f", file, "-y"); err != nil {
		t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	if !l.waitDomainState(h, vm, "running", 4*time.Minute) {
		t.Fatalf("test VM %s never ran on %s (virsh)", vm, h)
	}
	rows := l.mustSQL(h, "SELECT path FROM vm_disks WHERE vm_name = '"+vm+"' AND disk_name = 'root'")
	if len(rows) != 1 {
		t.Fatalf("root disk of %s: rows %v", vm, rows)
	}
	root := rows[0][0]
	if filepath.Dir(root) != srcDir {
		t.Fatalf("root disk %s is not in the test's own pool directory %s", root, srcDir)
	}
	overlay := filepath.Join(filepath.Dir(root), "."+filepath.Base(root)+".lv-pit")

	// The disk's qdev id, for HMP qemu-io -d.
	alias := strings.TrimSpace(l.mustSSH(h, 30*time.Second, fmt.Sprintf(
		`virsh dumpxml %s --xpath "string(//devices/disk[source/@file='%s']/alias/@name)"`, shellQuote(vm), root)))
	if alias == "" {
		t.Fatalf("no device alias for %s in %s's live XML", root, vm)
	}
	qio := func(cmd string) string {
		return fmt.Sprintf(`virsh qemu-monitor-command %s --hmp 'qemu-io -d %s "%s"'`, shellQuote(vm), alias, cmd)
	}
	for off := low + slot; off < high; off += 64 * mib {
		n := min(64*mib, high-off)
		if out := l.mustSSH(h, 2*time.Minute, qio(fmt.Sprintf("write -P 0xab %d %d", off, n))); strings.Contains(strings.ToLower(out), "error") {
			t.Fatalf("qemu-io fill: %s", out)
		}
	}

	pidFile := func(tag string) string { return fmt.Sprintf("/tmp/%s-%s.pid", stack, tag) }
	startWriter := func(tag, pause string) {
		t.Helper()
		script := fmt.Sprintf("for v in $(seq 1 %d); do %s && %s || exit 1; sleep %s; done",
			rounds, qio(fmt.Sprintf("write -P $v %d %d", low, slot)), qio(fmt.Sprintf("write -P $v %d %d", high, slot)), pause)
		l.mustSSH(h, 30*time.Second, fmt.Sprintf("nohup sh -c %s > /tmp/%s-%s.log 2>&1 & echo $! > %s",
			shellQuote(script), stack, tag, pidFile(tag)))
		t.Cleanup(func() { l.ssh(h, 30*time.Second, fmt.Sprintf("kill $(cat %s) 2>/dev/null", pidFile(tag))) })
		time.Sleep(3 * time.Second)
	}
	writerAlive := func(what, tag string) {
		t.Helper()
		if _, err := l.ssh(h, 20*time.Second, fmt.Sprintf("kill -0 $(cat %s)", pidFile(tag))); err != nil {
			t.Errorf("%s: the writer had finished before the copy did; the check would be vacuous", what)
		}
	}
	stopWriter := func(tag string) {
		l.ssh(h, 30*time.Second, fmt.Sprintf("kill $(cat %s) 2>/dev/null", pidFile(tag)))
	}
	slotByte := func(raw string, off int64) int {
		t.Helper()
		out := strings.TrimSpace(l.mustSSH(h, 30*time.Second, fmt.Sprintf("od -An -tu1 -j %d -N1 %s", off, shellQuote(raw))))
		v, err := strconv.Atoi(out)
		if err != nil {
			t.Fatalf("read slot at %d of %s: %q", off, raw, out)
		}
		return v
	}
	slots := func(what, copyPath string) (int, int) {
		t.Helper()
		if out, err := l.ssh(h, 5*time.Minute, "qemu-img check "+shellQuote(copyPath)); err != nil {
			t.Errorf("%s: qemu-img check %s: %v\n%s", what, copyPath, err, out)
		}
		raw := "/var/tmp/" + stack + "-check.raw"
		l.mustSSH(h, 10*time.Minute, "qemu-img convert -f qcow2 -O raw "+shellQuote(copyPath)+" "+raw)
		defer l.ssh(h, 30*time.Second, "rm -f "+raw)
		lo, hi := slotByte(raw, low), slotByte(raw, high)
		l.mark("%s: copy %s has LOW=%d HIGH=%d", what, copyPath, lo, hi)
		if hi == 0 || hi >= rounds {
			t.Errorf("%s: HIGH=%d: the copy was not taken while the writer ran", what, hi)
		}
		return lo, hi
	}
	requirePointInTime := func(what, copyPath string) {
		t.Helper()
		if lo, hi := slots(what, copyPath); lo != hi && lo != hi+1 {
			t.Errorf("%s: LOW=%d HIGH=%d — a state the disk was never in; the copy is smeared, not point-in-time", what, lo, hi)
		}
	}
	replicateVolume := func(what string) (string, string) {
		t.Helper()
		out, err := l.lv(h, "replicate-volume", vm, "root", copiesPool)
		if err != nil {
			t.Fatalf("%s: replicate-volume %s root %s: %v\n%s", what, vm, copiesPool, err, out)
		}
		target := ""
		for _, line := range strings.Split(out, "\n") {
			if p, ok := strings.CutPrefix(strings.TrimSpace(line), "Target: "); ok {
				target = p
			}
		}
		if target == "" {
			t.Fatalf("%s: replicate-volume printed no target:\n%s", what, out)
		}
		return target, out
	}
	lastReplicatedDetail := func() string {
		rows := l.mustSQL(h, "SELECT detail FROM vm_events WHERE vm_name = '"+vm+"' AND type = 'disk.replicated' ORDER BY ts DESC LIMIT 1")
		if len(rows) == 0 {
			return ""
		}
		return rows[0][0]
	}

	// Leg 1: a backup session.
	startWriter("l1", "0.25")
	target, out := replicateVolume("layer 1")
	writerAlive("layer 1", "l1")
	stopWriter("l1")
	if strings.Contains(out, "NOT point-in-time") {
		t.Errorf("layer 1 made a copy that is not point-in-time:\n%s", out)
	}
	if d := lastReplicatedDetail(); !strings.Contains(d, "backup session") {
		t.Errorf("layer 1's copy was not made by a backup session: %q", d)
	}
	requirePointInTime("layer 1 (backup session)", target)

	// Legs 2 and 3 change node-wide state for a few minutes: the backup
	// scratch directory, and the immutable bit on this test's own pool
	// directory. They run only on a node the operator pins to this test
	// (E2E_PIT_EXCLUSIVE_NODE, asserting no other e2e or backup runs there),
	// under a node-side lock, with a node-side watchdog (systemd-run) that
	// restores both even if this process is killed; each restore is checked.
	restore := fmt.Sprintf("[ -f %[1]s ] && rm -f %[1]s && mv %[1]s.e2e-held %[1]s; chattr -i %[2]s; rmdir /run/lv-e2e-pit.lock", scratch, shellQuote(srcDir))
	unit := "lv-e2e-pit-restore-" + suffix
	restoreAndVerify := func() {
		t.Helper()
		l.ssh(h, 30*time.Second, restore)
		if out, err := l.ssh(h, 30*time.Second, fmt.Sprintf("test -d %[1]s && ! test -e %[1]s.e2e-held && ! lsattr -d %[2]s | cut -c1-20 | grep -q i && echo restored", scratch, shellQuote(srcDir))); err != nil || !strings.Contains(out, "restored") {
			t.Errorf("leg 2/3 side effects not restored on %s: %v %s", h, err, out)
		} else {
			l.mark("legs 2/3: backup scratch and %s restored", srcDir)
		}
		l.ssh(h, 30*time.Second, "systemctl stop "+unit+".timer "+unit+".service 2>/dev/null")
	}
	forcedLegs := func() {
		// Leg 2: no session can open, so an external snapshot.
		l.mustSSH(h, 30*time.Second, fmt.Sprintf("mv %[1]s %[1]s.e2e-held && touch %[1]s", scratch))
		startWriter("l2", "0.25")
		target, out = replicateVolume("layer 2")
		writerAlive("layer 2", "l2")
		stopWriter("l2")
		if strings.Contains(out, "pit_overlay") {
			// Layer 2 waits for the pit_overlay release feature (round 5,
			// I3): until this build holds it, the copy takes the existing
			// path, marked, and no overlay is ever made.
			l.mark("layer 2 is gated on the pit_overlay release feature; the copy took the last layer")
			if !strings.Contains(out, "NOT point-in-time") || l.fileExists(h, overlay) {
				t.Errorf("a gated layer 2 made an overlay or an unmarked copy:\n%s", out)
			}
		} else {
			if strings.Contains(out, "NOT point-in-time") {
				t.Errorf("layer 2 made a copy that is not point-in-time:\n%s", out)
			}
			if d := lastReplicatedDetail(); !strings.Contains(d, "external snapshot") {
				t.Errorf("layer 2's copy was not made by an external snapshot: %q", d)
			}
			requirePointInTime("layer 2 (external snapshot)", target)
			if blk := l.mustSSH(h, 30*time.Second, "virsh domblklist "+shellQuote(vm)); !strings.Contains(blk, root) || strings.Contains(blk, ".lv-pit") {
				t.Errorf("after layer 2 the VM does not run on its disk:\n%s", blk)
			}
			inactive := l.mustSSH(h, 30*time.Second, "virsh dumpxml --inactive "+shellQuote(vm))
			if strings.Contains(inactive, ".lv-pit") || !strings.Contains(inactive, root) {
				t.Errorf("after layer 2 the persistent definition does not name the disk alone:\n%s", inactive)
			}
			if strings.Contains(inactive, "<backingStore type") {
				t.Errorf("after layer 2 the persistent definition keeps a backing chain:\n%s", inactive)
			}
			if job, _ := l.ssh(h, 30*time.Second, "virsh blockjob "+shellQuote(vm)+" "+shellQuote(root)+" --info"); !strings.Contains(job, "No current block job") {
				t.Errorf("after layer 2 a block job is left on the disk: %s", job)
			}
			if l.fileExists(h, overlay) {
				t.Errorf("after layer 2 the overlay %s is still there", overlay)
			}
			// The window's token was written on the real disk before the
			// snapshot (round 4, N1). On a pool filesystem with user xattrs it
			// is still there, 32 hex digits; a filesystem without them (NFS
			// before 4.2) has none, and the binding recorded no_xattr.
			if tok, err := l.ssh(h, 30*time.Second, "getfattr --only-values -n user.litevirt.pit_window "+shellQuote(root)+" 2>&1"); err != nil {
				t.Logf("layer 2: no window token on %s (a filesystem without user xattrs?): %s", root, tok)
			} else if tok = strings.TrimSpace(tok); len(tok) != 32 {
				t.Errorf("layer 2: the window token on %s is %q, want 32 hex digits", root, tok)
			}
		}

		// Leg 3: no session and no snapshot, so main's -U copy, marked.
		l.mustSSH(h, 30*time.Second, "chattr +i "+shellQuote(srcDir))
		startWriter("l3", "0.25")
		target, out = replicateVolume("layer 3")
		writerAlive("layer 3", "l3")
		stopWriter("l3")
		restoreAndVerify()
		if !strings.Contains(out, "NOT point-in-time") {
			t.Errorf("layer 3's copy was not reported NOT point-in-time:\n%s", out)
		}
		if rec := l.mustSSH(h, 30*time.Second, "grep -o '\"[^\"]*"+filepath.Base(target)+"\"[^}]*}' /var/lib/litevirt/pool-uploads.json || true"); !strings.Contains(rec, "not_point_in_time") {
			t.Errorf("layer 3's copy is not recorded as not point-in-time: %q", rec)
		}
		lo, hi := slots("layer 3 (-U)", target)
		l.mark("layer 3: LOW=%d HIGH=%d (smeared: %v)", lo, hi, lo != hi && lo != hi+1)
	}
	// The legs' gate is a subtest of its own, so a skip shows in the results
	// (a red run on the lab must not pass on layers 1 and 4 alone).
	forced := false
	t.Run("forced layers 2 and 3", func(st *testing.T) {
		if os.Getenv("E2E_PIT_EXCLUSIVE_NODE") != h {
			st.Skipf("set E2E_PIT_EXCLUSIVE_NODE=%s to pin legs 2 and 3 to this node (no other e2e or backup may run there)", h)
		}
		if out, err := l.ssh(h, 20*time.Second, "mkdir /run/lv-e2e-pit.lock"); err != nil {
			st.Skipf("another run holds /run/lv-e2e-pit.lock on %s: %s", h, out)
		}
		forced = true
	})
	if forced {
		if out, err := l.ssh(h, 30*time.Second, fmt.Sprintf("systemd-run --unit %s --on-active=30m /bin/sh -c %s", unit, shellQuote(restore))); err != nil {
			l.ssh(h, 20*time.Second, "rmdir /run/lv-e2e-pit.lock")
			t.Fatalf("arm the restore watchdog on %s: %v %s", h, err, out)
		}
		t.Cleanup(restoreAndVerify)
		forcedLegs()
	}

	// Leg 4: scheduled replication of the same VM, every minute.
	l.mustLV(h, "replication", "schedule", "add", vm, "--cron", "* * * * *", "--target-pool", copiesPool, "--target-host", h, "--keep", "1")
	t.Cleanup(func() { l.lv(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool) })
	startWriter("sched", "0.5")
	var replica string
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) && replica == "" {
		time.Sleep(10 * time.Second)
		replica = strings.TrimSpace(l.mustSSH(h, 30*time.Second,
			"find "+shellQuote(filepath.Join(copiesDir, ".replicas"))+" -name 'root-*.qcow2' 2>/dev/null | head -1"))
	}
	writerAlive("scheduled replication", "sched")
	stopWriter("sched")
	if replica == "" {
		t.Fatalf("no scheduled replica of %s appeared in %s", vm, copiesDir)
	}
	l.lv(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool)
	if rec := l.mustSSH(h, 30*time.Second, "cat "+shellQuote(replica+".json")); strings.Contains(rec, "not_point_in_time") {
		t.Errorf("the scheduled replica is recorded as not point-in-time: %s", rec)
	}
	requirePointInTime("scheduled replication", replica)
}
