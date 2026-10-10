package e2e

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A copy of a RUNNING VM's disk is point-in-time (colonelpanik/litevirt#256),
// for lv replicate-volume and for scheduled replication, on the nested lab
// (E2E_LAB_DIR; skipped without it, and the whole suite skips without
// LITEVIRT_E2E=1).
//
// The writer: on the node, a loop of HMP qemu-io writes into the running
// domain's disk — the same block layer a guest write goes through, finished
// before the next starts, so each is as good as a guest's fsynced record.
// Round v writes the byte v over a 64 KiB slot LOW, THEN over a 64 KiB slot
// HIGH, at a higher offset. At every instant the disk therefore holds
// LOW == HIGH or LOW == HIGH+1. The region between the slots is filled first,
// so a copy spends time between reading LOW and reading HIGH.
//
// A copy smeared across its read (qemu-img convert -U of the live image)
// reads LOW early and HIGH late, catches HIGH from a later round, and shows
// HIGH > LOW — a state the disk was never in. A point-in-time copy never
// does. Checked from the node with qemu-img and od, never through litevirt:
//
//   - the copy's slots satisfy LOW == HIGH or LOW == HIGH+1, and HIGH > 0
//     (the copy was taken while the writer ran);
//
//   - qemu-img check on the copy is clean;
//
//   - the copy is not reported, or recorded, as not point-in-time.
//
//     LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//     go test ./tests/e2e/ -run TestReplicateVolume_RunningVMIsPointInTime -v -timeout 40m
func TestReplicateVolume_RunningVMIsPointInTime(t *testing.T) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]

	const (
		mib     = int64(1 << 20)
		slot    = int64(64 << 10)
		diskLen = 1024 * mib
		low     = 256 * mib
		high    = diskLen - slot
		rounds  = 160 // below the fill byte 0xab, so a slot's byte says which it holds
	)

	suffix := strings.TrimPrefix(uniqueName("pit"), "e2e-")
	copiesDir := "/var/lib/litevirt/pools/pitcopies-" + suffix
	copiesPool := "pitcopies-" + suffix
	l.mustSSH(h, 30*time.Second, "mkdir -p "+shellQuote(copiesDir))
	l.mustLV(h, "pool", "create", copiesPool, "--driver", "dir", "--source", copiesDir, "--host", h)
	t.Cleanup(func() {
		l.lv(h, "pool", "delete", copiesPool, "--host", h, "--force")
		l.ssh(h, 60*time.Second, "rm -rf "+shellQuote(copiesDir))
	})

	stack := uniqueName("pitrep")
	vm := stack + "-1"
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      root:\n        size: \"1G\"\n    placement:\n      host: %s\n",
		stack, vm, drillImage(), drillMemory(), h)
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

	// The disk's qdev id, for HMP qemu-io -d.
	alias := strings.TrimSpace(l.mustSSH(h, 30*time.Second, fmt.Sprintf(
		`virsh dumpxml %s --xpath "string(//devices/disk[source/@file='%s']/alias/@name)"`, shellQuote(vm), root)))
	if alias == "" {
		t.Fatalf("no device alias for %s in %s's live XML", root, vm)
	}
	qio := func(cmd string) string {
		return fmt.Sprintf(`virsh qemu-monitor-command %s --hmp 'qemu-io -d %s "%s"'`, shellQuote(vm), alias, cmd)
	}
	// Fill between the slots so the copy takes time to get from LOW to HIGH,
	// and prove the writer works before relying on it.
	for off := low + slot; off < high; off += 64 * mib {
		n := min(64*mib, high-off)
		if out := l.mustSSH(h, 2*time.Minute, qio(fmt.Sprintf("write -P 0xab %d %d", off, n))); strings.Contains(strings.ToLower(out), "error") {
			t.Fatalf("qemu-io fill: %s", out)
		}
	}

	startWriter := func(tag string, pause string) {
		t.Helper()
		script := fmt.Sprintf("for v in $(seq 1 %d); do %s && %s || exit 1; sleep %s; done",
			rounds, qio(fmt.Sprintf("write -P $v %d %d", low, slot)), qio(fmt.Sprintf("write -P $v %d %d", high, slot)), pause)
		l.mustSSH(h, 30*time.Second, fmt.Sprintf("nohup sh -c %s > /tmp/%s-%s.log 2>&1 & echo $! > /tmp/%s-%s.pid",
			shellQuote(script), stack, tag, stack, tag))
		t.Cleanup(func() { l.ssh(h, 30*time.Second, fmt.Sprintf("kill $(cat /tmp/%s-%s.pid) 2>/dev/null", stack, tag)) })
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
	requirePointInTime := func(what, copyPath string) {
		t.Helper()
		if out, err := l.ssh(h, 5*time.Minute, "qemu-img check "+shellQuote(copyPath)); err != nil {
			t.Errorf("%s: qemu-img check %s: %v\n%s", what, copyPath, err, out)
		}
		raw := "/var/tmp/" + stack + "-check.raw"
		l.mustSSH(h, 10*time.Minute, "qemu-img convert -f qcow2 -O raw "+shellQuote(copyPath)+" "+raw)
		defer l.ssh(h, 30*time.Second, "rm -f "+raw)
		lo, hi := slotByte(raw, low), slotByte(raw, high)
		l.mark("%s: copy %s has LOW=%d HIGH=%d", what, copyPath, lo, hi)
		if hi == 0 || hi == 0xab {
			t.Errorf("%s: HIGH=%d: the copy was not taken while the writer ran", what, hi)
		}
		if lo != hi && lo != hi+1 {
			t.Errorf("%s: LOW=%d HIGH=%d — a state the disk was never in; the copy is smeared, not point-in-time", what, lo, hi)
		}
	}

	// lv replicate-volume of the running VM.
	startWriter("rv", "0.05")
	time.Sleep(3 * time.Second)
	out, err := l.lv(h, "replicate-volume", vm, "root", copiesPool)
	if err != nil {
		t.Fatalf("replicate-volume %s root %s: %v\n%s", vm, copiesPool, err, out)
	}
	if strings.Contains(out, "NOT point-in-time") {
		t.Errorf("replicate-volume made a copy that is not point-in-time:\n%s", out)
	}
	target := ""
	for _, line := range strings.Split(out, "\n") {
		if p, ok := strings.CutPrefix(strings.TrimSpace(line), "Target: "); ok {
			target = p
		}
	}
	if target == "" {
		t.Fatalf("replicate-volume printed no target:\n%s", out)
	}
	requirePointInTime("replicate-volume", target)
	l.ssh(h, 30*time.Second, fmt.Sprintf("kill $(cat /tmp/%s-rv.pid) 2>/dev/null", stack))

	// Scheduled replication of the same VM, every minute, into the same pool.
	l.mustLV(h, "replication", "schedule", "add", vm, "--cron", "* * * * *", "--target-pool", copiesPool, "--target-host", h, "--keep", "1")
	t.Cleanup(func() { l.lv(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool) })
	startWriter("sched", "0.3")
	var replica string
	deadline := time.Now().Add(4 * time.Minute)
	for time.Now().Before(deadline) && replica == "" {
		time.Sleep(10 * time.Second)
		replica = strings.TrimSpace(l.mustSSH(h, 30*time.Second,
			"find "+shellQuote(filepath.Join(copiesDir, ".replicas"))+" -name 'root-*.qcow2' 2>/dev/null | head -1"))
	}
	if replica == "" {
		t.Fatalf("no scheduled replica of %s appeared in %s", vm, copiesDir)
	}
	l.lv(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool)
	if rec := l.mustSSH(h, 30*time.Second, "cat "+shellQuote(replica+".json")); strings.Contains(rec, "not_point_in_time") {
		t.Errorf("the scheduled replica is recorded as not point-in-time: %s", rec)
	}
	requirePointInTime("scheduled replication", replica)
}
