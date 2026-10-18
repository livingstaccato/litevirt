package e2e

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/tests/e2e/pitprobe"
)

// An --incremental replication schedule copies a VM's data disk through a
// qemu dirty-bitmap checkpoint chain of its own, on the nested lab
// (E2E_LAB_DIR; skipped without it, and the whole suite skips without
// LITEVIRT_E2E=1). Lab 2 is the intended lab.
//
// A running VM with a root and a data disk replicates every minute into a
// second dir pool on its own host. Known bytes are written into the data disk
// through the guest's block layer (HMP qemu-io, tests/e2e/pitprobe) between
// runs. Checked on the node with virsh, qemu-img and sha256sum, never through
// litevirt:
//
//  1. The first run copies the data disk whole (a raw replica) and leaves a
//     libvirt checkpoint lvrepl-data-<run> whose bitmap is on the data disk.
//  2. Two later runs are incremental (their disk.replicated events say so),
//     each superseding the last checkpoint: only the newest is left.
//  3. With the schedule removed and the VM paused, the newest data replica is
//     byte-identical (sha256) to the data disk's guest-visible content.
//  4. A promotion of that run under a new name restores the data disk from it,
//     and the restored disk is byte-identical to the source too.
//
// Run it with:
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab2 \
//	  go test ./tests/e2e/ -run TestReplication_IncrementalDataDisk -v -timeout 30m
func TestReplication_IncrementalDataDisk(t *testing.T) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]
	const mib = int64(1 << 20)

	suffix := strings.TrimPrefix(uniqueName("incr"), "e2e-")
	srcDir := "/var/lib/litevirt/pools/incrsrc-" + suffix
	copiesDir := "/var/lib/litevirt/pools/incrcopies-" + suffix
	srcPool, copiesPool := "incrsrc-"+suffix, "incrcopies-"+suffix
	for pool, dir := range map[string]string{srcPool: srcDir, copiesPool: copiesDir} {
		l.mustSSH(h, 30*time.Second, "mkdir -p "+shellQuote(dir))
		l.mustLV(h, pitprobe.DirPoolCreateArgs(pool, dir, h)...)
		pool, dir := pool, dir
		t.Cleanup(func() {
			l.lv(h, "pool", "delete", pool, "--host", h, "--force")
			l.ssh(h, 60*time.Second, "rm -rf "+shellQuote(dir))
		})
	}

	stack := uniqueName("incrrep")
	vm := stack + "-1"
	promoted := vm + "-dr"
	scratch := "/var/tmp/" + stack
	t.Cleanup(func() {
		l.ssh(h, 30*time.Second, fmt.Sprintf("rm -f /tmp/%s.yaml %s-*.raw", stack, scratch))
	})
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    firmware: bios\n    disks:\n      root:\n        size: \"1G\"\n        storage: %q\n      data:\n        size: \"64M\"\n        storage: %q\n    placement:\n      host: %s\n",
		stack, vm, drillImage(), drillMemory(), srcPool, srcPool, h)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(h, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	t.Cleanup(func() { l.deleteVMs(stack, map[string]string{h: vm}) })
	if out, err := l.lv(h, "compose", "up", "-f", file, "-y"); err != nil {
		t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	if !l.waitDomainState(h, vm, "running", 4*time.Minute) {
		t.Fatalf("test VM %s never ran on %s (virsh)", vm, h)
	}
	rows := l.mustSQL(h, "SELECT path FROM vm_disks WHERE vm_name = '"+vm+"' AND disk_name = 'data'")
	if len(rows) != 1 {
		t.Fatalf("data disk of %s: rows %v", vm, rows)
	}
	data := rows[0][0]
	alias, err := pitprobe.DiskAlias(l.mustSSH(h, 30*time.Second, pitprobe.DumpXMLCmd(shellQuote(vm))), data)
	if err != nil {
		t.Fatalf("device alias of %s in %s's live XML: %v", data, vm, err)
	}
	dev := pitprobe.QemuIODevice(alias)
	write := func(off, n int64, pattern byte) {
		t.Helper()
		if out := l.mustSSH(h, 2*time.Minute, pitprobe.HMPQemuIO(shellQuote(vm), dev, fmt.Sprintf("write -P 0x%02x %d %d", pattern, off, n))); !pitprobe.Wrote(out) {
			t.Fatalf("qemu-io write at %d on %s: %s", off, dev, out)
		}
	}
	write(0, 4*mib, 0x11)
	write(32*mib, mib, 0x22)

	// The runs of the data disk, oldest first: the taken time of each raw
	// data replica in the copies pool.
	replicaDir := filepath.Join(copiesDir, ".replicas")
	dataRuns := func() []string {
		out, _ := l.ssh(h, 30*time.Second, "find "+shellQuote(replicaDir)+" -name 'data-*.raw' -printf '%f\\n' 2>/dev/null")
		var runs []string
		for _, f := range strings.Fields(out) {
			runs = append(runs, strings.TrimSuffix(strings.TrimPrefix(f, "data-"), ".raw"))
		}
		sort.Strings(runs)
		return runs
	}
	waitRun := func(after string) string {
		t.Helper()
		deadline := time.Now().Add(4 * time.Minute)
		for time.Now().Before(deadline) {
			if runs := dataRuns(); len(runs) > 0 && runs[len(runs)-1] > after {
				return runs[len(runs)-1]
			}
			time.Sleep(10 * time.Second)
		}
		t.Fatalf("no raw replica of %s's data disk newer than %q in %s", vm, after, replicaDir)
		return ""
	}
	detailOf := func(run string) string {
		t.Helper()
		rows := l.mustSQL(h, "SELECT detail FROM vm_events WHERE vm_name = '"+vm+"' AND type = 'disk.replicated' AND result = 'ok' AND detail LIKE 'data → %"+run+"%' ORDER BY ts DESC LIMIT 1")
		if len(rows) != 1 {
			t.Fatalf("no disk.replicated event for data at %s", run)
		}
		return rows[0][0]
	}
	checkpoints := func() []string {
		return strings.Fields(l.mustSSH(h, 30*time.Second, "virsh checkpoint-list "+shellQuote(vm)+" --name"))
	}
	bitmaps := func() string {
		return l.mustSSH(h, 30*time.Second, "qemu-img info -U --output=json "+shellQuote(data))
	}

	l.mustLV(h, "replication", "schedule", "add", vm, "--cron", "* * * * *", "--target-pool", copiesPool,
		"--target-host", h, "--keep", "5", "--incremental")
	t.Cleanup(func() { l.lv(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool) })

	// 1. The first run: a full raw copy, and the data disk's own checkpoint.
	run1 := waitRun("")
	l.mark("first data run %s: %s", run1, detailOf(run1))
	if d := detailOf(run1); !strings.Contains(d, "full") {
		t.Errorf("the first run of the data disk is not full: %s", d)
	}
	cp1 := "lvrepl-data-" + run1
	if cps := checkpoints(); !containsString(cps, cp1) {
		t.Fatalf("no checkpoint %s on %s after the first run (checkpoints %v)", cp1, vm, cps)
	}
	if info := bitmaps(); !strings.Contains(info, cp1) {
		t.Errorf("the data disk carries no bitmap %s: %s", cp1, info)
	}

	// 2. Two incremental runs.
	write(8*mib, 2*mib, 0x33)
	run2 := waitRun(run1)
	write(48*mib, 512<<10, 0x44)
	write(63*mib, mib, 0x55)
	run3 := waitRun(run2)
	for _, run := range []string{run2, run3} {
		d := detailOf(run)
		l.mark("data run %s: %s", run, d)
		if !strings.Contains(d, "incremental") {
			t.Errorf("the data disk's run %s was not incremental: %s", run, d)
		}
	}
	if cps := checkpoints(); containsString(cps, cp1) || !containsString(cps, "lvrepl-data-"+run3) {
		t.Errorf("checkpoints after the third run: %v, want lvrepl-data-%s and not the superseded %s", cps, run3, cp1)
	}

	// 3. No more runs; the newest data replica is the data disk, byte for byte.
	l.mustLV(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool)
	time.Sleep(75 * time.Second) // a run started before the removal finishes
	runs := dataRuns()
	last := runs[len(runs)-1]
	sum := func(path string) string {
		out := strings.Fields(l.mustSSH(h, 5*time.Minute, "sha256sum "+shellQuote(path)))
		if len(out) == 0 {
			t.Fatalf("sha256sum %s: no output", path)
		}
		return out[0]
	}
	l.mustSSH(h, 30*time.Second, "virsh suspend "+shellQuote(vm))
	srcRaw := scratch + "-src.raw"
	l.mustSSH(h, 5*time.Minute, "qemu-img convert -U -f qcow2 -O raw "+shellQuote(data)+" "+srcRaw)
	l.mustSSH(h, 30*time.Second, "virsh resume "+shellQuote(vm))
	want := sum(srcRaw)
	replicaFile := strings.TrimSpace(l.mustSSH(h, 30*time.Second, "find "+shellQuote(replicaDir)+" -name 'data-"+last+".raw' | head -1"))
	if got := sum(replicaFile); got != want {
		t.Fatalf("the data replica of run %s (sha256 %s) is not the data disk (sha256 %s)", last, got, want)
	}

	// 4. A restore from that run reproduces the data disk exactly.
	rootReplica := strings.TrimSpace(l.mustSSH(h, 30*time.Second, "find "+shellQuote(replicaDir)+" -name 'root-"+last+".*' ! -name '*.json' -printf '%f\\n' | head -1"))
	if rootReplica == "" {
		t.Fatalf("no root replica of run %s", last)
	}
	t.Cleanup(func() { l.lv(h, "rm", promoted, "--force") })
	if out, err := l.lv(h, "replication", "promote", vm, "--replica", rootReplica, "--pool", copiesPool,
		"--host", h, "--new-name", promoted); err != nil {
		t.Fatalf("promote %s from %s: %v\n%s", vm, rootReplica, err, out)
	}
	l.lv(h, "stop", promoted, "--force")
	l.waitDomainState(h, promoted, "shut off", 2*time.Minute)
	rows = l.mustSQL(h, "SELECT path FROM vm_disks WHERE vm_name = '"+promoted+"' AND disk_name = 'data'")
	if len(rows) != 1 {
		t.Fatalf("the promoted VM %s has no data disk: rows %v", promoted, rows)
	}
	restored := scratch + "-restored.raw"
	l.mustSSH(h, 5*time.Minute, "qemu-img convert -U -O raw "+shellQuote(rows[0][0])+" "+restored)
	if got := sum(restored); got != want {
		t.Fatalf("the data disk restored from run %s (sha256 %s) is not the source (sha256 %s)", last, got, want)
	}
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
