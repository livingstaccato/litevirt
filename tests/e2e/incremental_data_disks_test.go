package e2e

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
// runs, and the test keeps a model of the disk: zeros (a new disk the guest
// never touches) plus every write. Each replica checked is compared, by
// sha256 on the node, with the model at its run; the replica of a run is one
// whose time is after the last write, so its point in time follows it.
// Checked on the node with virsh, qemu-img and sha256sum, never through
// litevirt:
//
//  1. The first run copies the data disk whole (a raw replica) and leaves a
//     libvirt checkpoint lvrepl-data-<run> whose bitmap is on the data disk.
//  2. Two later runs are incremental (their disk.replicated events say so),
//     each superseding the last checkpoint: only the newest is left.
//  3. After `lv stop --force` (qemu killed; the writes flushed first) and a
//     start, the next run is not incremental: an unclean stop leaves the
//     bitmap inconsistent, which libvirt refuses.
//  4. After a clean `lv stop` and a start, the next run IS incremental: the
//     bitmap persisted.
//  5. After a live detach and reattach of the same file (virsh), the next
//     run's replica is still exact, whichever way it was made.
//  6. With the schedule removed and the VM shut off cleanly (a consistent
//     state, no -U), the data disk equals the model, and so does the newest
//     replica.
//  7. A promotion of that run under a new name restores the data disk from
//     it, equal to the model too.
//
// Run it with:
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab2 \
//	  go test ./tests/e2e/ -run TestReplication_IncrementalDataDisk -v -timeout 45m
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
	size, err := l.qemuVirtualSize(h, data)
	if err != nil || size <= 0 {
		t.Fatalf("virtual size of %s: %d %v", data, size, err)
	}
	model := make([]byte, size)
	sumOf := func(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

	dev := func() string {
		t.Helper()
		alias, err := pitprobe.DiskAlias(l.mustSSH(h, 30*time.Second, pitprobe.DumpXMLCmd(shellQuote(vm))), data)
		if err != nil {
			t.Fatalf("device alias of %s in %s's live XML: %v", data, vm, err)
		}
		return pitprobe.QemuIODevice(alias)
	}
	nodeNow := func() string {
		return strings.TrimSpace(l.mustSSH(h, 20*time.Second, "date -u +%Y%m%d-%H%M%S"))
	}
	// write writes pattern over [off, off+n) through the guest's block layer,
	// into the model too, and returns the node's time after it.
	write := func(off, n int64, pattern byte) string {
		t.Helper()
		if out := l.mustSSH(h, 2*time.Minute, pitprobe.HMPQemuIO(shellQuote(vm), dev(), fmt.Sprintf("write -P 0x%02x %d %d", pattern, off, n))); !pitprobe.Wrote(out) {
			t.Fatalf("qemu-io write at %d: %s", off, out)
		}
		for i := off; i < off+n; i++ {
			model[i] = pattern
		}
		time.Sleep(time.Second)
		return nodeNow()
	}
	flush := func() {
		t.Helper()
		l.mustSSH(h, 2*time.Minute, pitprobe.HMPQemuIO(shellQuote(vm), dev(), "flush"))
	}

	// The runs of the data disk, oldest first: the taken time of each data
	// replica in the copies pool (raw from a chain, qcow2 from a fallback).
	replicaDir := filepath.Join(copiesDir, ".replicas")
	type replica struct{ taken, file string }
	dataRuns := func() []replica {
		out, _ := l.ssh(h, 30*time.Second, "find "+shellQuote(replicaDir)+" -name 'data-*' ! -name '*.json' ! -name '.*' 2>/dev/null")
		var runs []replica
		for _, f := range strings.Fields(out) {
			base := filepath.Base(f)
			ext := filepath.Ext(base)
			if ext != ".raw" && ext != ".qcow2" {
				continue
			}
			runs = append(runs, replica{taken: strings.TrimSuffix(strings.TrimPrefix(base, "data-"), ext), file: f})
		}
		sort.Slice(runs, func(i, j int) bool { return runs[i].taken < runs[j].taken })
		return runs
	}
	// waitRun is the first data replica of a run later than after.
	waitRun := func(after string) replica {
		t.Helper()
		deadline := time.Now().Add(4 * time.Minute)
		for time.Now().Before(deadline) {
			for _, r := range dataRuns() {
				if r.taken > after {
					return r
				}
			}
			time.Sleep(10 * time.Second)
		}
		t.Fatalf("no replica of %s's data disk from a run after %s in %s", vm, after, replicaDir)
		return replica{}
	}
	detailOf := func(run string) string {
		t.Helper()
		rows := l.mustSQL(h, "SELECT detail FROM vm_events WHERE vm_name = '"+vm+"' AND type = 'disk.replicated' AND result = 'ok' AND detail LIKE 'data → %"+run+"%' ORDER BY ts DESC LIMIT 1")
		if len(rows) != 1 {
			// A fallback copy's event names the replica file, which carries the run.
			rows = l.mustSQL(h, "SELECT detail FROM vm_events WHERE vm_name = '"+vm+"' AND type = 'disk.replicated' AND result = 'ok' AND detail LIKE 'data → %data-"+run+"%' ORDER BY ts DESC LIMIT 1")
		}
		if len(rows) != 1 {
			t.Fatalf("no disk.replicated event for data at %s", run)
		}
		return rows[0][0]
	}
	sumOnNode := func(path, format string) string {
		t.Helper()
		raw := scratch + "-check.raw"
		defer l.ssh(h, 30*time.Second, "rm -f "+raw)
		l.mustSSH(h, 5*time.Minute, fmt.Sprintf("qemu-img convert -f %s -O raw %s %s", format, shellQuote(path), raw))
		out := strings.Fields(l.mustSSH(h, 5*time.Minute, "sha256sum "+raw))
		if len(out) == 0 {
			t.Fatalf("sha256sum of %s: no output", path)
		}
		return out[0]
	}
	exact := func(what string, r replica) {
		t.Helper()
		format := strings.TrimPrefix(filepath.Ext(r.file), ".")
		if got, want := sumOnNode(r.file, format), sumOf(model); got != want {
			t.Fatalf("%s: the data replica of run %s (%s, sha256 %s) is not the disk at that run (sha256 %s)", what, r.taken, format, got, want)
		}
		l.mark("%s: data replica of run %s is exact (%s)", what, r.taken, detailOf(r.taken))
	}
	checkpoints := func() []string {
		return strings.Fields(l.mustSSH(h, 30*time.Second, "virsh checkpoint-list "+shellQuote(vm)+" --name"))
	}
	restart := func(force bool) {
		t.Helper()
		args := []string{"stop", vm}
		if force {
			args = append(args, "--force")
		}
		if out, err := l.lv(h, args...); err != nil {
			t.Fatalf("lv %v: %v\n%s", args, err, out)
		}
		if !l.waitDomainState(h, vm, "shut off", 4*time.Minute) {
			t.Fatalf("%s did not shut off (lv %v)", vm, args)
		}
		l.mustLV(h, "start", vm)
		if !l.waitDomainState(h, vm, "running", 4*time.Minute) {
			t.Fatalf("%s did not run again", vm)
		}
	}

	write(0, 4*mib, 0x11)
	write(32*mib, mib, 0x22)
	at := nodeNow()

	l.mustLV(h, "replication", "schedule", "add", vm, "--cron", "* * * * *", "--target-pool", copiesPool,
		"--target-host", h, "--keep", "8", "--incremental")
	t.Cleanup(func() { l.lv(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool) })

	// 1. The first run: a full raw copy, and the data disk's own checkpoint.
	r1 := waitRun(at)
	if d := detailOf(r1.taken); !strings.Contains(d, "full") || filepath.Ext(r1.file) != ".raw" {
		t.Errorf("the first run of the data disk is not a full raw copy: %s (%s)", d, r1.file)
	}
	exact("first run", r1)
	cp1 := "lvrepl-data-" + r1.taken
	if cps := checkpoints(); !containsString(cps, cp1) {
		t.Fatalf("no checkpoint %s on %s after the first run (checkpoints %v)", cp1, vm, cps)
	}
	if info := l.mustSSH(h, 30*time.Second, "qemu-img info -U --output=json "+shellQuote(data)); !strings.Contains(info, cp1) {
		t.Errorf("the data disk carries no bitmap %s: %s", cp1, info)
	}

	// 2. Two incremental runs.
	at = write(8*mib, 2*mib, 0x33)
	r2 := waitRun(at)
	exact("second run", r2)
	at = write(48*mib, 512<<10, 0x44)
	write(size-mib, mib, 0x55)
	at = nodeNow()
	r3 := waitRun(at)
	exact("third run", r3)
	for _, r := range []replica{r2, r3} {
		if d := detailOf(r.taken); !strings.Contains(d, "incremental") {
			t.Errorf("the data disk's run %s was not incremental: %s", r.taken, d)
		}
	}
	if cps := checkpoints(); containsString(cps, cp1) || !containsString(cps, "lvrepl-data-"+r3.taken) {
		t.Errorf("checkpoints after the third run: %v, want lvrepl-data-%s and not the superseded %s", cps, r3.taken, cp1)
	}

	// 3. An unclean stop: the next run is not incremental, and exact.
	flush()
	restart(true)
	at = write(16*mib, mib, 0x66)
	rd := waitRun(at)
	if d := detailOf(rd.taken); strings.Contains(d, "incremental") {
		t.Errorf("the run after an unclean stop was incremental: %s", d)
	}
	exact("after an unclean stop", rd)
	// The chain is established again by the next run, whatever this one was.
	at = write(20*mib, mib, 0x67)
	exact("chain re-established", waitRun(at))

	// 4. A clean stop: the next run is incremental, and exact.
	restart(false)
	at = write(24*mib, mib, 0x77)
	rc := waitRun(at)
	if d := detailOf(rc.taken); !strings.Contains(d, "incremental") {
		t.Errorf("the run after a clean stop and start was not incremental: %s", d)
	}
	exact("after a clean restart", rc)

	// 5. A live detach and reattach of the same file.
	blk := l.mustSSH(h, 30*time.Second, "virsh domblklist "+shellQuote(vm)+" --details")
	target := ""
	for _, line := range strings.Split(blk, "\n") {
		if f := strings.Fields(line); len(f) == 4 && f[3] == data {
			target = f[2]
		}
	}
	if target == "" {
		t.Fatalf("no target for %s in %s", data, blk)
	}
	flush()
	l.mustSSH(h, time.Minute, fmt.Sprintf("virsh detach-disk %s %s --live", shellQuote(vm), target))
	time.Sleep(5 * time.Second)
	l.mustSSH(h, time.Minute, fmt.Sprintf("virsh attach-disk %s %s %s --live --driver qemu --subdriver qcow2 --targetbus virtio",
		shellQuote(vm), shellQuote(data), target))
	at = write(28*mib, mib, 0x88)
	exact("after a detach and reattach", waitRun(at))

	// 6. No more runs; the VM shut off cleanly; the disk and the newest
	// replica both equal the model.
	l.mustLV(h, "replication", "schedule", "rm", vm, "--target-pool", copiesPool)
	time.Sleep(75 * time.Second) // a run started before the removal finishes
	if out, err := l.lv(h, "stop", vm); err != nil {
		t.Fatalf("lv stop %s: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(h, vm, "shut off", 4*time.Minute) {
		t.Fatalf("%s did not shut off cleanly", vm)
	}
	want := sumOf(model)
	if got := sumOnNode(data, "qcow2"); got != want {
		t.Fatalf("the data disk (sha256 %s) is not the model of what was written (sha256 %s)", got, want)
	}
	runs := dataRuns()
	last := runs[len(runs)-1]
	exact("newest replica", last)

	// 7. A restore from that run reproduces the data disk exactly.
	rootReplica := strings.TrimSpace(l.mustSSH(h, 30*time.Second, "find "+shellQuote(replicaDir)+" -name 'root-"+last.taken+".*' ! -name '*.json' -printf '%f\\n' | head -1"))
	if rootReplica == "" {
		t.Fatalf("no root replica of run %s", last.taken)
	}
	t.Cleanup(func() { l.lv(h, "rm", promoted, "--force") })
	if out, err := l.lv(h, "replication", "promote", vm, "--replica", rootReplica, "--pool", copiesPool,
		"--host", h, "--new-name", promoted); err != nil {
		t.Fatalf("promote %s from %s: %v\n%s", vm, rootReplica, err, out)
	}
	l.lv(h, "stop", promoted)
	if !l.waitDomainState(h, promoted, "shut off", 4*time.Minute) {
		t.Fatalf("the promoted VM %s did not shut off cleanly", promoted)
	}
	rows = l.mustSQL(h, "SELECT path FROM vm_disks WHERE vm_name = '"+promoted+"' AND disk_name = 'data'")
	if len(rows) != 1 {
		t.Fatalf("the promoted VM %s has no data disk: rows %v", promoted, rows)
	}
	restoredFmt := "qcow2"
	if info := l.mustSSH(h, 30*time.Second, "qemu-img info -U --output=json "+shellQuote(rows[0][0])); strings.Contains(info, `"format": "raw"`) {
		restoredFmt = "raw"
	}
	if got := sumOnNode(rows[0][0], restoredFmt); got != want {
		t.Fatalf("the data disk restored from run %s (sha256 %s) is not the source (sha256 %s)", last.taken, got, want)
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
