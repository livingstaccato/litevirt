package e2e

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/tests/e2e/pitprobe"
)

// A replication schedule's --bwlimit paces a real cross-host run on the nested
// lab (E2E_LAB_DIR; skipped without it, and the whole suite skips without
// LITEVIRT_E2E=1). A stopped VM's 2 GiB root disk is filled on the node with
// qemu-io (no zero clusters), so a full replica sends about 2 GiB. Scheduled
// every minute into a pool on a second node:
//
//  1. at --bwlimit 20MiB the run takes at least ~100 s (2 GiB / 20 MiB/s),
//     measured from the run's scheduled time (backup_schedules.last_run_at)
//     to its disk.replicated event, both read from the node's database;
//     `lv replication schedule ls` shows the rate;
//
//  2. re-added without --bwlimit, the stored limit stays (ls still shows it);
//
//  3. at --bwlimit 0 the limit is gone (ls shows "-") and the next run is
//     faster than half the limited one;
//
//  4. `lv replication schedule rm` clears the stored rate record.
//
//     LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//     go test ./tests/e2e/ -run TestReplicationRate_BwlimitPacesAScheduledRun -v -timeout 30m
func TestReplicationRate_BwlimitPacesAScheduledRun(t *testing.T) {
	l := newLab(t)
	up := labUpHosts(l, 2)
	h, tgt := up[0], up[1]
	if out, err := l.ssh(h, 20*time.Second, "command -v qemu-io"); err != nil {
		t.Skipf("%s has no qemu-io: %s", h, strings.TrimSpace(out))
	}

	suffix := strings.TrimPrefix(uniqueName("rr"), "e2e-")
	srcPool, dstPool := "rrsrc-"+suffix, "rrdst-"+suffix
	srcDir, dstDir := "/var/lib/litevirt/pools/"+srcPool, "/var/lib/litevirt/pools/"+dstPool
	for _, p := range []struct{ pool, dir, host string }{{srcPool, srcDir, h}, {dstPool, dstDir, tgt}} {
		l.mustSSH(p.host, 30*time.Second, "mkdir -p "+shellQuote(p.dir))
		l.mustLV(h, pitprobe.DirPoolCreateArgs(p.pool, p.dir, p.host)...)
		p := p
		t.Cleanup(func() {
			l.lv(h, "pool", "delete", p.pool, "--host", p.host, "--force")
			l.ssh(p.host, 60*time.Second, "rm -rf "+shellQuote(p.dir))
		})
	}

	stack := uniqueName("rrate")
	vm := stack + "-1"
	t.Cleanup(func() { l.ssh(h, 30*time.Second, "rm -f /tmp/"+stack+".yaml") })
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      root:\n        size: \"2G\"\n        storage: %q\n    placement:\n      host: %s\n",
		stack, vm, drillImage(), drillMemory(), srcPool, h)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(h, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	t.Cleanup(func() { l.deleteVMs(stack, map[string]string{h: vm}) })
	if out, err := l.lv(h, "compose", "up", "-f", file, "-y"); err != nil {
		t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	l.mustLV(h, "stop", vm)
	if !l.waitDomainState(h, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop on %s (virsh)", vm, h)
	}
	rows := l.mustSQL(h, "SELECT path FROM vm_disks WHERE vm_name = '"+vm+"' AND disk_name = 'root'")
	if len(rows) != 1 {
		t.Fatalf("root disk of %s: rows %v", vm, rows)
	}
	root := rows[0][0]
	// The whole 2G disk, in two 1G writes: qemu-io refuses one write longer
	// than 2147483136 bytes ("length cannot exceed ... without -n").
	if out, err := l.ssh(h, 10*time.Minute, "qemu-io -f qcow2 -c 'write -P 0x5a 0 1G' -c 'write -P 0x5a 1G 1G' "+shellQuote(root)); err != nil || strings.Count(out, "wrote") != 2 {
		t.Fatalf("fill %s with qemu-io: %v\n%s", root, err, out)
	}

	add := func(extra ...string) {
		t.Helper()
		args := append([]string{"replication", "schedule", "add", vm, "--cron", "* * * * *",
			"--target-pool", dstPool, "--target-host", tgt, "--keep", "1"}, extra...)
		l.mustLV(h, args...)
	}
	rateShown := func() string {
		t.Helper()
		out := l.mustLV(h, "replication", "schedule", "ls")
		lines := strings.Split(out, "\n")
		if len(lines) == 0 {
			t.Fatalf("schedule ls printed nothing")
		}
		// Locate RATE by its position among the header's whitespace fields;
		// no column before it holds a space, so rows split the same way.
		idx := -1
		for i, f := range strings.Fields(lines[0]) {
			if f == "RATE" {
				idx = i
			}
		}
		if idx < 0 {
			t.Fatalf("schedule ls has no RATE column:\n%s", out)
		}
		for _, line := range lines[1:] {
			if f := strings.Fields(line); len(f) > idx && f[0] == vm {
				return f[idx]
			}
		}
		t.Fatalf("schedule ls has no row for %s:\n%s", vm, out)
		return ""
	}
	// runAfter waits for the first run that starts after since and returns
	// how long it took: from its scheduled time to its disk.replicated event.
	runAfter := func(what string, since time.Time) time.Duration {
		t.Helper()
		deadline := time.Now().Add(8 * time.Minute)
		for time.Now().Before(deadline) {
			time.Sleep(10 * time.Second)
			sr := l.mustSQL(h, "SELECT last_run_at, last_run_err FROM backup_schedules WHERE vm_name = '"+vm+"' AND repo = '"+dstPool+"' AND deleted_at IS NULL")
			if len(sr) != 1 || sr[0][0] == "" {
				continue
			}
			start, err := time.Parse(time.RFC3339, sr[0][0])
			if err != nil || !start.After(since) {
				continue
			}
			if sr[0][1] != "" {
				t.Fatalf("%s: the run at %s failed: %s", what, sr[0][0], sr[0][1])
			}
			ev := l.mustSQL(h, "SELECT ts FROM vm_events WHERE vm_name = '"+vm+"' AND type = 'disk.replicated' AND result = 'ok' AND ts > '"+start.UTC().Format(time.RFC3339)+"' ORDER BY ts ASC LIMIT 1")
			if len(ev) != 1 {
				continue
			}
			end, err := time.Parse(time.RFC3339Nano, ev[0][0])
			if err != nil {
				t.Fatalf("%s: event ts %q: %v", what, ev[0][0], err)
			}
			d := end.Sub(start)
			l.mark("%s: run at %s took %s", what, start.Format(time.RFC3339), d)
			return d
		}
		t.Fatalf("%s: no completed run after %s", what, since.Format(time.RFC3339))
		return 0
	}
	nodeNow := func() time.Time {
		t.Helper()
		ts, err := time.Parse(time.RFC3339, strings.TrimSpace(l.mustSSH(h, 20*time.Second, "date -u +%Y-%m-%dT%H:%M:%SZ")))
		if err != nil {
			t.Fatal(err)
		}
		return ts
	}

	// 1. Limited.
	add("--bwlimit", "20MiB")
	t.Cleanup(func() { l.lv(h, "replication", "schedule", "rm", vm, "--target-pool", dstPool) })
	if r := rateShown(); r != "20MiB/s" {
		t.Fatalf("ls RATE = %q, want 20MiB/s", r)
	}
	limited := runAfter("limited", nodeNow())
	if limited < 90*time.Second {
		t.Errorf("a 2 GiB full replica at 20MiB/s took %s, want about 100 s or more", limited)
	}

	// 2. Re-added without --bwlimit: the limit stays.
	add()
	if r := rateShown(); r != "20MiB/s" {
		t.Errorf("after a re-add without --bwlimit, ls RATE = %q, want the stored 20MiB/s", r)
	}

	// 3. Cleared: faster.
	add("--bwlimit", "0")
	if r := rateShown(); r != "-" {
		t.Errorf("after --bwlimit 0, ls RATE = %q, want -", r)
	}
	unlimited := runAfter("unlimited", nodeNow())
	if unlimited*2 > limited {
		t.Errorf("unlimited run took %s, limited %s: the limit did not pace the run", unlimited, limited)
	}

	// 4. Removing the schedule clears the stored record (it was already
	// cleared by step 3; set it again first so the delete has one to clear).
	add("--bwlimit", "20MiB")
	l.mustLV(h, "replication", "schedule", "rm", vm, "--target-pool", dstPool)
	key := "replication_rate/" + vm + "/" + dstPool
	if rr := l.mustSQL(h, "SELECT count(*), quote(value) FROM cluster_policies WHERE key = '"+key+"' AND value = ''"); len(rr) != 1 || rr[0][0] != "1" {
		t.Errorf("after schedule rm, the rate record %s = %v, want one cleared row", key, rr)
	}
}
