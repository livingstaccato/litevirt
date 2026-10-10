package e2e

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Backup compression and bandwidth limits on a real node, against a real
// qcow2 disk. What is checked is read from the node — repo.json, the chunk
// files' sizes with du, cmp of the restored file against the disk — never
// from litevirt's own report of what it did.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_Backup -v -timeout 30m

var (
	bkDoneRE    = regexp.MustCompile(`\[done\] manifest=(\S+) chunks=\d+ bytes=(\d+)`)
	bkRestoreRE = regexp.MustCompile(`restored to (\S+)`)
)

// bkStoppedVM creates one small VM and stops it, so a backup reads its disk
// file — a fixed set of bytes cmp can compare a restore against.
func bkStoppedVM(l *lab, prefix string) (host, vm, disk string) {
	l.t.Helper()
	host = labUpHosts(l, 1)[0]
	vm = l.createVMs(host, prefix, host)[host]
	disk = snapActiveDisk(l, host, vm)
	l.mustLV(host, "stop", vm)
	deadline := time.Now().Add(2 * time.Minute)
	for snapDomState(l, host, vm) != "shut off" {
		if time.Now().After(deadline) {
			l.t.Fatalf("%s did not stop", vm)
		}
		time.Sleep(2 * time.Second)
	}
	return host, vm, disk
}

func bkRepo(l *lab, host, name string, initArgs ...string) string {
	l.t.Helper()
	dir := fmt.Sprintf("/var/tmp/%s-%d", name, time.Now().UnixNano())
	l.mustLV(host, append([]string{"backup", "repo", "init", dir}, initArgs...)...)
	l.onRestore(func() { _, _ = l.ssh(host, time.Minute, "rm -rf "+shellQuote(dir)) })
	return dir
}

// bkSnapshot backs vm up into repo and returns the manifest timestamp, the
// bytes it covered and the wall time.
func bkSnapshot(l *lab, host, vm, repo string, extra ...string) (ts string, bytes int64, took time.Duration) {
	l.t.Helper()
	start := time.Now()
	out := l.mustLV(host, append([]string{"backup", "snapshot", vm, "--repo", repo, "--quiesce", "off"}, extra...)...)
	took = time.Since(start)
	m := bkDoneRE.FindStringSubmatch(out)
	if m == nil {
		l.t.Fatalf("backup of %s printed no [done] line:\n%s", vm, out)
	}
	n, _ := strconv.ParseInt(m[2], 10, 64)
	return m[1], n, took
}

// A compressed repo is marked so older releases refuse it, its chunk files
// are smaller than the bytes they hold, and a restore reproduces the disk
// byte for byte.
func TestLab_BackupCompression_RoundTripAndOnDiskSize(t *testing.T) {
	l := newLab(t)
	host, vm, disk := bkStoppedVM(l, "bkz")
	repo := bkRepo(l, host, "e2e-bkz")

	meta := l.mustSSH(host, 30*time.Second, "cat "+shellQuote(repo+"/repo.json"))
	if !strings.Contains(meta, `"compression": "zstd"`) || !strings.Contains(meta, `"schema_version": 2`) {
		t.Fatalf("a default repo is not marked compressed / schema 2:\n%s", meta)
	}

	ts, covered, _ := bkSnapshot(l, host, vm, repo)
	onDisk, err := strconv.ParseInt(strings.Fields(l.mustSSH(host, time.Minute,
		"du -sb --apparent-size "+shellQuote(repo+"/chunks")))[0], 10, 64)
	if err != nil {
		t.Fatalf("du: %v", err)
	}
	l.saveEvidence("bkz-sizes", fmt.Sprintf("covered=%d chunks_on_disk=%d", covered, onDisk))
	if onDisk >= covered {
		t.Fatalf("chunks take %d bytes on disk for %d bytes backed up: nothing was compressed", onDisk, covered)
	}

	out := l.mustLV(host, "backup", "restore-from", "--repo", repo, "--vm", vm, "--disk", "root", "--timestamp", ts)
	m := bkRestoreRE.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("restore printed no target:\n%s", out)
	}
	l.onRestore(func() { _, _ = l.ssh(host, time.Minute, "rm -f "+shellQuote(m[1])) })
	// A stopped VM's backup is its disk file; the restore writes it back as-is.
	if res, err := l.ssh(host, 5*time.Minute, "cmp "+shellQuote(disk)+" "+shellQuote(m[1])+" && echo SAME"); err != nil || !strings.Contains(res, "SAME") {
		t.Fatalf("restored file differs from %s: %v\n%s", disk, err, res)
	}
}

// --compression none keeps the format earlier releases read: schema 1, and
// chunk files that are the bytes themselves.
func TestLab_BackupCompression_NoneIsTheOldFormat(t *testing.T) {
	l := newLab(t)
	host, vm, _ := bkStoppedVM(l, "bkn")
	repo := bkRepo(l, host, "e2e-bkn", "--compression", "none")
	meta := l.mustSSH(host, 30*time.Second, "cat "+shellQuote(repo+"/repo.json"))
	if strings.Contains(meta, "compression") || !strings.Contains(meta, `"schema_version": 1`) {
		t.Fatalf("--compression none wrote:\n%s", meta)
	}
	bkSnapshot(l, host, vm, repo)
	// Every chunk file's bytes hash to its own name (b3sum, when present).
	if out, err := l.ssh(host, 5*time.Minute,
		`command -v b3sum >/dev/null || { echo NOB3; exit 0; }; cd `+shellQuote(repo+"/chunks")+
			` && for f in */*; do [ "$(b3sum --no-names "$f")" = "$(basename "$f")" ] || echo "BAD $f"; done; echo DONE`); err != nil {
		t.Fatalf("checking chunks: %v\n%s", err, out)
	} else if strings.Contains(out, "BAD") {
		t.Fatalf("an uncompressed repo holds a chunk that is not its plaintext:\n%s", out)
	}
}

// A bandwidth limit holds a backup to its rate: the bytes read divided by
// the limit is a floor on the wall time.
func TestLab_BackupBWLimit_HoldsTheRate(t *testing.T) {
	l := newLab(t)
	host, vm, _ := bkStoppedVM(l, "bkbw")
	repo := bkRepo(l, host, "e2e-bkbw")
	const rate = 4 << 20 // 4 MiB/s
	_, covered, took := bkSnapshot(l, host, vm, repo, "--bwlimit", "4MiB")
	floor := time.Duration(float64(covered) / rate * float64(time.Second))
	l.saveEvidence("bkbw", fmt.Sprintf("covered=%d took=%v floor=%v", covered, took, floor))
	if covered < 8<<20 {
		t.Skipf("the disk backed up only %d bytes; too little to time a 4 MiB/s limit", covered)
	}
	if took < floor*9/10 {
		t.Fatalf("backup of %d bytes at --bwlimit 4MiB took %v, under the %v the limit allows", covered, took, floor)
	}
}
