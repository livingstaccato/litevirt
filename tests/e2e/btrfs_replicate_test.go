package e2e

import (
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// lv replicate-volume of a btrfs disk into a btrfs pool, on the nested lab
// (E2E_LAB_DIR; skipped without it, and the whole suite skips without
// LITEVIRT_E2E=1). Skipped on a node without btrfs-progs.
//
// A loop-backed btrfs filesystem on one node holds two btrfs pools, "src" and
// "copies". A VM's root disk is created in "src" (a subvolume of its own), and
// is replicated into "copies". What is checked is read from the node itself
// with btrfs and qemu-img, never from litevirt: the copy is a NEW, writable
// subvolume directly under the copies pool holding exactly the disk file, its
// bytes are the source's (the VM is stopped first), a second copy is another
// new subvolume, a copy onto an existing name is refused and leaves that name
// as it was, and no staging subvolume or directory is left in either pool.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_BtrfsNativeReplicate -v -timeout 30m

const btrfsE2EMount = "/srv/lv-e2e-btrfs"

func TestLab_BtrfsNativeReplicate(t *testing.T) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]
	if out, err := l.ssh(h, 20*time.Second, "command -v btrfs && command -v mkfs.btrfs"); err != nil {
		t.Skipf("%s has no btrfs-progs: %s", h, strings.TrimSpace(out))
	}

	img := "/var/tmp/lv-e2e-btrfs.img"
	srcDir, copiesDir := btrfsE2EMount+"/src", btrfsE2EMount+"/copies"
	l.mustSSH(h, 2*time.Minute, fmt.Sprintf(
		"umount %[1]s 2>/dev/null; rm -f %[2]s && truncate -s 3G %[2]s && mkfs.btrfs -q -f %[2]s && mkdir -p %[1]s && mount -o loop %[2]s %[1]s && mkdir %[3]s %[4]s",
		btrfsE2EMount, img, srcDir, copiesDir))
	t.Cleanup(func() { l.ssh(h, 60*time.Second, fmt.Sprintf("umount %s; rm -f %s", btrfsE2EMount, img)) })

	suffix := strings.TrimPrefix(uniqueName("btr"), "e2e-")
	srcPool, copiesPool := "btrsrc-"+suffix, "btrcopies-"+suffix
	for pool, dir := range map[string]string{srcPool: srcDir, copiesPool: copiesDir} {
		l.mustLV(h, "pool", "create", pool, "--driver", "btrfs", "--source", dir, "--host", h)
		pool := pool
		t.Cleanup(func() { l.lv(h, "pool", "delete", pool, "--host", h, "--force") })
	}

	stack := uniqueName("btrrep")
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
	disk := rows[0][0]
	sub := filepath.Dir(disk)
	if filepath.Dir(sub) != srcDir {
		t.Fatalf("root disk %s is not in a subvolume of its own under %s", disk, srcDir)
	}
	l.mustSSH(h, 30*time.Second, "btrfs subvolume show "+shellQuote(sub))
	l.mustLV(h, "stop", vm)
	if !l.waitDomainState(h, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop (virsh)", vm)
	}

	replicate := func(extra ...string) (string, string, error) {
		out, err := l.lv(h, append([]string{"replicate-volume", vm, "root", copiesPool}, extra...)...)
		target := ""
		for _, line := range strings.Split(out, "\n") {
			if p, ok := strings.CutPrefix(strings.TrimSpace(line), "Target: "); ok {
				target = p
			}
		}
		return target, out, err
	}
	requireCopy := func(target string) {
		t.Helper()
		copySub := filepath.Dir(target)
		if filepath.Dir(copySub) != copiesDir || filepath.Base(target) != filepath.Base(disk) {
			t.Fatalf("copy at %q, want <%s>/<new subvolume>/%s", target, copiesDir, filepath.Base(disk))
		}
		l.mustSSH(h, 30*time.Second, "btrfs subvolume show "+shellQuote(copySub))
		if ro := l.mustSSH(h, 30*time.Second, "btrfs property get -ts "+shellQuote(copySub)+" ro"); !strings.Contains(ro, "ro=false") {
			t.Errorf("copy subvolume %s: %s, want a writable copy", copySub, strings.TrimSpace(ro))
		}
		if ls := strings.TrimSpace(l.mustSSH(h, 30*time.Second, "ls -A "+shellQuote(copySub))); ls != filepath.Base(disk) {
			t.Errorf("copy subvolume holds %q, want only %s", ls, filepath.Base(disk))
		}
		if out, err := l.ssh(h, 5*time.Minute, "qemu-img compare -U "+shellQuote(disk)+" "+shellQuote(target)); err != nil {
			t.Errorf("copy %s differs from %s: %v\n%s", target, disk, err, out)
		}
	}
	requireNoStaging := func() {
		t.Helper()
		if out := l.mustSSH(h, 30*time.Second, "ls -A "+srcDir+" "+copiesDir+"; btrfs subvolume list "+btrfsE2EMount); strings.Contains(out, ".litevirt-") {
			t.Errorf("staging left behind:\n%s", out)
		}
	}

	first, out, err := replicate()
	if err != nil {
		t.Fatalf("replicate-volume %s root %s: %v\n%s", vm, copiesPool, err, out)
	}
	if !strings.Contains(out, "native") {
		t.Errorf("replicate-volume did not report a native copy:\n%s", out)
	}
	requireCopy(first)
	requireNoStaging()
	l.mark("btrfs: native copy %s", first)

	second, out, err := replicate()
	if err != nil {
		t.Fatalf("second replicate-volume: %v\n%s", err, out)
	}
	if filepath.Dir(second) == filepath.Dir(first) {
		t.Fatalf("second copy %s reused the first's subvolume", second)
	}
	requireCopy(second)
	requireCopy(first)

	// An admin naming an existing subvolume: refused, and it is left as it was.
	taken := filepath.Base(filepath.Dir(first))
	before := l.mustSSH(h, 30*time.Second, "btrfs subvolume show "+shellQuote(filepath.Dir(first))+" | grep -i uuid; sha256sum "+shellQuote(first))
	if _, out, err := replicate("--target-path", taken); err == nil || !strings.Contains(out+err.Error(), "exist") {
		t.Errorf("copy onto existing subvolume %s: err %v\n%s, want AlreadyExists", taken, err, out)
	}
	if after := l.mustSSH(h, 30*time.Second, "btrfs subvolume show "+shellQuote(filepath.Dir(first))+" | grep -i uuid; sha256sum "+shellQuote(first)); after != before {
		t.Errorf("the existing copy changed:\nbefore %s\nafter  %s", before, after)
	}
	requireNoStaging()
	l.mark("btrfs: second copy %s, existing name refused", second)
}
