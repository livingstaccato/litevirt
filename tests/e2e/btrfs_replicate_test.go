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
// "copies". A VM gets a blank data disk in "src" (standalone, a subvolume of
// its own) and a root disk there on the image (a qcow2 with a backing file).
// What is checked is read from the node itself with btrfs, stat and qemu-img,
// never from litevirt:
//
//   - the data disk is copied natively: the copy is a NEW file directly in
//     the copies pool's directory (where every copy is), standalone, with the
//     disk's bytes (the VM is stopped first);
//   - a second copy is another new file; a copy onto an existing name is
//     refused and leaves that file as it was;
//   - the root disk, on a base image, is NOT sent natively: its copy is the
//     flattened qemu-img copy, with no backing file;
//   - no staging subvolume, directory or file is left in either pool.
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
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      root:\n        size: \"1G\"\n        storage: %q\n      data:\n        size: \"64M\"\n        storage: %q\n    placement:\n      host: %s\n",
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
	diskPath := func(disk string) string {
		rows := l.mustSQL(h, "SELECT path FROM vm_disks WHERE vm_name = '"+vm+"' AND disk_name = '"+disk+"'")
		if len(rows) != 1 {
			t.Fatalf("%s disk of %s: rows %v", disk, vm, rows)
		}
		return rows[0][0]
	}
	data, root := diskPath("data"), diskPath("root")
	for _, d := range []string{data, root} {
		if filepath.Dir(filepath.Dir(d)) != srcDir {
			t.Fatalf("disk %s is not in a subvolume of its own under %s", d, srcDir)
		}
		l.mustSSH(h, 30*time.Second, "btrfs subvolume show "+shellQuote(filepath.Dir(d)))
	}
	if info := l.mustSSH(h, 30*time.Second, "qemu-img info -U "+shellQuote(data)); strings.Contains(info, "backing file:") {
		t.Fatalf("the data disk %s has a backing file:\n%s", data, info)
	}
	if info := l.mustSSH(h, 30*time.Second, "qemu-img info -U "+shellQuote(root)); !strings.Contains(info, "backing file:") {
		t.Skipf("the root disk %s has no backing file on this build; the flattening leg needs one:\n%s", root, info)
	}
	l.mustLV(h, "stop", vm)
	if !l.waitDomainState(h, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop (virsh)", vm)
	}

	replicate := func(disk string, extra ...string) (string, string, error) {
		out, err := l.lv(h, append([]string{"replicate-volume", vm, disk, copiesPool}, extra...)...)
		target := ""
		for _, line := range strings.Split(out, "\n") {
			if p, ok := strings.CutPrefix(strings.TrimSpace(line), "Target: "); ok {
				target = p
			}
		}
		return target, out, err
	}
	requireStandaloneCopy := func(target, of string) {
		t.Helper()
		if filepath.Dir(target) != copiesDir {
			t.Fatalf("copy at %q, want a file directly in %s", target, copiesDir)
		}
		if typ := strings.TrimSpace(l.mustSSH(h, 30*time.Second, "stat -c %F "+shellQuote(target))); typ != "regular file" {
			t.Errorf("copy %s is a %q, want a regular file", target, typ)
		}
		if info := l.mustSSH(h, 30*time.Second, "qemu-img info -U "+shellQuote(target)); strings.Contains(info, "backing file:") {
			t.Errorf("copy %s depends on another file:\n%s", target, info)
		}
		if out, err := l.ssh(h, 5*time.Minute, "qemu-img compare -U "+shellQuote(of)+" "+shellQuote(target)); err != nil {
			t.Errorf("copy %s differs from %s: %v\n%s", target, of, err, out)
		}
	}
	requireNoStaging := func() {
		t.Helper()
		if out := l.mustSSH(h, 30*time.Second, "ls -A "+srcDir+" "+copiesDir+"; btrfs subvolume list "+btrfsE2EMount); strings.Contains(out, ".litevirt-") {
			t.Errorf("staging left behind:\n%s", out)
		}
	}

	first, out, err := replicate("data")
	if err != nil {
		t.Fatalf("replicate-volume %s data %s: %v\n%s", vm, copiesPool, err, out)
	}
	if !strings.Contains(out, "native btrfs") {
		t.Errorf("the data disk's copy was not native:\n%s", out)
	}
	requireStandaloneCopy(first, data)
	requireNoStaging()
	l.mark("btrfs: native copy %s", first)

	second, out, err := replicate("data")
	if err != nil || second == first {
		t.Fatalf("second replicate-volume: %v (target %s, first %s)\n%s", err, second, first, out)
	}
	requireStandaloneCopy(second, data)
	requireStandaloneCopy(first, data)

	// An admin naming an existing copy: refused, and it is left as it was.
	before := l.mustSSH(h, 30*time.Second, "stat -c '%i %s %Y' "+shellQuote(first)+"; sha256sum "+shellQuote(first))
	if _, out, err := replicate("data", "--target-path", filepath.Base(first)); err == nil || !strings.Contains(out+err.Error(), "exist") {
		t.Errorf("copy onto existing %s: err %v\n%s, want AlreadyExists", first, err, out)
	}
	if after := l.mustSSH(h, 30*time.Second, "stat -c '%i %s %Y' "+shellQuote(first)+"; sha256sum "+shellQuote(first)); after != before {
		t.Errorf("the existing copy changed:\nbefore %s\nafter  %s", before, after)
	}

	// The root disk is on a base image: the flattening file copy, not a send.
	rootCopy, out, err := replicate("root")
	if err != nil {
		t.Fatalf("replicate-volume %s root: %v\n%s", vm, err, out)
	}
	if strings.Contains(out, "native") {
		t.Errorf("a disk on a base image was sent natively:\n%s", out)
	}
	requireStandaloneCopy(rootCopy, root)
	requireNoStaging()
	l.mark("btrfs: second copy %s, existing name refused, root flattened to %s", second, rootCopy)
}
