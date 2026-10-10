package e2e

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// VM disks on a litevirt `ceph` pool whose nodes hold ONLY a restricted client
// key (`profile rbd pool=<pool>`, no admin keyring anywhere), on the nested lab
// (E2E_LAB_DIR; the whole suite skips without LITEVIRT_E2E=1). Lab 2 B6.
//
// Needs a ceph pool already created on at least two up nodes (lab 2:
// `ONLY=ceph tools/litevirt-pools.sh`). Everything checked is read from the
// nodes with virsh and rbd, never from litevirt:
//
//   - a root disk from an image is an rbd clone of the image's imported,
//     protected base, and a data disk is an rbd image of the size asked for;
//   - the domain opens them as the restricted client through a libvirt ceph
//     secret (<auth username=…><secret type='ceph' uuid=…/>), with <host>
//     monitors, and the secret is private (its value cannot be read back);
//   - the VM boots, live-migrates to a second node (whose libvirt holds the
//     same secret), and is still running there;
//   - a clone is an rbd copy in the pool, cloned from the same base;
//   - delete removes every VM image and keeps the base;
//   - a create that fails after its ceph disk exists (proven from the daemon
//     log) leaves no image behind.
//
// Run it with:
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	E2E_CEPH_POOL=ceph E2E_CEPH_ID=litevirt \
//	  go test ./tests/e2e/ -run TestLab_CephVMDisks -v -timeout 40m
func TestLab_CephVMDisks(t *testing.T) {
	l := newLab(t)
	up := labUpHosts(l, 2)
	pool, client := envOr("E2E_CEPH_POOL", "ceph"), envOr("E2E_CEPH_ID", "litevirt")

	// The pool on two nodes, and its rbd pool name.
	var hosts []string
	rbdPool := ""
	for _, h := range up {
		rows, err := l.sql(h, fmt.Sprintf("SELECT source FROM storage_pools WHERE host_name = '%s' AND name = '%s' AND driver = 'ceph' AND deleted_at IS NULL", h, pool))
		if err != nil || len(rows) != 1 {
			continue
		}
		rbdPool = rows[0][0]
		hosts = append(hosts, h)
	}
	if len(hosts) < 2 {
		t.Skipf("ceph pool %q is not on two up nodes (found on %v)", pool, hosts)
	}
	src, dst := hosts[0], hosts[1]
	rbd := func(h, args string) (string, error) {
		return l.ssh(h, 60*time.Second, "rbd --id "+shellQuote(client)+" "+args)
	}
	// Only the restricted key: no admin keyring on either node.
	for _, h := range []string{src, dst} {
		if out, err := l.ssh(h, 20*time.Second, "ls /etc/ceph/; test ! -e /etc/ceph/ceph.client.admin.keyring && test ! -e /etc/ceph/ceph.keyring && test ! -e /etc/ceph/keyring"); err != nil {
			t.Fatalf("%s holds an admin keyring; this test proves the restricted key alone works:\n%s", h, out)
		}
	}

	stack := uniqueName("cephvm")
	vm := stack + "-1"
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      root:\n        size: \"1G\"\n        storage: %q\n      data:\n        size: \"64M\"\n        storage: %q\n    placement:\n      host: %s\n",
		stack, vm, drillImage(), drillMemory(), pool, pool, src)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(src, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	clone := stack + "-copy"
	t.Cleanup(func() {
		l.lv(src, "rm", "--force", clone)
		l.deleteVMs(stack, map[string]string{src: vm})
	})
	if out, err := l.lv(src, "compose", "up", "-f", file, "-y"); err != nil {
		t.Fatalf("compose up %s: %v\n%s", stack, err, out)
	}
	if !l.waitDomainState(src, vm, "running", 5*time.Minute) {
		t.Fatalf("%s never ran on %s (virsh)", vm, src)
	}
	l.mark("ceph: %s running on %s", vm, src)

	// The images, read from the cluster.
	rootImg, dataImg := rbdPool+"/"+vm+"-root", rbdPool+"/"+vm+"-data"
	rootInfo, err := rbd(src, "info "+shellQuote(rootImg))
	if err != nil {
		t.Fatalf("rbd info %s: %v\n%s", rootImg, err, rootInfo)
	}
	parent := regexp.MustCompile(`parent: (\S+@base)`).FindStringSubmatch(rootInfo)
	if parent == nil || !strings.Contains(parent[1], "/lvimage+") {
		t.Fatalf("root disk %s is not a clone of an imported base:\n%s", rootImg, rootInfo)
	}
	base := parent[1]
	if out, err := rbd(src, "snap ls --all "+shellQuote(strings.TrimSuffix(base, "@base"))); err != nil || !strings.Contains(out, "base") {
		t.Fatalf("base snapshot %s: %v\n%s", base, err, out)
	}
	if out, err := rbd(src, "info --format json "+shellQuote(dataImg)); err != nil || !strings.Contains(out, `"size":67108864`) {
		t.Fatalf("data disk %s is not 64 MiB: %v\n%s", dataImg, err, out)
	}

	// The domain authenticates through a private libvirt ceph secret.
	secretOf := func(h string) string {
		t.Helper()
		x := l.mustSSH(h, 30*time.Second, "virsh -c qemu:///system dumpxml "+shellQuote(vm))
		for _, want := range []string{"protocol='rbd'", "<auth username='" + client + "'>", "<host name="} {
			if !strings.Contains(x, want) {
				t.Fatalf("domain %s on %s lacks %s:\n%s", vm, h, want, x)
			}
		}
		for _, never := range []string{"keyring", "client.admin"} {
			if strings.Contains(x, never) {
				t.Fatalf("domain %s on %s names %q:\n%s", vm, h, never, x)
			}
		}
		m := regexp.MustCompile(`<secret type='ceph' uuid='([0-9a-f-]+)'/>`).FindStringSubmatch(x)
		if m == nil {
			t.Fatalf("domain %s on %s names no ceph secret:\n%s", vm, h, x)
		}
		if out := l.mustSSH(h, 30*time.Second, "virsh -c qemu:///system secret-list"); !strings.Contains(out, m[1]) {
			t.Fatalf("secret %s is not defined on %s:\n%s", m[1], h, out)
		}
		if out, err := l.ssh(h, 30*time.Second, "virsh -c qemu:///system secret-get-value "+m[1]); err == nil {
			t.Fatalf("secret %s on %s is readable (not private): %d bytes", m[1], h, len(out))
		}
		return m[1]
	}
	secret := secretOf(src)

	// Live migration: the target opens the same disks through the same secret.
	if out, err := l.lv(src, "migrate", vm, dst); err != nil {
		t.Fatalf("lv migrate %s %s: %v\n%s", vm, dst, err, out)
	}
	if !l.waitDomainState(dst, vm, "running", 5*time.Minute) {
		t.Fatalf("%s is not running on %s after the live migration (virsh)", vm, dst)
	}
	if got := secretOf(dst); got != secret {
		t.Fatalf("the target names secret %s, the source %s", got, secret)
	}
	l.mark("ceph: %s live-migrated to %s", vm, dst)

	// Clone: an rbd copy in the pool, of the same base.
	l.mustLV(dst, "stop", vm)
	if !l.waitDomainState(dst, vm, "shut off", 3*time.Minute) {
		t.Fatalf("%s did not stop (virsh)", vm)
	}
	if out, err := l.lv(dst, "clone", vm, clone); err != nil {
		t.Fatalf("lv clone %s %s: %v\n%s", vm, clone, err, out)
	}
	cloneRoot := rbdPool + "/" + clone + "-root"
	if out, err := rbd(dst, "info "+shellQuote(cloneRoot)); err != nil || !strings.Contains(out, "parent: "+base) {
		t.Fatalf("clone root %s is not a clone of %s: %v\n%s", cloneRoot, base, err, out)
	}
	if out, err := rbd(dst, "info "+shellQuote(rbdPool+"/"+clone+"-data")); err != nil {
		t.Fatalf("clone data disk: %v\n%s", err, out)
	}
	l.mark("ceph: cloned %s → %s", vm, clone)

	// Delete: every VM image goes, the base stays.
	if out, err := l.lv(dst, "rm", "--force", clone); err != nil {
		t.Fatalf("lv rm %s: %v\n%s", clone, err, out)
	}
	l.deleteVMs(stack, map[string]string{src: vm})
	deadline := time.Now().Add(2 * time.Minute)
	for {
		ls, err := rbd(src, "ls "+shellQuote(rbdPool))
		if err != nil {
			t.Fatalf("rbd ls: %v\n%s", err, ls)
		}
		left := []string{}
		for _, img := range strings.Fields(ls) {
			if strings.HasPrefix(img, vm+"-") || strings.HasPrefix(img, clone+"-") {
				left = append(left, img)
			}
		}
		if len(left) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("images left after delete: %v", left)
		}
		time.Sleep(5 * time.Second)
	}
	if out, err := rbd(src, "info "+shellQuote(base)); err != nil {
		t.Fatalf("the base %s was removed with the VMs: %v\n%s", base, err, out)
	}

	// A create that fails AFTER its ceph disk exists removes it. The second
	// disk names a pool that exists in the cluster — a throwaway dir pool on
	// dst only — so compose's cluster-wide storage check passes, and CreateVM
	// on src fails resolving it there (resolveVolume: "… storage pool on host
	// …") once the ceph disk has been made: compose creates disks in name
	// order (sortedKeys), "data" before "zz". The daemon log on src proves the
	// image was created, so the "nothing left" check is not vacuous.
	badStack := stack + "-bad"
	bad := badStack + "-1"
	elsewhere := "cephnohere-" + strings.TrimPrefix(stack, "e2e-")
	elsewhereDir := "/var/tmp/" + elsewhere
	l.mustSSH(dst, 30*time.Second, "mkdir -p "+shellQuote(elsewhereDir))
	l.mustLV(dst, "pool", "create", elsewhere, "--driver", "dir", "--target", elsewhereDir, "--host", dst)
	t.Cleanup(func() {
		l.lv(dst, "pool", "delete", elsewhere, "--host", dst, "--force")
		l.ssh(dst, 30*time.Second, "rmdir "+shellQuote(elsewhereDir))
	})
	badYAML := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      data:\n        size: \"64M\"\n        storage: %q\n      zz:\n        size: \"64M\"\n        storage: %q\n    placement:\n      host: %s\n",
		badStack, bad, drillImage(), drillMemory(), pool, elsewhere, src)
	badFile := "/tmp/" + badStack + ".yaml"
	l.mustSSH(src, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(badYAML))+" | base64 -d > "+badFile)
	t.Cleanup(func() { l.deleteVMs(badStack, map[string]string{src: bad}) })
	since := l.nodeNow(src)
	out, err := l.lv(src, "compose", "up", "-f", badFile, "-y")
	if err == nil {
		t.Fatalf("a create with a disk on a pool %s does not have succeeded:\n%s", src, out)
	}
	if !strings.Contains(out+err.Error(), "storage pool on host") {
		t.Fatalf("the create did not fail resolving the second disk on %s (so no ceph disk was made first):\n%v\n%s", src, err, out)
	}
	if made := l.journalSince(src, since, "Ceph RBD disk created.*"+bad+"-data"); !strings.Contains(made, bad+"-data") {
		t.Fatalf("the daemon on %s never created %s-data, so the cleanup was not exercised", src, bad)
	}
	if ls, _ := rbd(src, "ls "+shellQuote(rbdPool)); strings.Contains(ls, bad+"-") {
		t.Fatalf("the failed create left an image behind:\n%s", ls)
	}
	l.mark("ceph: done")
}
