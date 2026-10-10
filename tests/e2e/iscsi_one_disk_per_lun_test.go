package e2e

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// One iSCSI LUN, one disk, on the nested lab (E2E_LAB_DIR; skipped without it,
// and the whole suite skips without LITEVIRT_E2E=1).
//
// The first node serves an iSCSI target with two 512 MiB LUNs (LIO, through
// targetcli; skipped on a node without it). Both nodes get a pool per LUN
// (open-iscsi's iscsiadm logs them in; skipped without it). Then:
//
//   - VM A on node 1 takes LUN 0: virsh on node 1 shows the domain's disk is
//     that LUN's /dev/disk/by-path device, and the device exists there;
//   - VM B on node 2 with a disk on LUN 0 is REFUSED, naming VM A — and virsh
//     on node 2 shows no domain B was defined;
//   - VM B on node 2 with its ROOT disk on LUN 1, built on the image, runs,
//     and LUN 1's boot sector is the image's (the image was written onto it);
//   - no shared_lun health condition stands.
//
// It needs a build where the iscsi_lun_claim release feature can open (this
// branch merged with feat/release-token, the daemon wiring
// Server.SetReleaseFeatureGate) and an adopted voter generation: without
// either, every iscsi create is refused and the first deploy fails saying so.
//
// Run it with:
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_ISCSIOneDiskPerLUN -v -timeout 30m
func TestLab_ISCSIOneDiskPerLUN(t *testing.T) {
	l := newLab(t)
	up := labUpHosts(l, 2)
	h1, h2 := up[0], up[1]
	for _, h := range []string{h1, h2} {
		if out, err := l.ssh(h, 20*time.Second, "command -v iscsiadm"); err != nil {
			t.Skipf("%s has no iscsiadm (open-iscsi): %s", h, strings.TrimSpace(out))
		}
	}
	if out, err := l.ssh(h1, 20*time.Second, "command -v targetcli"); err != nil {
		t.Skipf("%s has no targetcli to serve a test target: %s", h1, strings.TrimSpace(out))
	}
	addr := l.mustSQL(h1, "SELECT address FROM hosts WHERE name = '"+h1+"' AND deleted_at IS NULL")
	if len(addr) != 1 || addr[0][0] == "" {
		t.Fatalf("no address for %s: %v", h1, addr)
	}
	// With the port: udev names the device ip-<addr>:3260-iscsi-..., and the
	// pool's portal option is what the disk path is spelled from.
	portal := addr[0][0] + ":3260"

	suffix := strings.TrimPrefix(uniqueName("lun"), "e2e-")
	iqn := "iqn.2026-10.io.litevirt:e2e-" + suffix
	var setup []string
	for i := 0; i < 2; i++ {
		setup = append(setup,
			fmt.Sprintf("targetcli /backstores/fileio create lve2e-%[1]s-%[2]d /var/tmp/lve2e-%[1]s-%[2]d.img 512M", suffix, i))
	}
	setup = append(setup, "targetcli /iscsi create "+iqn)
	for i := 0; i < 2; i++ {
		setup = append(setup, fmt.Sprintf("targetcli /iscsi/%s/tpg1/luns create /backstores/fileio/lve2e-%s-%d", iqn, suffix, i))
	}
	setup = append(setup, "targetcli /iscsi/"+iqn+"/tpg1 set attribute generate_node_acls=1 demo_mode_write_protect=0 authentication=0 cache_dynamic_acls=1")
	l.mustSSH(h1, 2*time.Minute, strings.Join(setup, " && "))
	t.Cleanup(func() {
		l.ssh(h1, time.Minute, fmt.Sprintf(
			"targetcli /iscsi delete %[1]s; for i in 0 1; do targetcli /backstores/fileio delete lve2e-%[2]s-$i; rm -f /var/tmp/lve2e-%[2]s-$i.img; done",
			iqn, suffix))
	})

	pool := func(lun int) string { return fmt.Sprintf("lun%d-%s", lun, suffix) }
	for _, h := range []string{h1, h2} {
		for lun := 0; lun < 2; lun++ {
			l.mustLV(h, "pool", "create", pool(lun), "--driver", "iscsi", "--source", iqn,
				"--option", "portal="+portal, "--option", fmt.Sprintf("lun=%d", lun), "--host", h)
			h, p := h, pool(lun)
			t.Cleanup(func() { l.lv(h, "pool", "delete", p, "--host", h, "--force") })
		}
	}

	// deploy brings up one VM pinned to host with a disk on pool — a data
	// disk, or with onRoot the root disk itself (built on the image) — and
	// returns its name and compose's error.
	deploy := func(host, prefix, pool string, onRoot bool) (string, error) {
		stack := uniqueName(prefix)
		vm := stack + "-1"
		disks := fmt.Sprintf("      root:\n        size: \"1G\"\n      data:\n        size: \"64M\"\n        storage: %q\n", pool)
		if onRoot {
			disks = fmt.Sprintf("      root:\n        size: \"64M\"\n        storage: %q\n", pool)
		}
		yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n%s    placement:\n      host: %s\n",
			stack, vm, drillImage(), drillMemory(), disks, host)
		file := "/tmp/" + stack + ".yaml"
		l.mustSSH(host, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
		t.Cleanup(func() { l.deleteVMs(stack, map[string]string{host: vm}) })
		out, err := l.lv(host, "compose", "up", "-f", file, "-y")
		if err != nil {
			return vm, fmt.Errorf("%v: %s", err, out)
		}
		return vm, nil
	}

	a, err := deploy(h1, "luna", pool(0), false)
	if err != nil {
		t.Fatalf("VM on LUN 0: %v", err)
	}
	if !l.waitDomainState(h1, a, "running", 4*time.Minute) {
		t.Fatalf("%s never ran on %s (virsh)", a, h1)
	}
	dev := fmt.Sprintf("/dev/disk/by-path/ip-%s-iscsi-%s-lun-0", portal, iqn)
	xml := l.mustSSH(h1, 30*time.Second, "virsh -c qemu:///system dumpxml "+shellQuote(a))
	if !strings.Contains(xml, "'"+dev+"'") && !strings.Contains(xml, `"`+dev+`"`) {
		t.Fatalf("%s's domain does not use %s:\n%s", a, dev, xml)
	}
	l.mustSSH(h1, 20*time.Second, "test -b "+shellQuote(dev))

	b, err := deploy(h2, "lunb", pool(0), false)
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("VM %q", a)) {
		t.Fatalf("second VM on LUN 0 from %s: got %v, want a refusal naming %s", h2, err, a)
	}
	if out, _ := l.ssh(h2, 20*time.Second, "virsh -c qemu:///system domstate "+shellQuote(b)); strings.TrimSpace(out) == "running" ||
		strings.Contains(out, "shut off") {
		t.Fatalf("the refused VM %s has a domain on %s: %s", b, h2, out)
	}

	// LUN 1 as a ROOT disk from the image: the image is written onto the
	// LUN, so its first sector is the image's (an MBR: 55 aa at 510), not
	// the zeros a fresh LUN reads.
	dev1 := fmt.Sprintf("/dev/disk/by-path/ip-%s-iscsi-%s-lun-1", portal, iqn)
	b2, err := deploy(h2, "lunc", pool(1), true)
	if err != nil {
		t.Fatalf("VM with its root disk on LUN 1: %v", err)
	}
	if !l.waitDomainState(h2, b2, "running", 4*time.Minute) {
		t.Fatalf("%s never ran on %s (virsh)", b2, h2)
	}
	sig := strings.TrimSpace(l.mustSSH(h2, 30*time.Second, "dd if="+shellQuote(dev1)+" bs=1 skip=510 count=2 2>/dev/null | od -An -tx1"))
	if sig != "55 aa" {
		t.Errorf("LUN 1's boot sector ends %q, want \"55 aa\": the image was not written onto the LUN", sig)
	}

	rows := l.mustSQL(h1, "SELECT subject_id FROM health_conditions WHERE evaluator = 'shared_lun' AND lifecycle != 'resolved' AND deleted_at IS NULL")
	if len(rows) != 0 {
		t.Errorf("a shared_lun condition stands: %v", rows)
	}
}
