package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// lv move-volume of a litevirt VM on the nested lab. Every litevirt domain
// carries namespaced metadata (the managed stamp, and the owner-epoch marker
// once written), and the move redefines the domain: the disk must land on the
// new pool and the <metadata> of the persistent definition must come through
// byte for byte. What is checked is read from the node with virsh, never from
// litevirt.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_MoveVolumeKeepsMetadata -v -timeout 30m
func TestLab_MoveVolumeKeepsMetadata(t *testing.T) {
	l := newLab(t)
	h, vm := snapTestVM(l, "mvns")

	// The reconciler stamps a domain it has a live row for; wait for it.
	var before string
	deadline := time.Now().Add(3 * time.Minute)
	for {
		before = inactiveMetadata(l, h, vm)
		if strings.Contains(before, "https://litevirt.dev/xmlns/managed/1") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s on %s never got the managed stamp:\n%s", vm, h, before)
		}
		time.Sleep(5 * time.Second)
	}
	l.mark("mvns: %s metadata before the move:\n%s", vm, before)

	pool := uniqueName("mvns")
	dir := "/var/tmp/" + pool
	l.mustSSH(h, 30*time.Second, "mkdir -p "+shellQuote(dir))
	l.mustLV(h, "pool", "create", pool, "--driver", "dir", "--target", dir, "--host", h)
	t.Cleanup(func() {
		l.lv(h, "pool", "delete", pool, "--host", h, "--force")
		l.ssh(h, 30*time.Second, "rm -rf "+shellQuote(dir))
	})

	snapStop(l, h, vm)
	if out, err := l.lv(h, "move-volume", vm, "root", pool); err != nil {
		t.Fatalf("lv move-volume %s root %s: %v\n%s", vm, pool, err, out)
	}
	l.mark("mvns: %s root moved to %s", vm, pool)

	if disk := snapActiveDisk(l, h, vm); !strings.HasPrefix(disk, dir+"/") {
		t.Fatalf("%s's vda is %s after the move, want a file under %s", vm, disk, dir)
	}
	if after := inactiveMetadata(l, h, vm); after != before {
		t.Fatalf("%s's <metadata> changed across the move:\nbefore:\n%s\nafter:\n%s", vm, before, after)
	}
	if out, err := l.lv(h, "start", vm); err != nil {
		t.Fatalf("%s cannot be started after the move: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(h, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running after its start", vm)
	}
}

var metadataBlock = regexp.MustCompile(`(?s)<metadata>.*</metadata>`)

// inactiveMetadata is the <metadata> element of vm's persistent definition.
func inactiveMetadata(l *lab, host, vm string) string {
	l.t.Helper()
	out := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system dumpxml --inactive "+shellQuote(vm))
	return metadataBlock.FindString(out)
}
