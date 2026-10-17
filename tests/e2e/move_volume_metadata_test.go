package e2e

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

// lv move-volume of a litevirt VM on the nested lab. Every litevirt domain
// carries namespaced metadata (the managed stamp and the owner-epoch marker),
// and the move redefines the domain: the disk must land on the new pool and
// the <metadata> of the persistent definition must come through byte for
// byte. What is checked is read from the node with virsh, never from
// litevirt. The offline test moves a stopped VM; the live one moves a running
// VM, which pivots a block copy.
//
//	LITEVIRT_E2E=1 LV_BIN=/usr/local/bin/litevirt E2E_LAB_DIR=~/litevirt-lab \
//	  go test ./tests/e2e/ -run TestLab_MoveVolumeKeepsMetadata -v -timeout 30m
func TestLab_MoveVolumeKeepsMetadataOffline(t *testing.T) {
	moveVolumeKeepsMetadata(t, false)
}

func TestLab_MoveVolumeKeepsMetadataLive(t *testing.T) {
	moveVolumeKeepsMetadata(t, true)
}

func moveVolumeKeepsMetadata(t *testing.T, live bool) {
	l := newLab(t)
	h := labUpHosts(l, 1)[0]

	// The pool's teardown is queued before the VM exists, so it runs after the
	// VM's delete: a pool still holding a disk fails to delete, and only an
	// empty directory is removed, so a disk left behind is seen, not erased.
	pool := uniqueName("mvns")
	dir := "/var/tmp/" + pool
	l.mustSSH(h, 30*time.Second, "mkdir -p "+shellQuote(dir))
	l.mustLV(h, "pool", "create", pool, "--driver", "dir", "--target", dir, "--host", h)
	l.onRestore(func() {
		if out, err := l.lv(h, "pool", "delete", pool, "--host", h); err != nil {
			t.Errorf("cleanup: pool %s on %s: %v\n%s", pool, h, err, out)
		}
		if out, err := l.ssh(h, 30*time.Second, "rmdir "+shellQuote(dir)); err != nil {
			t.Errorf("cleanup: %s on %s is not empty: %v\n%s", dir, h, err, out)
		}
	})

	vm := l.createVMs(h, "mvns", h)[h]
	// The marker is written while the domain runs; read what the move starts
	// from only after any stop, so a stop that touched it fails here.
	waitStampedMetadata(l, h, vm)
	if !live {
		snapStop(l, h, vm)
	}
	before := waitStampedMetadata(l, h, vm)
	l.mark("mvns: %s metadata before the move:\n%s", vm, before)

	if out, err := l.lv(h, "move-volume", vm, "root", pool); err != nil {
		t.Fatalf("lv move-volume %s root %s: %v\n%s", vm, pool, err, out)
	}
	l.mark("mvns: %s root moved to %s (live=%v)", vm, pool, live)

	if disk := snapActiveDisk(l, h, vm); !strings.HasPrefix(disk, dir+"/") {
		t.Fatalf("%s's vda is %s after the move, want a file under %s", vm, disk, dir)
	}
	if disk := inactiveVDA(l, h, vm); !strings.HasPrefix(disk, dir+"/") {
		t.Fatalf("%s's persistent vda is %s after the move, want a file under %s", vm, disk, dir)
	}
	if after := inactiveMetadata(l, h, vm); after != before {
		t.Fatalf("%s's <metadata> changed across the move:\nbefore:\n%s\nafter:\n%s", vm, before, after)
	}
	if live {
		snapStop(l, h, vm)
	}
	if out, err := l.lv(h, "start", vm); err != nil {
		t.Fatalf("%s cannot be started after the move: %v\n%s", vm, err, out)
	}
	if !l.waitDomainState(h, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running after its start", vm)
	}
}

// waitStampedMetadata waits until vm's persistent <metadata> carries both the
// managed stamp and the owner-epoch marker, and returns it.
func waitStampedMetadata(l *lab, host, vm string) string {
	l.t.Helper()
	deadline := time.Now().Add(3 * time.Minute)
	for {
		md := inactiveMetadata(l, host, vm)
		if strings.Contains(md, "https://litevirt.dev/xmlns/managed/1") &&
			strings.Contains(md, "https://litevirt.dev/xmlns/owner-epoch/1") {
			return md
		}
		if time.Now().After(deadline) {
			l.t.Fatalf("%s on %s never carried both the managed stamp and the owner-epoch marker "+
				"(the marker needs enforcement.owner_epoch):\n%s", vm, host, md)
		}
		time.Sleep(5 * time.Second)
	}
}

var metadataBlock = regexp.MustCompile(`(?s)<metadata>.*</metadata>`)

// inactiveMetadata is the <metadata> element of vm's persistent definition.
func inactiveMetadata(l *lab, host, vm string) string {
	l.t.Helper()
	out := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system dumpxml --inactive "+shellQuote(vm))
	return metadataBlock.FindString(out)
}

// inactiveVDA is the file vda names in vm's persistent definition.
func inactiveVDA(l *lab, host, vm string) string {
	l.t.Helper()
	out := l.mustSSH(host, 30*time.Second, "virsh -c qemu:///system domblklist --inactive "+shellQuote(vm))
	for _, ln := range strings.Split(out, "\n") {
		if f := strings.Fields(ln); len(f) == 2 && f[0] == "vda" {
			return f[1]
		}
	}
	l.t.Fatalf("%s on %s has no persistent vda:\n%s", vm, host, out)
	return ""
}
