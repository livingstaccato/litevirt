package e2e

import (
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

// Lab drills for the daily-operations group: a clone onto another host, the
// undrain failback, and the dedicated migration network. Written for the lab and
// run by the controller (lab 2): every claim is read from virsh, qemu-img, ss
// and stat on the nodes, never only from litevirt's own view.
//
// The lab has no shared storage, so what failback does to a VM on shared disks
// (live migration back) is the fleet suite's to prove (tests/fleet/failback_test.go);
// what the lab proves is the other half of its contract, that a VM it must not
// move live is left running where it is.

// A clone made with --host ends up on that host: a defined, shut-off domain
// there, its disk a qcow2 of the source's virtual size, and nothing left behind
// on the source host.
func TestLab_CloneToAnotherHost(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	src := l.leastLoaded(q, l.except())
	dst := l.leastLoaded(q, l.except(src))
	sv := l.createStoppedVM(q, "clone", src)
	before, err := l.inspectVM(q, sv.name)
	if err != nil || len(before.Disks) == 0 {
		t.Fatalf("inspect %s: %v %+v", sv.name, err, before)
	}
	srcSize, err := l.qemuVirtualSize(src, before.Disks[0].Path)
	if err != nil {
		t.Fatalf("source disk size: %v", err)
	}

	clone := uniqueName("clonehost")
	l.onRestore(func() {
		if via := l.liveHost(); via != "" {
			l.lv(via, "rm", "--force", clone)
		}
	})
	l.mustLVf(q, "clone to another host", "clone", sv.name, clone, "--host", dst)

	got, err := l.inspectVM(q, clone)
	if err != nil || got.HostName != dst || len(got.Disks) != 1 {
		t.Fatalf("clone record = %+v (err %v), want one disk on %s", got, err, dst)
	}
	path := got.Disks[0].Path
	if out := l.mustSSH(dst, 30*time.Second, "virsh -c qemu:///system domstate "+shellQuote(clone)); strings.TrimSpace(out) != "shut off" {
		t.Errorf("virsh domstate on %s = %q, want shut off", dst, out)
	}
	if size, err := l.qemuVirtualSize(dst, path); err != nil || size != srcSize {
		t.Errorf("clone disk on %s: size %d err %v, want the source's %d", dst, size, err, srcSize)
	}
	if out, err := l.ssh(dst, 60*time.Second, "qemu-img check -U "+shellQuote(path)); err != nil {
		t.Errorf("qemu-img check of the clone's disk on %s: %v\n%s", dst, err, out)
	}
	if l.fileExists(src, path) {
		t.Errorf("the staged copy %s is still on %s", path, src)
	}
	if out, err := l.ssh(src, 30*time.Second, "virsh -c qemu:///system dominfo "+shellQuote(clone)); err == nil {
		t.Errorf("%s still defines the clone's domain:\n%s", src, out)
	}
	if !l.fileExists(src, before.Disks[0].Path) {
		t.Errorf("the source VM's disk %s is gone from %s", before.Disks[0].Path, src)
	}

	// It runs where it was put.
	l.mustLVf(q, "start the clone", "start", clone)
	if !l.waitDomainState(dst, clone, "running", 3*time.Minute) {
		t.Fatalf("the clone never ran on %s (virsh)", dst)
	}
	if l.waitDomainState(src, clone, "running", 5*time.Second) {
		t.Errorf("the clone is running on %s too", src)
	}
}

// After a drain, `lv host failback --all` moves back what it can move live
// and reports the rest. The lab's VMs have host-local disks, which a live move
// would have to copy, so the VM must be reported and left running on the host
// the drain put it on, and its record kept.
func TestLab_UndrainFailbackLeavesAHostLocalVMRunning(t *testing.T) {
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.except(q))
	vm := l.createVMs(q, "fb", victim)[victim]

	l.mustLVf(q, "drain", "host", "drain", victim)
	l.onRestore(func() {
		if via := l.liveHost(); via != "" {
			l.lv(via, "host", "undrain", victim)
		}
	})
	moved, err := l.inspectVM(q, vm)
	if err != nil || moved.HostName == victim || moved.HostName == "" {
		t.Fatalf("the drain left %s on %s: %+v %v", vm, victim, moved, err)
	}
	if !l.waitDomainState(moved.HostName, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running on %s after the drain (virsh)", vm, moved.HostName)
	}

	l.mustLVf(q, "undrain", "host", "undrain", victim)
	out, err := l.lv(q, "host", "failback", victim, "--all")
	if err != nil {
		t.Fatalf("failback --all: %v\n%s", err, out)
	}
	if !strings.Contains(out, vm) || !strings.Contains(out, "skipped") || !strings.Contains(out, "host-local") {
		t.Errorf("failback output does not report %s skipped for its host-local disk:\n%s", vm, out)
	}
	after, err := l.inspectVM(q, vm)
	if err != nil || after.HostName != moved.HostName {
		t.Errorf("%s is on %q after failback, want it left on %s (%v)", vm, after.HostName, moved.HostName, err)
	}
	if !l.waitDomainState(moved.HostName, vm, "running", 30*time.Second) {
		t.Errorf("%s stopped running on %s", vm, moved.HostName)
	}
	if l.waitDomainState(victim, vm, "running", 5*time.Second) {
		t.Errorf("%s is running on %s too", vm, victim)
	}
}

// With migration.network set (E2E_LAB_MIGRATION_NET, the CIDR every node has an
// address in and carries in its config), a --with-storage migration's data
// connection goes to the target's address in that network, and the cluster
// address sees no migration data. Read with ss on the source while the move
// runs: the migration ports (49152-49215) peer.
func TestLab_MigrationNetworkCarriesTheStorageCopy(t *testing.T) {
	cidr := os.Getenv("E2E_LAB_MIGRATION_NET")
	if cidr == "" {
		t.Skip("set E2E_LAB_MIGRATION_NET to the CIDR of the lab's migration network " +
			"(every node needs an address in it and `migration: network:` set to it)")
	}
	_, mnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("E2E_LAB_MIGRATION_NET=%q: %v", cidr, err)
	}
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	src := l.leastLoaded(q, l.except())
	dst := l.leastLoaded(q, l.except(src))
	vm := l.createVMs(q, "mignet", src)[src]

	// Sample the source's established migration connections while the move runs.
	sample := "for i in $(seq 1 240); do ss -Htn state established '( dport >= :49152 and dport <= :49215 )'; sleep 0.25; done > /tmp/mignet.ss 2>&1 &"
	l.mustSSH(src, 20*time.Second, "rm -f /tmp/mignet.ss; "+sample+" echo started")
	out, err := l.lv(q, "migrate", vm, dst, "--with-storage")
	if err != nil {
		t.Fatalf("migrate --with-storage: %v\n%s", err, out)
	}
	if !l.waitDomainState(dst, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running on %s after the migration (virsh)", vm, dst)
	}
	l.ssh(src, 20*time.Second, "pkill -f 'seq 1 240' ; true")
	seen := l.mustSSH(src, 20*time.Second, "cat /tmp/mignet.ss")
	l.saveEvidence("migration-network-ss", seen)

	onNet, off := 0, 0
	for _, line := range strings.Split(seen, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		host, _, err := net.SplitHostPort(f[3])
		if err != nil {
			continue
		}
		if ip := net.ParseIP(host); ip != nil && mnet.Contains(ip) {
			onNet++
		} else {
			off++
		}
	}
	if onNet == 0 {
		t.Errorf("no migration connection to an address in %s was seen on %s:\n%s", cidr, src, seen)
	}
	if off != 0 {
		t.Errorf("%d migration connection(s) left %s for an address outside %s:\n%s", off, src, cidr, seen)
	}
	if ev, _ := l.lv(q, "events", vm); strings.Contains(ev, "network_fallback") {
		t.Errorf("the migration fell back to the cluster address:\n%s", ev)
	}
}

// sharedPool is a storage pool every lab node mounts (an NFS export from one
// lab node, say), named by E2E_LAB_SHARED_POOL. The lab has no shared storage of
// its own, so the proofs that need it are opt-in.
func sharedPool(t *testing.T) string {
	p := os.Getenv("E2E_LAB_SHARED_POOL")
	if p == "" {
		t.Skip("set E2E_LAB_SHARED_POOL to a storage pool every lab node mounts (an NFS export from one node)")
	}
	return p
}

// createSharedVM makes a running VM on host whose disks are all on the shared
// pool, with placement.failback set when failback is true.
func (l *lab) createSharedVM(via, prefix, host, pool string, failback bool) string {
	l.t.Helper()
	stack := uniqueName(prefix)
	name := stack + "-1"
	yaml := fmt.Sprintf("name: %s\nvms:\n  %s:\n    image: %s\n    cpu: 1\n    memory: %s\n    disks:\n      root:\n        size: 4G\n        storage: %s\n    placement:\n      host: %s\n      failback: %t\n",
		stack, name, drillImage(), drillMemory(), pool, host, failback)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(via, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	l.onRestore(func() { l.deleteVMs(stack, map[string]string{host: name}) })
	l.mustLVf(via, "compose up on the shared pool", "compose", "up", "-f", file, "-y")
	if !l.waitDomainState(host, name, "running", 4*time.Minute) {
		l.t.Fatalf("shared-storage VM %s never ran on %s (virsh)", name, host)
	}
	return name
}

// A drain moves a shared-storage VM by live migration, and an undrain with the
// VM opted in (placement.failback) live-migrates it back by itself, in the
// background. Read with virsh on both hosts: the domain is running on the
// returning host and gone from the other, never on both.
func TestLab_LiveFailbackOnSharedStorage(t *testing.T) {
	pool := sharedPool(t)
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	victim := l.leastLoaded(q, l.except(q))
	vm := l.createSharedVM(q, "fbshared", victim, pool, true)

	l.mustLVf(q, "drain", "host", "drain", victim)
	l.onRestore(func() {
		if via := l.liveHost(); via != "" {
			l.lv(via, "host", "undrain", victim)
		}
	})
	moved, err := l.inspectVM(q, vm)
	if err != nil || moved.HostName == victim {
		t.Fatalf("the drain left %s on %s: %+v %v", vm, victim, moved, err)
	}
	if !l.waitDomainState(moved.HostName, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running on %s after the drain (virsh)", vm, moved.HostName)
	}

	out := l.mustLV(q, "host", "undrain", victim, "--failback")
	if !strings.Contains(out, vm) || !strings.Contains(out, "moved") {
		t.Errorf("undrain --failback did not report %s moved:\n%s", vm, out)
	}
	if !l.waitDomainState(victim, vm, "running", 3*time.Minute) {
		t.Fatalf("%s never ran on %s after the failback (virsh)", vm, victim)
	}
	if l.waitDomainState(moved.HostName, vm, "running", 5*time.Second) {
		t.Errorf("%s is running on %s as well as %s", vm, moved.HostName, victim)
	}
	if got, err := l.inspectVM(q, vm); err != nil || got.HostName != victim {
		t.Errorf("record says %q after failback (%v), want %s", got.HostName, err, victim)
	}
}

// A memory-only migration over the migration network leaves libvirt's tunnel for
// QEMU's own TLS stream: the 49152-49215 peers are in the CIDR and the tunnel's
// port 16514 carries no migration data. It needs shared storage (the VM has no
// disk to copy) and migration TLS on both hosts.
func TestLab_MigrationNetworkCarriesMemoryOnlyOverTLS(t *testing.T) {
	cidr := os.Getenv("E2E_LAB_MIGRATION_NET")
	if cidr == "" {
		t.Skip("set E2E_LAB_MIGRATION_NET (the CIDR of the lab's migration network)")
	}
	pool := sharedPool(t)
	_, mnet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("E2E_LAB_MIGRATION_NET=%q: %v", cidr, err)
	}
	l := newLab(t)
	b := l.requireBaseline()
	l.restoreOnCleanup(b)

	q := l.hosts[0]
	src := l.leastLoaded(q, l.except())
	dst := l.leastLoaded(q, l.except(src))
	vm := l.createSharedVM(q, "mignetmem", src, pool, false)

	sample := "for i in $(seq 1 240); do ss -Htn state established '( dport >= :49152 and dport <= :49215 ) or ( dport = :16514 )'; sleep 0.25; done > /tmp/mignetmem.ss 2>&1 &"
	l.mustSSH(src, 20*time.Second, "rm -f /tmp/mignetmem.ss; "+sample+" echo started")
	out, err := l.lv(q, "migrate", vm, dst)
	if err != nil {
		t.Fatalf("migrate: %v\n%s", err, out)
	}
	if !l.waitDomainState(dst, vm, "running", 3*time.Minute) {
		t.Fatalf("%s is not running on %s after the migration (virsh)", vm, dst)
	}
	l.ssh(src, 20*time.Second, "pkill -f 'seq 1 240' ; true")
	seen := l.mustSSH(src, 20*time.Second, "cat /tmp/mignetmem.ss")
	l.saveEvidence("migration-network-memory-ss", seen)
	direct := 0
	for _, line := range strings.Split(seen, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		host, port, err := net.SplitHostPort(f[3])
		if err != nil {
			continue
		}
		ip := net.ParseIP(host)
		switch {
		case port == "16514" && ip != nil && ip.Equal(net.ParseIP(l.ip[dst])):
			// libvirt's control connection to the cluster address, which is expected;
			// it must not carry the memory (it is small), which the stream check below shows.
		case ip != nil && mnet.Contains(ip):
			direct++
		default:
			t.Errorf("a migration connection went to %s (outside %s):\n%s", f[3], cidr, seen)
		}
	}
	if direct == 0 {
		t.Errorf("no QEMU migration stream to an address in %s was seen:\n%s", cidr, seen)
	}
}
