// Fleet scenario for `lv migrate --cold` of a STOPPED VM.
//
// A stopped VM has no running guest for libvirt to migrate, so it used to be
// refused outright ("must be running to migrate"), while the CLI's --cold help
// said the VM must be stopped. It now moves the way a stopped Secure-Boot/vTPM
// VM always has: its host-local disk files are streamed to the target over the
// peer connection, its domain is defined there, and the VM and its disk rows
// move to the target in one transaction, still stopped. A failure before that
// commit leaves the VM on the source and takes back what reached the target.
//
// Multi-node by construction: the bytes leave one daemon's disk and land on
// another's over real gRPC, and the define and the cleanup run on the target.
// The two nodes share the test process's filesystem, so each is given its own
// root for disk files (SetHostDiskRootForTest) — otherwise the disk's recorded
// path would name the same file on both, and a copy could pass by moving
// nothing.

package fleet

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

type coldStoppedScenario struct {
	c        *Cluster
	src, dst *Node
	disk     string // the host-local disk's recorded path
	shared   string // the shared disk's recorded path
	payload  []byte
}

// newColdStoppedScenario is a stopped VM os1 on node 0 with one host-local
// disk holding payload and one disk on shared storage.
func newColdStoppedScenario(t *testing.T) *coldStoppedScenario {
	t.Helper()
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	t.Cleanup(c.Stop)
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range []*Node{src, dst} {
		n.Server.SetHostDiskRootForTest(filepath.Join(c.tmpRoot, "fs-"+n.Name))
	}

	sc := &coldStoppedScenario{
		c: c, src: src, dst: dst,
		// Under the target's disks dir: a disk-artifact root there, as the
		// same path is on every host in production.
		disk:   filepath.Join(c.tmpRoot, dst.Name, "data", "disks", "os1-root.qcow2"),
		shared: filepath.Join(c.tmpRoot, "nfs", "os1-data.qcow2"),
	}
	// Not a qcow2, so it is copied as it is; a zero megabyte in the middle is
	// skipped on the wire and must still read back as zeros.
	sc.payload = make([]byte, 3<<20+4321)
	for i := range sc.payload {
		if i < 1<<20 || i >= 2<<20 {
			sc.payload[i] = byte(i*31 + 7)
		}
	}
	sp := sc.file(src, sc.disk)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, sc.payload, 0o600); err != nil {
		t.Fatal(err)
	}

	spec, err := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), src.DB, corrosion.VMRecord{
		Name: "os1", HostName: src.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: "os1", DiskName: "root", HostName: src.Name, Path: sc.disk, SizeBytes: int64(len(sc.payload)), StorageType: "local", TargetDev: "vda"},
		{VMName: "os1", DiskName: "data", HostName: src.Name, Path: sc.shared, SizeBytes: 1 << 30, StorageType: "nfs", TargetDev: "vdb"},
	}); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	if err := src.Virt.DefineDomain(`<domain type='kvm'><name>os1</name><uuid>11111111-2222-4333-8444-555555555555</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + sc.disk + `'/><target dev='vda'/></disk>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + sc.shared + `'/><target dev='vdb'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define source domain: %v", err)
	}
	return sc
}

// file is where node n keeps the disk file recorded at path.
func (sc *coldStoppedScenario) file(n *Node, path string) string {
	return filepath.Join(sc.c.tmpRoot, "fs-"+n.Name, path)
}

func (sc *coldStoppedScenario) migrateCold(t *testing.T) error {
	t.Helper()
	st, err := sc.c.SelfClient(sc.src).MigrateVM(context.Background(), &pb.MigrateVMRequest{
		VmName: "os1", TargetHost: sc.dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); rerr == io.EOF {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

func (sc *coldStoppedScenario) vm(t *testing.T) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), sc.dst.DB, "os1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", vm, err)
	}
	return vm
}

func (sc *coldStoppedScenario) diskHosts(t *testing.T) map[string]string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), sc.dst.DB, "os1")
	if err != nil {
		t.Fatalf("GetVMDisks: %v", err)
	}
	out := map[string]string{}
	for _, d := range disks {
		out[d.DiskName] = d.HostName
	}
	return out
}

func receivingScratch(dir string) []string {
	ents, _ := os.ReadDir(dir)
	var left []string
	for _, e := range ents {
		if strings.Contains(e.Name(), ".receiving-") {
			left = append(left, e.Name())
		}
	}
	return left
}

// A stopped VM migrated with --cold arrives on the target stopped, with its
// host-local disk's bytes, its domain defined and its disk rows moved; the
// source keeps neither the disk nor the domain, and libvirt is never asked to
// migrate anything.
//
// Mutations: restore the "must be running" gate for non-firmware VMs — the
// migration is refused and goes red. Skip the disk copy — the target has no
// disk and goes red. Skip the source disk removal — the source still holds the
// file and goes red.
func TestFleet_ColdMigrationOfAStoppedVMMovesItsDisk(t *testing.T) {
	sc := newColdStoppedScenario(t)
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("migrate --cold of a stopped VM: %v", err)
	}

	got, err := os.ReadFile(sc.file(sc.dst, sc.disk))
	if err != nil {
		t.Fatalf("the disk did not arrive on %s: %v", sc.dst.Name, err)
	}
	if string(got) != string(sc.payload) {
		t.Fatalf("the disk on %s is %d bytes that differ from the source's %d", sc.dst.Name, len(got), len(sc.payload))
	}
	if _, err := os.Stat(sc.file(sc.src, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the source still holds the migrated disk (stat: %v)", err)
	}
	if left := receivingScratch(filepath.Dir(sc.file(sc.dst, sc.disk))); len(left) > 0 {
		t.Errorf("scratch files left on the target: %v", left)
	}

	vm := sc.vm(t)
	if vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Fatalf("VM row = host %s state %s, want host %s state stopped", vm.HostName, vm.State, sc.dst.Name)
	}
	for name, host := range sc.diskHosts(t) {
		if host != sc.dst.Name {
			t.Errorf("disk %s row names %s, want %s", name, host, sc.dst.Name)
		}
	}
	if !sc.dst.Virt.DomainExists("os1") {
		t.Errorf("domain os1 is not defined on %s, so the VM cannot be started there", sc.dst.Name)
	} else if active, _ := sc.dst.Virt.DomainIsActive("os1"); active {
		t.Errorf("domain os1 is active on %s; a cold migration of a stopped VM must leave it stopped", sc.dst.Name)
	}
	if sc.src.Virt.DomainExists("os1") {
		t.Errorf("domain os1 is still defined on the source %s", sc.src.Name)
	}
	for _, e := range sc.src.Virt.EventLog() {
		if e.Op == "migrate" {
			t.Errorf("libvirt was asked to migrate a stopped VM: %s", e.Note)
		}
	}
}

// A failure after the disk reached the target and before the handoff commits
// leaves the VM where it was, stopped, with its disk, and takes back the copy
// the attempt left on the target. The define on the target is the last step
// before the commit, so failing it exercises the whole rollback.
//
// Mutation: drop the target cleanup (the abort's CleanupMigrationArtifacts) —
// the copy stays on the target and goes red.
func TestFleet_ColdMigrationOfAStoppedVMRollsBackOnFailure(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.dst.Virt.FailDefineDomain = func(string) error { return errors.New("injected define failure") }

	err := sc.migrateCold(t)
	if err == nil || !strings.Contains(err.Error(), "injected define failure") {
		t.Fatalf("migrate --cold with a failing define = %v, want the define failure", err)
	}

	if _, err := os.Stat(sc.file(sc.dst, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the failed attempt left its disk copy on %s (stat: %v)", sc.dst.Name, err)
	}
	if left := receivingScratch(filepath.Dir(sc.file(sc.dst, sc.disk))); len(left) > 0 {
		t.Errorf("scratch files left on the target: %v", left)
	}
	got, err := os.ReadFile(sc.file(sc.src, sc.disk))
	if err != nil || string(got) != string(sc.payload) {
		t.Fatalf("the source's disk did not survive the failed attempt intact (err %v, %d bytes)", err, len(got))
	}
	vm := sc.vm(t)
	if vm.HostName != sc.src.Name || vm.State != "stopped" {
		t.Fatalf("VM row = host %s state %s, want host %s state stopped", vm.HostName, vm.State, sc.src.Name)
	}
	for name, host := range sc.diskHosts(t) {
		if host != sc.src.Name {
			t.Errorf("disk %s row names %s after a failed attempt, want %s", name, host, sc.src.Name)
		}
	}
	if sc.dst.Virt.DomainExists("os1") {
		t.Errorf("domain os1 is defined on %s after a failed attempt", sc.dst.Name)
	}
	if !sc.src.Virt.DomainExists("os1") {
		t.Errorf("domain os1 is gone from the source after a failed attempt")
	}

	// And the retry, once the target can define again, goes through: nothing
	// the failed attempt left stands in its way.
	sc.dst.Virt.FailDefineDomain = nil
	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("retry after the failed attempt: %v", err)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name {
		t.Fatalf("after the retry the VM row names %s, want %s", vm.HostName, sc.dst.Name)
	}
}
