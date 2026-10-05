// Fleet scenario for `lv host drain` of a host holding a STOPPED VM with a
// host-local disk.
//
// Drain used to "cold-reassign" a stopped VM: it moved the VM's row to the
// target and nothing else. The disk file stayed on the drained host, the disk
// rows still named it, and the domain was never defined on the target, so the
// VM arrived on the target without its data. A stopped VM now drains the way
// `lv migrate --cold` moves it (coldMigrateStoppedVM): disks streamed, domain
// defined on the target, VM and disk rows handed over in one transaction, and
// the source cleaned up only after that commit. A VM the cold move refuses, or
// that fails part-way, stays on the drained host with its disks, and the drain
// reports it and ends incomplete.
//
// It reuses the cold-migration scenario (migrate_cold_stopped_test.go): two
// daemons over real gRPC, each with its own root for disk files.

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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// drain runs DrainHost for the scenario's source and returns every progress
// frame by VM name, plus the stream's final error.
func (sc *coldStoppedScenario) drain(t *testing.T) (map[string]*pb.DrainProgress, error) {
	t.Helper()
	st, err := sc.c.SelfClient(sc.src).DrainHost(context.Background(), &pb.DrainHostRequest{Name: sc.src.Name})
	if err != nil {
		return nil, err
	}
	got := map[string]*pb.DrainProgress{}
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			return got, nil
		}
		if rerr != nil {
			return got, rerr
		}
		got[p.VmName] = p
	}
}

// addStoppedLocalVM adds a second stopped VM on the source with one
// host-local disk holding payload, and returns that disk's recorded path.
func (sc *coldStoppedScenario) addStoppedLocalVM(t *testing.T, name string, payload []byte) string {
	t.Helper()
	disk := filepath.Join(sc.c.tmpRoot, sc.dst.Name, "data", "disks", name+"-root.raw")
	sp := sc.file(sc.src, disk)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sp, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256})
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(context.Background(), sc.src.DB, corrosion.VMRecord{
		Name: name, HostName: sc.src.Name, State: "stopped", Spec: string(spec), CPUActual: 1, MemActual: 256,
	}, nil, []corrosion.DiskRecord{
		{VMName: name, DiskName: "root", HostName: sc.src.Name, Path: disk, SizeBytes: int64(len(payload)), StorageType: "local", TargetDev: "vda"},
	}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
	if err := sc.src.Virt.DefineDomain(`<domain type='kvm'><name>` + name + `</name><uuid>22222222-3333-4444-8555-666666666666</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + disk + `'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define source domain %s: %v", name, err)
	}
	return disk
}

func (sc *coldStoppedScenario) vmNamed(t *testing.T, name string) *corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), sc.src.DB, name)
	if err != nil || vm == nil {
		t.Fatalf("GetVM %s: %v %v", name, vm, err)
	}
	return vm
}

// Draining a host moves a stopped VM WITH its host-local disk: the bytes are
// on the target, the VM is stopped there with its domain defined and its disk
// rows moved, and the drained host keeps neither the disk nor the domain.
//
// Mutation: put the old row-only reassign back for a stopped VM — the disk
// never reaches the target and the test goes red.
func TestFleet_DrainMovesAStoppedVMWithItsLocalDisk(t *testing.T) {
	sc := newColdStoppedScenario(t)

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain of a host holding one stopped VM: %v", err)
	}
	p := progress["os1"]
	if p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done", p)
	}
	if p.Strategy != pb.MigrateStrategy_MIGRATE_COLD || p.TargetHost != sc.dst.Name {
		t.Errorf("drain progress for os1 = strategy %s target %s, want cold to %s", p.Strategy, p.TargetHost, sc.dst.Name)
	}

	got, err := os.ReadFile(sc.file(sc.dst, sc.disk))
	if err != nil {
		t.Fatalf("the disk did not arrive on %s: %v", sc.dst.Name, err)
	}
	if string(got) != string(sc.payload) {
		t.Fatalf("the disk on %s is %d bytes that differ from the source's %d", sc.dst.Name, len(got), len(sc.payload))
	}
	if _, err := os.Stat(sc.file(sc.src, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the drained host still holds the moved disk (stat: %v)", err)
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
		t.Errorf("domain os1 is active on %s; draining a stopped VM must leave it stopped", sc.dst.Name)
	}
	if sc.src.Virt.DomainExists("os1") {
		t.Errorf("domain os1 is still defined on the drained host %s", sc.src.Name)
	}
}

// A stopped VM the drain cannot move stays on the drained host with its disk
// and its rows, and is reported: its progress frame says failed and why, and
// the drain ends "drain incomplete" naming the VM left behind, with the host
// still draining. A movable stopped VM in the same drain still moves.
//
// os2's define on the target fails — the last step before the handoff — so
// its disk has already been copied there and must be taken back.
//
// Mutation: row-move a stopped VM whose cold move failed (the old fallback) —
// os2's row names the target and the test goes red.
func TestFleet_DrainLeavesAStoppedVMItCannotMoveAndReportsIt(t *testing.T) {
	sc := newColdStoppedScenario(t)
	payload2 := make([]byte, 1<<20+77)
	for i := range payload2 {
		payload2[i] = byte(i*13 + 1)
	}
	disk2 := sc.addStoppedLocalVM(t, "os2", payload2)
	sc.dst.Virt.FailDefineDomain = func(xml string) error {
		if strings.Contains(xml, "<name>os2</name>") {
			return errors.New("injected define failure for os2")
		}
		return nil
	}

	progress, err := sc.drain(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "drain incomplete: 1 VM(s) remain") {
		t.Fatalf("drain with an unmovable stopped VM = %v, want FailedPrecondition drain incomplete: 1 VM(s) remain", err)
	}
	if p := progress["os2"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "injected define failure for os2") {
		t.Fatalf("drain progress for os2 = %+v, want failed with the define failure", p)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" {
		t.Fatalf("drain progress for os1 = %+v, want done", p)
	}

	vm2 := sc.vmNamed(t, "os2")
	if vm2.HostName != sc.src.Name || vm2.State != "stopped" {
		t.Fatalf("os2 row = host %s state %s, want it left on %s, stopped", vm2.HostName, vm2.State, sc.src.Name)
	}
	disks, err := corrosion.GetVMDisks(context.Background(), sc.src.DB, "os2")
	if err != nil || len(disks) != 1 || disks[0].HostName != sc.src.Name {
		t.Fatalf("os2 disk rows = %+v (%v), want one naming %s", disks, err, sc.src.Name)
	}
	got, err := os.ReadFile(sc.file(sc.src, disk2))
	if err != nil || string(got) != string(payload2) {
		t.Fatalf("os2's disk did not stay intact on the drained host (err %v, %d bytes)", err, len(got))
	}
	if _, err := os.Stat(sc.file(sc.dst, disk2)); !os.IsNotExist(err) {
		t.Errorf("the failed move left os2's disk copy on %s (stat: %v)", sc.dst.Name, err)
	}
	if !sc.src.Virt.DomainExists("os2") {
		t.Errorf("os2's domain is gone from the drained host")
	}
	if sc.dst.Virt.DomainExists("os2") {
		t.Errorf("os2's domain is defined on %s after its move failed", sc.dst.Name)
	}
	if h, _ := corrosion.GetHost(context.Background(), sc.src.DB, sc.src.Name); h == nil || h.State != "draining" {
		t.Errorf("drained host state = %+v, want draining (the drain did not complete)", h)
	}

	// os1 moved in the same drain, with its disk.
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "stopped" {
		t.Errorf("os1 row = host %s state %s, want host %s state stopped", vm.HostName, vm.State, sc.dst.Name)
	}
	if got, err := os.ReadFile(sc.file(sc.dst, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Errorf("os1's disk did not arrive intact on %s (err %v)", sc.dst.Name, err)
	}
}

// A stopped Secure Boot VM now drains through the cold path too, and with its
// refusals: one with a host-local disk is refused there ("move it to shared
// storage first"), not moved, and left on the drained host with its disk.
// Drain used to refuse every firmware VM up front, so this also shows the
// stopped one reaches the cold path at all.
//
// Mutation: refuse every firmware VM up front again — os1's frame is the old
// "skipped" refusal and the test goes red.
func TestFleet_DrainRefusesAStoppedFirmwareVMOnLocalStorage(t *testing.T) {
	sc := newColdStoppedScenario(t)
	ctx := context.Background()
	spec, err := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256, SecureBoot: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.src.DB.Execute(ctx, `UPDATE vms SET spec = ?, updated_at = ? WHERE name = 'os1'`, string(spec), sc.src.DB.NowTS()); err != nil {
		t.Fatalf("mark os1 Secure Boot: %v", err)
	}
	if err := corrosion.SetHostLabel(ctx, sc.src.DB, sc.dst.Name, corrosion.LabelSecureBootCapable, "true"); err != nil {
		t.Fatalf("label %s Secure-Boot-capable: %v", sc.dst.Name, err)
	}

	progress, err := sc.drain(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "drain incomplete: 1 VM(s) remain") {
		t.Fatalf("drain with a stopped firmware VM on local storage = %v, want drain incomplete", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "failed" || !strings.Contains(p.Error, "has a host-local disk") {
		t.Fatalf("drain progress for os1 = %+v, want failed with the cold path's host-local refusal", p)
	}
	if vm := sc.vmNamed(t, "os1"); vm.HostName != sc.src.Name || vm.State != "stopped" {
		t.Fatalf("os1 row = host %s state %s, want it left on %s, stopped", vm.HostName, vm.State, sc.src.Name)
	}
	if got, err := os.ReadFile(sc.file(sc.src, sc.disk)); err != nil || string(got) != string(sc.payload) {
		t.Fatalf("os1's disk did not stay intact on the drained host (err %v)", err)
	}
	if _, err := os.Stat(sc.file(sc.dst, sc.disk)); !os.IsNotExist(err) {
		t.Errorf("the refused move left a disk copy on %s (stat: %v)", sc.dst.Name, err)
	}
}

// A VM recorded here with no domain — what a drain by an older build left on
// the host it moved a stopped VM to — is refused with a message that says so
// and points at the recovery, not a bare libvirt lookup failure.
//
// Mutation: drop the no-domain refusal — the frame carries "cannot confirm
// the domain ... is shut off" and goes red.
func TestFleet_DrainExplainsAVMWithNoDomain(t *testing.T) {
	sc := newColdStoppedScenario(t)
	if err := sc.src.Virt.UndefineDomain("os1", false); err != nil {
		t.Fatalf("undefine os1: %v", err)
	}

	progress, err := sc.drain(t)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "drain incomplete: 1 VM(s) remain") {
		t.Fatalf("drain = %v, want drain incomplete", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "failed" ||
		!strings.Contains(p.Error, `VM "os1" has no domain defined on `+sc.src.Name) || !strings.Contains(p.Error, "A VM with no domain") {
		t.Fatalf("drain progress for os1 = %+v, want failed: has no domain defined, with the docs pointer", p)
	}
	if vm := sc.vm(t); vm.HostName != sc.src.Name {
		t.Errorf("os1 row names %s, want it left on %s", vm.HostName, sc.src.Name)
	}
}
