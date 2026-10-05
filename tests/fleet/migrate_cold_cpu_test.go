// Fleet scenarios for the migration CPU preflight on a COLD move.
//
// The preflight asks the target whether it can run the CPU the guest is
// running on right now. That question only exists for a live migration: a
// cold-moved guest is booted fresh on the target, where host-model and
// host-passthrough expand to the target's own CPU. Asked of a cold move, it
// refused moves between hosts of different CPU generations for no reason — and
// a drain moves every running host-local-disk VM cold, so a drain into a pool
// of different hosts ended incomplete with every such VM left behind.

package fleet

import (
	"context"
	"encoding/json"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// setCPUMode records cpuMode on os1's stored spec.
func (sc *coldStoppedScenario) setCPUMode(t *testing.T, cpuMode string) {
	t.Helper()
	spec, err := json.Marshal(&pb.VMSpec{Name: "os1", Cpu: 1, MemoryMib: 256, CpuMode: cpuMode})
	if err != nil {
		t.Fatal(err)
	}
	if err := sc.src.DB.Execute(context.Background(), `UPDATE vms SET spec = ?, updated_at = ? WHERE name = 'os1'`,
		string(spec), sc.src.DB.NowTS()); err != nil {
		t.Fatalf("record os1's cpu_mode: %v", err)
	}
}

// makeTargetCPUIncompatible gives the source a host-passthrough CPU the target
// says it cannot run, the answer that refuses a live migration
// (TestFleet_MigrateVM_PassthroughComparesTheSourceHostCPU).
func (sc *coldStoppedScenario) makeTargetCPUIncompatible(t *testing.T) {
	t.Helper()
	sc.setCPUMode(t, lv.CPUModeHostPassthrough)
	sc.src.Virt.HostCPUModel = "Sapphire-Rapids"
	incompatible := lv.CPUCompareIncompatible
	sc.dst.Virt.CPUCompareResult = &incompatible
}

// A stopped host-passthrough VM moves cold to a host whose CPU differs; the
// target is not asked about the source's CPU at all.
//
// Mutation: run preflightTargetCPU for cold moves again — the move is refused
// with "cannot run VM" and goes red.
func TestFleet_ColdMigrationIsNotCPUPreflighted(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeTargetCPUIncompatible(t)

	if err := sc.migrateCold(t); err != nil {
		t.Fatalf("migrate --cold of a stopped VM to a host with another CPU: %v", err)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name {
		t.Fatalf("os1 row names %s, want %s", vm.HostName, sc.dst.Name)
	}
	if asked := sc.dst.Virt.ComparedCPUXML(); len(asked) != 0 {
		t.Errorf("a cold move asked the target to compare a CPU: %q", asked)
	}
}

// A drain moves a running host-local-disk VM cold, so the target's CPU does
// not matter to it either: the VM arrives and runs there.
//
// Mutation: as above — the drain ends incomplete with os1 left running on the
// source, and goes red.
func TestFleet_DrainColdMoveIsNotCPUPreflighted(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.makeRunning(t)
	sc.makeTargetCPUIncompatible(t)

	progress, err := sc.drain(t)
	if err != nil {
		t.Fatalf("drain into a host with another CPU: %v", err)
	}
	if p := progress["os1"]; p == nil || p.Status != "done" || p.Error != "" {
		t.Fatalf("drain progress for os1 = %+v, want done with no error", p)
	}
	if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != "running" {
		t.Fatalf("os1 row = host %s state %s, want host %s running", vm.HostName, vm.State, sc.dst.Name)
	}
	if asked := sc.dst.Virt.ComparedCPUXML(); len(asked) != 0 {
		t.Errorf("a drain's cold move asked the target to compare a CPU: %q", asked)
	}
}
