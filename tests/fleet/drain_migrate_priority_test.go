// Fleet scenario: compose `migrate.priority` orders `lv host drain`.
package fleet

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// addPrioritisedStoppedVM is addStoppedLocalVM with a compose migrate.priority
// in the stored spec and its own domain UUID.
func (sc *coldStoppedScenario) addPrioritisedStoppedVM(t *testing.T, name, uuid string, priority int32) {
	t.Helper()
	disk := filepath.Join(sc.c.tmpRoot, sc.dst.Name, "data", "disks", name+"-root.raw")
	sp := sc.file(sc.src, disk)
	if err := os.MkdirAll(filepath.Dir(sp), 0o755); err != nil {
		t.Fatal(err)
	}
	payload := []byte(name + "'s disk")
	if err := os.WriteFile(sp, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	spec, err := json.Marshal(&pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256, Migrate: &pb.MigrationPolicy{Priority: priority}})
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
	if err := sc.src.Virt.DefineDomain(`<domain type='kvm'><name>` + name + `</name><uuid>` + uuid + `</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='raw'/><source file='` + disk + `'/><target dev='vda'/></disk>` +
		`</devices></domain>`); err != nil {
		t.Fatalf("define source domain %s: %v", name, err)
	}
}

// TestFleet_DrainMovesHigherMigratePriorityFirst: a drain with one worker
// moves its VMs one at a time, so the order of its progress frames is the
// order the moves ran in. "zz-high" (priority 100) sorts last by name and
// must move first; "aa-low" (priority 0) and "os1" (no migrate section, the
// default 0) tie and keep their name order behind it. Every VM still moves —
// priority orders a drain, it never drops a VM from one.
//
// Mutation: drop the SortVMsByMigratePriority call in DrainHost — the frames
// come in the replica's row order, which is insertion order (os1, aa-low,
// zz-high), and the test goes red. Drop only the name tie-break — the ties
// come in row order (zz-high, os1, aa-low), red.
func TestFleet_DrainMovesHigherMigratePriorityFirst(t *testing.T) {
	sc := newColdStoppedScenario(t)
	sc.addPrioritisedStoppedVM(t, "aa-low", "33333333-4444-4555-8666-777777777777", 0)
	sc.addPrioritisedStoppedVM(t, "zz-high", "44444444-5555-4666-8777-888888888888", 100)

	st, err := sc.c.SelfClient(sc.src).DrainHost(context.Background(), &pb.DrainHostRequest{Name: sc.src.Name, Parallel: 1})
	if err != nil {
		t.Fatalf("DrainHost: %v", err)
	}
	var order []string
	for {
		p, rerr := st.Recv()
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			t.Fatalf("drain stream after %v: %v", order, rerr)
		}
		if p.Status != "done" || p.Error != "" {
			t.Fatalf("drain progress for %s = %+v, want done", p.VmName, p)
		}
		order = append(order, p.VmName)
	}
	if want := []string{"zz-high", "aa-low", "os1"}; !slices.Equal(order, want) {
		t.Fatalf("drain moved %v, want %v: the highest migrate.priority first, ties in name order", order, want)
	}
}
