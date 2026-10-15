package health

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// CR7-3: a VM in error whose held start `lv stop --force` cancelled keeps its
// row error, and the domain libvirt starts for it late is destroyed by the
// cancelled-starts sweep. The reconciler, which records a running domain
// under an error row as running, leaves such a VM alone; any other errored VM
// whose domain runs is still recorded running.
//
// Mutation: the probe not consulted — vm-cancelled is written running: red.
func TestReconciler_AnErroredVMWithACancelledStartIsNotRecordedRunning(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	fake := libvirtfake.New()
	for _, name := range []string{"vm-cancelled", "vm-other"} {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: name, HostName: "host-a", Spec: `{"cpu":1,"memory":512}`, State: "error", StateDetail: "failover start failed",
		}, nil, nil); err != nil {
			t.Fatalf("InsertVM: %v", err)
		}
		if err := fake.DefineDomain("<domain><name>" + name + "</name></domain>"); err != nil {
			t.Fatal(err)
		}
		if err := fake.StartDomain(name); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReconciler("host-a", t.TempDir(), db, fake)
	r.SetCancelledStartProbe(func(vm, _, _ string) bool { return vm == "vm-cancelled" })
	r.reconcile(ctx)

	if vm, err := corrosion.GetVM(ctx, db, "vm-cancelled"); err != nil || vm.State != "error" {
		t.Fatalf("vm-cancelled after a pass: %+v %v, want error", vm, err)
	}
	if vm, err := corrosion.GetVM(ctx, db, "vm-other"); err != nil || vm.State != "running" {
		t.Fatalf("vm-other after a pass: %+v %v, want running", vm, err)
	}
}

// Round 1, I-1: the VM checker's restart-policy pass neither heals a VM with
// a cancelled start here to running nor starts it under its restart policy;
// a VM without one is still restarted.
//
// Mutation: the probe not consulted in the checker — vm-cancelled is
// restarted: red.
func TestVMChecker_AVMWithACancelledStartIsNotRestarted(t *testing.T) {
	db := testStartDB(t)
	seedRestartPolicyVM(t, db, "vm-cancelled", "node1")
	seedRestartPolicyVM(t, db, "vm-other", "node1")
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	v.SetCancelledStartProbe(func(vm, _, _ string) bool { return vm == "vm-cancelled" })
	v.SweepOnce(context.Background())
	if got := restartAttempts(t, db, "vm-cancelled"); got != 0 {
		t.Fatalf("vm-cancelled restart attempts = %d, want 0", got)
	}
	if got := restartAttempts(t, db, "vm-other"); got == 0 {
		t.Fatal("vm-other was not restarted: the probe stops more than the VM it names")
	}
}
