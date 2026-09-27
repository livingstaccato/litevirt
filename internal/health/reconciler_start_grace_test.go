package health

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A VM the reconciler boots — an onboot start at daemon startup, a pending
// start after a failover — opens the healthcheck's start grace. The
// healthcheck's first sweep after a daemon start sees every VM for the first
// time and cannot tell a VM that has run for weeks from one booting now, so a
// first sighting there opens no grace: without being told, it probed the
// still-booting guest and restarted or migrated it.
func TestReconcilerStart_OpensTheHealthcheckStartGrace(t *testing.T) {
	for _, path := range []string{"onboot", "pending"} {
		t.Run(path, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			state, spec := "stopped", `{"onboot":true}`
			if path == "pending" {
				state, spec = "pending", `{}`
			}
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm1", HostName: "node-a", Spec: spec, State: state}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
			if err := db.Execute(ctx, `UPDATE vms SET created_at = ? WHERE name = 'vm1'`, old); err != nil {
				t.Fatalf("backdate created_at: %v", err)
			}

			fake := libvirtfake.New()
			vc := NewVMChecker("node-a", t.TempDir(), db, nil)
			r := NewReconciler("node-a", t.TempDir(), db, fake)
			r.SetVMStartObserver(vc)

			if path == "onboot" {
				r.StartOnbootVMs(ctx)
			} else {
				vm, _ := corrosion.GetVM(ctx, db, "vm1")
				r.startPendingVM(ctx, *vm)
			}
			if !startedOrDefined(fake, "vm1") {
				t.Fatal("the reconciler did not start vm1")
			}
			vm, err := corrosion.GetVM(ctx, db, "vm1")
			if err != nil || vm == nil {
				t.Fatalf("GetVM: %v %v", vm, err)
			}
			// The checker's first sweep: a first sighting, which on its own opens
			// no grace.
			vc.observeStarts([]corrosion.VMRecord{*vm}, time.Now())
			if !vc.inStartGrace(*vm, time.Now()) {
				t.Fatalf("vm1 is not in its start grace after the reconciler's %s start: its first probe "+
					"failure would act on a guest that is still booting", path)
			}
		})
	}
}
