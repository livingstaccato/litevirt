package health

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// F-4. The reconciler's start recorded "started by reconciler after failover"
// whatever made it start the VM, so a start an operator re-armed with `lv start`
// after `lv stop --force`, or an onboot start, read as a failover that never
// happened. The detail names why the VM was started.
//
// Mutation: the detail is the failover text for every start — red.
func TestReconcilerStart_DetailNamesWhyTheVMWasStarted(t *testing.T) {
	for _, tc := range []struct {
		name, state, spec, detail, want, notWant string
		onboot                                   bool
	}{
		{name: "failover", state: "pending", spec: `{}`, want: "after failover"},
		{name: "re-armed operator start", state: "starting", spec: `{}`,
			detail: "operator start: the start cancelled earlier is made again",
			want:   "operator start", notWant: "failover"},
		{name: "onboot", state: "stopped", spec: `{"onboot":true}`, onboot: true,
			want: "onboot", notWant: "failover"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
				Name: "vm1", HostName: "node-a", Spec: tc.spec, State: tc.state, StateDetail: tc.detail}, nil, nil); err != nil {
				t.Fatalf("InsertVM: %v", err)
			}
			fake := libvirtfake.New()
			r := NewReconciler("node-a", t.TempDir(), db, fake)
			if tc.onboot {
				r.StartOnbootVMs(ctx)
			} else {
				vm, _ := corrosion.GetVM(ctx, db, "vm1")
				r.startPendingVM(ctx, *vm)
			}
			vm, err := corrosion.GetVM(ctx, db, "vm1")
			if err != nil || vm == nil {
				t.Fatalf("GetVM: %v %v", vm, err)
			}
			if vm.State != "running" {
				t.Fatalf("state = %q (%q), want running", vm.State, vm.StateDetail)
			}
			if !strings.Contains(vm.StateDetail, tc.want) || (tc.notWant != "" && strings.Contains(vm.StateDetail, tc.notWant)) {
				t.Errorf("state_detail = %q, want it to name %q and not %q", vm.StateDetail, tc.want, tc.notWant)
			}
		})
	}
}
