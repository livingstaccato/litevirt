package health

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// n10-2: a domain the reconciler finds already running leaves a
// vm.adopted_running event (not a start event), and the refusals' list of
// starts shows it.
func TestReconcilerStart_AlreadyRunningLeavesAnAdoptionEvent(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	r, _, _ := sharedDiskReconciler(t, db)
	fake, _, _ := seedMovedVM(t, db, r.dataDir, "dst", false, false)
	r.virt = fake
	fake.SetState("mv", libvirtfake.StateRunning)
	fresh, _ := corrosion.GetVM(ctx, db, "mv")
	r.startPendingVM(ctx, *fresh)
	evs, err := corrosion.ListVMEvents(ctx, db, "mv", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	n := map[string]int{}
	for _, e := range evs {
		n[e.Type]++
	}
	if n[AdoptedRunningEventType] != 1 || n[StartingEventType] != 0 {
		t.Fatalf("events = %v, want one %s and no %s", n, AdoptedRunningEventType, StartingEventType)
	}
	if txt := MoveStartsText(ctx, db, UnresolvedMove{VM: "mv"}); !strings.Contains(txt, "found running on node-a") {
		t.Fatalf("the list of starts does not show the adoption: %q", txt)
	}
}
