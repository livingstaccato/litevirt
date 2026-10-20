package health

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// m9-2: the starts listed for an operator may be incomplete whether or not
// any is listed (another host's clock, the event prune, the row window, an
// older build), and the text says so in both cases.
func TestMoveStartsText_SaysTheListMayBeIncomplete(t *testing.T) {
	ctx := context.Background()
	for _, started := range []bool{false, true} {
		db := testReconcilerDB(t)
		seedMovedVM(t, db, t.TempDir(), "src", true, true)
		if started {
			if err := corrosion.InsertVMEvent(ctx, db, corrosion.VMEventRecord{VMName: "mv", HostName: "node-b",
				Type: StartingEventType, Detail: "starting on node-b at ownership generation 6"}); err != nil {
				t.Fatal(err)
			}
		}
		txt := MoveStartsText(ctx, db, UnresolvedMove{VM: "mv"})
		for _, need := range []string{"may be incomplete", "clock", "pruned", "lv events mv"} {
			if !strings.Contains(txt, need) {
				t.Fatalf("started=%v: %q does not say %q", started, txt, need)
			}
		}
	}
}

// m9-3: the reconciler records a start event only for a start it makes, not
// for a domain it finds already running.
func TestReconcilerStart_AlreadyRunningRecordsNoStartEvent(t *testing.T) {
	ctx := context.Background()
	for _, running := range []bool{false, true} {
		db := testReconcilerDB(t)
		r, _, _ := sharedDiskReconciler(t, db)
		fake, _, _ := seedMovedVM(t, db, r.dataDir, "dst", false, false)
		r.virt = fake
		if running {
			fake.SetState("mv", libvirtfake.StateRunning)
		}
		fresh, _ := corrosion.GetVM(ctx, db, "mv")
		r.startPendingVM(ctx, *fresh)
		evs, err := corrosion.ListVMEvents(ctx, db, "mv", 100, "")
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, e := range evs {
			if e.Type == StartingEventType {
				n++
			}
		}
		if want := map[bool]int{false: 1, true: 0}[running]; n != want {
			t.Fatalf("already running=%v: %d start events, want %d", running, n, want)
		}
	}
}
