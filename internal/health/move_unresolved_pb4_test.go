package health

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// I8-1: every start this guard records also leaves a replicated vm.starting
// event (`lv events <vm>` lists it), and the forked-history refusals name
// those starts since the move began, or say that none is recorded and that
// the absence proves nothing. They no longer name `lv audit ls --action
// vm.start`, which lists only overcommitted starts.
func TestNoteStartingHere_RecordsAReplicatedStartEvent(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	dir := t.TempDir()
	seedMovedVM(t, db, dir, "src", true, true)
	for i := 0; i < 2; i++ {
		if err := NoteStartingHere(ctx, db, dir, "mv"); err != nil {
			t.Fatal(err)
		}
	}
	evs, err := corrosion.ListVMEvents(ctx, db, "mv", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range evs {
		if e.Type == StartingEventType {
			n++
			if !strings.Contains(e.Detail, "generation") {
				t.Fatalf("event detail %q names no generation", e.Detail)
			}
		}
	}
	if n != 2 {
		t.Fatalf("%d %s events, want one per start: %+v", n, StartingEventType, evs)
	}
}

func TestResolveRemoteMove_ForkTextListsTheRecordedStarts(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		started bool
		want    string
	}{
		{name: "a start recorded since the move", started: true, want: "node-b at ownership generation 6"},
		{name: "none recorded", want: "absence proves nothing"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			seedRemotePivot(t, db, "", 6, true)
			if tc.started {
				if err := corrosion.InsertVMEvent(ctx, db, corrosion.VMEventRecord{VMName: "mv", HostName: "node-b",
					Type: StartingEventType, Detail: "starting on node-b at ownership generation 6"}); err != nil {
					t.Fatal(err)
				}
			}
			err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-b", "mv", MoveDomain{})
			if !IsMoveUnresolved(err) || !strings.Contains(err.Error(), tc.want) ||
				!strings.Contains(err.Error(), "lv events mv") || strings.Contains(err.Error(), "--action vm.start") {
				t.Fatalf("want the refusal to list the starts (%q) and name `lv events mv`, got %v", tc.want, err)
			}
		})
	}
}

// I8-2: the move's holder that gets the VM back after it changed hands does
// not trust its own persistent config naming the copy: another host may have
// run the VM on the source since. Its start holds with both exits; with no
// change of hands it settles onto the copy as before.
func TestResolveUnresolvedMove_HolderAfterAChangeOfHandsHolds(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		epoch int64
		holds bool
	}{
		{name: "back on the holder one generation on", epoch: 6, holds: true},
		{name: "never left the holder", epoch: 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			dir := t.TempDir()
			fake, src, dst := seedMovedVM(t, db, dir, "dst", true, true)
			ms, _ := UnresolvedMovesOf(dir, "mv")
			ms[0].Owner, ms[0].OwnerEpoch = "node-a", 5
			if err := RecordUnresolvedMove(dir, ms[0]); err != nil {
				t.Fatal(err)
			}
			if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-a", dst, "local", "warm"); err != nil {
				t.Fatal(err)
			}
			if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ? WHERE name = 'mv'`, tc.epoch); err != nil {
				t.Fatal(err)
			}
			err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", fakeMoveDomain(fake))
			if !tc.holds {
				if err != nil {
					t.Fatalf("heal: %v", err)
				}
				if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 0 {
					t.Fatalf("record kept: %+v", left)
				}
				return
			}
			if !IsMoveUnresolved(err) || !strings.Contains(err.Error(), "changed hands") ||
				!strings.Contains(err.Error(), resolveAcceptCmd("mv", src)) || !strings.Contains(err.Error(), resolveAcceptCmd("mv", dst)) {
				t.Fatalf("want the forked-history hold naming both exits, got %v", err)
			}
			if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 1 {
				t.Fatalf("record dropped: %+v", left)
			}
			if !MoveConditionCovers(ctx, db, "mv", "root") {
				t.Fatal("the hold raised no condition")
			}
		})
	}
}

// I8-2: an admin's `--accept <src>` on the VM's owner while the holder was
// away is never undone by the holder's own heal when the VM comes back to it:
// with its config naming the copy it holds (the row stays on the source);
// with its config naming the source the record settles and nothing changes.
func TestResolveUnresolvedMove_HolderNeverUndoesAHandResolution(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		config string
		holds  bool
	}{
		{name: "the holder's config names the copy", config: "dst", holds: true},
		{name: "the holder's config names the source", config: "src"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			dir := t.TempDir()
			fake, src, _ := seedMovedVM(t, db, dir, tc.config, true, true)
			ms, _ := UnresolvedMovesOf(dir, "mv")
			ms[0].Owner, ms[0].OwnerEpoch, ms[0].At = "node-a", 5, "2026-10-18T10:00:00Z"
			if err := RecordUnresolvedMove(dir, ms[0]); err != nil {
				t.Fatal(err)
			}
			if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
				t.Fatal(err)
			}
			// node-b ran it on the source; an admin kept the source there.
			if err := db.Execute(ctx, `UPDATE vms SET host_name = 'node-b', vm_owner_epoch = 6 WHERE name = 'mv'`); err != nil {
				t.Fatal(err)
			}
			handResolve(t, db, "mv", true)
			// node-b is lost; the VM comes back to node-a.
			if err := db.Execute(ctx, `UPDATE vms SET host_name = 'node-a' WHERE name = 'mv'`); err != nil {
				t.Fatal(err)
			}
			err := ResolveUnresolvedMoves(ctx, db, dir, "node-a", "mv", fakeMoveDomain(fake))
			if got := movedRowPath(t, db); got != src {
				t.Fatalf("row names %s, want the admin's %s kept", got, src)
			}
			if !tc.holds {
				if err != nil {
					t.Fatalf("heal: %v", err)
				}
				if left, _ := UnresolvedMovesOf(dir, "mv"); len(left) != 0 {
					t.Fatalf("record kept: %+v", left)
				}
				return
			}
			if !IsMoveUnresolved(err) || !strings.Contains(err.Error(), "by hand") {
				t.Fatalf("want a hold naming the hand resolution, got %v", err)
			}
		})
	}
}

// m8-2: with the VM's domain running here, an operation that cannot pick the
// wrong copy is not refused by the forked-history holds: a live migration
// without storage (the running qemu keeps the file it opened), and a reader
// of the running domain's own file. The condition stays open for the next
// start. A reader of another file, or a caller that boots, is held.
func TestResolveRemoteMove_RunningUsesThatCannotPickTheWrongCopy(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		use     MoveUse
		live    string // the file the running domain's live disk names: "dst" or "src"
		stopped bool   // the domain is shut off
		holds   bool
	}{
		{name: "a boot is held", use: MoveUseBoots, live: "dst", holds: true},
		{name: "a live migration without storage", use: MoveUseMigratesRunning, live: "src"},
		{name: "a reader of the running domain's own file", use: MoveUseReadsRunning, live: "dst"},
		{name: "a reader of another file than the running one", use: MoveUseReadsRunning, live: "src", holds: true},
		{name: "a migration of a shut-off domain (cold) is held", use: MoveUseMigratesRunning, live: "dst", stopped: true, holds: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			src, dst := seedRemotePivot(t, db, "", 6, true)
			if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-b", dst, "nfs", "warm"); err != nil {
				t.Fatal(err)
			}
			live := dst
			if tc.live == "src" {
				live = src
			}
			f := libvirtfake.New()
			if err := f.DefineDomain(moveDomainXML("mv", dst)); err != nil {
				t.Fatal(err)
			}
			if !tc.stopped {
				f.SetState("mv", libvirtfake.StateRunning)
			}
			dom := fakeMoveDomain(f)
			dom.LiveXML = func() (string, error) { return moveDomainXML("mv", live), nil }
			dom.Use = tc.use
			err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-b", "mv", dom)
			if tc.holds != IsMoveUnresolved(err) || (!tc.holds && err != nil) {
				t.Fatalf("err = %v, want held=%v", err, tc.holds)
			}
			if got := movedRowPath(t, db); got != dst {
				t.Fatalf("row names %s", got)
			}
			if !MoveConditionCovers(ctx, db, "mv", "root") {
				t.Fatal("the condition was closed")
			}
		})
	}
}

func fakeMoveDomain(f *libvirtfake.Fake) MoveDomain {
	return MoveDomain{
		InactiveXML: func() (string, error) { return f.DumpXMLInactive("mv") },
		State:       func() (string, error) { return f.DomainState("mv") },
	}
}
