package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedRemotePivot is node-a's pivoted move of mv's root disk onto a copy on
// a shared nfs pool both hosts define, published as node-a's condition; the
// move began with node-a owning mv at generation 5 (unless owner says
// otherwise, "-" for none). mv is now on node-b at generation vmEpoch, its
// disk row on the source. srcLater sets the source's modification time after
// the copy's (the guest wrote it there since); otherwise the copy is later.
func seedRemotePivot(t *testing.T, db *corrosion.Client, owner string, vmEpoch int64, srcLater bool) (src, dst string) {
	t.Helper()
	ctx := context.Background()
	originDir := t.TempDir()
	_, src, dst = seedMovedVM(t, db, originDir, "dst", true, true)
	ms, _ := UnresolvedMovesOf(originDir, "mv")
	ms[0].DstType = "nfs"
	switch owner {
	case "":
		ms[0].Owner = "node-a"
	case "-":
		ms[0].Owner = ""
	default:
		ms[0].Owner = owner
	}
	ms[0].OwnerEpoch = 5
	if err := RecordUnresolvedMove(originDir, ms[0]); err != nil {
		t.Fatal(err)
	}
	if err := PublishUnresolvedMoves(ctx, db, originDir, "node-a", "mv"); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"node-a", "node-b"} {
		if err := corrosion.UpsertStoragePool(ctx, db, corrosion.StoragePoolRecord{HostName: host, Name: "warm",
			Driver: "nfs", Source: "nas:/vol", Target: filepath.Dir(dst)}); err != nil {
			t.Fatal(err)
		}
	}
	fakeNFSMount(t, filepath.Dir(dst), "nas:/vol")
	if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-b", src, "local", "hot"); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET host_name = 'node-b', vm_owner_epoch = ? WHERE name = 'mv'`, vmEpoch); err != nil {
		t.Fatal(err)
	}
	early, late := time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
	srcT, dstT := early, late
	if srcLater {
		srcT, dstT = late, early
	}
	if err := os.Chtimes(src, srcT, srcT); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(dst, dstT, dstT); err != nil {
		t.Fatal(err)
	}
	return src, dst
}

// I7-1 (was I6-1): with no domain of the VM here (a start rebuilds it from
// the disk row), a pivoted move's row is never pointed at the copy by itself,
// whatever the generation, the start record or the files' times say: those
// are printed for the operator, who chooses with --accept. The row stays on
// the source, both files intact, the condition open, nothing audited as an
// automatic repoint.
func TestResolveRemoteMove_NoDomainNeverRepoints(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		owner      string
		vmEpoch    int64
		srcLater   bool
		startedAt  int64 // a record of this host's start at that generation; 0: none
		equalTimes bool
		reader     bool // a domain reader that finds no domain, as on a real start
		want       string
	}{
		{name: "straight from the holder, one generation on, the copy later", vmEpoch: 6, want: "not defined here"},
		{name: "straight from the holder, a domain reader finding none", vmEpoch: 6, reader: true, want: "not defined here"},
		{name: "this host's start before the move began", vmEpoch: 6, startedAt: 4, want: "not defined here"},
		{name: "two changes of hands", vmEpoch: 7, want: "not defined here"},
		{name: "no change of generation", vmEpoch: 5, want: "not defined here"},
		{name: "the record names no owner", owner: "-", vmEpoch: 6, want: "not defined here"},
		{name: "the move began under another owner", owner: "node-c", vmEpoch: 6, want: "not defined here"},
		{name: "this host started the VM since the move began", vmEpoch: 6, startedAt: 6, want: "started the VM"},
		{name: "the source modified after the copy", vmEpoch: 6, srcLater: true, want: "not defined here"},
		{name: "the same modification times", vmEpoch: 6, equalTimes: true, want: "not defined here"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			src, dst := seedRemotePivot(t, db, tc.owner, tc.vmEpoch, tc.srcLater)
			if tc.equalTimes {
				same := time.Now().Add(-time.Hour)
				for _, p := range []string{src, dst} {
					if err := os.Chtimes(p, same, same); err != nil {
						t.Fatal(err)
					}
				}
			}
			for p, w := range map[string]string{src: "node-b's writes", dst: "node-a's writes"} {
				st, _ := os.Stat(p)
				if err := os.WriteFile(p, []byte(w), 0o600); err != nil {
					t.Fatal(err)
				}
				_ = os.Chtimes(p, st.ModTime(), st.ModTime())
			}
			here := t.TempDir()
			if tc.startedAt != 0 {
				if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ? WHERE name = 'mv'`, tc.startedAt); err != nil {
					t.Fatal(err)
				}
				if err := NoteStartingHere(ctx, db, here, "mv"); err != nil {
					t.Fatal(err)
				}
				if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ? WHERE name = 'mv'`, tc.vmEpoch); err != nil {
					t.Fatal(err)
				}
			}
			dom := MoveDomain{}
			if tc.reader {
				dom = MoveDomain{
					InactiveXML: func() (string, error) { return "", os.ErrNotExist },
					State:       func() (string, error) { return "", errNoDomainForTest },
				}
			}
			err := ResolveUnresolvedMoves(ctx, db, here, "node-b", "mv", dom)
			audits, qerr := db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.auto_repoint'`)
			if qerr != nil {
				t.Fatal(qerr)
			}
			if !IsMoveUnresolved(err) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want a refusal saying %q, got %v", tc.want, err)
			}
			for _, need := range []string{resolveAcceptCmd("mv", src), resolveAcceptCmd("mv", dst), "modified", "bytes",
				"lv events mv"} {
				if !strings.Contains(err.Error(), need) {
					t.Fatalf("the refusal does not say %q: %v", need, err)
				}
			}
			if strings.Contains(err.Error(), "lacks the writes") {
				t.Fatalf("the refusal calls the source stale: %v", err)
			}
			if got := movedRowPath(t, db); got != src {
				t.Fatalf("row names %s, want the source %s kept", got, src)
			}
			if !MoveConditionCovers(ctx, db, "mv", "root") {
				t.Fatal("the condition was closed")
			}
			if len(audits) != 0 {
				t.Fatalf("auto-repoint audited without a repoint: %+v", audits)
			}
			for p, w := range map[string]string{src: "node-b's writes", dst: "node-a's writes"} {
				if b, rerr := os.ReadFile(p); rerr != nil || string(b) != w {
					t.Fatalf("%s = %q %v", p, b, rerr)
				}
			}
		})
	}
}

var errNoDomainForTest = errString("Domain not found: no domain with matching name 'mv'")

type errString string

func (e errString) Error() string { return string(e) }

// m6-2: a VM that changed hands since the move began, with no domain here and
// the copy not on a shared pool here, gets the forked-history text: the
// source is not called stale, and both exits are named.
func TestResolveRemoteMove_NotSharedForkedHistoryText(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	src, dst := seedRemotePivot(t, db, "", 7, true)
	if err := db.Execute(ctx, `DELETE FROM storage_pools WHERE host_name = 'node-b'`); err != nil {
		t.Fatal(err)
	}
	err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-b", "mv", MoveDomain{})
	if !IsMoveUnresolved(err) || strings.Contains(err.Error(), "lacks the writes") ||
		!strings.Contains(err.Error(), resolveAcceptCmd("mv", src)) || !strings.Contains(err.Error(), resolveAcceptCmd("mv", dst)) {
		t.Fatalf("want the forked-history refusal naming both exits, got %v", err)
	}
	if got := movedRowPath(t, db); got != src {
		t.Fatalf("row names %s", got)
	}
}

// m6-3: a hand resolution over unreadable evidence settles a returning
// holder's record of a listed disk only when the record knew nothing more
// than an unpivoted move; a record that knew a pivot is kept and raised again.
func TestPublishUnresolvedMoves_UnreadableHandMarkerReRaisesWhatItDidNotSee(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		pivoted bool
		kept    bool
	}{
		{name: "unpivoted: dropped"},
		{name: "pivoted: kept and raised", pivoted: true, kept: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			dir := t.TempDir()
			seedMovedVM(t, db, dir, "dst", true, tc.pivoted)
			ms, _ := UnresolvedMovesOf(dir, "mv")
			ms[0].At = "2026-10-18T10:00:00Z"
			if err := RecordUnresolvedMove(dir, ms[0]); err != nil {
				t.Fatal(err)
			}
			if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
				t.Fatal(err)
			}
			row, _, open, err := OpenMoveCondition(ctx, db, "mv")
			if err != nil || !open {
				t.Fatalf("condition: %v %v", open, err)
			}
			row.Evidence = `{"hand":true,"hand_disks":["root"],"hand_at":"2026-10-18T11:00:00Z"}`
			row.Lifecycle, row.ResolvedAt = corrosion.ConditionResolved, "2026-10-18T11:00:00Z"
			if err := corrosion.UpsertHealthCondition(ctx, db, row); err != nil {
				t.Fatal(err)
			}
			if err := db.Execute(ctx, `UPDATE vms SET host_name = 'node-b' WHERE name = 'mv'`); err != nil {
				t.Fatal(err)
			}
			if err := PublishUnresolvedMoves(ctx, db, dir, "node-a", "mv"); err != nil {
				t.Fatal(err)
			}
			left, _ := UnresolvedMovesOf(dir, "mv")
			if (len(left) == 1) != tc.kept {
				t.Fatalf("records left = %+v, want kept=%v", left, tc.kept)
			}
			if MoveConditionCovers(ctx, db, "mv", "root") != tc.kept {
				t.Fatalf("condition open = %v, want %v", !tc.kept, tc.kept)
			}
		})
	}
}

// I6-1 residual: every start path records the generation this host started
// the VM at, before the domain starts; a start refused by the heal records
// nothing; a VM deleted or renamed over drops the record.
func TestNoteStartingHere_StartPathsRecordTheGeneration(t *testing.T) {
	ctx := context.Background()
	t.Run("the reconciler's start", func(t *testing.T) {
		db := testReconcilerDB(t)
		r, _, _ := sharedDiskReconciler(t, db)
		fake, _, _ := seedMovedVM(t, db, r.dataDir, "dst", false, false)
		r.virt = fake
		if err := db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 9 WHERE name = 'mv'`); err != nil {
			t.Fatal(err)
		}
		fresh, _ := corrosion.GetVM(ctx, db, "mv")
		r.startPendingVM(ctx, *fresh)
		if g, ok, err := startedHereAt(r.dataDir, "mv"); err != nil || !ok || g != 9 {
			t.Fatalf("start record = %d %v %v, want generation 9", g, ok, err)
		}
		if err := ForgetUnresolvedMoves(ctx, db, r.dataDir, "mv"); err != nil {
			t.Fatal(err)
		}
		if _, ok, _ := startedHereAt(r.dataDir, "mv"); ok {
			t.Fatal("the start record outlived the VM's name")
		}
	})
	t.Run("the health check's restart", func(t *testing.T) {
		db := testReconcilerDB(t)
		dataDir := t.TempDir()
		fake, _, _ := seedMovedVM(t, db, dataDir, "dst", false, false)
		v := NewVMChecker("node-a", dataDir, db, nil)
		v.virt = fake
		if err := v.startGuarded(ctx, "mv"); err != nil {
			t.Fatal(err)
		}
		if _, ok, err := startedHereAt(dataDir, "mv"); err != nil || !ok {
			t.Fatalf("start record = %v %v", ok, err)
		}
	})
	t.Run("a start the heal refuses", func(t *testing.T) {
		db := testReconcilerDB(t)
		dataDir := t.TempDir()
		fake, _, _ := seedMovedVM(t, db, dataDir, "src", true, true)
		v := NewVMChecker("node-a", dataDir, db, nil)
		v.virt = fake
		if err := v.startGuarded(ctx, "mv"); err == nil {
			t.Fatal("started")
		}
		if _, ok, _ := startedHereAt(dataDir, "mv"); ok {
			t.Fatal("a refused start was recorded")
		}
	})
}
