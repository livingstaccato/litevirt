package health

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// I7-2: a disk row naming the copy is no proof once the VM changed hands
// since the move began. Replicas can disagree on it (a host that missed the
// holder's commit names the source and may have run the VM on it), so the
// heal holds with both exits named instead of letting the start boot the
// copy, and the condition stays open. With no change of hands the row on the
// copy settles the move, as before.
func TestResolveRemoteMove_RowOnTheCopyAfterAChangeOfHandsHolds(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		host    string // the VM's owner now
		epoch   int64
		define  string // "dst": a shut-off domain here whose config names the copy
		heal    string // the healing host
		holds   bool
		wantTxt string
	}{
		{name: "rescheduled here, one generation on", host: "node-b", epoch: 6, heal: "node-b", holds: true},
		{name: "rescheduled here, no new generation", host: "node-b", epoch: 5, heal: "node-b", holds: true},
		{name: "rescheduled here, the config here names the copy", host: "node-b", epoch: 6, define: "dst", heal: "node-b", holds: true},
		{name: "a later generation on the same owner", host: "node-a", epoch: 6, heal: "node-a", holds: true},
		{name: "no change of hands", host: "node-a", epoch: 5, heal: "node-a"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			src, dst := seedRemotePivot(t, db, "", tc.epoch, true)
			if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", tc.host, dst, "nfs", "warm"); err != nil {
				t.Fatal(err)
			}
			if err := db.Execute(ctx, `UPDATE vms SET host_name = ? WHERE name = 'mv'`, tc.host); err != nil {
				t.Fatal(err)
			}
			for p, w := range map[string]string{src: "node-b's writes", dst: "node-a's writes"} {
				st, _ := os.Stat(p)
				if err := os.WriteFile(p, []byte(w), 0o600); err != nil {
					t.Fatal(err)
				}
				_ = os.Chtimes(p, st.ModTime(), st.ModTime())
			}
			dom := MoveDomain{}
			if tc.define != "" {
				f := libvirtfake.New()
				if err := f.DefineDomain(moveDomainXML("mv", dst)); err != nil {
					t.Fatal(err)
				}
				dom = MoveDomain{
					InactiveXML: func() (string, error) { return f.DumpXMLInactive("mv") },
					State:       func() (string, error) { return f.DomainState("mv") },
				}
			}
			err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), tc.heal, "mv", dom)
			if !tc.holds {
				if err != nil {
					t.Fatalf("heal: %v", err)
				}
				return
			}
			if !IsMoveUnresolved(err) {
				t.Fatalf("want a refusal, got %v", err)
			}
			for _, need := range []string{resolveAcceptCmd("mv", src), resolveAcceptCmd("mv", dst), "changed hands",
				"modified", "bytes", "lv events mv", "on the VM's owner " + tc.host + " (LV_HOST=" + tc.host + ")"} {
				if !strings.Contains(err.Error(), need) {
					t.Fatalf("the refusal does not say %q: %v", need, err)
				}
			}
			if strings.Contains(err.Error(), "lacks the writes") {
				t.Fatalf("the refusal calls the source stale: %v", err)
			}
			if got := movedRowPath(t, db); got != dst {
				t.Fatalf("row names %s, want it left on %s", got, dst)
			}
			if !MoveConditionCovers(ctx, db, "mv", "root") {
				t.Fatal("the condition was closed")
			}
			for p, w := range map[string]string{src: "node-b's writes", dst: "node-a's writes"} {
				if b, rerr := os.ReadFile(p); rerr != nil || string(b) != w {
					t.Fatalf("%s = %q %v", p, b, rerr)
				}
			}
		})
	}
}

// m7-2: the forked-history refusal reached because the disk row names a third
// host, with the copy on a shared pool here, says so instead of calling the
// pool unshared.
func TestResolveRemoteMove_RowOnAnotherHostForkText(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	src, _ := seedRemotePivot(t, db, "", 6, true)
	if err := corrosion.UpdateDiskPlacement(ctx, db, "mv", "root", "node-c", src, "local", "hot"); err != nil {
		t.Fatal(err)
	}
	err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-b", "mv", MoveDomain{})
	if !IsMoveUnresolved(err) || !strings.Contains(err.Error(), "the disk row names host node-c") ||
		strings.Contains(err.Error(), "not on a shared pool") {
		t.Fatalf("want the fork text naming the row's host, got %v", err)
	}
}

// m7-3: the one automatic repoint left in the remote heal (a shut-off domain
// here whose persistent config names the copy) audits the evidence it used.
func TestResolveRemoteMove_AutoRepointAuditNamesItsEvidence(t *testing.T) {
	ctx := context.Background()
	db := testReconcilerDB(t)
	_, dst := seedRemotePivot(t, db, "", 6, false)
	f := libvirtfake.New()
	if err := f.DefineDomain(moveDomainXML("mv", dst)); err != nil {
		t.Fatal(err)
	}
	dom := MoveDomain{
		InactiveXML: func() (string, error) { return f.DumpXMLInactive("mv") },
		State:       func() (string, error) { return f.DomainState("mv") },
	}
	if err := ResolveUnresolvedMoves(ctx, db, t.TempDir(), "node-b", "mv", dom); err != nil {
		t.Fatalf("heal: %v", err)
	}
	if got := movedRowPath(t, db); got != dst {
		t.Fatalf("row names %s, want %s", got, dst)
	}
	rows, err := db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.auto_repoint'`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit = %+v %v", rows, err)
	}
	d := rows[0].String("detail")
	if !strings.Contains(d, "persistent config") || !strings.Contains(d, "shared pool") ||
		strings.Contains(d, "no start elsewhere") {
		t.Fatalf("auto-repoint audit = %q, want the config and shared-pool evidence", d)
	}
}
