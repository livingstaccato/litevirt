package grpcapi

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// m10-1: keeping the copy over a forked history fails closed. Off the VM's
// owner it is refused with where to run it, --force or not; on the owner, a
// file that cannot be read here is refused unless --force.
func TestResolveHealthCondition_KeepingTheCopyFailsClosed(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name       string
		offOwner   bool
		unreadable bool
		force      bool
		ok         bool
		want       string
	}{
		{name: "off the owner", offOwner: true, want: "LV_HOST=node-c"},
		{name: "off the owner, --force", offOwner: true, force: true, want: "LV_HOST=node-c"},
		{name: "the source unreadable on the owner", unreadable: true, want: "cannot be read here"},
		{name: "the source unreadable on the owner, --force", unreadable: true, force: true, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "", false)
			setModTimes(t, src, dst) // the copy is the later file: only the new gates can refuse
			if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst, "nfs", "warm"); err != nil {
				t.Fatal(err)
			}
			if tc.offOwner {
				if err := s.db.Execute(ctx, `UPDATE vms SET host_name = 'node-c' WHERE name = 'vm1'`); err != nil {
					t.Fatal(err)
				}
			}
			if tc.unreadable {
				if err := os.Remove(src); err != nil {
					t.Fatal(err)
				}
			}
			rctx := acceptCtx(dst)
			if tc.force {
				rctx = forceCtx(dst)
			}
			_, err := s.ResolveHealthCondition(rctx, moveResolveReq("keep the copy"))
			if !tc.ok {
				mustRefuse(t, s, err, dst, tc.want)
				if !health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
					t.Fatal("the condition was closed")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			rows, qerr := s.db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
			if qerr != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "--force") {
				t.Fatalf("divergence audit = %+v %v, want the forced keep", rows, qerr)
			}
		})
	}
}

// m10-2: with the running guest on a file the row does not name, the only
// exit offered is `lv stop`: no --accept that the next gate refuses.
func TestResolveHealthCondition_RunningDivergedOffersOnlyStop(t *testing.T) {
	for _, accept := range []string{"", "dst"} {
		s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "src", true)
		fakeOf(t, s).SetActiveXML("vm1", fakeDomainXML("vm1", "vda", dst))
		rctx := adminCtx()
		if accept == "dst" {
			rctx = acceptCtx(dst)
		}
		_, err := s.ResolveHealthCondition(rctx, moveResolveReq("x"))
		mustRefuse(t, s, err, src, "lv stop vm1")
		for _, loop := range []string{"--accept " + dst, "--accept " + src} {
			if strings.Contains(err.Error(), loop) {
				t.Fatalf("accept=%q: the refusal offers %q, which a gate refuses: %v", accept, loop, err)
			}
		}
	}
	// The live file is the row's: --accept of it is the exit.
	s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "src", true)
	_, err := s.ResolveHealthCondition(acceptCtx(dst), moveResolveReq("x"))
	mustRefuse(t, s, err, src, "--accept "+src)
}

// n10-1: a catch-up move's refusal does not say the guest was pivoted.
func TestResolveHealthCondition_CatchUpRefusalSaysWhatHappened(t *testing.T) {
	ctx := context.Background()
	s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "", false)
	row, ev, open, err := health.OpenMoveCondition(ctx, s.db, "vm1")
	if err != nil || !open {
		t.Fatalf("condition: %v %v", open, err)
	}
	ev.Moves[0].Pivoted, ev.Moves[0].CatchUp, ev.Moves[0].Live = false, true, false
	b, _ := json.Marshal(ev)
	row.Evidence = string(b)
	if err := corrosion.UpsertHealthCondition(ctx, s.db, row); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst, "nfs", "warm"); err != nil {
		t.Fatal(err)
	}
	_, err = s.ResolveHealthCondition(acceptCtx(dst), moveResolveReq("x"))
	mustRefuse(t, s, err, dst, "named "+dst+" in the persistent config before the move")
	if strings.Contains(err.Error(), "pivoted") {
		t.Fatalf("a catch-up called a pivot: %v", err)
	}
	_ = src
}
