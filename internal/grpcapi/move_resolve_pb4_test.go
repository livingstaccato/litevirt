package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// I8-3: `--accept <src>` over a forked history whose owner's persistent config
// names the copy points that config at the source (the domain shut off) as
// well as the row, under the forked-history gates; with the domain running it
// is refused with `lv stop`, never with a text calling the source stale.
// The source is the later file.
func TestResolveHealthCondition_ForkAcceptOfTheSourceRepointsTheConfig(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name     string
		rowOnDst bool
		running  bool
		want     string
	}{
		{name: "row on the copy", rowOnDst: true},
		{name: "row on the source"},
		{name: "running on the copy", rowOnDst: true, running: true, want: "lv stop vm1"},
		{name: "running on the copy, row on the source", running: true, want: "lv stop vm1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "dst", tc.running)
			if tc.rowOnDst {
				if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst, "nfs", "warm"); err != nil {
					t.Fatal(err)
				}
			}
			row := diskRowOf(t, s, "root").Path
			_, err := s.ResolveHealthCondition(acceptCtx(src), moveResolveReq("ran on the source elsewhere"))
			if tc.want != "" {
				mustRefuse(t, s, err, row, tc.want)
				if strings.Contains(err.Error(), "lacks the writes") {
					t.Fatalf("the refusal calls the source stale: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if r := diskRowOf(t, s, "root"); r.Path != src {
				t.Fatalf("row = %+v, want the source", r)
			}
			x, _ := fakeOf(t, s).DumpXMLInactive("vm1")
			if !strings.Contains(x, src) || strings.Contains(x, dst) {
				t.Fatalf("persistent config = %s, want it on %s", x, src)
			}
			rows, qerr := s.db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
			if qerr != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "persistent config") {
				t.Fatalf("divergence audit = %+v %v, want it to name the config change", rows, qerr)
			}
		})
	}
}

// I8-3: on a host that does not own the VM, `--accept <src>` over a forked
// history is refused with where it runs, not with a stale-source text.
func TestResolveHealthCondition_ForkAcceptOfTheSourceOffTheOwner(t *testing.T) {
	ctx := context.Background()
	s, src, _ := forkedMoveServer(t, "node-a", 3, 4, "", false)
	if err := s.db.Execute(ctx, `UPDATE vms SET host_name = 'node-c' WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	_, err := s.ResolveHealthCondition(acceptCtx(src), moveResolveReq("x"))
	mustRefuse(t, s, err, src, "LV_HOST=node-c")
	if strings.Contains(err.Error(), "lacks the writes") {
		t.Fatalf("the refusal calls the source stale: %v", err)
	}
}

// I8-2: the holder that got the VM back after it changed hands resolves its
// held move itself: `--accept <src>` points its config and row at the source.
func TestResolveHealthCondition_HolderOwnerAcceptsTheSourceAfterAChangeOfHands(t *testing.T) {
	ctx := context.Background()
	s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "dst", false)
	s.hostName = "node-a"
	if err := s.db.Execute(ctx, `UPDATE vms SET host_name = 'node-a' WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "node-a", dst, "nfs", "warm"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ResolveHealthCondition(acceptCtx(src), moveResolveReq("node-b ran it on the source")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r := diskRowOf(t, s, "root"); r.Path != src {
		t.Fatalf("row = %+v, want the source", r)
	}
	if x, _ := fakeOf(t, s).DumpXMLInactive("vm1"); !strings.Contains(x, src) {
		t.Fatalf("persistent config = %s", x)
	}
}

// m8-2: the readers of a running domain's own file pass the forked-history
// hold through the server's wrapper; a boot of the same VM is held.
func TestResolveUnresolvedMovesFor_RunningReaderPasses(t *testing.T) {
	ctx := context.Background()
	s, _, dst := forkedMoveServer(t, "node-a", 3, 4, "dst", true)
	if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst, "nfs", "warm"); err != nil {
		t.Fatal(err)
	}
	if st, _ := fakeOf(t, s).DomainState("vm1"); st != "running" {
		t.Fatalf("domain %q", st)
	}
	if err := s.resolveUnresolvedMovesFor(ctx, "vm1", health.MoveUseReadsRunning); err != nil {
		t.Fatalf("a reader of the running file: %v", err)
	}
	if err := s.resolveUnresolvedMovesFor(ctx, "vm1", health.MoveUseMigratesRunning); err != nil {
		t.Fatalf("a live migration without storage: %v", err)
	}
	if err := s.resolveUnresolvedMoves(ctx, "vm1"); !health.IsMoveUnresolved(err) {
		t.Fatalf("a boot: %v, want held", err)
	}
	if !health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
		t.Fatal("the condition was closed")
	}
}
