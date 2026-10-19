package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

// I7-2: the owner's disk row may name the copy where another replica's named
// the source (the holder's commit reached this host only), and a host the VM
// passed through since may have run it on the source. The start holds; on the
// owner, with the holder proven powered off and the VM changed hands since the
// move began, `--accept <source>` points the row back at the source (its pool
// and type), keeps the copy on disk and audits the divergence. The same
// gates hold as for a forked history on the source: the owner's config, when
// defined, names the source and the domain is not active; refused while the
// copy is the later file, unless --force.
func TestResolveHealthCondition_RowOnTheCopyAcceptsTheSource(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name          string
		owner         string
		ownerEp, vmEp int64
		define        string
		running       bool
		copyLater     bool
		ok            bool
		want          string
	}{
		{name: "no domain on the owner", owner: "node-a", ownerEp: 3, vmEp: 3, ok: true},
		{name: "shut off, the config names the source", owner: "node-a", ownerEp: 3, vmEp: 4, define: "src", ok: true},
		{name: "the copy modified later", owner: "node-a", ownerEp: 3, vmEp: 4, copyLater: true, want: "--force"},
		{name: "no change of hands since the move", owner: "test-host", ownerEp: 4, vmEp: 4, want: "--accept "},
		{name: "running on the source", owner: "node-a", ownerEp: 3, vmEp: 4, define: "src", running: true, want: "lv stop vm1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, src, dst := forkedMoveServer(t, tc.owner, tc.ownerEp, tc.vmEp, tc.define, tc.running)
			if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst, "nfs", "warm"); err != nil {
				t.Fatal(err)
			}
			if tc.copyLater {
				setModTimes(t, src, dst)
			}
			_, err := s.ResolveHealthCondition(acceptCtx(src), moveResolveReq("ran on the source on another host"))
			for p, w := range forkWrites(src, dst) {
				if b, rerr := os.ReadFile(p); rerr != nil || string(b) != w {
					t.Fatalf("%s = %q %v, want it kept as it was", p, b, rerr)
				}
			}
			if !tc.ok {
				w := tc.want
				if w == "--accept " {
					w += dst
				}
				mustRefuse(t, s, err, dst, w)
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if r := diskRowOf(t, s, "root"); r.Path != src || r.StorageType != "ceph" || r.StorageVolume != "hot" {
				t.Fatalf("row = %+v, want the source", r)
			}
			if health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
				t.Fatal("the condition is still open")
			}
			rows, qerr := s.db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
			if qerr != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), dst) ||
				!strings.Contains(rows[0].String("detail"), "kept on disk") {
				t.Fatalf("divergence audit = %+v %v, want one row naming %s kept on disk", rows, qerr, dst)
			}
		})
	}
}

// m7-1: the replaced VM's restart after a cutover records this host's start
// of it, as every other start path does, so a later heal here with its
// domain gone is held by its own start.
func TestCutoverRestart_RecordsThisHostsStart(t *testing.T) {
	s, _, _, _ := firmwareFixture(t)
	if _, err := s.CutoverVM(adminCtx(), &pb.CutoverVMRequest{VmName: "app"}); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	if st, _ := s.virt.DomainState("app"); st != "running" {
		t.Fatalf("app is %q, want running", st)
	}
	ents, err := os.ReadDir(filepath.Join(s.dataDir, health.StartedHereDirName))
	if err != nil || len(ents) != 1 {
		t.Fatalf("start records = %v %v, want one", ents, err)
	}
}

// I7-1: the clean failover (the holder pivoted and was lost, the VM came here
// and ran nowhere since) is held by the start with no domain here; one
// `--accept <copy>` on the owner, with the holder proven powered off, points
// the row at the copy and resolves it.
func TestResolveHealthCondition_CleanFailoverNeedsOneAcceptOfTheCopy(t *testing.T) {
	ctx := context.Background()
	s, src, dst := forkedMoveServer(t, "node-a", 3, 3, "", false)
	setModTimes(t, src, dst)
	if _, err := s.ResolveHealthCondition(acceptCtx(dst), moveResolveReq("nothing ran it since the failover")); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r := diskRowOf(t, s, "root"); r.Path != dst || r.StorageType != "nfs" || r.StorageVolume != "warm" {
		t.Fatalf("row = %+v, want the copy", r)
	}
	if health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
		t.Fatal("the condition is still open")
	}
	if _, err := os.Stat(src); err != nil {
		t.Fatalf("the source is gone: %v", err)
	}
}
