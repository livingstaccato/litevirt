package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// I4-1: on the holder that owns the VM, a config and a row that both name the
// copy of a live move with no pivot recorded prove only that the define ran:
// the resolve is refused without --accept, as the holder's own settle refuses
// that state. --accept of the copy, or a config and row on the source (no
// pivot can have happened), resolve it.
func TestResolveHealthCondition_HolderConfigAndRowOnTheCopyUnpivoted(t *testing.T) {
	ctx := context.Background()
	onCopy := func(t *testing.T) (*Server, string, string) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dstFile, "local", "warm"); err != nil {
			t.Fatal(err)
		}
		return s, srcFile, dstFile
	}
	t.Run("no --accept: refused", func(t *testing.T) {
		s, srcFile, dstFile := onCopy(t)
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("config and row agree"))
		mustRefuse(t, s, err, dstFile, "recorded no pivot", "--accept", srcFile)
		if ms := moveRecords(t, s, "vm1"); len(ms) != 1 {
			t.Fatalf("records: %+v", ms)
		}
	})
	t.Run("--accept the copy", func(t *testing.T) {
		s, _, dstFile := onCopy(t)
		if _, err := s.ResolveHealthCondition(acceptCtx(dstFile), moveResolveReq("pivoted by hand before the crash")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if health.MoveConditionCovers(ctx, s.db, "vm1", "root") || diskRowPath(t, s, "vm1") != dstFile {
			t.Fatal("not resolved onto the accepted copy")
		}
	})
}

// fakeOf is s's libvirt fake.
func fakeOf(t *testing.T, s *Server) *libvirtfake.Fake {
	t.Helper()
	f, ok := s.virt.(*libvirtfake.Fake)
	if !ok {
		t.Fatal("not a libvirtfake")
	}
	return f
}

// I4-2: a hand resolution never repoints the owner's disk row under the
// owner's domain: not while it runs, not while its persistent config names the
// other file, and never from a holder that is not the owner (it cannot read
// that domain). The holder may still keep the file the row names.
func TestResolveHealthCondition_NeverRepointsUnderTheOwnersDomain(t *testing.T) {
	ctx := context.Background()
	t.Run("owner: the domain runs: refused", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root")
		f := fakeOf(t, s)
		if err := f.DefineDomain(fakeDomainXML("vm1", "vda", src["root"])); err != nil {
			t.Fatal(err)
		}
		f.SetState("vm1", libvirtfake.StateRunning)
		_, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x"))
		mustRefuse(t, s, err, src["root"], "is active", "lv stop vm1")
	})
	t.Run("owner: the persistent config names the other file: refused", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root")
		if err := fakeOf(t, s).DefineDomain(fakeDomainXML("vm1", "vda", src["root"])); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x"))
		mustRefuse(t, s, err, src["root"], "names "+src["root"], "virsh edit vm1")
	})
	t.Run("owner: the persistent config names the accepted file", func(t *testing.T) {
		s, _, dst := sharedMoveServer(t, "root")
		if err := fakeOf(t, s).DefineDomain(fakeDomainXML("vm1", "vda", dst["root"])); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if diskRowOf(t, s, "root").Path != dst["root"] {
			t.Fatal("row not on the accepted file")
		}
	})
	t.Run("holder, not the owner: a row change is refused", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root")
		s.hostName = "node-a"
		_, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x"))
		mustRefuse(t, s, err, src["root"], "owner test-host", "LV_HOST=test-host")
	})
	t.Run("holder, not the owner: keeping the row's file resolves", func(t *testing.T) {
		s, src, _ := sharedMoveServer(t, "root")
		s.hostName = "node-a"
		if _, err := s.ResolveHealthCondition(acceptCtx(src["root"]), moveResolveReq("the source is newer")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if diskRowOf(t, s, "root").Path != src["root"] || health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
			t.Fatal("not resolved on the row's file")
		}
	})
}

// I3-2 (re-review 4, section D): the resolve runs under the VM's lock. A
// move-volume holds that lock across its whole move, so a resolve that
// arrives meanwhile waits, and the move's record and condition survive it.
func TestResolveHealthCondition_WaitsForTheVMLock(t *testing.T) {
	ctx := context.Background()
	s, f, srcFile, dstFile := offlineMoveServer(t)
	crashAfterDefine(t, s, f, srcFile, dstFile, srcFile, true, false)
	unlock := s.lockVM("vm1")
	wctx, cancel := context.WithTimeout(adminCtx(), 300*time.Millisecond)
	_, err := s.ResolveHealthCondition(wctx, moveResolveReq("config and row on the source"))
	cancel()
	if err == nil {
		unlock()
		t.Fatal("resolved while a move held the VM lock")
	}
	// The move (holding the lock) records its retry, then its process dies.
	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	mk, merr := s.beginMoveMarker(ctx, vm, &disks[0], dstFile, "local", "warm", true, false, false)
	if merr != nil {
		unlock()
		t.Fatal(merr)
	}
	mk.endFlight()
	unlock()
	if ms := moveRecords(t, s, "vm1"); len(ms) != 1 || !ms[0].Live {
		t.Fatalf("the move's record did not survive: %+v", ms)
	}
	if !health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
		t.Fatal("the move's condition did not survive")
	}
}

// m3-2 (re-review 4, section D): a row write that fails on the second disk
// points the first back and is audited as failed.
func TestResolveHealthCondition_SecondRowWriteFails(t *testing.T) {
	ctx := context.Background()
	s, src, dst := sharedMoveServer(t, "root", "data")
	// The second row written onto the copy's pool fails, whichever disk it is.
	if err := s.db.Execute(ctx, `CREATE TRIGGER fail_second_row BEFORE INSERT ON vm_disks
		WHEN NEW.storage_volume = 'warm' AND (SELECT count(*) FROM vm_disks WHERE storage_volume = 'warm' AND deleted_at IS NULL) >= 1
		BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	_, err := s.ResolveHealthCondition(acceptCtx(dst["root"], dst["data"]), moveResolveReq("x"))
	if err == nil || !strings.Contains(err.Error(), "was pointed back at ") {
		t.Fatalf("want the failure naming the first row pointed back, got %v", err)
	}
	for _, d := range []string{"root", "data"} {
		if r := diskRowOf(t, s, d); r.Path != src[d] || r.StorageType != "ceph" {
			t.Fatalf("row %s left at %+v", d, r)
		}
	}
	if !health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
		t.Fatal("resolved by a failed resolve")
	}
	rows, qerr := s.db.Query(ctx, `SELECT result, detail FROM audit_log WHERE action = 'health.condition.resolve' ORDER BY result`)
	if qerr != nil || len(rows) != 2 || rows[0].String("result") != "failed" || !strings.Contains(rows[0].String("detail"), "pointed back") ||
		rows[1].String("result") != "pending" {
		t.Fatalf("audit = %+v %v, want the pending write and the failure", rows, qerr)
	}
}

// I4-3: the hand-resolution marker matches the move, not the time of its last
// rewrite. The holder records a pivot (rewriting its record) that never
// replicates, the VM fails over, an admin resolves the replicated evidence by
// hand; the returning holder drops its record and raises nothing, and says
// that its record knew more (m4-5).
func TestHandResolution_SurvivesTheHoldersPivotRewrite(t *testing.T) {
	ctx := context.Background()
	s, _, _, dstFile := offlineMoveServer(t)
	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	mk, err := s.beginMoveMarker(ctx, vm, &disks[0], dstFile, "local", "warm", true, false, false)
	if err != nil {
		t.Fatal(err)
	}
	replicated, _, err := corrosion.GetHealthCondition(ctx, s.db, health.MoveUnresolvedEvaluator, health.MoveUnresolvedCode, "vm", "vm1")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond)
	mk.pivoted()
	mk.endFlight() // power lost: the pivot's publish never left this host
	// What the cluster saw: the condition as first published. The VM failed
	// over to node-b, and an admin there resolved it by hand.
	var ev health.MoveUnresolvedEvidence
	if err := json.Unmarshal([]byte(replicated.Evidence), &ev); err != nil {
		t.Fatal(err)
	}
	ev.Hand = true
	b, _ := json.Marshal(ev)
	replicated.Evidence, replicated.Lifecycle, replicated.ResolvedAt = string(b), corrosion.ConditionResolved, "2026-10-18T00:00:00Z"
	if err := corrosion.UpsertHealthCondition(ctx, s.db, replicated); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET host_name = 'node-b' WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE vm_disks SET host_name = 'node-b' WHERE vm_name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(ctx, s.db, s.dataDir, s.hostName, "vm1"); err != nil {
		t.Fatalf("the returning holder: %v", err)
	}
	if health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
		t.Fatal("the returning holder raised the condition again over the admin's resolution")
	}
	if ms := moveRecords(t, s, "vm1"); len(ms) != 0 {
		t.Fatalf("the record was kept: %+v", ms)
	}
	rows, qerr := s.db.Query(ctx, `SELECT result, detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
	if qerr != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), "pivoted") {
		t.Fatalf("the divergence was not recorded: %+v %v", rows, qerr)
	}
}

// m4-1: a row pointed back at the source of a move gets the source's backing
// record back, which the commit cleared when the copy was flattened: by the
// holder's settle, and by a hand resolution keeping the source.
func TestPointBackToTheSourceRestoresItsBacking(t *testing.T) {
	ctx := context.Background()
	committed := func(t *testing.T) (*Server, string, string) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		if err := s.db.Execute(ctx, `UPDATE vm_disks SET backing_disk = 'base:root', backing_image = 'base.qcow2' WHERE vm_name = 'vm1'`); err != nil {
			t.Fatal(err)
		}
		crashAfterDefine(t, s, f, srcFile, dstFile, srcFile, true, false)
		if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dstFile, "local", "warm"); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.ClearDiskBacking(ctx, s.db, "vm1", "root", dstFile); err != nil {
			t.Fatal(err)
		}
		return s, srcFile, dstFile
	}
	backed := func(t *testing.T, s *Server, srcFile string) {
		t.Helper()
		disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
		if len(disks) != 1 || disks[0].Path != srcFile || disks[0].BackingDisk != "base:root" || disks[0].BackingImage != "base.qcow2" {
			t.Fatalf("row = %+v, want the source with its backing", disks)
		}
	}
	t.Run("the settle", func(t *testing.T) {
		s, srcFile, _ := committed(t)
		if err := s.resolveUnresolvedMoves(ctx, "vm1"); err != nil {
			t.Fatalf("settle: %v", err)
		}
		backed(t, s, srcFile)
	})
	t.Run("--accept the source", func(t *testing.T) {
		s, srcFile, _ := committed(t)
		if _, err := s.ResolveHealthCondition(acceptCtx(srcFile), moveResolveReq("never pivoted")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		backed(t, s, srcFile)
	})
}

// m4-3: a condition whose evidence cannot be read names no holder, so its
// hand resolution is accepted only on the VM's owner with the domain not
// active; it keeps the disk row.
func TestResolveHealthCondition_UnreadableEvidenceOnlyOnTheOwner(t *testing.T) {
	ctx := context.Background()
	broken := func(t *testing.T) (*Server, *libvirtfake.Fake, string) {
		s, f, srcFile, _ := offlineMoveServer(t)
		if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{Evaluator: health.MoveUnresolvedEvaluator,
			Code: health.MoveUnresolvedCode, SubjectKind: "vm", SubjectID: "vm1", Lifecycle: corrosion.ConditionConfirmed,
			Evidence: "{", LastSeen: "2026-10-18T00:00:00Z"}); err != nil {
			t.Fatal(err)
		}
		return s, f, srcFile
	}
	t.Run("the VM is on another host: refused", func(t *testing.T) {
		s, _, srcFile := broken(t)
		if err := s.db.Execute(ctx, `UPDATE vms SET host_name = 'node-b' WHERE name = 'vm1'`); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("x"))
		mustRefuse(t, s, err, srcFile, "cannot be read", "LV_HOST=node-b")
	})
	t.Run("the domain is active here: refused", func(t *testing.T) {
		s, f, srcFile := broken(t)
		f.SetState("vm1", libvirtfake.StateRunning)
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("x"))
		mustRefuse(t, s, err, srcFile, "cannot be read", "lv stop vm1")
	})
	t.Run("the owner, shut off: resolved, the row kept", func(t *testing.T) {
		s, _, srcFile := broken(t)
		if _, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("checked the file")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if health.MoveConditionCovers(ctx, s.db, "vm1", "root") || diskRowPath(t, s, "vm1") != srcFile {
			t.Fatal("not resolved, or the row changed")
		}
	})
}

// m4-1: a live move whose pivot fails points the row back at the source with
// the backing record the commit cleared for the flattened copy.
func TestMoveVolume_Live_PivotFailureRestoresTheSourcesBacking(t *testing.T) {
	ctx := context.Background()
	s, _, src, _ := liveMoveServerWithVirt(t, false)
	if err := s.db.Execute(ctx, `UPDATE vm_disks SET backing_disk = 'base:root' WHERE vm_name = 'vm-live'`); err != nil {
		t.Fatal(err)
	}
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")})
	fastPoll(t)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); status.Code(err) != codes.Internal {
		t.Fatalf("want the pivot failure, got %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm-live")
	if len(disks) != 1 || disks[0].Path != src || disks[0].BackingDisk != "base:root" {
		t.Fatalf("row = %+v, want the source with its backing", disks)
	}
}
