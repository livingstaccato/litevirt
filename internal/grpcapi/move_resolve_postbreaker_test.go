package grpcapi

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// forkedMoveServer is sharedMoveServer after a fork: node-a (proven powered
// off) pivoted vm1's root disk onto dst, and recorded the VM's owner as owner
// at generation ownerEpoch when the move began; vm1 is now on test-host at
// generation vmEpoch, its disk row on src. define is "src" or "dst", the file
// test-host's persistent config names, or "" for no domain; running whether
// it runs. Each file holds its own writes.
func forkedMoveServer(t *testing.T, owner string, ownerEpoch, vmEpoch int64, define string, running bool) (*Server, string, string) {
	t.Helper()
	ctx := context.Background()
	s, srcs, dsts := sharedMoveServer(t, "root")
	src, dst := srcs["root"], dsts["root"]
	holderDir := t.TempDir()
	if err := health.RecordUnresolvedMove(holderDir, health.UnresolvedMove{VM: "vm1", Disk: "root", TargetDev: "vda",
		Src: src, SrcType: "ceph", SrcPool: "hot", Dst: dst, DstType: "nfs", DstPool: "warm", Live: true, Pivoted: true,
		At: "2026-10-18T10:00:00.000000001Z", Owner: owner, OwnerEpoch: ownerEpoch}); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(ctx, s.db, holderDir, "node-a", "vm1"); err != nil {
		t.Fatal(err)
	}
	if ev := moveEvidence(t, s, "vm1"); len(ev.Moves) != 1 || !ev.Moves[0].Pivoted {
		t.Fatalf("evidence = %+v", ev)
	}
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = ? WHERE name = 'vm1'`, vmEpoch); err != nil {
		t.Fatal(err)
	}
	if define != "" {
		names := src
		if define == "dst" {
			names = dst
		}
		f := fakeOf(t, s)
		if err := f.DefineDomain(fakeDomainXML("vm1", "vda", names)); err != nil {
			t.Fatal(err)
		}
		if running {
			f.SetState("vm1", libvirtfake.StateRunning)
		}
	}
	for p, w := range forkWrites(src, dst) {
		if err := os.WriteFile(p, []byte(w), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// The owner wrote the source after the holder's last write to the copy.
	setModTimes(t, dst, src)
	return s, src, dst
}

// setModTimes gives earlier an older modification time than later.
func setModTimes(t *testing.T, earlier, later string) {
	t.Helper()
	e, l := time.Now().Add(-time.Hour), time.Now().Add(-time.Minute)
	if err := os.Chtimes(earlier, e, e); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(later, l, l); err != nil {
		t.Fatal(err)
	}
}

// forceCtx is acceptCtx with `lv health resolve --force`.
func forceCtx(paths ...string) context.Context {
	ctx := acceptCtx(paths...)
	md, _ := metadata.FromIncomingContext(ctx)
	return metadata.NewIncomingContext(ctx, metadata.Join(md, metadata.Pairs(MoveForceMDKey, "true")))
}

func forkWrites(src, dst string) map[string]string {
	return map[string]string{src: "test-host's writes since the failover", dst: "node-a's writes after the pivot"}
}

// I5-1: after a failover onto the source, a pivoted move's condition that
// arrives late leaves two histories: the copy holds the holder's writes after
// the pivot, the source the owner's since. On the owner, with the holder
// proven powered off, `--accept <row's file>` keeps the owner's when its
// persistent config names that file and the VM changed hands after the move
// began; the other file is kept on disk and the divergence is audited.
// Without that evidence only the copy is accepted.
func TestResolveHealthCondition_ForkedHistoryKeepsTheOwnersFile(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name          string
		owner         string
		ownerEp, vmEp int64
		define        string
		running       bool
		copyLater     bool // the copy was modified after the source
		force         bool
		ok            bool
		want          string
	}{
		{name: "another owner, running on the source", owner: "node-a", ownerEp: 3, vmEp: 3, define: "src", running: true, ok: true},
		{name: "the same owner at a later generation, shut off", owner: "test-host", ownerEp: 3, vmEp: 4, define: "src", ok: true},
		{name: "no change of hands since the move", owner: "test-host", ownerEp: 4, vmEp: 4, define: "src"},
		{name: "the record names no owner", vmEp: 4, define: "src"},
		// I8-3: a config naming the copy is pointed at the source with the
		// domain shut off, under the same gates.
		{name: "the owner's config names the copy", owner: "node-a", ownerEp: 3, vmEp: 4, define: "dst", ok: true},
		// I6-1: with no domain, a start rebuilds it from the disk row, so
		// keeping the row's file needs no config.
		{name: "no domain on the owner", owner: "node-a", ownerEp: 3, vmEp: 4, ok: true},
		// m6-1: the copy modified after the source shows nothing was written
		// here since the holder's last write.
		{name: "the copy modified later", owner: "node-a", ownerEp: 3, vmEp: 4, define: "src", copyLater: true,
			want: "--force"},
		{name: "the copy modified later, no domain", owner: "node-a", ownerEp: 3, vmEp: 4, copyLater: true, want: "--force"},
		{name: "the copy modified later, --force", owner: "node-a", ownerEp: 3, vmEp: 4, define: "src", copyLater: true,
			force: true, ok: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, src, dst := forkedMoveServer(t, tc.owner, tc.ownerEp, tc.vmEp, tc.define, tc.running)
			if tc.copyLater {
				setModTimes(t, src, dst)
			}
			rctx := acceptCtx(src)
			if tc.force {
				rctx = forceCtx(src)
			}
			_, err := s.ResolveHealthCondition(rctx, moveResolveReq("ran on the source since the failover"))
			for p, w := range forkWrites(src, dst) {
				if b, rerr := os.ReadFile(p); rerr != nil || string(b) != w {
					t.Fatalf("%s = %q %v, want it kept as it was", p, b, rerr)
				}
			}
			if !tc.ok {
				if tc.want != "" {
					// Both files' sizes and times, and how to judge them.
					mustRefuse(t, s, err, src, tc.want, "modified", "bytes", "lv events vm1")
					return
				}
				mustRefuse(t, s, err, src, "--accept "+dst)
				return
			}
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if r := diskRowOf(t, s, "root"); r.Path != src || r.StorageType != "ceph" || r.StorageVolume != "hot" {
				t.Fatalf("row = %+v, want the source", r)
			}
			row, _, gerr := corrosion.GetHealthCondition(ctx, s.db, health.MoveUnresolvedEvaluator, health.MoveUnresolvedCode, "vm", "vm1")
			if gerr != nil || row.Lifecycle != corrosion.ConditionResolved || !strings.Contains(row.Evidence, `"hand":true`) {
				t.Fatalf("condition = %+v %v, want resolved by hand", row, gerr)
			}
			rows, qerr := s.db.Query(ctx, `SELECT result, detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
			if qerr != nil || len(rows) != 1 || !strings.Contains(rows[0].String("detail"), dst) ||
				!strings.Contains(rows[0].String("detail"), "kept on disk") ||
				strings.Contains(rows[0].String("detail"), "--force") != tc.force {
				t.Fatalf("divergence audit = %+v %v, want one row naming %s kept on disk (forced=%v)", rows, qerr, dst, tc.force)
			}
			if tc.define != "" {
				// The persistent config, which `lv start` boots, names the file kept.
				if x, _ := fakeOf(t, s).DumpXMLInactive("vm1"); !strings.Contains(x, src) || strings.Contains(x, dst) {
					t.Fatalf("persistent config = %s, want it on %s", x, src)
				}
			}
			if tc.running {
				if st, _ := fakeOf(t, s).DomainState("vm1"); st != "running" {
					t.Fatalf("the domain was disturbed: %q", st)
				}
			}
		})
	}
	t.Run("on the holder: refused", func(t *testing.T) {
		s, src, dst := forkedMoveServer(t, "node-a", 3, 4, "src", false)
		s.hostName = "node-a"
		_, err := s.ResolveHealthCondition(acceptCtx(src), moveResolveReq("x"))
		mustRefuse(t, s, err, src, "--accept "+dst)
	})
}

// m5-4 (I4-3): a retry of a move keeps the move's identity (At) and the
// owner it began under, so a hand resolution of the evidence first published
// still settles the retried move's record when its holder returns.
func TestBeginMoveMarker_ARetryKeepsTheMovesIdentity(t *testing.T) {
	ctx := context.Background()
	s, _, _, dstFile := offlineMoveServer(t)
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 7 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	begin := func() *moveMarker {
		vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
		disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
		mk, err := s.beginMoveMarker(ctx, vm, &disks[0], dstFile, "local", "warm", true, false, false)
		if err != nil {
			t.Fatal(err)
		}
		return mk
	}
	first := begin()
	first.keep(errors.New("the mirror stalled"))
	first.done()
	replicated, _, err := corrosion.GetHealthCondition(ctx, s.db, health.MoveUnresolvedEvaluator, health.MoveUnresolvedCode, "vm", "vm1")
	if err != nil {
		t.Fatal(err)
	}
	ms := moveRecords(t, s, "vm1")
	if len(ms) != 1 || ms[0].Owner != "test-host" || ms[0].OwnerEpoch != 7 {
		t.Fatalf("record = %+v, want the owner test-host at generation 7", ms)
	}
	at := ms[0].At
	time.Sleep(5 * time.Millisecond)
	if err := s.db.Execute(ctx, `UPDATE vms SET vm_owner_epoch = 8 WHERE name = 'vm1'`); err != nil {
		t.Fatal(err)
	}
	retry := begin()
	retry.pivoted()
	retry.endFlight() // power lost after the pivot
	if ms := moveRecords(t, s, "vm1"); len(ms) != 1 || ms[0].At != at || ms[0].OwnerEpoch != 7 || !ms[0].Pivoted {
		t.Fatalf("the retry's record = %+v, want At %s and generation 7 kept", ms, at)
	}
	// The VM failed over to node-b, where an admin resolved the first
	// published evidence by hand.
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
	if err := health.PublishUnresolvedMoves(ctx, s.db, s.dataDir, s.hostName, "vm1"); err != nil {
		t.Fatalf("the returning holder: %v", err)
	}
	if health.MoveConditionCovers(ctx, s.db, "vm1", "root") || len(moveRecords(t, s, "vm1")) != 0 {
		t.Fatal("the returning holder raised the retried move again over the admin's resolution")
	}
}

// m5-1: a stack migration moves the disk row as it is under the VM's lock,
// not as it was planned: a hand resolution that repointed the row while the
// migration waited for the lock is not undone by copying the stale file.
func TestMigrateVMVolumes_RereadsTheDiskRowUnderTheVMLock(t *testing.T) {
	ctx := context.Background()
	s, f, srcFile, dstFile := offlineMoveServer(t)
	alt := filepath.Join(s.dataDir, "alt", "vm1-root.qcow2")
	if err := os.MkdirAll(filepath.Dir(alt), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(alt, 2<<20, nil); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
	vp := vmPlan{vm: *vm, disks: []diskPlan{{disk: disks[0], targetPool: "warm"}}}
	unlock := s.lockVM("vm1")
	var vmsDone, moved, skipped atomic.Int32
	done := make(chan error, 1)
	go func() {
		done <- s.migrateVMVolumes(ctx, func(*pb.StackVolumeProgress) error { return nil }, vp, false, 0, 1, &vmsDone, &moved, &skipped)
	}()
	time.Sleep(300 * time.Millisecond) // the migration waits for the lock
	// What a hand resolution does meanwhile: the row and the config name alt.
	if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", alt, "local", "alt"); err != nil {
		t.Fatal(err)
	}
	if err := f.DefineDomain(fakeDomainXML("vm1", "vda", alt)); err != nil {
		t.Fatal(err)
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatalf("migration: %v", err)
	}
	if got := diskRowPath(t, s, "vm1"); got != dstFile {
		t.Fatalf("row names %s, want %s", got, dstFile)
	}
	info, err := qcow2.Info(dstFile)
	if err != nil || info.VirtualSize != 2<<20 {
		t.Fatalf("the moved file = %+v %v, want the copy of %s (not of the stale %s)", info, err, alt, srcFile)
	}
}

// m5-3: a live move whose pivot fails points the row back at the source and
// restores its backing record in one write: a failure leaves the row on the
// copy with the record kept, never the source without its backing.
func TestMoveVolume_Live_PivotFailureNeverLeavesTheSourceWithoutItsBacking(t *testing.T) {
	ctx := context.Background()
	s, _, src, _ := liveMoveServerWithVirt(t, false)
	if err := s.db.Execute(ctx, `UPDATE vm_disks SET backing_disk = 'base:root' WHERE vm_name = 'vm-live'`); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `CREATE TRIGGER fail_backing_restore BEFORE INSERT ON vm_disks
		WHEN NEW.backing_disk = 'base:root' AND NEW.path = '`+src+`'
		BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
		t.Fatal(err)
	}
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")})
	fastPoll(t)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); status.Code(err) != codes.Internal {
		t.Fatalf("want the pivot failure, got %v", err)
	}
	disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm-live")
	if len(disks) != 1 {
		t.Fatalf("rows = %+v", disks)
	}
	if disks[0].Path == src && disks[0].BackingDisk != "base:root" {
		t.Fatalf("row = %+v: the source without its backing record", disks[0])
	}
	if disks[0].Path != src {
		ms := moveRecords(t, s, "vm-live")
		if len(ms) != 1 || ms[0].SrcBackingDisk != "base:root" || !health.MoveConditionCovers(ctx, s.db, "vm-live", "root") {
			t.Fatalf("row left on %s with no record to settle it: %+v", disks[0].Path, ms)
		}
	}
}

// m5-2: a condition whose evidence cannot be read is resolved on the owner
// only while its persistent config names each disk row's file, and the
// resolution marks those disks, so a holder returning with a record of a
// move begun before it drops the record instead of raising it again. A move
// begun after the resolution is not settled by it.
func TestResolveHealthCondition_UnreadableEvidenceConfigAndHandMarker(t *testing.T) {
	ctx := context.Background()
	broken := func(t *testing.T) (*Server, *libvirtfake.Fake, string, string) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		if err := corrosion.UpsertHealthCondition(ctx, s.db, corrosion.HealthCondition{Evaluator: health.MoveUnresolvedEvaluator,
			Code: health.MoveUnresolvedCode, SubjectKind: "vm", SubjectID: "vm1", Lifecycle: corrosion.ConditionConfirmed,
			Evidence: "{", LastSeen: "2026-10-18T00:00:00Z"}); err != nil {
			t.Fatal(err)
		}
		return s, f, srcFile, dstFile
	}
	t.Run("the config names another file: refused", func(t *testing.T) {
		s, f, srcFile, dstFile := broken(t)
		if err := f.DefineDomain(fakeDomainXML("vm1", "vda", dstFile)); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("x"))
		mustRefuse(t, s, err, srcFile, "cannot be read", srcFile, "virsh edit vm1")
	})
	before := func(r time.Time) string { return r.Add(-time.Hour).Format(time.RFC3339Nano) }
	for _, tc := range []struct {
		name    string
		at      func(resolved time.Time) string
		pivoted bool
		raised  bool
	}{
		{name: "a holder's record of a move begun before: dropped", at: before},
		// m6-3: the admin saw none of the pivot this record knew.
		{name: "a holder's pivoted record of a move begun before: kept", at: before, pivoted: true, raised: true},
		{name: "a holder's record of a move begun after: kept", at: func(r time.Time) string { return r.Add(time.Hour).Format(time.RFC3339Nano) }, pivoted: true, raised: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, srcFile, dstFile := broken(t)
			if _, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("checked the file")); err != nil {
				t.Fatalf("resolve: %v", err)
			}
			row, _, err := corrosion.GetHealthCondition(ctx, s.db, health.MoveUnresolvedEvaluator, health.MoveUnresolvedCode, "vm", "vm1")
			if err != nil || row.Lifecycle != corrosion.ConditionResolved {
				t.Fatalf("condition = %+v %v", row, err)
			}
			resolved, perr := time.Parse(time.RFC3339, row.ResolvedAt)
			if perr != nil {
				t.Fatal(perr)
			}
			// node-a returns with its record; the VM is test-host's.
			holderDir := t.TempDir()
			if err := health.RecordUnresolvedMove(holderDir, health.UnresolvedMove{VM: "vm1", Disk: "root", TargetDev: "vda",
				Src: srcFile, Dst: dstFile, Live: true, Pivoted: tc.pivoted, At: tc.at(resolved)}); err != nil {
				t.Fatal(err)
			}
			if err := health.PublishUnresolvedMoves(ctx, s.db, holderDir, "node-a", "vm1"); err != nil {
				t.Fatalf("the returning holder: %v", err)
			}
			if got := health.MoveConditionCovers(ctx, s.db, "vm1", "root"); got != tc.raised {
				t.Fatalf("condition raised = %v, want %v", got, tc.raised)
			}
			left, _ := health.UnresolvedMovesOf(holderDir, "vm1")
			if (len(left) == 1) != tc.raised {
				t.Fatalf("holder's records = %+v", left)
			}
			rows, qerr := s.db.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'health.condition.hand_diverged'`)
			if qerr != nil || len(rows) != 0 {
				t.Fatalf("a divergence was recorded: %+v %v", rows, qerr)
			}
		})
	}
}
