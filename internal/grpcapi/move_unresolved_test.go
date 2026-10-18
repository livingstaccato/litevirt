package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// moveRecords returns the unresolved-move records this host keeps for vm.
func moveRecords(t *testing.T, s *Server, vm string) []health.UnresolvedMove {
	t.Helper()
	ms, err := health.UnresolvedMovesOf(s.dataDir, vm)
	if err != nil {
		t.Fatalf("read unresolved-move records: %v", err)
	}
	return ms
}

// restoreDiskRow undoes SoftDeleteDisk, so a commit that failed once can
// succeed on a retry.
func restoreDiskRow(t *testing.T, s *Server, vm, disk string) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`UPDATE vm_disks SET deleted_at = NULL WHERE vm_name = ? AND disk_name = ?`, vm, disk); err != nil {
		t.Errorf("restore disk row: %v", err)
	}
}

// breakDefinesAfter lets the define naming path apply and succeed, runs after
// (if any), and makes every later define fail, so a rollback cannot apply.
func breakDefinesAfter(f *libvirtfake.Fake, path string, after func()) {
	broken := false
	f.FailDefineDomain = func(x string) error {
		if broken {
			return errors.New("libvirt connection lost")
		}
		if strings.Contains(x, path) {
			broken = true
			if after != nil {
				after()
			}
		}
		return nil
	}
}

// startHookMover runs onStart when the block copy starts.
type startHookMover struct {
	fakeLiveMover
	onStart func()
}

func (m *startHookMover) StartBlockCopy(dom, disk, xml string, flags uint32) error {
	if m.onStart != nil {
		m.onStart()
	}
	return m.fakeLiveMover.StartBlockCopy(dom, disk, xml, flags)
}

// pivotHookMover runs onPivot before each pivot.
type pivotHookMover struct {
	fakeLiveMover
	onPivot func()
}

func (m *pivotHookMover) PivotBlockCopy(dom, disk string) error {
	if m.onPivot != nil {
		m.onPivot()
	}
	return m.fakeLiveMover.PivotBlockCopy(dom, disk)
}

// I-R1: the redefine applies, the disk row commit fails, and pointing the
// config back fails. The mirror is not cancelled under a config that names the
// copy: the guest is pivoted onto it and the row follows, so the guest, the
// config and the row name the same file. Nothing is deleted.
func TestMoveVolume_Live_CommitAndRollbackFailPivotsOntoTheCopy(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	mover := &pivotHookMover{fakeLiveMover: fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}}
	mover.onPivot = func() { restoreDiskRow(t, s, "vm-live", "root") }
	s.SetLiveMover(mover)
	breakDefinesAfter(f, destPath, func() {
		if err := corrosion.SoftDeleteDisk(context.Background(), s.db, "vm-live", "root"); err != nil {
			t.Errorf("SoftDeleteDisk: %v", err)
		}
	})
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if mover.cancelCalls != 0 || mover.pivotCalls != 1 {
		t.Fatalf("cancel = %d pivot = %d, want 0/1: the mirror must not stop under a config naming the copy", mover.cancelCalls, mover.pivotCalls)
	}
	if after, _ := f.DumpXMLInactive("vm-live"); after != strings.Replace(before, src, destPath, 1) {
		t.Fatalf("the config does not name the copy:\n%s", after)
	}
	if got := diskRowPath(t, s, "vm-live"); got != destPath {
		t.Fatalf("disk row names %s, want the copy %s", got, destPath)
	}
	if !exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want both", exists(destPath), exists(src))
	}
	requireWarningEvent(t, s, "vm-live")
	if ms := moveRecords(t, s, "vm-live"); len(ms) != 0 {
		t.Fatalf("a resolved move left its record: %+v", ms)
	}
}

// I-R2: the pivot fails and pointing the config back fails. The mirror is left
// running (the config names the copy, which it keeps current), both files are
// kept, the row is back on the source, the error says what the operator does,
// and the unresolved-move record stays.
func TestMoveVolume_Live_PivotAndRollbackFailLeavesTheMirror(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")}
	s.SetLiveMover(mover)
	breakDefinesAfter(f, destPath, nil)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	for _, want := range []string{
		"the persistent config names " + destPath,
		"the guest is writing " + src,
		"Do not stop or restart the VM",
		"virsh blockjob vm-live " + src + " --pivot",
		"virsh blockjob vm-live " + src + " --abort",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error does not say %q: %v", want, err)
		}
	}
	if mover.cancelCalls != 0 || mover.pivotCalls != 1 {
		t.Fatalf("cancel = %d pivot = %d, want 0/1 (no cancel, no second pivot)", mover.cancelCalls, mover.pivotCalls)
	}
	if after, _ := f.DumpXMLInactive("vm-live"); after != strings.Replace(before, src, destPath, 1) {
		t.Fatalf("the config does not name the copy:\n%s", after)
	}
	if got := diskRowPath(t, s, "vm-live"); got != src {
		t.Fatalf("disk row names %s, want the source %s", got, src)
	}
	if !exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want both", exists(destPath), exists(src))
	}
	ms := moveRecords(t, s, "vm-live")
	if len(ms) != 1 || !ms[0].Live || ms[0].Pivoted || ms[0].Dst != destPath || ms[0].Src != src {
		t.Fatalf("want one live, unpivoted record of the move, got %+v", ms)
	}

	// The guest then stops on its own, before anyone pivots: the copy may lack
	// its last writes, so no start boots it.
	f.SetState("vm-live", libvirtfake.StateShutdown)
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm-live")
	_, serr := s.startVMLocked(adminCtx(), vm)
	if status.Code(serr) != codes.FailedPrecondition || !strings.Contains(serr.Error(), destPath) || !strings.Contains(serr.Error(), src) ||
		!strings.Contains(serr.Error(), "stopped before a pivot") {
		t.Fatalf("want the start refused naming both files, got %v", serr)
	}
	if st, _ := f.DomainState("vm-live"); st == "running" {
		t.Fatal("the domain was started")
	}
}

// m-R2b: the pivot fails and the row cannot be pointed back, but the config
// can: the copy is removed, and the error says the row names it and what
// points the row back. The record stays, so the next start does.
func TestMoveVolume_Live_PivotAndRowRollbackFailSaysTheRowNamesTheRemovedCopy(t *testing.T) {
	s, _, src, destPath, _ := liveLitevirtMove(t)
	mover := &pivotHookMover{fakeLiveMover: fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")}}
	mover.onPivot = func() {
		if err := corrosion.SoftDeleteDisk(context.Background(), s.db, "vm-live", "root"); err != nil {
			t.Errorf("SoftDeleteDisk: %v", err)
		}
	}
	s.SetLiveMover(mover)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "the disk row names "+destPath+", which was removed") ||
		!strings.Contains(err.Error(), "points the row back at "+src) {
		t.Fatalf("want Internal saying the row names the removed copy, got %v", err)
	}
	if exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want false/true", exists(destPath), exists(src))
	}
	if ms := moveRecords(t, s, "vm-live"); len(ms) != 1 {
		t.Fatalf("want the record kept, got %+v", ms)
	}
}

// m-R4: the redefine fails before any define (the config cannot be read): the
// config never named the copy, so the mirror stops and the copy is removed,
// with no double-fault advice.
func TestMoveVolume_Live_UnreadableConfigBeforeDefineCancels(t *testing.T) {
	s, f, src, destPath, _ := liveLitevirtMove(t)
	mover := &startHookMover{fakeLiveMover: fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}}
	mover.onStart = func() {
		f.FailDumpXMLInactive = func(string) error { return errors.New("libvirt connection lost") }
	}
	s.SetLiveMover(mover)
	defined := false
	f.FailDefineDomain = func(string) error { defined = true; return nil }
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "nothing was defined") ||
		strings.Contains(err.Error(), "Do not stop") {
		t.Fatalf("want a plain aborted cutover, got %v", err)
	}
	if defined {
		t.Fatal("a define was issued")
	}
	if mover.cancelCalls != 1 || mover.pivotCalls != 0 {
		t.Fatalf("cancel = %d pivot = %d, want 1/0", mover.cancelCalls, mover.pivotCalls)
	}
	if exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want false/true", exists(destPath), exists(src))
	}
	if ms := moveRecords(t, s, "vm-live"); len(ms) != 0 {
		t.Fatalf("an aborted cutover left a record: %+v", ms)
	}
}

// m-R5: without libvirt, a job that ended before the copy caught up is not
// pivoted onto and the row is not committed to it.
func TestMoveVolume_LiveNoVirt_JobEndedBeforeReadyRemovesTheCopy(t *testing.T) {
	s, src, _ := liveMoveTestServer(t, 4096)
	mover := endedEarlyMover()
	s.SetLiveMover(mover)
	fastPoll(t)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "before the copy caught up") {
		t.Fatalf("want Internal saying the job ended early, got %v", err)
	}
	if mover.pivotCalls != 0 {
		t.Fatalf("pivot = %d, want 0", mover.pivotCalls)
	}
	if got := diskRowPath(t, s, "vm-live"); got != src {
		t.Fatalf("disk row names %s, want the source %s", got, src)
	}
}

// m-R6: the guest already writes the copy and the catch-up redefine fails: the
// error says the config may still name the source and not to stop the VM, and
// the record (pivoted) stays.
func TestMoveVolume_Live_CatchUpRedefineFailureSaysTheGuestIsOnTheCopy(t *testing.T) {
	s, f, src, destPath := liveMoveServerWithVirt(t, true)
	f.FailDefineDomain = func(string) error { return errors.New("redefine rejected") }
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096})
	fastPoll(t)
	if err := os.WriteFile(destPath, []byte("copy"), 0o600); err != nil {
		t.Fatal(err)
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "The guest is writing "+destPath) ||
		!strings.Contains(err.Error(), "may still name "+src) || !strings.Contains(err.Error(), "Do not stop or restart the VM") ||
		!strings.Contains(err.Error(), "lv move-volume vm-live root warm") {
		t.Fatalf("want Internal saying the guest is on the copy, got %v", err)
	}
	ms := moveRecords(t, s, "vm-live")
	if len(ms) != 1 || !ms[0].Pivoted {
		t.Fatalf("want one pivoted record, got %+v", ms)
	}
}

// m-R7: a stream that drops after a live move committed does not skip the
// caller's completion: the move returns success and records its event.
func TestMoveVolume_Live_DroppedStreamAfterCommitStillCompletes(t *testing.T) {
	s, _, _, destPath, _ := liveLitevirtMove(t)
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096})
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm-live")
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm-live")
	send := func(p *pb.MoveVolumeProgress) error {
		if p.Phase == pb.MoveVolumeProgress_DONE {
			return errors.New("client went away")
		}
		return nil
	}
	if err := s.moveOneVolume(context.Background(), vm, &disks[0], "warm", false, send); err != nil {
		t.Fatalf("moveOneVolume: %v", err)
	}
	if got := diskRowPath(t, s, "vm-live"); got != destPath {
		t.Fatalf("disk row names %s, want %s", got, destPath)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "vm-live", 50, "")
	ok := false
	for _, e := range evs {
		if e.Type == "disk.moved" && e.Result == "ok" {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("no disk.moved ok event: %+v", evs)
	}
}

// m-R3: offline, the define fails but was stored and cannot be undone, then the
// row commit fails and the rollback fails: the error says the config may name
// the copy while the row names the source; no "completes onto it" warning is
// recorded for a move that did not complete; the record stays.
func TestMoveVolume_Offline_UnrolledDefineThenCommitFailureNamesBoth(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	defineThenFail(f, dstFile, true)
	inner := f.FailDefineDomain
	f.FailDefineDomain = func(x string) error {
		err := inner(x)
		if strings.Contains(x, dstFile) {
			if derr := corrosion.SoftDeleteDisk(context.Background(), s.db, "vm1", "root"); derr != nil {
				t.Errorf("SoftDeleteDisk: %v", derr)
			}
		}
		return err
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
	if err == nil || !strings.Contains(err.Error(), "may name "+dstFile) {
		t.Fatalf("want an error saying the config may name the copy, got %v", err)
	}
	evs, _ := corrosion.ListVMEvents(context.Background(), s.db, "vm1", 50, "")
	for _, e := range evs {
		if e.Type == "disk.moved" && e.Severity == "warning" {
			t.Fatalf("a completion warning was recorded for a move that failed: %+v", e)
		}
	}
	if !exists(dstFile) || !exists(srcFile) {
		t.Fatalf("dst exists=%v src exists=%v, want both", exists(dstFile), exists(srcFile))
	}
	if ms := moveRecords(t, s, "vm1"); len(ms) != 1 {
		t.Fatalf("want the record kept, got %+v", ms)
	}
}

// The offline double fault whose config cannot be read keeps the record, and a
// later start, once the config reads again, points the row at the copy it
// names and starts.
func TestMoveVolume_Offline_UnreadableDoubleFaultIsHealedByTheNextStart(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	armUnreadableAfterDefine(f, dstFile)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec); status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	if ms := moveRecords(t, s, "vm1"); len(ms) != 1 || ms[0].Live {
		t.Fatalf("want one offline record, got %+v", ms)
	}
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")

	// Still unreadable: refused, naming both files and the check.
	_, err := s.startVMLocked(adminCtx(), vm)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), srcFile) ||
		!strings.Contains(err.Error(), dstFile) || !strings.Contains(err.Error(), "virsh dumpxml --inactive vm1") {
		t.Fatalf("want the start refused naming both files, got %v", err)
	}
	if st, _ := f.DomainState("vm1"); st == "running" {
		t.Fatal("the domain was started")
	}

	// libvirt answers again: the start points the row at the copy and runs.
	f.FailDumpXMLInactive = nil
	f.FailDefineDomain = nil
	if _, err := s.startVMLocked(adminCtx(), vm); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := diskRowPath(t, s, "vm1"); got != dstFile {
		t.Fatalf("disk row names %s, want the copy %s the config names", got, dstFile)
	}
	if st, _ := f.DomainState("vm1"); st != "running" {
		t.Fatalf("domain state %q, want running", st)
	}
	if ms := moveRecords(t, s, "vm1"); len(ms) != 0 {
		t.Fatalf("the record outlived its resolution: %+v", ms)
	}
}

// crashAfterDefine leaves vm1 as a daemon that died mid-cutover leaves it: the
// record written, the config pointed at configNames, the row on the source,
// and a new process (nothing in flight).
func crashAfterDefine(t *testing.T, s *Server, f *libvirtfake.Fake, srcFile, dstFile, configNames string, live, pivoted bool) {
	t.Helper()
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	mk, err := s.beginMoveMarker(context.Background(), vm, &disks[0], dstFile, "local", "warm", live, pivoted, false)
	if err != nil {
		t.Fatalf("beginMoveMarker: %v", err)
	}
	if err := copyMovedFile(srcFile, dstFile); err != nil {
		t.Fatal(err)
	}
	if configNames != srcFile {
		if err := f.DefineDomain(fakeDomainXML("vm1", "vda", configNames)); err != nil {
			t.Fatal(err)
		}
	}
	mk.endFlight() // the process is gone; its record is not
}

func copyMovedFile(from, to string) error {
	b, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, b, 0o600)
}

// A daemon that dies between writing the record and resolving the move: the
// next start of the VM settles the row from the persistent config, or refuses
// when booting either file could lose writes.
func TestStartVM_SettlesAMoveACrashLeft(t *testing.T) {
	for _, tc := range []struct {
		name          string
		configDst     bool
		live, pivoted bool
		wantStart     bool
		wantRowDst    bool
		wantWhy       string
	}{
		{name: "offline, config names the copy", configDst: true, wantStart: true, wantRowDst: true},
		{name: "offline, config names the source", configDst: false, wantStart: true, wantRowDst: false},
		{name: "live before the pivot, config names the copy", configDst: true, live: true, wantWhy: "stopped before a pivot"},
		{name: "live before the pivot, config names the source", configDst: false, live: true, wantStart: true, wantRowDst: false},
		{name: "live after the pivot, config names the copy", configDst: true, live: true, pivoted: true, wantStart: true, wantRowDst: true},
		{name: "live after the pivot, config names the source", configDst: false, live: true, pivoted: true, wantWhy: "was moved onto"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, srcFile, dstFile := offlineMoveServer(t)
			names := srcFile
			if tc.configDst {
				names = dstFile
			}
			crashAfterDefine(t, s, f, srcFile, dstFile, names, tc.live, tc.pivoted)
			vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
			_, err := s.startVMLocked(adminCtx(), vm)
			st, _ := f.DomainState("vm1")
			if !tc.wantStart {
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), srcFile) || !strings.Contains(err.Error(), dstFile) ||
					!strings.Contains(err.Error(), tc.wantWhy) {
					t.Fatalf("want the start refused naming both files, got %v", err)
				}
				if st == "running" {
					t.Fatal("the domain was started")
				}
				if got := diskRowPath(t, s, "vm1"); got != srcFile {
					t.Fatalf("a refused start changed the row to %s", got)
				}
				if ms := moveRecords(t, s, "vm1"); len(ms) != 1 {
					t.Fatalf("a refused start dropped the record: %+v", ms)
				}
				return
			}
			if err != nil {
				t.Fatalf("start: %v", err)
			}
			want := srcFile
			if tc.wantRowDst {
				want = dstFile
			}
			if got := diskRowPath(t, s, "vm1"); got != want {
				t.Fatalf("disk row names %s, want %s", got, want)
			}
			if st != "running" {
				t.Fatalf("domain state %q, want running", st)
			}
			if ms := moveRecords(t, s, "vm1"); len(ms) != 0 {
				t.Fatalf("the record outlived its resolution: %+v", ms)
			}
			if !exists(srcFile) || !exists(dstFile) {
				t.Fatal("a file was removed")
			}
		})
	}
}

// A move still under way in this process is not settled by a start.
func TestStartVM_RefusesWhileTheMoveIsInFlight(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	mk, err := s.beginMoveMarker(context.Background(), vm, &disks[0], dstFile, "local", "warm", false, false, false)
	if err != nil {
		t.Fatal(err)
	}
	defer mk.done()
	_, serr := s.startVMLocked(adminCtx(), vm)
	if status.Code(serr) != codes.Unavailable || !health.MoveUnresolvedRetryable(serr) || !strings.Contains(serr.Error(), "in progress") {
		t.Fatalf("want the start refused while the move runs, got %v", serr)
	}
	if got := diskRowPath(t, s, "vm1"); got != srcFile {
		t.Fatalf("row changed to %s", got)
	}
	_ = f
}

// A record whose row no longer names either file describes nothing: it is
// removed and the start runs.
func TestStartVM_DropsAStaleMoveRecord(t *testing.T) {
	s, f, srcFile, _ := offlineMoveServer(t)
	if err := health.RecordUnresolvedMove(s.dataDir, health.UnresolvedMove{
		VM: "vm1", Disk: "root", TargetDev: "vda", Src: "/elsewhere/a.qcow2", Dst: "/elsewhere/b.qcow2",
	}); err != nil {
		t.Fatal(err)
	}
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
	if _, err := s.startVMLocked(adminCtx(), vm); err != nil {
		t.Fatalf("start: %v", err)
	}
	if got := diskRowPath(t, s, "vm1"); got != srcFile {
		t.Fatalf("row changed to %s", got)
	}
	if ms := moveRecords(t, s, "vm1"); len(ms) != 0 {
		t.Fatalf("stale record kept: %+v", ms)
	}
	if st, _ := f.DomainState("vm1"); st != "running" {
		t.Fatalf("domain state %q, want running", st)
	}
}

// A cold migration reads the disk rows only after the record is settled, and
// is refused when it cannot be.
func TestColdMoveDisks_HonoursAnUnresolvedMove(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, false, false)
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")

	f.FailDumpXMLInactive = func(string) error { return errors.New("libvirt connection lost") }
	if _, err := s.coldMoveDisks(context.Background(), vm); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want a refusal while the config cannot be read, got %v", err)
	}
	f.FailDumpXMLInactive = nil
	disks, err := s.coldMoveDisks(context.Background(), vm)
	if err != nil {
		t.Fatalf("coldMoveDisks: %v", err)
	}
	if len(disks) != 1 || disks[0].Path != dstFile {
		t.Fatalf("cold migration would stream %+v, want the copy %s the config names", disks, dstFile)
	}
}

// ClearUnresolvedMovesOf, which DeleteVM and RebuildVM run once the domain
// is gone, drops every record of the VM.
func TestClearUnresolvedMovesOf_DropsTheVMsRecords(t *testing.T) {
	dir := t.TempDir()
	if err := health.RecordUnresolvedMove(dir, health.UnresolvedMove{VM: "vm1", Disk: "root", Src: "/a", Dst: "/b"}); err != nil {
		t.Fatal(err)
	}
	if err := health.ClearUnresolvedMovesOf(dir, "vm1"); err != nil {
		t.Fatal(err)
	}
	if ms, err := health.UnresolvedMovesOf(dir, "vm1"); err != nil || len(ms) != 0 {
		t.Fatalf("records after clear: %+v %v", ms, err)
	}
}

// lv move-volume retried after the operator pivoted by hand, with the row
// already on the copy: the record goes once the config and the running guest
// are on the copy too; while the guest still writes the source the retry is
// refused and the record stays.
func TestMoveVolume_RetryAfterAManualPivotSettlesTheRecord(t *testing.T) {
	for _, tc := range []struct {
		name       string
		guestOnDst bool
		wantKept   bool
	}{
		{"guest pivoted onto the copy", true, false},
		{"guest still on the source", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, src, destPath := liveMoveServerWithVirt(t, tc.guestOnDst)
			if err := f.DefineDomain(fakeDomainXML("vm-live", "vda", destPath)); err != nil {
				t.Fatal(err)
			}
			f.SetState("vm-live", libvirtfake.StateRunning)
			active := src
			if tc.guestOnDst {
				active = destPath
			}
			f.SetDiskSource("vm-live", "vda", active)
			if err := corrosion.UpdateDiskPlacement(context.Background(), s.db, "vm-live", "root", "host-a", destPath, "local", "warm"); err != nil {
				t.Fatal(err)
			}
			if err := health.RecordUnresolvedMove(s.dataDir, health.UnresolvedMove{VM: "vm-live", Disk: "root",
				Src: src, SrcType: "local", SrcPool: "hot", Dst: destPath, DstType: "local", DstPool: "warm", Live: true}); err != nil {
				t.Fatal(err)
			}
			rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
			err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
			if tc.wantKept {
				// The mirror still runs: refused with the record's state, not a
				// "nothing to do".
				if !health.IsMoveUnresolved(err) || !strings.Contains(err.Error(), "mirror into "+destPath+" still running") {
					t.Fatalf("want the retry refused while the mirror runs, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("MoveVolume: %v", err)
			}
			if got := len(moveRecords(t, s, "vm-live")); (got == 1) != tc.wantKept {
				t.Fatalf("records = %d, want kept=%v", got, tc.wantKept)
			}
		})
	}
}

// I-1: a retry of a move whose live record says the guest was never pivoted
// does not clear the record or commit the row while the VM is stopped —
// whether the row is on the copy (the "nothing to do" branch) or on the
// source (the offline catch-up) — and a caller that is not MoveVolume
// (MigrateStackVolumes) gets the typed refusal.
func TestMoveVolume_RetryNeverClearsAnUnpivotedLiveRecord(t *testing.T) {
	for _, rowOnDst := range []bool{true, false} {
		for _, direct := range []bool{false, true} {
			name := map[bool]string{true: "row on the copy", false: "row on the source"}[rowOnDst] +
				map[bool]string{true: ", moveOneVolume", false: ", MoveVolume"}[direct]
			t.Run(name, func(t *testing.T) {
				s, f, srcFile, dstFile := offlineMoveServer(t)
				crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
				want := srcFile
				if rowOnDst {
					want = dstFile
					if err := corrosion.UpdateDiskPlacement(context.Background(), s.db, "vm1", "root", "test-host", dstFile, "local", "warm"); err != nil {
						t.Fatal(err)
					}
				}
				var err error
				if direct {
					vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
					disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
					err = s.moveOneVolume(context.Background(), vm, &disks[0], "warm", false, noopSend)
					var typed *health.MoveUnresolvedError
					if !errors.As(err, &typed) {
						t.Fatalf("want a *health.MoveUnresolvedError, got %T %v", err, err)
					}
				} else {
					rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
					err = s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
				}
				if status.Code(err) != codes.FailedPrecondition || !health.IsMoveUnresolved(err) || !strings.Contains(err.Error(), "stopped before a pivot") {
					t.Fatalf("want the retry refused, got %v", err)
				}
				if got := diskRowPath(t, s, "vm1"); got != want {
					t.Fatalf("the retry moved the row to %s", got)
				}
				if ms := moveRecords(t, s, "vm1"); len(ms) != 1 || !ms[0].Live || ms[0].Pivoted {
					t.Fatalf("the retry changed the record: %+v", ms)
				}
			})
		}
	}
}

// I-2: every reader that copies a VM's disk from its row honours an
// unresolved move: here a live one never pivoted whose config names the copy,
// which no reader may resolve, so each is refused and the row is untouched.
func TestCopyReaders_HonourAnUnresolvedMove(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(s *Server, vm *corrosion.VMRecord) error
	}{
		{"ReplicateVolume", func(s *Server, _ *corrosion.VMRecord) error {
			return s.ReplicateVolume(&pb.ReplicateVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"},
				&streamRecorder[pb.ReplicateVolumeProgress]{ctx: adminCtx()})
		}},
		{"scheduled replication", func(s *Server, vm *corrosion.VMRecord) error {
			return s.runVMReplication(adminCtx(), corrosion.BackupScheduleRecord{VMName: "vm1", TargetPool: "warm"}, vm, time.Now())
		}},
		{"cross-region replication", func(s *Server, _ *corrosion.VMRecord) error {
			// Refused before any disk is started on, not only by the
			// ReplicateVolume each disk goes through.
			rec := &streamRecorder[pb.MigrateProgress]{ctx: adminCtx()}
			err := s.replicateDisksForCrossRegion(adminCtx(), "vm1", "warm", rec)
			if len(rec.Sent) != 0 {
				return fmt.Errorf("a disk copy began (%d frames) before the refusal: %v", len(rec.Sent), err)
			}
			return err
		}},
		{"clone", func(s *Server, vm *corrosion.VMRecord) error {
			_, err := s.cloneVMOnSource(adminCtx(), &pb.CloneVMRequest{Source: "vm1", Target: "vm1-clone"}, vm, "", false)
			return err
		}},
		{"BuildImage", func(s *Server, _ *corrosion.VMRecord) error {
			_, err := s.BuildImage(adminCtx(), &pb.BuildImageRequest{VmName: "vm1", ImageName: "img1"})
			return err
		}},
		{"migration", func(s *Server, vm *corrosion.VMRecord) error {
			adopted := false
			return s.migrateOwnedVM(adminCtx(), &pb.MigrateVMRequest{VmName: "vm1", TargetHost: "other", WithStorage: true}, vm,
				func(pb.MigratePhase, float32, float32) error { return nil }, func() {}, &adopted, ownedMigrateOpts{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, srcFile, dstFile := offlineMoveServer(t)
			crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
			vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
			err := tc.run(s, vm)
			if !health.IsMoveUnresolved(err) || !strings.Contains(err.Error(), dstFile) {
				t.Fatalf("want the copy refused by the unresolved move, got %v", err)
			}
			if got := diskRowPath(t, s, "vm1"); got != srcFile {
				t.Fatalf("row changed to %s", got)
			}
		})
	}
}

// m-1: the refusal says what is true of the domain: a running guest still
// under a mirror is told to pivot or abort; a domain that is not defined is
// named, with the file a rebuild from the row boots.
func TestResolveUnresolvedMoves_RefusalDescribesTheDomain(t *testing.T) {
	t.Run("running under the mirror", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		f.SetState("vm1", libvirtfake.StateRunning)
		err := s.resolveUnresolvedMoves(context.Background(), "vm1")
		if err == nil || !strings.Contains(err.Error(), "still running") || !strings.Contains(err.Error(), "--pivot") ||
			strings.Contains(err.Error(), "stopped before a pivot") {
			t.Fatalf("want the running-mirror text, got %v", err)
		}
	})
	t.Run("no domain", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		if err := f.UndefineDomain("vm1", false); err != nil {
			t.Fatal(err)
		}
		err := s.resolveUnresolvedMoves(context.Background(), "vm1")
		if err == nil || !strings.Contains(err.Error(), "has no domain vm1") || !strings.Contains(err.Error(), "boots "+srcFile) ||
			!strings.Contains(err.Error(), "lv health resolve vm.move_unresolved vm/vm1") {
			t.Fatalf("want the missing-domain text, got %v", err)
		}
	})
}

// m-4: the record is replicated as a condition on the VM while the move is
// unresolved, and resolved with it.
func TestMoveVolume_UnresolvedMoveIsAClusterCondition(t *testing.T) {
	s, f, _, destPath, _ := liveLitevirtMove(t)
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")})
	breakDefinesAfter(f, destPath, nil)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); err == nil {
		t.Fatal("want the double fault")
	}
	if !health.MoveConditionCovers(context.Background(), s.db, "vm-live", "root") {
		t.Fatal("the unresolved move is not a cluster condition")
	}
	// Settled: the operator points the config back at the source and the
	// guest stops; the next start settles the record and the condition.
	f.FailDefineDomain = nil
	if err := f.DefineDomain(strings.Replace(mustInactive(t, f, "vm-live"), destPath, diskRowPath(t, s, "vm-live"), 1)); err != nil {
		t.Fatal(err)
	}
	f.SetState("vm-live", libvirtfake.StateShutdown)
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm-live")
	if _, err := s.startVMLocked(adminCtx(), vm); err != nil {
		t.Fatalf("start: %v", err)
	}
	if health.MoveConditionCovers(context.Background(), s.db, "vm-live", "root") {
		t.Fatal("the condition outlived the record")
	}
}

func mustInactive(t *testing.T, f *libvirtfake.Fake, vm string) string {
	t.Helper()
	x, err := f.DumpXMLInactive(vm)
	if err != nil {
		t.Fatal(err)
	}
	return x
}

// m-5: the offline catch-up commit (the config already names the copy) goes
// on when the record cannot be written, since it is what makes the config and
// the row agree; a forward cutover is refused instead.
func TestMoveVolume_CatchUpCommitsWhenTheRecordCannotBeWritten(t *testing.T) {
	block := func(t *testing.T, s *Server) {
		if err := os.WriteFile(s.dataDir+"/"+health.UnresolvedMoveDirName, []byte("not a directory"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("catch-up", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		if err := copyMovedFile(srcFile, dstFile); err != nil {
			t.Fatal(err)
		}
		if err := f.DefineDomain(fakeDomainXML("vm1", "vda", dstFile)); err != nil {
			t.Fatal(err)
		}
		block(t, s)
		rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
		if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec); err != nil {
			t.Fatalf("MoveVolume: %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != dstFile {
			t.Fatalf("row names %s, want %s", got, dstFile)
		}
	})
	t.Run("forward", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		block(t, s)
		rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
		err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
		if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "nothing changed") {
			t.Fatalf("want the cutover refused, got %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != srcFile {
			t.Fatalf("row names %s", got)
		}
		if after := mustInactive(t, f, "vm1"); strings.Contains(after, dstFile) {
			t.Fatalf("config changed: %s", after)
		}
	})
}

// publishForeignCondition raises vm1's condition as host holder would, with a
// live, unpivoted move of its root disk to dstFile.
func publishForeignCondition(t *testing.T, s *Server, holder, srcFile, dstFile string, pivoted bool) {
	t.Helper()
	dir := t.TempDir()
	if err := health.RecordUnresolvedMove(dir, health.UnresolvedMove{VM: "vm1", Disk: "root", TargetDev: "vda",
		Src: srcFile, SrcType: "local", SrcPool: "hot", Dst: dstFile, DstType: "local", DstPool: "warm",
		Live: true, Pivoted: pivoted}); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(context.Background(), s.db, dir, holder, "vm1"); err != nil {
		t.Fatal(err)
	}
}

func moveEvidence(t *testing.T, s *Server, vm string) health.MoveUnresolvedEvidence {
	t.Helper()
	_, ev, _, err := health.OpenMoveCondition(context.Background(), s.db, vm)
	if err != nil {
		t.Fatal(err)
	}
	return ev
}

// N-4: on a host that does not hold the condition, a move of the disk honours
// it (here: no pivot recorded, the row on the copy, so refused) and never
// overwrites the holder's entries; a move of another disk of the VM is
// refused rather than overwrite the holder's condition.
func TestMoveVolume_NonHolderHonoursTheCondition(t *testing.T) {
	s, _, srcFile, dstFile := offlineMoveServer(t)
	if err := copyMovedFile(srcFile, dstFile); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(context.Background(), s.db, "vm1", "root", "test-host", dstFile, "local", "warm"); err != nil {
		t.Fatal(err)
	}
	publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
	before := moveEvidence(t, s, "vm1")

	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "hot"}, rec)
	if !health.IsMoveUnresolved(err) || !strings.Contains(err.Error(), "node-a") {
		t.Fatalf("want the move refused by node-a's condition, got %v", err)
	}
	if got := diskRowPath(t, s, "vm1"); got != dstFile {
		t.Fatalf("row changed to %s", got)
	}
	if after := moveEvidence(t, s, "vm1"); after.Host != before.Host || len(after.Moves) != 1 || after.Moves[0].Dst != dstFile {
		t.Fatalf("the holder's condition was overwritten: %+v", after)
	}
}

// N-4: a covered disk already on the target pool, dispatched by a stack
// migration to a non-holder owner whose condition entry is proven settled
// (pivoted, row on the copy), is a DONE no-op, and the owner resolves the
// condition — not a "same path" error.
func TestMoveOneVolume_SettledForeignConditionIsANoOp(t *testing.T) {
	s, _, srcFile, dstFile := offlineMoveServer(t)
	if err := copyMovedFile(srcFile, dstFile); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.UpdateDiskPlacement(context.Background(), s.db, "vm1", "root", "test-host", dstFile, "local", "warm"); err != nil {
		t.Fatal(err)
	}
	publishForeignCondition(t, s, "node-a", srcFile, dstFile, true)
	vm, _ := corrosion.GetVM(context.Background(), s.db, "vm1")
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	var frames []*pb.MoveVolumeProgress
	err := s.moveOneVolume(context.Background(), vm, &disks[0], "warm", false, func(p *pb.MoveVolumeProgress) error {
		frames = append(frames, p)
		return nil
	})
	if err != nil {
		t.Fatalf("moveOneVolume: %v", err)
	}
	if len(frames) != 1 || frames[0].Phase != pb.MoveVolumeProgress_DONE {
		t.Fatalf("want one DONE frame, got %+v", frames)
	}
	if health.MoveConditionCovers(context.Background(), s.db, "vm1", "root") {
		t.Fatal("the owner did not resolve a settled condition")
	}
}

// acceptCtx is adminCtx carrying `lv health resolve --accept path`.
func acceptCtx(path string) context.Context {
	ctx := adminCtx()
	md, _ := metadata.FromIncomingContext(ctx)
	md = metadata.Join(md, metadata.Pairs(MoveAcceptMDKey, path))
	return metadata.NewIncomingContext(ctx, md)
}

// N-2, N2-2, N2-3: `lv health resolve vm.move_unresolved` needs a reason; from
// another host it is accepted only once the holder is proven powered off
// (corrosion.SharedDiskOwnerProvedOff); on the holder it also removes the
// records; --accept points the disk row at one of the move's files first.
func TestResolveHealthCondition_MoveUnresolved(t *testing.T) {
	ctx := context.Background()
	req := func(reason string) *pb.ResolveHealthConditionRequest {
		return &pb.ResolveHealthConditionRequest{Code: health.MoveUnresolvedCode, SubjectKind: "vm", SubjectId: "vm1", Reason: reason}
	}
	holder := func(t *testing.T, s *Server, state string, fences ...[2]string) {
		t.Helper()
		if state != "" {
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: "node-a", Address: "10.0.0.9", State: state}); err != nil {
				t.Fatal(err)
			}
		}
		for i, f := range fences {
			if err := corrosion.InsertFenceLog(ctx, s.db, corrosion.FenceLogRecord{ID: fmt.Sprintf("f%d", i), HostName: "node-a", Method: f[0], Result: f[1]}); err != nil {
				t.Fatal(err)
			}
		}
	}
	t.Run("no reason", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
		if _, err := s.ResolveHealthCondition(adminCtx(), req("")); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("want InvalidArgument, got %v", err)
		}
	})
	for _, tc := range []struct {
		name   string
		state  string
		fences [][2]string
		ok     bool
	}{
		{"holder alive", "active", nil, false},
		{"holder fenced, not proven off", "fenced", [][2]string{{"ssh", "fenced"}}, false},
		{"holder fenced and confirmed down", "fenced", [][2]string{{"manual", "manual-confirmed"}}, true},
		{"holder confirmed down, then rejoined", "active", [][2]string{{"manual", "manual-confirmed"}}, false},
		{"holder removed, never proven off", "", nil, false},
		{"holder removed after a confirmation", "", [][2]string{{"manual", "manual-confirmed"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, srcFile, dstFile := offlineMoveServer(t)
			holder(t, s, tc.state, tc.fences...)
			publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
			_, err := s.ResolveHealthCondition(adminCtx(), req("disk checked"))
			if tc.ok {
				if err != nil {
					t.Fatalf("resolve: %v", err)
				}
				if health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
					t.Fatal("not resolved")
				}
				return
			}
			if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "node-a holds") ||
				!strings.Contains(err.Error(), "fence-confirm") {
				t.Fatalf("want a refusal naming the holder, got %v", err)
			}
			if !health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
				t.Fatal("resolved anyway")
			}
		})
	}
	t.Run("on the holder", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		if _, err := s.ResolveHealthCondition(adminCtx(), req("guest was pivoted by hand")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if ms := moveRecords(t, s, "vm1"); len(ms) != 0 {
			t.Fatalf("records kept: %+v", ms)
		}
		vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
		if _, err := s.startVMLocked(adminCtx(), vm); err != nil {
			t.Fatalf("the start after the resolve: %v", err)
		}
	})
	t.Run("--accept the copy on the holder", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		if _, err := s.ResolveHealthCondition(acceptCtx(dstFile), req("guest was pivoted before the crash")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != dstFile {
			t.Fatalf("row names %s, want the accepted %s", got, dstFile)
		}
		if health.MoveConditionCovers(ctx, s.db, "vm1", "root") || len(moveRecords(t, s, "vm1")) != 0 {
			t.Fatal("not resolved")
		}
	})
	t.Run("--accept a file the move does not name", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		if _, err := s.ResolveHealthCondition(acceptCtx("/etc/passwd"), req("x")); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("want InvalidArgument, got %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != srcFile {
			t.Fatalf("row changed to %s", got)
		}
	})
	t.Run("--accept from a host that does not read the holder's file", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		holder(t, s, "fenced", [2]string{"manual", "manual-confirmed"})
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
		_, err := s.ResolveHealthCondition(acceptCtx(dstFile), req("x"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "does not read that file") {
			t.Fatalf("want a refusal, got %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != srcFile || !health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
			t.Fatalf("row %s / condition changed", got)
		}
	})
}

// m-3: a VM created under a name an earlier VM's unresolved move was recorded
// for starts clean: the record and the condition are dropped.
func TestCreateVM_ForgetsAnEarlierVMsMoveRecords(t *testing.T) {
	s, _ := provableCreateServer(t)
	if err := health.RecordUnresolvedMove(s.dataDir, health.UnresolvedMove{VM: "reborn", Disk: "root", Src: "/a/x", Dst: "/b/x", Live: true}); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(context.Background(), s.db, s.dataDir, s.hostName, "reborn"); err != nil {
		t.Fatal(err)
	}
	req := disklessCreateRequest("reborn")
	req.Spec.Network = nil
	if _, err := s.CreateVM(adminCtx(), req); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	if ms := moveRecords(t, s, "reborn"); len(ms) != 0 {
		t.Fatalf("records kept: %+v", ms)
	}
	if health.MoveConditionCovers(context.Background(), s.db, "reborn", "root") {
		t.Fatal("condition left open")
	}
}
