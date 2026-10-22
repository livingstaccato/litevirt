package grpcapi

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	"github.com/litevirt/litevirt/internal/storage"
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
	if _, err := s.coldMoveDisks(context.Background(), vm, "target"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want a refusal while the config cannot be read, got %v", err)
	}
	f.FailDumpXMLInactive = nil
	disks, err := s.coldMoveDisks(context.Background(), vm, "target")
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

// acceptCtx is adminCtx carrying `lv health resolve --accept path`, once per
// path.
func acceptCtx(paths ...string) context.Context {
	ctx := adminCtx()
	md, _ := metadata.FromIncomingContext(ctx)
	for _, p := range paths {
		md = metadata.Join(md, metadata.Pairs(MoveAcceptMDKey, p))
	}
	return metadata.NewIncomingContext(ctx, md)
}

func moveResolveReq(reason string) *pb.ResolveHealthConditionRequest {
	return &pb.ResolveHealthConditionRequest{Code: health.MoveUnresolvedCode, SubjectKind: "vm", SubjectId: "vm1", Reason: reason}
}

// holderNodeA records node-a in state (none: removed) with fences.
func holderNodeA(t *testing.T, s *Server, state string, fences ...[2]string) {
	t.Helper()
	ctx := context.Background()
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

func provenOffNodeA(t *testing.T, s *Server) {
	t.Helper()
	holderNodeA(t, s, "fenced", [2]string{"manual", "manual-confirmed"})
}

// mustRefuse asserts err is a FailedPrecondition saying each of want, and that
// vm1's root row still names row and its condition is open.
func mustRefuse(t *testing.T, s *Server, err error, row string, want ...string) {
	t.Helper()
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("want FailedPrecondition, got %v", err)
	}
	for _, w := range want {
		if !strings.Contains(err.Error(), w) {
			t.Fatalf("refusal does not say %q: %v", w, err)
		}
	}
	if got := diskRowPath(t, s, "vm1"); got != row {
		t.Fatalf("row changed to %s", got)
	}
	if !health.MoveConditionCovers(context.Background(), s.db, "vm1", "root") {
		t.Fatal("resolved anyway")
	}
}

// N-2, N2-2, N2-3, I3-1, I3-2, m3-1: `lv health resolve vm.move_unresolved`
// needs a reason; from another host it is accepted only once the holder is
// proven powered off, and never defaults a move the row does not settle to
// the row; on the holder that owns the VM it is accepted only with the domain
// shut off and its persistent config naming the file the row is left on.
func TestResolveHealthCondition_MoveUnresolved(t *testing.T) {
	ctx := context.Background()
	t.Run("no reason", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
		if _, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("")); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("want InvalidArgument, got %v", err)
		}
	})
	// The gate, over a move the row settles (pivoted, row on the copy).
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
			s, f, srcFile, dstFile := offlineMoveServer(t)
			holderNodeA(t, s, tc.state, tc.fences...)
			if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dstFile, "local", "warm"); err != nil {
				t.Fatal(err)
			}
			// This host owns the VM: its config names the row's file.
			if err := f.DefineDomain(fakeDomainXML("vm1", "vda", dstFile)); err != nil {
				t.Fatal(err)
			}
			publishForeignCondition(t, s, "node-a", srcFile, dstFile, true)
			_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("disk checked"))
			if tc.ok {
				if err != nil {
					t.Fatalf("resolve: %v", err)
				}
				if health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
					t.Fatal("not resolved")
				}
				return
			}
			mustRefuse(t, s, err, dstFile, "node-a holds", "fence-confirm", "LV_HOST=node-a")
		})
	}

	// On the holder, which owns the VM: the persistent config decides.
	t.Run("holder: the config names the copy, the row the source, no --accept: refused", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("guest was pivoted by hand"))
		mustRefuse(t, s, err, srcFile, "names "+dstFile, "--accept "+dstFile, "virsh edit vm1")
		if ms := moveRecords(t, s, "vm1"); len(ms) != 1 {
			t.Fatalf("records: %+v", ms)
		}
	})
	t.Run("holder: --accept the source while the config names the copy: refused", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		_, err := s.ResolveHealthCondition(acceptCtx(srcFile), moveResolveReq("guest was not pivoted"))
		mustRefuse(t, s, err, srcFile, "names "+dstFile, "--accept "+dstFile)
	})
	t.Run("holder: --accept the copy the config names", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		if _, err := s.ResolveHealthCondition(acceptCtx(dstFile), moveResolveReq("guest was pivoted before the crash")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != dstFile {
			t.Fatalf("row names %s, want the accepted %s", got, dstFile)
		}
		if health.MoveConditionCovers(ctx, s.db, "vm1", "root") || len(moveRecords(t, s, "vm1")) != 0 {
			t.Fatal("not resolved")
		}
		vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
		if _, err := s.startVMLocked(adminCtx(), vm); err != nil {
			t.Fatalf("the start after the resolve: %v", err)
		}
		if x := mustInactive(t, f, "vm1"); !strings.Contains(x, dstFile) {
			t.Fatalf("the config does not name the row's file: %s", x)
		}
	})
	t.Run("holder: the config and the row name the source", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, srcFile, true, false)
		if _, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("guest was not pivoted")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != srcFile || health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
			t.Fatalf("row %s / not resolved", got)
		}
	})
	t.Run("holder: the domain is running: refused", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, srcFile, true, false)
		f.SetState("vm1", libvirtfake.StateRunning)
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("x"))
		mustRefuse(t, s, err, srcFile, "domain is active", "lv stop vm1")
	})
	t.Run("holder: a move of the disk in flight: refused", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		vm, _ := corrosion.GetVM(ctx, s.db, "vm1")
		disks, _ := corrosion.GetVMDisks(ctx, s.db, "vm1")
		mk, err := s.beginMoveMarker(ctx, vm, &disks[0], dstFile, "local", "warm", false, false, false)
		if err != nil {
			t.Fatal(err)
		}
		defer mk.done()
		_, rerr := s.ResolveHealthCondition(adminCtx(), moveResolveReq("x"))
		if status.Code(rerr) != codes.Unavailable || !strings.Contains(rerr.Error(), "in progress") {
			t.Fatalf("want a refusal while the move runs, got %v", rerr)
		}
		if !health.MoveConditionCovers(ctx, s.db, "vm1", "root") || diskRowPath(t, s, "vm1") != srcFile {
			t.Fatal("changed while the move ran")
		}
	})
	t.Run("--accept a file the move does not name", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		crashAfterDefine(t, s, f, srcFile, dstFile, dstFile, true, false)
		if _, err := s.ResolveHealthCondition(acceptCtx("/etc/passwd"), moveResolveReq("x")); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("want InvalidArgument, got %v", err)
		}
		if got := diskRowPath(t, s, "vm1"); got != srcFile {
			t.Fatalf("row changed to %s", got)
		}
	})

	// From another host, node-a proven off.
	t.Run("elsewhere: no pivot recorded, no --accept: refused", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		provenOffNodeA(t, s)
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("node-a is gone"))
		mustRefuse(t, s, err, srcFile, "recorded no pivot", "--accept", "qemu-img compare")
	})
	t.Run("elsewhere: pivoted, the row on the source, no --accept: refused", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		provenOffNodeA(t, s)
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, true)
		_, err := s.ResolveHealthCondition(adminCtx(), moveResolveReq("node-a is gone"))
		mustRefuse(t, s, err, srcFile, "only `--accept "+dstFile+"`")
	})
	t.Run("elsewhere: pivoted, --accept the source: refused", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		provenOffNodeA(t, s)
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, true)
		_, err := s.ResolveHealthCondition(acceptCtx(srcFile), moveResolveReq("node-a is gone"))
		mustRefuse(t, s, err, srcFile, "only `--accept "+dstFile+"`")
	})
	t.Run("elsewhere: --accept on a host that does not read the holder's file: refused", func(t *testing.T) {
		s, f, srcFile, dstFile := offlineMoveServer(t)
		provenOffNodeA(t, s)
		if err := f.DefineDomain(fakeDomainXML("vm1", "vda", dstFile)); err != nil {
			t.Fatal(err)
		}
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
		_, err := s.ResolveHealthCondition(acceptCtx(dstFile), moveResolveReq("x"))
		mustRefuse(t, s, err, srcFile, "does not read that file")
	})
	t.Run("elsewhere: --accept for a disk row that names neither file: refused", func(t *testing.T) {
		s, _, srcFile, dstFile := offlineMoveServer(t)
		provenOffNodeA(t, s)
		publishForeignCondition(t, s, "node-a", srcFile, dstFile, false)
		if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", "/srv/new/root.qcow2", "local", "hot"); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(acceptCtx(srcFile), moveResolveReq("x"))
		mustRefuse(t, s, err, "/srv/new/root.qcow2", "neither file of the move")
	})
}

// sharedMoveServer is test-host owning vm1, whose disks were moving live,
// with no pivot recorded, from pool hot (ceph) to pool warm (nfs) on node-a,
// now proven powered off. Both hosts define both pools alike and both are
// mounted here. src and dst map each disk to its files.
func sharedMoveServer(t *testing.T, disks ...string) (s *Server, src, dst map[string]string) {
	t.Helper()
	ctx := context.Background()
	s = testServer(t)
	s.hostName = "test-host"
	s.dataDir = t.TempDir()
	s.virt = libvirtfake.New()
	hot, warm := filepath.Join(s.dataDir, "mnt", "hot"), filepath.Join(s.dataDir, "mnt", "warm")
	src, dst = map[string]string{}, map[string]string{}
	var rows []corrosion.DiskRecord
	var moves []health.UnresolvedMove
	for i, d := range disks {
		src[d], dst[d] = filepath.Join(hot, "vm1-"+d+".qcow2"), filepath.Join(warm, "vm1-"+d+".qcow2")
		for _, p := range []string{src[d], dst[d]} {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		dev := fmt.Sprintf("vd%c", 'a'+i)
		rows = append(rows, corrosion.DiskRecord{VMName: "vm1", DiskName: d, HostName: "test-host", Path: src[d],
			TargetDev: dev, StorageType: "ceph", StorageVolume: "hot", SizeBytes: 1})
		moves = append(moves, health.UnresolvedMove{VM: "vm1", Disk: d, TargetDev: dev, Src: src[d], SrcType: "ceph", SrcPool: "hot",
			Dst: dst[d], DstType: "nfs", DstPool: "warm", Live: true})
	}
	if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "vm1", HostName: "test-host", State: "stopped"}, nil, rows); err != nil {
		t.Fatal(err)
	}
	for _, h := range []string{"test-host", "node-a"} {
		for _, p := range []corrosion.StoragePoolRecord{
			{HostName: h, Name: "hot", Driver: "ceph", Source: "mon:/vms", Target: hot},
			{HostName: h, Name: "warm", Driver: "nfs", Source: "nas:/vol", Target: warm},
		} {
			if err := corrosion.UpsertStoragePool(ctx, s.db, p); err != nil {
				t.Fatal(err)
			}
		}
	}
	tab := "1 0 8:1 / / rw - ext4 /dev/sda1 rw\n" +
		"2 1 0:40 / " + hot + " rw,nosuid,nodev - ceph mon:/vms rw\n" +
		"3 1 0:41 / " + warm + " rw,nosuid,nodev,noexec,nosymfollow - nfs4 nas:/vol rw\n"
	t.Cleanup(storage.OverrideMountInfoForTest(func() ([]byte, error) { return []byte(tab), nil }))
	provenOffNodeA(t, s)
	holderDir := t.TempDir()
	for _, m := range moves {
		if err := health.RecordUnresolvedMove(holderDir, m); err != nil {
			t.Fatal(err)
		}
	}
	if err := health.PublishUnresolvedMoves(ctx, s.db, holderDir, "node-a", "vm1"); err != nil {
		t.Fatal(err)
	}
	return s, src, dst
}

func diskRowOf(t *testing.T, s *Server, disk string) corrosion.DiskRecord {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range disks {
		if d.DiskName == disk {
			return d
		}
	}
	t.Fatalf("no disk %s", disk)
	return corrosion.DiskRecord{}
}

// I3-1, review concern 2: --accept on the VM's owner after a failover, the
// holder proven off: the row takes the accepted file with that file's type
// and pool and stays on the owner; every disk the row does not settle needs
// its own --accept; a host that is neither the owner nor the holder, or one
// whose pool is not the holder's, is refused; a resolution that cannot be
// recorded points the row back and is audited.
func TestResolveHealthCondition_AcceptOnTheOwnerAfterAFailover(t *testing.T) {
	ctx := context.Background()
	t.Run("--accept the copy", func(t *testing.T) {
		s, _, dst := sharedMoveServer(t, "root")
		if _, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("the copy is newer")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if r := diskRowOf(t, s, "root"); r.Path != dst["root"] || r.StorageType != "nfs" || r.StorageVolume != "warm" || r.HostName != "test-host" {
			t.Fatalf("row = %+v", r)
		}
		if health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
			t.Fatal("not resolved")
		}
		if row, _, err := corrosion.GetHealthCondition(ctx, s.db, health.MoveUnresolvedEvaluator, health.MoveUnresolvedCode, "vm", "vm1"); err != nil ||
			!strings.Contains(row.Evidence, `"hand":true`) {
			t.Fatalf("the resolution is not marked as by hand, so a returning holder raises it again: %q %v", row.Evidence, err)
		}
	})
	t.Run("--accept the source", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root")
		if err := corrosion.UpdateDiskPlacement(ctx, s.db, "vm1", "root", "test-host", dst["root"], "nfs", "warm"); err != nil {
			t.Fatal(err)
		}
		if _, err := s.ResolveHealthCondition(acceptCtx(src["root"]), moveResolveReq("the source is newer")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if r := diskRowOf(t, s, "root"); r.Path != src["root"] || r.StorageType != "ceph" || r.StorageVolume != "hot" || r.HostName != "test-host" {
			t.Fatalf("row = %+v", r)
		}
	})
	t.Run("on a host that is neither the owner nor the holder: refused", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root")
		if err := s.db.Execute(ctx, `UPDATE vms SET host_name = 'node-b' WHERE name = 'vm1'`); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x"))
		mustRefuse(t, s, err, src["root"], "run it on the VM's owner node-b")
	})
	t.Run("this host's pool of that name is local: refused", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root")
		if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{HostName: "test-host", Name: "warm",
			Driver: "local", Target: filepath.Dir(dst["root"])}); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x"))
		mustRefuse(t, s, err, src["root"], "does not read that file")
	})
	t.Run("two disks: one --accept each", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root", "data")
		_, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x"))
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "disk data") {
			t.Fatalf("want the resolve refused for disk data, got %v", err)
		}
		if diskRowOf(t, s, "root").Path != src["root"] || diskRowOf(t, s, "data").Path != src["data"] ||
			!health.MoveConditionCovers(ctx, s.db, "vm1", "root") {
			t.Fatal("changed by a refused resolve")
		}
		if _, err := s.ResolveHealthCondition(acceptCtx(dst["root"], src["data"]), moveResolveReq("checked both")); err != nil {
			t.Fatalf("resolve: %v", err)
		}
		if diskRowOf(t, s, "root").Path != dst["root"] || diskRowOf(t, s, "data").Path != src["data"] {
			t.Fatal("rows not as accepted")
		}
	})
	t.Run("the resolution cannot be recorded: the row is pointed back, audited", func(t *testing.T) {
		s, src, dst := sharedMoveServer(t, "root")
		if err := s.db.Execute(ctx, `CREATE TRIGGER fail_condition_resolve BEFORE UPDATE ON health_conditions
			BEGIN SELECT RAISE(ABORT, 'injected'); END`); err != nil {
			t.Fatal(err)
		}
		_, err := s.ResolveHealthCondition(acceptCtx(dst["root"]), moveResolveReq("x"))
		if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "pointed back at "+src["root"]) {
			t.Fatalf("want the failure, naming the row pointed back, got %v", err)
		}
		if r := diskRowOf(t, s, "root"); r.Path != src["root"] || r.StorageType != "ceph" {
			t.Fatalf("row left at %+v", r)
		}
		rows, qerr := s.db.Query(ctx, `SELECT result, detail FROM audit_log WHERE action = 'health.condition.resolve' AND result != 'pending'`)
		if qerr != nil || len(rows) != 1 || rows[0].String("result") != "failed" || !strings.Contains(rows[0].String("detail"), "pointed back") {
			t.Fatalf("audit = %+v %v", rows, qerr)
		}
	})
}

// m3-3: --accept on any other code is refused, not ignored.
func TestResolveHealthCondition_AcceptOnlyOnMoveConditions(t *testing.T) {
	s := testServer(t)
	if err := corrosion.UpsertHealthCondition(context.Background(), s.db, corrosion.HealthCondition{Evaluator: dualRunEvaluator,
		Code: "vm_dual_run", SubjectKind: "vm", SubjectID: "vm1", Lifecycle: corrosion.ConditionConfirmed,
		LastSeen: "2026-10-18T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	_, err := s.ResolveHealthCondition(acceptCtx("/x"), &pb.ResolveHealthConditionRequest{Code: "vm_dual_run", SubjectKind: "vm", SubjectId: "vm1", Reason: "x"})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "--accept applies only") {
		t.Fatalf("want InvalidArgument, got %v", err)
	}
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

// moveRecordKept fails unless vm's record is still here and its condition
// still open.
func moveRecordKept(t *testing.T, s *Server, vm, what string) {
	t.Helper()
	if ms := moveRecords(t, s, vm); len(ms) == 0 {
		t.Errorf("%s: the record was dropped", what)
	}
	if !health.MoveConditionCovers(context.Background(), s.db, vm, "root") {
		t.Errorf("%s: the condition was resolved", what)
	}
}

// moveRecordGone fails unless vm's records here are gone and its condition
// resolved.
func moveRecordGone(t *testing.T, s *Server, vm, what string) {
	t.Helper()
	if ms := moveRecords(t, s, vm); len(ms) != 0 {
		t.Errorf("%s: records kept: %+v", what, ms)
	}
	if health.MoveConditionCovers(context.Background(), s.db, vm, "root") {
		t.Errorf("%s: condition left open", what)
	}
}

// publishMoveAs records a move of vm's root disk here and opens its
// condition as reporter.
func publishMoveAs(t *testing.T, s *Server, vm, reporter string) {
	t.Helper()
	if err := health.RecordUnresolvedMove(s.dataDir, health.UnresolvedMove{VM: vm, Disk: "root", Src: "/a/x", Dst: "/b/x", Live: true}); err != nil {
		t.Fatal(err)
	}
	if err := health.PublishUnresolvedMoves(context.Background(), s.db, s.dataDir, reporter, vm); err != nil {
		t.Fatal(err)
	}
	if !health.MoveConditionCovers(context.Background(), s.db, vm, "root") {
		t.Fatal("control: no open condition before the delete")
	}
}

// failTombstoneOf makes every tombstone of vm's row fail until the returned
// func is called.
func failTombstoneOf(t *testing.T, s *Server, vm string) func() {
	t.Helper()
	if err := s.db.Execute(context.Background(), `CREATE TRIGGER fail_vm_tombstone BEFORE UPDATE OF deleted_at ON vms
		WHEN OLD.name = '`+vm+`' AND NEW.deleted_at IS NOT NULL BEGIN SELECT RAISE(ABORT, 'injected tombstone failure'); END`); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := s.db.Execute(context.Background(), `DROP TRIGGER fail_vm_tombstone`); err != nil {
			t.Fatal(err)
		}
	}
}

// removedHost records host as a cluster member that was removed.
func removedHost(t *testing.T, s *Server, host string) {
	t.Helper()
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: host, Address: "10.0.0.9", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `UPDATE hosts SET deleted_at = '2026-10-19T00:00:00Z' WHERE name = ?`, host); err != nil {
		t.Fatal(err)
	}
	if removed, err := corrosion.HostRemoved(ctx, s.db, host); err != nil || !removed {
		t.Fatalf("control: %s not removed (%v)", host, err)
	}
}

// A deleted VM's unresolved volume-move records and condition go with it,
// whichever path the delete takes, and only once its row is tombstoned: a
// delete that fails before that keeps the row, and with it the record and
// condition that guard its next start. Each path is driven through DeleteVM.
//
// Mutations, one at a time:
//   - drop the forget on the path with a domain here: "domain here" is red;
//     move it back above the tombstone: its failed delete is red;
//   - the same for the path that cleans up a record whose domain is gone
//     everywhere ("no domain anywhere");
//   - the same for deleteVMOnRemovedHost ("recorded on a removed host"),
//     including the forget moved above corrosion.DeleteVM.
func TestDeleteVM_ForgetsTheVMsMoveRecords(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T) *Server
		raise string // the condition's reporter; "" is this host
	}{
		{"domain here", func(t *testing.T) *Server {
			s, _ := deleteDiskServerWith(t, true)
			return s
		}, ""},
		{"no domain anywhere", func(t *testing.T) *Server {
			s, _, _ := runningNoDomainServer(t)
			return s
		}, ""},
		{"recorded on a removed host", func(t *testing.T) *Server {
			s := testServerWithLocks(t)
			removedHost(t, s, "gone-host")
			if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{Name: "a", HostName: "gone-host", Spec: "{}", State: "running"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			return s
		}, "gone-host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := tc.setup(t)
			reporter := tc.raise
			if reporter == "" {
				reporter = s.hostName
			}
			publishMoveAs(t, s, "a", reporter)
			restore := failTombstoneOf(t, s, "a")
			if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"}); err == nil {
				t.Fatal("the delete succeeded although its tombstone was made to fail")
			}
			if vm, _ := corrosion.GetVM(context.Background(), s.db, "a"); vm == nil {
				t.Fatal("control: the failed delete tombstoned the row")
			}
			moveRecordKept(t, s, "a", "a delete that failed at its tombstone")
			restore()
			if _, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"}); err != nil {
				t.Fatalf("DeleteVM: %v", err)
			}
			if vm, _ := corrosion.GetVM(context.Background(), s.db, "a"); vm != nil {
				t.Fatalf("the VM row survived the delete: %+v", vm)
			}
			moveRecordGone(t, s, "a", "the delete")
		})
	}
}

// A delete that tombstoned the VM and stopped before its forget (a crash
// between the two) leaves the record and condition; a later lv rm of the
// name, which finds only the tombstone, finishes the forget. A condition
// another live host raised is left: it may be a newer VM's of the name whose
// row this replica has not received.
//
// Mutations: drop the forget from deleteOfNoLiveRow — "this host raised it"
// and "a removed host raised it" are red; resolve whichever host raised it —
// "another live host raised it" is red.
func TestDeleteVM_OfATombstonedVMFinishesItsForget(t *testing.T) {
	for _, tc := range []struct {
		name     string
		reporter string // "" is this host
		removed  bool
		wantGone bool
	}{
		{"this host raised it", "", false, true},
		{"a removed host raised it", "gone-host", true, true},
		{"another live host raised it", "node-b", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServerWithLocks(t)
			ctx := context.Background()
			reporter := tc.reporter
			if reporter == "" {
				reporter = s.hostName
			}
			if tc.removed {
				removedHost(t, s, reporter)
			}
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "a", HostName: s.hostName, Spec: "{}", State: "stopped"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			publishMoveAs(t, s, "a", reporter)
			if err := corrosion.DeleteVM(ctx, s.db, "a"); err != nil { // the tombstone, then the crash
				t.Fatal(err)
			}
			_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "a"})
			if status.Code(err) != codes.NotFound {
				t.Fatalf("lv rm of a deleted VM: %v, want NotFound", err)
			}
			if ms := moveRecords(t, s, "a"); len(ms) != 0 {
				t.Errorf("records of a deleted VM kept: %+v", ms)
			}
			open := health.MoveConditionCovers(ctx, s.db, "a", "root")
			if tc.wantGone && open {
				t.Error("the deleted VM's condition is still open")
			}
			if !tc.wantGone && !open {
				t.Error("a condition another live host raised was resolved")
			}
		})
	}
}

// A rebuild forgets the old VM's unresolved-move records and condition only
// once its row is tombstoned: one that fails before that keeps the row, and
// with it the record and condition that guard its next start.
//
// Mutation: move RebuildVM's forget back to right after its undefine — the
// failed rebuild drops the record, red.
func TestRebuildVM_ForgetsTheMoveRecordsOnlyOnceTheRowIsTombstoned(t *testing.T) {
	stageGenisoimage(t)
	s, _, _ := isoServer(t)
	const name = "rbm"
	if _, err := s.CreateVM(adminCtx(), seedCreateRequest(t, s, name, "")); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	publishMoveAs(t, s, name, s.hostName)
	restore := failTombstoneOf(t, s, name)
	if _, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name}); err == nil {
		t.Fatal("the rebuild succeeded although its tombstone was made to fail")
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, name); vm == nil {
		t.Fatal("control: the failed rebuild tombstoned the row")
	}
	moveRecordKept(t, s, name, "a rebuild that failed at its tombstone")
	restore()
	if _, err := s.RebuildVM(adminCtx(), &pb.RebuildVMRequest{Name: name}); err != nil {
		t.Fatalf("RebuildVM: %v", err)
	}
	moveRecordGone(t, s, name, "the rebuild")
}

// The forget a later lv rm finishes for a deleted VM is the deleter's to do:
// a caller who may not delete that VM (an operator of another project)
// leaves its record and condition as they are.
//
// Mutation: drop the vm.delete check before forgetMovesOfDeletedVM — the
// other project's operator clears them, red.
func TestDeleteVM_OfATombstonedVMForgetsOnlyForItsDeleter(t *testing.T) {
	for _, tc := range []struct {
		project  string
		wantGone bool
	}{
		{"beta", false},
		{"alpha", true},
	} {
		t.Run("operator of "+tc.project, func(t *testing.T) {
			s := testServerWithLocks(t)
			ctx := context.Background()
			if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: "a", HostName: s.hostName, Spec: "{}", State: "stopped", Project: "alpha"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			publishMoveAs(t, s, "a", s.hostName)
			if err := corrosion.DeleteVM(ctx, s.db, "a"); err != nil {
				t.Fatal(err)
			}
			caller := projectBoundCtx(t, s, "op-"+tc.project, tc.project)
			if _, err := s.DeleteVM(caller, &pb.DeleteVMRequest{Name: "a"}); status.Code(err) != codes.NotFound {
				t.Fatalf("lv rm of a deleted VM: %v, want NotFound", err)
			}
			if tc.wantGone {
				moveRecordGone(t, s, "a", "lv rm by the VM's project operator")
			} else {
				moveRecordKept(t, s, "a", "lv rm by another project's operator")
			}
		})
	}
}
