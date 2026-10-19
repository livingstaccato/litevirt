package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The managed stamp and owner-epoch marker as libvirt dumps them in a
// litevirt domain's <metadata> (SetDomainManagedIncarnation, SetDomainOwnerEpoch).
const (
	mvManagedEl    = `<litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1" incarnation="2026-10-17T18:44:33.798Z"/>`
	mvOwnerEpochEl = `<litevirt-owner-epoch:owner-epoch xmlns:litevirt-owner-epoch="https://litevirt.dev/xmlns/owner-epoch/1">4</litevirt-owner-epoch:owner-epoch>`
)

func litevirtDomainXML(name, dev, srcPath string) string {
	return "<domain type='kvm'>\n  <name>" + name + "</name>\n  <uuid>" + libvirtfake.DomainUUIDFor(name) + "</uuid>\n  <metadata>\n    " +
		mvManagedEl + "\n    " + mvOwnerEpochEl + "\n  </metadata>\n  <devices>\n" +
		"    <disk type='file' device='disk'>\n      <driver name='qemu' type='qcow2'/>\n" +
		"      <source file='" + srcPath + "'/>\n      <target dev='" + dev + "' bus='virtio'/>\n" +
		"    </disk>\n  </devices>\n</domain>\n"
}

// lv move-volume of a litevirt VM: its definition carries litevirt's
// namespaced metadata, and the move repoints the disk and redefines the
// domain with that metadata exactly as it was.
func TestMoveVolume_Offline_LitevirtMetadataSurvives(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	before := litevirtDomainXML("vm1", "vda", srcFile)
	if err := f.DefineDomain(before); err != nil {
		t.Fatalf("define: %v", err)
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{
		VmName: "vm1", DiskName: "root", TargetPool: "warm",
	}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	after, _ := f.DumpXMLInactive("vm1")
	if want := strings.Replace(before, srcFile, dstFile, 1); after != want {
		t.Fatalf("redefined domain is not the old one with only the disk repointed:\n%s", after)
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if len(disks) != 1 || disks[0].Path != dstFile {
		t.Fatalf("disk row not repointed: %+v", disks)
	}
}

// withEpoch5 is a litevirt domain whose owner-epoch marker reads 5, as one written
// by the reconciler while a move runs.
func withEpoch5(x string) string {
	return strings.Replace(x, ">4</litevirt-owner-epoch:owner-epoch>", ">5</litevirt-owner-epoch:owner-epoch>", 1)
}

// onSecondInactiveDump runs fn once, before the second persistent-config read of
// the move (the first is the preflight before the copy).
func onSecondInactiveDump(f *libvirtfake.Fake, fn func()) {
	n := 0
	f.FailDumpXMLInactive = func(string) error {
		n++
		if n == 2 {
			fn()
		}
		return nil
	}
}

// The owner-epoch marker is rewritten while the offline copy runs. The define
// carries the new marker, with only the disk repointed, rather than writing back
// the config read before the copy.
func TestMoveVolume_Offline_RebasesOnConfigChangedDuringCopy(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	before := litevirtDomainXML("vm1", "vda", srcFile)
	if err := f.DefineDomain(before); err != nil {
		t.Fatalf("define: %v", err)
	}
	onSecondInactiveDump(f, func() {
		if err := f.DefineDomain(withEpoch5(before)); err != nil {
			t.Errorf("redefine during copy: %v", err)
		}
	})
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	after, _ := f.DumpXMLInactive("vm1")
	if want := strings.Replace(withEpoch5(before), srcFile, dstFile, 1); after != want {
		t.Fatalf("define did not carry the marker written during the copy:\n%s", after)
	}
}

// The moved disk itself is repointed elsewhere while the copy runs. The move is
// refused: the config is left naming what it names, the copy is removed, the DB
// row and the source are kept.
func TestMoveVolume_Offline_RefusesWhenDiskChangedDuringCopy(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	before := litevirtDomainXML("vm1", "vda", srcFile)
	if err := f.DefineDomain(before); err != nil {
		t.Fatalf("define: %v", err)
	}
	elsewhere := litevirtDomainXML("vm1", "vda", "/var/lib/litevirt/disks/vm1-other.qcow2")
	onSecondInactiveDump(f, func() {
		if err := f.DefineDomain(elsewhere); err != nil {
			t.Errorf("redefine during copy: %v", err)
		}
	})
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Aborted {
		t.Fatalf("want Aborted, got %v", err)
	}
	if after, _ := f.DumpXMLInactive("vm1"); after != elsewhere {
		t.Fatalf("persistent config was changed:\n%s", after)
	}
	if exists(dstFile) {
		t.Error("the copy was left behind")
	}
	if !exists(srcFile) {
		t.Error("the source is gone")
	}
	disks, _ := corrosion.GetVMDisks(context.Background(), s.db, "vm1")
	if disks[0].Path != srcFile || disks[0].StorageVolume != "hot" {
		t.Fatalf("disk row changed: %+v", disks)
	}
}

// liveLitevirtMove is liveMoveServerWithVirt on a litevirt domain.
func liveLitevirtMove(t *testing.T) (s *Server, f *libvirtfake.Fake, src, destPath, before string) {
	t.Helper()
	return liveMoveServerWithVirtLitevirt(t, func(x, _ string) string { return x })
}

// liveMoveServerWithVirtLitevirt is liveLitevirtMove with the domain XML passed
// through mod (given the XML and the source path) before it is defined.
func liveMoveServerWithVirtLitevirt(t *testing.T, mod func(x, src string) string) (s *Server, f *libvirtfake.Fake, src, destPath, before string) {
	t.Helper()
	s, f, src, destPath = liveMoveServerWithVirt(t, false)
	before = mod(litevirtDomainXML("vm-live", "vda", src), src)
	if err := f.DefineDomain(before); err != nil {
		t.Fatalf("define: %v", err)
	}
	f.SetState("vm-live", libvirtfake.StateRunning) // a define leaves the fake's domain shut off
	if s.sourceClosedForPlainCopy(&corrosion.VMRecord{Name: "vm-live"}) {
		t.Fatal("the domain must read running, so the move takes the live path")
	}
	fastPoll(t)
	return s, f, src, destPath, before
}

// A live move of a litevirt VM: after the pivot, the persistent config is the
// old one with only the disk repointed.
func TestMoveVolume_Live_LitevirtMetadataSurvives(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if mover.pivotCalls != 1 {
		t.Fatalf("pivot = %d, want 1", mover.pivotCalls)
	}
	after, _ := f.DumpXMLInactive("vm-live")
	if want := strings.Replace(before, src, destPath, 1); after != want {
		t.Fatalf("persistent config after the pivot:\n%s\nwant\n%s", after, want)
	}
}

// A live move whose pivot fails: the rollback leaves the persistent config byte
// identical to what it was before the move.
func TestMoveVolume_Live_PivotFailureRestoresLitevirtConfig(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")})
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal on pivot failure, got %v", err)
	}
	if after, _ := f.DumpXMLInactive("vm-live"); after != before {
		t.Fatalf("persistent config not restored byte for byte:\n%s", after)
	}
	if exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want false/true", exists(destPath), exists(src))
	}
}

// markerWritingMover fails its pivot after the owner-epoch marker was rewritten
// in the persistent config, as the reconciler could between define and rollback.
type markerWritingMover struct {
	fakeLiveMover
	f *libvirtfake.Fake
}

func (m *markerWritingMover) PivotBlockCopy(dom, disk string) error {
	cur, _ := m.f.DumpXMLInactive(dom)
	_ = m.f.DefineDomain(withEpoch5(cur))
	return errors.New("pivot failed")
}

// The rollback repoints the disk on the config as it is at rollback time, so a
// marker written after the define is kept.
func TestMoveVolume_Live_RollbackKeepsMarkerWrittenAfterDefine(t *testing.T) {
	s, f, _, _, before := liveLitevirtMove(t)
	s.SetLiveMover(&markerWritingMover{fakeLiveMover: fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}, f: f})
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); status.Code(err) != codes.Internal {
		t.Fatalf("want Internal on pivot failure, got %v", err)
	}
	if after, _ := f.DumpXMLInactive("vm-live"); after != withEpoch5(before) {
		t.Fatalf("rollback did not keep the marker written after the define:\n%s", after)
	}
}

// defineThenFail makes the define that names path apply and then report an
// error, as a define whose reply is lost after libvirt stored it. With
// failAfter, every later define fails too, so the rollback cannot apply.
func defineThenFail(f *libvirtfake.Fake, path string, failAfter bool) {
	f.FailDefineDomain = func(x string) error {
		if !strings.Contains(x, path) {
			return nil
		}
		f.FailDefineDomain = nil
		if err := f.DefineDomain(x); err != nil {
			return err
		}
		if failAfter {
			f.FailDefineDomain = func(string) error { return errors.New("libvirt connection lost") }
		}
		return errors.New("connection reset after define")
	}
}

// A failed offline define that libvirt applied anyway is rolled back: the
// config names the source again, byte for byte, and the copy is removed.
func TestMoveVolume_Offline_AppliedDefineFailureRepointsTheSource(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	before := litevirtDomainXML("vm1", "vda", srcFile)
	if err := f.DefineDomain(before); err != nil {
		t.Fatalf("define: %v", err)
	}
	defineThenFail(f, dstFile, false)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	if after, _ := f.DumpXMLInactive("vm1"); after != before {
		t.Fatalf("the config does not name the source again:\n%s", after)
	}
	if exists(dstFile) || !exists(srcFile) {
		t.Fatalf("dst exists=%v src exists=%v, want false/true", exists(dstFile), exists(srcFile))
	}
	if got := diskRowPath(t, s, "vm1"); got != srcFile {
		t.Fatalf("disk row names %s, want the source %s", got, srcFile)
	}
}

// The rollback of that define fails too, so the config names the copy. The VM
// is stopped and the copy complete, so the row follows the config and the move
// completes with a warning; nothing is deleted.
func TestMoveVolume_Offline_UnrolledDefineCompletesOntoTheCopy(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	before := litevirtDomainXML("vm1", "vda", srcFile)
	if err := f.DefineDomain(before); err != nil {
		t.Fatalf("define: %v", err)
	}
	defineThenFail(f, dstFile, true)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if after, _ := f.DumpXMLInactive("vm1"); after != strings.Replace(before, srcFile, dstFile, 1) {
		t.Fatalf("the config does not name the copy:\n%s", after)
	}
	if got := diskRowPath(t, s, "vm1"); got != dstFile {
		t.Fatalf("disk row names %s, want the copy %s the config names", got, dstFile)
	}
	if !exists(dstFile) || !exists(srcFile) {
		t.Fatalf("dst exists=%v src exists=%v, want both", exists(dstFile), exists(srcFile))
	}
	requireWarningEvent(t, s, "vm1")
}

// The offline double fault with the config unreadable afterwards: the row
// stays on the source, both files are kept, and the error says the row and
// the config may disagree.
func TestMoveVolume_Offline_UnrolledDefineUnreadableConfigKeepsTheRow(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	if err := f.DefineDomain(litevirtDomainXML("vm1", "vda", srcFile)); err != nil {
		t.Fatalf("define: %v", err)
	}
	armUnreadableAfterDefine(f, dstFile)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "could not be read or names neither file") ||
		!strings.Contains(err.Error(), dstFile) || !strings.Contains(err.Error(), "virsh dumpxml --inactive vm1") {
		t.Fatalf("want Internal naming the copy and the check, got %v", err)
	}
	if got := diskRowPath(t, s, "vm1"); got != srcFile {
		t.Fatalf("disk row names %s, want the source %s", got, srcFile)
	}
	if !exists(dstFile) || !exists(srcFile) {
		t.Fatalf("dst exists=%v src exists=%v, want both", exists(dstFile), exists(srcFile))
	}
}

// A replan that cannot read the config keeps the copy and names it.
func TestMoveVolume_Offline_UnreadableReplanKeepsAndNamesTheCopy(t *testing.T) {
	s, f, srcFile, dstFile := offlineMoveServer(t)
	if err := f.DefineDomain(litevirtDomainXML("vm1", "vda", srcFile)); err != nil {
		t.Fatalf("define: %v", err)
	}
	n := 0
	f.FailDumpXMLInactive = func(string) error {
		if n++; n >= 2 {
			return errors.New("libvirt connection lost")
		}
		return nil
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Aborted || !strings.Contains(err.Error(), dstFile) {
		t.Fatalf("want Aborted naming %s, got %v", dstFile, err)
	}
	if !exists(dstFile) || !exists(srcFile) {
		t.Fatalf("dst exists=%v src exists=%v, want both", exists(dstFile), exists(srcFile))
	}
}

// cancelChecker is a live mover whose CancelBlockCopy records what the
// persistent config names at that moment.
type cancelChecker struct {
	fakeLiveMover
	f            *libvirtfake.Fake
	atCancel     string
	cancelledSeq int
}

func (m *cancelChecker) CancelBlockCopy(dom, disk string) error {
	m.atCancel, _ = m.f.DumpXMLInactive(dom)
	m.cancelledSeq++
	return m.fakeLiveMover.CancelBlockCopy(dom, disk)
}

// The live twin: a redefine that libvirt applied but reported failed is
// rolled back before the mirror stops, so the config never names a copy that
// no longer receives the guest's writes; then the dest is removed.
func TestMoveVolume_Live_AppliedDefineFailureRepointsTheSourceBeforeCancel(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	mover := &cancelChecker{fakeLiveMover: fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}, f: f}
	s.SetLiveMover(mover)
	defineThenFail(f, destPath, false)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	if mover.cancelledSeq == 0 || mover.atCancel != before {
		t.Fatalf("at the mirror's cancel (%d calls) the config was not back on the source:\n%s", mover.cancelledSeq, mover.atCancel)
	}
	if after, _ := f.DumpXMLInactive("vm-live"); after != before {
		t.Fatalf("the config does not name the source again:\n%s", after)
	}
	if exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want false/true", exists(destPath), exists(src))
	}
	if mover.pivotCalls != 0 {
		t.Fatalf("pivot = %d, want 0", mover.pivotCalls)
	}
	if got := diskRowPath(t, s, "vm-live"); got != src {
		t.Fatalf("disk row names %s, want the source %s", got, src)
	}
}

// armUnreadableAfterDefine makes the define naming path apply and report an
// error, every later define fail, and every later read of the persistent
// config fail, so neither the rollback nor a re-read can see the config.
func armUnreadableAfterDefine(f *libvirtfake.Fake, path string) {
	defineThenFail(f, path, true)
	inner := f.FailDefineDomain
	f.FailDefineDomain = func(x string) error {
		err := inner(x)
		if strings.Contains(x, path) {
			f.FailDumpXMLInactive = func(string) error { return errors.New("libvirt connection lost") }
		}
		return err
	}
}

// requireWarningEvent fails unless the VM has a disk.moved event of severity
// warning.
func requireWarningEvent(t *testing.T, s *Server, vm string) {
	t.Helper()
	evs, err := corrosion.ListVMEvents(context.Background(), s.db, vm, 50, "")
	if err != nil {
		t.Fatalf("list events: %v", err)
	}
	for _, e := range evs {
		if e.Type == "disk.moved" && e.Severity == "warning" {
			return
		}
	}
	t.Fatalf("no disk.moved warning event: %+v", evs)
}

// withSrcDescription is a litevirt domain whose <description> also mentions
// the source path, so the persistent config still names it after a cutover.
func withSrcDescription(x, src string) string {
	return strings.Replace(x, "</name>\n", "</name>\n  <description>moved from "+src+"</description>\n", 1)
}

// diskRowPath returns the path the VM's only disk row names.
func diskRowPath(t *testing.T, s *Server, vm string) string {
	t.Helper()
	disks, err := corrosion.GetVMDisks(context.Background(), s.db, vm)
	if err != nil || len(disks) != 1 {
		t.Fatalf("disk rows of %s: %+v, %v", vm, disks, err)
	}
	return disks[0].Path
}

// The live rollback fails too, so the config names the copy. The mirror is in
// sync, so the guest is pivoted onto the copy and the disk row follows: the
// guest, the config and the row all name the copy. The move completes with a
// warning, and the source is kept since no delete was asked for.
func TestMoveVolume_Live_UnrolledDefinePivotsOntoTheCopy(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	defineThenFail(f, destPath, true)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if mover.pivotCalls != 1 || mover.cancelCalls != 0 {
		t.Fatalf("pivot = %d cancel = %d, want 1/0", mover.pivotCalls, mover.cancelCalls)
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
	warned := false
	for _, p := range rec.Sent {
		if p.Phase == pb.MoveVolumeProgress_CUTOVER && strings.HasPrefix(p.Status, "warning: ") {
			warned = true
		}
	}
	if !warned || rec.Sent[len(rec.Sent)-1].Phase != pb.MoveVolumeProgress_DONE {
		t.Fatalf("want a warning frame and a final DONE, got %+v", rec.Sent)
	}
	requireWarningEvent(t, s, "vm-live")
}

// The same double fault with a delete of the source asked for: the completed
// move deletes the source, as a normal one does.
func TestMoveVolume_Live_UnrolledDefinePivotDeletesTheSourceWhenAsked(t *testing.T) {
	s, f, src, destPath, _ := liveLitevirtMove(t)
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096})
	defineThenFail(f, destPath, true)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm", DeleteSource: true}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if !exists(destPath) || exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want true/false", exists(destPath), exists(src))
	}
}

// The delete is skipped when the persistent config still names the source
// anywhere, since this move saw a define error.
func TestMoveVolume_Live_UnrolledDefinePivotKeepsASourceTheConfigNames(t *testing.T) {
	s, f, src, destPath, _ := liveMoveServerWithVirtLitevirt(t, withSrcDescription)
	s.SetLiveMover(&fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096})
	defineThenFail(f, destPath, true)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm", DeleteSource: true}, rec); err != nil {
		t.Fatalf("MoveVolume: %v", err)
	}
	if !exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want both", exists(destPath), exists(src))
	}
	if got := diskRowPath(t, s, "vm-live"); got != destPath {
		t.Fatalf("disk row names %s, want the copy %s", got, destPath)
	}
}

// The double fault, and the pivot onto the copy fails as well. The mirror is
// left running so the copy the config names stays current, both files are kept,
// the row still names the source, and the error names the file the config
// names, the file the guest writes, and what the operator does next.
func TestMoveVolume_Live_UnrolledDefineFailedPivotLeavesTheMirror(t *testing.T) {
	s, f, src, destPath, _ := liveLitevirtMove(t)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096, pivotErr: errors.New("pivot failed")}
	s.SetLiveMover(mover)
	defineThenFail(f, destPath, true)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal {
		t.Fatalf("want Internal, got %v", err)
	}
	for _, want := range []string{
		"the persistent config names " + destPath,
		"the guest is writing " + src,
		"virsh blockjob vm-live " + src + " --pivot",
		"virsh blockjob vm-live " + src + " --abort",
		"Do not stop or restart the VM",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error does not say %q: %v", want, err)
		}
	}
	if mover.pivotCalls != 1 || mover.cancelCalls != 0 {
		t.Fatalf("pivot = %d cancel = %d, want 1/0 (the mirror must stay)", mover.pivotCalls, mover.cancelCalls)
	}
	if !exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want both", exists(destPath), exists(src))
	}
	if got := diskRowPath(t, s, "vm-live"); got != src {
		t.Fatalf("disk row names %s, want the source %s (the guest still writes it)", got, src)
	}
}

// The double fault with the config unreadable afterwards: what the config
// names is unknown, so the mirror is neither pivoted nor cancelled, both files
// are kept, and the error says so.
func TestMoveVolume_Live_UnrolledDefineUnreadableConfigLeavesTheMirror(t *testing.T) {
	s, f, src, destPath, _ := liveLitevirtMove(t)
	mover := &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 4096}
	s.SetLiveMover(mover)
	armUnreadableAfterDefine(f, destPath)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "could not be read or names neither file") ||
		!strings.Contains(err.Error(), "Do not stop or restart the VM") ||
		!strings.Contains(err.Error(), "the guest is writing "+src) || !strings.Contains(err.Error(), destPath) {
		t.Fatalf("want Internal naming both files and the unreadable config, got %v", err)
	}
	if mover.pivotCalls != 0 || mover.cancelCalls != 0 {
		t.Fatalf("pivot = %d cancel = %d, want 0/0", mover.pivotCalls, mover.cancelCalls)
	}
	if !exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want both", exists(destPath), exists(src))
	}
	if got := diskRowPath(t, s, "vm-live"); got != src {
		t.Fatalf("disk row names %s, want the source %s", got, src)
	}
}

// endedEarlyMover is a live mover whose job is already gone at the first poll,
// without having caught up: an abort, or a mirror that failed mid-copy.
func endedEarlyMover() *fakeLiveMover {
	return &fakeLiveMover{jobEnd: 4096, progressBytesPerPoll: 1, finished: true}
}

// A job that ended before the copy caught up, with the guest still on the
// source: the copy may be partial, so it is removed and nothing is redefined.
func TestMoveVolume_Live_JobEndedBeforeReadyRemovesTheCopy(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	mover := endedEarlyMover()
	s.SetLiveMover(mover)
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || !strings.Contains(err.Error(), "before the copy caught up") {
		t.Fatalf("want Internal saying the job ended before it caught up, got %v", err)
	}
	if mover.pivotCalls != 0 {
		t.Fatalf("pivot = %d, want 0", mover.pivotCalls)
	}
	if after, _ := f.DumpXMLInactive("vm-live"); after != before {
		t.Fatalf("the config changed:\n%s", after)
	}
	if got := diskRowPath(t, s, "vm-live"); got != src {
		t.Fatalf("disk row names %s, want the source %s", got, src)
	}
	if exists(destPath) || !exists(src) {
		t.Fatalf("dest exists=%v src exists=%v, want false/true", exists(destPath), exists(src))
	}
}

// The same early end with a define that would fail after storing: the define
// is never reached, so no double fault can name the partial copy.
func TestMoveVolume_Live_JobEndedBeforeReadyNeverDefines(t *testing.T) {
	s, f, src, destPath, before := liveLitevirtMove(t)
	mover := endedEarlyMover()
	s.SetLiveMover(mover)
	defined := false
	defineThenFail(f, destPath, true)
	inner := f.FailDefineDomain
	f.FailDefineDomain = func(x string) error {
		if strings.Contains(x, destPath) {
			defined = true
		}
		return inner(x)
	}
	rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
	err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm-live", DiskName: "root", TargetPool: "warm"}, rec)
	if status.Code(err) != codes.Internal || strings.Contains(err.Error(), "--pivot") || strings.Contains(err.Error(), "stays current") {
		t.Fatalf("want Internal with no pivot advice, got %v", err)
	}
	if defined {
		t.Fatal("a define naming the copy was attempted after the job ended early")
	}
	if after, _ := f.DumpXMLInactive("vm-live"); after != before {
		t.Fatalf("the config changed:\n%s", after)
	}
	if exists(destPath) || !exists(src) || mover.pivotCalls != 0 {
		t.Fatalf("dest exists=%v src exists=%v pivot=%d, want false/true/0", exists(destPath), exists(src), mover.pivotCalls)
	}
}

// The offline double fault that completes onto the copy deletes the source
// when asked, unless the persistent config still names it anywhere.
func TestMoveVolume_Offline_UnrolledDefineDeleteSourceIsGuarded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mentionSrc bool
		wantSrc    bool
	}{
		{"config does not name the source", false, false},
		{"config still names the source", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, srcFile, dstFile := offlineMoveServer(t)
			x := litevirtDomainXML("vm1", "vda", srcFile)
			if tc.mentionSrc {
				x = withSrcDescription(x, srcFile)
			}
			if err := f.DefineDomain(x); err != nil {
				t.Fatalf("define: %v", err)
			}
			defineThenFail(f, dstFile, true)
			rec := &streamRecorder[pb.MoveVolumeProgress]{ctx: adminCtx()}
			if err := s.MoveVolume(&pb.MoveVolumeRequest{VmName: "vm1", DiskName: "root", TargetPool: "warm", DeleteSource: true}, rec); err != nil {
				t.Fatalf("MoveVolume: %v", err)
			}
			if !exists(dstFile) || exists(srcFile) != tc.wantSrc {
				t.Fatalf("dst exists=%v src exists=%v, want true/%v", exists(dstFile), exists(srcFile), tc.wantSrc)
			}
		})
	}
}
