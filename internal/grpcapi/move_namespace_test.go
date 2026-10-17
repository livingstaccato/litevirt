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
	return "<domain type='kvm'>\n  <name>" + name + "</name>\n  <metadata>\n    " +
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
	s, f, src, destPath = liveMoveServerWithVirt(t, false)
	before = litevirtDomainXML("vm-live", "vda", src)
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
