package grpcapi

import (
	"context"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
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
