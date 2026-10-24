package grpcapi

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const inspectOVF = `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vssd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_VirtualSystemSettingData"
  xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References><File ovf:href="disk-0.vmdk" ovf:id="file1"/></References>
  <DiskSection>
    <Disk ovf:capacity="40" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <NetworkSection><Network ovf:name="VM Network"/></NetworkSection>
  <VirtualSystem ovf:id="win2022">
    <OperatingSystemSection ovf:id="103" vmw:osType="windows9Server64Guest"/>
    <VirtualHardwareSection>
      <System><vssd:VirtualSystemType>vmx-14</vssd:VirtualSystemType></System>
      <Item><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>4</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>4</rasd:ResourceType><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:VirtualQuantity>8192</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>6</rasd:ResourceType><rasd:ResourceSubType>lsilogicsas</rasd:ResourceSubType><rasd:InstanceID>3</rasd:InstanceID></Item>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource><rasd:Parent>3</rasd:Parent><rasd:AddressOnParent>0</rasd:AddressOnParent></Item>
      <Item><rasd:ResourceType>10</rasd:ResourceType><rasd:ResourceSubType>E1000</rasd:ResourceSubType><rasd:Connection>VM Network</rasd:Connection><rasd:Address>00:50:56:01:02:03</rasd:Address></Item>
      <vmw:Config ovf:key="firmware" vmw:value="efi"/>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>`

// inspectOVA is a small OVA: the descriptor first, then a disk.
func inspectOVA(t *testing.T, diskBytes int) []byte {
	t.Helper()
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	for _, m := range []struct {
		name string
		body []byte
	}{{"win2022.ovf", []byte(inspectOVF)}, {"disk-0.vmdk", bytes.Repeat([]byte{0xAB}, diskBytes)}} {
		if err := tw.WriteHeader(&tar.Header{Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(m.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// treeOf lists every path under dir with its size.
func treeOf(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fi.Size()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func wantInspectPlan(t *testing.T, sent []*pb.ImportVMProgress) {
	t.Helper()
	if len(sent) != 1 || sent[0].Phase != "done" || sent[0].MappedSpecJson == "" {
		t.Fatalf("progress = %+v, want one done frame with the mapped spec", sent)
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(sent[0].MappedSpecJson), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Cpu != 4 || spec.MemoryMib != 8192 || spec.Firmware != "uefi" {
		t.Errorf("spec cpu=%d mem=%d firmware=%q, want 4/8192/uefi", spec.Cpu, spec.MemoryMib, spec.Firmware)
	}
	if len(spec.Disks) != 1 || spec.Disks[0].Size != "40G" || spec.Disks[0].Bus != "scsi" {
		t.Errorf("disks = %+v, want one 40G scsi disk", spec.Disks)
	}
	if len(spec.Network) != 1 || spec.Network[0].Name != "br0" || spec.Network[0].Model != "e1000" {
		t.Errorf("nics = %+v, want one e1000 on br0", spec.Network)
	}
}

func wantNothingImported(t *testing.T, s *Server, name string, before map[string]int64) {
	t.Helper()
	after := treeOf(t, s.dataDir)
	for p, n := range after {
		if m, ok := before[p]; !ok || m != n {
			t.Errorf("the inspect wrote %s (%d bytes)", p, n)
		}
	}
	if vm, _ := corrosion.GetVM(context.Background(), s.db, name); vm != nil {
		t.Errorf("the inspect wrote a VM row: %+v", vm)
	}
}

// An uploaded OVA is described from its descriptor: the upload stops being
// read there, and nothing is written — no staging directory, no upload file,
// no extracted disk, no row.
func TestImportVM_InspectOVAUploadWritesNothing(t *testing.T) {
	s := testServer(t)
	ova := inspectOVA(t, 2<<20)
	frames := []*pb.ImportVMRequest{{Name: "win", SourceFormat: "auto", Inspect: true, NetMap: map[string]string{"*": "br0"}}}
	for off := 0; off < len(ova); off += 64 << 10 {
		end := min(off+64<<10, len(ova))
		frames = append(frames, &pb.ImportVMRequest{Chunk: ova[off:end]})
	}
	// No room at all: an inspect that staged, unpacked or extracted anything
	// would be refused for it.
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 0, 100 << 30, nil }
	before := treeOf(t, s.dataDir)
	st := &fakeImportStream{ctx: adminCtx(), frames: frames}
	if err := s.ImportVM(st); err != nil {
		t.Fatalf("ImportVM --inspect: %v", err)
	}
	wantInspectPlan(t, st.sent)
	wantNothingImported(t, s, "win", before)
	if st.i >= len(frames) {
		t.Errorf("the inspect read all %d frames: it read the disk behind the descriptor", len(frames))
	}
}

// A --server-path OVA is read in place, under the same path check, and nothing
// is written beside it.
func TestImportVM_InspectOVAServerPathWritesNothing(t *testing.T) {
	s := testServer(t)
	staging := filepath.Join(s.dataDir, "imports", "staging")
	if err := os.MkdirAll(staging, 0o755); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(staging, "win.ova")
	if err := os.WriteFile(src, inspectOVA(t, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	// No room at all: an inspect that staged, unpacked or extracted anything
	// would be refused for it.
	s.diskSpaceOverride = func(string) (uint64, uint64, error) { return 0, 100 << 30, nil }
	before := treeOf(t, s.dataDir)
	st := &fakeImportStream{ctx: adminCtx(), frames: []*pb.ImportVMRequest{{
		Name: "win", SourcePath: src, Inspect: true, NetMap: map[string]string{"*": "br0"},
	}}}
	if err := s.ImportVM(st); err != nil {
		t.Fatalf("ImportVM --inspect --server-path: %v", err)
	}
	wantInspectPlan(t, st.sent)
	wantNothingImported(t, s, "win", before)
}

// The preview reads a --server-path OVA itself, so it takes the same path
// check as the import: a real OVA outside the staging root is refused to an
// operator, whether it calls this host or reaches it forwarded from an entry
// node (judged by the bearer it relays), and nothing of it is described. The
// admin control shows the file is an OVA the preview would describe.
//
// Mutation: resolve the path in inspectOVASource with a bare
// filepath.EvalSymlinks (no containment) and the operator gets the plan.
func TestImportVM_InspectOVAServerPathOutsideStagingRefused(t *testing.T) {
	s := testServer(t)
	src := filepath.Join(t.TempDir(), "secret.ova")
	if err := os.WriteFile(src, inspectOVA(t, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	inspect := func(ctx context.Context) ([]*pb.ImportVMProgress, error) {
		st := &fakeImportStream{ctx: ctx, frames: []*pb.ImportVMRequest{{
			Name: "win", SourcePath: src, Inspect: true, NetMap: map[string]string{"*": "br0"},
		}}}
		err := s.ImportVM(st)
		return st.sent, err
	}
	for _, tc := range []struct {
		name string
		ctx  context.Context
	}{
		{"direct", hostPathEngineCtx(t, s, "op", "Operator", "/")},
		{"forwarded", forwardedImportFor(t, s, "fwdop", "Operator")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sent, err := inspect(tc.ctx)
			if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "outside the import staging root") {
				t.Fatalf("an operator's --inspect --server-path outside the staging root: err = %v, want the staging-root refusal", err)
			}
			if len(sent) != 0 {
				t.Fatalf("the refused preview sent %+v", sent)
			}
		})
	}
	sent, err := inspect(adminCtx())
	if err != nil {
		t.Fatalf("the admin's --inspect --server-path: %v", err)
	}
	wantInspectPlan(t, sent)
}
