package fleet

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const inspectOVADescriptor = `<?xml version="1.0" encoding="UTF-8"?>
<Envelope xmlns="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:ovf="http://schemas.dmtf.org/ovf/envelope/1"
  xmlns:rasd="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/CIM_ResourceAllocationSettingData"
  xmlns:vmw="http://www.vmware.com/schema/ovf">
  <References><File ovf:href="disk-0.vmdk" ovf:id="file1"/></References>
  <DiskSection>
    <Disk ovf:capacity="20" ovf:capacityAllocationUnits="byte * 2^30" ovf:diskId="vmdisk1" ovf:fileRef="file1" ovf:format="http://www.vmware.com/interfaces/specifications/vmdk.html#streamOptimized"/>
  </DiskSection>
  <VirtualSystem ovf:id="app">
    <VirtualHardwareSection>
      <Item><rasd:ResourceType>3</rasd:ResourceType><rasd:VirtualQuantity>2</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>4</rasd:ResourceType><rasd:AllocationUnits>byte * 2^20</rasd:AllocationUnits><rasd:VirtualQuantity>2048</rasd:VirtualQuantity></Item>
      <Item><rasd:ResourceType>6</rasd:ResourceType><rasd:InstanceID>3</rasd:InstanceID></Item>
      <Item><rasd:ResourceType>17</rasd:ResourceType><rasd:HostResource>ovf:/disk/vmdisk1</rasd:HostResource><rasd:Parent>3</rasd:Parent><rasd:AddressOnParent>0</rasd:AddressOnParent></Item>
      <Item><rasd:ResourceType>10</rasd:ResourceType><rasd:ResourceSubType>VmxNet3</rasd:ResourceSubType><rasd:Connection>VM Network</rasd:Connection></Item>
    </VirtualHardwareSection>
  </VirtualSystem>
</Envelope>`

// An --inspect of an OVA uploaded through one node to another (--host) is
// described by the target from the descriptor alone. The target stops reading
// at the descriptor, the entry's relay ends with it, and the client's upload
// ends there too; neither node stages, unpacks or records anything.
//
// Mutation: drop the OVA fast path in ImportVM — the target stages the upload
// under <data_dir>/imports.
func TestFleet_ImportInspectOVA_ForwardedUploadWritesNothing(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, target := c.Nodes[0], c.Nodes[1]

	var ova bytes.Buffer
	tw := tar.NewWriter(&ova)
	for _, m := range []struct {
		name string
		body []byte
	}{{"app.ovf", []byte(inspectOVADescriptor)}, {"disk-0.vmdk", bytes.Repeat([]byte{0x5A}, 32<<20)}} {
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

	st, err := c.SelfClient(entry).ImportVM(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Send(&pb.ImportVMRequest{Name: "app", TargetHost: target.Name, Inspect: true, NetMap: map[string]string{"*": "br0"}}); err != nil {
		t.Fatal(err)
	}
	data := ova.Bytes()
	sent := 0
	for sent < len(data) {
		end := min(sent+256<<10, len(data))
		if err := st.Send(&pb.ImportVMRequest{Chunk: data[sent:end]}); err != nil {
			if err == io.EOF {
				break // the server has what it needs
			}
			t.Fatalf("send: %v", err)
		}
		sent = end
	}
	_ = st.CloseSend()
	var done *pb.ImportVMProgress
	for {
		p, err := st.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("forwarded inspect: %v", err)
		}
		if p.Phase == "done" {
			done = p
		}
	}
	if done == nil {
		t.Fatal("no plan came back")
	}
	var spec pb.VMSpec
	if err := json.Unmarshal([]byte(done.MappedSpecJson), &spec); err != nil {
		t.Fatal(err)
	}
	if spec.Cpu != 2 || spec.MemoryMib != 2048 || len(spec.Disks) != 1 || spec.Disks[0].Size != "20G" ||
		len(spec.Network) != 1 || spec.Network[0].Name != "br0" {
		t.Fatalf("plan = %+v", &spec)
	}
	if sent >= len(data) {
		t.Errorf("the client sent all %d bytes: the inspect read the disk behind the descriptor", len(data))
	}
	for _, n := range []*Node{entry, target} {
		if _, err := os.Stat(filepath.Join(n.FW.DataDir, "imports")); !os.IsNotExist(err) {
			t.Errorf("%s: the inspect made %s/imports (stat err %v)", n.Name, n.FW.DataDir, err)
		}
		if vm, _ := corrosion.GetVM(context.Background(), n.DB, "app"); vm != nil {
			t.Errorf("%s: the inspect wrote a VM row: %+v", n.Name, vm)
		}
	}
}

// The preview of a --server-path OVA reads the file on the host that runs
// it, under the import's path check: an operator naming a real OVA outside
// the staging root is refused, on the entry node and forwarded to another
// node (judged there by the bearer the entry relays), and no plan comes back.
// The admin control gets the plan, so the file is one the preview reads.
//
// Mutation: resolve the path in inspectOVASource with a bare
// filepath.EvalSymlinks (no containment) and the operator gets the plan.
func TestFleet_ImportInspectOVA_ServerPathOutsideStagingRefused(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	entry, target := c.Nodes[0], c.Nodes[1]
	tok := userOn(t, c, entry, "previewer", "operator")

	var ova bytes.Buffer
	tw := tar.NewWriter(&ova)
	for _, m := range []struct {
		name string
		body []byte
	}{{"app.ovf", []byte(inspectOVADescriptor)}, {"disk-0.vmdk", make([]byte, 1<<20)}} {
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
	src := filepath.Join(t.TempDir(), "secret.ova")
	if err := os.WriteFile(src, ova.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	preview := func(cl pb.LiteVirtClient, targetHost string) (*pb.ImportVMProgress, error) {
		st, err := cl.ImportVM(context.Background())
		if err != nil {
			return nil, err
		}
		if err := st.Send(&pb.ImportVMRequest{Name: "app", TargetHost: targetHost, SourcePath: src, Inspect: true, Final: true, NetMap: map[string]string{"*": "br0"}}); err != nil {
			return nil, err
		}
		_ = st.CloseSend()
		var done *pb.ImportVMProgress
		for {
			p, err := st.Recv()
			if err == io.EOF {
				return done, nil
			}
			if err != nil {
				return done, err
			}
			if p.Phase == "done" {
				done = p
			}
		}
	}
	for _, tc := range []struct {
		name, targetHost string
	}{{"direct", ""}, {"forwarded", target.Name}} {
		t.Run(tc.name, func(t *testing.T) {
			done, err := preview(c.bearerClient(entry, tok), tc.targetHost)
			if status.Code(err) != codes.PermissionDenied || !strings.Contains(err.Error(), "outside the import staging root") {
				t.Fatalf("an operator's --inspect --server-path outside the staging root: err = %v, want the staging-root refusal", err)
			}
			if done != nil {
				t.Fatalf("the refused preview returned a plan: %s", done.MappedSpecJson)
			}
		})
	}
	for _, th := range []string{"", target.Name} {
		done, err := preview(c.SelfClient(entry), th)
		if err != nil || done == nil || done.MappedSpecJson == "" {
			t.Fatalf("the admin's --inspect --server-path (target %q): plan %v, err %v", th, done, err)
		}
	}
}
