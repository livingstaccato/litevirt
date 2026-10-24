package main

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

const importInspectOVF = `<?xml version="1.0" encoding="UTF-8"?>
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

const importCLIToken = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210"

// importCLIDaemon starts a real grpcapi server behind both auth interceptors,
// points withClient at it as an admin, and returns its data dir and database.
func importCLIDaemon(t *testing.T) (string, *corrosion.Client) {
	t.Helper()
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(importCLIToken), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertUser(ctx, db, "root", "admin", string(hash)); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertToken(ctx, db, corrosion.TokenRecord{ID: "cli-token", Username: "root", Name: "cli", TokenHash: string(hash)}); err != nil {
		t.Fatal(err)
	}
	dataDir := t.TempDir()
	srv := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "test-host", DataDir: dataDir, DB: db})
	listener := bufconn.Listen(256 << 10)
	gs := grpc.NewServer(grpc.UnaryInterceptor(srv.UnaryAuthInterceptor), grpc.StreamInterceptor(srv.StreamAuthInterceptor))
	pb.RegisterLiteVirtServer(gs, srv)
	go func() { _ = gs.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := pb.NewLiteVirtClient(conn)
	orig := withClient
	withClient = func(ctx context.Context, fn func(context.Context, pb.LiteVirtClient) error) error {
		return fn(metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+importCLIToken), client)
	}
	t.Cleanup(func() {
		withClient = orig
		_ = conn.Close()
		gs.Stop()
		_ = listener.Close()
	})
	return dataDir, db
}

func writeInspectOVA(t *testing.T, path string, diskBytes int) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tw := tar.NewWriter(f)
	for _, m := range []struct {
		name string
		body []byte
	}{{"win2022.ovf", []byte(importInspectOVF)}, {"disk-0.vmdk", bytes.Repeat([]byte{0xAB}, diskBytes)}} {
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
}

func dirTree(t *testing.T, dir string) map[string]int64 {
	t.Helper()
	out := map[string]int64{}
	if err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fi.Size()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// lv import <local.ova> --inspect prints what the OVA holds — CPU, memory,
// firmware, each disk with its size and bus, each NIC — from the daemon's
// reading of its descriptor, and nothing is imported: the daemon stops
// reading the upload at the descriptor, the CLI stops sending there, and no
// file or row is written.
func TestImportCLI_InspectLocalOVAPrintsThePlanAndImportsNothing(t *testing.T) {
	dataDir, db := importCLIDaemon(t)
	ova := filepath.Join(t.TempDir(), "win2022.ova")
	// Far more than the transport buffers: the upload cannot finish
	// unread, so the CLI must stop at the server's end of the stream.
	writeInspectOVA(t, ova, 32<<20)
	before := dirTree(t, dataDir)

	cmd := newImportCmd()
	cmd.SetArgs([]string{ova, "--name", "win2022", "--network", "br0", "--inspect"})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	var err error
	out := captureStdout(t, func() { err = cmd.Execute() })
	if err != nil {
		t.Fatalf("lv import --inspect: %v\n%s", err, out)
	}
	for _, want := range []string{
		`Import plan for "win2022":`,
		"cpu=4 memory=8192MiB",
		"firmware=uefi",
		"disk root   bus=scsi controller=lsisas1068 size=40G",
		"nic  bridge=br0 model=e1000",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
	for p, n := range dirTree(t, dataDir) {
		if m, ok := before[p]; !ok || m != n {
			t.Errorf("the inspect wrote %s (%d bytes) on the daemon", p, n)
		}
	}
	if vm, _ := corrosion.GetVM(context.Background(), db, "win2022"); vm != nil {
		t.Errorf("the inspect wrote a VM row: %+v", vm)
	}
}
