package grpcapi

import (
	"errors"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// q35PriorXML is an existing q35 domain as libvirt keeps it: every device
// addressed, one root port in use, none spare.
const q35PriorXML = `<domain type='kvm'>
  <name>%s</name>
  <memory unit='KiB'>4194304</memory>
  <vcpu placement='static'>2</vcpu>
  <os><type arch='x86_64' machine='pc-q35-8.2'>hvm</type></os>
  <devices>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/d/%s-root.qcow2'/>
      <target dev='vda' bus='virtio'/>
      <alias name='ua-disk-root'/>
      <address type='pci' domain='0x0000' bus='0x01' slot='0x00' function='0x0'/>
    </disk>
    <controller type='pci' index='0' model='pcie-root'/>
    <controller type='pci' index='1' model='pcie-root-port'>
      <address type='pci' domain='0x0000' bus='0x00' slot='0x02' function='0x0'/>
    </controller>
  </devices>
</domain>`

func seedStoppedQ35VM(t *testing.T, s *Server, name string) {
	t.Helper()
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, name, "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: name, Cpu: 2, MemoryMib: 4096, Machine: "q35"}))
	if err := corrosion.InsertDisk(ctx, s.db, corrosion.DiskRecord{
		VMName: name, DiskName: "root", HostName: "test-host",
		Path: "/d/" + name + "-root.qcow2", DeviceKind: "disk", Bus: "virtio", TargetDev: "vda", DeleteWithVM: true,
	}); err != nil {
		t.Fatalf("insert root: %v", err)
	}
	if err := s.virt.DefineDomain(strings.ReplaceAll(q35PriorXML, "%s", name)); err != nil {
		t.Fatalf("seed prior domain: %v", err)
	}
}

// No backfill: a reconcile that patches an existing domain in place leaves
// its root ports as they are, whatever pci.spare_pcie_root_ports says.
//
// Mutation: top up after the patch path too — red.
func TestReconcile_PatchPathAddsNoSpareRootPorts(t *testing.T) {
	s := reconfigServer(t)
	s.SetSparePCIeRootPorts(4)
	seedStoppedQ35VM(t, s, "old")

	if err := s.reconcileDomainDefinition(adminCtx(), mustGetVM(t, s, "old"), nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := s.virt.(*libvirtfake.Fake).DefinedXML("old")
	if n := strings.Count(got, "pcie-root-port"); n != 1 {
		t.Fatalf("an in-place reconcile changed the root ports (%d, want the 1 it had):\n%s", n, got)
	}
}

// No backfill on `lv update` either: a cpu/memory change on a stopped VM
// patches the inactive XML and adds no root port.
//
// Mutation: drop the `regenerated` guard in UpdateVM — red.
func TestUpdateVM_InPlacePatchAddsNoSpareRootPorts(t *testing.T) {
	s := reconfigServer(t)
	s.SetSparePCIeRootPorts(4)
	seedStoppedQ35VM(t, s, "old")

	if _, err := s.UpdateVM(adminCtx(), &pb.UpdateVMRequest{Name: "old", Cpu: 4}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	got := s.virt.(*libvirtfake.Fake).DefinedXML("old")
	if !strings.Contains(got, "slot='0x02'") {
		t.Fatalf("UpdateVM did not take the in-place patch path this test is about:\n%s", got)
	}
	if n := strings.Count(got, "pcie-root-port"); n != 1 {
		t.Fatalf("an in-place update changed the root ports (%d, want the 1 it had):\n%s", n, got)
	}
}

// A full regenerate is a new definition, so it is topped up like a create.
//
// Mutation: drop the top-up from the regenerate branch — red.
func TestReconcile_RegenerateTopsUpSpareRootPorts(t *testing.T) {
	s := reconfigServer(t)
	s.SetSparePCIeRootPorts(4)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "fresh", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "fresh", Cpu: 2, MemoryMib: 4096, Machine: "q35"}))
	// No prior domain: the reconcile regenerates from the spec.
	if err := s.reconcileDomainDefinition(ctx, mustGetVM(t, s, "fresh"), nil); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	got := s.virt.(*libvirtfake.Fake).DefinedXML("fresh")
	if n := strings.Count(got, `model="pcie-root-port"`); n != 4 {
		t.Fatalf("regenerated domain has %d spare root ports, want 4:\n%s", n, got)
	}
}

// The top-up is a second define of a domain that is already valid. If it
// fails, the VM is created anyway, with what libvirt gave it.
//
// Mutation: make CreateVM fail on a top-up error — red.
func TestCreateVM_SpareRootPortTopUpFailureIsNotFatal(t *testing.T) {
	s, fake := provableCreateServer(t)
	s.SetSparePCIeRootPorts(4)
	fake.FailDefineDomain = func(x string) error {
		if strings.Contains(x, "pcie-root-port") {
			return errors.New("injected top-up define failure")
		}
		return nil
	}
	if _, err := s.CreateVM(adminCtx(), disklessCreateRequest("vm1")); err != nil {
		t.Fatalf("CreateVM failed on a failed spare-port top-up: %v", err)
	}
	domXML, err := fake.DumpXMLInactive("vm1")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	if strings.Contains(domXML, "pcie-root-port") {
		t.Fatalf("the failed top-up must leave the first definition in place:\n%s", domXML)
	}
}
