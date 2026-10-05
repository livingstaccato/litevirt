package grpcapi

import (
	"errors"
	"strings"
	"testing"
)

// TestCreateVM_SparePCIeRootPortsReachTheDefinedDomain closes the gap a unit
// test on GenerateDomainXML alone cannot: that the Server's configured value
// (SetSparePCIeRootPorts, in production `pci.spare_pcie_root_ports`) actually
// reaches the domain libvirt defines for a brand-new VM — the exact scenario
// the brief describes (a q35 guest needs spare root ports from the moment it
// is created, so its SECOND hot-plug doesn't hit "No more available PCI
// slots"). Without this end-to-end check, deleting the
// `s.ensureSparePCIeRootPorts(spec.Name)` top-up after CreateVM's define
// would pass every other test in this package.
func TestCreateVM_SparePCIeRootPortsReachTheDefinedDomain(t *testing.T) {
	s, fake := provableCreateServer(t)
	s.SetSparePCIeRootPorts(5)
	ctx := adminCtx()

	req := disklessCreateRequest("vm1")
	if _, err := s.CreateVM(ctx, req); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	domXML, err := fake.DumpXMLInactive("vm1")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	if n := strings.Count(domXML, `model="pcie-root-port"`); n != 5 {
		t.Fatalf("defined domain has %d pcie-root-port controllers, want 5 (configured via SetSparePCIeRootPorts):\n%s", n, domXML)
	}
}

// TestCreateVM_SparePCIeRootPortsDefaultZero_NoControllers: the Server's
// zero-value field (no SetSparePCIeRootPorts call — a daemon that never wired
// it) must define a domain with NO pcie-root-port controllers, i.e. the exact
// pre-this-feature XML. This is the Server-level companion to
// TestEnsureSparePCIeRootPorts's "want 0 never reads or defines anything".
func TestCreateVM_SparePCIeRootPortsDefaultZero_NoControllers(t *testing.T) {
	s, fake := provableCreateServer(t)
	ctx := adminCtx()

	req := disklessCreateRequest("vm1")
	if _, err := s.CreateVM(ctx, req); err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	domXML, err := fake.DumpXMLInactive("vm1")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	if strings.Contains(domXML, "pcie-root-port") {
		t.Fatalf("a Server with no spare-ports config must define a domain with none: %s", domXML)
	}
}

// The slot-exhaustion message names actions an operator can take. It used to
// say "redefine the VM", which no command does: the spare-port count reaches
// only a newly defined domain (create, import, clone), so it names lv clone
// and the docs section that explains why.
//
// Mutation: restore "and redefine the VM" — red.
func TestPCIAttachError_NamesAnActionThatExists(t *testing.T) {
	msg := pciAttachError("attach disk", errors.New("internal error: No more available PCI slots")).Error()
	for _, want := range []string{"detach another device", "pci.spare_pcie_root_ports", "lv clone", "docs/pci-passthrough.md"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not name %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "redefine") {
		t.Errorf("message names a redefine no command performs: %s", msg)
	}
}
