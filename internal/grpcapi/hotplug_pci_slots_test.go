package grpcapi

import (
	"strings"
	"testing"
)

// TestCreateVM_SparePCIeRootPortsReachTheDefinedDomain closes the gap a unit
// test on GenerateDomainXML alone cannot: that the Server's configured value
// (SetSparePCIeRootPorts, in production `pci.spare_pcie_root_ports`) actually
// reaches the domain libvirt defines for a brand-new VM — the exact scenario
// the brief describes (a q35 guest needs spare root ports from the moment it
// is created, so its SECOND hot-plug doesn't hit "No more available PCI
// slots"). Without this end-to-end check, deleting the one-line
// `vmCfg.SparePCIeRootPorts = s.sparePCIeRootPortsCfg` at the CreateVM call
// site would pass every other test in this package.
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
// pre-this-feature XML. This is the companion to the xmlgen-level "0 is a
// no-op" test, proven at the Server/RPC boundary instead of the pure builder.
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
