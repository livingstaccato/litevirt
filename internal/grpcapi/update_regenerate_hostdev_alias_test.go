package grpcapi

import (
	"encoding/xml"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// hostdevAliasesInXML reads each PCI <hostdev>'s alias from a definition,
// keyed by its source bus number (the tests use distinct buses).
func hostdevAliasesInXML(t *testing.T, domXML string) map[string]string {
	t.Helper()
	var d struct {
		Hostdevs []struct {
			Source struct {
				Address struct {
					Bus string `xml:"bus,attr"`
				} `xml:"address"`
			} `xml:"source"`
			Alias struct {
				Name string `xml:"name,attr"`
			} `xml:"alias"`
		} `xml:"devices>hostdev"`
	}
	if err := xml.Unmarshal([]byte(domXML), &d); err != nil {
		t.Fatalf("parse domain XML: %v\n%s", err, domXML)
	}
	out := map[string]string{}
	for _, h := range d.Hostdevs {
		out[h.Source.Address.Bus] = h.Alias.Name
	}
	return out
}

// UpdateVM's regenerate rebuilt the hostdevs from PCI ownership, which
// carries no alias, so a device attached through the journal lost its
// `ua-<device>-<member>` alias: the alias-keyed patcher and a later detach
// match the device by it. The regenerate keeps the alias the definition gave
// each owned address. An ownership-only device has none and gets none.
//
// Mutation: build the hostdevs without the definition's aliases — the
// journaled device goes red.
func TestUpdateVM_RegenerateKeepsAJournaledHostdevAlias(t *testing.T) {
	s := reconfigServer(t)
	ctx := adminCtx()
	insertTestVMWithSpec(t, ctx, s.db, "gpu", "test-host", "stopped",
		seedSpecJSON(t, &pb.VMSpec{Name: "gpu", Cpu: 2, MemoryMib: 2048, Machine: "pc"}))
	for _, addr := range []string{"0000:02:00.0", "0000:03:00.0"} {
		if err := corrosion.ObservePCIDevice(ctx, s.db, corrosion.PCIDeviceRecord{
			HostName: "test-host", Address: addr, Type: "gpu",
		}); err != nil {
			t.Fatalf("observe %s: %v", addr, err)
		}
		if ok, err := corrosion.ClaimPCIDevice(ctx, s.db, "test-host", addr, "gpu"); err != nil || !ok {
			t.Fatalf("claim %s: ok=%v err=%v", addr, ok, err)
		}
	}
	prior := `<domain type='kvm'><name>gpu</name><memory unit='KiB'>2097152</memory><vcpu>2</vcpu><devices>
<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x02' slot='0x00' function='0x0'/></source><alias name='ua-dev1-m0'/></hostdev>
<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x03' slot='0x00' function='0x0'/></source></hostdev>
</devices></domain>`
	if err := s.virt.DefineDomain(prior); err != nil {
		t.Fatalf("seed domain: %v", err)
	}

	// A machine change is never patched in place.
	if _, err := s.UpdateVM(ctx, &pb.UpdateVMRequest{Name: "gpu", Machine: "q35"}); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	domXML, err := s.virt.DumpXMLInactive("gpu")
	if err != nil {
		t.Fatalf("DumpXMLInactive: %v", err)
	}
	got := hostdevAliasesInXML(t, domXML)
	if len(got) != 2 {
		t.Fatalf("want both owned devices in the regenerated definition, got %v:\n%s", got, domXML)
	}
	if got["0x02"] != "ua-dev1-m0" {
		t.Errorf("the journaled device's alias is %q, want ua-dev1-m0:\n%s", got["0x02"], domXML)
	}
	if got["0x03"] != "" {
		t.Errorf("the ownership-only device gained alias %q:\n%s", got["0x03"], domXML)
	}
}
