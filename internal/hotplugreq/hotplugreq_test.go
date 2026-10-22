package hotplugreq

import (
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// With an address the request must classify as the address selector, the only
// one the stopped-VM journaled path handles; the CLI's default --type gpu must
// not turn it into a type selector.
func TestAttachPCI_AddressIsTheAddressSelector(t *testing.T) {
	req, err := AttachPCI("vm1", AttachPCIOptions{Address: "0000:41:00.0", Type: "gpu", Count: 1})
	if err != nil {
		t.Fatal(err)
	}
	if kind, _ := corrosion.ClassifyPCISelector(req.PciDevice); kind != "address" {
		t.Fatalf("selector kind = %q, want address", kind)
	}
	if _, err := AttachPCI("vm1", AttachPCIOptions{Address: "0000:41:00.0", Vendor: "10de"}); err == nil {
		t.Fatal("--address with --vendor was accepted")
	}
	req, _ = AttachPCI("vm1", AttachPCIOptions{Type: "gpu", Count: 1})
	if kind, _ := corrosion.ClassifyPCISelector(req.PciDevice); kind != "type" {
		t.Fatalf("no address: selector kind = %q, want type", kind)
	}
}
