package libvirt

import "testing"

// The managed stamp's parse contract: the element is proof, anything else under
// litevirt's namespace is an error, never a quiet "yes".
func TestParseManagedMetadata(t *testing.T) {
	for _, raw := range []string{"<managed/>", "<managed></managed>", `<litevirt-managed:managed xmlns:litevirt-managed="https://litevirt.dev/xmlns/managed/1"/>`} {
		if ok, err := parseManagedMetadata("vm1", raw); err != nil || !ok {
			t.Errorf("%q: (%v,%v), want (true,nil)", raw, ok, err)
		}
	}
	for _, raw := range []string{"not-xml<", "<owner-epoch>3</owner-epoch>", ""} {
		if ok, err := parseManagedMetadata("vm1", raw); err == nil || ok {
			t.Errorf("%q: (%v,%v), want an error", raw, ok, err)
		}
	}
}
