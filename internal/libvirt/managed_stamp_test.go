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

// The incarnation attribute (docs/design/partition-pause.md §6): read back as
// written, absent on an older binary's bare element (which still parses as a
// stamp), and an element that is not the stamp is an error.
//
// Mutation: report ok=true for an empty attribute — the bare-element case goes
// red; read a different attribute name — the round trip goes red.
func TestParseManagedIncarnation(t *testing.T) {
	inc, ok, err := parseManagedIncarnation("vm1", `<managed incarnation="2026-10-02T13:10:31.123456789Z"/>`)
	if err != nil || !ok || inc != "2026-10-02T13:10:31.123456789Z" {
		t.Fatalf("round trip: (%q,%v,%v)", inc, ok, err)
	}
	if inc, ok, err := parseManagedIncarnation("vm1", `<managed/>`); err != nil || ok || inc != "" {
		t.Fatalf("bare element: (%q,%v,%v), want no incarnation and no error", inc, ok, err)
	}
	if ok, err := parseManagedMetadata("vm1", `<managed incarnation="x"/>`); err != nil || !ok {
		t.Fatalf("an attributed stamp is no longer recognised as a stamp: (%v,%v)", ok, err)
	}
	if _, _, err := parseManagedIncarnation("vm1", `<owner-epoch>3</owner-epoch>`); err == nil {
		t.Fatal("a non-stamp element parsed as an incarnation")
	}
}
