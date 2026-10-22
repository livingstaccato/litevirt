package corrosion

import (
	"context"
	"sort"
	"testing"
)

// ReplacePCIRealizations retires an intent's rows and writes its new ones as
// one write: when the upsert fails after the tombstone, nothing is applied
// and the old rows stay live. A crash between the two cannot leave the
// intent with no live row.
func TestReplacePCIRealizations_RetireAndUpsertAreOneWrite(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	for i, addr := range []string{"0000:81:00.0", "0000:81:00.1"} {
		if err := UpsertPCIRealization(ctx, c, PCIRealizationRecord{VMName: "vm", DeviceID: "d", MemberID: []string{"m0", "m1"}[i],
			HostName: "h", ResolvedAddress: addr, Ordinal: i}); err != nil {
			t.Fatal(err)
		}
	}
	live := func() []string {
		t.Helper()
		rows, err := ListVMPCIRealizations(ctx, c, "vm")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, r := range rows {
			out = append(out, r.MemberID+"="+r.ResolvedAddress)
		}
		sort.Strings(out)
		return out
	}

	if _, err := c.db.Exec(`CREATE TRIGGER fail_realization_insert BEFORE INSERT ON vm_pci_realizations
		BEGIN SELECT RAISE(ABORT, 'injected upsert failure'); END`); err != nil {
		t.Fatalf("install trigger: %v", err)
	}
	err := ReplacePCIRealizations(ctx, c, "vm", "d", true, []PCIRealizationRecord{{VMName: "vm", DeviceID: "d", MemberID: "m0",
		HostName: "h", ResolvedAddress: "0000:81:00.0"}})
	if err == nil {
		t.Fatal("the upsert was meant to fail")
	}
	if got := live(); len(got) != 2 {
		t.Fatalf("after a failed replace the live rows are %v; want both old members, untouched", got)
	}
	if _, err := c.db.Exec(`DROP TRIGGER fail_realization_insert`); err != nil {
		t.Fatal(err)
	}

	if err := ReplacePCIRealizations(ctx, c, "vm", "d", true, []PCIRealizationRecord{{VMName: "vm", DeviceID: "d", MemberID: "m0",
		HostName: "h", ResolvedAddress: "0000:81:00.0"}}); err != nil {
		t.Fatal(err)
	}
	if got := live(); len(got) != 1 || got[0] != "m0=0000:81:00.0" {
		t.Fatalf("after the replace the live rows are %v; want m0 alone", got)
	}
}
