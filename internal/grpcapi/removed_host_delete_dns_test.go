package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/dns"
)

// Deleting a VM recorded on a removed host must take its DNS A record with it,
// as DeleteVM's normal path does. deleteVMOnRemovedHost tombstoned the rows and
// stopped there, so the name kept resolving to an address the cluster had just
// released — and could hand to the next workload. (The container branch,
// deleteContainerOnRemovedHost, already removed its record.)
func TestDeleteVMOnRemovedHost_RemovesTheDNSRecord(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	vm := corrosion.VMRecord{Name: "app", HostName: "gone-host", Spec: "{}", State: "running", StackName: "shop"}
	if err := corrosion.InsertVM(ctx, s.db, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	domain := s.dnsDomain
	if domain == "" {
		domain = "lv.local"
	}
	name := dns.VMRecordName(vm.Name, vm.StackName, domain)
	if err := dns.UpsertRecord(ctx, s.db, name, "10.0.0.7"); err != nil {
		t.Fatalf("UpsertRecord: %v", err)
	}
	live := func() bool {
		rows, err := s.db.Query(ctx, `SELECT 1 FROM dns_records WHERE name = ? AND deleted_at IS NULL`, name)
		if err != nil {
			t.Fatalf("read dns_records: %v", err)
		}
		return len(rows) > 0
	}
	if !live() {
		t.Fatalf("control: the seeded record %s is not live", name)
	}

	rec, err := corrosion.GetVM(ctx, s.db, vm.Name)
	if err != nil || rec == nil {
		t.Fatalf("GetVM: %v %v", rec, err)
	}
	if _, err := s.deleteVMOnRemovedHost(ctx, rec); err != nil {
		t.Fatalf("deleteVMOnRemovedHost: %v", err)
	}
	if v, _ := corrosion.GetVM(ctx, s.db, vm.Name); v != nil {
		t.Fatalf("the VM row survived the delete, so this test proves nothing about DNS: %+v", v)
	}
	if live() {
		t.Errorf("the A record %s outlived the VM deleted on a removed host", name)
	}
}
