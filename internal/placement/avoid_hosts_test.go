package placement

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A host in AvoidHosts is passed over while another host qualifies, however
// it scores, and chosen when it is the only one left; SelectBatch honours it
// as Select does.
//
// Mutation: make withoutAvoided return c unchanged — the first case goes red
// (node-a, the emptier host, is chosen); make it return kept even when empty
// — the second goes red (no eligible host).
func TestSelect_AvoidHostsIsPassedOverOnlyWhileAnotherQualifies(t *testing.T) {
	db := testDB(t)
	insertHost(t, db, corrosion.HostRecord{Name: "node-a", Address: "10.0.0.1", State: "active", CPUTotal: 64, MemTotal: 262144})
	insertHost(t, db, corrosion.HostRecord{Name: "node-b", Address: "10.0.0.2", State: "active", CPUTotal: 8, MemTotal: 16384})
	ctx := context.Background()
	avoidA := map[string]string{"node-a": "bridge br0 does not filter VLANs"}

	if h, err := Select(ctx, db, Request{VMName: "v", CPUNeeded: 1, MemMiBNeeded: 512}); err != nil || h != "node-a" {
		t.Fatalf("without AvoidHosts Select = %q, %v; the fixture wants node-a preferred", h, err)
	}
	if h, err := Select(ctx, db, Request{VMName: "v", CPUNeeded: 1, MemMiBNeeded: 512, AvoidHosts: avoidA}); err != nil || h != "node-b" {
		t.Fatalf("Select with node-a avoided = %q, %v; want node-b", h, err)
	}
	// node-b cannot hold it: node-a is the only host, and is chosen.
	if h, err := Select(ctx, db, Request{VMName: "v", CPUNeeded: 1, MemMiBNeeded: 100000, AvoidHosts: avoidA}); err != nil || h != "node-a" {
		t.Fatalf("Select with node-a avoided and the only fit = %q, %v; want node-a", h, err)
	}

	hosts, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		t.Fatal(err)
	}
	res, err := SelectBatch(hosts, nil, nil, nil, nil, time.Time{}, []Request{{VMName: "v", CPUNeeded: 1, MemMiBNeeded: 512, AvoidHosts: avoidA}})
	if err != nil || res["v"].Host != "node-b" {
		t.Fatalf("SelectBatch with node-a avoided = %+v, %v; want node-b", res["v"], err)
	}
}
