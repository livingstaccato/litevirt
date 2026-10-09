package health

import (
	"context"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// Owner-assert skips asking a host only when it is PROVED off: 'fenced' over a
// proof-grade fence. A host an older leader recorded 'fenced' on an SSH
// poweroff nothing verified may still be running the workload, and reclaiming
// it without asking that host is the split-brain the corroboration exists to
// prevent (colonelpanik/litevirt#253).
//
// Mutation: exclude every 'fenced' host on its state alone again, as before
// the fix — the SSH-fenced host drops out of the peers and the test goes red.
func TestWorkloadCapablePeers_AsksAFencedHostThatWasNotProvedOff(t *testing.T) {
	ctx := context.Background()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(ctx, db); err != nil {
		t.Fatalf("InitSchema: %v", err)
	}
	for _, h := range []corrosion.HostRecord{
		{Name: "self", Address: "10.0.0.1", State: "active"},
		{Name: "ssh-fenced", Address: "10.0.0.2", State: "fenced"},
		{Name: "ipmi-fenced", Address: "10.0.0.3", State: "fenced"},
		{Name: "confirmed", Address: "10.0.0.4", State: "fenced"},
		{Name: "offline", Address: "10.0.0.5", State: "offline"},
		{Name: "witness", Address: "10.0.0.6", State: "active", Role: "witness"},
	} {
		if err := corrosion.InsertHost(ctx, db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	for _, f := range []corrosion.FenceLogRecord{
		{ID: "1", HostName: "ssh-fenced", Method: "ssh", Result: "fenced"},
		{ID: "2", HostName: "ipmi-fenced", Method: "ipmi", Result: "fenced"},
		{ID: "3", HostName: "confirmed", Method: "manual", Result: "manual-confirmed"},
		{ID: "4", HostName: "offline", Method: "ipmi", Result: "fenced"},
	} {
		if err := corrosion.InsertFenceLog(ctx, db, f); err != nil {
			t.Fatalf("InsertFenceLog: %v", err)
		}
	}
	hosts, err := corrosion.ListHosts(ctx, db)
	if err != nil {
		t.Fatal(err)
	}

	got := workloadCapablePeers(ctx, db, hosts, "self")
	slices.Sort(got)
	want := []string{"offline", "ssh-fenced"}
	if !slices.Equal(got, want) {
		t.Errorf("workloadCapablePeers = %v, want %v: only a host proved off is not asked", got, want)
	}
}
