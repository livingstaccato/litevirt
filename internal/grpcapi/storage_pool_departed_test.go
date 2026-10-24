package grpcapi

import (
	"context"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Lab 4 finding 4: more than 20 minutes after `lv host rm node-5`, `lv pool
// ls` still listed node-5's `default` and `isos` pools as active. The
// removal leaves the pool rows (and the data on the machine) alone, so
// ListStoragePools lists a pool whose host has no live row as departed. Its
// row is not changed, and a re-added host's pools are listed as it reports
// them again.
//
// Mutation: drop the departed override — node-5's pools are listed active.
func TestListStoragePools_RemovedHostsPoolsAreDeparted(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	for _, h := range []string{"node-1", "node-5"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0." + h[5:], State: "active"}); err != nil {
			t.Fatal(err)
		}
		for _, pool := range []string{"default", "isos"} {
			if err := corrosion.UpsertStoragePool(ctx, s.db, corrosion.StoragePoolRecord{
				HostName: h, Name: pool, Driver: "dir", State: "active",
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	states := func() map[string]string {
		t.Helper()
		resp, err := s.ListStoragePools(adminCtx(), &pb.ListStoragePoolsRequest{})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, p := range resp.GetPools() {
			got[p.GetHost()+"/"+p.GetName()] = p.GetState()
		}
		return got
	}
	want := func(got map[string]string, node5 string) {
		t.Helper()
		for _, k := range []string{"node-1/default", "node-1/isos", "node-5/default", "node-5/isos"} {
			w := "active"
			if k[:6] == "node-5" {
				w = node5
			}
			if got[k] != w {
				t.Errorf("%s is %q, want %q (all: %v)", k, got[k], w, got)
			}
		}
	}
	want(states(), "active")

	if err := corrosion.DeleteHost(ctx, s.db, "node-5"); err != nil {
		t.Fatal(err)
	}
	want(states(), "departed")
	// The rows themselves are kept, as the host wrote them.
	if rows, err := corrosion.ListStoragePoolsForHost(ctx, s.db, "node-5"); err != nil || len(rows) != 2 || rows[0].State != "active" {
		t.Fatalf("node-5's pool rows after the removal: %+v, %v", rows, err)
	}

	// Re-added: its pools are its own again.
	if err := corrosion.AdmitHost(ctx, s.db, corrosion.HostRecord{Name: "node-5", Address: "10.0.0.5", State: "joining", CertSerial: "aa"}); err != nil {
		t.Fatal(err)
	}
	want(states(), "active")
}
