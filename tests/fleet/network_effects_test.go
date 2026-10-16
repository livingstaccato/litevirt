package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/network"
)

// The real peer RPC must update this node's modeled kernel, before and after
// rebuilding its server. TestMain's process-lifetime tripwire also refuses
// any fallback to the host bridge/arping executables.
func TestFleet_NetworkEffectsFDBSurvivesServerRebuild(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			restartNode(t, c, dst)
		}
		req := &pb.UpdateFDBRequest{Vni: 5178, Mac: "52:54:00:78:00:01", NewVtepIp: "192.0.2.8"}
		if _, err := c.PeerClient(src, dst).UpdateFDB(ctx, req); err != nil {
			t.Fatalf("phase %d add: %v", phase, err)
		}
		if got := dst.Net.FDBDestinations(5178, req.Mac); len(got) != 1 || got[0] != req.NewVtepIp {
			t.Fatalf("phase %d modeled FDB: %v", phase, got)
		}
		req.OldVtepIp, req.NewVtepIp = req.NewVtepIp, "192.0.2.9"
		if _, err := c.PeerClient(src, dst).UpdateFDB(ctx, req); err != nil {
			t.Fatalf("phase %d replace: %v", phase, err)
		}
		if got := dst.Net.FDBDestinations(5178, req.Mac); len(got) != 1 || got[0] != req.NewVtepIp {
			t.Fatalf("phase %d replaced FDB: %v", phase, got)
		}
		req.OldVtepIp, req.NewVtepIp = req.NewVtepIp, ""
		if _, err := c.PeerClient(src, dst).UpdateFDB(ctx, req); err != nil {
			t.Fatal(err)
		}
		if got := dst.Net.FDBDestinations(5178, req.Mac); len(got) != 0 {
			t.Fatalf("phase %d deleted FDB: %v", phase, got)
		}
	}
}

func TestFleet_NetworkEffectsPeerVTEPReplacesStaleRow(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	ctx := context.Background()
	if err := network.UpsertVTEP(ctx, dst.DB, "effects-vxlan", src.Name, "192.0.2.7", 5178); err != nil {
		t.Fatal(err)
	}
	for phase := 0; phase < 2; phase++ {
		if phase == 1 {
			restartNode(t, c, dst)
		}
		for _, addr := range []string{"192.0.2.8", "192.0.2.9"} {
			if _, err := c.PeerClient(src, dst).SyncVTEP(ctx, &pb.SyncVTEPRequest{NetworkName: "effects-vxlan", Vni: 5178, VtepIp: addr}); err != nil {
				t.Fatalf("phase %d sync: %v", phase, err)
			}
			if got := dst.Net.FDBDestinations(5178, "00:00:00:00:00:00"); len(got) != 1 || got[0] != addr {
				t.Fatalf("phase %d flood destinations: %v, want only pushed %s despite stale row", phase, got, addr)
			}
		}
	}
}

func TestFleet_NetworkEffectsMigrationRecordsGARP(t *testing.T) {
	c, src, dst, gates := guardHotplugCluster(t)
	refreshGuardQuorum(c, gates)
	if err := migrateAt(t, c, src, "web", dst.Name); err != nil {
		t.Fatal(err)
	}
	eventually(t, time.Second, "migration GARP in the source node's network fake", func() bool {
		return src.Net.GARPCount("lan", "10.30.0.41") == 1
	})
	if got := dst.Net.GARPCount("lan", "10.30.0.41"); got != 0 {
		t.Fatalf("GARP leaked across node models: %d", got)
	}
}
