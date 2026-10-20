package health

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func TestVMSnapshotClaimFreshRecipientsAndRestart(t *testing.T) {
	const token = capabilities.VMSnapshotClaimV1
	ctx := context.Background()
	if !capabilities.ReplicationGated(token) || !capabilities.Mandatory(token) ||
		!slices.Contains(capabilities.Supported(), token) || !slices.Contains(capabilities.All(), token) {
		t.Fatal("snapshot claim decoder missing canonical capability registration")
	}
	for _, scenario := range []string{"maintenance_unsupported", "member_join", "member_regression", "unreachable", "restart", "missing_marker"} {
		t.Run(scenario, func(t *testing.T) {
			db := testCheckHostDB(t)
			gateHost(t, db, "host-a", "active", "worker")
			gateHost(t, db, "host-b", "active", "worker")
			gateHost(t, db, "host-old", "maintenance", "worker")
			members := []corrosion.PeerInfo{{Name: "host-b"}}
			if scenario == "maintenance_unsupported" {
				members = append(members, corrosion.PeerInfo{Name: "host-old"})
			}
			db.SetMembersForTests(func() []corrosion.PeerInfo { return members })
			c := NewChecker("host-a", "/etc/litevirt/pki", db)
			base := ActivationMarkerBase(t.TempDir())
			if scenario != "missing_marker" {
				c.SetActivationMarker(base)
			}
			unsupported := scenario == "maintenance_unsupported"
			unreachable := false
			pings := 0
			ping := func(_ context.Context, host string) ([]string, time.Time, error) {
				pings++
				if unreachable {
					return nil, time.Time{}, errors.New("offline")
				}
				if unsupported && (host == "host-old" || scenario == "member_regression") {
					return nil, time.Time{}, nil
				}
				return capabilities.Supported(), time.Time{}, nil
			}
			c.SetPeerPinger(ping)
			wire := func() {
				db.SetVMSnapshotClaimCapability(func() bool { return c.DurablyLatched(token) }, func(ctx context.Context) bool {
					if !c.Enforced(ctx, token) || !c.DurablyLatched(token) {
						return false
					}
					ready, _ := c.CapabilityActive(ctx, token)
					return ready
				})
			}
			wire()
			if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "snapshot", HostName: "host-a", Project: "_default", Spec: `{}`, State: "stopped"}, nil, nil); err != nil {
				t.Fatal(err)
			}
			vm, err := corrosion.GetVM(ctx, db, "snapshot")
			if err != nil || vm == nil {
				t.Fatal(vm, err)
			}
			before := corrosion.SnapshotForDelete(*vm)
			op := corrosion.OperationRecord{ID: "claim", Method: "UpdateVM", Principal: "user:test", Project: "_default",
				ResourceKind: "vm", ResourceID: "snapshot", OperationKind: string(corrosion.OpResourceUpdateStopped), RequestHash: "request"}
			if scenario != "maintenance_unsupported" && scenario != "missing_marker" {
				if !c.Enforced(ctx, token) || !c.DurablyLatched(token) {
					t.Fatal("supported cluster did not persist latch")
				}
			}
			switch scenario {
			case "member_join":
				members = append(members, corrosion.PeerInfo{Name: "host-old"})
				unsupported = true
			case "member_regression":
				unsupported = true
			case "unreachable":
				unreachable = true
			case "restart":
				c = NewChecker("host-a", "/etc/litevirt/pki", db)
				c.SetActivationMarker(base)
				c.SetPeerPinger(ping)
				if !c.DurablyLatched(token) {
					t.Fatal("restart lost durable acceptance")
				}
				unsupported = true
				members = append(members, corrosion.PeerInfo{Name: "host-old"})
			}
			rowsBefore, err := db.Query(ctx, `SELECT * FROM mutation_log ORDER BY seq`)
			if err != nil {
				t.Fatal(err)
			}
			pingsBefore := pings
			if ok, err := db.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, before); ok || err == nil {
				t.Fatalf("unsupported/non-durable emission: ok=%v err=%v", ok, err)
			}
			if scenario != "missing_marker" && pings == pingsBefore {
				t.Fatal("emission used cached positive rather than fresh recipients")
			}
			rowsAfter, err := db.Query(ctx, `SELECT * FROM mutation_log ORDER BY seq`)
			if err != nil || len(rowsBefore) != len(rowsAfter) {
				t.Fatal("refusal emitted a claim")
			}
			vm, err = corrosion.GetVM(ctx, db, "snapshot")
			if err != nil || vm == nil || corrosion.SnapshotForDelete(*vm) != before || vm.ActiveOperationID != "" {
				t.Fatal("capability refusal mutated VM")
			}
		})
	}
}

func TestVMSnapshotClaimUniformRecipientsPermitEmission(t *testing.T) {
	ctx := context.Background()
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-old", "maintenance", "worker")
	db.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: "host-old"}} })
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.SetActivationMarker(ActivationMarkerBase(t.TempDir()))
	c.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return capabilities.Supported(), time.Time{}, nil
	})
	db.SetVMSnapshotClaimCapability(func() bool { return c.DurablyLatched(capabilities.VMSnapshotClaimV1) }, func(ctx context.Context) bool {
		if !c.Enforced(ctx, capabilities.VMSnapshotClaimV1) || !c.DurablyLatched(capabilities.VMSnapshotClaimV1) {
			return false
		}
		ready, _ := c.CapabilityActive(ctx, capabilities.VMSnapshotClaimV1)
		return ready
	})
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "snapshot", HostName: "host-a", Project: "_default", Spec: `{}`, State: "stopped"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	vm, err := corrosion.GetVM(ctx, db, "snapshot")
	if err != nil || vm == nil {
		t.Fatal(vm, err)
	}
	op := corrosion.OperationRecord{ID: "claim", Method: "UpdateVM", Principal: "user:test", Project: "_default",
		ResourceKind: "vm", ResourceID: "snapshot", OperationKind: string(corrosion.OpResourceUpdateStopped), RequestHash: "request"}
	if ok, err := db.BeginVMOperationAtSnapshot(ctx, op, `{"cpu":4}`, corrosion.SnapshotForDelete(*vm)); !ok || err != nil {
		t.Fatal(ok, err)
	}
}
