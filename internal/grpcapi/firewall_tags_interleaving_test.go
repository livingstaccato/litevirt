package grpcapi

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// The real feature callback resumes after a peer acknowledgement. The hook
// changes only stored workload/lease facts; the grant and writer are unchanged.
type tagInterleavingGate struct {
	*relGate
	before func()
}

func (g *tagInterleavingGate) WithFeature(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
	return g.relGate.WithFeature(ctx, f, func(ctx context.Context, grant capabilities.FeatureGrant) error {
		if g.before != nil {
			fn := g.before
			g.before = nil
			fn()
		}
		return write(ctx, grant)
	})
}

func TestSetFirewallTags_OwnerTransferCannotAuthorizeOldOwner(t *testing.T) {
	for _, phase := range []string{"gate", "gate-copied", "before-mint", "before-write", "owner-aba"} {
		t.Run(phase, func(t *testing.T) {
			s, g := tagsServer(t)
			insertTestVM(t, adminCtx(), s.db, "web", s.hostName, "running")
			if phase == "gate-copied" {
				insertTestVM(t, adminCtx(), s.db, "copy", s.hostName, "running")
				for _, n := range []string{"web", "copy"} {
					setVMSpec(t, s, n, `{"name":"`+n+`","firewall_id":"`+fwA+`"}`)
				}
				seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "old"}, "copy", "")
			}
			called := false
			var transferredID, transferredTags string
			transfer := func() {
				called = true
				vm, err := corrosion.GetVM(context.Background(), s.db, "web")
				if err != nil || vm == nil {
					t.Fatalf("read owner: %v", err)
				}
				if err := corrosion.TransferVMOwner(context.Background(), s.db, "web", "node-new", "running", vm.OwnerEpoch); err != nil {
					t.Fatal(err)
				}
				if phase == "owner-aba" {
					if err := corrosion.TransferVMOwner(context.Background(), s.db, "web", s.hostName, "running", vm.OwnerEpoch+1); err != nil {
						t.Fatal(err)
					}
				}
				transferredID = vmFWID(t, s, "web")
				if transferredID != "" {
					transferredTags, _ = tagsRowValue(t, s, corrosion.TagMemberVM, transferredID)
				}
			}
			switch phase {
			case "gate", "gate-copied":
				s.SetReleaseFeatureGate(&tagInterleavingGate{relGate: g, before: transfer})
			case "before-mint", "owner-aba":
				s.testFirewallTagsBeforeMint = transfer
			case "before-write":
				s.testFirewallTagsBeforeWrite = transfer
			}
			_, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"role": "stale"}})
			if !called {
				t.Fatal("owner transition was not reached")
			}
			if status.Code(err) != codes.Aborted {
				t.Errorf("old owner completed after transfer: %v, want Aborted", err)
			}
			if got := vmFWID(t, s, "web"); got != transferredID {
				t.Errorf("old owner minted after transfer: %q -> %q", transferredID, got)
			}
			if transferredID != "" {
				if got, _ := tagsRowValue(t, s, corrosion.TagMemberVM, transferredID); got != transferredTags {
					t.Errorf("old owner changed tags after transfer: %q -> %q", transferredTags, got)
				}
			}
		})
	}
}

func TestSweepFirewallTagOrphans_RechecksAfterFeatureWait(t *testing.T) {
	for _, change := range []string{"live-holder", "lost-identity", "open-move", "lease-transfer", "lease-expiry", "row-version", "unchanged"} {
		t.Run(change, func(t *testing.T) {
			s, g, _, _ := sweepServer(t, "")
			g.open = true
			markTagsUsed(t, s)
			ctx := context.Background()
			seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "old"}, "web", "")
			now := time.Now().Add(25 * time.Hour)
			candidates, err := corrosion.FirewallTagsOrphans(ctx, s.db, now, firewallTagsOrphanGrace)
			if err != nil || len(candidates) != 1 {
				t.Fatalf("selected orphan: %v %v", candidates, err)
			}
			called := false
			expected, _ := tagsRowValue(t, s, corrosion.TagMemberVM, fwA)
			exec := func(q string, args ...interface{}) {
				if err := s.db.Execute(ctx, q, args...); err != nil {
					t.Fatal(err)
				}
			}
			s.SetReleaseFeatureGate(&tagInterleavingGate{relGate: g, before: func() {
				called = true
				switch change {
				case "live-holder":
					insertTestVM(t, ctx, s.db, "web", s.hostName, "running")
					setVMSpec(t, s, "web", `{"name":"web","firewall_id":"`+fwA+`"}`)
				case "lost-identity":
					insertTestVM(t, ctx, s.db, "web", s.hostName, "running")
				case "open-move":
					exec(`INSERT INTO runtime_action_proofs (id,action,target_kind,target_name,dest_host,coordinator,relocation_token,status,created_at,updated_at) VALUES ('moving',?,'vm','web','node-new',?,'token',?,?,?)`, corrosion.ActionRelocate, s.hostName, corrosion.ProofPrepared, s.db.NowTS(), s.db.NowTS())
				case "lease-transfer":
					exec(`UPDATE leader_election SET holder = 'node-new' WHERE key = ?`, corrosion.LeaseKeyFailover)
				case "lease-expiry":
					exec(`UPDATE leader_election SET expires_at = '2000-01-01T00:00:00Z' WHERE key = ?`, corrosion.LeaseKeyFailover)
				case "row-version":
					seedTagsFor(t, s, corrosion.TagMemberVM, fwA, map[string]string{"role": "new"}, "web", "")
					expected, _ = tagsRowValue(t, s, corrosion.TagMemberVM, fwA)
				}
			}})
			s.sweepFirewallTagOrphans(ctx, now)
			if !called {
				t.Fatal("selected orphan did not reach the feature gate")
			}
			got, _ := tagsRowValue(t, s, corrosion.TagMemberVM, fwA)
			if change == "unchanged" {
				if got != "" {
					t.Fatalf("unchanged orphan was not cleared: %q", got)
				}
				return
			}
			if got != expected {
				t.Fatalf("stale orphan selection cleared tags after %s: %q -> %q", change, expected, got)
			}
		})
	}
}

func TestSetFirewallTags_MoveArrivingBeforeMintPreservesTargetTags(t *testing.T) {
	s, _ := tagsServer(t)
	ctx := context.Background()
	exec := func(q string, args ...interface{}) {
		if err := s.db.Execute(ctx, q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO containers (host_name,name,state,state_detail,create_spec,created_at,updated_at) VALUES (?,'moving','stopped','operator-stop',?,'t','t')`, s.hostName, `{"template":"debian","fw_id":"`+fwA+`"}`)
	seedTagsFor(t, s, corrosion.TagMemberCT, fwA, map[string]string{"role": "target"}, "moving", s.hostName)
	before, _ := tagsRowValue(t, s, corrosion.TagMemberCT, fwA)
	called := false
	s.testFirewallTagsBeforeMint = func() {
		called = true
		exec(`INSERT INTO containers (host_name,name,state,relocate_token,create_spec,created_at,updated_at) VALUES ('node-new','moving','running','move-token',?,'t','t')`, `{"template":"debian","fw_id":"`+fwA+`"}`)
		exec(`INSERT INTO runtime_action_proofs (id,action,target_kind,target_name,dest_host,coordinator,relocation_token,status,created_at,updated_at) VALUES ('move-proof',?,'container','moving','node-new',?,'move-token',?,'t','t')`, corrosion.ActionRelocate, s.hostName, corrosion.ProofInProgress)
	}
	_, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "ct", Host: s.hostName, Workload: "moving", Set: map[string]string{"role": "source"}})
	if !called {
		t.Fatal("real container setter did not reach mint")
	}
	if status.Code(err) != codes.FailedPrecondition {
		t.Errorf("open move tag set: %v", err)
	}
	rows, qerr := s.db.Query(ctx, `SELECT create_spec FROM containers WHERE name = 'moving' AND deleted_at IS NULL`)
	if qerr != nil || len(rows) != 2 {
		t.Fatalf("move pair: %v %v", rows, qerr)
	}
	for _, r := range rows {
		if corrosion.FirewallIDOf(corrosion.TagMemberCT, r.String("create_spec")) != fwA {
			t.Errorf("move pair identity changed: %v", r)
		}
	}
	if got, _ := tagsRowValue(t, s, corrosion.TagMemberCT, fwA); got != before {
		t.Fatalf("real target tags cleared: %q -> %q", before, got)
	}
}
