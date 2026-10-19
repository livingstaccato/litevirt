package grpcapi

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/apimeta"
	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

func admit(s *Server, name string) (*pb.AdmitHostResponse, error) {
	return admitFrom(s, name, true)
}

// admitFrom is admit from an lv that names the release it installs
// (this release's), or, with current false, from a previous release's.
func admitFrom(s *Server, name string, current bool) (*pb.AdmitHostResponse, error) {
	ctx := adminCtx()
	if current {
		ctx = metadata.NewIncomingContext(ctx, metadata.Pairs(apimeta.AdmitInstallsReleaseHeader, capabilities.ReleaseToken))
	}
	return s.AdmitHost(ctx, &pb.AdmitHostRequest{Name: name, Address: "10.0.0.9", CertSerial: "0a0b0c"})
}

// admitAt is admit at another address than admit's: AdmitHost refuses a
// second name at an address a host already holds.
func admitAt(s *Server, name, addr string) (*pb.AdmitHostResponse, error) {
	ctx := metadata.NewIncomingContext(adminCtx(), metadata.Pairs(apimeta.AdmitInstallsReleaseHeader, capabilities.ReleaseToken))
	return s.AdmitHost(ctx, &pb.AdmitHostRequest{Name: name, Address: addr, CertSerial: "0b0c0d"})
}

// TestAdmitHost_AHeldAdmitterRefuses is I-A: a node that is itself holding its
// own audit rows is a rebuilt host whose history has not arrived, and it cannot
// vouch for another name's. It refuses rather than answer "no history".
//
// Mutation: drop the AuditChainHeld check in auditAdmissionPosition — it
// answers seq 0.
func TestAdmitHost_AHeldAdmitterRefuses(t *testing.T) {
	s := testServer(t)
	s.db.HoldAuditUntilCaughtUp(corrosion.AuditHoldConfig{Host: s.hostName, Target: 9, TargetHash: "ab"})
	if _, err := admit(s, "node-4"); status.Code(err) != codes.Unavailable {
		t.Fatalf("AdmitHost through a held node: %v, want Unavailable", err)
	}
}

// TestAdmitHost_AnUnseededAdmitterRefuses is I-C: a replica that has caught up
// — its one completed exchange was with a held, empty rebuilt peer — or that is
// alone, is no evidence it holds the cluster's history. Only a seeded replica
// vouches.
//
// Mutation: drop the AuditSeeded check — the caught-up, unseeded node answers.
func TestAdmitHost_AnUnseededAdmitterRefuses(t *testing.T) {
	ctx := context.Background()
	// Caught up, not seeded, with a peer.
	s := testServer(t)
	for _, h := range []string{s.hostName, "peer-host"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	s.db.MarkReplicaCaughtUpForTests("a-held-empty-peer")
	if _, err := admit(s, "node-4"); status.Code(err) != codes.Unavailable {
		t.Fatalf("caught up but not seeded: %v, want Unavailable", err)
	}
	// Alone and not seeded: a founder that lost its state.db, or a rebuilt host
	// at first boot (M-J).
	s = testServer(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, err := admit(s, "node-4"); status.Code(err) != codes.Unavailable {
		t.Fatalf("alone, not seeded: %v, want Unavailable", err)
	}
}

// TestAdmitHost_ASingleNodeFounderCanAddAHost: the founder, seeded at genesis
// and alone in its cluster, has nobody to catch up with and vouches from its
// own replica.
//
// Mutation: require a completed exchange even when alone — refused.
func TestAdmitHost_ASingleNodeFounderCanAddAHost(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.MarkAuditSeeded(ctx, "genesis"); err != nil {
		t.Fatal(err)
	}
	s.db.MarkReplicaStale("no peer has ever been reachable")
	resp, err := admit(s, "node-1")
	if err != nil || !resp.GetAuditPositionProven() || resp.GetAuditTailSeq() != 0 {
		t.Fatalf("a seeded founder alone: %+v, %v; want a vouched seq 0", resp, err)
	}
	// Seeded but with a peer and not caught up since starting: refused.
	s = testServer(t)
	for _, h := range []string{s.hostName, "peer-host"} {
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.db.MarkAuditSeeded(ctx, "upgrade"); err != nil {
		t.Fatal(err)
	}
	s.db.MarkReplicaStale("restarted")
	if _, err := admit(s, "node-4"); status.Code(err) != codes.Unavailable {
		t.Fatalf("seeded, stale replica with a peer: %v, want Unavailable", err)
	}
}

// TestAdmitHost_ATailBelowTheCARetirementRefuses: `lv host rm` CA-retired the
// name's key at seq 3; a replica whose copy of the chain ends at 1 is behind
// the one that removed it, and its answer would let the rebuilt host open early.
//
// Mutation: drop the CARetirementFloor comparison — it answers seq 1.
func TestAdmitHost_ATailBelowTheCARetirementRefuses(t *testing.T) {
	ctx := context.Background()
	s, dir, keyID := retireFixture(t, "node-1")
	if err := s.db.MarkAuditSeeded(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		insAudit(t, s, "node-1")
	}
	sig, err := corrosion.SignLifecycleWithCA(dir, "node-1", keyID, "retired", 3)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx,
		`INSERT INTO audit_key_lifecycle (host_name, key_id, event, at_seq, by_key_id, signature, created_at, updated_at, deleted_at)
		 VALUES ('node-1', ?, 'retired', 3, 'cluster-ca', ?, '2026-10-01T00:00:00Z', '2026-10-01T00:00:00Z', NULL)`,
		keyID, sig); err != nil {
		t.Fatal(err)
	}
	if resp, err := admit(s, "node-1"); err != nil || resp.GetAuditTailSeq() != 3 || !resp.GetAuditPositionProven() {
		t.Fatalf("a current replica: %+v, %v; want seq 3, vouched", resp, err)
	}
	if err := s.db.Execute(ctx, `DELETE FROM hosts WHERE name = 'node-1'`); err != nil {
		t.Fatal(err)
	}
	if err := s.db.Execute(ctx, `DELETE FROM audit_log WHERE host_name = 'node-1' AND seq > 1`); err != nil {
		t.Fatal(err)
	}
	_, err = admit(s, "node-1")
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("a replica behind the CA retirement: %v, want Unavailable", err)
	}
}

// TestGetStateDigest_ReportsSeededOnlyWhenNotHeld: a peer that completes an
// exchange with this node becomes seeded on its word, so it says seeded only
// when its replica is seeded and it is not still waiting for its own history.
//
// Mutation: report AuditSeeded alone — a held node seeds its peers.
func TestGetStateDigest_ReportsSeededOnlyWhenNotHeld(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	if resp, err := s.GetStateDigest(adminCtx(), nil); err != nil || resp.GetAuditSeeded() {
		t.Fatalf("unseeded: %v %v", resp.GetAuditSeeded(), err)
	}
	if err := s.db.MarkAuditSeeded(ctx, "test"); err != nil {
		t.Fatal(err)
	}
	if resp, err := s.GetStateDigest(adminCtx(), nil); err != nil || !resp.GetAuditSeeded() {
		t.Fatalf("seeded: %v %v", resp.GetAuditSeeded(), err)
	}
	s.db.HoldAuditUntilCaughtUp(corrosion.AuditHoldConfig{Host: s.hostName, Target: 9, TargetHash: "ab"})
	if resp, err := s.GetStateDigest(adminCtx(), nil); err != nil || resp.GetAuditSeeded() {
		t.Fatalf("seeded but held: %v %v; want not reported seeded", resp.GetAuditSeeded(), err)
	}
}

// fd re-review N-m4: two `lv host add` runs against one machine under two
// names each passed the CLI's address check before either was admitted.
// AdmitHost itself refuses an address (at the gRPC port it records) that
// another live or joining host already holds; a removed host's, or another
// port's, does not count.
//
// Mutation: drop the check — "live" and "joining" are admitted.
func TestAdmitHost_RefusesAnAddressAnotherHostHolds(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		other   corrosion.HostRecord
		removed bool
		refuse  bool
	}{
		{"live", corrosion.HostRecord{Name: "other", Address: "10.0.0.9", GRPCPort: 7443, State: "active"}, false, true},
		{"joining", corrosion.HostRecord{Name: "other", Address: "10.0.0.9", GRPCPort: 7443, State: corrosion.HostStateJoining}, false, true},
		{"removed", corrosion.HostRecord{Name: "other", Address: "10.0.0.9", GRPCPort: 7443, State: "active"}, true, false},
		{"another port", corrosion.HostRecord{Name: "other", Address: "10.0.0.9", GRPCPort: 7500, State: "active"}, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testServer(t)
			if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
				t.Fatal(err)
			}
			if err := s.db.MarkAuditSeeded(ctx, "genesis"); err != nil {
				t.Fatal(err)
			}
			s.db.MarkReplicaCaughtUpForTests("peer")
			tc.other.CertSerial = "ffee"
			if err := corrosion.InsertHost(ctx, s.db, tc.other); err != nil {
				t.Fatal(err)
			}
			if tc.removed {
				if err := corrosion.DeleteHost(ctx, s.db, "other"); err != nil {
					t.Fatal(err)
				}
			}
			_, err := admit(s, "node-1")
			if tc.refuse {
				// N2-n2: a machine rebuilt under a new name usually replaces a dead
				// host, which `lv host rm --dead` removes.
				if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "lv host rm other") ||
					!strings.Contains(err.Error(), "lv host rm --dead other") {
					t.Fatalf("admit at an address other holds = %v, want a refusal naming it", err)
				}
				if h, _ := corrosion.GetHost(ctx, s.db, "node-1"); h != nil {
					t.Error("the refused host was admitted")
				}
				return
			}
			if err != nil {
				t.Fatalf("admit = %v, want it admitted", err)
			}
		})
	}
}

// TestAdmitHost_RefusesAnUnsafeName: a host named after a fixed file of the
// operator's PKI directory ("ca") or one that leaves it is refused by the
// daemon too, so an lv that does not check cannot record one; "lv-cli" is the
// distributable client certificate's Common Name.
//
// Mutation: drop the ValidateHostName check in AdmitHost — "ca" is admitted.
func TestAdmitHost_RefusesAnUnsafeName(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"ca", "client", "lv-cli", "node-1-migration", "../esc", "-rf", ".hidden"} {
		s := testServer(t)
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
		if err := s.db.MarkAuditSeeded(ctx, "genesis"); err != nil {
			t.Fatal(err)
		}
		s.db.MarkReplicaStale("no peer has ever been reachable")
		if _, err := admit(s, name); status.Code(err) != codes.InvalidArgument {
			t.Errorf("AdmitHost(%q) = %v, want InvalidArgument", name, err)
		}
		if h, _ := corrosion.GetHost(ctx, s.db, name); h != nil {
			t.Errorf("%q was admitted", name)
		}
	}
	// The same server admits an ordinary name.
	s := testServer(t)
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{Name: s.hostName, Address: "10.0.0.1", State: "active"}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.MarkAuditSeeded(ctx, "genesis"); err != nil {
		t.Fatal(err)
	}
	s.db.MarkReplicaStale("no peer has ever been reachable")
	if _, err := admit(s, "node-1"); err != nil {
		t.Fatalf("AdmitHost(node-1) = %v", err)
	}
}
