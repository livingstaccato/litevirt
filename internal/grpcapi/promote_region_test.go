package grpcapi

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestAutoPromoteInRegion_RefusesAReplicaOutsideTheRegion: under region-scoped
// failover the coordinator asks for a promotion that stays in the fenced
// host's region. A replica held by a host in another region is refused before
// anything is persisted or relayed, and the coordinator falls back to the
// region-constrained reschedule.
func TestAutoPromoteInRegion_RefusesAReplicaOutsideTheRegion(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
		Name: s.hostName, Address: "10.0.0.1", SSHUser: "root", State: "active", CertSerial: "s",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.UpdateHostRegion(ctx, s.db, s.hostName, "east"); err != nil {
		t.Fatalf("UpdateHostRegion: %v", err)
	}
	seedReplicaOfAge(t, s, "db-r", "0 * * * *", 10*time.Minute)

	err := s.AutoPromoteReplicaInRegion(ctx, "db-r", "", 0, "west")
	if !errors.Is(err, errReplicaOutOfRegion) {
		t.Fatalf("promotion onto an east replica host, asked to stay in west: err=%v, want errReplicaOutOfRegion", err)
	}
	if n := proofRowCount(t, s); n != 0 {
		t.Fatalf("a refused out-of-region promotion persisted %d proof row(s)", n)
	}

	// The same replica, asked to stay in its own region, is not refused for region.
	if err := s.AutoPromoteReplicaInRegion(ctx, "db-r", "", 0, "east"); errors.Is(err, errReplicaOutOfRegion) {
		t.Fatalf("an in-region replica was refused as out of region: %v", err)
	}
}

func proofRowCount(t *testing.T, s *Server) int {
	t.Helper()
	rows, err := s.db.Query(context.Background(), `SELECT count(*) AS n FROM runtime_action_proofs`)
	if err != nil || len(rows) != 1 {
		t.Fatalf("count proofs: %v", err)
	}
	return rows[0].Int("n")
}

// scopeServer is testServer with five voters in east (test-host, e2, e3) and
// west (w1, w2).
