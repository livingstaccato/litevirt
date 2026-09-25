package health

import (
	"context"
	"errors"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// A peer whose TLS endpoint answers but whose daemon says it cannot serve is
// recorded as UNREADY, not healthy.
//
// The listener in healthyPeer is the wedged daemon: it completes a handshake
// and nothing more, which is precisely what a daemon with a stalled WAL
// checkpoint does. Before the readiness probe this peer was reported healthy,
// kept its voting weight and kept receiving pushes it could not apply.
func TestCheckHost_ReachableButNotReadyIsNotHealthy(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	addr, port := healthyPeer(t)
	c := probingChecker(t, db)
	c.SetPeerReadiness(func(context.Context, string) (bool, string, error) {
		return false, "database read timed out", nil
	})

	c.checkHost(ctx, corrosion.HostRecord{Name: "host-b", Address: addr, GRPCPort: port})

	rows, err := db.Query(ctx,
		`SELECT status, consecutive_failures, last_seen FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-b")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row, got %d", len(rows))
	}
	if got := rows[0].String("status"); got != StatusUnready {
		t.Errorf("status = %q, want %q — a peer that answers TLS but cannot serve is not healthy", got, StatusUnready)
	}
	if got := rows[0].Int("consecutive_failures"); got == 0 {
		t.Error("consecutive_failures = 0; an unready observation is a failed observation")
	}
	if got := rows[0].String("last_seen"); got != "" {
		t.Errorf("last_seen = %q, want empty — last_seen means last seen HEALTHY", got)
	}
}

// Unreachable and reachable-but-not-ready are different verdicts. An RPC that
// does not complete says nothing about readiness, and must keep the existing
// suspect path — the one fencing quorum reads.
func TestCheckHost_UnreachableIsSuspectNeverUnready(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	c := probingChecker(t, db)
	c.SetPeerReadiness(func(context.Context, string) (bool, string, error) {
		return false, "", errors.New("dial tcp: connection refused")
	})

	host := corrosion.HostRecord{Name: "host-b", Address: "127.0.0.1", GRPCPort: 1}
	for i := 0; i < suspectThreshold; i++ {
		c.checkHost(ctx, host)
	}

	rows, err := db.Query(ctx,
		`SELECT status FROM host_health WHERE observer = ? AND target = ?`, "host-a", "host-b")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row, got %d", len(rows))
	}
	if got := rows[0].String("status"); got != "suspect" {
		t.Errorf("status = %q, want suspect — an RPC that never completed is unreachable, not unready", got)
	}
}

// A peer that answers the readiness probe affirmatively is still healthy. Without
// this, "report every peer unready" would pass the two tests above.
func TestCheckHost_ReadyPeerStaysHealthy(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	addr, port := healthyPeer(t)
	c := probingChecker(t, db)
	c.SetPeerReadiness(func(context.Context, string) (bool, string, error) {
		return true, "", nil
	})

	c.checkHost(ctx, corrosion.HostRecord{Name: "host-b", Address: addr, GRPCPort: port})

	rows, err := db.Query(ctx,
		`SELECT status, consecutive_failures FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-b")
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 host_health row, got %d", len(rows))
	}
	if got := rows[0].String("status"); got != "healthy" {
		t.Errorf("status = %q, want healthy", got)
	}
	if got := rows[0].Int("consecutive_failures"); got != 0 {
		t.Errorf("consecutive_failures = %d, want 0", got)
	}
}

// The readiness prober is asked about the peer by NAME. A prober handed the
// wrong name answers about the wrong daemon, which is how a wedged node keeps a
// healthy row while some other node's answer is recorded against it.
func TestCheckHost_ReadinessIsAskedAboutTheProbedPeer(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	addr, port := healthyPeer(t)
	c := probingChecker(t, db)
	var asked []string
	c.SetPeerReadiness(func(_ context.Context, host string) (bool, string, error) {
		asked = append(asked, host)
		return true, "", nil
	})

	c.checkHost(ctx, corrosion.HostRecord{Name: "host-b", Address: addr, GRPCPort: port})

	if len(asked) != 1 || asked[0] != "host-b" {
		t.Errorf("readiness prober asked about %v, want [host-b]", asked)
	}
}

// A run of unready answers is not a run of silence. Each of those probes
// reached the peer and got an answer, so none of them is evidence toward
// "suspect" — the verdict fencing quorum counts. The first probe that goes
// unanswered afterwards starts the silence count at one, and the peer has to
// miss suspectThreshold in a row like any other before it can be suspect.
//
// Carrying the unready count over let a single dropped packet after a long
// unready stretch jump straight to suspect with consecutive_failures well past
// offlineThreshold: fence-eligible on one miss.
func TestCheckHost_UnreadyAnswersDoNotCountTowardSuspect(t *testing.T) {
	db := testCheckHostDB(t)
	ctx := context.Background()
	c := probingChecker(t, db)
	answer := func(context.Context, string) (bool, string, error) {
		return false, "database read timed out", nil
	}
	c.SetPeerReadiness(func(ctx context.Context, h string) (bool, string, error) { return answer(ctx, h) })
	host := corrosion.HostRecord{Name: "host-b", Address: "127.0.0.1", GRPCPort: 1}

	for i := 0; i < 20; i++ {
		c.checkHost(ctx, host)
	}
	answer = func(context.Context, string) (bool, string, error) {
		return false, "", errors.New("context deadline exceeded")
	}
	c.checkHost(ctx, host)

	rows, err := db.Query(ctx,
		`SELECT status, consecutive_failures FROM host_health WHERE observer = ? AND target = ?`,
		"host-a", "host-b")
	if err != nil || len(rows) != 1 {
		t.Fatalf("query: rows=%d err=%v", len(rows), err)
	}
	if got := rows[0].String("status"); got == "suspect" {
		t.Fatalf("one unanswered probe after 20 unready answers made the peer suspect (consecutive_failures=%d); "+
			"it needs %d unanswered probes in a row", rows[0].Int("consecutive_failures"), suspectThreshold)
	}
	if got := rows[0].Int("consecutive_failures"); got != 1 {
		t.Errorf("consecutive_failures = %d after the first unanswered probe, want 1", got)
	}
}
