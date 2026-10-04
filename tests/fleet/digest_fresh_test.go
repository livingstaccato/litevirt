package fleet

import (
	"context"
	"testing"

	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// The verifying paths compare what every host holds NOW. A scheduled pass
// may use a peer's cached digest, but `lv cluster converge` — its full pass
// and its cross-host report — asks each peer for a scan. The difference shows
// only for a write the peer's cache cannot see: one made by another process.
func TestFleet_ConvergeReadsPeersFreshDigests(t *testing.T) {
	c := New(t, Options{Nodes: 2})
	a, b := c.Nodes[0], c.Nodes[1]
	b.DB.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: a.Name}} })
	ctx := context.Background()

	// Both sides agree, and a's digests are cached.
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("the catch-up pass did not run")
	}
	if _, err := a.DB.StateDigestCached(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.ExecOutOfProcessForTest(`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		VALUES ('out-of-process', 'h', 'y', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}

	// Precondition: a scheduled pass, reading a's cache, sees nothing to do.
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunSampledOnce(ctx) {
		t.Fatal("the scheduled pass did not run")
	}
	if hasStack(t, b, "out-of-process") {
		t.Fatal("precondition: the scheduled pass already saw the out-of-process write; the test cannot tell cached from fresh")
	}

	// The operator's full pass repairs it. (First: a fresh scan on a stores
	// what it finds, so any fresh read would refill a's cache.)
	if !corrosion.NewAntiEntropy(b.DB, b.PKIDir, 0).RunOnce(ctx) {
		t.Fatal("the full pass did not run")
	}
	if !hasStack(t, b, "out-of-process") {
		t.Fatal("the operator's full pass compared against the peer's cached digest and missed the write")
	}

	// A second write beneath a's hook, after its cache was refilled; the
	// cross-host report shows a's table as it is now.
	if _, err := a.DB.StateDigestCached(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.DB.ExecOutOfProcessForTest(`INSERT INTO stacks (name, compose_hash, compose_yaml, state, created_at, updated_at)
		VALUES ('out-of-process-2', 'h', 'y', 'active', '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')`); err != nil {
		t.Fatal(err)
	}
	report, err := c.SelfClient(b).GetClusterStateDigest(ctx, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _ := a.DB.StateDigest(ctx)
	var want string
	for _, d := range fresh {
		if d.Name == "stacks" {
			want = d.Hash
		}
	}
	found := false
	for _, h := range report.GetHosts() {
		if h.GetHostName() != a.Name {
			continue
		}
		for _, d := range h.GetTables() {
			if d.GetName() == "stacks" {
				found = true
				if d.GetHash() != want {
					t.Errorf("the converge report carries %s's cached stacks digest %s, not its current %s", a.Name, d.GetHash(), want)
				}
			}
		}
	}
	if !found {
		t.Fatalf("the converge report has no stacks digest for %s: %+v", a.Name, report)
	}
}
