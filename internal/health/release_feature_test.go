package health

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

const testFeature capabilities.Feature = "widgets"

// releaseFeatureChecker is host-a in a two-host cluster whose peer host-b
// advertises the release token only while bAdvertises is true.
func releaseFeatureChecker(t *testing.T, bAdvertises *atomic.Bool) (*Checker, *corrosion.Client, string) {
	t.Helper()
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		testFeature: {Token: capabilities.ReleaseToken, Description: "Widgets on every VM"},
	}))
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")
	db.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: "host-b"}} })
	db.SetClusterPolicyGate(func() bool { return true })
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.SetPeerPinger(func(_ context.Context, host string) ([]string, time.Time, error) {
		if host == "host-b" && !bAdvertises.Load() {
			return withoutToken(capabilities.Supported(), capabilities.ReleaseToken), time.Time{}, nil
		}
		return capabilities.Supported(), time.Time{}, nil
	})
	dir := t.TempDir()
	c.SetActivationMarker(ActivationMarkerBase(dir))
	return c, db, dir
}

func withoutToken(toks []string, drop string) []string {
	var out []string
	for _, t := range toks {
		if t != drop {
			out = append(out, t)
		}
	}
	return out
}

func used(t *testing.T, db *corrosion.Client) bool {
	t.Helper()
	u, err := corrosion.ReleaseFeatureUsed(context.Background(), db, capabilities.ReleaseToken, string(testFeature))
	if err != nil {
		t.Fatalf("ReleaseFeatureUsed: %v", err)
	}
	return u
}

// TestRequireFeature_RefusedUntilLatched: while a host still runs the previous
// build the feature is refused with the operator-facing reason, and nothing is
// recorded.
func TestRequireFeature_RefusedUntilLatched(t *testing.T) {
	var b atomic.Bool
	c, db, _ := releaseFeatureChecker(t, &b)
	err := c.RequireFeature(context.Background(), testFeature)
	want := "the cluster upgrade must finish first (widgets needs " + capabilities.ReleaseToken + ")"
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) {
		t.Fatalf("RequireFeature before the latch: %v, want FailedPrecondition containing %q", err, want)
	}
	if used(t, db) {
		t.Fatal("a refused RequireFeature recorded the feature as used")
	}
}

// TestRequireFeature_RecordsUseBeforeReturning: once latched, the first use is
// recorded — durably, on the replication stream — before RequireFeature lets
// the caller write, and the marker carries the rollback rule.
func TestRequireFeature_RecordsUseBeforeReturning(t *testing.T) {
	var b atomic.Bool
	b.Store(true)
	c, db, dir := releaseFeatureChecker(t, &b)
	if err := c.RequireFeature(context.Background(), testFeature); err != nil {
		t.Fatalf("RequireFeature on a latched cluster: %v", err)
	}
	if !used(t, db) {
		t.Fatal("RequireFeature returned nil without recording the use: a rollback would find the " +
			"feature unused and keep running over its data")
	}
	if !c.DurablyLatched(capabilities.ReleaseToken) {
		t.Fatal("the release token is not durably latched after RequireFeature succeeded")
	}
	b2, err := os.ReadFile(filepath.Join(dir, ActivationMarkerPrefix+"."+capabilities.ReleaseToken))
	if err != nil || !strings.Contains(string(b2), "rollback: safe_if_unused") {
		t.Fatalf("release token marker = %q (err %v), want the safe_if_unused rule", b2, err)
	}
	// A second use writes nothing more.
	before := countLog(t, db)
	if err := c.RequireFeature(context.Background(), testFeature); err != nil {
		t.Fatalf("second RequireFeature: %v", err)
	}
	if got := countLog(t, db); got != before {
		t.Fatalf("a repeat use grew the mutation log from %d to %d", before, got)
	}
}

// TestRequireFeature_RecordFailureRefuses: a use that cannot be recorded is a
// write that must not happen.
func TestRequireFeature_RecordFailureRefuses(t *testing.T) {
	var b atomic.Bool
	b.Store(true)
	c, db, _ := releaseFeatureChecker(t, &b)
	db.SetWriteQuarantine(func() string { return "test quarantine" })
	err := c.RequireFeature(context.Background(), testFeature)
	if err == nil {
		t.Fatal("RequireFeature returned nil although the use could not be recorded")
	}
	if status.Code(err) == codes.OK || status.Code(err) == codes.Unknown {
		t.Fatalf("RequireFeature record failure: %v, want a gRPC status", err)
	}
	db.SetWriteQuarantine(nil)
	db.SetClusterPolicyGate(func() bool { return false })
	if err := c.RequireFeature(context.Background(), testFeature); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RequireFeature with the policy table gated: %v, want FailedPrecondition", err)
	}
	if used(t, db) {
		t.Fatal("a failed record left the feature marked used")
	}
}

// TestRequireFeature_FirstUseReconfirmsEveryRecipient: the latch is monotone,
// so a host rolled back after it formed does not unlatch it. A first use
// re-confirms, fresh, that every host this node replicates to still
// advertises the token; a rolled-back one holds the first use off, so no
// feature data is ever written while it is running.
func TestRequireFeature_FirstUseReconfirmsEveryRecipient(t *testing.T) {
	var b atomic.Bool
	b.Store(true)
	c, db, _ := releaseFeatureChecker(t, &b)
	if !c.Enforced(context.Background(), capabilities.ReleaseToken) {
		t.Fatal("the release token did not latch on a uniform cluster")
	}
	b.Store(false) // host-b rolled back after the latch
	err := c.RequireFeature(context.Background(), testFeature)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "cluster upgrade must finish first") {
		t.Fatalf("first use with host-b rolled back: %v, want FailedPrecondition", err)
	}
	if used(t, db) {
		t.Fatal("the first use was recorded while a recipient could not keep the feature")
	}
}

// TestRequireFeature_UndeclaredFeatureRefused: the set is closed.
func TestRequireFeature_UndeclaredFeatureRefused(t *testing.T) {
	var b atomic.Bool
	b.Store(true)
	c, _, _ := releaseFeatureChecker(t, &b)
	if err := c.RequireFeature(context.Background(), "not_declared"); status.Code(err) != codes.Internal {
		t.Fatalf("RequireFeature for a feature outside the declared set: %v, want Internal", err)
	}
}

func countLog(t *testing.T, db *corrosion.Client) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT seq FROM mutation_log`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	return len(rows)
}

// TestRequireFeature_RefusedUntilDurable: a latch held only in memory is lost
// on a restart, so it does not open a feature — the first use would otherwise
// be recorded under a latch the next boot does not remember.
func TestRequireFeature_RefusedUntilDurable(t *testing.T) {
	var b atomic.Bool
	b.Store(true)
	c, db, _ := releaseFeatureChecker(t, &b)
	c.SetActivationMarker("") // nothing can persist
	if !c.Enforced(context.Background(), capabilities.ReleaseToken) || c.DurablyLatched(capabilities.ReleaseToken) {
		t.Fatal("setup: want the token latched in memory only")
	}
	err := c.RequireFeature(context.Background(), testFeature)
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("RequireFeature on an in-memory latch: %v, want FailedPrecondition", err)
	}
	if used(t, db) {
		t.Fatal("a use was recorded under a latch that does not survive a restart")
	}
}
