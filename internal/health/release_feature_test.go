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

// relEnv is host-a in a two-host cluster. host-b advertises the release token
// while bAdvertises is true, and acknowledges holding a used record while
// bHolds is true.
type relEnv struct {
	c           *Checker
	db          *corrosion.Client
	dir         string
	bAdvertises atomic.Bool
	bHolds      atomic.Bool
	confirmed   atomic.Int32
}

func newRelEnv(t *testing.T) *relEnv {
	t.Helper()
	t.Cleanup(capabilities.OverrideFeaturesForTest(map[capabilities.Feature]capabilities.FeatureInfo{
		testFeature: {Token: capabilities.ReleaseToken, Description: "Widgets on every VM"},
	}))
	prev := releaseAckTimeout
	releaseAckTimeout = 300 * time.Millisecond
	t.Cleanup(func() { releaseAckTimeout = prev })
	e := &relEnv{db: testCheckHostDB(t), dir: t.TempDir()}
	gateHost(t, e.db, "host-a", "active", "worker")
	gateHost(t, e.db, "host-b", "active", "worker")
	e.db.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: "host-b"}} })
	e.db.SetClusterPolicyGate(func() bool { return true })
	e.bAdvertises.Store(true)
	e.bHolds.Store(true)
	e.c = e.checker()
	return e
}

// checker is a fresh Checker over the same database and marker directory: a
// restarted daemon.
func (e *relEnv) checker() *Checker {
	c := NewChecker("host-a", "/etc/litevirt/pki", e.db)
	c.SetPeerPinger(func(_ context.Context, host string) ([]string, time.Time, error) {
		if host == "host-b" && !e.bAdvertises.Load() {
			return withoutToken(capabilities.Supported(), capabilities.ReleaseToken), time.Time{}, nil
		}
		return capabilities.Supported(), time.Time{}, nil
	})
	c.SetReleaseUseConfirmer(func(_ context.Context, host, token, feature string) (bool, error) {
		e.confirmed.Add(1)
		return host == "host-b" && e.bHolds.Load(), nil
	})
	c.SetActivationMarker(ActivationMarkerBase(e.dir))
	return c
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

// write runs a feature write through the gate and reports whether it ran.
func (e *relEnv) write(t *testing.T, c *Checker, f capabilities.Feature) (bool, error) {
	t.Helper()
	wrote := false
	err := c.WithFeature(context.Background(), f, func(_ context.Context, g capabilities.FeatureGrant) error {
		if err := g.Check(f); err != nil {
			return err
		}
		wrote = true
		return nil
	})
	return wrote, err
}

func (e *relEnv) state(t *testing.T) (present, acked bool) {
	t.Helper()
	p, a, err := corrosion.ReleaseFeatureState(context.Background(), e.db, capabilities.ReleaseToken, string(testFeature))
	if err != nil {
		t.Fatalf("ReleaseFeatureState: %v", err)
	}
	return p, a
}

// ownRecords counts this node's replicated release-feature records.
func (e *relEnv) ownRecords(t *testing.T) int {
	t.Helper()
	rows, err := e.db.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	n := 0
	for _, r := range rows {
		if strings.Contains(r.String("stmts"), "release_feature/") {
			n++
		}
	}
	return n
}

// TestWithFeature_RefusedUntilLatched: while a host still runs the previous
// build the feature is refused with the operator-facing reason, the write does
// not run, and nothing is recorded.
func TestWithFeature_RefusedUntilLatched(t *testing.T) {
	e := newRelEnv(t)
	e.bAdvertises.Store(false)
	wrote, err := e.write(t, e.c, testFeature)
	want := "the cluster upgrade must finish first (widgets needs " + capabilities.ReleaseToken + ")"
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), want) || wrote {
		t.Fatalf("WithFeature before the latch: wrote=%v err=%v, want FailedPrecondition containing %q", wrote, err, want)
	}
	if p, _ := e.state(t); p {
		t.Fatal("a refused WithFeature recorded the feature as used")
	}
}

// TestWithFeature_RecordsAndAcksBeforeTheWrite (I1): the first use is recorded,
// acknowledged by every recipient, and marked acknowledged, all before the
// write runs; the marker carries the rollback rule.
func TestWithFeature_RecordsAndAcksBeforeTheWrite(t *testing.T) {
	e := newRelEnv(t)
	var atWrite [2]bool
	err := e.c.WithFeature(context.Background(), testFeature, func(context.Context, capabilities.FeatureGrant) error {
		atWrite[0], atWrite[1] = e.state(t)
		return nil
	})
	if err != nil {
		t.Fatalf("WithFeature on a latched cluster: %v", err)
	}
	if !atWrite[0] || !atWrite[1] {
		t.Fatalf("at the write: present=%v acked=%v, want the record present and acknowledged", atWrite[0], atWrite[1])
	}
	if e.confirmed.Load() == 0 {
		t.Fatal("no recipient was asked to acknowledge the record")
	}
	b, err := os.ReadFile(filepath.Join(e.dir, ActivationMarkerPrefix+"."+capabilities.ReleaseToken))
	if err != nil || !strings.Contains(string(b), "rollback: safe_if_unused") {
		t.Fatalf("release token marker = %q (err %v), want the safe_if_unused rule", b, err)
	}
	before := e.ownRecords(t)
	if _, err := e.write(t, e.c, testFeature); err != nil {
		t.Fatalf("second write: %v", err)
	}
	if got := e.ownRecords(t); got != before {
		t.Fatalf("a repeat use in the same process wrote %d more record(s)", got-before)
	}
}

// TestWithFeature_UnacknowledgedRefuses (I1): a recipient that has not
// acknowledged the record holds the write off, with Unavailable.
func TestWithFeature_UnacknowledgedRefuses(t *testing.T) {
	e := newRelEnv(t)
	e.bHolds.Store(false)
	wrote, err := e.write(t, e.c, testFeature)
	if status.Code(err) != codes.Unavailable || wrote {
		t.Fatalf("WithFeature with host-b not holding the record: wrote=%v err=%v, want Unavailable", wrote, err)
	}
	if !strings.Contains(err.Error(), "host-b") {
		t.Errorf("the refusal does not name the recipient that has not acknowledged: %v", err)
	}
	if _, acked := e.state(t); acked {
		t.Fatal("the record was marked acknowledged although host-b never acknowledged it")
	}
	// After a restart the unacknowledged record still has to be acknowledged.
	c2 := e.checker()
	if wrote, err := e.write(t, c2, testFeature); status.Code(err) != codes.Unavailable || wrote {
		t.Fatalf("restarted, record still unacknowledged: wrote=%v err=%v, want Unavailable", wrote, err)
	}
	e.bHolds.Store(true)
	if wrote, err := e.write(t, c2, testFeature); err != nil || !wrote {
		t.Fatalf("once host-b holds it: wrote=%v err=%v", wrote, err)
	}
}

// TestWithFeature_ReassertsItsOwnRecordOncePerProcess (C1 writer side): a node
// that finds another node's acknowledged record still puts its OWN record on
// its own stream before its first write, so no origin's feature data travels
// without a record ahead of it. It needs no acknowledgement for that.
func TestWithFeature_ReassertsItsOwnRecordOncePerProcess(t *testing.T) {
	e := newRelEnv(t)
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), e.db, capabilities.ReleaseToken,
		string(testFeature), "host-x", true); err != nil {
		t.Fatal(err)
	}
	e.bHolds.Store(false) // acknowledgement not needed for an acknowledged record
	before := e.ownRecords(t)
	var atWrite int
	err := e.c.WithFeature(context.Background(), testFeature, func(context.Context, capabilities.FeatureGrant) error {
		atWrite = e.ownRecords(t)
		return nil
	})
	if err != nil {
		t.Fatalf("WithFeature over an acknowledged record: %v", err)
	}
	if atWrite != before+1 {
		t.Fatalf("own records at the write = %d, want %d: this node's stream carries no record ahead of its data", atWrite, before+1)
	}
}

// TestWithFeature_RecordFailureRefuses: a use that cannot be recorded is a
// write that must not happen.
func TestWithFeature_RecordFailureRefuses(t *testing.T) {
	e := newRelEnv(t)
	e.db.SetWriteQuarantine(func() string { return "test quarantine" })
	wrote, err := e.write(t, e.c, testFeature)
	if err == nil || wrote || status.Code(err) == codes.OK || status.Code(err) == codes.Unknown {
		t.Fatalf("WithFeature under quarantine: wrote=%v err=%v, want a gRPC refusal", wrote, err)
	}
	e.db.SetWriteQuarantine(nil)
	e.db.SetClusterPolicyGate(func() bool { return false })
	if wrote, err := e.write(t, e.c, testFeature); status.Code(err) != codes.FailedPrecondition || wrote {
		t.Fatalf("WithFeature with the policy table gated: wrote=%v err=%v, want FailedPrecondition", wrote, err)
	}
	if p, _ := e.state(t); p {
		t.Fatal("a failed record left the feature marked used")
	}
}

// TestWithFeature_FirstUseReconfirmsEveryRecipient: a host rolled back after the
// latch holds every first use off.
func TestWithFeature_FirstUseReconfirmsEveryRecipient(t *testing.T) {
	e := newRelEnv(t)
	if !e.c.Enforced(context.Background(), capabilities.ReleaseToken) {
		t.Fatal("the release token did not latch on a uniform cluster")
	}
	e.bAdvertises.Store(false)
	wrote, err := e.write(t, e.c, testFeature)
	if status.Code(err) != codes.FailedPrecondition || wrote || !strings.Contains(err.Error(), "cluster upgrade must finish first") {
		t.Fatalf("first use with host-b rolled back: wrote=%v err=%v, want FailedPrecondition", wrote, err)
	}
	if p, _ := e.state(t); p {
		t.Fatal("the first use was recorded while a recipient could not keep the feature")
	}
}

// TestWithFeature_UndeclaredFeatureRefused: the set is closed.
func TestWithFeature_UndeclaredFeatureRefused(t *testing.T) {
	e := newRelEnv(t)
	if wrote, err := e.write(t, e.c, "not_declared"); status.Code(err) != codes.Internal || wrote {
		t.Fatalf("WithFeature for an undeclared feature: wrote=%v err=%v, want Internal", wrote, err)
	}
}

// TestWithFeature_RefusedUntilDurable: a latch held only in memory does not
// open a feature.
func TestWithFeature_RefusedUntilDurable(t *testing.T) {
	e := newRelEnv(t)
	e.c.SetActivationMarker("")
	if !e.c.Enforced(context.Background(), capabilities.ReleaseToken) || e.c.DurablyLatched(capabilities.ReleaseToken) {
		t.Fatal("setup: want the token latched in memory only")
	}
	if wrote, err := e.write(t, e.c, testFeature); status.Code(err) != codes.FailedPrecondition || wrote {
		t.Fatalf("WithFeature on an in-memory latch: wrote=%v err=%v, want FailedPrecondition", wrote, err)
	}
	if p, _ := e.state(t); p {
		t.Fatal("a use was recorded under a latch that does not survive a restart")
	}
}

// TestWithFeature_WriteErrorIsReturned: the grant does not swallow the write's
// own failure.
func TestWithFeature_WriteErrorIsReturned(t *testing.T) {
	e := newRelEnv(t)
	boom := status.Error(codes.Aborted, "boom")
	err := e.c.WithFeature(context.Background(), testFeature, func(context.Context, capabilities.FeatureGrant) error { return boom })
	if err != boom {
		t.Fatalf("WithFeature = %v, want the write's error", err)
	}
}

// TestUnknownReleaseTokenFromAPeerIsReported (C1): a peer advertising a release
// token this build does not know is how a node that has no marker — it was away
// while the token latched — learns it may be holding data it cannot keep.
func TestUnknownReleaseTokenFromAPeerIsReported(t *testing.T) {
	e := newRelEnv(t)
	var seen []string
	e.c.SetUnknownReleaseTokenObserver(func(tok string) { seen = append(seen, tok) })
	e.c.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return append(capabilities.Supported(), "release_2099_01_v1", "something_else_v9"), time.Time{}, nil
	})
	e.c.CapabilityActive(context.Background(), capabilities.SplitBrainGateV1)
	if len(seen) == 0 || seen[0] != "release_2099_01_v1" {
		t.Fatalf("observer saw %v, want release_2099_01_v1 only", seen)
	}
	for _, s := range seen {
		if s != "release_2099_01_v1" {
			t.Fatalf("observer saw %q, which is not an unknown release token", s)
		}
	}
}
