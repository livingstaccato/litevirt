package health

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	confirm     func(host string) (bool, error)
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
		if e.confirm != nil {
			return e.confirm(host)
		}
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
	e.c.SetUnknownReleaseTokenObserver(func(peer, tok string) { seen = append(seen, tok) })
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

// TestUnknownReleaseToken_ObserverWiredLater (N7): a token seen before the
// observer is wired is not swallowed.
func TestUnknownReleaseToken_ObserverWiredLater(t *testing.T) {
	e := newRelEnv(t)
	e.c.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
		return append(capabilities.Supported(), "release_2099_01_v1"), time.Time{}, nil
	})
	e.c.CapabilityActive(context.Background(), capabilities.SplitBrainGateV1)
	var seen []string
	e.c.SetUnknownReleaseTokenObserver(func(peer, tok string) { seen = append(seen, peer+"/"+tok) })
	e.c.CapabilityActive(context.Background(), capabilities.ReleaseToken)
	if len(seen) != 1 || !strings.HasSuffix(seen[0], "/release_2099_01_v1") {
		t.Fatalf("observer saw %v, want one report of release_2099_01_v1", seen)
	}
}

// TestWithFeature_AckSetIncludesEveryVoter (N3): a voter in maintenance is not
// a replication recipient right now, but a later probation majority may ask it,
// so a first use waits for it too. A powered-off maintenance host that is not a
// voter does not block.
func TestWithFeature_AckSetIncludesEveryVoter(t *testing.T) {
	e := newRelEnv(t)
	gateHost(t, e.db, "host-c", "maintenance", "worker") // voter, in maintenance, not a member
	gateHost(t, e.db, "host-d", "maintenance", "worker") // not a voter, powered off
	e.c.SetVoterSetForTest(func(context.Context) (map[string]bool, error) {
		return map[string]bool{"host-a": true, "host-b": true, "host-c": true}, nil
	})
	var mu sync.Mutex
	asked := map[string]bool{}
	cHolds := false
	e.confirm = func(host string) (bool, error) {
		mu.Lock()
		defer mu.Unlock()
		asked[host] = true
		return host == "host-b" || (host == "host-c" && cHolds), nil
	}
	wrote, err := e.write(t, e.c, testFeature)
	if status.Code(err) != codes.Unavailable || wrote || !strings.Contains(err.Error(), "host-c") ||
		!strings.Contains(err.Error(), "lv cluster voter rm host-c") {
		t.Fatalf("first use with voter host-c not holding the record: wrote=%v err=%v, want Unavailable naming "+
			"host-c and `lv cluster voter rm host-c` as the way out if it is gone", wrote, err)
	}
	mu.Lock()
	if asked["host-d"] {
		t.Error("host-d, a powered-off non-voter, was asked to acknowledge")
	}
	cHolds = true
	mu.Unlock()
	if wrote, err := e.write(t, e.c, testFeature); err != nil || !wrote {
		t.Fatalf("once host-c holds it: wrote=%v err=%v", wrote, err)
	}
}

// TestWithFeature_ProbationHostIsNotCalledGone (m1): a voter that has not
// acknowledged because it is in release probation — it refuses every push
// until it lifts — is a live host. The refusal says it is in probation and
// points at the status command; it does not tell the operator to remove it
// from the voter set.
func TestWithFeature_ProbationHostIsNotCalledGone(t *testing.T) {
	e := newRelEnv(t)
	gateHost(t, e.db, "host-c", "active", "worker")
	e.db.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: "host-b"}, {Name: "host-c"}} })
	e.c.SetVoterSetForTest(func(context.Context) (map[string]bool, error) {
		return map[string]bool{"host-a": true, "host-b": true, "host-c": true}, nil
	})
	e.confirm = func(host string) (bool, error) {
		if host == "host-c" {
			return false, fmt.Errorf("%s: %w", host, corrosion.ErrReleaseProbation)
		}
		return true, nil
	}
	wrote, err := e.write(t, e.c, testFeature)
	if status.Code(err) != codes.Unavailable || wrote {
		t.Fatalf("first use with host-c in probation: wrote=%v err=%v, want Unavailable", wrote, err)
	}
	if !strings.Contains(err.Error(), "host-c is in release probation") ||
		!strings.Contains(err.Error(), "`lv cluster upgrade-status`") ||
		strings.Contains(err.Error(), "voter rm host-c") {
		t.Fatalf("refusal = %v, want host-c named as in release probation with the status command, "+
			"and no `lv cluster voter rm host-c`", err)
	}
}

// TestWithFeature_AcksAreAskedInParallel (N10): one slow recipient does not
// add its delay to every other's.
func TestWithFeature_AcksAreAskedInParallel(t *testing.T) {
	e := newRelEnv(t)
	for _, h := range []string{"host-c", "host-d", "host-e"} {
		gateHost(t, e.db, h, "active", "worker")
	}
	e.db.SetMembersForTests(func() []corrosion.PeerInfo {
		return []corrosion.PeerInfo{{Name: "host-b"}, {Name: "host-c"}, {Name: "host-d"}, {Name: "host-e"}}
	})
	e.confirm = func(string) (bool, error) {
		time.Sleep(150 * time.Millisecond)
		return true, nil
	}
	start := time.Now()
	if _, err := e.write(t, e.c, testFeature); err != nil {
		t.Fatalf("WithFeature: %v", err)
	}
	if d := time.Since(start); d > 450*time.Millisecond {
		t.Fatalf("four 150ms acknowledgements took %v: asked one at a time", d)
	}
}

// TestWithFeature_RefusalNamesTheLaggingHosts (UX 1): a feature refused
// mid-upgrade says which hosts hold the release back, on which build, and where
// to look — so it never reads as a broken feature.
func TestWithFeature_RefusalNamesTheLaggingHosts(t *testing.T) {
	e := newRelEnv(t)
	if err := corrosion.UpdateHostVersion(context.Background(), e.db, "host-b", "1.9.0"); err != nil {
		t.Fatal(err)
	}
	e.bAdvertises.Store(false)
	_, err := e.write(t, e.c, testFeature)
	for _, want := range []string{"host-b (1.9.0)", "lv cluster upgrade-status"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %v does not contain %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "host-a") {
		t.Fatalf("refusal %v names this host, which is on the release", err)
	}
}

// TestFeatureAvailable_ReadsTheLatchWithoutAsking (m7): a caller that falls
// back rather than fails asks whether a feature can be used at all without
// any peer being pinged: the feature's token has latched durably here. It is a
// hint, never a grant: the write still goes through WithFeature.
func TestFeatureAvailable_ReadsTheLatchWithoutAsking(t *testing.T) {
	e := newRelEnv(t)
	var pings atomic.Int32
	e.c.SetPeerPinger(func(_ context.Context, host string) ([]string, time.Time, error) {
		pings.Add(1)
		return capabilities.Supported(), time.Time{}, nil
	})
	if e.c.FeatureAvailable(testFeature) || pings.Load() != 0 {
		t.Fatalf("before the latch: available=%v pings=%d, want false and no ping", e.c.FeatureAvailable(testFeature), pings.Load())
	}
	if !e.c.Enforced(context.Background(), capabilities.ReleaseToken) || !e.c.DurablyLatched(capabilities.ReleaseToken) {
		t.Fatal("setup: the release token did not latch durably")
	}
	before := pings.Load()
	if !e.c.FeatureAvailable(testFeature) {
		t.Fatal("not available once the release token latched durably")
	}
	if pings.Load() != before {
		t.Fatalf("the availability read pinged %d peer(s)", pings.Load()-before)
	}
	if e.c.FeatureAvailable("undeclared") {
		t.Fatal("an undeclared feature reported available")
	}
	e2 := newRelEnv(t)
	e2.c.SetActivationMarker("")
	e2.c.Enforced(context.Background(), capabilities.ReleaseToken)
	if e2.c.FeatureAvailable(testFeature) {
		t.Fatal("available on a latch held only in memory")
	}
}

// TestWithFeature_RefusalTextIsExact (UX 1; lab 1 could not try it live, since
// no gated action exists on this branch): the whole operator-facing refusal,
// word for word — each lagging host with its build version, or unreachable,
// and the pointer to the status command at the end.
func TestWithFeature_RefusalTextIsExact(t *testing.T) {
	e := newRelEnv(t)
	ctx := context.Background()
	gateHost(t, e.db, "host-c", "active", "worker")
	if err := corrosion.UpdateHostVersion(ctx, e.db, "host-b", "1.9.0"); err != nil {
		t.Fatal(err)
	}
	e.c.SetPeerPinger(func(_ context.Context, host string) ([]string, time.Time, error) {
		switch host {
		case "host-b":
			return withoutToken(capabilities.Supported(), capabilities.ReleaseToken), time.Time{}, nil
		case "host-c":
			return nil, time.Time{}, errors.New("connection refused")
		}
		return capabilities.Supported(), time.Time{}, nil
	})
	_, err := e.write(t, e.c, testFeature)
	want := "the cluster upgrade must finish first (widgets needs " + capabilities.ReleaseToken + "): " +
		"not on this release yet: host-b (1.9.0), host-c (unreachable) — see `lv cluster upgrade-status`"
	if status.Code(err) != codes.FailedPrecondition || status.Convert(err).Message() != want {
		t.Fatalf("refusal = %v\nwant FailedPrecondition %q", err, want)
	}
}

// FeatureRefusal (the entry-node fail-fast): refuses with the release text,
// names the lagging host and ends with the upgrade-status pointer; passes once
// every host is on the release, driving the latch itself; and in neither case
// records a use.
//
// Mutations: make it write the use record — the state checks go red; make it
// return nil without checking the latch — the refusal case goes red; skip
// c.Enforced — the latch-driven pass goes red.
func TestFeatureRefusal_RefusesNamesLaggardsDrivesTheLatchAndRecordsNothing(t *testing.T) {
	e := newRelEnv(t)
	ctx := context.Background()
	if err := corrosion.UpdateHostVersion(ctx, e.db, "host-b", "1.9.0"); err != nil {
		t.Fatal(err)
	}
	e.bAdvertises.Store(false)
	err := e.c.FeatureRefusal(ctx, testFeature)
	if status.Code(err) != codes.FailedPrecondition ||
		!strings.Contains(err.Error(), "the cluster upgrade must finish first (widgets needs "+capabilities.ReleaseToken+")") ||
		!strings.Contains(err.Error(), "host-b (1.9.0)") || !strings.HasSuffix(err.Error(), "`lv cluster upgrade-status`") {
		t.Fatalf("refusal = %v", err)
	}
	if p, _ := e.state(t); p {
		t.Fatal("a refusal recorded a use")
	}
	// Every host upgraded; nothing has driven the latch yet.
	e.bAdvertises.Store(true)
	e.c = e.checker() // the negative ping answer is cached for a few seconds
	if e.c.FeatureAvailable(testFeature) {
		t.Fatal("the token latched before anything drove it")
	}
	if err := e.c.FeatureRefusal(ctx, testFeature); err != nil {
		t.Fatalf("after the roll: %v", err)
	}
	if !e.c.FeatureAvailable(testFeature) {
		t.Error("the entry check passed without latching the token")
	}
	if p, _ := e.state(t); p {
		t.Fatal("a passing entry check recorded a use")
	}
	if err := e.c.FeatureRefusal(ctx, "not_declared"); status.Code(err) != codes.Internal {
		t.Errorf("undeclared feature: %v, want Internal", err)
	}
}

// The refusal of a first use some host has not acknowledged carries "not yet
// acknowledged by": grpcapi's restore refusal (restoreHostAccessRefusal)
// recognises a lasting refusal by it and names --without-host-access there.
// Changing this text needs that check changed too.
func TestWithFeature_UnackedRefusalCarriesItsMarker(t *testing.T) {
	e := newRelEnv(t)
	e.bHolds.Store(false)
	_, err := e.write(t, e.c, testFeature)
	if status.Code(err) != codes.Unavailable || !strings.Contains(err.Error(), "not yet acknowledged by") {
		t.Fatalf("unacknowledged first use = %v; want Unavailable carrying \"not yet acknowledged by\"", err)
	}
}

func TestContinuityReleaseFirstUseClosed(t *testing.T) {
	for _, mode := range []string{"supported", "old-decoder", "missing-ack", "delayed-ack", "maintenance-voter", "missing-marker"} {
		t.Run(mode, func(t *testing.T) {
			db := testCheckHostDB(t)
			gateHost(t, db, "host-a", "active", "worker")
			state := "active"
			if mode == "maintenance-voter" {
				state = "maintenance"
			}
			gateHost(t, db, "host-b", state, "worker")
			db.SetMembersForTests(func() []corrosion.PeerInfo { return []corrosion.PeerInfo{{Name: "host-b"}} })
			db.SetClusterPolicyGate(func() bool { return true })
			c := NewChecker("host-a", "/unused", db)
			c.SetActivationMarker(ActivationMarkerBase(t.TempDir()))
			c.SetPeerPinger(func(context.Context, string) ([]string, time.Time, error) {
				caps := capabilities.Supported()
				if mode == "old-decoder" {
					caps = withoutToken(caps, capabilities.Release202702V1)
				}
				return caps, time.Time{}, nil
			})
			var confirmations atomic.Int32
			c.SetReleaseUseConfirmer(func(_ context.Context, host, token, feature string) (bool, error) {
				if token != capabilities.Release202702V1 || feature != string(capabilities.FeatureAutomationIdentityContinuity) {
					t.Error("wrong release boundary")
				}
				calls := confirmations.Add(1)
				if mode == "missing-ack" || mode == "maintenance-voter" {
					return false, nil
				}
				return mode != "delayed-ack" || calls > 1, nil
			})
			if mode == "maintenance-voter" {
				db.SetMembersForTests(func() []corrosion.PeerInfo { return nil })
				c.SetVoterSetForTest(func(context.Context) (map[string]bool, error) {
					return map[string]bool{"host-a": true, "host-b": true}, nil
				})
			}
			if mode == "missing-marker" {
				c.SetActivationMarker("")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 350*time.Millisecond)
			defer cancel()
			wrote := false
			err := c.WithFeature(ctx, capabilities.FeatureAutomationIdentityContinuity, func(_ context.Context, g capabilities.FeatureGrant) error {
				if err := g.Check(capabilities.FeatureAutomationIdentityContinuity); err != nil {
					return err
				}
				wrote = true
				return nil
			})
			positive := mode == "supported" || mode == "delayed-ack"
			if positive {
				if err != nil || !wrote {
					t.Fatal("complete first use refused", err)
				}
			} else if err == nil || wrote {
				t.Fatal("incomplete first use admitted")
			}
			if mode == "maintenance-voter" && confirmations.Load() == 0 {
				t.Fatal("maintenance voter omitted from ACK set")
			}
		})
	}
}
