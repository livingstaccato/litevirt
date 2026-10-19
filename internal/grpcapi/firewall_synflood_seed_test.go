package grpcapi

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// seedGate is a release-feature gate a test opens while a loop runs.
type seedGate struct {
	t     testing.TB
	mu    sync.Mutex
	open  bool
	calls int
}

func (g *seedGate) WithFeature(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
	g.mu.Lock()
	g.calls++
	open := g.open
	g.mu.Unlock()
	if !open {
		return status.Errorf(codes.FailedPrecondition, "the cluster upgrade must finish first (%s needs %s)", f, capabilities.ReleaseToken)
	}
	return write(ctx, capabilities.GrantForTest(g.t, f))
}

func (g *seedGate) FeatureAvailable(capabilities.Feature) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.open
}

func (g *seedGate) set(open bool) {
	g.mu.Lock()
	g.open = open
	g.mu.Unlock()
}

func (g *seedGate) refusals() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// The founder's SYN-flood seed has its own decision file and loop (spec
// §1.4, I-8). With the release latch delayed past the enforcement seed, the
// enforcement mode lands and its file goes while the SYN-flood file stays and
// nothing SYN-flood is written; once the latch forms, the seed lands once,
// stamped seedTS (below any operator write), audited, and only then is its
// file removed.
//
// Mutations: remove the decision file on a refusal (sharing the enforcement
// loop's lifetime) — the file is gone before the latch: red; stamp the seed
// NowTS — red.
func TestSeedFirewallSynfloodLoop_OutlastsTheLatch(t *testing.T) {
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	g := &seedGate{t: t}
	s.SetReleaseFeatureGate(g)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	enfPath, sfPath := filepath.Join(dir, "firewall-initial-mode"), filepath.Join(dir, "firewall-synflood-decision")
	for p, v := range map[string]string{enfPath: corrosion.FirewallEnforce + "\n", sfPath: corrosion.SynfloodOn + "\n"} {
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gone := func(p string) bool { _, err := os.Stat(p); return os.IsNotExist(err) }
	go s.SeedFirewallEnforcementLoop(ctx, 5*time.Millisecond, enfPath)
	done := make(chan struct{})
	go func() { s.SeedFirewallSynfloodLoop(ctx, 5*time.Millisecond, sfPath); close(done) }()

	waitUntil(t, "the enforcement seed", func() bool { return gone(enfPath) })
	waitUntil(t, "three refused SYN-flood seeds", func() bool { return g.refusals() >= 3 || gone(sfPath) })
	if gone(sfPath) {
		t.Fatal("the SYN-flood decision is gone before the release latch: it would never be recorded")
	}
	if _, recorded, err := corrosion.GetFirewallSynflood(ctx, s.db, ""); err != nil || recorded {
		t.Fatalf("a SYN-flood row before the latch (recorded %v, %v)", recorded, err)
	}

	g.set(true)
	waitUntil(t, "the SYN-flood decision to be consumed", func() bool {
		if !gone(sfPath) {
			return false
		}
		if _, recorded, _ := corrosion.GetFirewallSynflood(ctx, s.db, ""); !recorded {
			t.Fatal("the decision was removed before the policy was recorded")
		}
		return true
	})
	<-done
	p, recorded, err := corrosion.GetFirewallSynflood(ctx, s.db, "")
	if err != nil || !recorded || !p.On() || p.Rate != corrosion.SynfloodDefaultRate || p.Burst != corrosion.SynfloodDefaultBurst {
		t.Fatalf("seeded policy = %+v (recorded %v, %v), want on at the defaults", p, recorded, err)
	}
	if p.UpdatedAt != "0001-01-01T00:00:00.000000001Z" || p.SetBy != "litevirt (initial)" {
		t.Errorf("seed stamped %q by %q, want seedTS by litevirt (initial)", p.UpdatedAt, p.SetBy)
	}
	wantAudit(t, s, "firewall.synflood", "litevirt", "cluster", "before=unset after=on 200/1000 (initial, at genesis)")
}

// A joiner, a rejoiner or a host of a cluster that upgraded has no decision
// file: the loop returns at once and writes nothing, latch or not.
func TestSeedFirewallSynfloodLoop_NoDecisionWritesNothing(t *testing.T) {
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(&seedGate{t: t, open: true})
	done := make(chan struct{})
	go func() {
		s.SeedFirewallSynfloodLoop(context.Background(), time.Millisecond, filepath.Join(t.TempDir(), "firewall-synflood-decision"))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the loop did not return with no decision on disk")
	}
	if _, recorded, err := corrosion.GetFirewallSynflood(context.Background(), s.db, ""); err != nil || recorded {
		t.Errorf("no decision, yet a SYN-flood row (recorded %v, %v)", recorded, err)
	}
}

// A row recorded before the seed could land (an operator's off) ends the
// loop with its decision consumed and the row untouched.
func TestSeedFirewallSynfloodLoop_OperatorRowEndsIt(t *testing.T) {
	ctx := context.Background()
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	s.SetReleaseFeatureGate(&seedGate{t: t, open: true})
	if err := corrosion.SetFirewallSynflood(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureFirewallSynflood), "",
		corrosion.FirewallSynflood{Mode: corrosion.SynfloodOff}, "olga"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "firewall-synflood-decision")
	if err := os.WriteFile(path, []byte("on\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s.SeedFirewallSynfloodLoop(ctx, time.Millisecond, path)
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("the decision was not consumed: %v", err)
	}
	if p, _, err := corrosion.GetFirewallSynflood(ctx, s.db, ""); err != nil || p.On() || p.SetBy != "olga" {
		t.Errorf("the operator's off = %+v, %v; want it untouched", p, err)
	}
}
