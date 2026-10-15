package grpcapi

import (
	"context"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// sweepServer is a server whose failover lease is held by holder (this host
// when holder is empty), with a
// release gate g and two probes: firewall_log's data present, and
// firewall_tag_groups' absent. probed counts probe calls.
func sweepServer(t *testing.T, holder string) (*Server, *relGate, []releaseUseProbe, *atomic.Int32) {
	t.Helper()
	s := testServer(t)
	s.db.SetClusterPolicyGate(func() bool { return true })
	g := &relGate{t: t}
	s.SetReleaseFeatureGate(g)
	if holder == "" {
		holder = s.hostName
	}
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	if err := s.db.Execute(context.Background(),
		`INSERT INTO leader_election (key, holder, expires_at, updated_at) VALUES (?, ?, ?, ?)`,
		corrosion.LeaseKeyFailover, holder, exp, exp); err != nil {
		t.Fatal(err)
	}
	var probed atomic.Int32
	probes := []releaseUseProbe{
		{feature: capabilities.FeatureFirewallLog, present: func(context.Context, *corrosion.Client) (bool, error) {
			probed.Add(1)
			return true, nil
		}},
		{feature: capabilities.FeatureFirewallTagGroups, present: func(context.Context, *corrosion.Client) (bool, error) {
			probed.Add(1)
			return false, nil
		}},
	}
	return s, g, probes, &probed
}

// runSweepFor runs the sweep loop at interval every for d, then stops it.
func runSweepFor(s *Server, probes []releaseUseProbe, every, d time.Duration) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runReleaseUseSweep(ctx, every, probes)
	}()
	time.Sleep(d)
	cancel()
	<-done
}

// After the latch, the lease holder records the use of a feature whose data
// is present and whose use is not recorded; a feature with no data is not
// recorded (DECISION 0-F). The loop runs a sweep within one interval.
//
// Mutations: skip the data check (record every unrecorded feature) — the tag
// feature is recorded, red; never run the loop — the loop records nothing,
// red.
func TestReleaseUseSweep_HolderRecordsUseFoundInData(t *testing.T) {
	s, g, probes, _ := sweepServer(t, "")
	g.open = true
	s.sweepReleaseUses(context.Background(), probes)
	if !slices.Equal(g.used, []capabilities.Feature{capabilities.FeatureFirewallLog}) {
		t.Errorf("uses recorded by one sweep = %v, want firewall_log only (its data is present)", g.used)
	}

	// The loop: a sweep within one interval. The window is many intervals
	// long, so a loaded host still gets a tick in.
	s2, g2, probes2, _ := sweepServer(t, "")
	g2.open = true
	runSweepFor(s2, probes2, 20*time.Millisecond, 400*time.Millisecond)
	if len(g2.used) == 0 || slices.ContainsFunc(g2.used, func(f capabilities.Feature) bool { return f != capabilities.FeatureFirewallLog }) {
		t.Errorf("uses recorded by the loop = %v, want firewall_log only", g2.used)
	}
}

// A non-holder does nothing, and before the latch nothing runs: no gate is
// asked and no data is read.
//
// Mutations: drop the lease-holder check — the non-holder records, red; drop
// the latch check — the gate is asked before the latch, red.
func TestReleaseUseSweep_NonHolderAndPreLatchDoNothing(t *testing.T) {
	s, g, probes, probed := sweepServer(t, "another-host")
	g.open = true
	runSweepFor(s, probes, 20*time.Millisecond, 120*time.Millisecond)
	if g.calls != 0 || probed.Load() != 0 {
		t.Errorf("a non-holder asked the gate %d time(s) and read data %d time(s), want none", g.calls, probed.Load())
	}

	s2, g2, probes2, probed2 := sweepServer(t, "")
	runSweepFor(s2, probes2, 20*time.Millisecond, 120*time.Millisecond)
	if g2.calls != 0 || probed2.Load() != 0 {
		t.Errorf("before the latch the holder asked the gate %d time(s) and read data %d time(s), want none", g2.calls, probed2.Load())
	}
}

// A use already recorded is not recorded again.
//
// Mutation: drop the recorded check — the gate is asked, red.
func TestReleaseUseSweep_RecordedUseIsLeftAlone(t *testing.T) {
	s, g, probes, _ := sweepServer(t, "")
	ctx := context.Background()
	info, _ := capabilities.LookupFeature(capabilities.FeatureFirewallLog)
	if err := corrosion.RecordReleaseFeatureUse(ctx, s.db, info.Token, string(capabilities.FeatureFirewallLog), "h", true); err != nil {
		t.Fatal(err)
	}
	g.open = true
	s.sweepReleaseUses(ctx, probes)
	if g.calls != 0 {
		t.Errorf("a recorded use was recorded again: gate asked %d time(s) (%v)", g.calls, g.used)
	}
}
