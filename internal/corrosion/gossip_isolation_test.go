package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func isolationClient(t *testing.T) *Client {
	t.Helper()
	c := newPruneTestClient(t)
	c.hostName = "node-3"
	return c
}

func isolationRow(t *testing.T, c *Client) (HealthCondition, bool) {
	t.Helper()
	row, ok, err := GetHealthCondition(context.Background(), c, gossipEvaluator, condGossipIsolated, "host", "node-3")
	if err != nil {
		t.Fatalf("GetHealthCondition: %v", err)
	}
	return row, ok
}

// isolatedRejoiner is a rejoiner for a node that sees nobody and cannot reach
// any of its targets — the "joined 0 of N" state.
func isolatedRejoiner() *rejoiner {
	return &rejoiner{
		peerCount: func() int { return 0 },
		targets:   func() []string { return []string{"10.0.0.1", "10.0.0.2"} },
		join:      func([]string) (int, error) { return 0, errors.New("dial tcp 10.0.0.1:7946: i/o timeout") },
	}
}

func healthyRejoiner() *rejoiner {
	return &rejoiner{
		peerCount: func() int { return 2 },
		targets:   func() []string { return []string{"10.0.0.1", "10.0.0.2"} },
		join:      func([]string) (int, error) { return 0, errors.New("must not dial") },
	}
}

func reporter(c *Client) *isolationReporter {
	return &isolationReporter{c: c, host: c.hostName, now: time.Now}
}

// A node that can see nobody and cannot re-join says so in `lv health`, not
// only in its journal.
//
// "joined 0 of N" was a log line. A log line is a finding only for somebody
// already reading that node's journal, and the node that has lost every peer is
// exactly the one nobody is looking at: its peers see it as a suspect host,
// which reads as "that machine is down", not "that machine is up and alone".
func TestMembershipTick_AnIsolatedNodeRecordsACondition(t *testing.T) {
	c := isolationClient(t)
	rep := reporter(c)

	c.membershipTick(context.Background(), isolatedRejoiner(), rep)

	row, ok := isolationRow(t, c)
	if !ok {
		t.Fatal("no gossip_isolated condition after a failed re-join with no visible peers")
	}
	if row.Lifecycle == ConditionResolved {
		t.Errorf("lifecycle = %q, want an open condition", row.Lifecycle)
	}
	if row.SubjectKind != "host" || row.SubjectID != "node-3" {
		t.Errorf("subject = %s/%s, want host/node-3 — a per-host finding keyed on anything shared "+
			"would have every node writing one row under LWW", row.SubjectKind, row.SubjectID)
	}
	if !strings.Contains(row.Evidence, "i/o timeout") {
		t.Errorf("evidence %q does not carry the join error an operator needs", row.Evidence)
	}
}

// A second consecutive isolated pass confirms it, the same observe→confirm step
// every other evaluator uses. One pass could be a restart racing its seeds.
func TestMembershipTick_ASecondIsolatedPassConfirms(t *testing.T) {
	c := isolationClient(t)
	rep := reporter(c)

	c.membershipTick(context.Background(), isolatedRejoiner(), rep)
	if row, _ := isolationRow(t, c); row.Lifecycle != ConditionObserved {
		t.Fatalf("after one pass lifecycle = %q, want observed", row.Lifecycle)
	}
	c.membershipTick(context.Background(), isolatedRejoiner(), rep)

	row, _ := isolationRow(t, c)
	if row.Lifecycle != ConditionConfirmed {
		t.Errorf("after two isolated passes lifecycle = %q, want confirmed", row.Lifecycle)
	}
}

// Seeing peers again resolves it on the first pass. Unlike most evaluators this
// needs no run of clean passes: visible peers are positive evidence of
// membership, not an absence of evidence of isolation.
func TestMembershipTick_SeeingPeersAgainResolves(t *testing.T) {
	c := isolationClient(t)
	rep := reporter(c)
	c.membershipTick(context.Background(), isolatedRejoiner(), rep)
	c.membershipTick(context.Background(), isolatedRejoiner(), rep)

	c.membershipTick(context.Background(), healthyRejoiner(), rep)

	row, ok := isolationRow(t, c)
	if !ok || row.Lifecycle != ConditionResolved {
		t.Errorf("after peers reappeared lifecycle = %q (ok=%v), want resolved", row.Lifecycle, ok)
	}
}

// A successful re-join resolves it too — the pass that ends the isolation is
// itself the evidence.
func TestMembershipTick_ASuccessfulRejoinResolves(t *testing.T) {
	c := isolationClient(t)
	rep := reporter(c)
	c.membershipTick(context.Background(), isolatedRejoiner(), rep)

	rejoined := isolatedRejoiner()
	rejoined.join = func([]string) (int, error) { return 2, nil }
	c.membershipTick(context.Background(), rejoined, rep)

	if row, _ := isolationRow(t, c); row.Lifecycle != ConditionResolved {
		t.Errorf("after a successful re-join lifecycle = %q, want resolved", row.Lifecycle)
	}
}

// A condition left open by a PREVIOUS process is still resolved. The daemon
// restart that is the traditional cure for this wedge would otherwise leave a
// confirmed isolation on record forever, because the new process has no memory
// of having reported it.
func TestMembershipTick_ResolvesAConditionAnEarlierProcessLeftOpen(t *testing.T) {
	c := isolationClient(t)
	reporter(c).report(context.Background(), true, errors.New("earlier run"))
	reporter(c).report(context.Background(), true, errors.New("earlier run"))

	c.membershipTick(context.Background(), healthyRejoiner(), reporter(c)) // fresh reporter = restarted daemon

	if row, _ := isolationRow(t, c); row.Lifecycle != ConditionResolved {
		t.Errorf("a condition from an earlier process is still %q after this node saw peers", row.Lifecycle)
	}
}

// A healthy node writes nothing, pass after pass. A row per node per 30 s would
// be pure replication traffic for a finding that is not there.
func TestMembershipTick_AHealthyNodeWritesNothing(t *testing.T) {
	c := isolationClient(t)
	rep := reporter(c)

	for i := 0; i < 3; i++ {
		c.membershipTick(context.Background(), healthyRejoiner(), rep)
	}

	if _, ok := isolationRow(t, c); ok {
		t.Error("a node that always saw its peers wrote a gossip_isolated row")
	}
}

// A single-node cluster with no seeds has nobody to be isolated from.
func TestMembershipTick_ASingleNodeClusterIsNotIsolated(t *testing.T) {
	c := isolationClient(t)
	alone := &rejoiner{
		peerCount: func() int { return 0 },
		targets:   func() []string { return nil },
		join:      func([]string) (int, error) { return 0, errors.New("must not dial") },
	}

	c.membershipTick(context.Background(), alone, reporter(c))

	if _, ok := isolationRow(t, c); ok {
		t.Error("a single-node cluster was reported as isolated")
	}
}
