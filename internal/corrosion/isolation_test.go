package corrosion

import (
	"context"
	"errors"
	"testing"
)

func seedHost(t *testing.T, c *Client, name string) {
	t.Helper()
	if err := InsertHost(context.Background(), c, HostRecord{
		Name: name, Address: "10.0.0.1", SSHUser: "root", CertSerial: "x",
	}); err != nil {
		t.Fatalf("seed host %s: %v", name, err)
	}
}

// The epoch is CLUSTER state about a host, written by a healthy peer: a node
// that cannot be trusted to replicate cannot be trusted to record (or clear)
// its own quarantine.
func TestIsolationEpochIsPeerWrittenAndMonotone(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedHost(t, c, "n1")
	seedHost(t, c, "n2")

	// A host may not isolate itself.
	if err := IsolateHost(ctx, c, "n1", "n1", IsolationManual); !errors.Is(err, ErrSelfIsolation) {
		t.Fatalf("self-isolation: err=%v, want ErrSelfIsolation", err)
	}
	// A made-up reason is refused — the reason drives operator surfaces.
	if err := IsolateHost(ctx, c, "n2", "n1", "because"); err == nil {
		t.Fatal("an unknown isolation reason must be refused")
	}
	if epoch, _, _ := HostIsolation(ctx, c, "n1"); epoch != 0 {
		t.Fatalf("refused isolations must not have landed: epoch=%d", epoch)
	}

	// A healthy peer records it.
	if err := IsolateHost(ctx, c, "n2", "n1", IsolationRolledBackLatch); err != nil {
		t.Fatalf("peer isolation: %v", err)
	}
	epoch, reason, err := HostIsolation(ctx, c, "n1")
	if err != nil || epoch != 1 || reason != IsolationRolledBackLatch {
		t.Fatalf("after isolation: epoch=%d reason=%q err=%v", epoch, reason, err)
	}

	// Re-observation is idempotent: the epoch does NOT climb on every sweep
	// (the detector runs continuously, so a fresh epoch per pass would make the
	// number meaningless and rewrite the row forever).
	if err := IsolateHost(ctx, c, "n2", "n1", IsolationRolledBackLatch); !errors.Is(err, ErrIsolationNotMonotone) {
		t.Fatalf("re-isolation: err=%v, want ErrIsolationNotMonotone", err)
	}
	if e, _, _ := HostIsolation(ctx, c, "n1"); e != 1 {
		t.Fatalf("re-observation moved the epoch: %d", e)
	}

	// A second isolated host takes the NEXT cluster-wide epoch, so the values
	// order isolations across the cluster.
	seedHost(t, c, "n3")
	if err := IsolateHost(ctx, c, "n2", "n3", IsolationManual); err != nil {
		t.Fatalf("isolate n3: %v", err)
	}
	if e, _, _ := HostIsolation(ctx, c, "n3"); e != 2 {
		t.Fatalf("second isolation epoch = %d, want 2", e)
	}
}

// Only a VERIFIED reseed clears the epoch, and only the epoch it reconciled:
// an isolation recorded while the reseed ran must not be swallowed by it.
func TestClearHostIsolationPinsTheEpoch(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	seedHost(t, c, "n1")
	seedHost(t, c, "n2")
	if err := IsolateHost(ctx, c, "n2", "n1", IsolationManual); err != nil {
		t.Fatalf("isolate: %v", err)
	}

	// Clearing a DIFFERENT epoch than the one recorded matches nothing.
	if err := ClearHostIsolation(ctx, c, "n1", 99); !errors.Is(err, ErrNoRowsAffected) {
		t.Fatalf("stale-epoch clear: err=%v, want ErrNoRowsAffected", err)
	}
	if e, _, _ := HostIsolation(ctx, c, "n1"); e != 1 {
		t.Fatalf("a stale clear must leave the isolation: epoch=%d", e)
	}

	// Clearing the reconciled epoch works.
	if err := ClearHostIsolation(ctx, c, "n1", 1); err != nil {
		t.Fatalf("clear: %v", err)
	}
	e, reason, _ := HostIsolation(ctx, c, "n1")
	if e != 0 || reason != "" {
		t.Fatalf("after clear: epoch=%d reason=%q", e, reason)
	}

	// A host that was never isolated is not isolated, and an unknown host is
	// NOT reported isolated — inventing one would refuse legitimate first
	// contact from a peer we haven't recorded yet.
	if e, _, _ := HostIsolation(ctx, c, "never-seen"); e != 0 {
		t.Fatalf("unknown host reported isolated: %d", e)
	}
}
