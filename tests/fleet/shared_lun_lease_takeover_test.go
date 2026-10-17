package fleet

import (
	"context"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestFleet_SharedLUN_ASurvivorTakesTheScanOverWhenItsHolderGoes is lab 3's
// roll (build ac2139ed): the shared_lun scan runs under its own lease,
// shared_lun_detector, and that key was missing from the closed set peers
// answer GetLeaseTermHighWater for. Every peer refused the quorum high-water
// read a takeover needs, so once the term-1 holder went away no node could
// take the lease, the scan stopped, and five minutes later `lv health` sat at
// DEGRADED with no condition to say why.
//
// The first holder mints alone, as the lab's first node did in a cluster of
// one; every node then runs the scan as the daemon does, the holder dies, and
// a survivor must take the lease over, at the term after the holder's, and
// scan again.
//
// Mutation: drop LeaseKeySharedLUN from corrosion.leaseKeys (and its guard in
// AcquireLeaseWithTerm) and the survivors never take the lease.
func TestFleet_SharedLUN_ASurvivorTakesTheScanOverWhenItsHolderGoes(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 31})
	a, survivors := c.Nodes[0], c.Nodes[1:]
	runCheckers(t, c)

	const interval = time.Second

	// a holds the lease before the clearance exists, as the bootstrap node of
	// a cluster of one does.
	if held, term, err := corrosion.AcquireLeaseWithTerm(ctx, a.DB, corrosion.LeaseKeySharedLUN, a.Name,
		2*interval, time.Now()); err != nil || !held || term != 1 {
		t.Fatalf("%s: first acquire held=%v term=%d err=%v, want term 1", a.Name, held, term, err)
	}
	c.WaitConverged(t, convergeTimeout)
	wireMintClearance(c)

	// Each node's ticker runs at its own phase, as daemons started at
	// different moments do. Started together, both survivors would sweep for
	// the takeover in the same instant, both read the same high water and both
	// mint the next term — a contested term the contest machinery then retires.
	// That race is the lease's, for every key, and is not what this scenario
	// is about.
	stops := map[string]func(){}
	for _, n := range c.Nodes {
		nctx, cancel := context.WithCancel(ctx)
		done := make(chan struct{})
		stop := func() { cancel(); <-done }
		t.Cleanup(stop)
		stops[n.Name] = stop
		go func() { defer close(done); n.Server.RunSharedLUNDetector(nctx, interval) }()
		time.Sleep(interval / 3)
	}
	eventually(t, 20*time.Second, a.Name+" scans while it holds the lease", func() bool {
		return sharedLUNScannedBy(t, a, a.Name, time.Time{})
	})

	// a goes away: its scan stops and nobody can reach it.
	stops[a.Name]()
	c.Kill(a)
	gone := time.Now().UTC().Truncate(time.Second)

	var taker *Node
	eventually(t, 45*time.Second, "a survivor takes the shared_lun lease over and scans", func() bool {
		for _, n := range survivors {
			if sharedLUNScannedBy(t, n, n.Name, gone.Add(time.Second)) {
				taker = n
				return true
			}
		}
		return false
	})
	holder, _, err := corrosion.ReadLeaseRow(ctx, taker.DB, corrosion.LeaseKeySharedLUN)
	if err != nil || holder != taker.Name {
		t.Fatalf("%s scanned but its lease row names %q (err %v)", taker.Name, holder, err)
	}
	// The takeover is the term after a's last one. a's ledger is read now,
	// not at the kill: its scan has stopped, so the newest term it holds is
	// final. a usually took term 1, but setup that outlasts its 2s lease makes
	// a lapse-and-retake mint a later one, so the test does not assume it.
	held, err := corrosion.CurrentLeaseTerm(ctx, a.DB, corrosion.LeaseKeySharedLUN)
	if err != nil || held < 1 {
		t.Fatalf("%s: newest lease term %d (err %v), want the term it held", a.Name, held, err)
	}
	want := held + 1
	if term, err := corrosion.CurrentLeaseTerm(ctx, taker.DB, corrosion.LeaseKeySharedLUN); err != nil || term != want {
		t.Fatalf("%s: lease term %d (err %v), want the takeover at term %d (%s held %d)",
			taker.Name, term, err, want, a.Name, held)
	}

	// One claimant for the takeover term: the other survivor saw the
	// takeover rather than minting its own.
	for _, n := range survivors {
		if h, ok, err := corrosion.LeaseTermHolder(ctx, n.DB, corrosion.LeaseKeySharedLUN, want); err != nil || (ok && h != taker.Name) {
			t.Fatalf("%s records term %d for %q (err %v); %s took it — two holders", n.Name, want, h, err, taker.Name)
		}
	}

	// The scan keeps running, not one pass.
	first := sharedLUNLastScan(t, taker)
	eventually(t, 10*time.Second, "the survivor's scan runs again", func() bool {
		return sharedLUNLastScan(t, taker).After(first)
	})

	// And health names no shared_lun staleness. The other survivor runs the
	// read so it also proves the evaluator row reached a non-writer.
	reader := survivors[0]
	if reader == taker {
		reader = survivors[1]
	}
	// Quiesce the scans first: a row rewritten every second never compares
	// equal across replicas.
	for _, n := range survivors {
		stops[n.Name]()
	}
	c.WaitConverged(t, convergeTimeout, survivors...)
	resp, err := c.SelfClient(reader).GetClusterHealth(ctx, &pb.GetClusterHealthRequest{})
	if err != nil {
		t.Fatalf("GetClusterHealth on %s: %v", reader.Name, err)
	}
	for _, r := range resp.GetReasons() {
		if strings.Contains(r, "shared_lun") {
			t.Errorf("%s: health still degraded by the shared_lun scan after the takeover: %q", reader.Name, r)
		}
	}
	for _, e := range resp.GetEvaluators() {
		if e.GetEvaluator() != "shared_lun" {
			continue
		}
		at, err := time.Parse(time.RFC3339, e.GetLastScan())
		if err != nil || at.Before(gone) || e.GetReporter() == a.Name {
			t.Errorf("%s: shared_lun evaluator last scan %q by %s; want a scan by a survivor after %s went",
				reader.Name, e.GetLastScan(), e.GetReporter(), a.Name)
		}
	}
}

// sharedLUNLastScan is n's replica's shared_lun evaluator LastScan, zero when
// it has none.
func sharedLUNLastScan(t *testing.T, n *Node) time.Time {
	t.Helper()
	rows, err := corrosion.ListHealthEvaluatorStatus(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("%s: list evaluator status: %v", n.Name, err)
	}
	for _, r := range rows {
		if r.Evaluator == "shared_lun" {
			at, _ := time.Parse(time.RFC3339, r.LastScan)
			return at
		}
	}
	return time.Time{}
}

// sharedLUNScannedBy reports whether n's replica holds a shared_lun scan by
// reporter at or after since.
func sharedLUNScannedBy(t *testing.T, n *Node, reporter string, since time.Time) bool {
	t.Helper()
	rows, err := corrosion.ListHealthEvaluatorStatus(context.Background(), n.DB)
	if err != nil {
		t.Fatalf("%s: list evaluator status: %v", n.Name, err)
	}
	for _, r := range rows {
		if r.Evaluator != "shared_lun" || r.Reporter != reporter {
			continue
		}
		at, err := time.Parse(time.RFC3339, r.LastScan)
		return err == nil && !at.Before(since)
	}
	return false
}
