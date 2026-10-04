// Fleet scenario: a host removed for good and added back under the same name
// is not fenced while it joins (kvm003 drill 6, main-8d1e56dc, finding B6).
//
// On the lab, `lv host add` of node-5 after `lv host rm --dead node-5` had the
// coordinator SSH-fence the new machine 0.4 s after its row was created
// ("quorum reached ... observers=2 quorum=2"), part-way through its setup. Two
// things made that happen:
//
//   - every observer's health checker kept node-5's failure count, keyed by
//     name, from before the removal: the removed host left the host table, so
//     it was never in the probe plan's candidates and never pruned. Its first
//     probe of the new machine published that count plus one, already past the
//     fence threshold, as a fresh observation;
//   - the admission records the host 'active' before its daemon has ever run,
//     so even with clean counts it is fence-eligible as soon as FailuresToFence
//     probes find nothing listening — which they will, for the length of the
//     setup.
//
// Real health checkers run on the observers here, probing over real TLS, and a
// real coordinator decides on what they publish.
package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cli"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// observedFailures is observer's own published failure count against target,
// with the row's time, or ok=false when it has none.
func observedFailures(n *Node, target string) (int, time.Time, bool) {
	rows, err := n.DB.Query(context.Background(),
		`SELECT consecutive_failures, updated_at FROM host_health WHERE observer = ? AND target = ? AND deleted_at IS NULL`,
		n.Name, target)
	if err != nil || len(rows) == 0 {
		return 0, time.Time{}, false
	}
	at, ok := corrosion.ParseUpdatedAt(rows[0].String("updated_at"))
	return rows[0].Int("consecutive_failures"), at, ok
}

// TestFleet_ReaddedHostIsNotFencedWhileItJoins: observers a, b and o watch d
// die long enough to build a failure count past the fence threshold. d is
// confirmed off and removed for good, then admitted again under its name with
// a fresh certificate, as `lv host add` does, and its daemon does not start
// for twice the time a fence takes to build. The coordinator must not fence it
// while it joins, and no observer counts a failure against it meanwhile: a
// joining host is not probed. Once the daemon's boot write records it
// 'active', a host that still does not answer is fenced as usual, but only
// after the observers have counted it down afresh, from zero.
//
// On the kvm003 lab (drill 6, main-b3368d7c) node-4 was SSH-fenced 2 s after
// `lv host add` returned: the observers had counted it down all through its
// setup, the coordinator skipped it only while it was joining, and the count
// was past the threshold the moment its boot write made it 'active'.
//
// Mutations: (1) probe a joining host again — the first verdict after the
// boot write carries the count from the join and d is fenced at once; (2) skip
// the 'joining' check in the coordinator together with (1), or (3) admit the
// host 'active' — d is fenced while it joins; (4) let a fence row from before
// d last turned active count (fenceRowCutoff) — the old machine's
// confirmation, a minute old, has the new one skipped as recently fenced.
func TestFleet_ReaddedHostIsNotFencedWhileItJoins(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	c := New(t, Options{Nodes: 4, IndependentReplicas: true, FaultSeed: 3301})
	a, b, o, d := c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3]
	observers := []*Node{a, b, o}
	c.WaitConverged(t, convergeTimeout)
	// host_membership_split_v1 is mandatory and latched on any current
	// cluster, the lab included: every node reads host_membership.
	for _, n := range c.Nodes {
		splitMembership(t, n)
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range observers {
		go health.NewChecker(n.Name, n.PKIDir, n.DB).Start(ctx)
	}

	// d dies, and stays dead long enough for a count past the threshold.
	d.Stop()
	c.Kill(d)
	before := health.FailuresToFence + 2
	eventually(t, 3*time.Minute, "every observer to count d failing past the fence threshold", func() bool {
		for _, n := range observers {
			if f, _, ok := observedFailures(n, d.Name); !ok || f < before {
				return false
			}
		}
		return true
	})

	// Confirmed off and removed for good. The confirmation is a minute old
	// when the machine is added again, well inside the five-minute window in
	// which the coordinator skips a host as recently fenced: it is the OLD
	// machine's, and must not hold back a fence of the new one once it is
	// active (failover.fenceRowCutoff). Written in fence-confirm's statement
	// shape, so it replicates.
	if err := a.DB.Execute(ctx,
		`INSERT OR IGNORE INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		"confirm-"+d.Name, d.Name, "manual", "manual-confirmed",
		time.Now().Add(-time.Minute).UTC().Format(time.RFC3339), "operator confirmation"); err != nil {
		t.Fatalf("fence-confirm %s: %v", d.Name, err)
	}
	if err := corrosion.UpdateHostState(ctx, a.DB, d.Name, "fenced"); err != nil {
		t.Fatalf("record %s fenced: %v", d.Name, err)
	}
	withOperatorPKI(t, a)
	if err := cli.HostRemoveDead(ctx, c.SelfClient(a), d.Name, false); err != nil {
		t.Fatalf("lv host rm --dead %s: %v", d.Name, err)
	}
	eventually(t, convergeTimeout, "the removal to reach every observer", func() bool {
		for _, n := range observers {
			if h, err := corrosion.GetHost(ctx, n.DB, d.Name); err != nil || h != nil {
				return false
			}
		}
		return true
	})
	// Two probe cycles with d out of the host table.
	time.Sleep(2 * health.ProbeInterval)

	// The lease holder's coordinator, polling on the real clock its observers
	// stamp their verdicts with.
	var mu sync.Mutex
	var fencedAt []time.Time
	coord := failover.NewCoordinator(a.Name, a.DB)
	coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		if h.Name == d.Name {
			mu.Lock()
			fencedAt = append(fencedAt, time.Now())
			mu.Unlock()
		}
		return fence.Result{Method: "fleet-test", Success: true}
	})
	fences := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(fencedAt)
	}
	go func() {
		tk := time.NewTicker(250 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				coord.RunOnce(ctx)
			}
		}
	}()

	// `lv host add`: admitted under its old name with a fresh certificate.
	// Its daemon never starts, and nothing listens where it is recorded.
	admitted := time.Now()
	if _, err := c.SelfClient(a).AdmitHost(ctx, &pb.AdmitHostRequest{
		Name: d.Name, Address: d.Address, CertSerial: "0a0b0c0d0e0f",
	}); err != nil {
		t.Fatalf("admit %s again: %v", d.Name, err)
	}

	// It joins for twice the time a fence takes to build, and no observer
	// counts a failure against it meanwhile: there is nothing to probe yet,
	// and a count built now would be past the threshold the moment its boot
	// write made it 'active'.
	joinedFor := 2 * health.FailuresToFence * health.ProbeInterval
	for deadline := admitted.Add(joinedFor); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		for _, n := range observers {
			if f, at, ok := observedFailures(n, d.Name); ok && at.After(admitted) && f > 0 {
				t.Fatalf("%s counted %d failure(s) against %s while it was joining", n.Name, f, d.Name)
			}
		}
	}
	if n := fences(); n != 0 {
		t.Fatalf("the coordinator fenced %s %d times while it was joining", d.Name, n)
	}

	// The daemon's boot write, which records it 'active'. It still does not
	// answer, so it is now a failed host like any other: fenced, but only once
	// the observers have counted it down from zero. A probe cycle can begin
	// at any moment after the boot write, so FailuresToFence failures span at
	// least FailuresToFence-1 intervals.
	booted := time.Now()
	if err := corrosion.UpdateHostStartup(ctx, a.DB, d.Name, "active", "", 0, 0, 0, false); err != nil {
		t.Fatalf("boot write: %v", err)
	}
	eventually(t, convergeTimeout, "the coordinator to fence the booted host that does not answer", func() bool {
		return fences() > 0
	})
	mu.Lock()
	first := fencedAt[0]
	mu.Unlock()
	if grace := time.Duration(health.FailuresToFence-1) * health.ProbeInterval; first.Sub(booted) < grace {
		t.Fatalf("%s was fenced %s after its boot write made it active, inside the %s its observers need "+
			"to count it down afresh: the count built while it joined carried over", d.Name,
			first.Sub(booted).Round(time.Millisecond), grace)
	}
}
