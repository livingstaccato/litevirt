// Fleet scenarios: an operator's `lv host fence-confirm` made during an outage
// in which the cluster never fenced the host (docs/migration-failover.md,
// "Resuming a recovery from a confirmation").
//
// This is the forced-reconfiguration flow of docs/design/recovery-claims.md
// §7.3 drill 6, found broken on the kvm003 lab (main-8d1e56dc): three of five
// voters are destroyed, so no fence quorum can form and no fence attempt runs.
// The operator confirms each lost host off — force-reconfigure demands it —
// which also records the hosts 'fenced', taking them off the fence path for
// good. The confirmation-resume path then refused every tick ("the newest
// fence attempt predates this outage"), because it resumes only on a fence the
// cluster itself ran for this outage, and there was none.
//
// A confirmation made during THIS outage now puts the host back on the fence
// path: the coordinator fences it afresh — its own attempt, under every gate the
// ordinary fence applies — and recovers from that. A confirmation older than
// the outage still authorises nothing.
package fleet

import (
	"context"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// seedFenceAttempt writes a fencing_log row for host at time at, on n only (n
// is the coordinator that reads it): a fence attempt from an earlier outage, as
// drill 3 left node-4's. InsertFenceLog stamps its own clock, so the row is
// written directly.
func seedFenceAttempt(t *testing.T, n *Node, host, id, method, result string, at time.Time) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		id, host, method, result, at.UTC().Format(time.RFC3339), "an earlier outage's fence"); err != nil {
		t.Fatalf("seed fence attempt %s: %v", id, err)
	}
}

// TestFleet_ConfirmationOfThisOutageFencesAfresh: voters a and b watch d fail
// without a break for two minutes; nothing has fenced d in this outage. An
// operator confirms d off. The lease holder must fence d itself, then recover
// its VM — whatever an earlier outage left in fencing_log.
//
//   - no-attempt: d was never fenced at all (drill 6's node-3 after a rebuild).
//   - old-partial: a failed attempt two days old (node-3's 09-29 row).
//   - old-fence-no-longer-stands: a successful SSH fence twenty minutes old,
//     from an outage d returned from (node-4's and node-5's rows).
//   - stale-confirmation: the confirmation predates the outage — d answered
//     after it and has been failing again for one minute, and the write of its
//     return was lost so it still reads 'fenced'. Nothing is fenced and nothing
//     moves: the confirmation attests to an earlier outage.
//
// Mutations: (1) drop the fresh-fence branch (confirmationFencesAfresh returns
// false) — the three positive arms go red, nothing is fenced, as on the lab;
// (2) drop the outage test on the confirmation (accept any confirmation newer
// than every attempt) — stale-confirmation goes red: d is fenced and its VM
// moves on a confirmation of an outage it recovered from.
func TestFleet_ConfirmationOfThisOutageFencesAfresh(t *testing.T) {
	for _, tc := range []struct {
		name      string
		seed      int64
		attempt   string // "", "partial" or "fenced"
		attemptAt time.Duration
		stale     bool
	}{
		{name: "no-attempt", seed: 3101},
		{name: "old-partial", seed: 3102, attempt: "partial", attemptAt: 48 * time.Hour},
		{name: "old-fence-no-longer-stands", seed: 3103, attempt: "fenced", attemptAt: 20 * time.Minute},
		{name: "stale-confirmation", seed: 3104, stale: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			c := New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: tc.seed})
			a, b, d := c.Nodes[0], c.Nodes[1], c.Nodes[2]
			vm := "vm-" + tc.name
			insertVM(t, a, vm, d.Name)
			c.WaitConverged(t, convergeTimeout)
			c.Kill(d)

			clock := NewVirtualClock(time.Now().UTC())
			cs := c.NewCoordinators(clock)
			// The operator confirms d off. FenceHost stamps the row with the
			// real clock, which the virtual one started from.
			if _, err := c.SelfClient(a).FenceHost(ctx,
				&pb.FenceHostRequest{Name: d.Name, Confirmed: true, ConfirmManualOnly: true}); err != nil {
				t.Fatalf("fence-confirm %s: %v", d.Name, err)
			}

			streak := streakSince(2 * time.Minute)
			if tc.stale {
				// d came back after the confirmation, and has been failing
				// again for one minute.
				clock.Advance(10 * time.Minute)
				streak = streakSince(time.Minute)
			}
			for _, o := range []*Node{a, b} {
				PublishHealth(t, o, d.Name, streak, clock.Now())
			}
			c.WaitConverged(t, convergeTimeout, a, b)
			// Seeded last, on a only: a's coordinator is the one that reads it.
			if tc.attempt != "" {
				method := "manual"
				if tc.attempt == "fenced" {
					method = "ssh"
				}
				seedFenceAttempt(t, a, d.Name, "earlier-"+tc.name, method, tc.attempt, clock.Now().Add(-tc.attemptAt))
			}

			for i := 0; i < 3; i++ {
				cs.Tick(ctx, a)
				clock.Advance(contentionPoll)
			}

			fencedD := 0
			for _, f := range cs.Fences() {
				if f.Target == d.Name {
					fencedD++
				}
			}
			moved := vmOn(t, a, vm).HostName != d.Name
			if tc.stale {
				if fencedD != 0 || moved {
					t.Fatalf("a confirmation older than the outage authorised a fence (%d) or a move (%v)", fencedD, moved)
				}
				return
			}
			if fencedD != 1 {
				t.Fatalf("the coordinator fenced %s %d times on a confirmation of this outage, want exactly 1 fresh fence", d.Name, fencedD)
			}
			if !moved {
				t.Fatalf("%s is still recorded on %s after the confirmation and a fresh fence", vm, d.Name)
			}
		})
	}
}
