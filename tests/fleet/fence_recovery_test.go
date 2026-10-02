// Fleet scenarios: a successor resuming a recovery from a fence that a dead
// leader recorded (docs/migration-failover.md, "Resuming a recovery from a
// recorded fence"; colonelpanik/litevirt#252).
//
// Every arm uses crashFleet: voters a, b, c, a non-voting leader x and the dead
// owner d holding vm. x fences d and dies at its first claim RPC, once its
// fence has reached every voter, so the recovery is left to a — which must
// either finish it exactly once, from x's record and without fencing d again,
// or, where the record no longer stands, leave the workload where it is.
package fleet

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
)

// fenceSettled holds x's first claim RPC until every voter's replica records
// x's fence of the dead owner (the fencing_log row and the host's 'fenced'
// state), so a scenario about what a successor does with a dead leader's
// recorded fence is not also a race over whether the record got out. The row
// and the state travel in one entry, so a voter holds both or neither; the
// wait is for the push, not for an ordering between them.
type fenceSettled struct {
	voters []*Node
	host   string
	once   sync.Once
	ok     bool
}

func (f *fenceSettled) await() {
	f.once.Do(func() {
		ctx := context.Background()
		for deadline := time.Now().Add(convergeTimeout); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
			all := true
			for _, n := range f.voters {
				h, err := corrosion.GetHost(ctx, n.DB, f.host)
				rows, qerr := n.DB.Query(ctx, `SELECT 1 AS one FROM fencing_log WHERE host_name = ? AND result = 'fenced'`, f.host)
				if err != nil || qerr != nil || h == nil || h.State != "fenced" || len(rows) == 0 {
					all = false
					break
				}
			}
			if all {
				f.ok = true
				return
			}
		}
	})
}

// dieAtFirstClaim is x's claim script: hold x's first claim RPC until its fence
// has settled on every voter, then take x out of the cluster before anything
// it claims reaches a voter.
func dieAtFirstClaim(c *Cluster, x *Node, settled *fenceSettled) ClaimScript {
	var once sync.Once
	return func(m ClaimMsg) ClaimFate {
		if m.From != x.Name {
			return ClaimDefault
		}
		settled.await()
		once.Do(func() { c.Kill(x) })
		return ClaimDropRequest
	}
}

// deadLeaderFence runs x's fence of d with fr and kills x before its recovery
// gets anywhere. It returns the coordinators, the clock and a count of the
// fences every node other than x issues from here on.
func deadLeaderFence(t *testing.T, c *Cluster, voters []*Node, x, d *Node, fr fence.Result) (*Coordinators, *VirtualClock, *atomic.Int32) {
	t.Helper()
	ctx := context.Background()
	a := voters[0]
	settled := &fenceSettled{voters: voters, host: d.Name}
	c.SetClaimScript(dieAtFirstClaim(c, x, settled))

	clock := NewVirtualClock(time.Now().UTC())
	cs := c.NewCoordinators(clock)
	var refenced atomic.Int32
	cs.ByNode[x.Name].Gate = quorateGate{}
	cs.ByNode[x.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result { return fr })
	cs.ByNode[a.Name].Gate = quorateGate{}
	cs.ByNode[a.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		refenced.Add(1)
		return fence.Result{Method: "ipmi", Success: true}
	})

	cs.Tick(ctx, x)
	c.Crash(x)
	if !settled.ok {
		t.Fatalf("x's fence of %s never settled on every voter", d.Name)
	}
	if h, _ := corrosion.GetHost(ctx, a.DB, d.Name); h == nil || h.State != "fenced" {
		t.Fatalf("fixture: %s is %+v on %s after x's fence, want 'fenced'", d.Name, h, a.Name)
	}
	return cs, clock, &refenced
}

// streakSince is a consecutive_failures count whose run, at one probe per
// health.ProbeInterval, began at least d ago: an observer that has watched the
// host fail without a break for that long.
func streakSince(d time.Duration) int {
	return int(d/health.ProbeInterval) + health.FailuresToFence + 1
}

// tickUntilDecided runs a's coordinator until it decides vm off d, or gives up.
func tickUntilDecided(ctx context.Context, t *testing.T, cs *Coordinators, a, d *Node, vm string, ticks int) *corrosion.VMRecord {
	t.Helper()
	for i := 0; i < ticks; i++ {
		cs.Tick(ctx, a)
		if vmr := vmOn(t, a, vm); vmr.PendingActionID != "" && vmr.HostName != d.Name {
			return vmr
		}
		cs.Clock.Advance(contentionPoll)
	}
	return nil
}

// TestFleet_FenceRecovery_SuccessorResumesFromADeadLeadersFence: a dead
// leader's fence of a host that is still down is authority for its successor
// to finish the recovery — once, from the record, without fencing the host
// again.
//
//   - verified-aged: x's IPMI power-off is older than the five-minute
//     recent-fence window when a takes over, and every voter has watched d fail
//     without a break since before it.
//   - best-effort: x's fence was an SSH power-off, which reports success
//     without verifying it. x itself would have rescheduled on it (no safe-fence
//     policy, no fence_requires_confirmation label), so its successor may too.
//
// Both left d 'fenced' with its workload on it until `lv host fence-confirm`.
//
// Mutation: make resumableFence demand a fence inside recentFenceWindow
// (verified-aged goes red), or a proof-grade one (best-effort goes red).
func TestFleet_FenceRecovery_SuccessorResumesFromADeadLeadersFence(t *testing.T) {
	for _, tc := range []struct {
		name string
		seed int64
		fr   fence.Result
		age  time.Duration // how long after x's fence a takes over
	}{
		{name: "verified-aged", seed: 2701, fr: fence.Result{Method: "ipmi", Success: true, Detail: "verified off"}, age: 7 * time.Minute},
		{name: "best-effort", seed: 2702, fr: fence.Result{Method: "ssh", Success: true, Detail: "poweroff sent"}, age: time.Minute},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vm := "vm-resume-" + tc.name
			c, a, b, cc, x, d := crashFleet(t, tc.seed, vm)
			voters := []*Node{a, b, cc}
			ledger := watchClaims(t, c)
			cs, clock, refenced := deadLeaderFence(t, c, voters, x, d, tc.fr)

			clock.Advance(tc.age)
			for _, n := range voters {
				PublishHealth(t, n, d.Name, streakSince(tc.age+time.Minute), clock.Now())
			}
			c.WaitConverged(t, convergeTimeout, voters...)

			decided := tickUntilDecided(ctx, t, cs, a, d, vm, 4)
			if decided == nil {
				t.Fatalf("the successor never resumed the recovery of %s from x's %s fence: %+v",
					d.Name, tc.fr.Method, vmOn(t, a, vm))
			}
			// More ticks change nothing: the recovery happened once.
			for i := 0; i < 3; i++ {
				clock.Advance(contentionPoll)
				cs.Tick(ctx, a)
			}
			if n := refenced.Load(); n != 0 {
				t.Errorf("the successor fenced %s %d more time(s); x's record was the authority", d.Name, n)
			}
			c.WaitConverged(t, convergeTimeout, voters...)
			claimReconciler(t, c.Node(decided.HostName)).ReconcileOnce(ctx)
			out := checkClaimSafety(t, ledger, a, vm, c.Nodes)
			if len(out.Running) == 1 && out.Running[0] != decided.HostName {
				t.Errorf("%s runs on %s, not on the decided destination %s", vm, out.Running[0], decided.HostName)
			}
		})
	}
}

// TestFleet_FenceRecovery_HostBackSinceItsFenceIsNotRecovered: a fence the host
// has come back from since is no authority, however the successor finds it.
//
//   - aged-streaks-restarted: x's verified fence is seven minutes old and d
//     answered after it; it is down again now, so every voter's failing run
//     began after the fence. Nobody has watched it stay down since.
//   - recent-seen-answering: x's verified fence is a minute old, inside the
//     recent-fence window, and voter b saw d answer after it. d is quorum-down
//     (a and c), so it is a fence candidate, but its old fence is not this
//     outage's.
//
// In both, d's recorded state is still 'fenced' (its daemon's boot write never
// reached anyone), which is the case the state check cannot catch. Nothing may
// move: no proof, no running domain.
//
// Mutation: drop the this-outage check from resumableFence (aged arm goes red)
// or the seen-since check (recent arm goes red).
func TestFleet_FenceRecovery_HostBackSinceItsFenceIsNotRecovered(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seed    int64
		age     time.Duration
		answers bool // b's latest verdict is d answering
	}{
		{name: "aged-streaks-restarted", seed: 2711, age: 7 * time.Minute},
		{name: "recent-seen-answering", seed: 2712, age: time.Minute, answers: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vm := "vm-back-" + tc.name
			c, a, b, cc, x, d := crashFleet(t, tc.seed, vm)
			voters := []*Node{a, b, cc}
			cs, clock, refenced := deadLeaderFence(t, c, voters, x, d,
				fence.Result{Method: "ipmi", Success: true, Detail: "verified off"})

			clock.Advance(tc.age)
			now := clock.Now()
			// d's failing runs began after it came back: a fresh streak of five.
			for _, n := range voters {
				if tc.answers && n == b {
					publishAnswered(t, n, d.Name, now)
					continue
				}
				PublishHealth(t, n, d.Name, 5, now)
			}
			c.WaitConverged(t, convergeTimeout, voters...)

			for i := 0; i < 4; i++ {
				cs.Tick(ctx, a)
				clock.Advance(contentionPoll)
				for _, n := range voters {
					if tc.answers && n == b {
						publishAnswered(t, n, d.Name, clock.Now())
						continue
					}
					PublishHealth(t, n, d.Name, 5, clock.Now())
				}
				c.WaitConverged(t, convergeTimeout, voters...)
			}
			if vmr := vmOn(t, a, vm); vmr.HostName != d.Name || vmr.PendingActionID != "" {
				t.Errorf("%s was recovered off %s on the strength of a fence %s came back from: %+v", vm, d.Name, d.Name, vmr)
			}
			for _, n := range c.Nodes {
				if n == x || n == d {
					continue
				}
				if ids := proofsNaming(t, n, vm, a.Name); len(ids) != 0 {
					t.Errorf("%s holds a transfer proof for %s: %v", n.Name, vm, ids)
				}
				if ids := proofsNaming(t, n, vm, b.Name); len(ids) != 0 {
					t.Errorf("%s holds a transfer proof for %s: %v", n.Name, vm, ids)
				}
				if ids := proofsNaming(t, n, vm, cc.Name); len(ids) != 0 {
					t.Errorf("%s holds a transfer proof for %s: %v", n.Name, vm, ids)
				}
			}
			if n := refenced.Load(); n != 0 {
				t.Errorf("the successor fenced %s %d time(s) while it is recorded 'fenced'", d.Name, n)
			}
		})
	}
}

// publishAnswered is n's verdict that target answered its probe just now, in
// the shape every observer's verdict replicates in.
func publishAnswered(t *testing.T, n *Node, target string, at time.Time) {
	t.Helper()
	if err := n.DB.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)`,
		n.Name, target, "healthy", 0, nil, at.UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatalf("publish %s's healthy verdict of %s: %v", n.Name, target, err)
	}
}
