// Fleet scenarios: a successor resuming a recovery from a fence that a dead
// leader recorded (docs/migration-failover.md, "Resuming a recovery from a
// recorded fence"; colonelpanik/litevirt#252).
//
// Every arm uses crashFleet: voters a, b, c, a non-voting leader x and the dead
// owner d holding vm. x fences d and dies at its first claim RPC, once its
// fence has reached every voter, so the recovery is left to a — which must
// either finish it exactly once (from x's record, or from a fresh verified
// fence of its own), or leave the workload where it is.
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
// gets anywhere. a's coordinator fences with aFr from here on. It returns the
// coordinators, the clock and a count of the fences a issues.
func deadLeaderFence(t *testing.T, c *Cluster, voters []*Node, x, d *Node, fr, aFr fence.Result) (*Coordinators, *VirtualClock, *atomic.Int32) {
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
	cs.ByNode[a.Name].SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
		refenced.Add(1)
		if h.FenceStrategy != fr.Method {
			t.Errorf("a re-fenced %s with strategy %q, not the recorded method %q", h.Name, h.FenceStrategy, fr.Method)
		}
		return aFr
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

// fencesOf lists n's fencing_log rows for host, as id/method/result.
func fencesOf(t *testing.T, n *Node, host string) []corrosion.FenceLogRecord {
	t.Helper()
	rows, err := n.DB.Query(context.Background(),
		`SELECT id, method, result FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		t.Fatalf("%s: read fencing_log: %v", n.Name, err)
	}
	var out []corrosion.FenceLogRecord
	for _, r := range rows {
		out = append(out, corrosion.FenceLogRecord{ID: r.String("id"), Method: r.String("method"), Result: r.String("result")})
	}
	return out
}

var (
	verifiedOff = fence.Result{Method: "ipmi", Success: true, Detail: "verified off"}
	sshOff      = fence.Result{Method: "ssh", Success: true, Detail: "poweroff sent"}
	ipmiFailed  = fence.Result{Method: "ipmi", Success: false, Detail: "BMC unreachable"}
)

// TestFleet_FenceRecovery_SuccessorResumesFromADeadLeadersFence: a dead
// leader's fence of a host that is still down is authority for its successor
// to finish the recovery exactly once — from the record, or, for a VERIFIED
// fence that is aged or in doubt, only after powering the host off again with
// the recorded method.
//
//   - verified-recent: x's IPMI power-off is a minute old and every voter has
//     watched d fail without a break since before it. Resumed from the record;
//     no second fence.
//   - verified-aged: the same power-off seven minutes old. A fresh verified
//     power-off is idempotent and cheap, and authority by itself: a re-fences d,
//     then recovers on the FRESH fence.
//   - verified-host-back: a minute after the IPMI fence d answered, and it has
//     been failing again since T0+2m (a fresh run of five); the record of its
//     return is lost. Not resumed from the record; re-fenced, then recovered.
//   - verified-refence-fails: aged, and a's re-fence fails. Nothing moves, the
//     host is not re-fenced again every tick, and it is left for an operator.
//   - best-effort: x's fence was an SSH power-off, which reports success without
//     verifying it. x itself would have rescheduled on it (no safe-fence policy,
//     no fence_requires_confirmation label), so its successor may too — and
//     never re-fences it: an SSH power-off of a host that is already off fails.
//
// Mutations: resume an aged verified fence from the record (verified-aged and
// verified-host-back go red: no re-fence); resume after a FAILED re-fence
// (verified-refence-fails goes red); re-fence an unverified fence
// (best-effort goes red).
func TestFleet_FenceRecovery_SuccessorResumesFromADeadLeadersFence(t *testing.T) {
	for _, tc := range []struct {
		name        string
		seed        int64
		fr, aFr     fence.Result
		age         time.Duration // how long after x's fence a takes over
		shortStreak bool          // the voters' failing runs began after d's return
		wantRefence int32
		wantMoved   bool
	}{
		{name: "verified-recent", seed: 2731, fr: verifiedOff, aFr: verifiedOff, age: time.Minute, wantMoved: true},
		{name: "verified-aged", seed: 2701, fr: verifiedOff, aFr: verifiedOff, age: 7 * time.Minute, wantRefence: 1, wantMoved: true},
		{name: "verified-host-back", seed: 2732, fr: verifiedOff, aFr: verifiedOff, age: 3 * time.Minute, shortStreak: true, wantRefence: 1, wantMoved: true},
		{name: "verified-refence-fails", seed: 2733, fr: verifiedOff, aFr: ipmiFailed, age: 7 * time.Minute, wantRefence: 1},
		{name: "best-effort", seed: 2702, fr: sshOff, aFr: sshOff, age: time.Minute, wantMoved: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vm := "vm-resume-" + tc.name
			c, a, b, cc, x, d := crashFleet(t, tc.seed, vm)
			voters := []*Node{a, b, cc}
			ledger := watchClaims(t, c)
			cs, clock, refenced := deadLeaderFence(t, c, voters, x, d, tc.fr, tc.aFr)
			xFences := fencesOf(t, a, d.Name)

			clock.Advance(tc.age)
			publish := func() {
				failures := streakSince(tc.age + time.Minute)
				if tc.shortStreak {
					failures = 5
				}
				for _, n := range voters {
					PublishHealth(t, n, d.Name, failures, clock.Now())
				}
				c.WaitConverged(t, convergeTimeout, voters...)
			}
			publish()

			var decided *corrosion.VMRecord
			for i := 0; i < 6 && decided == nil; i++ {
				cs.Tick(ctx, a)
				if vmr := vmOn(t, a, vm); vmr.PendingActionID != "" && vmr.HostName != d.Name {
					decided = vmr
				}
				clock.Advance(contentionPoll)
				publish()
			}
			if n := refenced.Load(); n != tc.wantRefence {
				t.Errorf("a fenced %s %d time(s), want %d", d.Name, n, tc.wantRefence)
			}
			if !tc.wantMoved {
				if decided != nil {
					t.Fatalf("%s was recovered after its re-fence failed: %+v", vm, decided)
				}
				for _, n := range voters {
					for _, dest := range []*Node{a, b, cc} {
						if ids := proofsNaming(t, n, vm, dest.Name); len(ids) != 0 {
							t.Errorf("%s holds a transfer proof for %s to %s: %v", n.Name, vm, dest.Name, ids)
						}
					}
				}
				if h, _ := corrosion.GetHost(ctx, a.DB, d.Name); h == nil || h.State == "fenced" {
					t.Errorf("%s is %+v after a failed re-fence; it is no longer known to be off", d.Name, h)
				}
				return
			}
			if decided == nil {
				t.Fatalf("the successor never recovered %s from x's %s fence: %+v", d.Name, tc.fr.Method, vmOn(t, a, vm))
			}
			c.WaitConverged(t, convergeTimeout, voters...)
			claimReconciler(t, c.Node(decided.HostName)).ReconcileOnce(ctx)
			out := checkClaimSafety(t, ledger, a, vm, c.Nodes)
			if len(out.Running) == 1 && out.Running[0] != decided.HostName {
				t.Errorf("%s runs on %s, not on the decided destination %s", vm, out.Running[0], decided.HostName)
			}
			if tc.wantRefence > 0 {
				// The recovery rests on the fresh fence, not on x's.
				var fresh []string
				for _, f := range fencesOf(t, a, d.Name) {
					if f.Result == "fenced" && f.ID != xFences[0].ID {
						fresh = append(fresh, f.ID)
					}
				}
				if len(fresh) != 1 {
					t.Errorf("fresh verified fences of %s = %v, want exactly one", d.Name, fresh)
				}
			}
		})
	}
}

// TestFleet_FenceRecovery_HostBackSinceItsFenceIsNotRecovered: an UNVERIFIED
// fence the host may have come back from since is no authority, however the
// successor finds it, and it is never re-fenced. Each arm's x fence is an SSH
// power-off; d is recorded 'fenced' throughout (its daemon's boot write never
// reached anyone, or lost LWW), which is the case the state check cannot catch.
//
//   - aged-streaks-restarted: seven minutes on, every voter's failing run began
//     after the fence. Nobody has watched it stay down since.
//   - recent-answered-then-down: d answered a minute after the fence and has
//     been failing since T0+2m. At T0+3m, inside the recent-fence window, the
//     verdict that it answered is overwritten by the failing one, and only the
//     runs' start betrays the return.
//   - recent-seen-answering: a minute on, voter b's latest verdict is d
//     answering. d is quorum-down (a and c), so it is a fence candidate, but
//     its old fence is not this outage's.
//
// Nothing may move: no proof, no fence, no running domain.
//
// Mutation: drop the failing-run check from fenceStillStands (both run arms go
// red; on the recent arm, so does a check that applies it outside the window
// only) or the answered check (recent-seen-answering goes red).
func TestFleet_FenceRecovery_HostBackSinceItsFenceIsNotRecovered(t *testing.T) {
	for _, tc := range []struct {
		name    string
		seed    int64
		age     time.Duration
		answers bool // b's latest verdict is d answering
	}{
		{name: "aged-streaks-restarted", seed: 2711, age: 7 * time.Minute},
		{name: "recent-answered-then-down", seed: 2713, age: 3 * time.Minute},
		{name: "recent-seen-answering", seed: 2712, age: time.Minute, answers: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vm := "vm-back-" + tc.name
			c, a, b, cc, x, d := crashFleet(t, tc.seed, vm)
			voters := []*Node{a, b, cc}
			cs, clock, refenced := deadLeaderFence(t, c, voters, x, d, sshOff, sshOff)

			clock.Advance(tc.age)
			publish := func() {
				for _, n := range voters {
					if tc.answers && n == b {
						publishAnswered(t, n, d.Name, clock.Now())
						continue
					}
					// d's failing runs began after it came back: a fresh run of five.
					PublishHealth(t, n, d.Name, 5, clock.Now())
				}
				c.WaitConverged(t, convergeTimeout, voters...)
			}
			publish()
			for i := 0; i < 4; i++ {
				cs.Tick(ctx, a)
				clock.Advance(contentionPoll)
				publish()
			}
			if vmr := vmOn(t, a, vm); vmr.HostName != d.Name || vmr.PendingActionID != "" {
				t.Errorf("%s was recovered off %s on the strength of a fence %s came back from: %+v", vm, d.Name, d.Name, vmr)
			}
			for _, n := range voters {
				for _, dest := range []*Node{a, b, cc} {
					if ids := proofsNaming(t, n, vm, dest.Name); len(ids) != 0 {
						t.Errorf("%s holds a transfer proof for %s to %s: %v", n.Name, vm, dest.Name, ids)
					}
				}
			}
			if n := refenced.Load(); n != 0 {
				t.Errorf("the successor fenced %s %d time(s); an unverified fence is never re-fenced", d.Name, n)
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
