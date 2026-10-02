// Fleet scenarios: a coordinator that crashes midway through collecting
// accepts (docs/design/recovery-claims.md §3.15 rows 2–3, §7.1 "Coordinator
// crash mid-collection"), colonelpanik/litevirt#250.
//
// The coordinator x is NOT a voter, so every message it sends crosses a link
// and the claim script decides exactly which voters its Accept reaches. It
// reaches k of the three voters, each of which commits its accept, and then x
// dies before any reply comes back: its daemon stops (Crash) with no
// certificate formed and no proof written. A second coordinator — a voter,
// so its own vote is the local path — then runs the claim on the same key.
//
//   - k = 1, below a majority, and a's Prepare reaches the voter holding x's
//     value: a learns it and completes it (it is free not to, Paxos-wise, but
//     the proposer adopts the highest accepted value it sees).
//   - k = 1, and a's first Prepare to that voter is lost: a never sees x's
//     value and decides its own. x's value must never become chosen.
//   - k = 2, a majority, before any certificate is stored: x's value WAS
//     chosen, nobody knows it, and every majority a can collect includes a
//     voter holding it — a must adopt it, with x's proof ID.
//
// Every arm asserts the full safety set (claim_invariants_test.go): one chosen
// value, one certified value, one minted proof, one running domain.
package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// crashFleet is five hosts: voters a, b, c (generation 3, after genesis over
// all five and the removal of x and d), a non-voting coordinator x whose
// capacity is full so no placement picks it, and the dead owner d holding vm.
func crashFleet(t *testing.T, seed int64, vm string) (c *Cluster, a, b, cc, x, d *Node) {
	t.Helper()
	ctx := context.Background()
	c = New(t, Options{Nodes: 5, IndependentReplicas: true, FaultSeed: seed})
	a, b, cc, x, d = c.Nodes[0], c.Nodes[1], c.Nodes[2], c.Nodes[3], c.Nodes[4]
	insertVM(t, a, vm, d.Name)
	if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{
		Name: "full-" + x.Name, HostName: x.Name, Spec: `{}`, State: "running",
		CPUActual: 64, MemActual: 262144,
	}, nil, nil); err != nil {
		t.Fatalf("fill %s: %v", x.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
	genesisByTick(t, c, a)
	for i, h := range []*Node{x, d} {
		if _, err := c.SelfClient(a).ChangeVoterConfig(ctx, &pb.ChangeVoterConfigRequest{Op: "rm", Host: h.Name}); err != nil {
			t.Fatalf("voter rm %s: %v", h.Name, err)
		}
		adoptAll(t, c, int64(2+i))
	}
	if cfg := voterRow(t, a, 3); cfg == nil || len(cfg.Names()) != 3 {
		t.Fatalf("voter generation 3 = %+v, want {a, b, c}", cfg)
	}
	enableRecoveryClaims(t, c, a, b, cc, x)
	c.Kill(d)
	now := time.Now().UTC()
	for _, n := range []*Node{a, b, cc, x} {
		PublishHealth(t, n, d.Name, 5, now)
	}
	c.WaitConverged(t, convergeTimeout, a, b, cc, x)
	return c, a, b, cc, x, d
}

// crashAfterAccepts is the claim script for x's crash: x's Accept reaches
// exactly the voters in reach, each commits it, and x dies — every link to and
// from it fails — at the last of them, before any reply is read. Its Accept to
// any other voter is never sent. lostPrepare additionally drops the first
// Prepare a sends to that voter.
type crashAfterAccepts struct {
	c           *Cluster
	x           *Node
	reach       map[string]bool
	lostPrepare struct{ from, to string }

	mu        sync.Mutex
	delivered int
	dropped   bool
}

func (s *crashAfterAccepts) script(m ClaimMsg) ClaimFate {
	s.mu.Lock()
	defer s.mu.Unlock()
	if m.From == s.lostPrepare.from && m.To == s.lostPrepare.to && m.Method == "PrepareRecoveryClaim" && !s.dropped {
		s.dropped = true
		return ClaimDropRequest
	}
	if m.From != s.x.Name || m.Method != "AcceptRecoveryClaim" {
		return ClaimDefault
	}
	if !s.reach[m.To] {
		return ClaimDropRequest
	}
	s.delivered++
	if s.delivered == len(s.reach) {
		s.c.Kill(s.x)
	}
	return ClaimDropReply
}

func TestFleet_RecoveryClaim_CoordinatorCrashMidCollection(t *testing.T) {
	for _, tc := range []struct {
		name  string
		seed  int64
		reach []int // indexes into {a, b, c} whose voters commit x's accept
		// lostPrepare: a's first Prepare to the one voter holding x's value
		// is lost, so a never learns it.
		lostPrepare bool
		// adopt: a must complete x's value (same proof ID).
		adopt bool
	}{
		{name: "one-of-three-seen", seed: 2601, reach: []int{1}, adopt: true},
		{name: "one-of-three-unseen", seed: 2602, reach: []int{1}, lostPrepare: true},
		{name: "majority-before-certificate", seed: 2603, reach: []int{1, 2}, adopt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			vm := "vm-crash-" + tc.name
			c, a, b, cc, x, d := crashFleet(t, tc.seed, vm)
			voters := []*Node{a, b, cc}
			ledger := watchClaims(t, c)
			key := vmKey(vm, 0)

			s := &crashAfterAccepts{c: c, x: x, reach: map[string]bool{}}
			for _, i := range tc.reach {
				s.reach[voters[i].Name] = true
			}
			if tc.lostPrepare {
				s.lostPrepare.from, s.lostPrepare.to = a.Name, voters[tc.reach[0]].Name
			}
			c.SetClaimScript(s.script)

			clock := NewVirtualClock(time.Now().UTC())
			cs := c.NewCoordinators(clock)
			for _, n := range []*Node{a, x} {
				cs.ByNode[n.Name].Gate = quorateGate{}
				// A verified power-off. Whether x's fence row replicates before
				// it dies is a race, and a successor resumes a recovery from a
				// dead leader's fence only when that fence is proof-grade; a
				// best-effort one leaves d 'fenced' and its workloads waiting for
				// `lv host fence-confirm`, which is not what this scenario is
				// about.
				cs.ByNode[n.Name].SetFencer(func(context.Context, fence.HostConfig) fence.Result {
					return fence.Result{Method: "ipmi", Success: true}
				})
			}
			cs.Tick(ctx, x)
			c.Crash(x)

			// x's value is on exactly the voters it reached, and nowhere is it
			// certified or minted.
			var xValue *corrosion.ClaimValue
			for _, v := range voters {
				st := voterState(t, v, key)
				held := st.Value != nil && st.Accepted.Coordinator == x.Name
				if held != s.reach[v.Name] {
					t.Fatalf("%s holds x's value = %v, want %v (state %+v)", v.Name, held, s.reach[v.Name], st)
				}
				if held {
					xValue = st.Value
				}
			}
			if xValue == nil || xValue.Proof == nil {
				t.Fatal("no voter holds x's value; the crash is vacuous")
			}
			for _, n := range c.Nodes {
				if n != x && n != d {
					if ids := proofsNaming(t, n, vm, xValue.Proof.DestHost); len(ids) != 0 {
						t.Fatalf("%s holds a proof minted before x's crash: %v", n.Name, ids)
					}
				}
			}

			// The second coordinator takes over once x's lease has run out.
			clock.Advance(time.Minute)
			now := clock.Now()
			for _, n := range voters {
				PublishHealth(t, n, d.Name, 5, now)
			}
			c.WaitConverged(t, convergeTimeout, voters...)
			var decided *corrosion.VMRecord
			for i := 0; i < 4; i++ {
				cs.Tick(ctx, a)
				if vmr := vmOn(t, a, vm); vmr.PendingActionID != "" && vmr.HostName != d.Name {
					decided = vmr
					break
				}
				clock.Advance(contentionPoll)
			}
			if decided == nil {
				for _, q := range []string{`SELECT * FROM leader_election`, `SELECT * FROM fencing_log`,
					`SELECT name, state FROM hosts`, `SELECT observer, target, consecutive_failures, updated_at FROM host_health`} {
					rows, err := a.DB.Query(ctx, q)
					t.Logf("%s: %v %v", q, rows, err)
				}
				t.Logf("clock now %s", clock.Now())
				t.Fatalf("the second coordinator did not decide: %+v", vmOn(t, a, vm))
			}

			// The destination executes; every safety property holds.
			c.WaitConverged(t, convergeTimeout, voters...)
			claimReconciler(t, c.Node(decided.HostName)).ReconcileOnce(ctx)
			out := checkClaimSafety(t, ledger, a, vm, c.Nodes)
			if tc.adopt && decided.PendingActionID != xValue.Proof.ID {
				t.Errorf("the second coordinator decided proof %s, not the crashed coordinator's %s (Paxos value adoption)",
					decided.PendingActionID, xValue.Proof.ID)
			}
			if !tc.adopt && decided.PendingActionID == xValue.Proof.ID {
				t.Errorf("the second coordinator completed x's value %s although it never saw it", xValue.Proof.ID)
			}
			xDigest, _ := xValue.Digest()
			if tc.adopt != out.Chosen[key][xDigest] {
				t.Errorf("x's value chosen = %v, want %v (chosen %v)", out.Chosen[key][xDigest], tc.adopt, keys(out.Chosen[key]))
			}
			if len(out.Certified[key]) != 1 {
				t.Errorf("certified values for %s: %v, want exactly one", key, keys(out.Certified[key]))
			}
		})
	}
}
