package health

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
)

func gateHost(t *testing.T, db *corrosion.Client, name, state, role string) {
	t.Helper()
	if err := corrosion.InsertHost(context.Background(), db, corrosion.HostRecord{
		Name: name, Address: "10.0.0.9", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: state, Role: role, CertSerial: name,
	}); err != nil {
		t.Fatalf("InsertHost(%s): %v", name, err)
	}
}

// warm marks the checker past its warmup window and sets peer probe results as a
// real probe cycle would — including the lastHealthyAt/lastFailureAt monotonic
// anchors, since quorum counts a peer only on a restart-local fresh probe success
// (a healthy status alone, e.g. seeded from a stale DB row, must not count).
func warm(c *Checker, healthy map[string]bool) {
	c.mu.Lock()
	c.probedOnce = true
	c.startedAt = time.Now().Add(-time.Hour)
	mono := time.Now()
	for name, ok := range healthy {
		ps := &peerState{}
		if ok {
			ps.status = "healthy"
			ps.lastHealthyAt = mono
		} else {
			ps.status = "suspect"
			ps.lastFailureAt = mono
		}
		c.peers[name] = ps
	}
	c.mu.Unlock()
}

func TestQuorumProof_SelfCounting_WitnessMajority(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "wit-1", "active", "witness")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	// All reachable: self + b + witness = 3, needed = 3/2+1 = 2 → Yes.
	warm(c, map[string]bool{"host-b": true, "wit-1": true})
	if st, live, needed := c.QuorumProof(context.Background()); st != QuorumYes || live != 3 || needed != 2 {
		t.Fatalf("all-up: got state=%d live=%d needed=%d; want Yes/3/2", st, live, needed)
	}

	// Lose the worker peer: self + witness = 2 >= 2 → still Yes (witness counts).
	warm(c, map[string]bool{"host-b": false, "wit-1": true})
	if st, live, _ := c.QuorumProof(context.Background()); st != QuorumYes || live != 2 {
		t.Fatalf("worker-down: got state=%d live=%d; want Yes/2 (witness must count)", st, live)
	}

	// Lose the witness too: only self = 1 < 2 → No.
	warm(c, map[string]bool{"host-b": false, "wit-1": false})
	if st, live, _ := c.QuorumProof(context.Background()); st != QuorumNo || live != 1 {
		t.Fatalf("both-down: got state=%d live=%d; want No/1", st, live)
	}
}

// A peer whose status was SEEDED "healthy" from the host_health DB row at bootstrap
// (a restart) but has NOT been probed healthy THIS run (lastHealthyAt zero) must
// NOT count toward quorum — otherwise a just-restarted isolated node briefly
// regains quorum from stale pre-restart rows.
func TestQuorumProof_StaleSeededPeerNotCounted(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.mu.Lock()
	c.probedOnce = true
	c.startedAt = time.Now().Add(-time.Hour)
	// Simulate the checker.go bootstrap: status seeded healthy from the DB, but
	// lastHealthyAt is zero (no fresh in-run probe success yet).
	c.peers["host-b"] = &peerState{status: "healthy"}
	c.mu.Unlock()

	// denom = self + host-b = 2 → needed = 2. host-b is stale-seeded, so live =
	// self only = 1 < 2 → No (must NOT count the stale row).
	st, live, needed := c.QuorumProof(context.Background())
	if st != QuorumNo || live != 1 || needed != 2 {
		t.Fatalf("stale-seeded: got state=%d live=%d needed=%d; want No/1/2 — a DB-seeded healthy status must not count without a fresh probe", st, live, needed)
	}

	// Once a fresh probe lands (lastHealthyAt set), host-b counts → Yes.
	c.mu.Lock()
	c.peers["host-b"].lastHealthyAt = time.Now()
	c.mu.Unlock()
	if st, live, _ := c.QuorumProof(context.Background()); st != QuorumYes || live != 2 {
		t.Fatalf("after fresh probe: got state=%d live=%d; want Yes/2", st, live)
	}
}

func TestQuorumProof_Warmup(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.mu.Lock()
	c.startedAt = time.Now() // fresh, no probe cycle yet
	c.mu.Unlock()
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumUnknown {
		t.Fatalf("fresh start: got state=%d; want Unknown (warmup)", st)
	}
}

// A local DB-read failure must yield QuorumUnknown, NOT No: gates still fail closed on
// Unknown, but the VIPDemoter treats No as a trigger to demote local VIPs (self-fencing
// only on a demote failure with a verified watchdog), so a transient SQLite error on a
// healthy quorum-holding node must not be read as confirmed quorum loss.
func TestQuorumProof_DBErrorIsUnknownNotNo(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	c.mu.Lock()
	c.probedOnce = true // past warmup — so a bare No would be a "confirmed" loss
	c.startedAt = time.Now().Add(-time.Hour)
	c.mu.Unlock()

	// Break the host-table read.
	if err := db.Execute(context.Background(), `DROP TABLE hosts`); err != nil {
		t.Fatalf("drop hosts: %v", err)
	}
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumUnknown {
		t.Fatalf("DB read error: got state=%d; want Unknown (not No — the demoter must not act)", st)
	}
}

func TestQuorumProof_FencedPeerNotCounted(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "host-c", "fenced", "worker") // fenced: out of denominator AND live

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	// A fenced host is not voting-eligible even if we "probed" it healthy.
	warm(c, map[string]bool{"host-b": true, "host-c": true})
	// denom = self + host-b = 2 → needed = 2. live = self + host-b = 2 → Yes.
	st, live, needed := c.QuorumProof(context.Background())
	if st != QuorumYes || live != 2 || needed != 2 {
		t.Fatalf("fenced-excluded: got state=%d live=%d needed=%d; want Yes/2/2", st, live, needed)
	}
}

// M1: a healthy cluster with >2 workers must NOT be missing-witness-blocked — quorum math
// already arbitrates a clean split (a 2-2 of four needs 3 to act), so the block is scoped
// to exactly 2 workers; a broader even-count block would permanently stop the rebalance
// executor on a healthy 4/6-worker cluster.
func TestDecisionGate_FourWorkersNotBlocked(t *testing.T) {
	db := testCheckHostDB(t)
	for _, n := range []string{"host-a", "host-b", "host-c", "host-d"} {
		gateHost(t, db, n, "active", "worker")
	}
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "host-c": true, "host-d": true})
	if r := c.DecisionGate(context.Background()); !r.OK {
		t.Fatalf("healthy 4-worker cluster must not be blocked; got refused %q", r.Reason)
	}
}

func TestDecisionGate_MissingWitness(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker") // self
	gateHost(t, db, "host-b", "active", "worker")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true}) // both up → QuorumYes
	if r := c.DecisionGate(context.Background()); r.OK || r.Reason != ReasonMissingWitness {
		t.Fatalf("2-worker no-witness: got OK=%v reason=%q; want refused missing_witness", r.OK, r.Reason)
	}

	// Add a witness → 2 workers + 1 witness, no longer blocked.
	gateHost(t, db, "wit-1", "active", "witness")
	warm(c, map[string]bool{"host-b": true, "wit-1": true})
	if r := c.DecisionGate(context.Background()); !r.OK {
		t.Fatalf("2-worker+witness: got refused %q; want OK", r.Reason)
	}
}

// With an adopted voter generation the voter majority governs, not the
// two-worker heuristic. drill 6 on main-b3368d7c forced generation 10 = {node-1,
// node-2} after node-3..5 were lost for good and fence-confirmed, and every
// recovery of their workloads was then refused missing_witness until a third
// host was added; a 3-voter generation with one member fenced is blocked the
// same way. The heuristic stood in for a fixed denominator: a set derived from
// replicated host state can shrink on one side of a split. An adopted set
// changes only by a decided generation, so its majority is a real majority.
//
// The two-node split the heuristic prevents stays prevented: each side of a
// split sees one of two voters, below the majority of two, and is refused
// no_quorum. (Under recovery claims a side also cannot form a certificate,
// which needs both accepts.)
//
// Mutation: drop the adopted-generation exemption — the "adopted, both up"
// cases are refused missing_witness. Make it skip the quorum read — the split
// cases pass.
func TestDecisionGate_AnAdoptedVoterGenerationGovernsTwoWorkers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		voters  []string // adopted generation; nil = derived
		fenced  []string // hosts recorded fenced
		healthy map[string]bool
		want    string // "" = OK
	}{
		{"derived, both up", nil, nil, map[string]bool{"host-b": true}, ReasonMissingWitness},
		{"adopted pair, both up", []string{"host-a", "host-b"}, nil, map[string]bool{"host-b": true}, ""},
		{"adopted pair, split", []string{"host-a", "host-b"}, nil, map[string]bool{"host-b": false}, ReasonNoQuorum},
		{"adopted three, one fenced, both up", []string{"host-a", "host-b", "host-c"}, []string{"host-c"},
			map[string]bool{"host-b": true}, ""},
		{"adopted three, one fenced, split", []string{"host-a", "host-b", "host-c"}, []string{"host-c"},
			map[string]bool{"host-b": false}, ReasonNoQuorum},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, self := range []string{"host-a", "host-b"} {
				db := testCheckHostDB(t)
				gateHost(t, db, "host-a", "active", "worker")
				gateHost(t, db, "host-b", "active", "worker")
				for _, f := range tc.fenced {
					gateHost(t, db, f, "fenced", "worker")
				}
				if tc.voters != nil {
					adoptVoters(t, db, tc.voters...)
				}
				peer := map[string]string{"host-a": "host-b", "host-b": "host-a"}[self]
				c := NewChecker(self, "/etc/litevirt/pki", db)
				warm(c, map[string]bool{peer: tc.healthy["host-b"]})
				r := c.DecisionGate(context.Background())
				if (tc.want == "") != r.OK || (tc.want != "" && r.Reason != tc.want) {
					t.Fatalf("%s: DecisionGate OK=%v reason=%q; want %q", self, r.OK, r.Reason, tc.want)
				}
			}
		})
	}
}

// A self-fenced node fails BOTH gates closed regardless of otherwise-perfect quorum/role —
// a doomed node must take no runtime-ownership decide/execute while it waits to reboot.
func TestGates_SelfFencedFailClosed(t *testing.T) {
	db := testCheckHostDB(t)
	for _, n := range []string{"host-a", "host-b", "host-c"} {
		gateHost(t, db, n, "active", "worker")
	}
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "host-c": true}) // healthy quorum, active worker

	// Sanity: without the fence both gates pass.
	if r := c.ExecutionGate(context.Background()); !r.OK {
		t.Fatalf("precondition: ExecutionGate should pass unfenced; got %q", r.Reason)
	}
	if r := c.DecisionGate(context.Background()); !r.OK {
		t.Fatalf("precondition: DecisionGate should pass unfenced; got %q", r.Reason)
	}

	fenced := false
	c.SetSelfFenced(func() bool { return fenced })
	if r := c.ExecutionGate(context.Background()); !r.OK { // predicate false → still passes
		t.Fatalf("nil/false fence must not block; got %q", r.Reason)
	}
	fenced = true
	if r := c.ExecutionGate(context.Background()); r.OK || r.Reason != ReasonSelfFenced {
		t.Fatalf("fenced ExecutionGate: got OK=%v reason=%q; want self_fenced", r.OK, r.Reason)
	}
	if r := c.DecisionGate(context.Background()); r.OK || r.Reason != ReasonSelfFenced {
		t.Fatalf("fenced DecisionGate: got OK=%v reason=%q; want self_fenced", r.OK, r.Reason)
	}
}

func TestExecutionGate_WitnessCannotExecute(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "wit-1", "active", "witness") // self is a witness
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "host-c", "active", "worker")

	c := NewChecker("wit-1", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "host-c": true})
	// Quorum is held (self+2 = 3, needed 2), but a witness must not execute.
	if r := c.ExecutionGate(context.Background()); r.OK || r.Reason != ReasonLocalNotActiveWorker {
		t.Fatalf("witness execute: got OK=%v reason=%q; want local_not_active_worker", r.OK, r.Reason)
	}
}

func TestDecisionGate_NotCoordinatorEligibleWhenDraining(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "draining", "worker") // self draining: votes but can't coordinate
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "wit-1", "active", "witness")

	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "wit-1": true})
	if r := c.DecisionGate(context.Background()); r.OK || r.Reason != ReasonNotCoordinatorElig {
		t.Fatalf("draining coordinator: got OK=%v reason=%q; want not_coordinator_eligible", r.OK, r.Reason)
	}
}

// A transient PeerTLSConfig failure at Start must NOT leave startedAt==0 (which would make
// QuorumProof skip warmup and report a permanent false QuorumNo — refusing every gated action).
// Start anchors the warmup clock BEFORE the (now-retrying) TLS load, so QuorumProof reports
// Unknown (warmup, safe fail-closed) instead of a bogus confirmed loss.
func TestChecker_TLSLoadFailureAnchorsWarmup(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "active", "worker")
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "host-c", "active", "worker")
	c := NewChecker("host-a", "/nonexistent/litevirt/pki", db) // PeerTLSConfig fails → retry loop
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Start(ctx)
	var st QuorumState
	for i := 0; i < 200; i++ {
		if st, _, _ = c.QuorumProof(context.Background()); st == QuorumUnknown {
			return // PASS: warmup (anchored), never a false loss
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("QuorumProof never reached Unknown despite the startedAt anchor (last=%v) — false quorum-loss on TLS failure", st)
}

// TestQuorumProof_PostFenceSlackAcrossClusterSizes pins the arithmetic that
// grpcapi's leaseTermMinVotingHosts floor is chosen on — after the fence, not
// before it.
//
// The floor's rationale used to invoke the single-host-outage case: two hosts are
// unsafe because a majority is both of them, so three is "survivable". The flaw
// is that it counted hosts BEFORE the loss. The coordinator persists the failed
// host fenced/offline before it stamps the reschedule proof, and the barrier can
// only ever gather self plus the SURVIVING peers, so what matters is the slack
// between what it can gather and what it needs:
//
//	hosts  denom  needed  canAnswer  slack
//	    2      1       1          1      0
//	    3      2       2          2      0   <- every survivor mandatory
//	    4      3       2          3      1   <- first size that tolerates one
//	    5      4       3          4      1
//
// So at three hosts every survivor's answer is mandatory for every accepted
// proof, and four is the smallest cluster where one slow or silent peer still
// leaves a quorum. Three is kept anyway, deliberately — raising the floor would
// leave the minimum supported cluster with no lease-term enforcement at all,
// and a missed answer is a retry (the reconciler leaves the VM pending) rather
// than a stranded workload.
//
// The second thing pinned here is that VotingEligible's exclusion of a fenced
// host HELPS. It is tempting to read it as the cause of the tight three-host
// case; it is not. Keeping the fenced host in the denominator would make FOUR
// hosts slack-0 as well (denom 4, needed 3, canAnswer 3), pushing the first
// tolerant size out to five. The exclusion is load-bearing in the safe
// direction and must not be "corrected".
func TestQuorumProof_PostFenceSlackAcrossClusterSizes(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		hosts             int
		wantNeeded        int
		wantCanAnswer     int
		wantSlack         int
		survivorMandatory bool
	}{
		{hosts: 3, wantNeeded: 2, wantCanAnswer: 2, wantSlack: 0, survivorMandatory: true},
		{hosts: 4, wantNeeded: 2, wantCanAnswer: 3, wantSlack: 1},
		{hosts: 5, wantNeeded: 3, wantCanAnswer: 4, wantSlack: 1},
	} {
		t.Run(fmt.Sprintf("%dhosts", tc.hosts), func(t *testing.T) {
			db := testCheckHostDB(t)
			names := make([]string, tc.hosts)
			for i := range names {
				names[i] = fmt.Sprintf("host-%d", i)
				gateHost(t, db, names[i], "active", "worker")
			}
			self, doomed := names[0], names[tc.hosts-1]

			c := NewChecker(self, "/etc/litevirt/pki", db)

			// The last host dies and the coordinator fences it. Every other peer
			// is probed healthy; the fenced one is not.
			if err := corrosion.UpdateHostState(ctx, db, doomed, "fenced"); err != nil {
				t.Fatalf("UpdateHostState(fenced): %v", err)
			}
			probes := map[string]bool{}
			for _, n := range names[1:] {
				probes[n] = n != doomed
			}
			warm(c, probes)

			st, _, needed := c.QuorumProof(ctx)
			if st != QuorumYes {
				t.Fatalf("state = %d, want QuorumYes with every survivor healthy", st)
			}
			if needed != tc.wantNeeded {
				t.Errorf("needed = %d, want %d", needed, tc.wantNeeded)
			}

			peers := c.HealthyPeers(ctx)
			for _, p := range peers {
				if p == doomed {
					t.Errorf("HealthyPeers included the fenced host %q, which cannot answer "+
						"the barrier and must not be counted as able to", doomed)
				}
			}
			canAnswer := len(peers) + 1 // self reads its own ledger
			if canAnswer != tc.wantCanAnswer {
				t.Errorf("canAnswer = %d, want %d", canAnswer, tc.wantCanAnswer)
			}

			if slack := canAnswer - needed; slack != tc.wantSlack {
				t.Errorf("slack = %d, want %d: this is the number of surviving peers that may "+
					"miss leaseBarrierBudget while the barrier still reaches a quorum, and "+
					"it is the number the enforcement floor is actually chosen on",
					slack, tc.wantSlack)
			}

			if tc.survivorMandatory && canAnswer != needed {
				t.Errorf("canAnswer=%d needed=%d: at this size every survivor's answer is "+
					"supposed to be mandatory, and the equality is what makes it so",
					canAnswer, needed)
			}

			// A fence does not require the box to stop answering. `lv host fence`
			// on a responsive host, and a fence confirmed by IPMI while the BMC
			// still serves the daemon, both leave a host that probes HEALTHY and
			// is nonetheless out of the cluster. Only VotingEligible excludes it
			// — the probe filter above does not — so pin it here, or the state
			// filter in HealthyPeers can be deleted without any test noticing.
			warm(c, func() map[string]bool {
				p := map[string]bool{}
				for _, n := range names[1:] {
					p[n] = true // including the fenced one
				}
				return p
			}())
			for _, p := range c.HealthyPeers(ctx) {
				if p == doomed {
					t.Errorf("HealthyPeers included %q, which is fenced but still probing "+
						"healthy; a fenced host must not answer the barrier for the "+
						"cluster it was just evicted from", doomed)
				}
			}
			if _, _, n := c.QuorumProof(ctx); n != tc.wantNeeded {
				t.Errorf("needed = %d, want %d: a fenced host that still answers must not "+
					"re-enter the denominator either", n, tc.wantNeeded)
			}
		})
	}
}

// DrainExecutionGate is ExecutionGate with one difference: a draining worker
// passes. Every other local state, a witness, a lost quorum and a self-fence
// are refused exactly as ExecutionGate refuses them, and ExecutionGate itself
// still refuses a draining host.
//
// Mutations: let localHostIsActiveWorker pass "draining" — ExecutionGate's
// draining row goes red; drop "draining" from localHostIsEvacuatingWorker —
// DrainExecutionGate's goes red; let it pass any state — the upgrading,
// maintenance and fenced rows go red.
func TestDrainExecutionGate_OnlyDrainingIsAdded(t *testing.T) {
	for _, tc := range []struct {
		state, role string
		exec, drain string // "" = OK, else the refusal reason
	}{
		{"active", "worker", "", ""},
		{"draining", "worker", ReasonLocalNotActiveWorker, ""},
		{"upgrading", "worker", ReasonLocalNotActiveWorker, ReasonLocalNotActiveWorker},
		{"maintenance", "worker", ReasonLocalNotActiveWorker, ReasonLocalNotActiveWorker},
		{"fenced", "worker", ReasonLocalNotActiveWorker, ReasonLocalNotActiveWorker},
		{"draining", "witness", ReasonLocalNotActiveWorker, ReasonLocalNotActiveWorker},
	} {
		t.Run(tc.state+"/"+tc.role, func(t *testing.T) {
			db := testCheckHostDB(t)
			gateHost(t, db, "host-a", tc.state, tc.role) // self
			gateHost(t, db, "host-b", "active", "worker")
			gateHost(t, db, "host-c", "active", "worker")
			c := NewChecker("host-a", "/etc/litevirt/pki", db)
			warm(c, map[string]bool{"host-b": true, "host-c": true})
			ctx := context.Background()
			for _, g := range []struct {
				name string
				got  GateResult
				want string
			}{
				{"ExecutionGate", c.ExecutionGate(ctx), tc.exec},
				{"DrainExecutionGate", c.DrainExecutionGate(ctx), tc.drain},
			} {
				if (g.want == "") != g.got.OK || g.got.Reason != g.want {
					t.Errorf("%s: OK=%v reason=%q, want reason %q", g.name, g.got.OK, g.got.Reason, g.want)
				}
			}
		})
	}
}

// A draining host passes DrainExecutionGate only with quorum and unfenced.
//
// Mutation: skip the quorum check in executionGate for the drain gate — the
// no-quorum case passes and goes red.
func TestDrainExecutionGate_KeepsQuorumAndSelfFence(t *testing.T) {
	db := testCheckHostDB(t)
	gateHost(t, db, "host-a", "draining", "worker")
	gateHost(t, db, "host-b", "active", "worker")
	gateHost(t, db, "host-c", "active", "worker")
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	ctx := context.Background()

	warm(c, map[string]bool{"host-b": false, "host-c": false})
	if r := c.DrainExecutionGate(ctx); r.OK || r.Reason != ReasonNoQuorum {
		t.Fatalf("draining, no quorum: OK=%v reason=%q, want no_quorum", r.OK, r.Reason)
	}
	warm(c, map[string]bool{"host-b": true, "host-c": true})
	if r := c.DrainExecutionGate(ctx); !r.OK {
		t.Fatalf("draining, quorum: refused %q", r.Reason)
	}
	c.SetSelfFenced(func() bool { return true })
	if r := c.DrainExecutionGate(ctx); r.OK || r.Reason != ReasonSelfFenced {
		t.Fatalf("draining, self-fenced: OK=%v reason=%q, want self_fenced", r.OK, r.Reason)
	}
}
