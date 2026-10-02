// Fleet scenarios for partition pause (docs/design/partition-pause.md,
// colonelpanik/litevirt#250 / #253).
//
// kvm003 drill 1, 2026-10-02: a 2|3 nftables split; the majority fenced node-1
// with a best-effort SSH fence that could not reach it (assurance assumed),
// decided a certified claim and started d1a on node-5, while node-1 never
// stopped its own copy — d1a ran twice through the partition and after it, and
// node-1's reconciler refused to stop it forever.
//
// These scenarios run the real pieces end to end over a real gossip partition
// (RealGossip + SplitGossip, which drops every RPC between the halves): the
// real health checker probing peers' readiness every 2 s, the real partition
// pauser on its quorum, the real failover coordinator on the real host_health
// rows the checkers publish, real recovery claims, the real reconciler with
// Layer 3, and libvirtfake as each node's hypervisor. Time is REAL: the
// checker's 2 s probe interval cannot be shortened, so these take tens of
// seconds each. T_pause is shortened for the scenarios (ppTPause) and the
// coordinator's wait is derived from it with the PRODUCTION margin.
package fleet

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ppTPause is the scenarios' T_pause. Long enough that the minority pauses
// AFTER the majority's fence decision (the checker needs ~4-6 s to call a
// fail-fast peer suspect, the coordinator ~10 s to see five failures), so a
// coordinator that did not wait would start its replacement while the
// original still runs — which is what makes the wait observable at all.
const ppTPause = 8 * time.Second

// ppRecoverBound bounds how long a scenario waits for the majority to decide
// and start a recovery. It is generous on purpose: under -race every node's
// SQLite transactions slow by an order of magnitude, a voter's promise can run
// past the proposer's 3 s per-call timeout, and the claim then retries on the
// next poll (recovery-claims.md §6, duelling and slow voters). That costs
// liveness, never the property under test, which every scenario asserts on
// the order of events rather than on how long they took.
const ppRecoverBound = 4 * time.Minute

// ppWait is the coordinator's wait for a cluster of n hosts under ppTPause.
func ppWait(targets int) time.Duration { return ppTPause + health.PartitionPauseMarginFor(targets) }

// ppGate is the coordinator's gate: the node's REAL checker for quorum and the
// decide gate, every split-brain token latched (claimsLatched) plus
// partition_pause_v1.
type ppGate struct{ chk *health.Checker }

func (g ppGate) DecisionGate(ctx context.Context) health.GateResult { return g.chk.DecisionGate(ctx) }
func (g ppGate) QuorumProof(ctx context.Context) (health.QuorumState, int, int) {
	return g.chk.QuorumProof(ctx)
}
func (g ppGate) Enforced(_ context.Context, tok string) bool {
	return claimsLatched(tok) || tok == capabilities.PartitionPauseV1
}
func (g ppGate) PeerSupportsFresh(context.Context, string, string) bool { return true }

type ppNode struct {
	n      *Node
	chk    *health.Checker
	pauser *health.PartitionPauser
	coord  *failover.Coordinator
	rec    *health.Reconciler
}

type ppFence struct {
	target string
	at     time.Time
}

// ppStack is the daemon's partition-pause wiring on every node, driven by
// real time.
type ppStack struct {
	c     *Cluster
	nodes []*ppNode
	mu    sync.Mutex
	fence []ppFence
}

type ppOpts struct {
	// pauseOff lists nodes whose enforcement.partition_pause is off (a host
	// without the token).
	pauseOff map[string]bool
	// latched: the coordinators rely on the pause (partition_pause_v1
	// latched). False models a cluster where it has not latched.
	latched bool
	// coordinators, when set, names the only nodes that run a failover
	// coordinator. Every node runs one in production; a scenario whose
	// subject is not the lease contest names one, because coordinators that
	// each hold the lease in their own replica and all claim the moment they
	// fence duel each other's ballots for minutes under -race (each
	// voter's promise is a local transaction, and the proposer's per-call
	// timeout is 3 s), which is recovery-claims.md §6's duelling-proposer
	// liveness case, not what the scenario tests.
	coordinators map[string]bool
}

func newPPStack(t *testing.T, c *Cluster, o ppOpts) *ppStack {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	s := &ppStack{c: c}
	for _, n := range c.Nodes {
		dataDir := filepath.Join(t.TempDir(), n.Name)
		chk := health.NewChecker(n.Name, n.PKIDir, n.DB)
		chk.SetPeerReadiness(n.Server.PeerReady)
		go chk.Start(ctx)

		on := !o.pauseOff[n.Name]
		p := health.NewPartitionPauser(n.Name, dataDir, n.DB)
		p.SetQuorum(chk.ExecutionQuorum)
		p.SetEnabled(func() bool { return on })
		p.SetVMBackend(n.Virt)
		p.SetResumeConfirmer(n.Server.CheckPartitionResume)
		p.SetTimings(ppTPause, 100*time.Millisecond)
		go p.Start(ctx)

		coord := failover.NewCoordinator(n.Name, n.DB)
		name := n.Name
		coord.SetFencer(func(_ context.Context, h fence.HostConfig) fence.Result {
			s.mu.Lock()
			s.fence = append(s.fence, ppFence{target: h.Name, at: time.Now()})
			s.mu.Unlock()
			// The drill's fence: SSH cannot reach a partitioned host, and the
			// best-effort strategy proceeds anyway — assurance assumed.
			return fence.Result{Method: "best-effort-ssh", Success: true,
				Detail: "SSH failed (fleet partition), proceeding anyway: by " + name}
		})
		coord.Gate = ppGate{chk}
		coord.Claimer = n.Server
		coord.RecoveryClaimEnforced = n.Server.RecoveryClaimEnforced
		coord.ClaimHealth = n.Server.RecoveryClaimHealthTick
		latched := o.latched
		coord.PartitionPauseEnforced = func(context.Context) bool { return latched }
		coord.PauseWaitFor = ppWait
		coord.LastContact = chk.LastContact
		// The harness runs no capability sweep to fill the checker's Ping
		// cache; every node in these scenarios runs the flag on.
		pauseOn := o.pauseOff
		coord.PeerAdvertised = func(peer, tok string) bool { return tok == capabilities.PartitionPauseV1 && !pauseOn[peer] }
		coord.QuorumRegain = chk.InQuorumRegainGraceFor

		rec := health.NewReconciler(n.Name, dataDir, n.DB, n.Virt)
		rec.SetGate(epochGate{})
		rec.SetRecoveryClaimGate(n.Server.RecoveryClaimGateForPendingProof)
		rec.SetSettleVerifier(n.Server.VerifySettleProof)
		rec.SetPeerRuntimeChecker(n.Server.CheckPeerVMRuntime)

		pn := &ppNode{n: n, chk: chk, pauser: p, coord: coord, rec: rec}
		s.nodes = append(s.nodes, pn)
		// Reconcilers tick fast. Coordinators tick at about a second, each at
		// its own phase: every node holds the lease in its own replica until
		// the lease row converges, and coordinators polling in lock-step every
		// few hundred ms duel each other's claim ballots indefinitely under
		// -race (production polls every 5 s).
		phase := time.Duration(len(s.nodes)) * 190 * time.Millisecond
		go func() {
			tk := time.NewTicker(300 * time.Millisecond)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					pn.rec.ReconcileOnce(ctx)
				}
			}
		}()
		if o.coordinators != nil && !o.coordinators[n.Name] {
			continue
		}
		go func() {
			select {
			case <-ctx.Done():
				return
			case <-time.After(phase):
			}
			tk := time.NewTicker(time.Second)
			defer tk.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tk.C:
					pn.coord.RunOnce(ctx)
				}
			}
		}()
	}
	eventually(t, 30*time.Second, "every node's checker to see the voter majority", func() bool {
		for _, pn := range s.nodes {
			if st, _, _ := pn.chk.QuorumProof(context.Background()); st != health.QuorumYes {
				return false
			}
		}
		return true
	})
	return s
}

func (s *ppStack) fencesOf(target string) []ppFence {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ppFence
	for _, f := range s.fence {
		if f.target == target {
			out = append(out, f)
		}
	}
	return out
}

// runSampler records, every few ms, how many nodes run vm (fake state
// running). It is the "no instant has two active copies" check; the event-log
// order check below it is the exact one.
type runSampler struct {
	mu      sync.Mutex
	max     int
	overlap []string
	since   map[string]time.Time // node → first time seen running after mark
	mark    time.Time
}

func sampleRunning(t *testing.T, c *Cluster, vm string) *runSampler {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rs := &runSampler{since: map[string]time.Time{}}
	go func() {
		tk := time.NewTicker(5 * time.Millisecond)
		defer tk.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-tk.C:
				var running []string
				for _, n := range c.Nodes {
					if st, ok := n.Virt.RawState(vm); ok && st == libvirtfake.StateRunning {
						running = append(running, n.Name)
					}
				}
				now := time.Now()
				rs.mu.Lock()
				if len(running) > rs.max {
					rs.max = len(running)
				}
				if len(running) > 1 && len(rs.overlap) < 5 {
					rs.overlap = append(rs.overlap, fmt.Sprintf("%s: %v", now.Format("15:04:05.000"), running))
				}
				if !rs.mark.IsZero() {
					for _, r := range running {
						if _, ok := rs.since[r]; !ok {
							rs.since[r] = now
						}
					}
				}
				rs.mu.Unlock()
			}
		}
	}()
	return rs
}

// markNow starts recording which nodes run the VM from now on.
func (rs *runSampler) markNow() {
	rs.mu.Lock()
	rs.mark, rs.since = time.Now(), map[string]time.Time{}
	rs.mu.Unlock()
}

func firstEvent(n *Node, op, vm string) (libvirtfake.Event, bool) {
	for _, ev := range n.Virt.EventLog() {
		if ev.Op == op && ev.Domain == vm {
			return ev, true
		}
	}
	return libvirtfake.Event{}, false
}

func runningOn(c *Cluster, vm string) []string {
	var out []string
	for _, n := range c.Nodes {
		if st, ok := n.Virt.RawState(vm); ok && st == libvirtfake.StateRunning {
			out = append(out, n.Name)
		}
	}
	return out
}

func insertVMPolicy(t *testing.T, n *Node, name, host, policy string) {
	t.Helper()
	if err := corrosion.InsertVM(context.Background(), n.DB, corrosion.VMRecord{
		Name: name, HostName: host, Spec: `{"on_host_failure":"` + policy + `"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM %s on %s: %v", name, n.Name, err)
	}
}

// TestFleet_PartitionPause_MinorityPausesBeforeTheMajorityRecovers is drill 1
// with Layer 2 latched: split 2|3, the majority fences node-0 with a fence that
// cannot reach it, and the original must stop executing BEFORE the replacement
// starts.
//
// Mutations: start the replacement at the decision (deadline = anchor in
// pauseDeadlinePassed) — the replacement starts while node-0 still runs and
// the overlap check goes red; never pause (lostFor < p.after → true) — the
// overlap check goes red; resume without the majority's confirmation — node-0,
// its replica still stale, runs pp-vm again after the heal and the post-heal
// check goes red; one-way without its kept-failing clause — the heal raises
// partition_one_way and the last check goes red.
func TestFleet_PartitionPause_MinorityPausesBeforeTheMajorityRecovers(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	insertVMPolicy(t, owner, "pp-none", owner.Name, "none")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)
	owner.Virt.SetState("pp-none", libvirtfake.StateRunning)
	genesisByTick(t, c, c.Nodes[2])
	enableRecoveryClaims(t, c)

	// One coordinator decides, as one lease holder did in drill 1 (see
	// ppOpts.coordinators); the blip scenario runs one on every node.
	s := newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true}})
	rs := sampleRunning(t, c, "pp-vm")

	minority, majority := c.Nodes[:2], c.Nodes[2:]
	split := time.Now()
	c.SplitGossip(minority, majority)

	var dest *Node
	eventually(t, ppRecoverBound, "the majority to start pp-vm's replacement", func() bool {
		for _, n := range majority {
			if st, ok := n.Virt.RawState("pp-vm"); ok && st == libvirtfake.StateRunning {
				dest = n
				return true
			}
		}
		return false
	})

	// The minority paused, and not before T_pause of lost quorum.
	susp, ok := firstEvent(owner, "suspend", "pp-vm")
	if !ok {
		t.Fatalf("%s never suspended pp-vm", owner.Name)
	}
	if d := susp.When.Sub(split); d < ppTPause {
		t.Fatalf("%s paused pp-vm %v after the split, before T_pause %v", owner.Name, d, ppTPause)
	}
	if d := susp.When.Sub(split); d > ppTPause+20*time.Second {
		t.Fatalf("%s paused pp-vm only %v after the split", owner.Name, d)
	}
	// The majority started the replacement only after the deadline it derived.
	fences := s.fencesOf(owner.Name)
	if len(fences) == 0 {
		t.Fatalf("no coordinator fenced %s", owner.Name)
	}
	start, ok := firstEvent(dest, "start", "pp-vm")
	if !ok {
		t.Fatalf("%s runs pp-vm with no start event", dest.Name)
	}
	if w := ppWait(len(c.Nodes) - 1); start.When.Sub(fences[0].at) < w {
		t.Fatalf("%s started pp-vm %v after the fence decision; the wait is %v", dest.Name,
			start.When.Sub(fences[0].at), w)
	}
	// Never two running at once: exactly, by event order...
	if !susp.When.Before(start.When) {
		t.Fatalf("the replacement started on %s at %s, before %s paused the original at %s",
			dest.Name, start.When.Format("15:04:05.000"), owner.Name, susp.When.Format("15:04:05.000"))
	}
	// ...and by sampling.
	rs.mu.Lock()
	maxRun, overlap := rs.max, rs.overlap
	rs.mu.Unlock()
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once: %v", overlap)
	}
	// The fence was recorded as relying on the pause.
	rows, err := dest.DB.Query(ctx, `SELECT method, result, detail FROM fencing_log WHERE host_name = ?`, owner.Name)
	if err != nil || len(rows) == 0 {
		t.Fatalf("no fencing_log row for %s on %s: %v", owner.Name, dest.Name, err)
	}
	for _, r := range rows {
		if a := corrosion.FenceAssuranceDetail(r.String("method"), r.String("result"), r.String("detail")); a != corrosion.FenceSelfPaused {
			t.Errorf("fence of %s recorded with assurance %s, want %s", owner.Name, a, corrosion.FenceSelfPaused)
		}
	}
	// A policy-none VM is neither paused nor replaced.
	if st, _ := owner.Virt.RawState("pp-none"); st != libvirtfake.StateRunning {
		t.Errorf("pp-none (on_host_failure=none) is %s on %s; nothing replaces it, so it keeps running", st, owner.Name)
	}

	// After the heal nothing resumes on the minority. For the first stretch
	// the network is back but REPLICATION into and out of the minority is
	// still held, so node-0's own replica still says pp-vm is its own at the
	// recorded epoch and incarnation — only the voters it asks directly can
	// tell it the workload moved. Then replication returns and Layer 3 stops
	// the paused copy on the certified claim.
	rs.markNow()
	c.HealGossip()
	for _, a := range minority {
		for _, b := range majority {
			c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
		}
	}
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	time.Sleep(12 * time.Second)
	if row := vmOn(t, owner, "pp-vm"); row == nil || row.HostName != owner.Name {
		t.Fatalf("setup: replication reached %s while it was held (row %+v); the stale-replica window is not exercised", owner.Name, row)
	}
	c.ClearLinkFaults()
	time.Sleep(10 * time.Second)
	rs.mu.Lock()
	since := rs.since
	maxRun = rs.max
	rs.mu.Unlock()
	if at, ran := since[owner.Name]; ran {
		t.Fatalf("%s ran pp-vm again at %s after the heal; a workload a certified claim moved must stay stopped",
			owner.Name, at.Format("15:04:05.000"))
	}
	if maxRun > 1 {
		t.Fatalf("pp-vm ran on more than one host at once after the heal")
	}
	if got := runningOn(c, "pp-vm"); len(got) != 1 || got[0] != dest.Name {
		t.Fatalf("pp-vm runs on %v after the heal, want only %s", got, dest.Name)
	}
	// A symmetric split, healed, is not a one-way partition: the minority's
	// new healthy rows land while the majority's last failures are still
	// fresh, which must not raise partition_one_way.
	for _, n := range c.Nodes {
		for _, m := range minority {
			if row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, corrosion.PartitionPauseEvaluator,
				corrosion.CondPartitionOneWay, "host", m.Name); err != nil || ok {
				t.Errorf("%s raised partition_one_way for %s on a symmetric split: %+v (%v)", n.Name, m.Name, row, err)
			}
		}
	}
}

// TestFleet_PartitionSettle_DualRunSettlesToTheCertifiedCopy is drill 1 on a
// host WITHOUT the token: node-0 does not pause and the cluster has not
// latched, so the majority recovers at once and pp-dual runs twice through the
// partition (which this scenario asserts, so it cannot pass vacuously). After
// the heal, Layer 3 stops node-0's copy on the certified claim: exactly one
// copy runs, and node-0's is destroyed, not undefined first, with
// vm_settled and a partition.settle audit row.
//
// Mutation: drop the settle hook in selfFence — node-0's copy keeps running
// and the final check goes red.
func TestFleet_PartitionSettle_DualRunSettlesToTheCertifiedCopy(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-dual", owner.Name, "restart-any")
	if err := corrosion.GraduateVMOwnerEpoch(ctx, owner.DB, "pp-dual"); err != nil {
		t.Fatalf("graduate pp-dual: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-dual", libvirtfake.StateRunning)
	if err := owner.Virt.SetDomainOwnerEpoch("pp-dual", 1, true); err != nil {
		t.Fatal(err)
	}
	genesisByTick(t, c, c.Nodes[2])
	enableRecoveryClaims(t, c)

	s := newPPStack(t, c, ppOpts{latched: false, pauseOff: map[string]bool{owner.Name: true},
		coordinators: map[string]bool{c.Nodes[2].Name: true}})
	// The owner's reconciler stamps the domain with its row's incarnation while
	// the row still names it — the evidence Layer 3 settles on.
	eventually(t, 10*time.Second, "pp-dual's managed stamp to carry its incarnation", func() bool {
		inc, ok, err := owner.Virt.GetDomainManagedIncarnation("pp-dual")
		return err == nil && ok && inc != ""
	})

	c.SplitGossip(c.Nodes[:1], c.Nodes[1:])
	eventually(t, ppRecoverBound, "the dual run: pp-dual running on the owner AND a recovery destination", func() bool {
		return len(runningOn(c, "pp-dual")) == 2
	})
	_ = s

	c.HealGossip()
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	eventually(t, ppRecoverBound, "the dual run to settle to one copy", func() bool {
		got := runningOn(c, "pp-dual")
		return len(got) == 1 && got[0] != owner.Name
	})
	if st, ok := owner.Virt.RawState("pp-dual"); ok && st == libvirtfake.StateRunning {
		t.Fatalf("%s still runs pp-dual", owner.Name)
	}
	if _, ok := firstEvent(owner, "destroy", "pp-dual"); !ok {
		t.Fatalf("%s stopped pp-dual without a destroy", owner.Name)
	}
	// The settle writes its audit row and condition just after the destroy
	// that the wait above observed.
	eventually(t, 30*time.Second, "vm_settled and the partition.settle audit row on "+owner.Name, func() bool {
		cond, ok, err := corrosion.GetHealthCondition(ctx, owner.DB, corrosion.PartitionPauseEvaluator,
			corrosion.CondVMSettled, "vm", "pp-dual@"+owner.Name)
		if err != nil || !ok || cond.Lifecycle != corrosion.ConditionConfirmed {
			return false
		}
		rows, err := owner.DB.Query(ctx, `SELECT detail FROM audit_log WHERE action = 'partition.settle' AND target = 'pp-dual'`)
		return err == nil && len(rows) > 0
	})
}

// TestFleet_PartitionPause_FleetWideBlipPausesThenResumesEverything: every
// node cut off from every other. No host has a majority, so nothing fences
// anyone; every recoverable workload pauses, partition_paused is raised on
// every host, and when the network heals — no daemon restart — every
// workload resumes and every condition resolves.
//
// Mutations: hold every resume (DecideResume never OK) — nothing resumes and
// the resume wait goes red; skip the partition_paused condition — the raised
// check goes red.
func TestFleet_PartitionPause_FleetWideBlipPausesThenResumesEverything(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, Relays: 3, RealGossip: true})
	for _, n := range c.Nodes {
		insertVMPolicy(t, n, "blip-"+n.Name, n.Name, "restart-any")
	}
	c.WaitConverged(t, convergeTimeout)
	for _, n := range c.Nodes {
		n.Virt.SetState("blip-"+n.Name, libvirtfake.StateRunning)
	}
	newPPStack(t, c, ppOpts{latched: true})

	c.SplitAll()
	eventually(t, 60*time.Second, "every node to pause its workload", func() bool {
		for _, n := range c.Nodes {
			if st, _ := n.Virt.RawState("blip-" + n.Name); st != libvirtfake.StatePaused {
				return false
			}
		}
		return true
	})
	for _, n := range c.Nodes {
		row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, corrosion.PartitionPauseEvaluator,
			corrosion.CondPartitionPaused, "host", n.Name)
		if err != nil || !ok || row.Lifecycle == corrosion.ConditionResolved {
			t.Fatalf("%s has no open partition_paused while its workload is paused: (%+v, %v, %v)", n.Name, row, ok, err)
		}
	}

	c.HealGossip()
	eventually(t, 90*time.Second, "every workload to resume after the heal", func() bool {
		for _, n := range c.Nodes {
			if st, _ := n.Virt.RawState("blip-" + n.Name); st != libvirtfake.StateRunning {
				return false
			}
		}
		return true
	})
	eventually(t, 30*time.Second, "every partition_paused to resolve", func() bool {
		for _, n := range c.Nodes {
			row, ok, err := corrosion.GetHealthCondition(ctx, n.DB, corrosion.PartitionPauseEvaluator,
				corrosion.CondPartitionPaused, "host", n.Name)
			if err != nil || !ok || row.Lifecycle != corrosion.ConditionResolved {
				return false
			}
		}
		return true
	})
	// Nothing moved: no host had a majority to decide anything.
	for _, n := range c.Nodes {
		vm, err := corrosion.GetVM(ctx, n.DB, "blip-"+n.Name)
		if err != nil || vm == nil || vm.HostName != n.Name {
			t.Fatalf("blip-%s moved during a fleet-wide blip: %+v (%v)", n.Name, vm, err)
		}
		if got := runningOn(c, "blip-"+n.Name); len(got) != 1 || got[0] != n.Name {
			t.Fatalf("blip-%s runs on %v after the blip, want only %s", n.Name, got, n.Name)
		}
	}
}

// TestFleet_PartitionPause_ResumeWithoutClaimsReadsTheVotersRows: recovery
// claims OFF (the default). The majority recovers pp-vm off a paused node-0;
// then an operator undrains node-0 (`lv host undrain`) while replication into
// node-0 is still held. Every voter now reports node-0 active and there is no
// claim to find, so only the voters' own ROWS — pp-vm on the replacement host
// — can tell node-0, whose replica still says the VM is its own, not to
// resume a second copy.
//
// Mutation: drop the row comparison in DecideResume — node-0 resumes pp-vm
// beside the replacement and this goes red.
func TestFleet_PartitionPause_ResumeWithoutClaimsReadsTheVotersRows(t *testing.T) {
	ctx := context.Background()
	c := New(t, Options{Nodes: 5, IndependentReplicas: true, Relays: 5, RealGossip: true})
	owner := c.Nodes[0]
	insertVMPolicy(t, owner, "pp-vm", owner.Name, "restart-any")
	c.WaitConverged(t, convergeTimeout)
	owner.Virt.SetState("pp-vm", libvirtfake.StateRunning)

	newPPStack(t, c, ppOpts{latched: true, coordinators: map[string]bool{c.Nodes[2].Name: true}})
	rs := sampleRunning(t, c, "pp-vm")
	minority, majority := c.Nodes[:2], c.Nodes[2:]
	c.SplitGossip(minority, majority)

	var dest *Node
	eventually(t, ppRecoverBound, "the majority to start pp-vm's replacement", func() bool {
		for _, n := range majority {
			if st, ok := n.Virt.RawState("pp-vm"); ok && st == libvirtfake.StateRunning {
				dest = n
				return true
			}
		}
		return false
	})
	if st, _ := owner.Virt.RawState("pp-vm"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: %s's copy is %s, want paused", owner.Name, st)
	}

	rs.markNow()
	c.HealGossip()
	for _, a := range minority {
		for _, b := range majority {
			c.SetLinkFaultBoth(a, b, LinkFault{Block: true})
		}
	}
	c.WaitGossip(t, remergeBound, "the halves to merge", c.GossipConverged)
	if err := corrosion.UpdateHostState(ctx, dest.DB, owner.Name, "active"); err != nil {
		t.Fatalf("undrain %s: %v", owner.Name, err)
	}
	eventually(t, 30*time.Second, "the undrain to reach every majority voter", func() bool {
		for _, n := range majority {
			if h, err := corrosion.GetHost(ctx, n.DB, owner.Name); err != nil || h == nil || h.State != "active" {
				return false
			}
		}
		return true
	})
	time.Sleep(15 * time.Second)
	if row := vmOn(t, owner, "pp-vm"); row == nil || row.HostName != owner.Name {
		t.Fatalf("setup: replication reached %s while it was held (row %+v)", owner.Name, row)
	}
	rs.mu.Lock()
	at, ran := rs.since[owner.Name]
	rs.mu.Unlock()
	if ran {
		t.Fatalf("%s resumed pp-vm at %s beside %s's replacement: its stale replica was trusted over the voters' rows",
			owner.Name, at.Format("15:04:05.000"), dest.Name)
	}
	if st, _ := owner.Virt.RawState("pp-vm"); st != libvirtfake.StatePaused {
		t.Fatalf("%s's copy is %s, want still paused", owner.Name, st)
	}
}
