package failover

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/hlc"
)

// setHA writes the cluster HA policy on db, after whatever row it holds.
func setHA(t *testing.T, db *corrosion.Client, state string) string {
	t.Helper()
	ctx := context.Background()
	db.SetClusterPolicyGate(func() bool { return true })
	cur, _ := corrosion.GetHAPolicy(ctx, db)
	ts, err := corrosion.SetHAPolicy(ctx, db, capabilities.GrantForTest(t, capabilities.FeatureHADisarm), state, "test", "alice", cur.UpdatedAt)
	if err != nil {
		t.Fatalf("set HA %s: %v", state, err)
	}
	return ts
}

func fenceRows(t *testing.T, db *corrosion.Client) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id FROM fencing_log`)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

// L1, the fence: while disarmed, a host the quorum reports down is not
// fenced, its state is not touched, and the skip is counted, once per
// cycle, as ha_disarmed. Armed again, it is fenced and recovered.
//
// Mutation: skip the candidate and fence re-reads — the host is fenced while
// disarmed and this goes red.
func TestHADisarm_NoFenceWhileDisarmed(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	setHA(t, db, corrosion.HADisarmed)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFence))
	fm := newFakeMetrics()
	c.Metrics = fm

	c.run(ctx)
	c.run(ctx)
	if fences != 0 || fenceRows(t, db) != 0 {
		t.Fatalf("disarmed: %d fences, %d fencing_log rows", fences, fenceRows(t, db))
	}
	if got := hostState(t, db, ctx); got != "active" {
		t.Fatalf("disarmed: host state written to %q", got)
	}
	if fm.attempts[foKey(PhaseSkip, ResultSkipped, ErrHADisarmed)] != 2 {
		t.Fatalf("skip metric = %v, want one ha_disarmed skip per cycle", fm.attempts)
	}
	if !c.ha.loggedDisarm["down"] || c.holdReason["down"] != "recovery held: HA disarmed" {
		t.Fatalf("episode log %v, hold reason %q", c.ha.loggedDisarm, c.holdReason["down"])
	}

	setHA(t, db, corrosion.HAArmed)
	c.run(ctx)
	if fences != 1 || vmHost(t, db, ctx) != "alive" {
		t.Fatalf("armed again: %d fences, VM on %q", fences, vmHost(t, db, ctx))
	}
	if c.ha.loggedDisarm != nil {
		t.Fatal("the disarm episode's log memory outlived the arm")
	}
}

// L1, the resume: a fence an operator recorded after this coordinator's own
// failed one is not recovered from while disarmed.
func TestHADisarm_RecordedFenceIsNotResumed(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	lengthenStreak(t, db, ctx, 2*time.Minute)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence))
	c.run(ctx)
	ageFenceRows(t, db, ctx, 10*time.Second)
	operatorFences(t, db, ctx)

	setHA(t, db, corrosion.HADisarmed)
	c.run(ctx)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" {
		t.Fatalf("disarmed: recovery resumed from the recorded fence, VM on %q", got)
	}
	setHA(t, db, corrosion.HAArmed)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("armed again: VM still on %q", got)
	}
}

// A recovery held after its fence, the claim retries and the pause waits are
// all kept while disarmed, and run once HA is armed again.
//
// Mutation: drop the resume of a held recovery from the fence loop — the VM
// stays on the fenced host after the arm and this goes red.
func TestHADisarm_HeldWorkIsKeptAndRunsAfterArm(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFence))
	// HA is disarmed between the fence and its recovery.
	c.ha.beforeHold = func(site string) {
		if site == haSiteRecovery {
			setHA(t, db, corrosion.HADisarmed)
			c.ha.beforeHold = nil
		}
	}
	c.run(ctx)
	if fences != 1 || vmHost(t, db, ctx) != "down" || !c.ha.heldRecovery["down"] {
		t.Fatalf("fenced then disarmed: %d fences, VM on %q, held=%v", fences, vmHost(t, db, ctx), c.ha.heldRecovery)
	}
	c.claimRetry = map[string]bool{"down": true}
	c.pauseWaits = map[string]pauseWait{"down": {deadline: time.Now().Add(-time.Hour)}}
	c.run(ctx)
	if !c.claimRetry["down"] || c.pauseWaits["down"].deadline.IsZero() || !c.ha.heldRecovery["down"] {
		t.Fatalf("disarmed: held work consumed: claimRetry=%v pauseWaits=%v held=%v", c.claimRetry, c.pauseWaits, c.ha.heldRecovery)
	}
	if vmHost(t, db, ctx) != "down" {
		t.Fatal("disarmed: the VM moved")
	}
	delete(c.claimRetry, "down")
	delete(c.pauseWaits, "down")

	fm := newFakeMetrics()
	c.Metrics = fm
	setHA(t, db, corrosion.HAArmed)
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" || fences != 1 {
		t.Fatalf("armed again: VM on %q after %d fences, want recovered without a second fence", got, fences)
	}
	// Re-review 1 m-2: counted and bound like the successor's resume.
	if fm.attempts[foKey(PhaseRecovery, ResultOK, ErrRecoveryResumed)] != 1 || c.fencedOn["down"] == "" {
		t.Fatalf("resume bookkeeping: attempts %v, fencedOn %q", fm.attempts, c.fencedOn["down"])
	}
}

// Kept while disarmed: recoverHosts re-admits a host that answers.
func TestHADisarm_RecoverHostsRuns(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: "back", Address: "10.0.0.7", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "offline", FenceStrategy: "manual"}); err != nil {
		t.Fatal(err)
	}
	healthyObservers(t, db, "back", "h1", "h2", "h3")
	setHA(t, db, corrosion.HADisarmed)
	c := newTestCoordinator("coordinator", db)
	var sites []string
	c.ha.beforeHold = func(site string) { sites = append(sites, site) }
	c.run(ctx)
	if h, _ := corrosion.GetHost(ctx, db, "back"); h == nil || h.State != "active" {
		t.Fatalf("recoverHosts did not run while disarmed: %+v", h)
	}
	for _, s := range sites {
		if s == "pass" {
			t.Fatal("a recovery pass was consulted although the cycle read disarmed")
		}
	}
}

// An unreadable policy holds every fence; a read error decides nothing,
// recoverHosts included.
func TestHADisarm_UnreadableOrUnreadDecidesNothing(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	if err := db.Execute(ctx, `INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, NULL)
	 ON CONFLICT(key) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`, "ha", `not json`, "x", db.NowTS()); err != nil {
		t.Fatal(err)
	}
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFence))
	c.run(ctx)
	if fences != 0 {
		t.Fatal("an unreadable HA policy was read as armed")
	}

	db2, _ := seedDownHost(t, "ssh", trustSSH)
	if err := corrosion.InsertHost(ctx, db2, corrosion.HostRecord{Name: "back", Address: "10.0.0.7", SSHUser: "root",
		SSHPort: 22, GRPCPort: 7443, State: "offline", FenceStrategy: "manual"}); err != nil {
		t.Fatal(err)
	}
	healthyObservers(t, db2, "back", "h1", "h2", "h3", "alive", "coordinator")
	c2 := newTestCoordinator("coordinator", db2)
	c2.SetFencer(countingFencer(&fences, sshFence))
	c2.ha.read = func(context.Context) (corrosion.HAPolicy, error) {
		return corrosion.HAPolicy{}, errors.New("disk on fire")
	}
	c2.run(ctx)
	if fences != 0 {
		t.Fatal("a cycle that could not read the policy fenced")
	}
	if h, _ := corrosion.GetHost(ctx, db2, "back"); h == nil || h.State != "offline" {
		t.Fatalf("a cycle that could not read the policy decided a re-admission: %+v", h)
	}
	// The control: once the policy reads, the same cycle re-admits it.
	c2.ha.read = nil
	setHA(t, db2, corrosion.HADisarmed)
	c2.run(ctx)
	if h, _ := corrosion.GetHost(ctx, db2, "back"); h == nil || h.State != "active" {
		t.Fatalf("control: the fixture's host was not re-admitted: %+v", h)
	}
}

// The policy flips between candidate selection and the fence: no fence.
//
// Mutation: drop the re-read in failover() — the host is fenced and this goes
// red.
func TestHADisarm_FlipBeforeTheFence(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFence))
	c.ha.beforeHold = func(site string) {
		if site == haSiteFence {
			setHA(t, db, corrosion.HADisarmed)
		}
	}
	c.run(ctx)
	if fences != 0 || fenceRows(t, db) != 0 {
		t.Fatalf("HA disarmed just before the fence: %d fences", fences)
	}
}

// The policy flips immediately before each proof-mint site: nothing is
// minted, and the recovery waits for the arm.
//
// Mutation: remove the re-read at any one site — that site's case mints and
// goes red.
func TestHADisarm_FlipBeforeEachMintSite(t *testing.T) {
	gate := fakeFailoverGate{supports: map[string]bool{"alive": true, "live": true},
		enforced: map[string]bool{capabilities.SplitBrainGateV1: true}}
	proofs := func(t *testing.T, db *corrosion.Client, name string) int {
		rows, err := db.Query(context.Background(), `SELECT id FROM runtime_action_proofs WHERE target_name = ?`, name)
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}

	// The VM reschedule, at both of its re-reads.
	for _, site := range []string{haSiteReschedule, haSiteReschedule + "-mint"} {
		t.Run(site, func(t *testing.T) {
			db, ctx := seedDownHost(t, "ssh", trustSSH)
			c := newTestCoordinator("coordinator", db)
			c.SetFencer(countingFencer(new(int), sshFence))
			c.Gate = gate
			reached := false
			c.ha.beforeHold = func(s string) {
				if s == site {
					reached = true
					setHA(t, db, corrosion.HADisarmed)
				}
			}
			c.run(ctx)
			if !reached {
				t.Fatalf("site %s was never reached", site)
			}
			if n := proofs(t, db, "vm"); n != 0 || vmHost(t, db, ctx) != "down" {
				t.Fatalf("disarmed at %s: %d proofs, VM on %q", site, n, vmHost(t, db, ctx))
			}
		})
	}

	// The container image-recreate and restore-relocation, and the re-key of a
	// VM stopped by intent: each once armed (the control: it moves) and once
	// disarmed at its own site.
	ctFixture := func(t *testing.T) (*corrosion.Client, *corrosion.ContainerRecord) {
		db := newTestDB(t)
		if err := corrosion.UpsertContainer(context.Background(), db, corrosion.ContainerRecord{HostName: "dead", Name: "ct1",
			State: "running", Image: "alpine:3.19", OnHostFailure: "image-recreate"}); err != nil {
			t.Fatal(err)
		}
		if err := corrosion.InsertHost(context.Background(), db, corrosion.HostRecord{Name: "live", Address: "10.0.0.2",
			SSHUser: "root", SSHPort: 22, GRPCPort: 7443, State: "active", CPUTotal: 8, MemTotal: 8192}); err != nil {
			t.Fatal(err)
		}
		runsContainers(t, db, "live")
		ct, _ := corrosion.GetContainer(context.Background(), db, "dead", "ct1")
		return db, ct
	}
	for _, site := range []string{haSiteRecreate, haSiteRelocate, haSiteRekey} {
		for _, flip := range []bool{false, true} {
			t.Run(site+map[bool]string{false: "/armed", true: "/disarmed"}[flip], func(t *testing.T) {
				ctx := context.Background()
				var db *corrosion.Client
				var c *Coordinator
				reached := false
				hook := func(s string) {
					if s == site {
						reached = true
						if flip {
							setHA(t, db, corrosion.HADisarmed)
						}
					}
				}
				moved := false
				switch site {
				case haSiteRecreate, haSiteRelocate:
					var ct *corrosion.ContainerRecord
					db, ct = ctFixture(t)
					c = newTestCoordinator("coord", db)
					c.Gate = gate
					c.ha.beforeHold = hook
					if site == haSiteRecreate {
						c.imageRecreateOrSkip(ctx, &corrosion.HostRecord{Name: "dead"}, *ct, "live", nil)
					} else {
						c.startRelocation(ctx, &corrosion.HostRecord{Name: "dead"}, *ct, []corrosion.HostRecord{{Name: "live", State: "active"}})
					}
					moved = proofs(t, db, "ct1") > 0
				case haSiteRekey:
					db = newTestDB(t)
					for _, h := range []string{"down", "alive"} {
						if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: h, Address: "10.0.0.4", SSHUser: "root",
							SSHPort: 22, GRPCPort: 7443, State: "active"}); err != nil {
							t.Fatal(err)
						}
					}
					if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: "vm", HostName: "down",
						Spec: `{"on_host_failure":"restart-any"}`, State: "stopped", StateDetail: "stopped by operator"}, nil, nil); err != nil {
						t.Fatal(err)
					}
					c = newTestCoordinator("coordinator", db)
					c.run(ctx) // takes the lease; nothing is down
					c.ha.beforeHold = hook
					vm, _ := corrosion.GetVM(ctx, db, "vm")
					c.rekeyStoppedVM(ctx, "down", *vm, "alive", "")
					moved = vmHost(t, db, ctx) == "alive"
				}
				if !reached {
					t.Fatalf("site %s was never reached", site)
				}
				if moved == flip {
					t.Fatalf("%s with HA disarmed=%v: moved=%v", site, flip, moved)
				}
			})
		}
	}
}

// The stall alert names the hold.
func TestHADisarm_StallAlertSaysHeld(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	clock := time.Now()
	c := newTestCoordinator("coordinator", db)
	c.Now = func() time.Time { return clock }
	c.SetFencer(countingFencer(new(int), sshFence))
	var reason string
	c.OnRecoveryStalled = func(_, _, r string, _ int, _ time.Time) { reason = r }
	c.ha.beforeHold = func(site string) {
		if site == haSiteRecovery {
			setHA(t, db, corrosion.HADisarmed)
			c.ha.beforeHold = nil
		}
	}
	c.run(ctx)
	clock = clock.Add(recoveryStallAfter + time.Minute)
	holdLeaseThrough(t, db, ctx, clock)
	c.run(ctx)
	if !strings.Contains(reason, "recovery held: HA disarmed") {
		t.Fatalf("stall alert reason %q, want it to say the recovery is held by the disarm", reason)
	}
}

// ── L2: the peer veto ───────────────────────────────────────────────────────

// vetoCoord is a coordinator "a" over voters a..e with the peer veto wired to
// fakes: live is the set LiveVoters answers, answers the recorded Ready
// answers. read records which voters were read.
type vetoCoord struct {
	*Coordinator
	live    map[string]bool
	answers map[string]PeerHAAnswer
	read    map[string]bool
	asked   map[string]bool // the voters LiveVoters was asked about
	now     time.Time
}

func newVetoCoord(t *testing.T, voters ...string) *vetoCoord {
	t.Helper()
	if len(voters) == 0 {
		voters = []string{"a", "b", "c", "d", "e"}
	}
	db := newTestDB(t)
	v := &vetoCoord{Coordinator: NewCoordinator("a", db), live: map[string]bool{}, answers: map[string]PeerHAAnswer{},
		read: map[string]bool{}, now: time.Unix(1_900_000_000, 0)}
	vr := corrosion.VoterRegionSets{Voters: map[string]bool{}, RegionOf: map[string]string{}}
	for _, n := range voters {
		vr.Voters[n] = true
		vr.RegionOf[n] = "default"
	}
	v.scope = quorumView{vr: vr}
	v.Mono = func() time.Time { return v.now }
	v.LiveVoters = func(vs, _ map[string]bool) map[string]bool {
		v.asked = vs
		out := map[string]bool{}
		for n := range v.live {
			if vs[n] {
				out[n] = true
			}
		}
		return out
	}
	v.PeerHAState = func(p string) (PeerHAAnswer, bool) {
		v.read[p] = true
		a, ok := v.answers[p]
		return a, ok
	}
	v.ha.featureUsed.Store(true)
	return v
}

func (v *vetoCoord) setLive(names ...string) {
	v.live = map[string]bool{}
	for _, n := range names {
		v.live[n] = true
	}
}

// armedAnswer is a fresh, known, armed answer about row at.
func (v *vetoCoord) armedAnswer(at string) PeerHAAnswer {
	return PeerHAAnswer{Asked: v.now.Add(-time.Second), Known: true, PolicyAt: at}
}

func (v *vetoCoord) veto(own corrosion.HAPolicy) []haVeto {
	v.read = map[string]bool{}
	return v.haPeerVeto(context.Background(), "x", own)
}

func rules(vs []haVeto) string {
	var out []string
	for _, x := range vs {
		out = append(out, x.Voter+"="+x.Rule)
	}
	return strings.Join(out, ",")
}

func rfc(at time.Time) string { return at.UTC().Format(time.RFC3339Nano) }

// W_L2 is derived from the checker's exported constants: 20 s today.
func TestPeerAnswerWindow_DerivedFromTheChecker(t *testing.T) {
	want := time.Duration(health.SuspectThreshold)*(health.ProbeInterval+health.ProbeTimeout) + health.ProbeInterval + health.ProbeTimeout
	if PeerAnswerWindow != want || PeerAnswerWindow != 20*time.Second {
		t.Fatalf("PeerAnswerWindow = %s, want %s (20 s)", PeerAnswerWindow, want)
	}
}

// L2 reads exactly the voters the gate counts live, less itself, and no
// other: not a suspect voter, not a non-voter, not this node.
func TestPeerVeto_ReadsExactlyTheLiveVoters(t *testing.T) {
	v := newVetoCoord(t)
	v.setLive("a", "b", "c", "nonvoter")
	for _, n := range []string{"b", "c", "d", "e", "nonvoter"} {
		v.answers[n] = v.armedAnswer("")
	}
	// d is dead (suspect, so not live) and its last answer was a disarm.
	v.answers["d"] = PeerHAAnswer{Asked: v.now.Add(-time.Second), Known: true, Disarmed: true}
	if got := v.veto(corrosion.HAPolicy{State: corrosion.HAArmed}); got != nil {
		t.Fatalf("vetoes %s, want none (the dead voter's disarm is not read)", rules(got))
	}
	if len(v.read) != 2 || !v.read["b"] || !v.read["c"] {
		t.Fatalf("read %v, want exactly b and c", v.read)
	}
	if !v.asked["e"] || v.asked["nonvoter"] {
		t.Fatalf("LiveVoters was asked about %v, want the scope's voter set", v.asked)
	}
}

// A live voter's disarm vetoes, and one voter is enough.
//
// Mutation: veto only when a majority of the live voters disarm — the single
// disarm passes and this goes red.
func TestPeerVeto_OneDisarmedLiveVoterVetoes(t *testing.T) {
	v := newVetoCoord(t)
	v.setLive("a", "b", "c", "d", "e")
	for _, n := range []string{"b", "c", "d", "e"} {
		v.answers[n] = v.armedAnswer("")
	}
	v.answers["e"] = PeerHAAnswer{Asked: v.now.Add(-time.Second), Known: true, Disarmed: true, PolicyAt: rfc(v.now)}
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "e=disarmed" {
		t.Fatalf("vetoes %q, want e=disarmed", got)
	}
}

// R-I1: a confirming voter that has missed two probes is still healthy, and
// its 5 s old answer is still read and still vetoes.
//
// Mutations: put back a fixed 2 × checkInterval freshness filter, or read only
// fresh answers — the 5 s old disarm is skipped and this goes red.
func TestPeerVeto_AnAnswerFromAVoterThatMissedTwoProbesStillVetoes(t *testing.T) {
	v := newVetoCoord(t)
	v.setLive("a", "b", "c")
	v.answers["b"] = v.armedAnswer("")
	v.answers["c"] = PeerHAAnswer{Asked: v.now.Add(-5 * time.Second), Known: true, Disarmed: true, PolicyAt: rfc(v.now)}
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "c=disarmed" {
		t.Fatalf("vetoes %q, want c=disarmed", got)
	}
}

// An answer whose probe was sent more than W_L2 ago, from a voter still
// counted live, vetoes as stale — and so does a live voter with no answer.
func TestPeerVeto_StaleAnswerVetoes(t *testing.T) {
	v := newVetoCoord(t)
	v.setLive("a", "b", "c")
	v.answers["b"] = v.armedAnswer("")
	v.answers["c"] = PeerHAAnswer{Asked: v.now.Add(-PeerAnswerWindow - time.Millisecond), Known: true}
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "c=stale" {
		t.Fatalf("vetoes %q, want c=stale", got)
	}
	delete(v.answers, "c")
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "c=stale" {
		t.Fatalf("no answer: vetoes %q, want c=stale", got)
	}
}

// R2-I2: the intersection voter's only answer was SENT 1 s before the
// confirmation (received 2 s after it), so it says armed. Deciding once the
// handler's W_L2 has passed, that answer is older than W_L2 from its send time
// and vetoes as stale — it is not taken as post-confirmation evidence.
func TestPeerVeto_AnswerSentBeforeConfirmationIsStaleAfterTheWait(t *testing.T) {
	v := newVetoCoord(t)
	tc := v.now
	v.setLive("a", "b", "c")
	v.answers["b"] = PeerHAAnswer{Asked: tc.Add(-time.Second), Known: true} // armed, sent before T_c
	v.answers["c"] = PeerHAAnswer{Asked: tc.Add(-time.Second), Known: true}
	v.now = tc.Add(PeerAnswerWindow + 100*time.Millisecond) // the handler returned; X decides
	got := v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})
	if rules(got) != "b=stale,c=stale" {
		t.Fatalf("vetoes %q, want both answers stale", rules(got))
	}
}

// ha_known=false vetoes.
//
// Mutation: read ha_known=false as armed — this goes red.
func TestPeerVeto_UnknownVetoes(t *testing.T) {
	v := newVetoCoord(t)
	v.setLive("a", "b", "c")
	v.answers["b"] = v.armedAnswer("")
	v.answers["c"] = PeerHAAnswer{Asked: v.now.Add(-time.Second)}
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "c=unknown" {
		t.Fatalf("vetoes %q, want c=unknown", got)
	}
}

// R2-I1: fewer than a majority of the scope's voters counted live vetoes as
// no_quorum, whatever the answers say. A mid-cycle drop with the lease row
// still valid is exactly this.
//
// Mutation: remove the no_quorum check — this goes red.
func TestPeerVeto_NoQuorumVetoes(t *testing.T) {
	v := newVetoCoord(t)
	v.setLive("a", "b")
	v.answers["b"] = v.armedAnswer("")
	got := v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})
	if len(got) != 1 || got[0].Rule != VetoNoQuorum {
		t.Fatalf("vetoes %q, want no_quorum", rules(got))
	}
}

// R2-m1: self is never read and does not veto; its own replica is L1's.
func TestPeerVeto_SelfIsNotRead(t *testing.T) {
	v := newVetoCoord(t)
	v.setLive("a", "b", "c")
	v.answers["b"] = v.armedAnswer("")
	v.answers["c"] = v.armedAnswer("")
	if got := v.veto(corrosion.HAPolicy{State: corrosion.HAArmed}); got != nil || v.read["a"] {
		t.Fatalf("vetoes %q, read %v: self must not be read", rules(got), v.read)
	}
	// L1 covers self: its own disarmed replica holds.
	setHA(t, v.db, corrosion.HADisarmed)
	if !v.haHold(context.Background(), "x", haSiteFence) {
		t.Fatal("this node's own disarm did not hold")
	}
}

// The timestamp rule. A lagging voter's disarm OLDER than the arm this node
// holds is no veto (the re-arm case); one with the same timestamp and another
// state vetoes; with no row here any disarm vetoes; HLC and RFC3339 order by
// instant.
//
// Mutation: drop the timestamp rule — the lagging disarm vetoes and this goes
// red.
func TestPeerVeto_TimestampRule(t *testing.T) {
	t0 := time.Unix(1_900_000_000, 0)
	hlcAt := func(at time.Time) string { return hlc.Timestamp{PhysicalMS: at.UnixMilli(), NodeID: "z"}.String() }
	cases := []struct {
		name     string
		own      corrosion.HAPolicy
		peerAt   string
		wantVeto bool
	}{
		{"lagging disarm older than the held arm", corrosion.HAPolicy{State: corrosion.HAArmed, UpdatedAt: rfc(t0.Add(time.Minute))}, rfc(t0), false},
		{"equal timestamp, other state", corrosion.HAPolicy{State: corrosion.HAArmed, UpdatedAt: rfc(t0)}, rfc(t0), true},
		{"newer disarm", corrosion.HAPolicy{State: corrosion.HAArmed, UpdatedAt: rfc(t0)}, rfc(t0.Add(time.Second)), true},
		{"no row here", corrosion.HAPolicy{State: corrosion.HAArmed}, rfc(t0), true},
		{"held HLC arm newer than an RFC3339 disarm", corrosion.HAPolicy{State: corrosion.HAArmed, UpdatedAt: hlcAt(t0.Add(time.Second))}, rfc(t0), false},
		{"held RFC3339 arm older than an HLC disarm", corrosion.HAPolicy{State: corrosion.HAArmed, UpdatedAt: rfc(t0)}, hlcAt(t0.Add(time.Second)), true},
	}
	for _, tc := range cases {
		v := newVetoCoord(t)
		v.setLive("a", "b", "c")
		v.answers["b"] = v.armedAnswer(tc.own.UpdatedAt)
		v.answers["c"] = PeerHAAnswer{Asked: v.now.Add(-time.Second), Known: true, Disarmed: true, PolicyAt: tc.peerAt}
		if got := v.veto(tc.own); (got != nil) != tc.wantVeto {
			t.Errorf("%s: vetoes %q, want veto=%v", tc.name, rules(got), tc.wantVeto)
		}
	}
}

// Region scope: L is the target's region's live voters, and q its majority.
func TestPeerVeto_RegionScopeCountsTheTargetsRegion(t *testing.T) {
	v := newVetoCoord(t, "a", "e1", "e2", "w1", "w2", "w3")
	v.scope.region = true
	for n, r := range map[string]string{"a": "east", "e1": "east", "e2": "east", "w1": "west", "w2": "west", "w3": "west"} {
		v.scope.vr.RegionOf[n] = r
	}
	v.scope.vr.RegionOf["x"] = "west"
	v.setLive("a", "e1", "e2", "w1") // a cluster majority, but one west voter of three
	v.answers["w1"] = v.armedAnswer("")
	got := v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})
	if len(got) != 1 || got[0].Rule != VetoNoQuorum || len(v.asked) != 3 || !v.asked["w3"] {
		t.Fatalf("vetoes %q over %v, want no_quorum over west's voters", rules(got), v.asked)
	}
}

// Before this replica holds the ha_disarm used record no `ha` row can exist
// anywhere, so the veto is not applied: a rolling upgrade into this build,
// whose older peers answer without the HA fields, holds nothing back.
func TestPeerVeto_NotAppliedBeforeTheFeatureIsUsed(t *testing.T) {
	v := newVetoCoord(t)
	v.ha.featureUsed.Store(false)
	v.setLive("a", "b", "c")
	v.answers["b"] = PeerHAAnswer{Asked: v.now.Add(-time.Second)}
	v.answers["c"] = PeerHAAnswer{Asked: v.now.Add(-time.Second)}
	if got := v.veto(corrosion.HAPolicy{State: corrosion.HAArmed}); got != nil {
		t.Fatalf("vetoes %q before the feature was used", rules(got))
	}
	info, _ := capabilities.LookupFeature(capabilities.FeatureHADisarm)
	v.db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.RecordReleaseFeatureUse(context.Background(), v.db, info.Token, string(capabilities.FeatureHADisarm), "a", true); err != nil {
		t.Fatal(err)
	}
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "b=unknown,c=unknown" {
		t.Fatalf("after the first use: vetoes %q, want both unknown", got)
	}
}

// Review I-1: a coordinator whose replica lacks the used record — a host
// absent at the first use, or added since — still honours a live voter's
// disarm. Only a build with the feature that holds a row can answer
// disarmed, so the rule cannot veto falsely during a rolling upgrade; the
// fail-safe rules (stale, unknown, no_quorum) stay off until the record is
// here.
//
// Mutation: put the whole-L2 gate back — the disarm passes and this goes red.
func TestPeerVeto_DisarmedVetoesBeforeTheFeatureIsUsed(t *testing.T) {
	v := newVetoCoord(t)
	v.ha.featureUsed.Store(false)
	v.setLive("a", "b", "c")
	v.answers["b"] = PeerHAAnswer{Asked: v.now.Add(-time.Hour)} // old and unknown: not a veto yet
	v.answers["c"] = PeerHAAnswer{Asked: v.now.Add(-time.Hour), Known: true, Disarmed: true, PolicyAt: rfc(v.now)}
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "c=disarmed" {
		t.Fatalf("no used record here: vetoes %q, want c=disarmed only", got)
	}
	// Fewer than a majority live, no used record: the disarm still vetoes.
	v.setLive("a", "c")
	if got := rules(v.veto(corrosion.HAPolicy{State: corrosion.HAArmed})); got != "c=disarmed" {
		t.Fatalf("no used record, no majority: vetoes %q, want c=disarmed only", got)
	}
}

// Review I-2: a recovery a disarm held after a verified fence is not resumed
// on that fence once it has aged past recentFenceWindow: the host is fenced
// again before anything moves, as every other resume from a recorded fence.
//
// Mutation: resume the held recovery directly on the original fence — one
// fence, the VM moves, and this goes red.
func TestHADisarm_HeldRecoveryIsRefencedWhenItsFenceAged(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	moved := -1
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		if moved < 0 && vmHost(t, db, ctx) != "down" {
			moved = fences
		}
		return fence.Result{Method: "ipmi", Detail: "verified off", Success: true}
	})
	c.ha.beforeHold = func(site string) {
		if site == haSiteRecovery {
			setHA(t, db, corrosion.HADisarmed)
			c.ha.beforeHold = nil
		}
	}
	c.run(ctx)
	if fences != 1 || vmHost(t, db, ctx) != "down" || !c.ha.heldRecovery["down"] {
		t.Fatalf("fenced then disarmed: %d fences, VM on %q, held=%v", fences, vmHost(t, db, ctx), c.ha.heldRecovery)
	}
	// The disarm lasted past recentFenceWindow; the host stayed down.
	ageFenceRows(t, db, ctx, recentFenceWindow+time.Minute)
	lengthenStreak(t, db, ctx, recentFenceWindow+2*time.Minute)
	setHA(t, db, corrosion.HAArmed)
	c.run(ctx)
	if fences != 2 {
		t.Fatalf("after the arm: %d fences, want the aged fence renewed (2) before any recovery", fences)
	}
	if moved != -1 {
		t.Fatalf("the VM moved before the re-fence (at fence %d)", moved)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("after the re-fence the VM is on %q, want alive", got)
	}
}

// Re-review 1 I-1: a re-fence of a held recovery that does not run (here, a
// local stall on the first armed cycle) keeps the held mark, so the next
// cycle fences again and recovers instead of leaving the host cached.
//
// Mutation: drop the held mark before the outcome is known — the second
// armed cycle does nothing and this goes red.
func TestHADisarm_HeldRecoveryDeferredRefenceIsRetried(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return fence.Result{Method: "ipmi", Detail: "verified off", Success: true}
	})
	c.ha.beforeHold = func(site string) {
		if site == haSiteRecovery {
			setHA(t, db, corrosion.HADisarmed)
			c.ha.beforeHold = nil
		}
	}
	c.run(ctx)
	ageFenceRows(t, db, ctx, recentFenceWindow+time.Minute)
	lengthenStreak(t, db, ctx, recentFenceWindow+2*time.Minute)
	setHA(t, db, corrosion.HAArmed)
	stalled := true
	c.LocalStall = func() bool { return stalled }
	c.run(ctx)
	if fences != 1 || vmHost(t, db, ctx) != "down" || !c.ha.heldRecovery["down"] {
		t.Fatalf("stalled armed cycle: %d fences, VM on %q, held=%v; want no fence and the mark kept",
			fences, vmHost(t, db, ctx), c.ha.heldRecovery)
	}
	stalled = false
	c.run(ctx)
	if fences != 2 || vmHost(t, db, ctx) != "alive" {
		t.Fatalf("next armed cycle: %d fences, VM on %q; want the re-fence and the recovery", fences, vmHost(t, db, ctx))
	}
}

// Re-review 2 m-1: a one-off read error on the fence log never lets an aged
// verified fence resume without a re-fence. The judgement is made on the one
// read that was error-checked; an error keeps the mark (with the reason on the
// stall alert, m-2), and the next cycle fences again before anything moves.
//
// Mutation: judge on a second read after the error check — the first cycle
// resumes on the aged fence and this goes red.
func TestHADisarm_HeldRecoveryOneOffReadErrorNeverSkipsTheRefence(t *testing.T) {
	db, ctx := seedDownHost(t, "ipmi", nil)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	moved := -1
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		if moved < 0 && vmHost(t, db, ctx) != "down" {
			moved = fences
		}
		return fence.Result{Method: "ipmi", Detail: "verified off", Success: true}
	})
	c.ha.beforeHold = func(site string) {
		if site == haSiteRecovery {
			setHA(t, db, corrosion.HADisarmed)
			c.ha.beforeHold = nil
		}
	}
	c.run(ctx)
	ageFenceRows(t, db, ctx, recentFenceWindow+time.Minute)
	lengthenStreak(t, db, ctx, recentFenceWindow+2*time.Minute)
	setHA(t, db, corrosion.HAArmed)
	failed := false
	c.ha.readErr = func(what string) error {
		if what == "fence log" && !failed {
			failed = true
			return errors.New("injected: database is locked")
		}
		return nil
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "down" || fences != 1 {
		t.Fatalf("cycle with the read error: VM on %q after %d fences; want nothing moved and no fence", got, fences)
	}
	if !c.ha.heldRecovery["down"] || !strings.Contains(c.holdReason["down"], "could not be read") {
		t.Fatalf("read error: held=%v reason %q; want the mark kept and the read error on the stall alert",
			c.ha.heldRecovery, c.holdReason["down"])
	}
	c.run(ctx)
	if fences != 2 || moved != -1 || vmHost(t, db, ctx) != "alive" {
		t.Fatalf("next cycle: %d fences, moved at fence %d, VM on %q; want the re-fence before the recovery",
			fences, moved, vmHost(t, db, ctx))
	}
}

// Re-review 2 m-2: every keep-branch on a read error names the read error on
// the stall alert.
func TestHADisarm_HeldRecoveryReadErrorsNameThemselves(t *testing.T) {
	for _, what := range []string{"host", "fence log", "health"} {
		db, ctx := seedDownHost(t, "ssh", trustSSH)
		c := newTestCoordinator("coordinator", db)
		c.SetFencer(countingFencer(new(int), sshFence))
		c.ha.beforeHold = func(site string) {
			if site == haSiteRecovery {
				setHA(t, db, corrosion.HADisarmed)
				c.ha.beforeHold = nil
			}
		}
		c.run(ctx)
		setHA(t, db, corrosion.HAArmed)
		c.ha.readErr = func(w string) error {
			if w == what {
				return errors.New("injected")
			}
			return nil
		}
		c.run(ctx)
		if vmHost(t, db, ctx) != "down" || !c.ha.heldRecovery["down"] || !strings.Contains(c.holdReason["down"], "could not be read") {
			t.Errorf("%s read error: VM on %q, held=%v, reason %q", what, vmHost(t, db, ctx), c.ha.heldRecovery, c.holdReason["down"])
		}
	}
}

// Re-review 1 I-1: a read error while judging a held recovery keeps the mark;
// the next cycle, with the rows readable, recovers.
func TestHADisarm_HeldRecoveryReadErrorIsRetried(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	c := newTestCoordinator("coordinator", db)
	c.SetFencer(countingFencer(new(int), sshFence))
	c.ha.beforeHold = func(site string) {
		if site == haSiteRecovery {
			setHA(t, db, corrosion.HADisarmed)
			c.ha.beforeHold = nil
		}
	}
	c.run(ctx)
	setHA(t, db, corrosion.HAArmed)
	if _, err := db.DB().ExecContext(ctx, `ALTER TABLE fencing_log RENAME TO fencing_log_gone`); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if vmHost(t, db, ctx) != "down" || !c.ha.heldRecovery["down"] {
		t.Fatalf("fence log unreadable: VM on %q, held=%v; want nothing moved and the mark kept", vmHost(t, db, ctx), c.ha.heldRecovery)
	}
	if _, err := db.DB().ExecContext(ctx, `ALTER TABLE fencing_log_gone RENAME TO fencing_log`); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Fatalf("fence log readable again: VM on %q, want alive", got)
	}
}

// Re-review 1 m-1: after the arm, a held recovery whose unverified (SSH)
// fence no longer stands — the host was seen answering after it — moves
// nothing and fences nothing; the decline is final. (A verified fence that no
// longer stands is fenced again instead: TestHADisarm_HeldRecoveryIsRefenced.)
//
// Mutation: resume the held recovery directly — the VM moves and this goes
// red.
func TestHADisarm_HeldRecoveryOnAFenceThatNoLongerStandsMovesNothing(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		fences++
		return sshFence
	})
	c.ha.beforeHold = func(site string) {
		if site == haSiteRecovery {
			setHA(t, db, corrosion.HADisarmed)
			c.ha.beforeHold = nil
		}
	}
	c.run(ctx)
	ageFenceRows(t, db, ctx, time.Minute)
	lengthenStreak(t, db, ctx, 5*time.Minute)
	// Someone saw the host answer after the fence: it was powered on again.
	if err := db.Execute(ctx, `INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES ('outsider', 'down', 'unready', 1, NULL, strftime('%Y-%m-%dT%H:%M:%SZ','now'))`); err != nil {
		t.Fatal(err)
	}
	setHA(t, db, corrosion.HAArmed)
	c.run(ctx)
	c.run(ctx)
	if fences != 1 || vmHost(t, db, ctx) != "down" {
		t.Fatalf("after the arm: %d fences, VM on %q; want no second fence and nothing moved", fences, vmHost(t, db, ctx))
	}
	if c.ha.heldRecovery["down"] {
		t.Fatal("a decline on readable rows left the held mark")
	}
	if !strings.Contains(c.holdReason["down"], "no longer stands") {
		t.Fatalf("hold reason %q", c.holdReason["down"])
	}
}

// A veto while this node's own replica is armed raises ha_disarm_peer_veto
// and litevirt_ha_peer_veto naming the voter and the rule; a no_quorum veto
// is counted as a loss of quorum and raises neither (R3-m3). Both resolve once
// a cycle passes without a veto.
func TestPeerVeto_VisibleAndResolves(t *testing.T) {
	ctx := context.Background()
	v := newVetoCoord(t)
	fm := newFakeMetrics()
	v.Metrics = fm
	var gauge bool
	v.HAPeerVetoGauge = func(on bool) { gauge = on }
	cond := func() corrosion.HealthCondition {
		row, _, _ := corrosion.GetHealthCondition(ctx, v.db, corrosion.HADisarmEvaluator, corrosion.CondHAPeerVeto, "host", "a")
		return row
	}

	v.setLive("a", "b")
	if !v.haHold(ctx, "x", haSiteFence) {
		t.Fatal("no_quorum did not hold")
	}
	v.syncHAVeto(ctx)
	if gauge || cond().Lifecycle == corrosion.ConditionConfirmed || fm.attempts[foKey(PhaseQuorum, ResultRefused, ErrNoQuorum)] != 1 {
		t.Fatalf("no_quorum: gauge=%v cond=%+v metrics=%v", gauge, cond(), fm.attempts)
	}

	v.ha.cycleVetoes = nil
	v.setLive("a", "b", "c")
	v.answers["b"] = v.armedAnswer("")
	v.answers["c"] = PeerHAAnswer{Asked: v.now.Add(-time.Second), Known: true, Disarmed: true, PolicyAt: "T9"}
	if !v.haHold(ctx, "x", haSiteFence) {
		t.Fatal("a live voter's disarm did not hold")
	}
	v.syncHAVeto(ctx)
	if c := cond(); !gauge || c.Lifecycle != corrosion.ConditionConfirmed || !strings.Contains(c.Evidence, `c: disarmed (ha_policy_at "T9")`) ||
		fm.attempts[foKey(PhaseSkip, ResultSkipped, ErrHAPeerVeto)] != 1 {
		t.Fatalf("peer veto: gauge=%v cond=%+v metrics=%v", gauge, c, fm.attempts)
	}

	v.ha.cycleVetoes = nil
	v.answers["c"] = v.armedAnswer("")
	if v.haHold(ctx, "x", haSiteFence) {
		t.Fatal("held with every live voter armed")
	}
	v.syncHAVeto(ctx)
	if gauge || cond().Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("resolved: gauge=%v cond=%+v", gauge, cond())
	}
}

// R3-m2: an armed cluster in which this node counts the scope's quorum live,
// every live voter answering armed and fresh, still fences.
func TestPeerVeto_ArmedClusterWithQuorumStillFences(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	c := newTestCoordinator("coordinator", db)
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFence))
	c.ha.featureUsed.Store(true)
	c.LiveVoters = func(vs, _ map[string]bool) map[string]bool {
		return map[string]bool{"coordinator": true, "alive": true}
	}
	c.PeerHAState = func(p string) (PeerHAAnswer, bool) {
		return PeerHAAnswer{Asked: time.Now(), Known: true}, true
	}
	c.run(ctx)
	if fences != 1 || vmHost(t, db, ctx) != "alive" {
		t.Fatalf("armed, quorum live: %d fences, VM on %q", fences, vmHost(t, db, ctx))
	}
}

// F1 (lab 1, 3241dda4): a host that fails while HA is disarmed is held at the
// candidate site, before any fence, so it stays recorded active and
// strandedByHost (fenced and offline hosts only) never names it. The stall
// alert still names it, held by the disarm, recoveryStallAfter after the hold
// was first seen — not from a fence row of an earlier outage. Nothing is
// fenced, written or moved. Armed again, it is fenced and recovered, and the
// alert ends.
//
// Mutation: pass strandedByHost's count alone to alertStalledRecoveries (no
// heldBeforeFence) — no alert, and this goes red. Start the unfenced clock
// from the newest fence row — the alert comes on the first cycle, red.
func TestHADisarm_StallAlertNamesHostHeldBeforeFence(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	old := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := db.Execute(ctx,
		`INSERT INTO fencing_log (id, host_name, method, result, timestamp, detail) VALUES (?, ?, ?, ?, ?, ?)`,
		"old", "down", "ssh", "fenced", old, "an earlier outage [path=managed]"); err != nil {
		t.Fatal(err)
	}
	setHA(t, db, corrosion.HADisarmed)
	clock := time.Now()
	start := clock
	c := newTestCoordinator("coordinator", db)
	c.Now = func() time.Time { return clock }
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFence))
	type alert struct {
		host, reason string
		pending      int
		since        time.Time
	}
	var alerts []alert
	c.OnRecoveryStalled = func(host, _, reason string, pending int, since time.Time) {
		alerts = append(alerts, alert{host, reason, pending, since})
	}
	tick := func(d time.Duration) {
		t.Helper()
		clock = clock.Add(d)
		holdLeaseThrough(t, db, ctx, clock)
		if err := db.Execute(ctx, `UPDATE host_health SET updated_at = ? WHERE target = 'down'`,
			clock.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		c.run(ctx)
	}

	c.run(ctx)
	if len(alerts) != 0 {
		t.Fatalf("alerted on the first held cycle (the clock started from an older fence row?): %+v", alerts)
	}
	tick(recoveryStallAfter / 2)
	if len(alerts) != 0 {
		t.Fatalf("alerted before recoveryStallAfter: %+v", alerts)
	}
	tick(recoveryStallAfter/2 + time.Second)
	if len(alerts) != 1 {
		t.Fatalf("stall alerts for a host held before its fence: %+v, want one", alerts)
	}
	if a := alerts[0]; a.host != "down" || a.reason != "recovery held: HA disarmed; held: vm/vm" || a.pending != 1 || !a.since.Equal(start) {
		t.Fatalf("alert = %+v, want host down, reason %q, pending 1, since %v", a, "recovery held: HA disarmed", start)
	}
	if fences != 0 || fenceRows(t, db) != 1 || hostState(t, db, ctx) != "active" || vmHost(t, db, ctx) != "down" {
		t.Fatalf("disarmed: %d fences, %d fencing_log rows, host %q, VM on %q — the alert must not act",
			fences, fenceRows(t, db), hostState(t, db, ctx), vmHost(t, db, ctx))
	}
	tick(time.Minute)
	if len(alerts) != 1 {
		t.Fatalf("alerted again inside recoveryStallRepeat: %+v", alerts)
	}

	setHA(t, db, corrosion.HAArmed)
	tick(time.Second)
	if fences != 1 || vmHost(t, db, ctx) != "alive" {
		t.Fatalf("armed again: %d fences, VM on %q", fences, vmHost(t, db, ctx))
	}
	if len(c.stallSince) != 0 || len(c.stallUnfenced) != 0 {
		t.Fatalf("the stall clock outlived the recovery: %v %v", c.stallSince, c.stallUnfenced)
	}
}

// A host held unfenced, then armed and fenced, starts its stall clock again
// from that fence: the alert it raised while held does not stand in for the
// recovery's own, which comes recoveryStallAfter after the fence and names
// what holds it now.
//
// Mutation: keep the held clock across the fence (drop the stallUnfenced
// reset) — the post-fence alert waits out recoveryStallRepeat, and this goes
// red.
func TestHADisarm_HeldClockRestartsAtTheFence(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	setHA(t, db, corrosion.HADisarmed)
	// fencing_log rows carry the wall clock: start early enough that the
	// fence, after the held alert, lands at the virtual clock's now.
	clock := time.Now().Add(-recoveryStallAfter - 2*time.Second)
	c := newTestCoordinator("coordinator", db)
	c.Now = func() time.Time { return clock }
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFailedFence))
	var reasons []string
	var sinces []time.Time
	c.OnRecoveryStalled = func(_, _, reason string, _ int, since time.Time) {
		reasons = append(reasons, reason)
		sinces = append(sinces, since)
	}
	tick := func(d time.Duration) {
		t.Helper()
		clock = clock.Add(d)
		holdLeaseThrough(t, db, ctx, clock)
		if err := db.Execute(ctx, `UPDATE host_health SET updated_at = ? WHERE target = 'down'`,
			clock.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		c.run(ctx)
	}
	tick(0)
	tick(recoveryStallAfter + time.Second)
	if len(reasons) != 1 || reasons[0] != "recovery held: HA disarmed; held: vm/vm" {
		t.Fatalf("held alerts = %q, want one held by the disarm", reasons)
	}

	setHA(t, db, corrosion.HAArmed)
	tick(time.Second)
	if fences != 1 {
		t.Fatalf("armed: %d fences, want 1", fences)
	}
	fencedAt := clock.Add(-3 * time.Second)
	if len(reasons) != 1 {
		t.Fatalf("alerted on the cycle that fenced: %q", reasons)
	}
	tick(recoveryStallAfter + time.Second)
	if len(reasons) != 2 || strings.HasPrefix(reasons[1], "recovery held: HA disarmed") || sinces[1].Before(fencedAt) {
		t.Fatalf("alerts after the fence: %q since %v, want a second one, from the fence at %v, naming what holds it now",
			reasons, sinces, fencedAt)
	}
}

// A host restarting for an upgrade is not fenced inside upgradingTimeout
// armed or not, so a hold over it is no stall: it is named held only once it
// has sat 'upgrading' past the timeout (stuck), recoveryStallAfter after that.
//
// Mutation: admit an 'upgrading' host into heldBeforeFence whatever its age —
// it alerts inside the upgrade grace, and this goes red.
func TestHADisarm_UpgradingHostIsNotNamedHeldInsideItsGrace(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", trustSSH)
	if err := corrosion.UpdateHostState(ctx, db, "down", "upgrading"); err != nil {
		t.Fatal(err)
	}
	setHA(t, db, corrosion.HADisarmed)
	clock := time.Now()
	c := newTestCoordinator("coordinator", db)
	c.Now = func() time.Time { return clock }
	fences := 0
	c.SetFencer(countingFencer(&fences, sshFence))
	var reasons []string
	c.OnRecoveryStalled = func(_, _, reason string, _ int, _ time.Time) { reasons = append(reasons, reason) }
	tick := func(d time.Duration) {
		t.Helper()
		clock = clock.Add(d)
		holdLeaseThrough(t, db, ctx, clock)
		if err := db.Execute(ctx, `UPDATE host_health SET updated_at = ? WHERE target = 'down'`,
			clock.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
		c.run(ctx)
	}
	tick(0)
	tick(recoveryStallAfter + time.Second)
	tick(30 * time.Second)
	if len(reasons) != 0 {
		t.Fatalf("alerted for a host inside its upgrade grace (%v): %q", upgradingTimeout, reasons)
	}
	tick(upgradingTimeout - recoveryStallAfter - 30*time.Second) // past the grace: stuck
	tick(recoveryStallAfter + time.Second)
	if len(reasons) != 1 || reasons[0] != "recovery held: HA disarmed; held: vm/vm" {
		t.Fatalf("a host stuck upgrading past %v: alerts %q, want one held by the disarm", upgradingTimeout, reasons)
	}
	if fences != 0 {
		t.Fatalf("%d fences while disarmed", fences)
	}
}
