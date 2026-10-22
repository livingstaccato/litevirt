package failover

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// needsFence gives host a workload that needs its fence and is never moved: a
// restart-same VM on a host-local disk, held for its host after the fence. A
// test whose subject is what a fence does, not whether one is needed, adds it
// so the fence runs (holdUnneededFence).
func needsFence(t *testing.T, db *corrosion.Client, host string) {
	t.Helper()
	name := "held-for-" + host
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
		Name: name, HostName: host, State: "running", Spec: `{"on_host_failure":"restart-same"}`,
	}, nil, []corrosion.DiskRecord{{VMName: name, DiskName: "root", HostName: host,
		Path: "/var/lib/litevirt/disks/" + name + ".qcow2", SizeBytes: 1 << 30}}); err != nil {
		t.Fatalf("InsertVM %s: %v", name, err)
	}
}

// recordingFencer is stubFencer(true) that records each host it fenced.
func recordingFencer(fenced *[]string) Fencer {
	return func(_ context.Context, h fence.HostConfig) fence.Result {
		*fenced = append(*fenced, h.Name)
		return fence.Result{Method: "test", Detail: "stub", Success: true}
	}
}

// fenceHeldRow reads host's ha.fence_held; open reports whether it is raised
// and not resolved.
func fenceHeldRow(t *testing.T, db *corrosion.Client, host string) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), db, RefenceEvaluator, CondFenceHeld, "host", host)
	if err != nil {
		t.Fatalf("read %s: %v", CondFenceHeld, err)
	}
	return row, ok && row.Lifecycle != corrosion.ConditionResolved
}

func hostFenceRows(t *testing.T, db *corrosion.Client, host string) int {
	t.Helper()
	rows, err := db.Query(context.Background(), `SELECT id FROM fencing_log WHERE host_name = ?`, host)
	if err != nil {
		t.Fatal(err)
	}
	return len(rows)
}

func heldFixture(t *testing.T, policy string) (*corrosion.Client, *Coordinator, *[]string, *fakeMetrics) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "bad", Address: "10.0.0.99", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "best-effort",
	}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "mtl", HostName: "bad", State: "running", Spec: `{"on_host_failure":"` + policy + `"}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	downObservers(t, db, "bad", "h1", "h2", "h3")
	var fenced []string
	c := NewCoordinator("coordinator", db)
	c.SetFencer(recordingFencer(&fenced))
	fm := newFakeMetrics()
	c.Metrics = fm
	return db, c, &fenced, fm
}

// TestFenceHeld_NothingRecoverableIsRecordedOfflineNotFenced: a quorum fails a
// host whose only VM is on_host_failure: none. It is recorded offline, never
// fenced, no fencing_log row is written, and ha.fence_held names the VM left
// running. Cycles after keep it so.
//
// Mutation: make holdUnneededFence return false — the host is fenced.
func TestFenceHeld_NothingRecoverableIsRecordedOfflineNotFenced(t *testing.T) {
	db, c, fenced, fm := heldFixture(t, "none")
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		c.run(ctx)
	}
	if len(*fenced) != 0 {
		t.Fatalf("fenced %v; nothing on bad needs a fence", *fenced)
	}
	if h, _ := corrosion.GetHost(ctx, db, "bad"); h == nil || h.State != "offline" {
		t.Fatalf("bad is %+v, want offline", h)
	}
	if n := hostFenceRows(t, db, "bad"); n != 0 {
		t.Fatalf("%d fencing_log rows for a held fence, want none: nothing may read the hold as a fence", n)
	}
	row, open := fenceHeldRow(t, db, "bad")
	if !open {
		t.Fatalf("%s not raised: %+v", CondFenceHeld, row)
	}
	var ev fenceHeldEvidence
	if err := json.Unmarshal([]byte(row.Evidence), &ev); err != nil {
		t.Fatalf("evidence %q: %v", row.Evidence, err)
	}
	if len(ev.Workloads) != 1 || !strings.Contains(ev.Workloads[0], "vm/mtl") || !strings.Contains(ev.Workloads[0], "none") {
		t.Errorf("evidence workloads %v, want vm/mtl with its policy", ev.Workloads)
	}
	if row.Severity != corrosion.SeverityWarning {
		t.Errorf("severity %q, want warning", row.Severity)
	}
	if got := fm.attempts[foKey(PhaseSkip, ResultSkipped, ErrNothingRecoverable)]; got != 3 {
		t.Errorf("nothing_recoverable skips = %d, want 3: every cycle decides afresh (attempts=%v)", got, fm.attempts)
	}
	if c.fenced["bad"] {
		t.Error("a held host was cached as handled; the next cycle would not re-check it")
	}
}

// TestFenceHeld_RecoverableVMStillFences: the same host with a restart-any VM
// is fenced, as before.
func TestFenceHeld_RecoverableVMStillFences(t *testing.T) {
	db, c, fenced, _ := heldFixture(t, "restart-any")
	c.run(context.Background())
	if len(*fenced) != 1 {
		t.Fatalf("fenced %v, want bad once", *fenced)
	}
	if _, open := fenceHeldRow(t, db, "bad"); open {
		t.Errorf("%s raised for a host that was fenced", CondFenceHeld)
	}
}

// TestFenceHeld_PolicyChangedDuringTheHoldFencesNextCycle: held, then the VM's
// policy becomes restart-any. The next cycle fences it — the hold is not
// cached as the terminal-state skip of an offline host — and the condition
// resolves.
//
// Mutation: drop `!held` from the terminal-state skip — the offline host is
// cached as handled and never fenced.
func TestFenceHeld_PolicyChangedDuringTheHoldFencesNextCycle(t *testing.T) {
	db, c, fenced, _ := heldFixture(t, "none")
	ctx := context.Background()
	c.run(ctx)
	if len(*fenced) != 0 {
		t.Fatalf("premise: fenced %v", *fenced)
	}
	if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'mtl'`, `{"on_host_failure":"restart-any"}`); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if len(*fenced) != 1 {
		t.Fatalf("fenced %v after mtl became recoverable, want bad once", *fenced)
	}
	if _, open := fenceHeldRow(t, db, "bad"); open {
		t.Errorf("%s still open after the fence", CondFenceHeld)
	}
}

// TestFenceHeld_ASuccessorRechecksTheHold: a coordinator that never saw the
// hold (a new lease holder, a restart) finds bad offline with no fence on
// record. The open condition sends it down the decision, not the terminal
// skip, so a VM made recoverable since is fenced for.
func TestFenceHeld_ASuccessorRechecksTheHold(t *testing.T) {
	db, c, _, _ := heldFixture(t, "none")
	ctx := context.Background()
	c.run(ctx)
	if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'mtl'`, `{"on_host_failure":"restart-any"}`); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
		t.Fatal(err)
	}
	var fenced []string
	succ := NewCoordinator("coordinator", db)
	succ.SetFencer(recordingFencer(&fenced))
	succ.run(ctx)
	if len(fenced) != 1 {
		t.Fatalf("the successor fenced %v, want bad once", fenced)
	}
}

// TestFenceHeld_WorkWaitingOnTheFenceStillFences: work recoverableOn leaves
// out on purpose still needs the fence: a none-policy VM mid-migration, a VM
// stopped by intent on shared storage (moved off still stopped), a container
// carrying a relocate-restore marker, a pending recovery proof.
func TestFenceHeld_WorkWaitingOnTheFenceStillFences(t *testing.T) {
	cases := map[string]func(t *testing.T, db *corrosion.Client){
		"migrating VM": func(t *testing.T, db *corrosion.Client) {
			if err := db.Execute(context.Background(), `UPDATE vms SET state = 'migrating' WHERE name = 'mtl'`); err != nil {
				t.Fatal(err)
			}
		},
		"pending VM": func(t *testing.T, db *corrosion.Client) {
			if err := db.Execute(context.Background(), `UPDATE vms SET state = 'pending' WHERE name = 'mtl'`); err != nil {
				t.Fatal(err)
			}
		},
		"starting VM": func(t *testing.T, db *corrosion.Client) {
			if err := db.Execute(context.Background(), `UPDATE vms SET state = 'starting' WHERE name = 'mtl'`); err != nil {
				t.Fatal(err)
			}
		},
		"relocating container": func(t *testing.T, db *corrosion.Client) {
			if err := corrosion.UpsertContainer(context.Background(), db, corrosion.ContainerRecord{
				HostName: "bad", Name: "web", State: "relocating", Image: "alpine:3.19",
				CPULimit: 1, MemMiB: 128, Project: "p1", OnHostFailure: "none",
			}); err != nil {
				t.Fatal(err)
			}
		},
		"stopped VM on shared storage": func(t *testing.T, db *corrosion.Client) {
			if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{
				Name: "sv", HostName: "bad", State: "stopped", StateDetail: "operator-stop",
				Spec: `{"on_host_failure":"restart-any"}`,
			}, nil, []corrosion.DiskRecord{{VMName: "sv", DiskName: "root", HostName: "bad",
				Path: "/mnt/nfs/sv.qcow2", SizeBytes: 1 << 30, StorageType: "nfs", StorageVolume: "shared"}}); err != nil {
				t.Fatal(err)
			}
		},
		"relocate-restore marker": func(t *testing.T, db *corrosion.Client) {
			if err := corrosion.UpsertContainer(context.Background(), db, corrosion.ContainerRecord{
				HostName: "bad", Name: "web", State: "relocating", Image: "alpine:3.19",
				StateDetail: corrosion.RelocateRestoreDetail("h1", "tok"), CPULimit: 1, MemMiB: 128, Project: "p1",
			}); err != nil {
				t.Fatal(err)
			}
		},
		"pending proof": func(t *testing.T, db *corrosion.Client) {
			if err := db.Execute(context.Background(), `INSERT INTO runtime_action_proofs
				(id, action, target_kind, target_name, dest_host, coordinator, status, created_at, updated_at)
				VALUES ('p1', 'reschedule', 'vm', 'mtl', 'h1', 'old', 'prepared', '2026-10-22T00:00:00Z', '2026-10-22T00:00:00Z')`); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, add := range cases {
		t.Run(name, func(t *testing.T) {
			db, c, fenced, _ := heldFixture(t, "none")
			add(t, db)
			c.run(context.Background())
			if len(*fenced) != 1 {
				t.Fatalf("fenced %v, want bad once: the %s waits on its fence", *fenced, name)
			}
		})
	}
}

// TestFenceHeld_UnreadableNeedsFenceAsBefore: when what needs the fence
// cannot be read, the host is fenced, as before this rule (fail closed).
//
// Mutation: hold on a fenceNeeds error — bad is not fenced.
func TestFenceHeld_UnreadableNeedsFenceAsBefore(t *testing.T) {
	db, c, fenced, _ := heldFixture(t, "none")
	if _, err := db.DB().ExecContext(context.Background(), `DROP TABLE runtime_action_proofs`); err != nil {
		t.Fatal(err)
	}
	c.run(context.Background())
	if len(*fenced) != 1 {
		t.Fatalf("fenced %v with fenceNeeds unreadable, want bad once", *fenced)
	}
}

// TestFenceHeld_AWorkloadPlacedDuringTheDecisionIsFencedForAtOnce: a
// recoverable VM recorded on the host after the decision read nothing, before
// the offline write landed (a placement racing the decision), is found by the
// re-check after the write, and the host is fenced in the same cycle.
//
// Mutation: drop the re-check after the offline write — bad is not fenced
// this cycle.
func TestFenceHeld_AWorkloadPlacedDuringTheDecisionIsFencedForAtOnce(t *testing.T) {
	db, c, fenced, _ := heldFixture(t, "none")
	ctx := context.Background()
	c.SetFenceHeldDecidedForTest(func(host string) {
		if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
			Name: "late", HostName: host, State: "running", Spec: `{"on_host_failure":"restart-any"}`,
		}, nil, nil); err != nil {
			t.Errorf("InsertVM: %v", err)
		}
	})
	c.run(ctx)
	if len(*fenced) != 1 {
		t.Fatalf("fenced %v, want bad once: late landed before the offline write", *fenced)
	}
	if _, open := fenceHeldRow(t, db, "bad"); open {
		t.Errorf("%s left open on a fenced host", CondFenceHeld)
	}
}

// TestFenceHeld_HostBackResolves: a held host a quorum sees healthy again
// returns to active, the condition resolves, and nothing was fenced.
func TestFenceHeld_HostBackResolves(t *testing.T) {
	db, c, fenced, _ := heldFixture(t, "none")
	ctx := context.Background()
	c.run(ctx)
	healthyObservers(t, db, "bad", "h1", "h2", "h3")
	c.run(ctx)
	c.run(ctx)
	if h, _ := corrosion.GetHost(ctx, db, "bad"); h == nil || h.State != "active" {
		t.Fatalf("bad is %+v, want active once healthy", h)
	}
	if _, open := fenceHeldRow(t, db, "bad"); open {
		t.Errorf("%s still open on an active host", CondFenceHeld)
	}
	if len(*fenced) != 0 {
		t.Errorf("fenced %v", *fenced)
	}
}

// TestFenceHeld_AnUnreachedFenceAfterAHoldRecoversNothing: held, then mtl
// becomes restart-any and the fence that follows is a best-effort one that
// did not reach the host. mtl became recoverable during the hold, so a
// partitioned host never paused it and may still run it: nothing is
// rescheduled until an operator confirms the host off. The control, the same
// fence of a host that was never held, recovers mtl as before.
//
// Mutation: drop the heldThisOutage refusal in recoverFenced — mtl is
// rescheduled on the unreached fence.
func TestFenceHeld_AnUnreachedFenceAfterAHoldRecoversNothing(t *testing.T) {
	unreached := func(context.Context, fence.HostConfig) fence.Result {
		return fence.Result{Method: "best-effort-ssh", Detail: "ssh: connect: no route to host", Success: true}
	}
	for _, held := range []bool{true, false} {
		t.Run(map[bool]string{true: "after a hold", false: "control"}[held], func(t *testing.T) {
			db, c, _, fm := heldFixture(t, map[bool]string{true: "none", false: "restart-any"}[held])
			ctx := context.Background()
			c.SetFencer(unreached)
			// The unsafe_auto_failover opt-out does not lift this refusal:
			// it waives the safe-fence policy, not the pause gap.
			if err := corrosion.SetHostLabel(ctx, db, "bad", corrosion.LabelUnsafeAutoFailover, "true"); err != nil {
				t.Fatal(err)
			}
			if held {
				c.run(ctx)
				if h, _ := corrosion.GetHost(ctx, db, "bad"); h == nil || h.State != "offline" {
					t.Fatalf("premise: bad = %+v, want held offline", h)
				}
				if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'mtl'`, `{"on_host_failure":"restart-any"}`); err != nil {
					t.Fatal(err)
				}
			}
			c.run(ctx)
			vm, _ := corrosion.GetVM(ctx, db, "mtl")
			if vm == nil {
				t.Fatal("mtl vanished")
			}
			if held {
				if vm.HostName != "bad" {
					t.Fatalf("mtl rescheduled to %s on a fence that never reached bad; it may still run there", vm.HostName)
				}
				if got := fm.attempts[foKey(PhaseSplitBrain, ResultRefused, ErrManualUnconfirmed)]; got != 1 {
					t.Errorf("manual_unconfirmed refusals = %d, want 1 (attempts=%v)", got, fm.attempts)
				}
				if !c.heldThisOutage(ctx, "bad") {
					t.Error("heldThisOutage forgot the hold once the fence was recorded")
				}
				return
			}
			if vm.HostName == "bad" {
				t.Fatalf("control: mtl = %+v, want it rescheduled as before", vm)
			}
		})
	}
}

// TestFenceHeld_ANewOutageIsNotTheHeldOne: a hold that ended in a fence stops
// counting once the host is back in service, so its next outage's recovery is
// judged as any other.
func TestFenceHeld_ANewOutageIsNotTheHeldOne(t *testing.T) {
	db, c, _, _ := heldFixture(t, "none")
	ctx := context.Background()
	c.run(ctx)
	if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'mtl'`, `{"on_host_failure":"restart-any"}`); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if !c.heldThisOutage(ctx, "bad") {
		t.Fatal("premise: the fenced outage does not read as held")
	}
	if err := corrosion.UpdateHostState(ctx, db, "bad", "active"); err != nil {
		t.Fatal(err)
	}
	c.resolveFenceHeldSettled(ctx)
	if c.heldThisOutage(ctx, "bad") {
		t.Fatal("a host back in service still reads as held from its previous outage")
	}
}

// leaseLapseGate enforces nothing, and runs onFenceState when the fence path
// asks whether fence_state_v1 has latched: the first thing failover does,
// before it measures the lease it needs to fence.
type leaseLapseGate struct {
	fakeFailoverGate
	onFenceState func()
}

func (g leaseLapseGate) Enforced(ctx context.Context, token string) bool {
	if token == capabilities.FenceStateV1 && g.onFenceState != nil {
		g.onFenceState()
	}
	return g.fakeFailoverGate.Enforced(ctx, token)
}

// TestFenceHeld_AFenceThatDidNotRunLeavesTheHostRechecked: held, then mtl
// becomes recoverable, and the fence it now needs does not run — the lease
// lapses before it can. The hold stays open, so the next cycle re-decides
// rather than caching the offline host as handled, and fences bad.
//
// Mutation: resolve ha.fence_held in holdUnneededFence when it decides to
// fence — the aborted fence leaves bad cached as terminal and never fenced.
func TestFenceHeld_AFenceThatDidNotRunLeavesTheHostRechecked(t *testing.T) {
	db, c, fenced, fm := heldFixture(t, "none")
	ctx := context.Background()
	lapse := false
	c.Gate = leaseLapseGate{fakeFailoverGate: fakeFailoverGate{enforced: map[string]bool{}}, onFenceState: func() {
		if lapse {
			lapse = false
			expireLeaseRow(t, db, ctx)
		}
	}}
	c.run(ctx)
	if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'mtl'`, `{"on_host_failure":"restart-any"}`); err != nil {
		t.Fatal(err)
	}
	lapse = true
	c.run(ctx)
	if len(*fenced) != 0 || fm.attempts[foKey(PhaseFence, ResultRefused, ErrLeaseLost)] == 0 {
		t.Fatalf("premise: fenced %v, lease-lost aborts %d; want the fence aborted", *fenced,
			fm.attempts[foKey(PhaseFence, ResultRefused, ErrLeaseLost)])
	}
	c.run(ctx)
	c.run(ctx)
	if len(*fenced) != 1 {
		t.Fatalf("fenced %v after the aborted fence, want bad once", *fenced)
	}
}

// TestFenceHeld_ASuccessorThatSawTheStateFirstRechecks: a successor's replica
// holds the hold's 'offline' before its ha.fence_held (two entries, either
// order), so it caches bad as terminal. Once the condition arrives the cache
// is dropped, and a VM made recoverable since is fenced for.
//
// Mutation: drop the fenceHeldOpen case from the handled branch — the
// successor never fences bad.
func TestFenceHeld_ASuccessorThatSawTheStateFirstRechecks(t *testing.T) {
	db, c, _, _ := heldFixture(t, "none")
	ctx := context.Background()
	c.run(ctx)
	cond, open := fenceHeldRow(t, db, "bad")
	if !open {
		t.Fatal("premise: no hold")
	}
	// The successor's replica: the state, not yet the condition.
	if err := db.Execute(ctx, `DELETE FROM health_conditions WHERE code = ?`, CondFenceHeld); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `DELETE FROM leader_election`); err != nil {
		t.Fatal(err)
	}
	var fenced []string
	succ := NewCoordinator("coordinator", db)
	succ.SetFencer(recordingFencer(&fenced))
	succ.run(ctx)
	if !succ.fenced["bad"] {
		t.Fatal("premise: the successor did not cache the offline host without its condition")
	}
	// The condition arrives; then mtl becomes recoverable.
	if err := corrosion.UpsertHealthCondition(ctx, db, cond); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `UPDATE vms SET spec = ? WHERE name = 'mtl'`, `{"on_host_failure":"restart-any"}`); err != nil {
		t.Fatal(err)
	}
	succ.run(ctx)
	if len(fenced) != 1 {
		t.Fatalf("the successor fenced %v, want bad once", fenced)
	}
}

// TestFenceHeld_AnUnchangedHoldIsNotRewritten: a hold that lasts does not
// rewrite its replicated row every cycle.
//
// Mutation: drop the unchanged early return in raiseFenceHeld — the row is
// rewritten each cycle.
func TestFenceHeld_AnUnchangedHoldIsNotRewritten(t *testing.T) {
	db, c, _, _ := heldFixture(t, "none")
	ctx := context.Background()
	for i := 0; i < 4; i++ {
		c.run(ctx)
	}
	row, open := fenceHeldRow(t, db, "bad")
	if !open || row.ObserveCount != 1 {
		t.Fatalf("hold row %+v: want open, written once (observe_count 1)", row)
	}
	// A change in what is left there is written.
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "other", HostName: "bad", State: "running", Spec: `{"on_host_failure":"none"}`,
	}, nil, nil); err != nil {
		t.Fatal(err)
	}
	c.run(ctx)
	if row, _ := fenceHeldRow(t, db, "bad"); row.ObserveCount != 2 || !strings.Contains(row.Evidence, "vm/other") {
		t.Fatalf("hold row %+v after a new workload: want it rewritten naming vm/other", row)
	}
}

// TestFenceHeld_TheHoldIsOneEntry: the 'offline' a hold records and the
// ha.fence_held that explains it replicate as ONE mutation_log entry, so no
// peer holds the state without the condition — a successor would read that
// host as terminal, and if the holder died between two entries the condition
// might never reach anyone.
//
// Mutation: write the state with UpdateHostStateFrom and the condition on its
// own — two entries.
func TestFenceHeld_TheHoldIsOneEntry(t *testing.T) {
	db, c, _, _ := heldFixture(t, "none")
	c.run(context.Background())
	rows, err := db.Query(context.Background(), `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatal(err)
	}
	var withCond, stateAlone int
	for _, r := range rows {
		s := r.String("stmts")
		cond := strings.Contains(s, "INTO health_conditions") && strings.Contains(s, CondFenceHeld)
		state := strings.Contains(s, `"offline"`) && (strings.Contains(s, "UPDATE hosts SET state") || strings.Contains(s, "host_membership"))
		switch {
		case cond && state:
			withCond++
		case state:
			stateAlone++
		}
	}
	if withCond != 1 || stateAlone != 0 {
		t.Fatalf("entries carrying the hold's state with its condition: %d, without it: %d; want 1 and 0", withCond, stateAlone)
	}
	if h, _ := corrosion.GetHost(context.Background(), db, "bad"); h == nil || h.State != "offline" {
		t.Fatalf("bad = %+v, want offline", h)
	}
}

// TestFenceHeld_AFenceSinceTheHoldEndsIt: the successor re-check applies only
// to a hold this replica has not seen end: once a fence of the host is
// recorded after the hold was raised, the hold no longer stands, even while
// its condition is still open here.
//
// Mutation: drop the fence-attempt check from fenceHeldStands.
func TestFenceHeld_AFenceSinceTheHoldEndsIt(t *testing.T) {
	db, c, _, _ := heldFixture(t, "none")
	ctx := context.Background()
	c.run(ctx)
	if !c.fenceHeldStands(ctx, "bad") {
		t.Fatal("premise: the hold does not stand")
	}
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "later", HostName: "bad", Method: "ssh", Result: "partial"}); err != nil {
		t.Fatal(err)
	}
	if _, open := fenceHeldRow(t, db, "bad"); !open {
		t.Fatal("premise: the condition is resolved already")
	}
	if c.fenceHeldStands(ctx, "bad") {
		t.Fatal("a hold with a fence recorded since still stands")
	}
}
