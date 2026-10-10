package failover

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fence"
)

// fenceStateLatched is a FailoverGate on which fence_state_v1, and nothing
// else, has latched.
func fenceStateLatched() FailoverGate {
	return fakeFailoverGate{enforced: map[string]bool{capabilities.FenceStateV1: true}}
}

// One classification (colonelpanik/litevirt#253): what the coordinator takes a
// live fence to prove is exactly what corrosion.FenceProofGrade takes its row
// to prove, for every method and outcome, and once fence_state_v1 has latched
// only such a fence records the host 'fenced'.
//
// Mutation: put the old rule (any successful, non-manual fence) back in
// fenceRecordState's latched branch — the ssh, watchdog, best-effort-ssh and
// unknown-method successes go red.
func TestFenceClassification_OneRule(t *testing.T) {
	h := &corrosion.HostRecord{Name: "down"}
	for _, method := range []string{"ipmi", "ssh", "watchdog", "best-effort-ssh", "manual", "test", ""} {
		for _, success := range []bool{true, false} {
			fr := fence.Result{Method: method, Success: success}
			pg := corrosion.FenceProofGrade(method, fr.LogResult())
			if got := fr.ProvedOff(); got != pg {
				t.Errorf("%s success=%v: ProvedOff = %v, FenceProofGrade of its row = %v", method, success, got, pg)
			}
			want := ""
			switch {
			case success && pg:
				want = "fenced"
			case success:
				want = "offline"
			}
			if got := fenceRecordState(h, fr, true); got != want {
				t.Errorf("%s success=%v, fence_state_v1 latched: records %q, want %q", method, success, got, want)
			}
		}
	}
	// The only proof-grade live fence is a verified IPMI power-off.
	if !(fence.Result{Method: "ipmi", Success: true}).ProvedOff() {
		t.Error("a successful IPMI fence must prove the host off")
	}
}

// Once fence_state_v1 has latched, an SSH fence records the host 'offline',
// not 'fenced' — and still recovers its workloads, exactly as before. Its row
// says what ran: ssh, fenced.
//
// Mutation: drop the latch check, so fenceRecordState keeps the legacy rule —
// the host is recorded 'fenced' and the test goes red.
func TestFailover_UnverifiedFenceRecordsOfflineOnceLatched(t *testing.T) {
	for _, method := range []string{"ssh", "watchdog", "best-effort-ssh"} {
		t.Run(method, func(t *testing.T) {
			strategy := method
			if method == "best-effort-ssh" {
				strategy = "best-effort"
			}
			db, ctx := seedDownHost(t, strategy, nil)
			c := newTestCoordinator("coordinator", db)
			c.Gate = fenceStateLatched()
			c.SetFencer(fencerReturning(method, true))

			c.run(ctx)

			if got := hostState(t, db, ctx); got != "offline" {
				t.Errorf("host state = %q after a %s fence with fence_state_v1 latched, want offline", got, method)
			}
			if got := vmHost(t, db, ctx); got != "alive" {
				t.Errorf("VM on %q; a %s fence must still recover the host's workloads", got, method)
			}
			rows, err := db.Query(ctx, `SELECT method, result FROM fencing_log WHERE host_name = 'down'`)
			if err != nil || len(rows) != 1 || rows[0].String("method") != method || rows[0].String("result") != "fenced" {
				t.Errorf("fencing_log = %v (err %v), want one %s/fenced row", rows, err, method)
			}
		})
	}
}

// Until fence_state_v1 latches, an SSH fence records 'fenced' exactly as every
// earlier build does: a successor on an older build resumes only from that.
//
// Mutation: record 'offline' for an unverified fence whether or not the token
// has latched — the host reads 'offline' and the test goes red.
func TestFailover_UnverifiedFenceRecordsFencedUntilLatched(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.Gate = fakeFailoverGate{enforced: map[string]bool{}}
	c.SetFencer(fencerReturning("ssh", true))

	c.run(ctx)

	if got := hostState(t, db, ctx); got != "fenced" {
		t.Errorf("host state = %q after an SSH fence with fence_state_v1 unlatched, want fenced (the legacy rule)", got)
	}
	if got := vmHost(t, db, ctx); got != "alive" {
		t.Errorf("VM on %q; an SSH fence recovers the workloads", got)
	}
}

// A verified fence records 'fenced' whether or not the token has latched.
func TestFailover_VerifiedFenceRecordsFenced(t *testing.T) {
	for _, latched := range []bool{false, true} {
		db, ctx := seedDownHost(t, "ipmi", nil)
		c := newTestCoordinator("coordinator", db)
		if latched {
			c.Gate = fenceStateLatched()
		}
		c.SetFencer(fencerReturning("ipmi", true))

		c.run(ctx)

		if got := hostState(t, db, ctx); got != "fenced" {
			t.Errorf("latched=%v: host state = %q after an IPMI fence, want fenced", latched, got)
		}
	}
}

// sshHandoff is handoffFixture for an SSH fence with fence_state_v1 latched
// on both coordinators: "bad" is SSH-fenced and recorded 'offline', its VM
// still on it, and the lease now belongs to "good".
func sshHandoff(t *testing.T) (*corrosion.Client, *Coordinator, *Coordinator, *time.Time) {
	t.Helper()
	db := newTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for _, name := range []string{"bad", "good"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
			Name: name, Address: "10.0.0.1", SSHUser: "root", SSHPort: 22,
			GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
		}); err != nil {
			t.Fatalf("InsertHost %s: %v", name, err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "vm1", HostName: "bad", Spec: `{"on_host_failure":"restart-any"}`, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	fenceQuorum(t, ctx, db, []string{"first", "good"}, "bad")

	first := NewCoordinator("first", db)
	second := NewCoordinator("good", db)
	first.Gate, second.Gate = fenceStateLatched(), fenceStateLatched()
	first.Now = func() time.Time { return now }
	second.Now = first.Now
	first.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		seedLease(t, db, "good", now.Add(leaseDuration))
		return fence.Result{Method: "ssh", Detail: "poweroff sent", Success: true}
	})
	second.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		t.Error("the successor fenced a host on an unverified fence; it is resumed, never re-fenced")
		return fence.Result{Method: "ssh", Success: false}
	})

	first.RunOnce(ctx)
	if h, _ := corrosion.GetHost(ctx, db, "bad"); h == nil || h.State != "offline" {
		t.Fatalf("fixture: bad is %+v after an SSH fence with fence_state_v1 latched, want offline", h)
	}
	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "bad" {
		t.Fatalf("fixture failed: vm1 should still be on bad after the handoff (err=%v)", err)
	}
	return db, first, second, &now
}

// A successor resumes a recovery from an unverified fence recorded 'offline'.
//
// Mutation: recordedFence accepts only 'fenced' again — the VM stays on the
// SSH-fenced host and the test goes red.
func TestRun_ResumesFromAnUnverifiedFenceRecordedOffline(t *testing.T) {
	db, _, second, _ := sshHandoff(t)
	second.RunOnce(context.Background())

	vm, err := corrosion.GetVM(context.Background(), db, "vm1")
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v", err)
	}
	if vm.HostName != "good" {
		t.Errorf("vm1 is still on %q — an SSH fence recorded 'offline' strands the workload when its leader loses the lease", vm.HostName)
	}
}

// The run loop does not cache-skip an 'offline' host whose newest fence
// succeeded. The successor first finds the fence in doubt — its observers'
// failing runs, as it has them so far, began after the fence — and declines;
// a cycle later the observers' rows show a run that spans the fence, and it
// resumes.
//
// Mutation: cache every 'offline' host as handled again, as before the fix —
// the declining cycle caches the host and the second never looks at it.
func TestRun_AnUnverifiedFenceRecordedOfflineIsReadAgainAfterADecline(t *testing.T) {
	db, _, second, now := sshHandoff(t)
	ctx := context.Background()

	setRunStart := func(start time.Time) {
		t.Helper()
		if err := db.Execute(ctx, `UPDATE host_health SET last_seen = ?, updated_at = ?`,
			start.Format(time.RFC3339), now.Add(2*time.Second).Format(time.RFC3339)); err != nil {
			t.Fatalf("set run start: %v", err)
		}
	}
	setRunStart(now.Add(time.Second))
	second.RunOnce(ctx)
	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "bad" {
		t.Fatalf("fixture: vm1 = %+v (err %v); a fence no observer has watched stand must be declined", vm, err)
	}

	setRunStart(now.Add(-time.Minute))
	second.RunOnce(ctx)
	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "good" {
		t.Errorf("vm1 = %+v (err %v); once the fence stands the successor must resume from the 'offline' record", vm, err)
	}
}

// An 'offline' host whose newest fence SUCCEEDED and whose workloads moved is
// not put back in service by a healthy quorum once recentFenceWindow has
// passed: it keeps the 'fenced' rule, `lv host undrain` only.
//
// Mutation: drop that rule from recoverHosts — the host is marked active.
func TestRecoverHosts_OfflineAfterAnUnverifiedFenceThatMovedWorkloadsStays(t *testing.T) {
	db, _, second, now := sshHandoff(t)
	ctx := context.Background()
	second.RunOnce(ctx)
	if vm, err := corrosion.GetVM(ctx, db, "vm1"); err != nil || vm == nil || vm.HostName != "good" {
		t.Fatalf("fixture failed: the successor did not relocate vm1 (err=%v)", err)
	}

	*now = now.Add(recentFenceWindow + time.Minute)
	if err := db.Execute(ctx,
		`UPDATE host_health SET status = 'healthy', consecutive_failures = 0, updated_at = ?`,
		now.Format(time.RFC3339)); err != nil {
		t.Fatalf("refresh health: %v", err)
	}
	second.RunOnce(ctx)

	if h, err := corrosion.GetHost(ctx, db, "bad"); err != nil || h == nil || h.State != "offline" {
		t.Errorf("bad = %+v (err %v); an SSH-fenced host whose VMs moved must stay offline until `lv host undrain`", h, err)
	}
}

// The same host is put back in service when the coordinator that fenced it
// moved nothing off it — the spurious-fence rule 'fenced' always had. Like
// 'fenced', and unlike main's 'offline', it does not wait out
// recentFenceWindow: phase 2 runs with the fence seconds old.
func TestRecoverHosts_OfflineAfterASpuriousUnverifiedFenceRecovers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "spur", Address: "10.0.0.60", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "active", FenceStrategy: "ssh",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	c := newTestCoordinator("coordinator", db)
	c.Gate = fenceStateLatched()
	c.SetFencer(fencerReturning("ssh", true))

	downObservers(t, db, "spur", "h1", "h2", "h3")
	c.run(ctx)
	if h, _ := corrosion.GetHost(ctx, db, "spur"); h == nil || h.State != "offline" {
		t.Fatalf("phase 1: expected offline, got %+v", h)
	}

	healthyObservers(t, db, "spur", "h1", "h2", "h3")
	c.run(ctx)
	if h, _ := corrosion.GetHost(ctx, db, "spur"); h == nil || h.State != "active" {
		t.Errorf("phase 2: an SSH-fenced host this coordinator moved nothing off should recover, got %+v", h)
	}
}

// A failed fence leaves the host 'offline' with nothing moved, and a healthy
// quorum puts it back in service once no fence is recent — unchanged.
func TestRecoverHosts_OfflineAfterAFailedFenceRecovers(t *testing.T) {
	db := newTestDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "flaky", Address: "10.0.0.62", SSHUser: "root", SSHPort: 22,
		GRPCPort: 7443, State: "offline", FenceStrategy: "ssh",
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	if err := corrosion.InsertFenceLog(ctx, db, corrosion.FenceLogRecord{
		ID: "f1", HostName: "flaky", Method: "ssh", Result: "partial",
	}); err != nil {
		t.Fatalf("InsertFenceLog: %v", err)
	}
	healthyObservers(t, db, "flaky", "h1", "h2", "h3")
	c := newTestCoordinator("coordinator", db)
	c.Gate = fenceStateLatched()
	c.run(ctx)

	if h, _ := corrosion.GetHost(ctx, db, "flaky"); h == nil || h.State != "active" {
		t.Errorf("an offline host whose fence failed should recover when healthy, got %+v", h)
	}
}

// orderGate records, in order, every fence_state_v1 latch read, and the
// fencer records when it ran: the two events a test needs to say whether
// anything slow sits between a fence and its record.
type orderGate struct {
	fakeFailoverGate
	events *[]string
}

func (g orderGate) Enforced(ctx context.Context, tok string) bool {
	if tok == capabilities.FenceStateV1 {
		*g.events = append(*g.events, "latch-read")
		// Unlatched, Checker.Enforced runs a live Ping sweep here.
		time.Sleep(50 * time.Millisecond)
	}
	return g.fakeFailoverGate.Enforced(ctx, tok)
}

// Nothing slow sits between a fence and the write that records it. Until
// fence_state_v1 latches, Gate.Enforced runs a live Ping sweep (up to 4 s);
// read after a successful SSH fence, it delayed the record — and a leader that
// died or lost its lease in that gap lost the record of a fence that had
// happened. The latch is read once, before the fence, and that answer serves
// recoverFenced too.
//
// Mutation: read the latch in fenceRecordState again (after the fence) — a
// latch read follows the fence and the test goes red.
func TestFailover_TheLatchIsReadBeforeTheFenceNotBetweenItAndItsRecord(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	var events []string
	c := newTestCoordinator("coordinator", db)
	c.Gate = orderGate{fakeFailoverGate: fakeFailoverGate{enforced: map[string]bool{}}, events: &events}
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		events = append(events, "fence")
		return fence.Result{Method: "ssh", Detail: "poweroff sent", Success: true}
	})

	c.run(ctx)

	fenced := -1
	for i, e := range events {
		if e == "fence" {
			fenced = i
		}
	}
	if fenced < 0 {
		t.Fatalf("fixture: the host was never fenced (events %v)", events)
	}
	for _, e := range events[fenced+1:] {
		if e == "latch-read" {
			t.Errorf("fence_state_v1 was read after the fence, between it and its record: %v", events)
		}
	}
	if got := hostState(t, db, ctx); got != "fenced" {
		t.Errorf("host state = %q; unlatched, an SSH fence records fenced", got)
	}
}

// A live unverified fence writes the host's 'offline' state once, in the
// entry that carries its row. recoverFenced used to write it again as an
// entry of its own (it was handed the pre-fence host, still 'active'): a
// second write that moves the host's HostFenceLife cutoff and can overwrite a
// boot write that landed in between.
//
// Mutation: hand recoverFenced the pre-fence host again — a second entry
// writes 'offline' alone.
func TestFailover_AnUnverifiedFenceWritesItsStateOnce(t *testing.T) {
	db, ctx := seedDownHost(t, "ssh", nil)
	c := newTestCoordinator("coordinator", db)
	c.Gate = fenceStateLatched()
	c.SetFencer(fencerReturning("ssh", true))

	c.run(ctx)

	rows, err := db.Query(ctx, `SELECT stmts FROM mutation_log`)
	if err != nil {
		t.Fatalf("read mutation_log: %v", err)
	}
	alone := 0
	for _, r := range rows {
		st := r.String("stmts")
		if !strings.Contains(st, "INTO fencing_log") && strings.Contains(st, "UPDATE hosts SET state") && strings.Contains(st, `"offline"`) {
			alone++
		}
	}
	if alone != 0 {
		t.Errorf("%d entries write 'offline' apart from the fence row's entry, want 0", alone)
	}
	if got := hostState(t, db, ctx); got != "offline" {
		t.Errorf("host state = %q, want offline", got)
	}
}

// pingingGate is a gate whose Enforced, like health.Checker's before a token
// latches, runs a live Ping sweep — recorded here — and whose Latched reads
// memory.
type pingingGate struct {
	fakeFailoverGate
	latched map[string]bool
	pinged  *[]string
}

func (g pingingGate) Enforced(ctx context.Context, tok string) bool {
	*g.pinged = append(*g.pinged, tok)
	return g.latched[tok]
}

func (g pingingGate) Latched(tok string) bool { return g.latched[tok] }

// The pre-fence fence_state_v1 read does not ping: a gate that can read its
// latch from memory is asked that way, so no fence — a verified IPMI one
// included — waits on a Ping sweep before it runs. The latched answer still
// decides the state (offline for an SSH fence once latched).
//
// Mutation: read the latch with Enforced again — fence_state_v1 is pinged
// and the test goes red.
func TestFailover_TheFenceStateLatchIsReadWithoutAPing(t *testing.T) {
	for _, tc := range []struct {
		method  string
		latched bool
		want    string
	}{{"ipmi", false, "fenced"}, {"ssh", true, "offline"}, {"ssh", false, "fenced"}} {
		db, ctx := seedDownHost(t, tc.method, nil)
		var pinged []string
		c := newTestCoordinator("coordinator", db)
		c.Gate = pingingGate{latched: map[string]bool{capabilities.FenceStateV1: tc.latched}, pinged: &pinged}
		c.SetFencer(fencerReturning(tc.method, true))

		c.run(ctx)

		for _, tok := range pinged {
			if tok == capabilities.FenceStateV1 {
				t.Errorf("%s fence (latched=%v): %s was read with a Ping sweep (Enforced)", tc.method, tc.latched, tok)
				break
			}
		}
		if got := hostState(t, db, ctx); got != tc.want {
			t.Errorf("%s fence (latched=%v): host state %q, want %q", tc.method, tc.latched, got, tc.want)
		}
	}
}

// Whether an assumed best-effort fence relies on the host's partition pause
// is decided BEFORE the fence: until partition_pause_v1 latches, that
// predicate runs a live Ping sweep, and between a successful fence and the
// write that records it a leader that died or lost its lease in the sweep
// lost the record of a fence that had happened.
//
// Mutation: decide it after the fence again (asSelfPause reading
// relyOnPartitionPause) — the predicate is read after the fence and the test
// goes red.
func TestFailover_PartitionPauseRelianceIsDecidedBeforeTheFence(t *testing.T) {
	db, ctx := seedDownHost(t, "best-effort", nil)
	var events []string
	c := newTestCoordinator("coordinator", db)
	c.PartitionPauseEnforced = func(context.Context) bool {
		events = append(events, "pause-read")
		return false
	}
	c.SetFencer(func(context.Context, fence.HostConfig) fence.Result {
		events = append(events, "fence")
		return fence.Result{Method: "best-effort-ssh", Detail: "ssh failed; proceeding", Success: true}
	})

	c.run(ctx)

	fenced := -1
	for i, e := range events {
		if e == "fence" {
			fenced = i
		}
	}
	if fenced < 0 {
		t.Fatalf("fixture: the host was never fenced (events %v)", events)
	}
	for _, e := range events[fenced+1:] {
		if e == "pause-read" {
			t.Errorf("the partition-pause predicate was read after the fence, between it and its record: %v", events)
		}
	}
	if !slices.Contains(events[:fenced], "pause-read") {
		t.Errorf("the partition-pause predicate was never read before the best-effort fence: %v", events)
	}
}
