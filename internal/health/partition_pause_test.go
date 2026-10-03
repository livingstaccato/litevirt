package health

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// pauseFixture is a 3-voter cluster seen from node-a: two VMs on node-a, one
// recoverable (restart-any) and one not (none), both running in the fake.
type pauseFixture struct {
	t       *testing.T
	db      *corrosion.Client
	virt    *libvirtfake.Fake
	p       *PartitionPauser
	dataDir string

	mu      sync.Mutex
	quorum  QuorumState
	now     time.Time
	confirm func(recs []PauseRecord) map[string]ResumeVerdict
	fenced  int
}

func newPauseFixture(t *testing.T, hosts ...corrosion.HostRecord) *pauseFixture {
	t.Helper()
	ctx := context.Background()
	f := &pauseFixture{t: t, db: corrosion.NewTestClientT(t), virt: libvirtfake.New(),
		dataDir: t.TempDir(), quorum: QuorumYes, now: time.Unix(1_800_000_000, 0)}
	if err := corrosion.InitSchema(ctx, f.db); err != nil {
		t.Fatal(err)
	}
	if len(hosts) == 0 {
		hosts = []corrosion.HostRecord{{Name: "node-a"}, {Name: "node-b"}, {Name: "node-c"}}
	}
	for _, h := range hosts {
		if h.State == "" {
			h.State = "active"
		}
		h.Address, h.GRPCPort = "127.0.0.1", 7443
		if err := corrosion.InsertHost(ctx, f.db, h); err != nil {
			t.Fatalf("InsertHost %s: %v", h.Name, err)
		}
	}
	for _, vm := range []struct{ name, policy string }{{"vm-ha", "restart-any"}, {"vm-none", "none"}} {
		if err := corrosion.InsertVM(ctx, f.db, corrosion.VMRecord{Name: vm.name, HostName: "node-a",
			Spec: `{"on_host_failure":"` + vm.policy + `"}`, State: "running"}, nil, nil); err != nil {
			t.Fatal(err)
		}
		f.virt.SetState(vm.name, libvirtfake.StateRunning)
	}
	f.p = NewPartitionPauser("node-a", f.dataDir, f.db)
	f.p.SetQuorum(func(context.Context) (QuorumState, int, int) { f.mu.Lock(); defer f.mu.Unlock(); return f.quorum, 1, 2 })
	f.p.SetEnabled(func() bool { return true })
	f.p.SetVMBackend(f.virt)
	f.p.SetClock(func() time.Time { f.mu.Lock(); defer f.mu.Unlock(); return f.now })
	f.p.SetResumeConfirmer(func(_ context.Context, recs []PauseRecord) map[string]ResumeVerdict {
		if f.confirm != nil {
			return f.confirm(recs)
		}
		out := map[string]ResumeVerdict{}
		for _, r := range recs {
			out[r.Key()] = ResumeVerdict{OK: true, Reason: "test: confirmed"}
		}
		return out
	})
	f.p.SetSelfFence(func() bool { return false }, func() { f.mu.Lock(); f.fenced++; f.mu.Unlock() })
	return f
}

func (f *pauseFixture) set(q QuorumState) { f.mu.Lock(); f.quorum = q; f.mu.Unlock() }
func (f *pauseFixture) advance(d time.Duration) {
	f.mu.Lock()
	f.now = f.now.Add(d)
	f.mu.Unlock()
}
func (f *pauseFixture) tick() { f.p.Evaluate(context.Background()) }

// regain holds the quorum at Yes for the unbroken T_pause a heal takes.
func (f *pauseFixture) regain() {
	f.set(QuorumYes)
	for i := 0; i <= int(PartitionPauseAfter/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
}

func (f *pauseFixture) raw(name string) libvirtfake.State {
	f.t.Helper()
	st, ok := f.virt.RawState(name)
	if !ok {
		f.t.Fatalf("domain %s is gone", name)
	}
	return st
}

func (f *pauseFixture) records() []PauseRecord {
	f.t.Helper()
	recs, err := newPauseStore(f.dataDir).list()
	if err != nil {
		f.t.Fatal(err)
	}
	return recs
}

func (f *pauseFixture) condition(code string) (corrosion.HealthCondition, bool) {
	f.t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), f.db,
		corrosion.PartitionPauseEvaluator, code, "host", "node-a")
	if err != nil {
		f.t.Fatal(err)
	}
	return row, ok
}

// loseFor holds quorum at q and ticks once per second for d.
func (f *pauseFixture) loseFor(q QuorumState, d time.Duration) {
	f.set(q)
	for elapsed := time.Duration(0); elapsed <= d; elapsed += time.Second {
		f.tick()
		f.advance(time.Second)
	}
}

// The core: after T_pause of continuous loss, the recoverable VM is suspended
// (RAM kept, still active) and recorded with its row's epoch and incarnation;
// the policy-none VM keeps running, because nothing would replace it.
//
// Mutations: drop the recoverability filter — vm-none is paused and this goes
// red; pause before T_pause (compare against 0) — the "not yet" check goes red.
func TestPartitionPause_PausesOnlyRecoverableAfterTPause(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter-2*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s before T_pause has elapsed; a loss shorter than T_pause must pause nothing", st)
	}
	f.loseFor(QuorumNo, 3*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after T_pause of lost quorum, want paused", st)
	}
	if st := f.raw("vm-none"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-none (on_host_failure=none) is %s; nothing replaces it, so it must keep running", st)
	}
	recs := f.records()
	if len(recs) != 1 || recs[0].Key() != "vm/vm-ha" {
		t.Fatalf("records = %+v, want exactly vm/vm-ha", recs)
	}
	row, _ := corrosion.GetVM(context.Background(), f.db, "vm-ha")
	if recs[0].Incarnation != corrosion.IncarnationOf(row.CreatedAt) || recs[0].OwnerEpoch != row.OwnerEpoch ||
		recs[0].Host != "node-a" {
		t.Fatalf("record %+v does not carry the row's identity (created_at %q, epoch %d)", recs[0], row.CreatedAt, row.OwnerEpoch)
	}
	if c, ok := f.condition(corrosion.CondPartitionPaused); !ok || c.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("no open %s condition while a workload is self-paused (ok=%v %+v)", corrosion.CondPartitionPaused, ok, c)
	}
}

// A blip — loss that ends before T_pause — pauses nothing, however often it
// recurs: the clock restarts on every Yes.
//
// Mutation: keep the loss clock across a Yes — the third blip pauses and this
// goes red.
func TestPartitionPause_BlipShorterThanTPausePausesNothing(t *testing.T) {
	f := newPauseFixture(t)
	for i := 0; i < 3; i++ {
		f.loseFor(QuorumNo, PartitionPauseAfter-3*time.Second)
		f.regain()
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after three blips each shorter than T_pause", st)
	}
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("records after blips: %+v", recs)
	}
	// The end state alone would not show a pause that was resumed again in the
	// next Yes; no suspend may have happened at all.
	for _, ev := range f.virt.EventLog() {
		if ev.Op == "suspend" {
			t.Fatalf("a blip shorter than T_pause suspended %s", ev.Domain)
		}
	}
}

// Unknown counts as loss (docs/design/partition-pause.md §3.1): the majority
// relies on a deadline, so a stretch of Unknown inside a real partition must
// not push the pause past it.
//
// Mutation: treat Unknown like Yes — nothing pauses and this goes red.
func TestPartitionPause_UnknownCountsAsLoss(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumUnknown, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after T_pause of Unknown, want paused", st)
	}
}

// A single-node cluster never pauses — nothing could recover its workloads
// anywhere else — even if its quorum view reads lost (a warmup that never
// completed, an unreadable store).
//
// Mutation: drop the single-voter exemption — vm-ha pauses and this goes red.
func TestPartitionPause_SingleNodeNeverPauses(t *testing.T) {
	f := newPauseFixture(t, corrosion.HostRecord{Name: "node-a"})
	f.loseFor(QuorumNo, 3*PartitionPauseAfter)
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("a single-node cluster paused vm-ha (%s)", st)
	}
}

// A host in maintenance is never fenced by the coordinator (run skips it), so
// nothing would recover its workloads; a witness runs none. Neither pauses.
//
// Mutations: drop the maintenance exemption / the witness exemption — the
// matching subtest goes red.
func TestPartitionPause_MaintenanceAndWitnessNeverPause(t *testing.T) {
	for _, tc := range []struct {
		name string
		self corrosion.HostRecord
	}{
		{"maintenance", corrosion.HostRecord{Name: "node-a", State: "maintenance"}},
		{"witness", corrosion.HostRecord{Name: "node-a", Role: "witness"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPauseFixture(t, tc.self, corrosion.HostRecord{Name: "node-b"}, corrosion.HostRecord{Name: "node-c"})
			f.loseFor(QuorumNo, 2*PartitionPauseAfter)
			if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
				t.Fatalf("a %s host paused vm-ha (%s)", tc.name, st)
			}
		})
	}
}

// With enforcement.partition_pause off nothing is paused — the kill switch —
// but what an earlier run paused is still resumed through the same checks, so
// turning the flag off cannot strand a paused workload.
//
// Mutations: ignore the flag on the pause side — the first half goes red; gate
// the resume side on the flag too — the second half goes red.
func TestPartitionPause_FlagOffPausesNothingButStillResumes(t *testing.T) {
	f := newPauseFixture(t)
	on := true
	f.p.SetEnabled(func() bool { return on })
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	on = false
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after the majority returned with the flag off; a paused workload was stranded", st)
	}
	f.loseFor(QuorumNo, 2*PartitionPauseAfter)
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s with enforcement.partition_pause off", st)
	}
}

// A domain that is already paused when the majority is lost belongs to whoever
// paused it (an operator, a snapshot). It is neither recorded nor, when the
// majority returns, resumed.
//
// Mutation: resume every paused domain instead of every recorded one — the
// operator's VM is resumed and this goes red.
func TestPartitionPause_LeavesAnOperatorPausedDomainAlone(t *testing.T) {
	f := newPauseFixture(t)
	f.virt.SetPaused("vm-ha")
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("an operator-paused domain was recorded as self-paused: %+v", recs)
	}
	// Not even attempted: a suspend of a paused domain fails, and that failure
	// would tell the majority this host's pause cannot be relied on.
	if c, ok := f.condition(corrosion.CondPartitionPauseFailed); ok && c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("the pauser tried to pause an operator-paused domain: %s", c.Evidence)
	}
	f.set(QuorumYes)
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("an operator-paused domain is %s after the majority returned; only self-paused workloads resume", st)
	}
}

// A suspend that fails raises partition_pause_failed (critical) — the condition
// the majority reads before relying on this host's pause — leaves no record for
// a workload that is not paused, retries every tick, and self-fences only when
// a verified watchdog is armed.
//
// Mutations: skip the condition — the first check goes red; self-fence
// regardless of armed — the unarmed subtest goes red; never self-fence — the
// armed subtest goes red.
func TestPartitionPause_SuspendFailureRaisesConditionAndFencesOnlyWhenArmed(t *testing.T) {
	for _, armed := range []bool{false, true} {
		name := "unarmed"
		if armed {
			name = "armed"
		}
		t.Run(name, func(t *testing.T) {
			f := newPauseFixture(t)
			a := armed
			f.p.SetSelfFence(func() bool { return a }, func() { f.mu.Lock(); f.fenced++; f.mu.Unlock() })
			f.virt.FailSuspendDomain = func(string) error { return errors.New("injected: qemu monitor wedged") }
			f.loseFor(QuorumNo, PartitionPauseAfter+2*time.Second)
			c, ok := f.condition(corrosion.CondPartitionPauseFailed)
			if !ok || c.Lifecycle == corrosion.ConditionResolved || c.Severity != corrosion.SeverityCritical {
				t.Fatalf("no open critical %s after a failed suspend (ok=%v %+v)", corrosion.CondPartitionPauseFailed, ok, c)
			}
			if !strings.Contains(c.Evidence, "vm-ha") {
				t.Fatalf("the condition does not name the workload: %s", c.Evidence)
			}
			if recs := f.records(); len(recs) != 0 {
				t.Fatalf("a record was left for a workload that is not paused: %+v", recs)
			}
			f.mu.Lock()
			fenced := f.fenced
			f.mu.Unlock()
			if armed && fenced == 0 {
				t.Fatal("a failed pause on a host with a verified watchdog did not self-fence")
			}
			if !armed && fenced != 0 {
				t.Fatal("a failed pause self-fenced on a host with no verified watchdog")
			}
			if failed, err := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); err != nil || !failed {
				t.Fatalf("HostPartitionPauseFailed = %v, %v; the majority would count this host as paused", failed, err)
			}
			// It retries, and once the pause succeeds the condition resolves.
			f.virt.FailSuspendDomain = nil
			f.tick()
			if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
				t.Fatalf("vm-ha is %s after the suspend stopped failing; the pause is not retried", st)
			}
			if failed, _ := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); failed {
				t.Fatal("partition_pause_failed is still open after every workload paused")
			}
		})
	}
}

// Resume needs the majority back AND a majority's confirmation; with both it
// resumes, drops the record and resolves the condition.
//
// Mutations: resume on QuorumYes without asking the confirmer — the held
// subtest goes red; skip the record removal — the record check goes red.
func TestPartitionPause_ResumesOnlyOnConfirmation(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	held := true
	f.confirm = func(recs []PauseRecord) map[string]ResumeVerdict {
		out := map[string]ResumeVerdict{}
		for _, r := range recs {
			out[r.Key()] = ResumeVerdict{OK: !held, Reason: "test"}
		}
		return out
	}
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s although the majority did not confirm it", st)
	}
	held = false
	f.advance(partitionResumeRecheck)
	f.regain()
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after the majority confirmed it", st)
	}
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("records after resume: %+v", recs)
	}
	if c, ok := f.condition(corrosion.CondPartitionPaused); !ok || c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("%s is not resolved after the last resume (ok=%v %+v)", corrosion.CondPartitionPaused, ok, c)
	}
}

// The local row must still name this host at the recorded epoch and
// incarnation; a row that moved is never resumed, whatever the confirmer says.
//
// Mutations: drop the host check / the epoch check / the incarnation check —
// the matching subtest goes red.
func TestPartitionPause_LocalRowMustStillBeOurs(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(t *testing.T, db *corrosion.Client)
	}{
		{"moved", func(t *testing.T, db *corrosion.Client) {
			if err := corrosion.UpdateVMHost(context.Background(), db, "vm-ha", "node-b", "running"); err != nil {
				t.Fatal(err)
			}
		}},
		{"epoch", func(t *testing.T, db *corrosion.Client) {
			if err := db.Execute(context.Background(), `UPDATE vms SET vm_owner_epoch = vm_owner_epoch + 1 WHERE name = ?`, "vm-ha"); err != nil {
				t.Fatal(err)
			}
		}},
		{"incarnation", func(t *testing.T, db *corrosion.Client) {
			if err := db.Execute(context.Background(), `UPDATE vms SET created_at = ? WHERE name = ?`, "2099-01-01T00:00:00Z", "vm-ha"); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newPauseFixture(t)
			f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
			tc.edit(t, f.db)
			f.set(QuorumYes)
			f.tick()
			if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
				t.Fatalf("vm-ha is %s although its row no longer matches the record", st)
			}
		})
	}
}

// A daemon restart while paused: the record survives, a NEW pauser over the
// same data dir neither re-pauses nor forgets it, and resumes it through the
// same checks.
//
// Mutation: keep records in memory only — the new pauser finds nothing and
// vm-ha stays paused, so this goes red.
func TestPartitionPause_RecordSurvivesARestart(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	restarted := NewPartitionPauser("node-a", f.dataDir, f.db)
	restarted.SetQuorum(func(context.Context) (QuorumState, int, int) { return QuorumYes, 2, 2 })
	restarted.SetEnabled(func() bool { return true })
	restarted.SetVMBackend(f.virt)
	restarted.SetClock(func() time.Time { return f.now })
	restarted.SetResumeConfirmer(func(_ context.Context, recs []PauseRecord) map[string]ResumeVerdict {
		out := map[string]ResumeVerdict{}
		for _, r := range recs {
			out[r.Key()] = ResumeVerdict{OK: true}
		}
		return out
	})
	for i := 0; i <= int(PartitionPauseAfter/time.Second); i++ {
		restarted.Evaluate(context.Background())
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after a restarted pauser regained the majority", st)
	}
}

// No confirmer wired is not a yes.
//
// Mutation: treat a nil confirmer as confirmed — vm-ha resumes and this goes red.
func TestPartitionPause_NoConfirmerHolds(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	f.p.SetResumeConfirmer(nil)
	f.set(QuorumYes)
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s with no majority confirmation wired", st)
	}
}

// DecideResume is the majority check of §3.5, step 3.
//
// Mutations: count an errored answer — "an error is not an answer" goes red;
// ignore HostDown — "fenced" goes red; ignore an accepted claim — "accepted"
// goes red; require fewer answers — "too few" goes red.
func TestDecideResume(t *testing.T) {
	rec := PauseRecord{Kind: PauseKindVM, Name: "vm-ha", Host: "node-a", OwnerEpoch: 3, Incarnation: "inc"}
	row := RowView{Live: true, Host: "node-a", OwnerEpoch: 3, Incarnation: "inc"}
	ok := func(v string) VoterAnswer {
		return VoterAnswer{Voter: v, HostState: "active", Rows: map[string]RowView{rec.Key(): row}}
	}
	with := func(v string, edit func(*RowView)) VoterAnswer {
		a := ok(v)
		r := row
		edit(&r)
		a.Rows = map[string]RowView{rec.Key(): r}
		return a
	}
	for _, tc := range []struct {
		name    string
		answers []VoterAnswer
		need    int
		want    bool
	}{
		{"enough clean answers", []VoterAnswer{ok("b"), ok("c")}, 2, true},
		{"too few", []VoterAnswer{ok("b")}, 2, false},
		{"an error is not an answer", []VoterAnswer{ok("b"), {Voter: "c", Err: errors.New("unreachable")}}, 2, false},
		{"fenced", []VoterAnswer{ok("b"), {Voter: "c", HostDown: true, HostState: "fenced"}}, 2, false},
		{"accepted", []VoterAnswer{ok("b"), {Voter: "c", HostState: "active", Rows: ok("c").Rows,
			Accepted: map[string]string{rec.Key(): "node-c"}}}, 2, false},
		{"an accept for another workload does not count", []VoterAnswer{ok("b"), {Voter: "c", HostState: "active", Rows: ok("c").Rows,
			Accepted: map[string]string{"vm/other": "node-c"}}}, 2, true},
		// The voter's own ROW must agree: with claims off, after an undrain,
		// or past an epoch the minority never saw, it is the only witness.
		{"row moved", []VoterAnswer{ok("b"), with("c", func(r *RowView) { r.Host = "node-c" })}, 2, false},
		{"row at another epoch", []VoterAnswer{ok("b"), with("c", func(r *RowView) { r.OwnerEpoch = 4 })}, 2, false},
		{"row another incarnation", []VoterAnswer{ok("b"), with("c", func(r *RowView) { r.Incarnation = "other" })}, 2, false},
		{"row gone", []VoterAnswer{ok("b"), with("c", func(r *RowView) { r.Live = false })}, 2, false},
		{"no row view is not an answer", []VoterAnswer{ok("b"), {Voter: "c", HostState: "active"}}, 2, false},
		{"need zero still needs no objection", []VoterAnswer{{Voter: "b", HostDown: true}}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := DecideResume(rec, tc.answers, tc.need)
			if got.OK != tc.want {
				t.Fatalf("DecideResume = %+v, want OK=%v", got, tc.want)
			}
			if got.Reason == "" {
				t.Fatal("a verdict carries no reason; the lab check greps it")
			}
		})
	}
}

// TestPartitionPauseWaitCoversTheMinority pins docs/design/partition-pause.md
// §4.1 and §4.4 against the live constants: for each cluster size, the
// majority's wait, measured from its fence decision, must cover the minority's
// worst-case detection after its last contact with the quorum observers (less
// the observers' own streak), the pauser's tick quantisation twice, T_pause,
// the time to execute the pauses, and slack.
//
// It recomputes the bound from first principles — a cycle waits for its
// slowest probe, probeConcurrency at a time — rather than calling the
// functions under test.
//
// Mutations: shorten partitionPauseSlack, or compute C(n) for one batch
// regardless of n — this goes red.
func TestPartitionPauseWaitCoversTheMinority(t *testing.T) {
	for _, tc := range []struct {
		hosts int
		want  time.Duration // docs/design/partition-pause.md §4.4's table
	}{{5, 23 * time.Second}, {17, 23 * time.Second}, {18, 35 * time.Second}, {40, 47 * time.Second}} {
		targets := tc.hosts - 1
		batches := (targets + probeConcurrency - 1) / probeConcurrency
		cycle := checkInterval
		if c := time.Duration(batches) * checkTimeout; c > cycle {
			cycle = c
		}
		detect := time.Duration(suspectThreshold+1) * cycle
		head := detect - time.Duration(FailuresToFence-1)*checkInterval
		if head < 0 {
			head = 0
		}
		need := head + 2*partitionPauseTick + PartitionPauseExecBudget + PartitionPauseAfter + 2*time.Second
		got := PartitionPauseWaitFor(targets)
		if got < need {
			t.Errorf("%d hosts: W = %v, but the minority may pause as late as %v after the decision "+
				"(cycle %v, detect %v)", tc.hosts, got, need, cycle, detect)
		}
		if got != tc.want {
			t.Errorf("%d hosts: W = %v, want the design's %v", tc.hosts, got, tc.want)
		}
	}
	if PartitionPauseWait != PartitionPauseWaitFor(1) || PartitionPauseWait != PartitionPauseAfter+PartitionPauseMargin {
		t.Fatalf("PartitionPauseWait %v is not the one-batch W(1) %v = T_pause %v + margin %v",
			PartitionPauseWait, PartitionPauseWaitFor(1), PartitionPauseAfter, PartitionPauseMargin)
	}
	// A loss the majority could not fence must not pause: T_pause is the
	// majority's own verdict-building time.
	if PartitionPauseAfter < FailuresToFence*checkInterval {
		t.Fatalf("T_pause %v is shorter than the %v the majority needs to build a fence verdict", PartitionPauseAfter, FailuresToFence*checkInterval)
	}
}

// InQuorumRegainGraceFor(QuorumScopeCluster): true while the cluster-wide
// quorum is lost and for QuorumRegainGrace after it is regained (its No→Yes
// transition), false for a daemon that never lost it and once the grace has
// passed. The failover coordinator defers new fences while it is true, so the
// failure rows a fleet-wide blip leaves behind fence nobody.
//
// Mutations: never record the loss — the "lost" checks go red; measure the
// grace from the last No instead of the transition (re-arm on every No) — the
// region test below goes red; compare against the wrong side of the grace —
// the "after the grace" check goes red.
func TestInQuorumRegainGrace_Cluster(t *testing.T) {
	db := testCheckHostDB(t)
	for _, h := range []string{"host-a", "host-b", "host-c"} {
		gateHost(t, db, h, "active", "worker")
	}
	c := NewChecker("host-a", "/etc/litevirt/pki", db)
	warm(c, map[string]bool{"host-b": true, "host-c": true})
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumYes {
		t.Fatalf("setup: quorum %d", st)
	}
	if c.InQuorumRegainGraceFor(context.Background(), QuorumScopeCluster) {
		t.Fatal("a daemon that never lost the quorum is in the regain grace")
	}
	warm(c, map[string]bool{"host-b": false, "host-c": false})
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumNo {
		t.Fatalf("setup: quorum %d, want No", st)
	}
	if !c.InQuorumRegainGraceFor(context.Background(), QuorumScopeCluster) {
		t.Fatal("a daemon without the quorum is not held back from fencing")
	}
	warm(c, map[string]bool{"host-b": true, "host-c": true})
	if st, _, _ := c.QuorumProof(context.Background()); st != QuorumYes {
		t.Fatalf("setup: quorum %d after regaining", st)
	}
	if !c.InQuorumRegainGraceFor(context.Background(), QuorumScopeCluster) {
		t.Fatal("a daemon that regained the quorum a moment ago is not in the regain grace")
	}
	c.mu.Lock()
	c.quorumRegainedAt[QuorumScopeCluster] = time.Now().Add(-QuorumRegainGrace - time.Second)
	c.mu.Unlock()
	if c.InQuorumRegainGraceFor(context.Background(), QuorumScopeCluster) {
		t.Fatal("still in the regain grace after it passed")
	}
}

// Under region-scoped failover a region majority WITHOUT a cluster majority is
// exactly the side that fences (docs/design/region-scoped-failover.md). Other
// consumers keep reading the cluster-wide quorum — the VIP demoter, the
// dual-run detector, the lease-term barrier — and it keeps reading No; that
// must not hold the region's fences back. The grace is per scope and runs from
// that scope's own No→Yes transition.
//
// Mutation: key every scope to the cluster-wide quorum — the region grace reads
// true and this goes red.
func TestInQuorumRegainGrace_ARegionMajorityWithoutTheClusterFences(t *testing.T) {
	ctx := context.Background()
	db := testCheckHostDB(t)
	for _, h := range []string{"e1", "e2", "e3", "w1", "w2", "w3", "w4"} {
		gateHost(t, db, h, "active", "worker")
	}
	for _, h := range []string{"e1", "e2", "e3"} {
		if err := corrosion.UpdateHostRegion(ctx, db, h, "east"); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range []string{"w1", "w2", "w3", "w4"} {
		if err := corrosion.UpdateHostRegion(ctx, db, h, "west"); err != nil {
			t.Fatal(err)
		}
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetFailoverScope(ctx, db, corrosion.FailoverScopeRegion, "test"); err != nil {
		t.Fatal(err)
	}
	c := NewChecker("e1", "/etc/litevirt/pki", db)
	// e1 reaches its own region and nothing west: 3 of 7 cluster-wide (No),
	// 3 of 3 in east (Yes).
	warm(c, map[string]bool{"e2": true, "e3": true, "w1": false, "w2": false, "w3": false, "w4": false})
	for i := 0; i < 5; i++ {
		if st, _, _ := c.QuorumProof(ctx); st != QuorumNo {
			t.Fatalf("setup: cluster quorum %d, want No", st)
		}
		if st, _, _ := c.ExecutionQuorum(ctx); st != QuorumYes {
			t.Fatalf("setup: east execution quorum %d, want Yes", st)
		}
	}
	if c.InQuorumRegainGraceFor(context.Background(), RegionQuorumScope("east")) {
		t.Fatal("east's majority is held back from fencing by the cluster-wide quorum it does not decide on")
	}
	if !c.InQuorumRegainGraceFor(context.Background(), QuorumScopeCluster) {
		t.Fatal("the cluster-wide scope, which is lost, reads as not in grace")
	}
}

// A coordinator outside region west reads west's quorum as No once — a
// decision about a west host while west was out of reach — and west then
// heals. Nothing on this daemon re-reads west's quorum on a schedule: only a
// fence decision about a west host does, and the regain grace runs ahead of
// it. A grace that trusted the recorded No would defer every later west fence
// for good. It re-reads instead: the heal opens the grace from the moment it
// is seen, and once that has passed a west host that fails is fenced.
//
// Mutation: drop the fresh read (trust quorumLost) — the "after the grace"
// check goes red, the scope stays in grace forever.
func TestInQuorumRegainGrace_ARemoteRegionHealsAndItsHostsFenceAgain(t *testing.T) {
	ctx := context.Background()
	db := testCheckHostDB(t)
	for _, h := range []string{"e1", "e2", "e3", "w1", "w2", "w3", "w4"} {
		gateHost(t, db, h, "active", "worker")
	}
	for _, h := range []string{"e1", "e2", "e3"} {
		if err := corrosion.UpdateHostRegion(ctx, db, h, "east"); err != nil {
			t.Fatal(err)
		}
	}
	for _, h := range []string{"w1", "w2", "w3", "w4"} {
		if err := corrosion.UpdateHostRegion(ctx, db, h, "west"); err != nil {
			t.Fatal(err)
		}
	}
	db.SetClusterPolicyGate(func() bool { return true })
	if err := corrosion.SetFailoverScope(ctx, db, corrosion.FailoverScopeRegion, "test"); err != nil {
		t.Fatal(err)
	}
	c := NewChecker("e1", "/etc/litevirt/pki", db)
	now := time.Now()
	c.clock = func() time.Time { return now }
	west := RegionQuorumScope("west")

	warm(c, map[string]bool{"e2": true, "e3": true, "w1": false, "w2": false, "w3": false, "w4": false})
	if st, _, _ := c.RegionQuorumProof(ctx, "west"); st != QuorumNo {
		t.Fatalf("setup: west quorum %d, want No", st)
	}
	if !c.InQuorumRegainGraceFor(ctx, west) {
		t.Fatal("west, out of reach, is not held back")
	}

	// West heals; then w1 fails. 3 of 4 west voters answer: still a majority.
	warm(c, map[string]bool{"e2": true, "e3": true, "w1": false, "w2": true, "w3": true, "w4": true})
	if !c.InQuorumRegainGraceFor(ctx, west) {
		t.Fatal("the heal, seen a moment ago, does not open the regain grace")
	}
	now = now.Add(QuorumRegainGrace + time.Second)
	if c.InQuorumRegainGraceFor(ctx, west) {
		t.Fatal("west's fences are still deferred a full grace after its quorum came back")
	}
}

// A lossy link: the quorum reads lost for a stretch and Yes for a shorter one,
// over and over. No Yes run lasts T_pause, so none is a heal, and the loss
// covers most of the window, so the host pauses — while a continuous clock,
// reset by every Yes, never would.
//
// The second pattern: seven seconds lost, three Yes. This host's Yes needs
// only SOME majority of the voters to answer its probes, and each voter's
// failure run is its own, not lined up with this host's readings, so a
// majority of voters can each count five consecutive failures across a
// stretch in which this host reads an intermittent Yes. A three-reading heal
// cleared the window on every Yes run, so the loss never reached T_pause and
// the host never paused, while the voters fenced it and waited out a pause
// that never came.
//
// Mutations: reset the window on any single Yes — the first pattern stays
// running and this goes red; count three Yes readings as a heal — the second
// pattern stays running and this goes red.
func TestPartitionPause_ALossyLinkStillPauses(t *testing.T) {
	for _, pat := range []struct {
		name      string
		lost, yes int
	}{{"two lost, one yes", 2, 1}, {"seven lost, three yes", 7, 3}} {
		t.Run(pat.name, func(t *testing.T) {
			f := newPauseFixture(t)
			for i := 0; i < 40/(pat.lost+pat.yes); i++ {
				f.loseFor(QuorumNo, time.Duration(pat.lost-1)*time.Second) // pat.lost readings lost
				f.set(QuorumYes)
				for j := 0; j < pat.yes; j++ {
					f.tick()
					f.advance(time.Second)
				}
			}
			if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
				t.Fatalf("vm-ha is %s after 40 s of a link losing the majority %d readings in %d",
					st, pat.lost, pat.lost+pat.yes)
			}
		})
	}
}

// Loss starts at the first reading that saw it. A host whose last reading was
// Yes and whose next reads No has been without the majority for T_pause only
// T_pause after that No — not a tick earlier, as charging the interval before
// the No would have it (and a blip a tick short of T_pause would pause, G6).
//
// Mutation: attribute each interval to the later reading — vm-ha pauses one
// reading early and this goes red.
func TestPartitionPause_LossStartsAtTheFirstLostReading(t *testing.T) {
	f := newPauseFixture(t)
	f.set(QuorumYes)
	for i := 0; i < 3; i++ {
		f.tick()
		f.advance(time.Second)
	}
	f.set(QuorumNo)
	for i := 0; i < int(PartitionPauseAfter/time.Second); i++ { // No readings at +0 s … +9 s
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after %v of No readings, short of T_pause", st, PartitionPauseAfter-time.Second)
	}
	f.tick() // +10 s
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s a full T_pause after the first No", st)
	}
}

// The checker's startup warmup reads Unknown, which counts as loss (§3.1) —
// but once the first Yes comes, warmup was never a loss, and a partition
// soon after start gets its full T_pause.
//
// Mutation: keep warmup's readings after the first Yes — vm-ha pauses early
// and this goes red.
func TestPartitionPause_WarmupIsNotALossOnceTheMajorityAnswers(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumUnknown, 2*time.Second) // warmup: three Unknown readings
	f.set(QuorumYes)
	f.tick()
	f.advance(time.Second)
	f.set(QuorumNo)
	for i := 0; i < int(PartitionPauseAfter/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s: startup warmup shortened the next loss", st)
	}
}

// A restart inside a partition reads Unknown then No and never Yes: its
// readings all count, so it pauses as a host that never restarted would.
//
// Mutation: drop warmup's readings on the first No as well — vm-ha pauses
// late and this goes red.
func TestPartitionPause_ARestartInsideAPartitionKeepsItsLoss(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumUnknown, 2*time.Second)
	f.loseFor(QuorumNo, PartitionPauseAfter-3*time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after T_pause of Unknown-then-No since start", st)
	}
}

// A heal is an unbroken T_pause of Yes: one reading short of it resumes
// nothing, and the reading that completes it does.
//
// Mutation: count a heal before T_pause — vm-ha resumes early and this goes
// red; never count one — vm-ha stays paused and this goes red.
func TestPartitionPause_AHealIsASustainedYesOfTPause(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("setup: vm-ha is %s", st)
	}
	f.set(QuorumYes)
	for i := 0; i < int(PartitionPauseAfter/time.Second); i++ {
		f.tick()
		f.advance(time.Second)
	}
	if st := f.raw("vm-ha"); st != libvirtfake.StatePaused {
		t.Fatalf("vm-ha is %s after %v of Yes, short of the T_pause a heal takes", st, PartitionPauseAfter-time.Second)
	}
	f.tick()
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("vm-ha is %s after an unbroken T_pause of Yes", st)
	}
}

// A record that no longer describes a paused domain is dropped when the
// majority is back, and partition_paused resolves: a held record must not
// keep the condition open forever, nor offer a stale epoch later.
//
// Mutation: keep such records — the record and the condition remain and this
// goes red.
func TestPartitionPause_DropsARecordWhoseDomainIsNoLongerPaused(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if len(f.records()) != 1 {
		t.Fatalf("setup: records %+v", f.records())
	}
	f.virt.SetState("vm-ha", libvirtfake.StateRunning) // an operator resumed it
	f.p.SetResumeConfirmer(nil)                        // and nothing would ever confirm it
	f.regain()
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("records = %+v after the domain stopped being paused", recs)
	}
	if c, ok := f.condition(corrosion.CondPartitionPaused); !ok || c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("partition_paused is not resolved (ok=%v %+v)", ok, c)
	}
}

// A record whose domain has been undefined since describes nothing: the
// domain lookup now fails not-found, and the record is dropped so
// partition_paused resolves. (Real libvirt reports an undefined domain as a
// lookup error, not as a state.)
//
// Mutation: keep a record whose lookup fails not-found — the record and the
// condition remain and this goes red.
func TestPartitionPause_DropsARecordWhoseDomainIsUndefined(t *testing.T) {
	f := newPauseFixture(t)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if len(f.records()) != 1 {
		t.Fatalf("setup: records %+v", f.records())
	}
	f.virt.FailDomainStateReason = func(name string) error {
		if name == "vm-ha" {
			return fmt.Errorf("lookup domain %s: Domain not found: no domain with matching name '%s'", name, name)
		}
		return nil
	}
	f.p.SetResumeConfirmer(nil)
	f.regain()
	if recs := f.records(); len(recs) != 0 {
		t.Fatalf("records = %+v after the domain was undefined", recs)
	}
	if c, ok := f.condition(corrosion.CondPartitionPaused); !ok || c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("partition_paused is not resolved (ok=%v %+v)", ok, c)
	}
}

// A libvirtd that wedges holds at most one abandoned goroutine per read kind:
// while a DomainStateReason has not returned, later ones fail at once instead
// of each leaving another goroutine behind, and every one of them is a failed
// pause. Once it returns, reads run again.
//
// Mutation: drop the guard — every tick issues another call and this goes red.
func TestPartitionPause_AWedgedReadLeaksOneGoroutinePerKind(t *testing.T) {
	f := newPauseFixture(t)
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	f.virt.FailDomainStateReason = func(name string) error {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return nil
	}
	f.loseFor(QuorumNo, PartitionPauseAfter+5*time.Second)
	mu.Lock()
	n := calls
	mu.Unlock()
	close(release)
	if n != 1 {
		t.Fatalf("%d DomainStateReason calls were issued against a wedged libvirtd; the guard admits one", n)
	}
	if failed, _ := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); !failed {
		t.Fatal("reads refused by the guard did not raise partition_pause_failed")
	}
}

// A slow libvirtd — every read answers, each just under the call timeout —
// cannot stretch the pass past E: reads stop at the pass budget and every
// domain left unread is a failed pause, not a wait.
//
// Mutation: give each read the full call timeout whatever is left of the
// pass — the pass takes about 8 s and this goes red.
func TestPartitionPause_ASlowLibvirtdCannotStretchThePassPastE(t *testing.T) {
	f := newPauseFixture(t)
	for _, n := range []string{"vm-x1", "vm-x2", "vm-x3", "vm-x4", "vm-x5", "vm-x6"} {
		f.virt.SetState(n, libvirtfake.StateRunning)
	}
	f.loseFor(QuorumNo, PartitionPauseAfter-time.Second) // one reading short of pausing
	f.virt.FailDomainStateReason = func(string) error {
		time.Sleep(partitionPauseCallTimeout * 3 / 4)
		return nil
	}
	start := time.Now()
	f.tick()
	if took := time.Since(start); took > PartitionPauseExecBudget+time.Second {
		t.Fatalf("the pause pass took %v against a slow libvirtd; E is %v", took, PartitionPauseExecBudget)
	}
	if failed, _ := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); !failed {
		t.Fatal("domains the pass had no budget to read were not reported as a failed pause")
	}
}

// Every workload the pass cannot account for is a failed pause: a domain whose
// state cannot be read is not known to be stopped.
//
// Mutation: skip an unreadable domain silently — no condition, and this goes
// red.
func TestPartitionPause_AnUnreadableDomainIsAFailedPause(t *testing.T) {
	f := newPauseFixture(t)
	f.virt.FailDomainStateReason = func(name string) error {
		if name == "vm-ha" {
			return errors.New("injected: libvirtd not answering")
		}
		return nil
	}
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if failed, _ := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); !failed {
		t.Fatal("an unreadable domain did not raise partition_pause_failed; the majority would count it paused")
	}
}

// A suspend that hangs is abandoned at the call timeout — the pass ends in its
// budget — and is never issued a second time while it is still running.
//
// Mutations: no in-flight guard — the second pass calls suspend again and
// this goes red; no call timeout — the pass blocks past its budget and this
// goes red.
func TestPartitionPause_AHungSuspendIsBoundedAndNotRepeated(t *testing.T) {
	f := newPauseFixture(t)
	release := make(chan struct{})
	defer close(release)
	var calls sync.Mutex
	n := 0
	f.virt.FailSuspendDomain = func(string) error {
		calls.Lock()
		n++
		calls.Unlock()
		<-release
		return nil
	}
	f.loseFor(QuorumNo, PartitionPauseAfter-time.Second)
	start := time.Now()
	f.tick() // the pass that pauses
	if d := time.Since(start); d > PartitionPauseExecBudget {
		t.Fatalf("a pass with a hung suspend took %v, past the %v budget", d, PartitionPauseExecBudget)
	}
	f.advance(time.Second)
	f.tick() // the next pass, with the first suspend still hung
	calls.Lock()
	got := n
	calls.Unlock()
	if got != 1 {
		t.Fatalf("suspend was called %d times while the first call was still running", got)
	}
	if failed, _ := corrosion.HostPartitionPauseFailed(context.Background(), f.db, "node-a"); !failed {
		t.Fatal("a hung suspend did not raise partition_pause_failed")
	}
}

// A VM being live-migrated is not paused: its target takes over.
//
// Mutation: drop the migrating exclusion — the VM is suspended and this goes
// red.
func TestPartitionPause_LeavesAMigratingVMAlone(t *testing.T) {
	f := newPauseFixture(t)
	if err := corrosion.UpdateVMState(context.Background(), f.db, "vm-ha", "migrating", ""); err != nil {
		t.Fatal(err)
	}
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw("vm-ha"); st != libvirtfake.StateRunning {
		t.Fatalf("a migrating VM is %s", st)
	}
}

// PeerAdvertisedLast reads the last cached Ping, however old, and never
// pings: the coordinator asks it about a host it has just found unreachable.
//
// Mutation: honour the cache TTL — the stale entry reads false and this goes
// red; ignore the entry's tokens — the second check goes red.
func TestPeerAdvertisedLast(t *testing.T) {
	c := NewChecker("host-a", "/etc/litevirt/pki", testCheckHostDB(t))
	if c.PeerAdvertisedLast("host-b", capabilities.PartitionPauseV1) {
		t.Fatal("a peer never pinged reads as advertising")
	}
	c.mu.Lock()
	c.peerCaps["host-b"] = peerCapEntry{caps: []string{capabilities.PartitionPauseV1}, fetchedAt: time.Now().Add(-time.Hour)}
	c.peerCaps["host-c"] = peerCapEntry{caps: []string{capabilities.SplitBrainGateV1}, fetchedAt: time.Now()}
	c.mu.Unlock()
	if !c.PeerAdvertisedLast("host-b", capabilities.PartitionPauseV1) {
		t.Fatal("an hour-old Ping that advertised the token reads false")
	}
	if c.PeerAdvertisedLast("host-c", capabilities.PartitionPauseV1) {
		t.Fatal("a Ping without the token reads true")
	}
}
