package health

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// scriptedProbe is a probe transport a test flips between passing and failing.
type scriptedProbe struct {
	mu     sync.Mutex
	pass   bool
	reason string
	calls  int
}

func (p *scriptedProbe) set(pass bool, reason string) {
	p.mu.Lock()
	p.pass, p.reason = pass, reason
	p.mu.Unlock()
}

func (p *scriptedProbe) fn(context.Context, corrosion.VMRecord, *pb.HealthCheckSpec) (bool, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls++
	if p.pass {
		return true, ""
	}
	return false, p.reason
}

func (p *scriptedProbe) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

type probeFixture struct {
	t     *testing.T
	ctx   context.Context
	db    *corrosion.Client
	v     *VMChecker
	probe *scriptedProbe
}

// newProbeFixture registers host node1 and a running VM "web" on it whose
// healthcheck is hc (nil: no healthcheck), with a scripted probe wired.
func newProbeFixture(t *testing.T, hc *pb.HealthCheckSpec) *probeFixture {
	t.Helper()
	db := testVMDB(t)
	ctx := context.Background()
	if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{
		Name: "node1", Address: "10.0.0.1", SSHUser: "root", SSHPort: 22, GRPCPort: 7443,
		State: "active", CertSerial: "a", MemTotal: 8192,
	}); err != nil {
		t.Fatalf("InsertHost: %v", err)
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "web", Healthcheck: hc})
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{
		Name: "web", HostName: "node1", Spec: string(spec), State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	v := NewVMChecker("node1", t.TempDir(), db, nil)
	p := &scriptedProbe{reason: "tcp 10.0.0.9:80: connection refused"}
	v.SetProbeFunc(p.fn)
	return &probeFixture{t: t, ctx: ctx, db: db, v: v, probe: p}
}

func (f *probeFixture) vm() *corrosion.VMRecord {
	f.t.Helper()
	vm, err := corrosion.GetVM(f.ctx, f.db, "web")
	if err != nil || vm == nil {
		f.t.Fatalf("GetVM: vm=%v err=%v", vm, err)
	}
	return vm
}

func (f *probeFixture) health() VMHealth {
	f.t.Helper()
	h, err := EvaluateVMHealth(f.ctx, f.db, f.vm())
	if err != nil {
		f.t.Fatalf("EvaluateVMHealth: %v", err)
	}
	return h
}

// rowStamp is the verdict row's updated_at: it moves on every write.
func (f *probeFixture) rowStamp() string {
	f.t.Helper()
	rows, err := f.db.Query(f.ctx, `SELECT updated_at FROM health_conditions
		WHERE evaluator = ? AND code = ? AND subject_id = 'web'`, VMProbeEvaluator, CondVMProbeFailing)
	if err != nil {
		f.t.Fatalf("read verdict row: %v", err)
	}
	if len(rows) == 0 {
		return ""
	}
	return rows[0].String("updated_at")
}

func (f *probeFixture) verdictRow() corrosion.HealthCondition {
	f.t.Helper()
	row, ok, err := corrosion.GetHealthCondition(f.ctx, f.db, VMProbeEvaluator, CondVMProbeFailing, "vm", "web")
	if err != nil || !ok {
		f.t.Fatalf("verdict row: ok=%v err=%v", ok, err)
	}
	return row
}

var tcpCheck = &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:80", Interval: "1ms", Retries: 2}

func TestVMHealth_NoHealthcheckRunningIsHealthy(t *testing.T) {
	f := newProbeFixture(t, nil)
	if h := f.health(); !h.Satisfied || h.HasHealthcheck {
		t.Fatalf("running VM without a healthcheck: %+v, want satisfied", h)
	}
	if err := corrosion.UpdateVMState(f.ctx, f.db, "web", "stopped", ""); err != nil {
		t.Fatal(err)
	}
	if h := f.health(); h.Satisfied {
		t.Fatalf("stopped VM without a healthcheck satisfied vm_healthy: %+v", h)
	}
}

func TestVMHealth_RunningIsNotEnoughWithAHealthcheck(t *testing.T) {
	f := newProbeFixture(t, tcpCheck)
	h := f.health()
	if h.Satisfied {
		t.Fatalf("running VM with a healthcheck and no verdict satisfied vm_healthy: %+v", h)
	}
	if h.Verdict != VerdictUnknown || !strings.Contains(h.Detail, "no probe verdict") {
		t.Errorf("health = %+v, want unknown / no probe verdict", h)
	}
}

func TestVMHealth_PassingProbeIsPublishedAndSatisfies(t *testing.T) {
	f := newProbeFixture(t, tcpCheck)
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	if h := f.health(); !h.Satisfied || h.Verdict != VerdictHealthy {
		t.Fatalf("after a passing probe: %+v, want healthy", h)
	}
	row := f.verdictRow()
	if row.Reporter != "node1" || row.Lifecycle != corrosion.ConditionResolved || row.Severity != corrosion.SeverityInfo {
		t.Errorf("healthy verdict row = %+v, want reporter node1, resolved, info", row)
	}
}

// Replication cost: a verdict is written on a transition, never per probe.
func TestVMHealth_VerdictIsWrittenOnlyOnTransition(t *testing.T) {
	f := newProbeFixture(t, tcpCheck)
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	first := f.rowStamp()
	if first == "" {
		t.Fatal("no verdict row after a passing probe")
	}
	for i := 0; i < 5; i++ {
		f.v.SweepOnce(f.ctx)
	}
	if f.probe.count() < 6 {
		t.Fatalf("probe ran %d times, want 6 (interval 1ms)", f.probe.count())
	}
	if got := f.rowStamp(); got != first {
		t.Fatalf("verdict row rewritten by repeated passing probes: %s -> %s", first, got)
	}

	// One failure is below retries (2): still healthy, still no write.
	f.probe.set(false, "tcp 10.0.0.9:80: connection refused")
	f.v.SweepOnce(f.ctx)
	if got := f.rowStamp(); got != first {
		t.Fatalf("verdict row rewritten by a failure below retries")
	}
	if h := f.health(); !h.Satisfied {
		t.Fatalf("one failure below retries flipped the verdict: %+v", h)
	}
	// The second consecutive failure is the transition.
	f.v.SweepOnce(f.ctx)
	unhealthy := f.rowStamp()
	if unhealthy == first {
		t.Fatal("healthy -> unhealthy transition was not written")
	}
	for i := 0; i < 3; i++ {
		f.v.SweepOnce(f.ctx)
	}
	if got := f.rowStamp(); got != unhealthy {
		t.Fatal("verdict row rewritten by repeated failing probes")
	}
}

func TestVMHealth_UnhealthyAfterRetriesCarriesTheReason(t *testing.T) {
	f := newProbeFixture(t, tcpCheck)
	f.probe.set(false, "tcp 10.0.0.9:80: connection refused")
	f.v.SweepOnce(f.ctx)
	if f.rowStamp() != "" {
		t.Fatal("a verdict was published before retries failures")
	}
	f.v.SweepOnce(f.ctx)
	h := f.health()
	if h.Satisfied || h.Verdict != VerdictUnhealthy {
		t.Fatalf("after retries failures: %+v, want unhealthy", h)
	}
	if !strings.Contains(h.Detail, "connection refused") {
		t.Errorf("unhealthy detail %q does not carry the probe's reason", h.Detail)
	}
	row := f.verdictRow()
	if row.Lifecycle != corrosion.ConditionConfirmed {
		t.Errorf("failing verdict lifecycle = %s, want confirmed (an open condition)", row.Lifecycle)
	}
	if row.Severity != corrosion.SeverityInfo {
		t.Errorf("failing verdict severity = %s, want info (it must not degrade the cluster roll-up)", row.Severity)
	}

	// Recovery is one pass.
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	if h := f.health(); !h.Satisfied {
		t.Fatalf("after recovery: %+v, want healthy", h)
	}
}

// A pass observed before a restart must not satisfy a wait on the VM after it.
func TestVMHealth_PassFromAPreviousIncarnationIsNotAPass(t *testing.T) {
	f := newProbeFixture(t, tcpCheck)
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	if !f.health().Satisfied {
		t.Fatal("setup: not healthy")
	}

	// A restart republishes "running", which rewrites the VM row.
	time.Sleep(2 * time.Millisecond)
	if err := corrosion.UpdateVMStateStrict(f.ctx, f.db, "web", "running", "restarted"); err != nil {
		t.Fatal(err)
	}
	h := f.health()
	if h.Satisfied {
		t.Fatalf("a verdict from before the restart satisfied vm_healthy: %+v", h)
	}
	if !strings.Contains(h.Detail, "previous incarnation") {
		t.Errorf("detail %q does not say the verdict is from a previous incarnation", h.Detail)
	}

	// The new incarnation's first probe fails (below retries): the old pass
	// must not be carried over to it.
	f.probe.set(false, "tcp 10.0.0.9:80: connection refused")
	f.v.SweepOnce(f.ctx)
	if h := f.health(); h.Satisfied {
		t.Fatalf("the old incarnation's pass was re-bound to the new one: %+v", h)
	}

	// Its first pass is what satisfies the wait.
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	if h := f.health(); !h.Satisfied {
		t.Fatalf("new incarnation passed but is not healthy: %+v", h)
	}
}

// A recreated VM (same name, new row) is a new incarnation too.
func TestVMHealth_RecreatedVMIsANewIncarnation(t *testing.T) {
	f := newProbeFixture(t, tcpCheck)
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	vm := f.vm()
	if err := corrosion.DeleteVM(f.ctx, f.db, "web"); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}
	time.Sleep(2 * time.Millisecond)
	if err := corrosion.InsertVM(f.ctx, f.db, corrosion.VMRecord{
		Name: "web", HostName: "node1", Spec: vm.Spec, State: "running",
	}, nil, nil); err != nil {
		t.Fatalf("re-InsertVM: %v", err)
	}
	if h := f.health(); h.Satisfied {
		t.Fatalf("the deleted VM's pass satisfied vm_healthy for its replacement: %+v", h)
	}
}

// A host that goes down cannot retract its last pass: the reader must stop
// believing it.
func TestVMHealth_OwnerHostDownMakesTheVerdictUnknown(t *testing.T) {
	for _, state := range []string{"offline", "fenced", "maintenance"} {
		t.Run(state, func(t *testing.T) {
			f := newProbeFixture(t, tcpCheck)
			f.probe.set(true, "")
			f.v.SweepOnce(f.ctx)
			if !f.health().Satisfied {
				t.Fatal("setup: not healthy")
			}
			if err := corrosion.UpdateHostState(f.ctx, f.db, "node1", state); err != nil {
				t.Fatal(err)
			}
			h := f.health()
			if h.Satisfied || h.Verdict != VerdictUnknown {
				t.Fatalf("owner %s: %+v, want unknown and not satisfied", state, h)
			}
			if !strings.Contains(h.Detail, "node1") || !strings.Contains(h.Detail, state) {
				t.Errorf("detail %q does not name the host and its state", h.Detail)
			}
		})
	}
}

// The start grace period still gates the healthcheck's ACTION, but no longer
// the probe: a waiter needs the verdict of a VM that was just created.
func TestVMHealth_GracePeriodProbesButDoesNotAct(t *testing.T) {
	f := newProbeFixture(t, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:80", Interval: "1ms", Retries: 1, Action: "restart"})
	f.probe.set(false, "tcp 10.0.0.9:80: connection refused")
	f.v.SweepOnce(f.ctx)
	if f.probe.count() != 1 {
		t.Fatalf("probe ran %d times for a VM inside its grace period, want 1", f.probe.count())
	}
	if h := f.health(); h.Verdict != VerdictUnhealthy {
		t.Fatalf("grace-period failure verdict = %+v, want unhealthy", h)
	}
	f.v.mu.Lock()
	acts, fails := f.v.actionCount["web"], f.v.failures["web"]
	f.v.mu.Unlock()
	if acts != 0 || fails != 0 {
		t.Errorf("grace-period failure counted toward the action: actions=%d failures=%d", acts, fails)
	}
}

func TestVMHealth_IntervalIsHonoured(t *testing.T) {
	f := newProbeFixture(t, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:80", Interval: "1h"})
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	f.v.SweepOnce(f.ctx)
	if n := f.probe.count(); n != 1 {
		t.Fatalf("interval 1h: probe ran %d times in two sweeps, want 1", n)
	}
	// A new incarnation is probed at once, interval or not.
	time.Sleep(2 * time.Millisecond)
	if err := corrosion.UpdateVMStateStrict(f.ctx, f.db, "web", "running", "restarted"); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx)
	if n := f.probe.count(); n != 2 {
		t.Fatalf("new incarnation was not probed at once: %d probes", n)
	}
}

func TestVMHealth_StoppedVMVerdictBecomesUnknownOnce(t *testing.T) {
	f := newProbeFixture(t, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:80", Interval: "1ms", Retries: 1})
	f.probe.set(false, "refused")
	f.v.SweepOnce(f.ctx)
	if f.verdictRow().Lifecycle != corrosion.ConditionConfirmed {
		t.Fatal("setup: not failing")
	}
	if err := corrosion.UpdateVMState(f.ctx, f.db, "web", "stopped", "operator-stop"); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx)
	row := f.verdictRow()
	ev, _ := decodeVerdict(row)
	if row.Lifecycle != corrosion.ConditionResolved || ev.Verdict != VerdictUnknown {
		t.Fatalf("stopped VM verdict = %s/%s, want resolved/unknown", row.Lifecycle, ev.Verdict)
	}
	stamp := f.rowStamp()
	f.v.SweepOnce(f.ctx)
	if f.rowStamp() != stamp {
		t.Fatal("an unknown verdict was rewritten on a later sweep")
	}
	// The verdict row is its own row: the stop reason is untouched.
	if vm := f.vm(); vm.StateDetail != "operator-stop" {
		t.Errorf("state_detail = %q after verdict writes, want operator-stop", vm.StateDetail)
	}
}

func TestVMHealth_DeletedVMFailingVerdictIsResolved(t *testing.T) {
	f := newProbeFixture(t, &pb.HealthCheckSpec{Type: "tcp", Target: "10.0.0.9:80", Interval: "1ms", Retries: 1})
	f.probe.set(false, "refused")
	f.v.SweepOnce(f.ctx)
	if err := corrosion.DeleteVM(f.ctx, f.db, "web"); err != nil {
		t.Fatal(err)
	}
	f.v.SweepOnce(f.ctx)
	row := f.verdictRow()
	if row.Lifecycle != corrosion.ConditionResolved || !strings.Contains(row.Evidence, "deleted") {
		t.Fatalf("deleted VM's failing verdict = %s %s, want resolved (deleted)", row.Lifecycle, row.Evidence)
	}
}

// A verdict row that disappeared (the 30-day resolved GC, a lost write) is
// republished by the next probe without any periodic rewrite.
func TestVMHealth_MissingRowIsRepublished(t *testing.T) {
	f := newProbeFixture(t, tcpCheck)
	f.probe.set(true, "")
	f.v.SweepOnce(f.ctx)
	if err := f.db.Execute(f.ctx, `UPDATE health_conditions SET deleted_at = ? WHERE subject_id = 'web'`,
		time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if f.health().Satisfied {
		t.Fatal("setup: tombstoned verdict still read")
	}
	f.v.SweepOnce(f.ctx)
	if h := f.health(); !h.Satisfied {
		t.Fatalf("tombstoned verdict was not republished: %+v", h)
	}
}
