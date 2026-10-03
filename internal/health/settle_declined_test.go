package health

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// captureSettleLogs routes slog through a buffer for the test and returns a
// counter of the settle-declined lines. Health tests do not run in parallel, so
// swapping the default logger is safe; it is restored on cleanup.
func captureSettleLogs(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&lockedWriter{mu: &mu, w: &buf}, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		var out []string
		for _, l := range strings.Split(buf.String(), "\n") {
			if strings.Contains(l, settleDeclinedLogMsg) {
				out = append(out, l)
			}
		}
		return out
	}
}

type lockedWriter struct {
	mu *sync.Mutex
	w  *bytes.Buffer
}

func (l *lockedWriter) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.w.Write(p)
}

// olderBuildCopy turns the fixture's local copy into the lab's: a RUNNING
// domain an older build defined — no managed-stamp incarnation, no pause
// record — whose owner epoch is known. Settle cannot identify it.
func olderBuildCopy(f *settleFixture) {
	f.t.Helper()
	if err := RemovePauseRecord(f.dataDir, PauseKindVM, "vm-a"); err != nil {
		f.t.Fatal(err)
	}
	f.virt.SetState("vm-a", libvirtfake.StateRunning)
	if err := f.virt.SetDomainOwnerEpoch("vm-a", 3, true); err != nil {
		f.t.Fatal(err)
	}
}

func settleDeclinedCondition(t *testing.T, f *settleFixture) (corrosion.HealthCondition, settleDeclinedEvidence, bool) {
	t.Helper()
	c, ok, err := corrosion.GetHealthCondition(context.Background(), f.db, corrosion.PartitionPauseEvaluator,
		corrosion.CondVMSettleDeclined, "vm", "vm-a@node-a")
	if err != nil {
		t.Fatal(err)
	}
	var ev settleDeclinedEvidence
	if ok {
		if err := json.Unmarshal([]byte(c.Evidence), &ev); err != nil {
			t.Fatalf("evidence %q: %v", c.Evidence, err)
		}
	}
	return c, ev, ok
}

// The lab case: a stale copy settle cannot identify used to be declined with
// nothing said about why. The decline is logged with its reason — once per
// reason, again only after settleDeclineLogEvery — and raised as
// vm_settle_declined with the reason and what to do; it resolves once the
// copy is no longer declined.
//
// Mutations: drop the log line, or log on every pass, or skip the condition
// write, or never resolve it — each goes red here.
func TestSettle_ADeclineSaysWhyAndWhatToDo(t *testing.T) {
	f := newSettleFixture(t)
	olderBuildCopy(f)
	clock := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.r.Now = func() time.Time { return clock }
	lines := captureSettleLogs(t)

	f.run()
	if got := len(lines()); got != 1 {
		t.Fatalf("first decline logged %d settle-declined lines, want 1", got)
	}
	if !strings.Contains(lines()[0], "incarnation is unknown") || !strings.Contains(lines()[0], "virsh destroy vm-a") {
		t.Fatalf("the decline log must carry the reason and the remedy: %s", lines()[0])
	}
	if _, _, ok := settleDeclinedCondition(t, f); ok {
		t.Fatal("vm_settle_declined raised on the first sighting; a transient decline must not raise it")
	}

	// The same reason every pass: no new line, and the condition is raised.
	for i := 0; i < 3; i++ {
		clock = clock.Add(15 * time.Second)
		f.run()
	}
	if got := len(lines()); got != 1 {
		t.Fatalf("an unchanged reason logged %d lines over four passes, want 1 (rate-limited)", got)
	}
	c, ev, ok := settleDeclinedCondition(t, f)
	if !ok || c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("vm_settle_declined = (%+v, %v), want confirmed", c, ok)
	}
	if !strings.Contains(ev.Reason, "incarnation is unknown") || ev.RowHost != "node-b" ||
		!strings.Contains(ev.Remedy, "virsh destroy vm-a") || ev.Local["owner_epoch"] != float64(3) {
		t.Fatalf("evidence does not say why or what to do: %+v", ev)
	}

	// Past the interval the same reason is logged again.
	clock = clock.Add(settleDeclineLogEvery)
	f.run()
	if got := len(lines()); got != 2 {
		t.Fatalf("after %s the decline logged %d lines in all, want 2", settleDeclineLogEvery, got)
	}

	// A new reason is logged at once and replaces the evidence.
	if err := f.virt.SetDomainManagedIncarnation("vm-a", corrosion.IncarnationOf(f.row.CreatedAt), true); err != nil {
		t.Fatal(err)
	}
	f.destState = RuntimeDefinedStopped
	clock = clock.Add(15 * time.Second)
	f.run()
	if got := len(lines()); got != 3 {
		t.Fatalf("a changed reason logged %d lines in all, want 3", got)
	}
	if _, ev, _ := settleDeclinedCondition(t, f); !strings.Contains(ev.Reason, "not running") {
		t.Fatalf("evidence kept the old reason after it changed: %+v", ev)
	}

	// Positive proof arrives: the copy settles and the condition resolves.
	f.destState = RuntimeRunning
	clock = clock.Add(15 * time.Second)
	if st := f.run(); st != libvirtfake.StateShutdown {
		t.Fatalf("vm-a is %s; with the proof complete it settles", st)
	}
	if c, _, ok := settleDeclinedCondition(t, f); !ok || c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("vm_settle_declined = (%+v, %v) after the copy settled, want resolved", c, ok)
	}
}

// A pass that could not read every row proves nothing by a copy's absence from
// its declines: a transient read error must not resolve an open decline.
//
// Mutation: ignore incomplete in reportSettleDeclines — this goes red.
func TestSettle_AnIncompletePassResolvesNoDecline(t *testing.T) {
	f := newSettleFixture(t)
	olderBuildCopy(f)
	f.run()
	f.run()
	if c, _, ok := settleDeclinedCondition(t, f); !ok || c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("vm_settle_declined = (%+v, %v), want confirmed", c, ok)
	}
	f.r.reportSettleDeclines(context.Background(), nil, true)
	if c, _, _ := settleDeclinedCondition(t, f); c.Lifecycle != corrosion.ConditionConfirmed {
		t.Fatalf("an incomplete pass resolved the decline: %+v", c)
	}
	f.r.reportSettleDeclines(context.Background(), nil, false)
	if c, _, _ := settleDeclinedCondition(t, f); c.Lifecycle != corrosion.ConditionResolved {
		t.Fatalf("a complete pass without the copy left the decline %s, want resolved", c.Lifecycle)
	}
}
