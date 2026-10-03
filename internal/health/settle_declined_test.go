package health

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	if !strings.Contains(ev.Reason, "incarnation is unknown") || ev.ReasonClass != "incarnation_unknown" ||
		ev.RowHost != "node-b" || !strings.Contains(ev.Remedy, "virsh destroy vm-a") || ev.Local["owner_epoch"] != float64(3) {
		t.Fatalf("evidence does not say why or what to do: %+v", ev)
	}
	// The remedy must make the operator confirm which copy is current first
	// (a converged-wrong host_name looks the same), and must not promise the
	// definition survives: the leftover cleanup undefines it, NVRAM included.
	for _, want := range []string{"lv cluster claim vm/vm-a", "virsh domstate vm-a", "converged-wrong host_name",
		"definition and NVRAM are removed"} {
		if !strings.Contains(ev.Remedy, want) {
			t.Fatalf("remedy lacks %q: %s", want, ev.Remedy)
		}
	}
	if strings.Contains(ev.Remedy, "definition and disks are kept") {
		t.Fatalf("remedy still claims the definition is kept: %s", ev.Remedy)
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

// A pass that could not EXAMINE a copy proves nothing by its absence from the
// declines: the copy's runtime state was unreadable, or its row says it is
// migrating. The open decline must stay as it is — resolving it only re-raises
// it a pass later, which is the flapping an operator would see. A complete pass
// without the copy then resolves it.
//
// Mutations: drop the keep mark for an unreadable state, or for a migrating
// row, or ignore keep in reportSettleDeclines — each goes red.
func TestSettle_AnUnexaminedCopyKeepsItsDecline(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		blind func(f *settleFixture)
		see   func(f *settleFixture)
	}{
		{"runtime state unreadable",
			func(f *settleFixture) {
				f.virt.FailDomainStateReason = func(string) error { return errors.New("libvirt: connection reset") }
			},
			func(f *settleFixture) { f.virt.FailDomainStateReason = nil }},
		{"row migrating",
			func(f *settleFixture) {
				if err := f.db.Execute(ctx, `UPDATE vms SET state = 'migrating' WHERE name = 'vm-a'`); err != nil {
					f.t.Fatal(err)
				}
			},
			func(f *settleFixture) {
				if err := f.db.Execute(ctx, `UPDATE vms SET state = 'running' WHERE name = 'vm-a'`); err != nil {
					f.t.Fatal(err)
				}
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSettleFixture(t)
			olderBuildCopy(f)
			f.run()
			f.run()
			if c, _, ok := settleDeclinedCondition(t, f); !ok || c.Lifecycle != corrosion.ConditionConfirmed {
				t.Fatalf("vm_settle_declined = (%+v, %v), want confirmed", c, ok)
			}
			tc.blind(f)
			f.run()
			if c, _, _ := settleDeclinedCondition(t, f); c.Lifecycle != corrosion.ConditionConfirmed {
				t.Fatalf("a pass that could not examine the copy resolved its decline: %+v", c)
			}
			tc.see(f)
			// Settle can now examine it and still declines: confirmed throughout.
			f.run()
			if c, _, _ := settleDeclinedCondition(t, f); c.Lifecycle != corrosion.ConditionConfirmed {
				t.Fatalf("decline after the blind pass is %s, want confirmed", c.Lifecycle)
			}
			// A complete pass without the copy resolves it.
			f.r.reportSettleDeclines(ctx, nil, nil)
			if c, _, _ := settleDeclinedCondition(t, f); c.Lifecycle != corrosion.ConditionResolved {
				t.Fatalf("a complete pass without the copy left the decline %s, want resolved", c.Lifecycle)
			}
		})
	}
}

// The raw reason can change every pass for one cause — an unreachable
// destination's gRPC error text varies. The rate limit is on the reason's
// CLASS, so a stream of different error strings logs once, not every pass, and
// rewrites the condition only on the log's cadence.
//
// Mutation: rate-limit on the raw reason again — this goes red.
func TestSettle_TheRateLimitIsOnTheReasonClass(t *testing.T) {
	f := newSettleFixture(t)
	olderBuildCopy(f)
	if err := f.virt.SetDomainManagedIncarnation("vm-a", corrosion.IncarnationOf(f.row.CreatedAt), true); err != nil {
		t.Fatal(err)
	}
	n := 0
	f.r.SetPeerRuntimeChecker(func(context.Context, string, string) (string, error) {
		n++
		return "", fmt.Errorf("rpc error: code = Unavailable desc = connection attempt %d refused", n)
	})
	clock := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	f.r.Now = func() time.Time { return clock }
	lines := captureSettleLogs(t)
	for i := 0; i < 5; i++ {
		f.run()
		clock = clock.Add(15 * time.Second)
	}
	if got := len(lines()); got != 1 {
		t.Fatalf("five passes of one cause with changing error text logged %d lines, want 1", got)
	}
	if !strings.Contains(lines()[0], "reason_class=destination_unreachable") {
		t.Fatalf("log line lacks the reason class: %s", lines()[0])
	}
	c, ev, ok := settleDeclinedCondition(t, f)
	if !ok || ev.ReasonClass != "destination_unreachable" {
		t.Fatalf("condition evidence class = %q (ok=%v), want destination_unreachable", ev.ReasonClass, ok)
	}
	// Raised once (second pass), then not rewritten for every new error string.
	if c.ObserveCount != 1 {
		t.Fatalf("condition written %d times over five passes of one cause, want 1", c.ObserveCount)
	}
}

// settleReasonClass must give every reason settle produces a stable class, so
// none falls to "other" (where every such reason would share one class).
func TestSettleReasonClass_EveryReasonHasAClass(t *testing.T) {
	for reason, want := range map[string]string{
		"the row does not name another host":                                                          "row_not_elsewhere",
		"the local copy's incarnation is unknown (no pause record, no managed-stamp incarnation)":     "incarnation_unknown",
		"the local copy's owner epoch is unknown (no pause record, no owner-epoch marker)":            "epoch_unknown",
		"the row is another incarnation of the name":                                                  "row_other_incarnation",
		"no certificate verifier":                                                                     "not_wired",
		"no certificate verifier wired":                                                               "not_wired",
		"no destination runtime check":                                                                "not_wired",
		"proofs unreadable: disk I/O error":                                                           "proofs_unreadable",
		"destroy failed: domain is locked":                                                            "destroy_failed",
		"no verified recovery-claim certificate gives this incarnation to node-b at owner epoch >= 3": "no_certificate",
		"proof p1 is prepared, not completed: no replacement is known to run":                         "proof_not_completed",
		`proof p1 was executed by "node-c", not its destination node-b`:                               "proof_executed_elsewhere",
		"proof p1: destination node-b unreachable: rpc error: code = Unavailable":                     "destination_unreachable",
		"proof p1: destination node-b reports it defined_stopped, not running":                        "destination_not_running",
		"proof p1's certificate decides another incarnation":                                          "certificate_other_incarnation",
		"proof p1's certificate decides owner epoch 2, older than the local copy's 3":                 "certificate_older_epoch",
		"proof p1: too few valid accepts":                                                             "certificate_invalid",
	} {
		if got := settleReasonClass(reason); got != want {
			t.Errorf("settleReasonClass(%q) = %q, want %q", reason, got, want)
		}
	}
}
