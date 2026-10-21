package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// withMigratingInventory answers failover's ask of a migration target with
// ask, for the test.
func withMigratingInventory(t *testing.T, ask func(ctx context.Context, host string) (runtimeInventory, error)) {
	t.Helper()
	old := migratingInventoryHook
	migratingInventoryHook = func(ctx context.Context, _ *Server, host string) (runtimeInventory, error) { return ask(ctx, host) }
	t.Cleanup(func() { migratingInventoryHook = old })
}

// unresolvedDetail is vm's vm.migration_unresolved detail, and whether it is open.
func unresolvedDetail(t *testing.T, s *Server, vm string) (string, bool) {
	t.Helper()
	row, ok, err := corrosion.GetHealthCondition(context.Background(), s.db, drainEvaluator, condMigrationUnresolved, "vm", vm)
	if err != nil {
		t.Fatal(err)
	}
	var ev migrationUnresolvedEvidence
	_ = json.Unmarshal([]byte(row.Evidence), &ev)
	return ev.Detail, ok && row.Lifecycle != corrosion.ConditionResolved
}

// A Secure Boot / vTPM VM recorded migrating on a failed source is never
// re-pointed by failover, whatever its target reports: its move is settled by
// its firmware records. The hold names the firmware move doctor, and the
// fence-confirm of the source while it is not proven off. Taking those steps
// — the source confirmed off, then `lv doctor firmware-move --adopt-target-copy`
// — leaves the VM running on the target alone, its row there.
//
// Mutation: re-point a firmware VM like any other (drop the firmware branch)
// — the "running" arm's row moves to dst-host, red.
func TestSettleFailedSourceMigrations_FirmwareVMIsHeldForTheDoctor(t *testing.T) {
	ctx := context.Background()
	t.Run("running_on_target/never_repointed", func(t *testing.T) {
		r, _ := lostWithOwed(t, false, false, libvirtfake.StateRunning)
		withMigratingInventory(t, func(ctx context.Context, host string) (runtimeInventory, error) {
			if host != "dst-host" {
				return runtimeInventory{}, fmt.Errorf("no such host %s", host)
			}
			return r.dst.collectRuntimeInventory(ctx), nil
		})
		row := r.row()
		if row.State != "migrating" || row.HostName != "src-host" {
			t.Fatalf("fixture: row %s on %s, want migrating on src-host", row.State, row.HostName)
		}
		d := r.src.SettleFailedSourceMigrations(ctx, "src-host", []corrosion.VMRecord{*row})[fwlVM]
		if d.Verdict != failover.MigratingHold {
			t.Fatalf("decision %+v, want a hold", d)
		}
		if after := r.row(); after.HostName != "src-host" || after.State != "migrating" {
			t.Fatalf("the firmware VM's row was moved to %s %s", after.HostName, after.State)
		}
		detail, open := unresolvedDetail(t, r.src, fwlVM)
		if !open || !strings.Contains(detail, "lv doctor firmware-move "+fwlVM+" --adopt-target-copy") ||
			!strings.Contains(detail, "lv host fence-confirm src-host") {
			t.Fatalf("condition open %v, detail %q; want it naming fence-confirm of src-host and the doctor", open, detail)
		}
	})
	t.Run("paused_on_target/the_hinted_steps_leave_one_copy", func(t *testing.T) {
		r, _ := lostWithOwed(t, false, false, "")
		withMigratingInventory(t, func(ctx context.Context, host string) (runtimeInventory, error) {
			return r.dst.collectRuntimeInventory(ctx), nil
		})
		if st, _ := r.dstFake.RawState(fwlVM); st != libvirtfake.StatePaused {
			t.Fatalf("fixture: target %s, want paused", st)
		}
		d := r.src.SettleFailedSourceMigrations(ctx, "src-host", []corrosion.VMRecord{*r.row()})[fwlVM]
		if d.Verdict != failover.MigratingHold || !strings.Contains(d.Detail, "lv host fence-confirm src-host") {
			t.Fatalf("decision %+v, want a hold naming the source's fence-confirm", d)
		}
		// `lv host fence-confirm src-host`, as it records it.
		if err := corrosion.RecordFenceWithState(ctx, r.src.db,
			corrosion.FenceLogRecord{ID: "fc-src", HostName: "src-host", Method: "manual", Result: "manual-confirmed"}, "fenced"); err != nil {
			t.Fatal(err)
		}
		d = r.src.SettleFailedSourceMigrations(ctx, "src-host", []corrosion.VMRecord{*r.row()})[fwlVM]
		if d.Verdict != failover.MigratingHold || strings.Contains(d.Detail, "fence-confirm") ||
			!strings.Contains(d.Detail, "--adopt-target-copy") {
			t.Fatalf("decision %+v, want a hold naming the doctor alone once the source is proven off", d)
		}
		if _, err := r.doctor(actAdopt); err != nil {
			t.Fatalf("lv doctor firmware-move %s --adopt-target-copy: %v", fwlVM, err)
		}
		row := r.row()
		if row.HostName != "dst-host" || row.State != "running" {
			t.Fatalf("row %s %s after the doctor, want running on dst-host", row.HostName, row.State)
		}
		var running []string
		for name, f := range map[string]*libvirtfake.Fake{"src-host": r.srcFake, "dst-host": r.dstFake} {
			if st, ok := f.RawState(fwlVM); ok && st == libvirtfake.StateRunning {
				running = append(running, name)
			}
		}
		if len(running) != 1 || running[0] != "dst-host" {
			t.Fatalf("the VM runs on %v, want dst-host alone", running)
		}
		if _, ok, _ := fwmig.New(r.dst.dataDir).GetHold(fwlVM); ok {
			t.Error("the target's hold is still there after the adoption")
		}
	})
}

// Failover asks each migration target once per pass, whatever the number of
// VMs held against it, at most migratingProbeConcurrency at a time, and gives
// up on what is left once migratingProbeBudget is spent: a target that does
// not answer holds its own VMs, and never the rest of the recovery for longer
// than the budget.
//
// Mutations: ask per VM (no per-target memo) — the call count per target is
// 3, red; drop the semaphore — the in-flight peak exceeds the bound, red;
// drop the pass's budget — the second arm runs past it, red.
func TestSettleFailedSourceMigrations_AsksEachTargetOnceWithinABudget(t *testing.T) {
	ctx := context.Background()
	setBounds := func(t *testing.T, timeout, budget time.Duration, conc int) {
		t.Helper()
		ot, ob, oc := migratingProbeTimeout, migratingProbeBudget, migratingProbeConcurrency
		migratingProbeTimeout, migratingProbeBudget, migratingProbeConcurrency = timeout, budget, conc
		t.Cleanup(func() { migratingProbeTimeout, migratingProbeBudget, migratingProbeConcurrency = ot, ob, oc })
	}
	vmsFor := func(targets ...string) []corrosion.VMRecord {
		var out []corrosion.VMRecord
		for _, tg := range targets {
			for i := 0; i < 3; i++ {
				out = append(out, corrosion.VMRecord{Name: fmt.Sprintf("%s-vm%d", tg, i), HostName: "src",
					State: "migrating", StateDetail: migratingDetailPrefix + tg})
			}
		}
		return out
	}
	// ask answers "fast-*" at once with a complete inventory holding none of
	// the VMs, and blocks any other target until its ask is cancelled.
	type probe struct {
		mu        sync.Mutex
		calls     map[string]int
		in, peak  atomic.Int32
		completed atomic.Int32
	}
	ask := func(p *probe) func(ctx context.Context, host string) (runtimeInventory, error) {
		return func(ctx context.Context, host string) (runtimeInventory, error) {
			p.mu.Lock()
			p.calls[host]++
			p.mu.Unlock()
			n := p.in.Add(1)
			defer p.in.Add(-1)
			for {
				pk := p.peak.Load()
				if n <= pk || p.peak.CompareAndSwap(pk, n) {
					break
				}
			}
			if strings.HasPrefix(host, "fast-") {
				p.completed.Add(1)
				return runtimeInventory{Host: host, Complete: true}, nil
			}
			<-ctx.Done()
			return runtimeInventory{}, ctx.Err()
		}
	}

	t.Run("every_target_asked_once", func(t *testing.T) {
		setBounds(t, 100*time.Millisecond, 5*time.Second, 2)
		p := &probe{calls: map[string]int{}}
		withMigratingInventory(t, ask(p))
		s := testServerWithLocks(t)
		vms := vmsFor("fast-a", "fast-b", "dead-a", "dead-b", "dead-c", "dead-d")
		start := time.Now()
		got := s.SettleFailedSourceMigrations(ctx, "src", vms)
		if el := time.Since(start); el > 2*time.Second {
			t.Errorf("the pass took %s; 4 dead targets at 2 at a time and 100ms each should take ~200ms", el)
		}
		for host, n := range p.calls {
			if n != 1 {
				t.Errorf("%s was asked %d times, want once for its 3 VMs", host, n)
			}
		}
		if len(p.calls) != 6 {
			t.Errorf("asked %v, want each of the 6 targets", p.calls)
		}
		if pk := p.peak.Load(); pk > 2 {
			t.Errorf("%d asks in flight at once, want at most 2", pk)
		}
		for _, vm := range vms {
			d := got[vm.Name]
			want := failover.MigratingHold
			if strings.HasPrefix(vm.Name, "fast-") {
				want = failover.MigratingRecover
			}
			if d.Verdict != want {
				t.Errorf("%s: %+v, want verdict %d", vm.Name, d, want)
			}
		}
	})
	t.Run("the_budget_bounds_the_pass", func(t *testing.T) {
		setBounds(t, 200*time.Millisecond, 250*time.Millisecond, 1)
		p := &probe{calls: map[string]int{}}
		withMigratingInventory(t, ask(p))
		s := testServerWithLocks(t)
		vms := vmsFor("dead-a", "dead-b", "dead-c", "dead-d", "dead-e", "dead-f")
		start := time.Now()
		got := s.SettleFailedSourceMigrations(ctx, "src", vms)
		if el := time.Since(start); el > time.Second {
			t.Fatalf("the pass took %s against a 250ms budget (6 dead targets at 200ms each, 1 at a time)", el)
		}
		unasked := 0
		for _, vm := range vms {
			d := got[vm.Name]
			if d.Verdict != failover.MigratingHold {
				t.Errorf("%s: %+v, want a hold", vm.Name, d)
			}
			if strings.Contains(d.Detail, "not asked within") {
				unasked++
			}
		}
		if unasked == 0 {
			t.Error("every target was asked; the budget did not cut the pass short")
		}
	})
}
