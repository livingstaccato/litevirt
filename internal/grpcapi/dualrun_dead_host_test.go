package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/hlc"
)

// Per-condition resolution coverage: one dead-but-registered host must not
// freeze every dual-run condition cluster-wide.
//
// The lab reproduction (2026-09-24): node-5 was registered but powered off for
// ten days. A runtime_owner_mismatch on a VM created long AFTER node-5 went
// dark was raised in a transient stale-replica window, the DB and runtime then
// converged — and the condition stayed critical forever, refusing admission to
// the involved host, because node-5 kept the scan's coverage partial. It
// cleared within one pass of `lv host rm node-5`.
//
// These tests use three hosts: h1 (self) and h2 reachable, h3 dead.

// seedHostHealth writes one host_health edge directly, with an explicit
// updated_at — the replicated evidence the resolution rule reads to decide
// when a host was last known alive.
func seedHostHealth(t *testing.T, s *Server, observer, target, status string, failures int, updatedAt string) {
	t.Helper()
	if err := s.db.Execute(context.Background(),
		`INSERT OR REPLACE INTO host_health (observer, target, status, consecutive_failures, last_seen, updated_at)
		 VALUES (?, ?, ?, ?, NULL, ?)`,
		observer, target, status, failures, updatedAt); err != nil {
		t.Fatalf("seed host_health %s->%s: %v", observer, target, err)
	}
}

func rfcAgo(d time.Duration) string { return time.Now().Add(-d).UTC().Format(time.RFC3339) }

// seedDeadH3 records h3 as last alive `ago`: its own observer rows stop at
// that instant, and the live observers now report it suspect.
func seedDeadH3(t *testing.T, s *Server, ago time.Duration) {
	t.Helper()
	seedHostHealth(t, s, "h3", "h1", "healthy", 0, rfcAgo(ago))
	seedHostHealth(t, s, "h3", "h2", "healthy", 0, rfcAgo(ago))
	seedHostHealth(t, s, "h1", "h3", "suspect", 500, rfcAgo(5*time.Second))
	seedHostHealth(t, s, "h2", "h3", "suspect", 500, rfcAgo(5*time.Second))
}

// confirmOwnerMismatchWithH3Dark raises and confirms runtime_owner_mismatch on
// vmA (DB owner h1, sole runtime holder h2) while h3 is unreachable, then
// switches the gather to the CONVERGED state: vmA on its owner only, h3 still
// unreachable.
func confirmOwnerMismatchWithH3Dark(t *testing.T, s *Server) {
	t.Helper()
	ctx := context.Background()
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {}, "h2": {diskHolderVMs: []string{"vmA"}},
	}, "h3")
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionConfirmed {
		t.Fatalf("setup: owner mismatch lifecycle = %q, want confirmed", got)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {},
	}, "h3")
}

func setVMCreated(t *testing.T, s *Server, name, createdAt string) {
	t.Helper()
	if err := s.db.Execute(context.Background(), `UPDATE vms SET created_at = ? WHERE name = ?`, createdAt, name); err != nil {
		t.Fatalf("set created_at: %v", err)
	}
}

// TestDualRunResolve_HostDeadBeforeWorkloadExisted_DoesNotBlock is the lab
// bug. h3 has been dark for ten days; vmA was created an hour ago. h3 cannot
// hold a copy of a VM that did not exist the last time it was alive, so its
// unreachability proves nothing either way about vmA — and must not hold vmA's
// condition open. The scan as a whole is still PARTIAL (h3's own coverage gap
// stands and the evaluator status says partial); only the per-condition
// resolution changes.
func TestDualRunResolve_HostDeadBeforeWorkloadExisted_DoesNotBlock(t *testing.T) {
	for _, tc := range []struct {
		name string
		// h3's last self-authored write, in whichever updated_at form is live.
		lastAlive string
	}{
		{"rfc3339 updated_at", rfcAgo(10 * 24 * time.Hour)},
		{"hlc updated_at", hlc.Timestamp{PhysicalMS: time.Now().Add(-10 * 24 * time.Hour).UnixMilli(), NodeID: "h3"}.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dualRunTestServer(t, 3)
			ctx := context.Background()
			seedVM(t, s, "vmA", "h1", "running")
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedHostHealth(t, s, "h3", "h1", "healthy", 0, tc.lastAlive)
			seedHostHealth(t, s, "h3", "h2", "healthy", 0, tc.lastAlive)
			seedHostHealth(t, s, "h1", "h3", "suspect", 500, rfcAgo(5*time.Second))

			confirmOwnerMismatchWithH3Dark(t, s)
			s.detectDualRunPass(ctx)
			s.detectDualRunPass(ctx)

			if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionResolved {
				t.Fatalf("owner mismatch lifecycle = %q after two clean passes, want resolved — "+
					"h3 has been dark since before vmA existed and cannot hold a copy of it", got)
			}
			// h3's own gap is untouched: it is still unreachable, still observed.
			if got := condLifecycle(s, kindDualRunCoverage, "h3"); got != corrosion.ConditionConfirmed {
				t.Errorf("coverage_gap(h3) = %q, want confirmed — the dead host's own gap must stand", got)
			}
			sts, err := corrosion.ListHealthEvaluatorStatus(ctx, s.db)
			if err != nil || len(sts) != 1 || sts[0].Coverage != corrosion.CoveragePartial {
				t.Errorf("evaluator status = %+v err=%v, want partial — the scan is still blind on h3", sts, err)
			}
		})
	}
}

// TestDualRunResolve_HostThatCouldHoldTheCopy_StillBlocks: the constraint the
// rule must keep. Each case is an unreachable h3 that COULD be running a copy
// of vmA, or whose evidence cannot be trusted to say otherwise — every one of
// them must hold the condition confirmed with its clean streak unadvanced.
func TestDualRunResolve_HostThatCouldHoldTheCopy_StillBlocks(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, s *Server)
	}{
		{"alive after the workload was created", func(t *testing.T, s *Server) {
			// vmA is ten days old; h3 went dark two days ago — it was alive
			// for eight days of vmA's life.
			setVMCreated(t, s, "vmA", rfcAgo(10*24*time.Hour))
			seedDeadH3(t, s, 2*24*time.Hour)
		}},
		{"a peer saw it healthy after the workload was created", func(t *testing.T, s *Server) {
			// h3's own rows are old, but h2 reached it after vmA existed.
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedHostHealth(t, s, "h3", "h1", "healthy", 0, rfcAgo(10*24*time.Hour))
			seedHostHealth(t, s, "h2", "h3", "healthy", 0, rfcAgo(time.Minute))
		}},
		{"a peer saw it answer unready after the workload was created", func(t *testing.T, s *Server) {
			// An unready answer is the host speaking: it is alive.
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedHostHealth(t, s, "h3", "h1", "healthy", 0, rfcAgo(10*24*time.Hour))
			seedHostHealth(t, s, "h2", "h3", "unready", 4, rfcAgo(time.Minute))
		}},
		{"last alive within clock-skew margin of creation", func(t *testing.T, s *Server) {
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedDeadH3(t, s, time.Hour+time.Minute)
		}},
		{"no liveness evidence for the host at all", func(t *testing.T, s *Server) {
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
		}},
		{"unparseable liveness evidence", func(t *testing.T, s *Server) {
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedDeadH3(t, s, 10*24*time.Hour)
			seedHostHealth(t, s, "h3", "h4", "healthy", 0, "not-a-timestamp")
		}},
		{"unparseable workload created_at", func(t *testing.T, s *Server) {
			setVMCreated(t, s, "vmA", "yesterday-ish")
			seedDeadH3(t, s, 10*24*time.Hour)
		}},
		{"workload created_at far in the future", func(t *testing.T, s *Server) {
			// A post-dated stamp would otherwise exempt every dead host.
			setVMCreated(t, s, "vmA", time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC).Format(time.RFC3339))
			seedDeadH3(t, s, 10*24*time.Hour)
		}},
		{"the dead host is the workload's DB owner", func(t *testing.T, s *Server) {
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedDeadH3(t, s, 10*24*time.Hour)
			if err := s.db.Execute(context.Background(), `UPDATE vms SET host_name = 'h3' WHERE name = 'vmA'`); err != nil {
				t.Fatalf("repoint owner: %v", err)
			}
		}},
		{"the workload is no longer in the DB", func(t *testing.T, s *Server) {
			// Nothing to date it by: the cluster-wide rule applies.
			seedDeadH3(t, s, 10*24*time.Hour)
			if err := s.db.Execute(context.Background(), `UPDATE vms SET deleted_at = ? WHERE name = 'vmA'`, rfcAgo(0)); err != nil {
				t.Fatalf("delete vmA: %v", err)
			}
		}},
		{"the host_health read fails", func(t *testing.T, s *Server) {
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedDeadH3(t, s, 10*24*time.Hour)
			if err := s.db.Execute(context.Background(), `ALTER TABLE host_health RENAME TO host_health_broken`); err != nil {
				t.Fatalf("hide host_health: %v", err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dualRunTestServer(t, 3)
			ctx := context.Background()
			seedVM(t, s, "vmA", "h1", "running")
			confirmOwnerMismatchWithH3Dark(t, s)
			tc.setup(t, s)
			for i := 0; i < 3; i++ {
				s.detectDualRunPass(ctx)
			}
			h := readCond(t, s, kindOwnerMismatch, "vmA")
			if h.Lifecycle != corrosion.ConditionConfirmed {
				t.Fatalf("lifecycle = %q, want confirmed retained — h3 could hold a copy of vmA "+
					"(or its evidence cannot prove otherwise), so its blindness must block resolution", h.Lifecycle)
			}
			if h.CleanCount != 0 {
				t.Errorf("clean streak advanced to %d, want 0", h.CleanCount)
			}
		})
	}
}

// TestDualRunResolve_ObservedHolderNeverExempt: a host the condition itself
// names as a holder demonstrably COULD hold the workload, whatever its
// liveness timestamps claim. Here the timestamps are made to lie (h2's rows
// say it died ten days ago, before vmA existed) and h2 then goes dark: the
// condition that saw vmA on h2 must not resolve on h2's absence.
func TestDualRunResolve_ObservedHolderNeverExempt(t *testing.T) {
	s := dualRunTestServer(t, 3)
	ctx := context.Background()
	seedVM(t, s, "vmA", "h1", "running")
	setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
	// Both h2 and h3 look dead since long before vmA: only their own old
	// rows, and h1 reporting them suspect.
	for _, h := range []string{"h2", "h3"} {
		seedHostHealth(t, s, h, "h1", "healthy", 0, rfcAgo(10*24*time.Hour))
		seedHostHealth(t, s, "h1", h, "suspect", 500, rfcAgo(5*time.Second))
	}

	// vmA on h1 AND h2 → vm_dual_run confirmed, involved hosts [h1 h2].
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {diskHolderVMs: []string{"vmA"}},
	}, "h3")
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunVM, "vmA") {
		t.Fatal("setup: vm_dual_run not confirmed")
	}
	// h2 goes dark too.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {diskHolderVMs: []string{"vmA"}},
	}, "h2", "h3")
	for i := 0; i < 3; i++ {
		s.detectDualRunPass(ctx)
	}
	if got := condLifecycle(s, kindDualRunVM, "vmA"); got != corrosion.ConditionConfirmed {
		t.Fatalf("vm_dual_run = %q, want confirmed — h2 was SEEN holding vmA; its absence proves nothing", got)
	}
}

// TestDualRunResolve_PartialOrUnsupportedHostNeverExempt: the exemption is for
// hosts that are unreachable. A host that ANSWERED — partially, or on an older
// binary — is alive right now and could be running anything, whatever its
// history says.
func TestDualRunResolve_PartialOrUnsupportedHostNeverExempt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		gather func(context.Context, []string) (map[string]runtimeSnapshot, []string, []string)
	}{
		{"partial", fixedGather(map[string]runtimeSnapshot{
			"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {}, "h3": {partial: true},
		})},
		{"unsupported", gatherWith(map[string]runtimeSnapshot{
			"h1": {diskHolderVMs: []string{"vmA"}}, "h2": {},
		}, nil, []string{"h3"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := dualRunTestServer(t, 3)
			ctx := context.Background()
			seedVM(t, s, "vmA", "h1", "running")
			setVMCreated(t, s, "vmA", rfcAgo(time.Hour))
			seedDeadH3(t, s, 10*24*time.Hour)
			confirmOwnerMismatchWithH3Dark(t, s)
			s.gatherRuntimeOverride = tc.gather
			for i := 0; i < 3; i++ {
				s.detectDualRunPass(ctx)
			}
			if got := condLifecycle(s, kindOwnerMismatch, "vmA"); got != corrosion.ConditionConfirmed {
				t.Fatalf("lifecycle = %q with h3 %s, want confirmed", got, tc.name)
			}
		})
	}
}

// TestDualRunResolve_HostScopedConditionsNeedOnlyTheirHost: coverage_gap and
// lww_unresolved are claims about ONE host's own runtime report, so a complete
// probe of that host is the whole proof of absence — another host being dead
// is irrelevant to them. Before this, a host that flapped once kept its
// warning (which also refuses admission to it) for as long as ANY other host
// stayed down.
func TestDualRunResolve_HostScopedConditionsNeedOnlyTheirHost(t *testing.T) {
	s := dualRunTestServer(t, 3)
	ctx := context.Background()
	// h3 has NO liveness evidence at all: nothing about it can be exempted,
	// so only the host-scoped rule can resolve anything here.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {}, "h2": {partial: true, unresolvedTies: 2},
	}, "h3")
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunCoverage, "h2") || !confirmedCond(s, kindLWWUnresolved, "h2") {
		t.Fatal("setup: coverage_gap(h2) and lww_unresolved(h2) not confirmed")
	}

	// h2 recovers fully; h3 stays dark.
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}, "h2": {}}, "h3")
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	for _, k := range []string{kindDualRunCoverage, kindLWWUnresolved} {
		if got := condLifecycle(s, k, "h2"); got != corrosion.ConditionResolved {
			t.Errorf("%s(h2) = %q, want resolved — h2 was completely probed twice", k, got)
		}
	}
	if got := condLifecycle(s, kindDualRunCoverage, "h3"); got != corrosion.ConditionConfirmed {
		t.Errorf("coverage_gap(h3) = %q, want confirmed", got)
	}

	// Control: a host-scoped condition whose host is itself PARTIAL does not resolve.
	s2 := dualRunTestServer(t, 3)
	s2.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {}, "h2": {unresolvedTies: 2}, "h3": {},
	})
	s2.detectDualRunPass(ctx)
	s2.detectDualRunPass(ctx)
	s2.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {}, "h2": {partial: true}, "h3": {},
	})
	for i := 0; i < 3; i++ {
		s2.detectDualRunPass(ctx)
	}
	if got := condLifecycle(s2, kindLWWUnresolved, "h2"); got != corrosion.ConditionConfirmed {
		t.Errorf("lww_unresolved(h2) = %q with h2 partial, want confirmed", got)
	}
}

// TestDualRunResolve_DBIndexFailureStillBlocksHostScoped: a pass whose DB
// index read failed resolves nothing, host-scoped conditions included — the
// per-condition rule narrows which HOSTS must be seen, never whether a blind
// pass counts.
func TestDualRunResolve_DBIndexFailureStillBlocksHostScoped(t *testing.T) {
	s := dualRunTestServer(t, 3)
	ctx := context.Background()
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {}, "h2": {partial: true},
	}, "h3")
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunCoverage, "h2") {
		t.Fatal("setup: coverage_gap(h2) not confirmed")
	}
	if err := s.db.Execute(ctx, `ALTER TABLE containers RENAME TO containers_broken`); err != nil {
		t.Fatalf("hide containers: %v", err)
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{"h1": {}, "h2": {}}, "h3")
	for i := 0; i < 3; i++ {
		s.detectDualRunPass(ctx)
	}
	if got := condLifecycle(s, kindDualRunCoverage, "h2"); got != corrosion.ConditionConfirmed {
		t.Fatalf("coverage_gap(h2) = %q with the container index unreadable, want confirmed", got)
	}
}

// TestDualRunResolve_VIPAndContainerStayClusterWide pins the deliberate fail-
// closed choice: a container name is not cluster-unique and a VIP has no
// incarnation stamp, so there is no instant before which a dead host provably
// could not hold one. Their conditions still need complete coverage.
func TestDualRunResolve_VIPAndContainerStayClusterWide(t *testing.T) {
	s := dualRunTestServer(t, 3)
	ctx := context.Background()
	seedDeadH3(t, s, 10*24*time.Hour)
	seedContainer(t, s, "web", "h1", "running")
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {runningCTs: []string{"web"}, kernelVIPs: []string{"10.0.0.9"}},
		"h2": {runningCTs: []string{"web"}, kernelVIPs: []string{"10.0.0.9"}},
	}, "h3")
	s.detectDualRunPass(ctx)
	s.detectDualRunPass(ctx)
	if !confirmedCond(s, kindDualRunCT, "web") || !confirmedCond(s, kindDualRunVIP, "10.0.0.9") {
		t.Fatal("setup: ct/vip dual-run not confirmed")
	}
	s.gatherRuntimeOverride = fixedGather(map[string]runtimeSnapshot{
		"h1": {runningCTs: []string{"web"}, kernelVIPs: []string{"10.0.0.9"}}, "h2": {},
	}, "h3")
	for i := 0; i < 3; i++ {
		s.detectDualRunPass(ctx)
	}
	if got := condLifecycle(s, kindDualRunCT, "web"); got != corrosion.ConditionConfirmed {
		t.Errorf("ct_dual_run = %q with h3 dark, want confirmed", got)
	}
	if got := condLifecycle(s, kindDualRunVIP, "10.0.0.9"); got != corrosion.ConditionConfirmed {
		t.Errorf("vip_dual_run = %q with h3 dark, want confirmed", got)
	}
}
