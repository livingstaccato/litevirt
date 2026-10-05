// A dual-run scan that lands on a migration's cutover must not block the
// VM's next migration.
//
// The detector probes each host at its own moment. A live migration pauses the
// source before it resumes the target, so no instant has two running copies —
// but a pass that probed the source just before the cutover and the target
// just after read both as active disk-holders, and wrote an OBSERVED
// vm_dual_run. Admission honours an observed row at once, so on the lab the
// next migration was refused ("active warning ownership condition
// (vm_dual_run ...)") for about two minutes, until two clean passes resolved it.
//
// A real dual run — the same VM running on two hosts outside any migration —
// is the split-brain signal and must still block on the first pass.

package fleet

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// emulateLibvirtMove makes MigrateToTarget on from do what libvirt does with
// MigratePersistDest|MigrateUndefineSource: the guest ends up running on to
// and its domain is gone from from. The fake otherwise moves nothing.
func emulateLibvirtMove(from, to *Node) {
	from.Virt.FailMigrateToTarget = func(name, _ string) error {
		to.Virt.SetState(name, libvirtfake.StateRunning)
		return from.Virt.UndefineDomain(name, false)
	}
}

// runOneDualRunPass runs the detector on n until it has finished one pass
// (the evaluator status row is its last write) and then stops it. The interval
// is long, so exactly one pass runs.
func runOneDualRunPass(t *testing.T, n *Node) {
	t.Helper()
	ctx := context.Background()
	if _, err := n.DB.DB().Exec(`DELETE FROM health_evaluator_status WHERE evaluator = 'dual_run'`); err != nil {
		t.Fatalf("clear evaluator status: %v", err)
	}
	dctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); n.Server.RunDualRunDetector(dctx, time.Hour) }()
	defer func() { stop(); <-done }()
	deadline := time.Now().Add(10 * time.Second)
	for {
		sts, err := corrosion.ListHealthEvaluatorStatus(ctx, n.DB)
		if err != nil {
			t.Fatalf("ListHealthEvaluatorStatus: %v", err)
		}
		for _, st := range sts {
			if st.Evaluator == "dual_run" {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the dual-run detector never finished a pass")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func vmDualRunLifecycle(t *testing.T, n *Node, vm string) string {
	t.Helper()
	h, ok, err := corrosion.GetHealthCondition(context.Background(), n.DB, "dual_run", "vm_dual_run", "vm", vm)
	if err != nil {
		t.Fatalf("GetHealthCondition: %v", err)
	}
	if !ok || h.Lifecycle == corrosion.ConditionResolved {
		return ""
	}
	return h.Lifecycle
}

func TestFleet_MigrateBackToBack_ScanAtCutoverDoesNotBlock(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	seedRunningVM(t, c, src, "mover", "", 1, 512)
	emulateLibvirtMove(src, dst)
	emulateLibvirtMove(dst, src)

	if err := migrateAt(t, c, src, "mover", dst.Name); err != nil {
		t.Fatalf("first migration %s -> %s: %v", src.Name, dst.Name, err)
	}

	// A pass that straddles that cutover: src's probe reads mover still
	// running, and the cutover lands right after — src's copy pauses, as
	// libvirt pauses a migration source before resuming the target. dst's
	// probe sees mover running there. Each host's answer was true when given.
	src.Virt.SetState("mover", libvirtfake.StateRunning)
	var straddled atomic.Bool
	src.Virt.FailDumpXML = func(name string) error {
		// DumpXML follows DomainState in the inventory probe, so the probe has
		// already counted mover as a disk-holder here.
		if name == "mover" && straddled.CompareAndSwap(false, true) {
			src.Virt.SetState("mover", libvirtfake.StatePaused)
		}
		return nil
	}
	runOneDualRunPass(t, src)
	src.Virt.FailDumpXML = nil
	if !straddled.Load() {
		t.Fatal("the detector never probed mover on the source; the scan did not straddle anything")
	}
	if err := src.Virt.UndefineDomain("mover", false); err != nil { // libvirt's MigrateUndefineSource
		t.Fatalf("undefine source copy: %v", err)
	}
	if got := vmDualRunLifecycle(t, src, "mover"); got != "" {
		t.Fatalf("a scan straddling the cutover recorded vm_dual_run %q for mover", got)
	}

	if err := migrateAt(t, c, dst, "mover", src.Name); err != nil {
		t.Fatalf("second, back-to-back migration %s -> %s refused after a scan at the cutover: %v",
			dst.Name, src.Name, err)
	}
	rec, err := corrosion.GetVM(context.Background(), src.DB, "mover")
	if err != nil || rec == nil || rec.HostName != src.Name {
		t.Fatalf("after the second migration: rec=%+v err=%v, want mover owned by %s", rec, err, src.Name)
	}

	// Control: a REAL dual run. mover is on src, and a copy runs on dst too,
	// with no migration anywhere. One pass records it and admission refuses
	// the next migration at once — the split-brain signal is not debounced.
	dst.Virt.SetState("mover", libvirtfake.StateRunning)
	runOneDualRunPass(t, src)
	if got := vmDualRunLifecycle(t, src, "mover"); got != corrosion.ConditionObserved {
		t.Fatalf("a real dual run after one pass: vm_dual_run %q, want observed", got)
	}
	err = migrateAt(t, c, src, "mover", dst.Name)
	if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "vm_dual_run") {
		t.Fatalf("migration during a real dual run: %v, want FailedPrecondition naming vm_dual_run", err)
	}
}
