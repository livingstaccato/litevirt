package fleet

// Live firmware moves (vTPM / Secure Boot) across daemon restarts, crashes and
// failures of the migration call: the fleet scenarios F-3, F-5, F-6, F-6b,
// F-6c, F-6d, F-7, F-7b, F-7c, F-7d and F-8 of trackD-phase2-spec.md §15.
//
// Every scenario runs a real move between two daemons over real gRPC, each
// node with its own firmware store and libvirt fake (spec §15, "Fake
// prerequisites"). A daemon restart keeps the node's libvirt fake: libvirt
// and its guests outlive the daemon (KillMode=process), so the new daemon
// finds the domains as the old one left them, its records on disk, and
// nothing of the old one's memory.
//
// A daemon that dies mid-move is modelled by stopping its move inside a
// libvirt call that never returns (fwliveRestartFreeze): the old process's
// goroutine is frozen there for good, as a killed process is, and writes
// nothing after; its gRPC server is then replaced. Where a crash point has no
// libvirt call to stop in, the scenario stops the move one call later and
// writes back the marker the source wrote at that point (fwliveRestartAt):
// the durable record a crash there leaves, with nothing else changed.
//
// The scene's one-copy watcher (fwliveOneCopy, fwlive_scene_test.go) checks
// the invariant every scenario keeps: at no moment do both hosts run the
// guest.

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// ── harness ──
//
// The scene, the one-copy watcher and the accessors are fwlive_scene_test.go's.

// fwliveRestartDown takes n's daemon down (downNode): its loops stop and its
// gRPC server goes away, every RPC it was serving cancelled. Its libvirt and
// its guests stay as they are.
func fwliveRestartDown(n *Node) { downNode(n) }

// fwliveRestartUp starts n's daemon again over the same database, data
// directory, firmware store and libvirt (upNode, keeping n.Virt): a new
// server on the same port, with nothing of the old one's memory. Its
// start-up recovery runs as the daemon's does (buildServer). Unlike
// restartNode it starts the replicator's push loop only on a cluster that
// runs one, and wires no LUN gate.
func fwliveRestartUp(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	upNode(t, c, n, true)
	if c.opts.IndependentReplicas {
		n.repl.Start(c.ctx)
		n.replStarted = true
	}
}

// fwliveRestartDaemon restarts n's daemon (down, then up).
func fwliveRestartDaemon(t *testing.T, c *Cluster, n *Node) {
	t.Helper()
	fwliveRestartDown(n)
	fwliveRestartUp(t, c, n)
}

// fwliveRestartRecovered waits for every firmware move recovery on n to end:
// the start-up one and one more pass.
func fwliveRestartRecovered(n *Node) {
	n.Server.FirmwareMoveRecoveryOnce(context.Background())
}

// fwliveRestartNever is never closed: a killed daemon's goroutine waits on it
// for good, as a killed process never resumes, so it writes nothing after its
// death. Its server is replaced (or, on a failed test, stopped outright by
// fwliveSetup's cleanup before the cluster stops), so nothing waits on it.
var fwliveRestartNever = make(chan struct{})

// fwliveRestartFreeze makes src's next migration of fwlive1 stop inside
// libvirt for good, as the source daemon dying there leaves it: crash runs
// first (what libvirt had done by then; it may land the guest on dst), the
// returned channel is closed, and the call never returns. The frozen
// goroutine belongs to the old daemon, which the scenario then replaces.
func fwliveRestartFreeze(t *testing.T, src, dst *Node, crash func(name string, p lv.MigrateParams)) <-chan struct{} {
	reached := make(chan struct{})
	src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		if crash != nil {
			crash(name, p)
		}
		close(reached)
		<-fwliveRestartNever // the daemon died here: nothing after this runs
		return errors.New("the daemon died in this call")
	}
	return reached
}

// fwliveRestartLand lands the migration on dst and leaves the source shut off
// with reason, as libvirt does when the migration itself completed.
func fwliveRestartLand(t *testing.T, src, dst *Node, reason string) func(string, lv.MigrateParams) {
	return func(name string, p lv.MigrateParams) {
		if err := dst.Virt.LandFirmwareLive(src.Virt, name, p); err != nil {
			t.Errorf("land the migration on %s: %v", dst.Name, err)
			return
		}
		src.Virt.ShutOffDomain(name, reason)
	}
}

// fwliveRestartReach waits for a frozen point.
func fwliveRestartReach(t *testing.T, reached <-chan struct{}, done <-chan error, what string) {
	t.Helper()
	select {
	case <-reached:
	case err := <-done:
		t.Fatalf("the move ended (%v) before %s", err, what)
	case <-time.After(time.Minute):
		t.Fatalf("the move did not reach %s within a minute", what)
	}
}

// fwliveRestartAt writes back the marker as the source wrote it at phase:
// m with that phase, and nothing of a park. The record a crash right after
// that write leaves.
func fwliveRestartAt(t *testing.T, n *Node, m fwmig.Marker, phase fwmig.Phase) fwmig.Marker {
	t.Helper()
	m.Phase, m.ParkedFrom, m.Detail = phase, "", ""
	if err := fwmig.New(n.FW.DataDir).PutMarker(m); err != nil {
		t.Fatalf("write the %s marker on %s: %v", phase, n.Name, err)
	}
	return m
}

// fwliveRestartResolve resolves fwlive1's open condition code, as the move
// resolves a condition its park raised: staging that takes a park back
// (fwliveRestartAt) takes its condition back too.
func fwliveRestartResolve(t *testing.T, n *Node, code string) {
	t.Helper()
	ctx := context.Background()
	row, found, err := corrosion.GetHealthCondition(ctx, n.DB, "firmware_migration", code, "vm", fwwVM)
	if err != nil || !found || row.Lifecycle == corrosion.ConditionResolved {
		t.Fatalf("condition %s to resolve: %+v (found %v, %v)", code, row, found, err)
	}
	now := time.Now().UTC().Format(time.RFC3339)
	row.Lifecycle, row.ResolvedAt, row.LastSeen, row.ObserveCount, row.CleanCount = corrosion.ConditionResolved, now, now, 0, row.CleanCount+1
	if err := corrosion.UpsertHealthCondition(ctx, n.DB, row); err != nil {
		t.Fatal(err)
	}
}

// fwliveRestartStoppedHere is the answer of a hook whose daemon was restarted
// under the call: the caller sees its connection go.
var fwliveRestartStoppedHere = status.Error(codes.Unavailable, "the daemon was restarted under this call")

// ── F-5: source daemon restart at each phase ──

// fwliveRestartCrashMigrating runs the move until the source daemon dies
// inside its migration call (marker migrating, row migrating), crash having
// run first, and takes the source daemon down. It returns the marker the
// dead daemon left.
func fwliveRestartCrashMigrating(t *testing.T, c *Cluster, src, dst *Node, crash func(string, lv.MigrateParams)) fwmig.Marker {
	t.Helper()
	return fwliveRestartCrashMigratingReq(t, c, src, dst, crash, &pb.MigrateVMRequest{
		VmName: fwwVM, TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
	})
}

func fwliveRestartCrashMigratingReq(t *testing.T, c *Cluster, src, dst *Node, crash func(string, lv.MigrateParams), req *pb.MigrateVMRequest) fwmig.Marker {
	t.Helper()
	reached := fwliveRestartFreeze(t, src, dst, crash)
	done := fwliveMigrateReq(t, c, src, req)
	fwliveRestartReach(t, reached, done, "the migration call")
	src.LandMigrationsOn(dst)
	fwliveRestartDown(src)
	m, ok := fwliveMarker(t, src)
	if !ok || m.Phase != fwmig.PhaseMigrating {
		t.Fatalf("the source died in the migration call with marker %+v (present %v), want migrating", m, ok)
	}
	if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "migrating" {
		t.Fatalf("row %s on %s when the source died, want migrating on %s", row.State, row.HostName, src.Name)
	}
	if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldPrepared {
		t.Fatalf("%s's hold %+v (present %v) when the source died, want prepared", dst.Name, h, ok)
	}
	return m
}

// fwliveRestartUndone asserts a move undone before cutover with the guest
// running on src: the target's hold and the NVRAM Prepare materialised are
// deleted (rule D, the source's domain active), nothing quarantined, the
// marker gone, the row running on src, the source state kept.
func fwliveRestartUndone(t *testing.T, src, dst *Node) {
	t.Helper()
	if st := fwliveState(src); st != string(libvirtfake.StateRunning) {
		t.Errorf("%s's guest is %s, want running", src.Name, st)
	}
	if st := fwliveState(dst); st != "undefined" {
		t.Errorf("%s has a domain (%s), want none", dst.Name, st)
	}
	if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "running" {
		t.Errorf("row %s on %s, want running on %s", row.State, row.HostName, src.Name)
	}
	if m, ok := fwliveMarker(t, src); ok {
		t.Errorf("marker left in %s (%s)", m.Phase, m.Detail)
	}
	if h, ok := fwliveHold(t, dst); ok {
		t.Errorf("%s's hold left in %s", dst.Name, h.State)
	}
	if _, ok := fwliveFile(dst.FW.NvramPath(fwwVM)); ok {
		t.Errorf("%s keeps the NVRAM Prepare materialised", dst.Name)
	}
	if q := fwliveQuarantines(dst); len(q) != 0 {
		t.Errorf("%s quarantined %v; a prepared hold with the source's domain active is deleted (rule D)", dst.Name, q)
	}
	fwliveSourceKept(t, src)
}

// F-5. The source daemon restarts with a live firmware move at each phase of
// its marker, and the start-up recovery takes the move on by spec §8.1's row
// for that phase and what the source observes: undone before the migration
// (preparing, prepared), M1 / M1p / waiting for libvirt's job / cutover
// (migrating), Verify after a re-hash (cutover), the commit (verified),
// Release (committed), the target checked first (released), and the cleanup
// resumed (cleaning). The guest runs on one host at every moment.
//
// Mutations (each red, then restored; trackD2-15-r1-report.md has the table):
//   - prepared: Abort sends source_domain_active=false — the target
//     quarantines instead of deleting (rule Q), red.
//   - migrating/paused: M1p does not resume the source — red.
//   - migrating/job: a job still running is taken as M1 — red.
//   - migrating/migrated: Abort on an inactive source ("Abort on inactive") —
//     the target's copy is discarded, red.
//   - migrating/unknown mismatch: V1 on any stop reason — red.
//   - cutover/changed: the cutover row skips its re-hash — red.
//   - released/fenced: the released row skips the proved-off check — red.
//   - verified: the row naming the source does not commit — red.
//   - committed: the committed row takes no step — red.
//   - cleaning: the source cleanup does not resume a cleaning marker — red.
//     (The start-up recovery and the cleanup retry both resume it,
//     whichever takes the VM first, so taking it from one of them alone is
//     not a reliable mutation.)
func TestFleet_FwLiveRestart_F5_SourceRestartAtEachPhase(t *testing.T) {
	ctx := context.Background()

	for _, phase := range []fwmig.Phase{fwmig.PhasePreparing, fwmig.PhasePrepared} {
		t.Run(string(phase), func(t *testing.T) {
			c, src, dst, _ := fwliveCluster(t)
			m := fwliveRestartCrashMigrating(t, c, src, dst, nil)
			// The marker as written at that phase, before the migration
			// call: the row is not yet migrating.
			if phase == fwmig.PhasePreparing {
				m.CreatedStubs = nil
			}
			fwliveRestartAt(t, src, m, phase)
			if err := corrosion.UpdateVMState(ctx, src.DB, fwwVM, "running", ""); err != nil {
				t.Fatal(err)
			}
			if _, ok := fwliveFile(dst.FW.NvramPath(fwwVM)); !ok {
				t.Fatalf("%s holds no materialised NVRAM before the restart", dst.Name)
			}
			fwliveRestartUp(t, c, src)
			fwliveRestartRecovered(src)
			fwliveRestartUndone(t, src, dst)
		})
	}

	t.Run("migrating/running_no_job", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		fwliveRestartCrashMigrating(t, c, src, dst, nil)
		fwliveRestartUp(t, c, src)
		fwliveRestartRecovered(src)
		// M1: Abort PRE_CUTOVER, the row restored from the running domain.
		fwliveRestartUndone(t, src, dst)
	})

	t.Run("migrating/paused_no_job", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		fwliveRestartCrashMigrating(t, c, src, dst, func(name string, _ lv.MigrateParams) {
			src.Virt.SetState(name, libvirtfake.StatePaused)
		})
		fwliveRestartUp(t, c, src)
		fwliveRestartRecovered(src)
		// M1p: the target holds no domain, so the paused source is resumed
		// first, then the row restored and the marker removed.
		if !fwliveDid(src, "resume") {
			t.Errorf("%s's paused guest was not resumed (ops %v)", src.Name, fwliveOps(src))
		}
		fwliveRestartUndone(t, src, dst)
	})

	t.Run("migrating/job_running", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		var job atomic.Bool
		var polls atomic.Int32
		job.Store(true)
		src.Virt.JobActive = func(string) (bool, error) {
			polls.Add(1)
			return job.Load(), nil
		}
		// libvirt has the guest on both hosts and is still migrating it.
		fwliveRestartCrashMigrating(t, c, src, dst, func(name string, p lv.MigrateParams) {
			if err := dst.Virt.LandFirmwareLive(src.Virt, name, p); err != nil {
				t.Errorf("land: %v", err)
			}
		})
		polls.Store(0)
		fwliveRestartUp(t, c, src)
		// While the job runs, the recovery waits: it looks at the job when
		// it takes the move and again while waiting for it, and nothing is
		// aborted, verified or resumed.
		eventually(t, time.Minute, "the recovery to look at the running job twice", func() bool { return polls.Load() >= 2 })
		if m, _ := fwliveMarker(t, src); m.Phase != fwmig.PhaseMigrating {
			t.Errorf("marker %s (%s) while libvirt still migrates, want migrating", m.Phase, m.Detail)
		}
		if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldPrepared {
			t.Errorf("%s's hold %+v (present %v) while libvirt still migrates, want prepared", dst.Name, h.State, ok)
		}
		if st := fwliveState(dst); st != string(libvirtfake.StatePaused) {
			t.Errorf("%s's guest is %s while libvirt still migrates, want paused", dst.Name, st)
		}
		// The job ends with the migration complete.
		src.Virt.ShutOffDomain(fwwVM, "migrated")
		job.Store(false)
		fwliveRestartRecovered(src)
		fwliveMoved(t, src, dst)
	})

	for _, reason := range []string{"migrated", "unknown"} {
		t.Run("migrating/inactive_"+reason, func(t *testing.T) {
			c, src, dst, _ := fwliveCluster(t)
			fwliveRestartCrashMigrating(t, c, src, dst, fwliveRestartLand(t, src, dst, reason))
			fwliveRestartUp(t, c, src)
			fwliveRestartRecovered(src)
			// Cutover with the stop reason read now, Verify MATCH, then
			// the commit, Release and the cleanup.
			fwliveMoved(t, src, dst)
		})
	}

	t.Run("migrating/inactive_unknown_mismatch", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		dst.Virt.CorruptLandedPermall = func(string) bool { return true }
		fwliveRestartCrashMigrating(t, c, src, dst, fwliveRestartLand(t, src, dst, "unknown"))
		fwliveRestartUp(t, c, src)
		fwliveRestartRecovered(src)
		// V1b: the source did not stop as a completed migration stops it,
		// so neither copy is declared current. Both are kept, the target
		// paused.
		m, ok := fwliveMarker(t, src)
		if !ok || m.Phase != fwmig.PhaseSourceStateSuspect {
			t.Fatalf("marker %+v (present %v), want source_state_suspect", m, ok)
		}
		if st := fwliveState(dst); st != string(libvirtfake.StatePaused) {
			t.Errorf("%s's guest is %s, want paused", dst.Name, st)
		}
		if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldMismatch {
			t.Errorf("%s's hold %+v (present %v), want mismatch", dst.Name, h.State, ok)
		}
		if _, ok := fwliveFile(fwlivePermall(dst)); !ok {
			t.Errorf("%s's copy of the TPM state is gone", dst.Name)
		}
		if q := fwliveQuarantines(dst); len(q) != 0 {
			t.Errorf("%s quarantined %v; V1b discards nothing", dst.Name, q)
		}
		if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "migrating" {
			t.Errorf("row %s on %s, want migrating on %s", row.State, row.HostName, src.Name)
		}
		fwliveSourceKept(t, src)
		if !fwliveCondition(t, src, "firmware_migration_source_state_suspect") {
			t.Error("no firmware_migration_source_state_suspect")
		}
	})

	// cutover: the marker as liveFirmwareCutover writes it, with the final
	// hashes and the stop reason, before Verify.
	cutover := func(t *testing.T, change bool) {
		c, src, dst, _ := fwliveCluster(t)
		m := fwliveRestartCrashMigrating(t, c, src, dst, fwliveRestartLand(t, src, dst, "migrated"))
		var err error
		if m.SrcPermallSHA256, err = src.FW.PermallSHA256(fwwUUID); err != nil {
			t.Fatal(err)
		}
		if m.SrcNvramSHA256, err = src.FW.NvramSHA256(fwwVM); err != nil {
			t.Fatal(err)
		}
		m.SrcStopReason = fwmig.StopReasonMigrated
		fwliveRestartAt(t, src, m, fwmig.PhaseCutover)
		if change {
			// The source's NVRAM is not what the cutover recorded.
			hlWrite(t, src.FW.NvramPath(fwwVM), []byte("written after the cutover"))
		}
		fwliveRestartUp(t, c, src)
		fwliveRestartRecovered(src)
		if !change {
			fwliveMoved(t, src, dst)
			return
		}
		// I6: the source copy may not be the final one, so nothing is
		// verified, committed or released.
		if m, ok := fwliveMarker(t, src); !ok || m.Phase != fwmig.PhaseSourceStateSuspect {
			t.Fatalf("marker %+v (present %v), want source_state_suspect", m, ok)
		}
		if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldPrepared {
			t.Errorf("%s's hold %+v (present %v), want prepared: Verify must not be asked", dst.Name, h.State, ok)
		}
		if st := fwliveState(dst); st != string(libvirtfake.StatePaused) {
			t.Errorf("%s's guest is %s, want paused", dst.Name, st)
		}
		if row := fwliveRow(t, src); row.HostName != src.Name {
			t.Errorf("row on %s, want %s (not committed)", row.HostName, src.Name)
		}
	}
	t.Run("cutover", func(t *testing.T) { cutover(t, false) })
	t.Run("cutover/source_changed", func(t *testing.T) { cutover(t, true) })

	t.Run("verified", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		src.LandMigrationsOn(dst)
		// C1: the commit does not land; the marker stays verified and the
		// target keeps its verified guest paused.
		if err := localExec(ctx, src.DB, `CREATE TRIGGER fwlive_restart_no_commit BEFORE UPDATE OF host_name ON vms
			WHEN NEW.host_name <> OLD.host_name BEGIN SELECT RAISE(ABORT, 'induced commit failure'); END`); err != nil {
			t.Fatal(err)
		}
		err := fwliveWait(t, fwliveMigrate(t, c, src, dst))
		if err == nil {
			t.Fatal("the move succeeded with its commit failing")
		}
		if err := localExec(ctx, src.DB, `DROP TRIGGER fwlive_restart_no_commit`); err != nil {
			t.Fatal(err)
		}
		if m, ok := fwliveMarker(t, src); !ok || m.Phase != fwmig.PhaseVerified {
			t.Fatalf("marker %+v (present %v) after the failed commit (%v), want verified", m, ok, err)
		}
		if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldVerified {
			t.Fatalf("%s's hold %+v (present %v), want verified", dst.Name, h.State, ok)
		}
		if row := fwliveRow(t, src); row.HostName != src.Name {
			t.Fatalf("row on %s after the failed commit", row.HostName)
		}
		fwliveRestartDaemon(t, c, src)
		fwliveRestartRecovered(src)
		fwliveMoved(t, src, dst)
	})

	t.Run("committed", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		src.LandMigrationsOn(dst)
		// Stop the move after its commit: a Release the target does not
		// have parks it, and the marker is then written back as it was.
		restore := dst.RefuseRPCs("ReleaseLiveFirmwareTarget")
		err := fwliveWait(t, fwliveMigrate(t, c, src, dst))
		restore()
		m, ok := fwliveMarker(t, src)
		if !ok || m.ParkedFrom != fwmig.PhaseCommitted {
			t.Fatalf("marker %+v (present %v) after Release was refused (%v), want parked from committed", m, ok, err)
		}
		fwliveRestartAt(t, src, m, fwmig.PhaseCommitted)
		// A crash at committed leaves no condition: the park's goes with
		// the park.
		fwliveRestartResolve(t, src, "firmware_migration_target_unreachable")
		if row := fwliveRow(t, src); row.HostName != dst.Name {
			t.Fatalf("row on %s, want %s (committed)", row.HostName, dst.Name)
		}
		if st := fwliveState(dst); st != string(libvirtfake.StatePaused) {
			t.Fatalf("%s's guest is %s before Release, want paused", dst.Name, st)
		}
		fwliveRestartDaemon(t, c, src)
		fwliveRestartRecovered(src)
		fwliveMoved(t, src, dst)
	})

	// cleanupCrash runs the move until the source daemon dies in its
	// cleanup, about to undefine the leftover (§6.7 step 3): marker
	// cleaning, the retained bundle written, the leftover still defined.
	cleanupCrash := func(t *testing.T, c *Cluster, src, dst *Node, beforeDeath func()) fwmig.Marker {
		t.Helper()
		src.LandMigrationsOn(dst)
		reached := make(chan struct{})
		var once atomic.Bool
		src.Virt.FailUndefinePreserv = func(name string) error {
			if name == fwwVM && once.CompareAndSwap(false, true) {
				close(reached)
				<-fwliveRestartNever // the daemon died here
				return errors.New("the daemon died in this call")
			}
			return nil
		}
		done := fwliveMigrate(t, c, src, dst)
		fwliveRestartReach(t, reached, done, "the source cleanup's undefine")
		if beforeDeath != nil {
			beforeDeath()
		}
		fwliveRestartDown(src)
		m, ok := fwliveMarker(t, src)
		if !ok || m.Phase != fwmig.PhaseCleaning {
			t.Fatalf("marker %+v (present %v), want cleaning", m, ok)
		}
		if st := fwliveState(src); st != string(libvirtfake.StateShutdown) {
			t.Fatalf("%s's leftover is %s, want defined and shut off", src.Name, st)
		}
		return m
	}
	bundle := func(src *Node, m fwmig.Marker) string {
		return filepath.Join(src.FW.DataDir, fwmig.RetainedDir, fwwVM+"-"+m.Attempt+".tar")
	}

	t.Run("released", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		m := cleanupCrash(t, c, src, dst, nil)
		// Released: the cleanup had not begun.
		fwliveRestartAt(t, src, m, fwmig.PhaseReleased)
		if err := os.Remove(bundle(src, m)); err != nil {
			t.Fatal(err)
		}
		fwliveRestartUp(t, c, src)
		fwliveRestartRecovered(src)
		fwliveMoved(t, src, dst)
	})

	t.Run("released/target_fenced", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		// An operator confirms the target off while the source is down.
		m := cleanupCrash(t, c, src, dst, func() { mustFenceConfirm(t, src, dst.Name) })
		fwliveRestartAt(t, src, m, fwmig.PhaseReleased)
		if err := os.Remove(bundle(src, m)); err != nil {
			t.Fatal(err)
		}
		fwliveRestartUp(t, c, src)
		fwliveRestartRecovered(src)
		// The target is proved off: the source state is kept for an
		// operator, not cleaned up.
		if m, ok := fwliveMarker(t, src); !ok || m.Phase != fwmig.PhaseTargetUnreachable {
			t.Fatalf("marker %+v (present %v), want target_unreachable", m, ok)
		}
		fwliveSourceKept(t, src)
		if st := fwliveState(src); st != string(libvirtfake.StateShutdown) {
			t.Errorf("%s's leftover is %s, want kept, shut off", src.Name, st)
		}
	})

	t.Run("cleaning", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		cleanupCrash(t, c, src, dst, nil)
		fwliveRestartUp(t, c, src)
		fwliveRestartRecovered(src)
		fwliveMoved(t, src, dst)
	})
}

// ── F-6, F-6b, F-6c, F-6d: target daemon restarts around Release ──

// fwliveRestartFinalNvram lands src's migrations on dst with the guest
// having written its UEFI variables during the migration: its final NVRAM,
// returned, is not the one Prepare materialised on the target (T0), so the
// target's NVRAM tells T0 from a run.
func fwliveRestartFinalNvram(src, dst *Node) []byte {
	final := []byte("fwlive1's UEFI vars, as the guest left them on the source")
	src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		if err := os.WriteFile(src.FW.NvramPath(name), final, 0o600); err != nil {
			return err
		}
		return dst.Virt.LandFirmwareLive(src.Virt, name, p)
	}
	return final
}

// fwliveRestartHoldRelease stops the source's next Release call at dst before
// its handler runs: at is closed when it arrives, and the call then waits for
// go on. The daemon it reached is then restarted under it (the caller's
// part): it answers as a dead daemon's call does, and the source retries
// Release against the new one.
func fwliveRestartHoldRelease(t *testing.T, dst *Node) (at <-chan struct{}, goOn func()) {
	a, g := make(chan struct{}), make(chan struct{})
	var once sync.Once
	goOn = func() { once.Do(func() { close(g) }) }
	t.Cleanup(goOn)
	dst.HookUnary("ReleaseLiveFirmwareTarget", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		close(a)
		<-g
		return nil, fwliveRestartStoppedHere
	})
	return a, goOn
}

// fwliveRestartArrive waits for a hooked call.
func fwliveRestartArrive(t *testing.T, at <-chan struct{}, done <-chan error, what string) {
	t.Helper()
	fwliveRestartReach(t, at, done, what)
}

// F-6. The target daemon restarts between Verify and Release: the commit has
// landed, the guest is held paused under a verified hold. The restarted
// daemon keeps it paused — the hold on disk refuses every resume and stop
// other than the move's own Release, whatever asks — and the source's retried
// Release resumes it there.
//
// Mutation: the source does not retry an unanswered Release (each call one
// attempt in the watched path) — the move parks target_unreachable, red.
func TestFleet_FwLiveRestart_F6_TargetRestartBetweenVerifyAndRelease(t *testing.T) {
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	src.LandMigrationsOn(dst)
	at, goOn := fwliveRestartHoldRelease(t, dst)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartArrive(t, at, done, "Release")

	check := func(when string) {
		t.Helper()
		if st := fwliveState(dst); st != string(libvirtfake.StatePaused) {
			t.Errorf("%s: %s's guest is %s, want held paused", when, dst.Name, st)
		}
		if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldVerified {
			t.Errorf("%s: %s's hold %+v (present %v), want verified", when, dst.Name, h.State, ok)
		}
		if m, ok := fwliveMarker(t, src); !ok || m.Phase != fwmig.PhaseCommitted {
			t.Errorf("%s: marker %+v (present %v), want committed", when, m.Phase, ok)
		}
		if row := fwliveRow(t, src); row.HostName != dst.Name {
			t.Errorf("%s: row on %s, want %s (committed)", when, row.HostName, dst.Name)
		}
	}
	check("before the restart")
	fwliveRestartDaemon(t, c, dst)
	check("after the restart")

	// What could run or stop the held guest on the restarted daemon: a
	// late NIC hand-over resume, the held-guest sweep, an operator's start
	// and stop. All refused; the guest stays paused.
	refused := func(what string, err error) {
		t.Helper()
		if status.Code(err) != codes.FailedPrecondition || !strings.Contains(err.Error(), "firmware") {
			t.Errorf("%s of the held guest = %v, want refused for its live firmware move", what, err)
		}
	}
	_, err := c.PeerClient(src, dst).ArmNICFirewall(ctx, &pb.ArmNICFirewallRequest{VmName: fwwVM, Resume: true})
	refused("ArmNICFirewall{resume}", err)
	dst.Server.ResumeHeldGuestsOnce(ctx)
	_, err = c.SelfClient(dst).StartVM(ctx, &pb.StartVMRequest{Name: fwwVM})
	refused("lv start", err)
	_, err = c.SelfClient(dst).StopVM(ctx, &pb.StopVMRequest{Name: fwwVM, Force: true})
	refused("lv stop", err)
	dst.Server.FirmwareHoldSweepOnce(ctx, time.Now().Add(3*time.Hour))
	check("after the restarted daemon's sweeps and the refused calls")
	for _, op := range []string{"resume", "start", "destroy", "shutdown", "undefine"} {
		if fwliveDid(dst, op) {
			t.Errorf("%s's libvirt did %s on the held guest (ops %v)", dst.Name, op, fwliveOps(dst))
		}
	}

	goOn()
	if err := fwliveWait(t, done); err != nil {
		t.Fatalf("the move after the target's restart: %v", err)
	}
	// The late sweep above raised firmware_migration_held for the guest it
	// found held 3 h; the sweep's next pass, with the hold gone, resolves
	// it.
	dst.Server.FirmwareHoldSweepOnce(ctx, time.Now())
	fwliveMoved(t, src, dst)
}

// F-6b. The target host goes down after Verify: the held guest's QEMU dies
// with it (the domain shut off, the migrated NVRAM never written), and its
// daemon restarts. Release then takes row H1: every check passes, so the
// source's final NVRAM is pushed, the VM is left stopped on the target with
// its verified TPM state, and nothing boots it (DECISION D-10). The source
// cleans up.
//
// Mutation: H1 skips the NVRAM push ("resume without the push") — the
// target's NVRAM stays the template, red.
func TestFleet_FwLiveRestart_F6b_HeldTargetShutOffAfterVerify(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	// The guest writes its UEFI variables during the migration: its final
	// NVRAM is not the one Prepare materialised on the target (T0), so H1
	// has something to push.
	final := fwliveRestartFinalNvram(src, dst)
	dst.HookUnary("VerifyLiveFirmwareTarget", func(ctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		resp, err := h(ctx, req)
		if r, _ := resp.(*pb.VerifyLiveFirmwareTargetResponse); err != nil || r.GetVerdict() != pb.FirmwareVerdict_FIRMWARE_VERDICT_MATCH {
			t.Errorf("Verify answered %v (%v), want MATCH", r.GetVerdict(), err)
		}
		// The target host crashes once Verify has answered.
		dst.Virt.ShutOffDomain(fwwVM, "crashed")
		return resp, err
	})
	at, goOn := fwliveRestartHoldRelease(t, dst)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartArrive(t, at, done, "Release")
	if b, _ := fwliveFile(dst.FW.NvramPath(fwwVM)); !bytes.Equal(b, fwwNvram) {
		t.Errorf("fixture: %s's NVRAM at Release is %q, want T0 (what Prepare materialised)", dst.Name, b)
	}
	fwliveRestartDaemon(t, c, dst)
	goOn()
	if err := fwliveWait(t, done); err != nil {
		t.Logf("the move returned %v", err)
	}

	if st := fwliveState(dst); st != string(libvirtfake.StateShutdown) {
		t.Errorf("%s's domain is %s, want defined and shut off: H1 never boots it", dst.Name, st)
	}
	for _, op := range []string{"start", "resume"} {
		if fwliveDid(dst, op) {
			t.Errorf("%s's libvirt did %s (ops %v)", dst.Name, op, fwliveOps(dst))
		}
	}
	row := fwliveRow(t, src)
	if row.HostName != dst.Name || row.State != "stopped" || !strings.Contains(row.StateDetail, "before release; firmware verified") {
		t.Errorf("row %s on %s (%q), want stopped on %s by H1", row.State, row.HostName, row.StateDetail, dst.Name)
	}
	if b, _ := fwliveFile(dst.FW.NvramPath(fwwVM)); !bytes.Equal(b, final) {
		t.Errorf("%s's NVRAM %q, want the source's final, pushed", dst.Name, b)
	}
	if b, _ := fwliveFile(fwlivePermall(dst)); !bytes.Equal(b, fwwPermall) {
		t.Errorf("%s's permall %q, want the verified copy, unchanged", dst.Name, b)
	}
	if h, ok := fwliveHold(t, dst); ok {
		t.Errorf("%s's hold left in %s", dst.Name, h.State)
	}
	if m, ok := fwliveMarker(t, src); ok {
		t.Errorf("marker left in %s (%s)", m.Phase, m.Detail)
	}
	if st := fwliveState(src); st != "undefined" {
		t.Errorf("%s's leftover is %s, want undefined by the cleanup", src.Name, st)
	}
	if _, ok := fwliveFile(src.FW.NvramPath(fwwVM)); ok {
		t.Errorf("%s's NVRAM not wiped by the cleanup", src.Name)
	}
}

// fwliveRestartKillAfterResume freezes dst's daemon the moment its Release
// has resumed the held guest, before the hold is updated (§6.6 step 5 then
// 6), as a daemon killed there leaves it. killed is closed then; the
// caller restarts the daemon. crash runs first, in the old daemon's last
// moment (a host crash).
func fwliveRestartKillAfterResume(t *testing.T, w *fwliveOneCopy, dst *Node, crash func()) <-chan struct{} {
	killed := make(chan struct{})
	var once atomic.Bool
	w.onRunning(dst, func(name string) {
		if name != fwwVM || !once.CompareAndSwap(false, true) {
			return
		}
		if crash != nil {
			crash()
		}
		close(killed)
		<-fwliveRestartNever // the daemon died here
	})
	return killed
}

// F-6c. The target daemon is killed right after Release resumed the held
// guest and before the hold was updated: the hold says resuming, the guest
// runs. The source's retried Release finds that on the restarted daemon and
// completes the hand-over (§6.6 step 2): no target_ran, the hold removed once
// the NVRAM is confirmed, the source cleaned up.
//
// Mutation: the hold is written resuming only after the resume ("resume
// before resuming is written") — the restarted daemon finds a running guest
// under a verified hold and answers TARGET_RAN, red.
func TestFleet_FwLiveRestart_F6c_TargetKilledAfterResume(t *testing.T) {
	c, src, dst, w := fwliveCluster(t)
	src.LandMigrationsOn(dst)
	killed := fwliveRestartKillAfterResume(t, w, dst, nil)
	done := fwliveMigrate(t, c, src, dst)
	fwliveRestartReach(t, killed, done, "the target's resume")
	if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldResuming {
		t.Errorf("%s's hold %+v (present %v) when its daemon died, want resuming", dst.Name, h.State, ok)
	}
	fwliveRestartDaemon(t, c, dst)
	if err := fwliveWait(t, done); err != nil {
		t.Fatalf("the move after the target's restart: %v", err)
	}
	fwliveMoved(t, src, dst)
	if fwliveCondition(t, src, "firmware_migration_target_ran") {
		t.Error("firmware_migration_target_ran raised for a hand-over")
	}
	if n := strings.Count(strings.Join(fwliveOps(dst), " "), "resume"); n != 1 {
		t.Errorf("%s resumed the guest %d times, want once", dst.Name, n)
	}
}

// F-6d. Release's resume fails once: the hold stays resuming over a paused
// guest, and the source's retry resumes it (§6.6 step 2a).
//
// Then the target host crashes right after a resume: the guest ran (its
// NVRAM is T1, the source's final, not the T0 Prepare materialised; its
// swtpm wrote the TPM state back), the domain is shut off and the daemon
// restarts. The retried Release takes H1's checks (step 2b), which find the
// guest ran: the move parks target_ran, the hold kept, nothing written
// anywhere, both copies kept. Each of H1's two run detectors catches it on
// its own (the NVRAM one is the only one an SB-only VM has).
//
// Mutations: a resuming hold over a paused guest is refused ("treat resuming
// + paused as refused") — the first case parks instead of resuming, red.
// H1 skips its permall check — the crash case still parks (the NVRAM
// detector), green; H1 skips its NVRAM-is-T0 check — still parks (the
// permall detector), green; H1 skips both — the crash case pushes the NVRAM
// and leaves the VM stopped, red.
func TestFleet_FwLiveRestart_F6d_ResumeFailsThenTargetCrashes(t *testing.T) {
	t.Run("resume_fails_once", func(t *testing.T) {
		c, src, dst, _ := fwliveCluster(t)
		src.LandMigrationsOn(dst)
		var failed atomic.Bool
		dst.Virt.FailResumeDomain = func(name string) error {
			if name == fwwVM && failed.CompareAndSwap(false, true) {
				return errors.New("induced resume failure")
			}
			return nil
		}
		if err := fwliveWait(t, fwliveMigrate(t, c, src, dst)); err != nil {
			t.Fatalf("the move with one failed resume: %v", err)
		}
		if !failed.Load() {
			t.Fatal("the resume never failed")
		}
		fwliveMoved(t, src, dst)
	})

	t.Run("target_crash_after_resume", func(t *testing.T) {
		c, src, dst, w := fwliveCluster(t)
		final := fwliveRestartFinalNvram(src, dst)
		killed := fwliveRestartKillAfterResume(t, w, dst, func() { dst.Virt.ShutOffDomain(fwwVM, "crashed") })
		done := fwliveMigrate(t, c, src, dst)
		fwliveRestartReach(t, killed, done, "the target's resume")
		// The guest ran: its NVRAM is T1 (the source's final, written on
		// resume), not the T0 Prepare materialised.
		ran, _ := fwliveFile(dst.FW.NvramPath(fwwVM))
		if !bytes.Equal(ran, final) || bytes.Equal(ran, fwwNvram) {
			t.Fatalf("fixture: the resumed guest's NVRAM is %q, want the source's final (T1), not T0", ran)
		}
		permall, _ := fwliveFile(fwlivePermall(dst))
		rowBefore := fwliveRow(t, src)
		fwliveRestartDaemon(t, c, dst)
		err := fwliveWait(t, done)
		if err == nil {
			t.Fatal("the move succeeded over a guest that ran before the crash")
		}
		m, ok := fwliveMarker(t, src)
		if !ok || m.Phase != fwmig.PhaseTargetRan {
			t.Fatalf("marker %+v (present %v) (move: %v), want target_ran", m, ok, err)
		}
		if !fwliveCondition(t, src, "firmware_migration_target_ran") {
			t.Error("no firmware_migration_target_ran")
		}
		if h, ok := fwliveHold(t, dst); !ok || h.State != fwmig.HoldResuming {
			t.Errorf("%s's hold %+v (present %v), want kept resuming", dst.Name, h.State, ok)
		}
		// Nothing written: the target's state and the row as the crash left
		// them, the source's state kept.
		if b, _ := fwliveFile(dst.FW.NvramPath(fwwVM)); !bytes.Equal(b, ran) {
			t.Errorf("%s's NVRAM changed to %q", dst.Name, b)
		}
		if b, _ := fwliveFile(fwlivePermall(dst)); !bytes.Equal(b, permall) {
			t.Errorf("%s's permall changed to %q", dst.Name, b)
		}
		if row := fwliveRow(t, src); row.HostName != rowBefore.HostName || row.State != rowBefore.State || row.StateDetail != rowBefore.StateDetail {
			t.Errorf("row %s on %s (%q), want as before Release: %s on %s (%q)",
				row.State, row.HostName, row.StateDetail, rowBefore.State, rowBefore.HostName, rowBefore.StateDetail)
		}
		if st := fwliveState(dst); st != string(libvirtfake.StateShutdown) {
			t.Errorf("%s's domain is %s, want shut off, not booted", dst.Name, st)
		}
		if n := strings.Count(strings.Join(fwliveOps(dst), " "), "start"); n != 0 {
			t.Errorf("%s started the guest %d times", dst.Name, n)
		}
		if b, _ := fwliveFile(fwlivePermall(src)); !bytes.Equal(b, fwwPermall) {
			t.Errorf("%s's permall %q, want its own, kept", src.Name, b)
		}
		if b, _ := fwliveFile(src.FW.NvramPath(fwwVM)); !bytes.Equal(b, final) {
			t.Errorf("%s's NVRAM %q, want its final, kept", src.Name, b)
		}
		if st := fwliveState(src); st != string(libvirtfake.StateShutdown) {
			t.Errorf("%s's leftover is %s, want kept, shut off", src.Name, st)
		}
	})
}

// ── F-7, F-7b, F-7c, F-7d: the migration call fails ──

// fwliveRestartFailMigration makes src's next migration of fwlive1 fail
// after do (what libvirt had done by then) with an error.
func fwliveRestartFailMigration(src *Node, do func(name string, p lv.MigrateParams)) {
	src.Virt.OnMigrateToTarget = func(name, _ string, p lv.MigrateParams) error {
		if do != nil {
			do(name, p)
		}
		return errors.New("induced migration failure")
	}
}

// F-7. The migration fails once libvirt has created the swtpm tree on the
// target, before any domain is defined there. Abort PRE_CUTOVER removes what
// the attempt created on the target (rule D: the tree, which was absent at
// Prepare, and the NVRAM Prepare materialised) and the source keeps running.
//
// Mutation: rule D leaves the swtpm tree — red.
func TestFleet_FwLiveRestart_F7_MigrationFailsAfterTargetTree(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	src.LandMigrationsOn(dst)
	var tree atomic.Bool
	dst.Virt.FailAfterTargetTree = func(name string) error {
		_, ok := fwliveFile(fwlivePermall(dst))
		tree.Store(ok)
		return errors.New("induced failure after the target's swtpm tree was created")
	}
	if err := fwliveWait(t, fwliveMigrate(t, c, src, dst)); err == nil {
		t.Fatal("the move succeeded with its migration failing")
	}
	if !tree.Load() {
		t.Fatalf("fixture: the target had no swtpm tree when the migration failed")
	}
	if _, err := os.Stat(dst.FW.SwtpmDir(fwwUUID)); !os.IsNotExist(err) {
		t.Errorf("%s's swtpm tree %s is left (%v)", dst.Name, dst.FW.SwtpmDir(fwwUUID), err)
	}
	fwliveRestartUndone(t, src, dst)
}

// F-7b. The migration call returns an error, but the source domain is no
// longer active (a Confirm-phase error after Finish): M1b. The move does not
// abort; it goes on to cutover, Verify answers MATCH, and it completes.
//
// Mutation: an error from the migration call aborts the move whatever the
// source domain's state ("Abort on error") — the target's copy is discarded
// and the guest runs nowhere, red.
func TestFleet_FwLiveRestart_F7b_MigrationErrorWithSourceInactive(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	fwliveRestartFailMigration(src, fwliveRestartLand(t, src, dst, "migrated"))
	if err := fwliveWait(t, fwliveMigrate(t, c, src, dst)); err != nil {
		t.Fatalf("the move after a Confirm-phase error: %v", err)
	}
	fwliveMoved(t, src, dst)
}

// F-7c. The migration call fails and leaves the source guest paused, with no
// domain on the target: M1p. Abort PRE_CUTOVER finds nothing held there, so
// the paused source is resumed first (the only copy), the row restored to
// running and the marker removed.
//
// Mutation: M1p leaves the source paused ("leave it paused") — red.
func TestFleet_FwLiveRestart_F7c_MigrationErrorWithSourcePaused(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	fwliveRestartFailMigration(src, func(name string, _ lv.MigrateParams) {
		src.Virt.SetState(name, libvirtfake.StatePaused)
	})
	if err := fwliveWait(t, fwliveMigrate(t, c, src, dst)); err == nil {
		t.Fatal("the move succeeded with its migration failing")
	}
	fwliveRestartUndone(t, src, dst)
}

// F-7d. A Confirm-phase failure: the migration call fails with the source
// still running, after the target defined the incoming guest paused under its
// prepared hold. The source decides from the Abort refusal (never Verify
// before cutover): the target's copy is discarded automatically (quarantined),
// the marker removed, the source keeps running, and `lv stop` then works.
//
// Mutation: the source parks instead of discarding ("park instead") — the
// marker stays and `lv stop` is refused, red.
func TestFleet_FwLiveRestart_F7d_ConfirmPhaseFailureDiscardsTargetCopy(t *testing.T) {
	ctx := context.Background()
	c, src, dst, _ := fwliveCluster(t)
	fwliveRestartFailMigration(src, func(name string, p lv.MigrateParams) {
		if err := dst.Virt.LandFirmwareLive(src.Virt, name, p); err != nil {
			t.Errorf("land: %v", err)
		}
	})
	if err := fwliveWait(t, fwliveMigrate(t, c, src, dst)); err == nil {
		t.Fatal("the move succeeded with its migration failing")
	}
	if st := fwliveState(src); st != string(libvirtfake.StateRunning) {
		t.Errorf("%s's guest is %s, want still running", src.Name, st)
	}
	if st := fwliveState(dst); st != "undefined" {
		t.Errorf("%s's copy is %s, want discarded", dst.Name, st)
	}
	if m, ok := fwliveMarker(t, src); ok {
		t.Fatalf("marker left in %s (%s)", m.Phase, m.Detail)
	}
	if h, ok := fwliveHold(t, dst); ok {
		t.Errorf("%s's hold left in %s", dst.Name, h.State)
	}
	q := fwliveQuarantines(dst)
	if len(q) != 1 {
		t.Fatalf("%s's quarantine %v, want the discarded copy", dst.Name, q)
	}
	if b, ok := fwliveFile(filepath.Join(q[0], "swtpm", "tpm2", "tpm2-00.permall")); !ok || !bytes.Equal(b, fwwPermall) {
		t.Errorf("the quarantine holds permall %q (present %v), want the discarded copy", b, ok)
	}
	if b, ok := fwliveFile(filepath.Join(q[0], "nvram")); !ok || !bytes.Equal(b, fwwNvram) {
		t.Errorf("the quarantine holds NVRAM %q (present %v), want the copy Prepare materialised", b, ok)
	}
	if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "running" {
		t.Errorf("row %s on %s, want running on %s", row.State, row.HostName, src.Name)
	}
	fwliveSourceKept(t, src)
	if _, err := c.SelfClient(src).StopVM(ctx, &pb.StopVMRequest{Name: fwwVM, Force: true}); err != nil {
		t.Fatalf("lv stop after the discard: %v", err)
	}
	if st := fwliveState(src); st != string(libvirtfake.StateShutdown) {
		t.Errorf("%s's guest is %s after lv stop, want shut off", src.Name, st)
	}
}

// ── F-8: R-I5 after the commit ──

// F-8. After the commit, once the target runs the guest and before the source
// has cleaned up, the source's reconciler runs over the leftover domain the
// move keeps defined and shut off — with stop reason migrated, and (a source
// host reboot) unknown, where the reconciler's proven-owner path asks the
// owner and finds the guest running there. Leftover cleanup would undefine it
// with UNDEFINE_NVRAM, deleting its NVRAM (probe (g)). The definition, the
// NVRAM and the TPM state stay as they are, and the move then completes.
//
// What protects each case:
//   - unknown: the reconciler's marker skip and the undefine guard's marker
//     refusal. Mutation: remove both — the leftover is undefined and its
//     NVRAM deleted, red.
//   - migrated: three layers — the reconciler's allowlist (cleanableLeftover
//     does not clean reason migrated), the marker skip and the guard.
//     Mutation: admit migrated in cleanableLeftover AND remove the skip AND
//     the guard's refusal — red. Any one of the three left in place keeps it
//     green (each was checked: allowlist alone admitting migrated; with the
//     skip removed too; with the guard's refusal removed too), so the case
//     pins all three as defence in depth.
func TestFleet_FwLiveRestart_F8_ReconcilerLeavesSourceStateAfterCommit(t *testing.T) {
	for _, reason := range []string{"migrated", "unknown"} {
		t.Run(reason, func(t *testing.T) {
			ctx := context.Background()
			c, src, dst, _ := fwliveCluster(t)
			src.LandMigrationsOn(dst)
			if reason == "unknown" {
				src.Virt.ReportSourceReasonUnknown = func(string) bool { return true }
			}
			dst.HookUnary("ReleaseLiveFirmwareTarget", func(hctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
				resp, err := h(hctx, req)
				if err != nil {
					t.Errorf("Release: %v", err)
					return resp, err
				}
				// The guest runs on the target; the source has its
				// marker, committed, and its leftover.
				if st := fwliveState(dst); st != string(libvirtfake.StateRunning) {
					t.Errorf("fixture: %s's guest is %s after Release, want running", dst.Name, st)
				}
				if m, _ := fwliveMarker(t, src); m.Phase != fwmig.PhaseCommitted {
					t.Errorf("fixture: marker %s, want committed", m.Phase)
				}
				if ds, _ := src.Virt.DomainStateReason(fwwVM); ds.Reason != reason {
					t.Errorf("fixture: the leftover's stop reason is %q, want %q", ds.Reason, reason)
				}
				rec := src.Reconciler()
				rec.SetPeerRuntimeChecker(src.Server.CheckPeerVMRuntime)
				for i := 0; i < 2; i++ {
					rec.ReconcileOnce(ctx)
				}
				if st := fwliveState(src); st != string(libvirtfake.StateShutdown) {
					t.Errorf("after the source's reconciler: leftover %s, want defined and shut off", st)
				}
				for _, op := range []string{"undefine", "nvram-deleted"} {
					if fwliveDid(src, op) {
						t.Errorf("after the source's reconciler: %s's libvirt did %s (ops %v)", src.Name, op, fwliveOps(src))
					}
				}
				fwliveSourceKept(t, src)
				return resp, err
			})
			if err := fwliveWait(t, fwliveMigrate(t, c, src, dst)); err != nil {
				t.Fatalf("the move: %v", err)
			}
			fwliveMoved(t, src, dst)
		})
	}
}

// ── F-3: target unreachable at Verify, fence-confirm, rejoin ──

// F-3. The source daemon restarts after the guest landed on the target, and
// the target is down: Verify goes unanswered, the move parks
// target_unreachable, and `lv start` is refused (the stale-or-current
// question is open). An operator confirms the target off; the next recovery
// pass resolves the move by fence (§7): the commit never landed, so the
// source's state is current — the owed DISCARD is recorded with the disk
// stubs the attempt made there, the marker removed, the row stopped, and
// `lv start` on the source succeeds. The target then comes back (its QEMU died
// with the host, its daemon restarted): the owed DISCARD lands, its copy is
// quarantined, its hold and the record go. The disk stub the attempt created
// there stays: the target's in-memory stub ledger did not survive its
// restart, so it no longer owns the file (a safe leak, spec §6.8).
//
// Mutations: the fence resolution keeps the marker — `lv start` stays
// refused, red; the owed DISCARD is never sent on rejoin — the hold and the
// record stay, red.
func TestFleet_FwLiveRestart_F3_TargetUnreachableFenceConfirmRejoin(t *testing.T) {
	ctx := context.Background()
	// A host-local disk, copied with the memory (storage route), so the
	// attempt creates a stub on the target.
	sc := fwliveSetup(t, true)
	c, src, dst, disk := sc.c, sc.src, sc.dst, sc.disk

	m := fwliveRestartCrashMigratingReq(t, c, src, dst, fwliveRestartLand(t, src, dst, "migrated"), &pb.MigrateVMRequest{
		VmName: fwwVM, TargetHost: dst.Name, Strategy: pb.MigrateStrategy_MIGRATE_LIVE, WithStorage: true,
	})
	if len(m.CreatedStubs) != 1 || m.CreatedStubs[0] != disk {
		t.Fatalf("the marker records stubs %v, want [%s]", m.CreatedStubs, disk)
	}
	if _, ok := fwliveFile(disk); !ok {
		t.Fatalf("fixture: no stub at %s on %s", disk, dst.Name)
	}

	// The target goes down with the guest held paused there; the source
	// daemon comes back.
	fwliveRestartDown(dst)
	fwliveRestartUp(t, c, src)
	fwliveRestartRecovered(src)
	parked, ok := fwliveMarker(t, src)
	if !ok || parked.Phase != fwmig.PhaseTargetUnreachable || parked.ParkedFrom != fwmig.PhaseCutover {
		t.Fatalf("marker %+v (present %v), want target_unreachable from cutover", parked, ok)
	}
	if !fwliveCondition(t, src, "firmware_migration_target_unreachable") {
		t.Error("no firmware_migration_target_unreachable")
	}
	if _, err := c.SelfClient(src).StartVM(ctx, &pb.StartVMRequest{Name: fwwVM}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("lv start while parked = %v, want FailedPrecondition", err)
	}
	if st := fwliveState(src); st != string(libvirtfake.StateShutdown) {
		t.Fatalf("%s's guest is %s after a refused start, want shut off", src.Name, st)
	}

	// fence-confirm, then the next recovery pass.
	mustFenceConfirm(t, src, dst.Name)
	fwliveRestartRecovered(src)
	if m, ok := fwliveMarker(t, src); ok {
		t.Fatalf("marker left in %s after the fence (%s)", m.Phase, m.Detail)
	}
	if row := fwliveRow(t, src); row.HostName != src.Name || row.State != "stopped" {
		t.Errorf("row %s on %s after the fence, want stopped on %s", row.State, row.HostName, src.Name)
	}
	owed, ok, err := fwmig.New(src.FW.DataDir).GetOwedDiscard(fwwVM, m.Attempt)
	if err != nil || !ok {
		t.Fatalf("no owed-discard record after the fence (%v)", err)
	}
	if owed.Target != dst.Name || len(owed.CreatedStubs) != 1 || owed.CreatedStubs[0] != disk {
		t.Errorf("owed discard %+v, want to %s with stubs [%s]", owed, dst.Name, disk)
	}
	if !fwliveCondition(t, src, "firmware_migration_discard_owed") {
		t.Error("no firmware_migration_discard_owed")
	}
	fwliveSourceKept(t, src)
	if _, err := c.SelfClient(src).StartVM(ctx, &pb.StartVMRequest{Name: fwwVM}); err != nil {
		t.Fatalf("lv start on %s after the fence: %v", src.Name, err)
	}
	if st := fwliveState(src); st != string(libvirtfake.StateRunning) {
		t.Fatalf("%s's guest is %s after lv start, want running", src.Name, st)
	}
	// The owed DISCARD is not answered while the target is down.
	fwliveRestartRecovered(src)
	if _, ok, _ := fwmig.New(src.FW.DataDir).GetOwedDiscard(fwwVM, m.Attempt); !ok {
		t.Fatal("the owed discard went while its target was down")
	}

	// The target comes back: its host was off, so its QEMU is gone and the
	// held domain shut off; its daemon starts with nothing of the stub
	// ledger.
	dst.Virt.ShutOffDomain(fwwVM, "crashed")
	fwliveRestartUp(t, c, dst)
	fwliveRestartRecovered(src)
	if _, ok, _ := fwmig.New(src.FW.DataDir).GetOwedDiscard(fwwVM, m.Attempt); ok {
		t.Error("the owed discard is still recorded after the target answered it")
	}
	if fwliveCondition(t, src, "firmware_migration_discard_owed") {
		t.Error("firmware_migration_discard_owed still open after the discard landed")
	}
	if h, ok := fwliveHold(t, dst); ok {
		t.Errorf("%s's hold left in %s", dst.Name, h.State)
	}
	if st := fwliveState(dst); st != "undefined" {
		t.Errorf("%s's copy is %s, want undefined by the discard", dst.Name, st)
	}
	q := fwliveQuarantines(dst)
	if len(q) != 1 {
		t.Fatalf("%s's quarantine %v, want the discarded copy", dst.Name, q)
	}
	if b, ok := fwliveFile(filepath.Join(q[0], "swtpm", "tpm2", "tpm2-00.permall")); !ok || !bytes.Equal(b, fwwPermall) {
		t.Errorf("the quarantine holds permall %q (present %v), want the discarded copy", b, ok)
	}
	if _, ok := fwliveFile(disk); !ok {
		t.Errorf("the stub %s was removed by a target that no longer owns it", disk)
	}
	if st := fwliveState(src); st != string(libvirtfake.StateRunning) {
		t.Errorf("%s's guest is %s after the discard, want still running", src.Name, st)
	}
}

// lab2-D2-proof F1. The source daemon restarts with the guest landed on the
// target, and its recovery verifies, commits and releases in one pass. The
// target refuses the first Release as it does when the commit has not yet
// replicated to it (its row still names the source). The recovery waits that
// out briefly and releases in the same pass, so the guest does not stay
// paused on the target until the next pass, a minute later.
//
// Mutation: drop the recovery's wait on the refusal — the move parks
// target_unreachable after the pass, red.
func TestFleet_FwLiveRestart_RecoveryReleaseWaitsForTheCommit(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	fwliveRestartCrashMigrating(t, c, src, dst, fwliveRestartLand(t, src, dst, "migrated"))
	var releases atomic.Int32
	dst.HookUnary("ReleaseLiveFirmwareTarget", func(hctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
		releases.Add(1)
		return nil, status.Errorf(codes.FailedPrecondition,
			"VM %q: its row names %s, not %s for this incarnation: the move has not committed, so the guest is not released", fwwVM, src.Name, dst.Name)
	})
	fwliveRestartUp(t, c, src)
	fwliveRestartRecovered(src)
	if releases.Load() != 1 {
		t.Fatalf("the refusing Release was asked %d times, want once", releases.Load())
	}
	fwliveMoved(t, src, dst)
}

// fwliveRestartMigrateLeases lists the MigrateVM admission leases still
// counted against n.
func fwliveRestartMigrateLeases(t *testing.T, n *Node) []string {
	t.Helper()
	views, err := corrosion.HostReservations(context.Background(), n.DB, n.Name)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, v := range views {
		if v.Op.Method == "MigrateVM" && v.Op.ResourceKind == corrosion.CapacityResourceKind {
			out = append(out, v.Op.ID)
		}
	}
	return out
}

// lab2-D2-proof F8. The source daemon dies holding the move's admission lease
// on the target (a MigrateVM transfer lease, which the stale-lease sweep
// keeps for 6 h, and `lv operation release-reservation` refuses). The marker
// records the lease, and the recovery that finishes the move in the dead
// process's place releases it, so the target's capacity is free again.
//
// Mutation: drop the release from the recovery — the lease stays counted on
// the target, red.
func TestFleet_FwLiveRestart_RecoveryReleasesTheDeadMovesLease(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	// A killed daemon releases nothing: the old server's move, which its
	// stop cancels here, never reaches the target with its release.
	var restarted atomic.Bool
	for i := 0; i < 4; i++ {
		dst.HookUnary("ReleaseHostCapacity", func(hctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
			if !restarted.Load() {
				return nil, fwliveRestartStoppedHere
			}
			return h(hctx, req)
		})
	}
	m := fwliveRestartCrashMigrating(t, c, src, dst, fwliveRestartLand(t, src, dst, "migrated"))
	if m.CapacityLease == "" || m.CapacityLeaseHolder != dst.Name {
		t.Fatalf("the marker records lease %q on %q, want the move's lease on %s", m.CapacityLease, m.CapacityLeaseHolder, dst.Name)
	}
	if got := fwliveRestartMigrateLeases(t, dst); len(got) != 1 || got[0] != m.CapacityLease {
		t.Fatalf("fixture: %s counts MigrateVM leases %v, want the move's %s", dst.Name, got, m.CapacityLease)
	}
	time.Sleep(200 * time.Millisecond) // the stopped server's move unwinds
	restarted.Store(true)
	fwliveRestartUp(t, c, src)
	fwliveRestartRecovered(src)
	fwliveMoved(t, src, dst)
	eventually(t, 30*time.Second, "the dead move's lease to be released on the target", func() bool {
		return len(fwliveRestartMigrateLeases(t, dst)) == 0
	})
}

// Review m4. The recovery's release of a dead move's lease fails (the holder
// does not answer), and the move parks: the marker keeps the lease, and a
// later pass, not only the next daemon start, releases it once the holder
// answers.
//
// Mutation: release only at start-up or from an unparked marker — the lease
// stays counted after the later pass, red.
func TestFleet_FwLiveRestart_ALaterPassReleasesTheDeadMovesLease(t *testing.T) {
	c, src, dst, _ := fwliveCluster(t)
	var down atomic.Bool
	down.Store(true)
	for _, method := range []string{"ReleaseHostCapacity", "ReleaseLiveFirmwareTarget"} {
		for i := 0; i < 40; i++ {
			dst.HookUnary(method, func(hctx context.Context, req any, h grpc.UnaryHandler) (any, error) {
				if down.Load() {
					return nil, status.Error(codes.Unavailable, "the target does not answer")
				}
				return h(hctx, req)
			})
		}
	}
	m := fwliveRestartCrashMigrating(t, c, src, dst, fwliveRestartLand(t, src, dst, "migrated"))
	time.Sleep(200 * time.Millisecond) // the stopped server's move unwinds
	fwliveRestartUp(t, c, src)
	fwliveRestartRecovered(src)
	if cur, ok := fwliveMarker(t, src); !ok || !cur.Phase.Parked() || cur.CapacityLease != m.CapacityLease {
		t.Fatalf("fixture: marker %+v (present %v), want parked and still naming the lease", cur, ok)
	}
	if got := fwliveRestartMigrateLeases(t, dst); len(got) != 1 {
		t.Fatalf("fixture: %s counts MigrateVM leases %v, want the dead move's", dst.Name, got)
	}
	down.Store(false)
	src.Server.FirmwareMoveRecoveryOnce(context.Background())
	eventually(t, 30*time.Second, "a later pass to release the dead move's lease", func() bool {
		return len(fwliveRestartMigrateLeases(t, dst)) == 0
	})
}
