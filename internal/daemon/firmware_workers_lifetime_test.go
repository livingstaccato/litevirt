package daemon

import (
	"context"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// A parked marker makes the real recovery read the DB and re-raise its
// condition after detaching from cancellation. No hypervisor or peer is needed.
func firmwareLifetimeMarker(t *testing.T, dir string) {
	t.Helper()
	err := fwmig.New(dir).PutMarker(fwmig.Marker{
		VM:      "held-guest",
		Binding: fwmig.Binding{UUID: "11111111-1111-4111-8111-111111111111", CreatedAt: "2026-10-19T00:00:00Z", Attempt: "22222222-2222-4222-8222-222222222222"},
		Target:  "peer", Route: fwmig.RouteStorageCopy,
		Phase: fwmig.PhaseSourcePaused, ParkedFrom: fwmig.PhaseMigrating,
		TPM: true, UEFI: true, SrcPermallSHA256: strings.Repeat("a", 64), SrcNvramSHA256: strings.Repeat("b", 64),
		Since: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC), Detail: "paused before cutover",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := fwmig.New(dir).PutOwedDiscard(fwmig.OwedDiscard{
		VM:      "owed-guest",
		Binding: fwmig.Binding{UUID: "33333333-3333-4333-8333-333333333333", CreatedAt: "2026-10-19T00:00:00Z", Attempt: "44444444-4444-4444-8444-444444444444"},
		Target:  "peer", Since: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC),
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonFirmwareWorkers_AllStopTriggersHoldDependencies(t *testing.T) {
	// Mutation: omit one producer/child family from shutdown, or use Run's
	// outer context for producers. Reexec/uninstall keep that context live.
	for _, trigger := range []string{"context", "reexec", "uninstall"} {
		for _, worker := range []string{
			"firmware_hold", "firmware_retained", "firmware_recovery", "replica_orphan",
			"firmware_startup_child", "firmware_periodic_child",
			"firmware_startup_discard", "firmware_periodic_discard",
		} {
			t.Run(trigger+"/"+worker, func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					outer, cancel := context.WithCancel(context.Background())
					defer cancel()
					db := corrosion.NewTestClientT(t)
					if err := corrosion.InitSchema(outer, db); err != nil {
						t.Fatal(err)
					}
					db.MarkReplicaCaughtUpForTests("peer")
					dir := t.TempDir()
					firmwareLifetimeMarker(t, dir)
					entered, release, exited := make(chan context.Context, 1), make(chan struct{}), make(chan struct{})
					var enterOnce, exitOnce sync.Once
					svc := grpcapi.NewServerForTests(grpcapi.TestServerOpts{
						HostName: "self", DataDir: dir, DB: db,
						DBWorkerEvent: func(ctx context.Context, name, event string) {
							if name != worker {
								return
							}
							if event == "entry" {
								enterOnce.Do(func() { entered <- ctx; <-release })
							}
							if event == "exit" {
								exitOnce.Do(func() { close(exited) })
							}
						},
					})
					c := newDBWorkerCoordinator(outer, svc)
					svc.MarkStartupWired()
					switch worker {
					case "firmware_hold", "firmware_retained":
						c.startFirmwareSweeps(outer)
					case "replica_orphan":
						c.startReplicaOrphanSweep(outer)
					case "firmware_startup_child", "firmware_startup_discard":
						c.recoverFirmwareMoves(outer)
					default:
						c.startFirmwareMoveRecovery(outer)
					}
					// Fake time advances to the real periodic pass when needed.
					workerCtx := <-entered
					reexec, uninstall := make(chan struct{}), make(chan struct{})
					stopped, cleaned := make(chan struct{}), make(chan struct{})
					go c.shutdown(outer, reexec, uninstall, func(daemonStopReason) {}, func() { close(stopped) }, func() {
						db.Close()
						close(cleaned)
					})
					switch trigger {
					case "context":
						cancel()
					case "reexec":
						close(reexec)
					case "uninstall":
						close(uninstall)
					}
					<-stopped
					synctest.Wait()
					select {
					case <-cleaned:
						t.Error("dependency cleanup ran while an admitted firmware worker was held")
					default:
						if _, err := corrosion.ListHosts(context.Background(), db); err != nil {
							t.Errorf("DB was unavailable before the admitted worker terminated: %v", err)
						}
					}
					if trigger != "context" && outer.Err() != nil {
						t.Error("reexec/uninstall incorrectly required outer cancellation")
					}
					if !strings.HasSuffix(worker, "_child") && workerCtx.Err() == nil {
						t.Error("shutdown did not cancel the firmware producer/owed-DISCARD context")
					}
					// Release even on RED, and terminate the raw baseline producers.
					cancel()
					close(release)
					<-exited
					<-cleaned
					synctest.Wait()
				})
			})
		}
	}
}

func TestDaemonFirmwareWorkers_ProducerStopsBeforeFinalChildJoin(t *testing.T) {
	// The periodic producer is already inside a pass when shutdown starts.
	// It admits an owed-DISCARD child after cancellation; joining only the
	// children present at shutdown would miss this child (or race Add/Wait).
	synctest.Test(t, func(t *testing.T) {
		outer, cancel := context.WithCancel(context.Background())
		defer cancel()
		db := corrosion.NewTestClientT(t)
		if err := corrosion.InitSchema(outer, db); err != nil {
			t.Fatal(err)
		}
		db.MarkReplicaCaughtUpForTests("peer")
		pass, letPass := make(chan struct{}), make(chan struct{})
		child, letChild := make(chan struct{}), make(chan struct{})
		producerExit, childExit := make(chan struct{}), make(chan struct{})
		svc := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "self", DataDir: t.TempDir(), DB: db,
			DBWorkerEvent: func(_ context.Context, worker, event string) {
				switch worker + "/" + event {
				case "firmware_recovery/pass":
					close(pass)
					<-letPass
				case "firmware_recovery/exit":
					close(producerExit)
				case "firmware_periodic_discard/entry":
					close(child)
					<-letChild
				case "firmware_periodic_discard/exit":
					close(childExit)
				}
			},
		})
		c := newDBWorkerCoordinator(outer, svc)
		c.startFirmwareMoveRecovery(outer)
		<-pass
		reexec, cleaned, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{})
		go c.shutdown(outer, reexec, nil, func(daemonStopReason) {}, func() { close(stopped) }, func() { db.Close(); close(cleaned) })
		close(reexec)
		<-stopped
		synctest.Wait()
		select {
		case <-cleaned:
			t.Error("cleanup ran before the producer stopped admitting children")
		default:
		}
		// Also stop the raw baseline loop so RED releases every goroutine.
		cancel()
		close(letPass)
		<-child
		<-producerExit
		synctest.Wait()
		select {
		case <-cleaned:
			t.Error("cleanup ran before the child admitted by the final pass terminated")
		default:
		}
		close(letChild)
		<-childExit
		<-cleaned
		synctest.Wait()
	})
}
