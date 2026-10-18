package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// Dropping writeBootStateWith's returned handle lets shutdown close the DB
// while a reconcile's serving worker still owns its local client.
func TestOwnRowReconcileServingWorkerHeldThroughAllStopTriggers(t *testing.T) {
	for _, trigger := range []string{"context", "reexec", "uninstall"} {
		t.Run(trigger, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cert := [2]string{"current", ""}
			d, _ := ownRowDaemon(t, "current", &cert)
			d.cfg.DataDir = t.TempDir()
			if err := corrosion.UpdateHostState(ctx, d.db, d.cfg.HostName, "joining"); err != nil {
				t.Fatal(err)
			}
			entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
			d.selfPinger = func() (pinger, func(), error) {
				close(entered)
				<-release
				return pingerFunc(func() error { return errors.New("not serving") }), func() { close(exited) }, nil
			}
			svc := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: d.cfg.HostName, DB: d.db, DataDir: t.TempDir()})
			c := newDBWorkerCoordinator(ctx, svc)
			d.reconcileBootReport(c.ctx)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("reconcile did not start serving worker")
			}
			c.wg.Add(1)
			go func() { defer c.wg.Done(); <-d.startOwnRowHold(c.ctx) }()
			reexec, uninstall, stopped, cleaned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			go c.shutdown(ctx, reexec, uninstall, func(daemonStopReason) {}, func() { close(stopped) }, func() { d.db.Close(); close(cleaned) })
			switch trigger {
			case "context":
				cancel()
			case "reexec":
				close(reexec)
			case "uninstall":
				close(uninstall)
			}
			<-stopped
			early := false
			select {
			case <-cleaned:
				early = true
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("actual serving worker did not release client")
			}
			select {
			case <-cleaned:
			case <-time.After(5 * time.Second):
				t.Fatal("joined shutdown never cleaned dependencies")
			}
			if early {
				t.Fatal("cleanup closed DB while own-row reconcile serving worker was held")
			}
		})
	}
}

// A reconcile already inside the loop must also leave before dependencies
// close; cancelling the outer Run context is not required for re-exec/uninstall.
func TestOwnRowReconcileHeldThroughAllStopTriggers(t *testing.T) {
	oldPoll := ownRowPoll
	ownRowPoll = time.Millisecond
	defer func() { ownRowPoll = oldPoll }()
	for _, trigger := range []string{"context", "reexec", "uninstall"} {
		t.Run(trigger, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cert := [2]string{"new", ""}
			d, _ := ownRowDaemon(t, "old", &cert)
			evaluated, entered, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var armed atomic.Bool
			var once sync.Once
			if _, err := d.db.ConfigureOwnRowHold(ctx, func() (string, string) {
				if armed.Load() {
					once.Do(func() { close(evaluated) })
				}
				return "new", ""
			}); err != nil {
				t.Fatal(err)
			}
			d.ownRowReconciler = func(context.Context) { close(entered); <-release }
			svc := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: d.cfg.HostName, DB: d.db, DataDir: t.TempDir()})
			c := newDBWorkerCoordinator(ctx, svc)
			armed.Store(true)
			done := d.startOwnRowHold(c.ctx)
			c.wg.Add(1)
			go func() { defer c.wg.Done(); <-done }()
			select {
			case <-evaluated:
			case <-time.After(5 * time.Second):
				c.cancel()
				close(release)
				<-done
				t.Fatal("loop never evaluated hold")
			}
			if _, err := d.db.DB().Exec(`UPDATE hosts SET cert_serial='new',incarnation=1 WHERE name=?`, d.cfg.HostName); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				c.cancel()
				close(release)
				<-done
				t.Fatal("hold never entered real reconcile")
			}
			reexec, uninstall, stopped, cleaned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			go c.shutdown(ctx, reexec, uninstall, func(daemonStopReason) {}, func() { close(stopped) }, func() { d.db.Close(); close(cleaned) })
			switch trigger {
			case "context":
				cancel()
			case "reexec":
				close(reexec)
			case "uninstall":
				close(uninstall)
			}
			<-stopped
			early := false
			select {
			case <-cleaned:
				early = true
			case <-time.After(30 * time.Millisecond):
			}
			close(release)
			select {
			case <-cleaned:
			case <-time.After(5 * time.Second):
				t.Fatal("reconcile failed to join")
			}
			if early {
				t.Fatal("cleanup closed DB during blocked own-row reconciliation")
			}
		})
	}
}
