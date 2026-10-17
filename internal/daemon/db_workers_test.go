package daemon

import (
	"context"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"sync"
	"testing"
	"time"
)

func TestDaemonDBWorkers_AllStopTriggersHoldCleanup(t *testing.T) {
	for _, trigger := range []string{"context", "reexec", "shutdown"} {
		for _, hold := range []string{"lb_entry", "vrrp_entry", "sweep_entry", "sweep_round"} {
			t.Run(trigger+"/"+hold, func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				db := corrosion.NewTestClientT(t)
				if err := corrosion.InitSchema(ctx, db); err != nil {
					t.Fatal(err)
				}
				entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
				var once sync.Once
				svc := grpcapi.NewServerForTests(grpcapi.TestServerOpts{HostName: "a", DataDir: t.TempDir(), DB: db, ReleaseSweepEvery: time.Millisecond, DBWorkerEvent: func(_ context.Context, n, e string) {
					if n+"_"+e == hold {
						once.Do(func() { close(entered); <-release })
					}
					if n == "vrrp" && e == "exit" {
						close(exited)
					}
				}})
				c := newDBWorkerCoordinator(ctx, svc)
				c.startSweep()
				c.startLB(time.Hour)
				select {
				case <-entered:
				case <-time.After(5 * time.Second):
					close(release)
					c.cancel()
					c.wg.Wait()
					t.Fatal("actual worker never reached hold")
				}
				cleanup := make(chan struct{})
				reexec, shutdown := make(chan struct{}), make(chan struct{})
				prepared := make(chan struct{})
				stopped := make(chan struct{})
				go c.shutdown(ctx, reexec, shutdown, func(daemonStopReason) { close(prepared) }, func() { close(stopped) }, func() { db.Close(); close(cleanup) })
				switch trigger {
				case "context":
					cancel()
				case "reexec":
					close(reexec)
				case "shutdown":
					close(shutdown)
				}
				<-prepared
				select {
				case <-stopped:
				case <-time.After(time.Second):
					t.Fatal("bounded stop-serving blocked on worker")
				}
				select {
				case <-c.ctx.Done():
				default:
					t.Error("shutdown did not cancel actual worker context")
				}
				early := false
				select {
				case <-cleanup:
					early = true
				case <-time.After(50 * time.Millisecond):
				}
				c.cancel()
				close(release)
				c.wg.Wait()
				select {
				case <-cleanup:
				case <-time.After(5 * time.Second):
					t.Fatal("cleanup not released")
				}
				select {
				case <-exited:
				case <-time.After(5 * time.Second):
					t.Fatal("actual outer VRRP child not terminal")
				}
				if early {
					t.Fatal("cleanup closed actual DB while real owned worker was held")
				}
			})
		}
	}
}
