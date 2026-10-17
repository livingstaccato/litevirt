package daemon

import (
	"context"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/tests/fleet"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Exercise the actual retained cleanup launched by a real TLS DeleteVM RPC,
// not a stand-in completion callback. Fleet owns actual final DB closure;
// this coordinator must not enter its cleanup callback before child exit.
func TestDaemonDeleteCleanup_AllStopTriggersHoldDependencyCleanup(t *testing.T) {
	for _, trigger := range []string{"context", "reexec", "shutdown"} {
		t.Run(trigger, func(t *testing.T) {
			entered, release, exited, draining := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			var once, entryOnce, drainOnce sync.Once
			var exits atomic.Int32
			const nodes = 3
			const children = nodes - 1 // The planner targets both other active hosts.
			unpark := func() { once.Do(func() { close(release) }) }
			f := fleet.New(t, fleet.Options{Nodes: nodes, IndependentReplicas: true, DBWorkerEvent: func(host string, _ context.Context, worker, event string) {
				if host != "node-0" {
					return
				}
				if worker == "delete_vm" && event == "drain" {
					drainOnce.Do(func() { close(draining) })
					return
				}
				if worker != "delete_cleanup" {
					return
				}
				if event == "entry" {
					entryOnce.Do(func() { close(entered) })
					<-release
				}
				if event == "exit" && exits.Add(1) == children {
					close(exited)
				}
			}})
			n := f.Nodes[0]
			ctx, cancel := context.WithCancel(context.Background())
			coordinatorDone := make(chan struct{})
			coordinatorStarted := false
			// Registered before fatal assertions; release and join before fleet
			// closes the dependencies, including a failed assertion after launch.
			t.Cleanup(func() {
				unpark()
				cancel()
				if coordinatorStarted {
					select {
					case <-coordinatorDone:
					case <-time.After(10 * time.Second):
						t.Error("coordinator did not exit during fixture cleanup")
					}
				}
			})
			if err := corrosion.InsertVM(ctx, n.DB, corrosion.VMRecord{Name: "owned", HostName: n.Name, State: "stopped", Spec: `{"name":"owned","cpu":1,"memory_mib":256}`}, nil, nil); err != nil {
				t.Fatal(err)
			}
			if err := n.Virt.DefineDomain(`<domain><name>owned</name></domain>`); err != nil {
				t.Fatal(err)
			}
			f.WaitConverged(t, 20*time.Second)
			if _, err := f.SelfClient(n).DeleteVM(ctx, &pb.DeleteVMRequest{Name: "owned"}); err != nil {
				t.Fatal(err)
			}
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("actual child did not enter")
			}
			f.WaitConverged(t, 20*time.Second)
			c := newDBWorkerCoordinator(ctx, n.Server)
			reexec, shutdown, stopped, cleaned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
			coordinatorStarted = true
			go func() {
				defer close(coordinatorDone)
				c.shutdown(ctx, reexec, shutdown, func(reason daemonStopReason) {
					want := map[string]daemonStopReason{"context": daemonContextStop, "reexec": daemonReExecStop, "shutdown": daemonUninstallStop}[trigger]
					if reason != want {
						t.Errorf("prepare reason %v want %v", reason, want)
					}
				}, func() { close(stopped) }, func() {
					if got := exits.Load(); got != children {
						t.Errorf("dependency cleanup preceded both actual child exits: got %d want %d", got, children)
					}
					close(cleaned)
				})
			}()
			switch trigger {
			case "context":
				cancel()
			case "reexec":
				close(reexec)
			case "shutdown":
				close(shutdown)
			}
			select {
			case <-stopped:
			case <-time.After(time.Second):
				t.Fatal("bounded stop-serving blocked on retained child")
			}
			select {
			case <-draining:
			case <-cleaned:
				t.Error("coordinator entered dependency cleanup without draining actual held child")
			case <-time.After(time.Second):
				t.Fatal("coordinator did not enter actual DeleteVM drain")
			}
			select {
			case <-cleaned:
				t.Error("coordinator entered dependency cleanup with actual child held")
			case <-time.After(50 * time.Millisecond):
			}
			if _, err := n.DB.Query(context.Background(), "SELECT 1"); err != nil {
				t.Fatal("child dependency closed", err)
			}
			unpark()
			select {
			case <-exited:
			case <-time.After(5 * time.Second):
				t.Fatal("real cleanup body failed to exit")
			}
			select {
			case <-cleaned:
			case <-time.After(time.Second):
				t.Fatal("coordinator failed to join released child")
			}
		})
	}
}
