package fleet

import (
	"context"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"sync"
	"testing"
	"time"
)

// Hold the actual detached origin before its next peer/DB round, after the
// DeleteVM RPC has returned. A held receiving RPC would be joined already by
// GracefulStop and would not expose this missing ownership edge.
func TestFleet_DeleteCleanupOriginHoldsDependencyClose(t *testing.T) {
	entered, release, exited, stopped := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	draining := make(chan struct{})
	var drainOnce sync.Once
	var once sync.Once
	unpark := func() { once.Do(func() { close(release) }) }
	c := New(t, Options{Nodes: 3, IndependentReplicas: true, DBWorkerEvent: func(host string, _ context.Context, worker, event string) {
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
			close(entered)
			<-release
		}
		if event == "exit" {
			close(exited)
		}
	}})
	stopStarted := false
	t.Cleanup(func() {
		unpark()
		if stopStarted {
			select {
			case <-stopped:
			case <-time.After(10 * time.Second):
				t.Error("cluster stop did not finish")
			}
		}
		// New also owns a final Stop cleanup. Disarm the bounded observation
		// only after our first Stop has joined, before that cleanup repeats.
		c.beforeDependencyClose = nil
		select {
		case <-entered:
			select {
			case <-exited:
			case <-time.After(10 * time.Second):
				t.Error("actual detached cleanup did not exit")
			}
		default:
		}
	})
	owner := c.Nodes[0]
	seedVM(t, c, owner, &pb.VMSpec{Name: "delete-owned", Cpu: 1, MemoryMib: 256})
	if _, err := c.SelfClient(owner).DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "delete-owned"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("real detached origin never entered")
	}
	c.WaitConverged(t, convergeTimeout)
	closeAttempt := make(chan string, 3)
	c.beforeDependencyClose = func(n *Node) { closeAttempt <- n.Name }
	stopStarted = true
	go func() { defer close(stopped); c.Stop() }()
	select {
	case <-draining:
	case <-time.After(5 * time.Second):
		t.Fatal("actual Stop never entered DeleteVM drain")
	}
	early := false
	select {
	case <-stopped:
		early = true
	case <-time.After(200 * time.Millisecond):
	}
	if !early {
		select {
		case n := <-closeAttempt:
			t.Errorf("dependency close reached %s while origin held", n)
		default:
		}
		if _, err := owner.DB.Query(context.Background(), "SELECT 1"); err != nil {
			t.Errorf("owned origin's actual DB closed while held: %v", err)
		}
	} else {
		if _, err := owner.DB.Query(context.Background(), "SELECT 1"); err == nil {
			t.Error("fixture stop returned without closing the actual DB")
		}
	}
	unpark()
	select {
	case <-exited:
	case <-time.After(10 * time.Second):
		t.Fatal("actual cleanup did not return after release")
	}
	select {
	case <-stopped:
	case <-time.After(10 * time.Second):
		t.Fatal("stop did not join released cleanup")
	}
	if early {
		t.Fatal("Cluster.Stop closed actual DB while detached DeleteVM origin remained held")
	}
	t.Log("actual returned DeleteVM child exited before dependency close")
}
