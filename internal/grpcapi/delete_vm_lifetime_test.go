package grpcapi

import (
	"context"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"sync"
	"testing"
	"time"
)

func TestDeleteVMWork_StoppedAdmissionRetainsOnlyOwnedChildren(t *testing.T) {
	s := &Server{}
	p, ok := s.deleteWork.begin()
	if !ok {
		t.Fatal("initial admission refused")
	}
	s.StopDeleteVMAdmission()
	entered, joined := make(chan struct{}), make(chan struct{})
	s.testDBWorkerEvent = func(_ context.Context, worker, event string) {
		if worker == "delete_vm" && event == "drain" {
			close(entered)
		}
	}
	go func() { s.WaitDeleteVMWork(); close(joined) }()
	<-entered
	done, ok := p.retainChild()
	if !ok {
		t.Fatal("admitted parent could not retain during shutdown")
	}
	p.finish()
	if late, ok := p.retainChild(); ok {
		late()
		t.Error("finished parent retained another child")
	}
	select {
	case <-joined:
		t.Error("drain returned while retained child owned")
	case <-time.After(50 * time.Millisecond):
	}
	done()
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("drain failed to finish")
	}
	if late, ok := p.retainChild(); ok {
		late()
		t.Error("drained parent reopened ownership")
	}
	if late, ok := s.deleteWork.begin(); ok {
		late.finish()
		t.Fatal("stopped admission reopened after drain")
	}
	// No DB exists: refusal must precede even the wrapper's first lookup.
	if _, err := s.DeleteVM(context.Background(), &pb.DeleteVMRequest{Name: "late"}); status.Code(err) != codes.Unavailable {
		t.Fatalf("late public call: %v", err)
	}
}

func TestDeleteVMWork_AdmissionAndStopAreAtomic(t *testing.T) {
	s := &Server{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if p, ok := s.deleteWork.begin(); ok {
				child, ok := p.retainChild()
				if !ok {
					t.Error("active parent lost retention")
				} else {
					child()
				}
				p.finish()
			}
		}()
	}
	close(start)
	s.StopDeleteVMAdmission()
	s.WaitDeleteVMWork()
	wg.Wait()
	if p, ok := s.deleteWork.begin(); ok {
		p.finish()
		t.Fatal("admission reopened after drain")
	}
}

func TestDeleteVMWork_JoinsWholePublicWrapperAfterInnerDelete(t *testing.T) {
	s, _ := deleteSeededVM(t, true)
	entered, release, draining, joined := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var once, drainOnce sync.Once
	unpark := func() { once.Do(func() { close(release) }) }
	returned := make(chan struct{})
	t.Cleanup(func() {
		unpark()
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
			t.Error("actual public wrapper failed to join during cleanup")
			return
		}
		s.StopDeleteVMAdmission()
		s.StopFirewallTagAdmission()
		done := make(chan struct{})
		go func() { s.WaitDeleteVMWork(); s.WaitFirewallTagWork(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("ownership drains failed to join during cleanup")
		}
	})
	s.testClearFirewallTags = func(context.Context, string, string) error { close(entered); <-release; return nil }
	s.testDBWorkerEvent = func(_ context.Context, worker, event string) {
		if worker == "delete_vm" && event == "drain" {
			drainOnce.Do(func() { close(draining) })
		}
	}
	result := make(chan error, 1)
	go func() {
		defer close(returned)
		_, err := s.DeleteVM(adminCtx(), &pb.DeleteVMRequest{Name: "vm1", Force: true})
		result <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("public wrapper never reached real post-delete tag completion")
	}
	if vm, err := corrosion.GetVM(context.Background(), s.db, "vm1"); err != nil || vm != nil {
		t.Fatalf("inner delete has not committed: vm=%v err=%v", vm, err)
	}
	s.StopDeleteVMAdmission()
	s.StopFirewallTagAdmission()
	go func() { s.WaitDeleteVMWork(); close(joined) }()
	<-draining
	select {
	case <-joined:
		t.Error("parent released at inner return, before wrapper completion")
	case <-time.After(50 * time.Millisecond):
	}
	unpark()
	select {
	case err := <-result:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("public wrapper did not finish")
	}
	select {
	case <-joined:
	case <-time.After(time.Second):
		t.Fatal("whole wrapper ownership did not finish")
	}
	s.WaitFirewallTagWork()
}
