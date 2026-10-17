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

func TestFirewallTagWork_ShutdownJoinsCommittedCompletion(t *testing.T) {
	s := copiedPair(t)
	ctx, cancel := context.WithCancel(adminCtx())
	defer cancel()
	entered, release := make(chan struct{}), make(chan struct{})
	s.testFirewallTagsBeforeMint = func() { close(entered); <-release }
	result := make(chan error, 1)
	go func() {
		_, err := s.SetFirewallTags(ctx, &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"role": "web"}})
		result <- err
	}()
	<-entered
	cancel()
	s.StopFirewallTagAdmission()
	joined := make(chan struct{})
	go func() { s.WaitFirewallTagWork(); close(joined) }()
	select {
	case <-joined:
		t.Error("joined while post-clear completion was held")
	case <-time.After(50 * time.Millisecond):
	}
	if _, err := s.SetFirewallTags(adminCtx(), &pb.SetFirewallTagsRequest{Kind: "vm", Workload: "web", Set: map[string]string{"late": "write"}}); status.Code(err) != codes.Unavailable {
		t.Errorf("late admission %v", err)
	}
	close(release)
	if err := <-result; err != nil {
		t.Fatal("admitted detached completion failed", err)
	}
	<-joined
	if id := vmFWID(t, s, "web"); id == fwA {
		t.Fatal("real admitted mint never completed")
	}
	wantAudit(t, s, "firewall.tag.rm", "admin", "web", "fw_id="+fwA+" copied_identity_cleared before={role=db} after=none")
}
func TestFirewallTagWork_ShutdownJoinsDeleteHygiene(t *testing.T) {
	s, _ := tagsServer(t)
	markTagsUsed(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	s.SetClearFirewallTagsForTest(func(context.Context, string, string) error { close(entered); <-release; return nil })
	done := make(chan struct{})
	go func() {
		s.clearDeletedFirewallTags(context.Background(), corrosion.TagMemberVM, "", "gone", fwA)
		close(done)
	}()
	<-entered
	s.StopFirewallTagAdmission()
	joined := make(chan struct{})
	go func() { s.WaitFirewallTagWork(); close(joined) }()
	select {
	case <-joined:
		t.Error("joined while real delete-clear call was held")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
	<-joined
	s.clearDeletedFirewallTags(context.Background(), corrosion.TagMemberVM, "", "late", fwB) // must leave to orphan sweep, without another clear call
}
func TestFirewallTagWork_AdmissionAndStopAreAtomic(t *testing.T) {
	s := &Server{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			done, ok := s.beginFirewallTagWork()
			if ok {
				done()
			}
		}()
	}
	close(start)
	s.StopFirewallTagAdmission()
	s.WaitFirewallTagWork()
	wg.Wait()
	if done, ok := s.beginFirewallTagWork(); ok {
		done()
		t.Fatal("admission reopened after wait")
	}
}
