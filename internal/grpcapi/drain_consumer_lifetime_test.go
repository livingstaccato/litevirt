package grpcapi

import (
	"context"
	"errors"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// Send fails only after a real queued drainOneVM has returned its outcome.
// The embedded stream supplies the existing generated-server stream methods.
type drainConsumerDisconnectStream struct {
	mockDrainStreamR2
	cancel  context.CancelFunc
	failure error
}

func (s *drainConsumerDisconnectStream) Send(p *pb.DrainProgress) error {
	s.sent = append(s.sent, p)
	s.cancel()
	return s.failure
}

func TestDrainHostDisconnectedConsumerHoldsShutdown(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		s := testServerR2(t)
		ctx := adminCtx()
		insertTestHostR2(t, ctx, s.db, "test-host", "active")
		if err := corrosion.InsertHost(ctx, s.db, corrosion.HostRecord{
			Name: "drain-dst", Address: "10.0.0.2", SSHUser: "root",
			SSHPort: 22, GRPCPort: 7443, State: "active", CPUTotal: 32, MemTotal: 65536,
		}); err != nil {
			t.Fatal(err)
		}
		// Same real placement/cold-refusal fixture as the existing stopped-VM
		// DrainHost test. No libvirt move or peer service is needed to owe the
		// disconnect consumer's final audit after an actual worker outcome.
		insertTestVMR2WithStack(t, ctx, s.db, "drain-consumer-vm", "test-host", "stopped", "")
		held, release, audited := make(chan struct{}), make(chan struct{}), make(chan struct{})
		var releaseOnce sync.Once
		unblock := func() { releaseOnce.Do(func() { close(release) }) }
		defer func() { unblock(); s.FinishDrainRecords(time.Second) }()
		s.testDBWorkerEvent = func(_ context.Context, worker, event string) {
			if worker != "drain_result_consumer" {
				return
			}
			switch event {
			case "before_audit":
				close(held)
				<-release
			case "after_audit":
				close(audited)
			}
		}
		rpcCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		disconnected := errors.New("drain consumer test: client disconnected")
		stream := &drainConsumerDisconnectStream{
			mockDrainStreamR2: mockDrainStreamR2{ctx: rpcCtx}, cancel: cancel, failure: disconnected,
		}
		// Synchronous return proves the admitted RPC parent has retired. One
		// job, one consumed result: its drainOneVM defer has also retired, and
		// this failure outcome launches neither an adopter nor a record job.
		err := s.DrainHost(&pb.DrainHostRequest{Name: "test-host", Parallel: 1}, stream)
		if !errors.Is(err, disconnected) {
			t.Fatalf("did not reach result-send disconnect: %v", err)
		}
		if len(stream.sent) != 1 || stream.sent[0].VmName != "drain-consumer-vm" ||
			stream.sent[0].TargetHost != "drain-dst" || stream.sent[0].Status != "failed" ||
			stream.sent[0].Strategy != pb.MigrateStrategy_MIGRATE_COLD {
			t.Fatalf("fixture did not complete the actual queued cold worker: %+v", stream.sent)
		}
		synctest.Wait()
		select {
		case <-held:
		default:
			t.Fatal("disconnected result consumer never reached its final audit")
		}
		finalAuditCount := func() int64 {
			t.Helper()
			rows, err := s.db.Query(ctx, `SELECT COUNT(*) AS n FROM audit_log WHERE action='host.drain' AND target='test-host' AND result='cancelled'`)
			if err != nil || len(rows) != 1 {
				t.Fatalf("read actual final audit: rows=%v err=%v", rows, err)
			}
			return rows[0].Int64("n")
		}
		if n := finalAuditCount(); n != 0 {
			t.Fatalf("final audit ran before its hold: %d", n)
		}
		joined := make(chan struct{})
		go func() { s.WaitGatewayAnnouncements(); close(joined) }()
		// Uses the real daemon migration/announcement shutdown join. All other
		// producers have ended; synctest supplies scheduling, not a sleep.
		synctest.Wait()
		select {
		case <-joined:
			t.Error("shutdown wait returned while disconnected drain consumer still owed final audit")
		default:
		}
		if n := finalAuditCount(); n != 0 {
			t.Fatalf("held audit unexpectedly appeared: %d", n)
		}
		unblock()
		synctest.Wait()
		select {
		case <-audited:
		default:
			t.Fatal("released consumer did not finish its actual audit call")
		}
		select {
		case <-joined:
		default:
			t.Fatal("shutdown join did not finish after the consumer completed")
		}
		if n := finalAuditCount(); n != 1 {
			t.Fatalf("consumer final audit count = %d, want 1", n)
		}
		vm, err := corrosion.GetVM(ctx, s.db, "drain-consumer-vm")
		if err != nil || vm == nil || vm.HostName != "test-host" || vm.State != "stopped" {
			t.Fatalf("cold-refusal control changed the VM: %+v, %v", vm, err)
		}
	})
}
