package grpcapi

import (
	"context"
	"testing"
	"testing/synctest"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestFirmwareAnnouncementProducers_ReleaseBeforeLaunchHoldsJoin(t *testing.T) {
	// Bounded gRPC stop may return while this admitted Release remains in
	// libvirt. Joining only announcements already launched lets daemon cleanup
	// close its DB before Release returns and launches the local announcement.
	// Mutation: omit the Release parent from the announcement drain boundary.
	synctest.Test(t, func(t *testing.T) {
		f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
		resuming, release := make(chan struct{}), make(chan struct{})
		announced := make(chan struct{})
		f.onResume(func() error {
			close(resuming)
			<-release
			f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
			return nil
		})
		f.s.testDBWorkerEvent = func(_ context.Context, worker, event string) {
			if worker == "gateway_local" && event == "exit" {
				close(announced)
			}
		}
		returned := make(chan error, 1)
		go func() {
			_, err := f.release(f.releaseReq())
			returned <- err
		}()
		<-resuming
		joined := make(chan struct{})
		go func() { f.s.WaitGatewayAnnouncements(); close(joined) }()
		synctest.Wait()
		select {
		case <-joined:
			t.Error("announcement drain returned while an admitted Release could still launch its local child")
		default:
		}
		close(release)
		if err := <-returned; err != nil {
			t.Errorf("the admitted Release did not finish after resume was released: %v", err)
		}
		<-announced
		<-joined
		f.s.WaitGatewayAnnouncements()
		synctest.Wait()
		if f.domState() != libvirtfake.StateRunning {
			t.Error("the admitted Release failed to resume its guest")
		}
	})
}

func TestFirmwareAnnouncementProducers_AdoptedMigrationBeforeFinishHoldsJoin(t *testing.T) {
	// The client returns before libvirt: the real adopter owns its eventual
	// finish and remote Release. An RPC-only join cannot see this producer.
	// Mutation: release the migration's lifetime when its caller returns,
	// without retaining ownership through the adopter's final finish.
	synctest.Test(t, func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		ctx, cancel := context.WithCancel(adminCtx())
		defer cancel()
		proceed := make(chan struct{})
		adopted, adopterExit := make(chan struct{}), make(chan struct{})
		land := r.srcFake.OnMigrateToTarget
		r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
			cancel()
			<-proceed
			return land(name, uri, p)
		}
		r.src.testDBWorkerEvent = func(_ context.Context, worker, event string) {
			if worker != "migration_adopter" {
				return
			}
			if event == "entry" {
				close(adopted)
			} else if event == "exit" {
				close(adopterExit)
			}
		}
		err := r.src.MigrateVM(&pb.MigrateVMRequest{
			VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
		}, &mockMigrateStream{ctx: ctx})
		if status.Code(err) != codes.DeadlineExceeded {
			close(proceed)
			t.Fatalf("migration did not transfer to its adopter: %v", err)
		}
		<-adopted
		joined := make(chan struct{})
		go func() { r.src.WaitGatewayAnnouncements(); close(joined) }()
		synctest.Wait()
		select {
		case <-joined:
			t.Error("announcement drain returned while the retained migration adopter could still finish and release its target")
		default:
		}
		close(proceed)
		<-adopterExit
		<-joined
		r.src.WaitGatewayAnnouncements()
		r.dst.WaitGatewayAnnouncements()
		synctest.Wait()
		if vm := r.row(); vm.HostName != "dst-host" {
			t.Errorf("the canceled caller's adopted move did not finish on its target: %s", vm.HostName)
		}
		if state, _ := r.dstFake.RawState(fwlVM); state != libvirtfake.StateRunning {
			t.Errorf("the adopted move did not release its target: %s", state)
		}
	})
}
