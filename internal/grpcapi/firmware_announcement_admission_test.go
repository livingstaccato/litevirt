package grpcapi

import (
	"context"
	"testing"
	"testing/synctest"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
)

func TestFirmwareAnnouncementAdmission_Closed(t *testing.T) {
	t.Run("MigrateVM", func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		r.src.WaitGatewayAnnouncements()
		err := r.src.MigrateVM(&pb.MigrateVMRequest{
			VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
		}, &mockMigrateStream{ctx: adminCtx()})
		if status.Code(err) != codes.Unavailable {
			t.Errorf("migration admitted after announcement drain closed: %v", err)
		}
		if vm := r.row(); vm.HostName != "src-host" || vm.State != "running" {
			t.Errorf("closed migration admission changed its VM: %+v", vm)
		}
		r.src.WaitGatewayAnnouncements()
		r.dst.WaitGatewayAnnouncements()
	})
	t.Run("drainOneVM", func(t *testing.T) {
		s, _, _ := abortTestServer(t, "closed-drain")
		s.pkiDir = t.TempDir()
		s.WaitGatewayAnnouncements()
		p := s.drainOneVM(adminCtx(), corrosion.VMRecord{Name: "closed-drain"}, corrosion.HostRecord{Name: "target-host", State: "active"})
		if p.Status != "skipped" || p.Error != "server is shutting down" {
			t.Errorf("host drain admitted after announcement drain closed: %+v", p)
		}
		vm, err := corrosion.GetVM(context.Background(), s.db, "closed-drain")
		if err != nil || vm == nil || vm.HostName != "test-host" || vm.State != "running" {
			t.Errorf("closed host-drain admission changed its VM: %+v, %v", vm, err)
		}
		s.WaitGatewayAnnouncements()
	})
	t.Run("ReleaseLiveFirmwareTarget", func(t *testing.T) {
		f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
		f.s.WaitGatewayAnnouncements()
		_, err := f.release(f.releaseReq())
		if status.Code(err) != codes.Unavailable {
			t.Errorf("Release admitted after announcement drain closed: %v", err)
		}
		if state := f.domState(); state != libvirtfake.StatePaused {
			t.Errorf("closed Release admission resumed its guest: %s", state)
		}
		f.s.WaitGatewayAnnouncements()
	})
}

func TestFirmwareAnnouncementAdmission_DrainBeforeAdoption(t *testing.T) {
	// Closing admission while the request is still live must allow its later
	// transfer to the adopter, without a zero-count interval or a new admission.
	synctest.Test(t, func(t *testing.T) {
		r := newFwlRig(t, fwlOpts{})
		ctx, cancel := context.WithCancel(adminCtx())
		defer cancel()
		moving, proceed := make(chan struct{}), make(chan struct{})
		adopted := make(chan struct{})
		land := r.srcFake.OnMigrateToTarget
		r.srcFake.OnMigrateToTarget = func(name, uri string, p lv.MigrateParams) error {
			close(moving)
			<-proceed
			return land(name, uri, p)
		}
		r.src.testDBWorkerEvent = func(_ context.Context, worker, event string) {
			if worker == "migration_adopter" && event == "entry" {
				close(adopted)
			}
		}
		returned := make(chan error, 1)
		go func() {
			returned <- r.src.MigrateVM(&pb.MigrateVMRequest{
				VmName: fwlVM, TargetHost: "dst-host", Strategy: pb.MigrateStrategy_MIGRATE_LIVE,
			}, &mockMigrateStream{ctx: ctx})
		}()
		<-moving
		joined := make(chan struct{})
		go func() { r.src.WaitGatewayAnnouncements(); close(joined) }()
		synctest.Wait()
		select {
		case <-joined:
			t.Error("announcement drain returned while the migration parent was still in libvirt")
		default:
		}
		cancel()
		if err := <-returned; status.Code(err) != codes.DeadlineExceeded {
			close(proceed)
			t.Fatalf("migration did not retain its adopter after admission closed: %v", err)
		}
		<-adopted
		synctest.Wait()
		select {
		case <-joined:
			t.Error("announcement drain lost ownership when the admitted parent transferred to its adopter")
		default:
		}
		close(proceed)
		<-joined
		r.src.WaitGatewayAnnouncements()
		r.dst.WaitGatewayAnnouncements()
		if vm := r.row(); vm.HostName != "dst-host" {
			t.Errorf("adopter retained after closure failed to commit: %+v", vm)
		}
		if state, _ := r.dstFake.RawState(fwlVM); state != libvirtfake.StateRunning {
			t.Errorf("adopter retained after closure failed to release its target: %s", state)
		}
	})
}

type announcementDrainLeasePeer struct {
	*fakeDestPeer
	releasing chan struct{}
	proceed   chan struct{}
}

func (p *announcementDrainLeasePeer) ReleaseHostCapacity(ctx context.Context, req *pb.ReleaseHostCapacityRequest, opts ...grpc.CallOption) (*emptypb.Empty, error) {
	close(p.releasing)
	<-p.proceed
	return p.fakeDestPeer.ReleaseHostCapacity(ctx, req, opts...)
}

func TestFirmwareAnnouncementAdmission_DirectDrainHoldsJoinThroughLeaseRelease(t *testing.T) {
	// The shared-storage host-drain path calls finish directly, bypassing
	// migrateOwnedVM. Its deferred destination lease release still uses peers.
	synctest.Test(t, func(t *testing.T) {
		s := testServer(t)
		s.pkiDir = t.TempDir()
		peer := &announcementDrainLeasePeer{
			fakeDestPeer: &fakeDestPeer{leaseID: "drain-lease"},
			releasing:    make(chan struct{}), proceed: make(chan struct{}),
		}
		s.peerClientOverride = func(context.Context, string) (pb.LiteVirtClient, func(), error) {
			return peer, func() {}, nil
		}
		virt := libvirtfake.New()
		s.virt = virt
		virt.SetState("mover", "running")
		if err := corrosion.InsertVM(context.Background(), s.db, corrosion.VMRecord{
			Name: "mover", HostName: "test-host", State: "running", CPUActual: 2, MemActual: 2048,
			Project: "proj", Spec: `{"name":"mover","cpu":2,"memory_mib":2048}`,
		}, nil, nil); err != nil {
			t.Fatal(err)
		}
		moving, proceed := make(chan struct{}), make(chan struct{})
		virt.OnMigrateToTarget = func(string, string, lv.MigrateParams) error {
			close(moving)
			<-proceed
			return nil
		}
		returned := make(chan *pb.DrainProgress, 1)
		go func() {
			returned <- s.drainOneVM(context.Background(), corrosion.VMRecord{Name: "mover"}, corrosion.HostRecord{
				Name: "drain-dst", Address: "10.0.0.77", State: "active",
			})
		}()
		<-moving
		joined := make(chan struct{})
		go func() { s.WaitGatewayAnnouncements(); close(joined) }()
		synctest.Wait()
		select {
		case <-joined:
			t.Error("announcement drain returned before direct host drain could finish its move")
		default:
		}
		close(proceed)
		<-peer.releasing
		synctest.Wait()
		select {
		case <-joined:
			t.Error("announcement drain returned before direct host drain released its destination lease")
		default:
		}
		close(peer.proceed)
		if p := <-returned; p.Status != "done" {
			t.Errorf("admitted direct host drain failed: %+v", p)
		}
		<-joined
		vm, err := corrosion.GetVM(context.Background(), s.db, "mover")
		if err != nil || vm == nil || vm.HostName != "drain-dst" || vm.State != "running" {
			t.Errorf("admitted direct host drain did not commit: %+v, %v", vm, err)
		}
		if released := peer.released(); len(released) != 1 {
			t.Errorf("direct host drain did not release exactly one destination lease: %v", released)
		}
	})
}
