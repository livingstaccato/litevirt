package grpcapi

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc"
)

func TestFirmwareAnnouncements_ReleaseLocalChildIsJoined(t *testing.T) {
	// Mutation: Release launches a detached local announcement without
	// enrolling it in the family drained before dependency cleanup.
	synctest.Test(t, func(t *testing.T) {
		f := newFwvFixture(t, fwmig.HoldVerified, libvirtfake.StatePaused, true)
		f.onResume(func() error {
			f.writeFile(f.store.NvramPath(fwtVM), fwvFinal)
			return nil
		})
		entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
		f.s.testDBWorkerEvent = func(ctx context.Context, worker, event string) {
			if worker != "gateway_local" {
				return
			}
			if event == "entry" {
				if ctx.Err() != nil {
					t.Error("Release announcement lost its detached context")
				}
				close(entered)
				<-release
			} else if event == "exit" {
				close(exited)
			}
		}
		if _, err := f.release(f.releaseReq()); err != nil {
			t.Fatal(err)
		}
		<-entered
		if f.domState() != libvirtfake.StateRunning {
			t.Error("announcement started before the released target was running")
		}
		joined := make(chan struct{})
		go func() { f.s.WaitGatewayAnnouncements(); close(joined) }()
		synctest.Wait()
		select {
		case <-joined:
			t.Error("gateway join returned while Release's detached local child could still read the DB")
		default:
		}
		close(release)
		<-exited
		<-joined
		synctest.Wait()
	})
}

func TestFirmwareAnnouncements_PausedHandoverTargetChildIsJoined(t *testing.T) {
	// The existing non-paused path is a positive control. The paused path
	// must announce only after resume succeeds and own that same child.
	for _, paused := range []bool{false, true} {
		name := "running"
		if paused {
			name = "paused"
		}
		t.Run(name, func(t *testing.T) {
			s := testServer(t)
			// Obtain the existing private peer credentials outside the bubble.
			// The interceptor below substitutes only successful remote RPCs;
			// migration finish, announcement launch, and join remain real.
			target := networkPeerFixture(t, s, migrationNetPeer{})
			synctest.Test(t, func(t *testing.T) {
				var resumed, delivered atomic.Bool
				s.SetPeerUnaryInterceptor(func(_ context.Context, method string, req, _ any, _ *grpc.ClientConn, _ grpc.UnaryInvoker, _ ...grpc.CallOption) error {
					if strings.HasSuffix(method, "/ArmNICFirewall") {
						if !req.(*pb.ArmNICFirewallRequest).GetResume() {
							t.Error("finish did not ask the target to resume")
						}
						resumed.Store(true)
					}
					if strings.HasSuffix(method, "/AnnounceMigratedGuest") {
						delivered.Store(true)
					}
					return nil
				})
				entered, release, exited := make(chan struct{}), make(chan struct{}), make(chan struct{})
				s.testDBWorkerEvent = func(_ context.Context, worker, event string) {
					if worker != "gateway_target" {
						return
					}
					if event == "entry" {
						if paused && !resumed.Load() {
							t.Error("paused handover announced before target resume succeeded")
						}
						close(entered)
						<-release
					} else if event == "exit" {
						close(exited)
					}
				}
				ctx, cancel := context.WithCancel(context.Background())
				cancel() // Finish owns the already-committed move after caller exit.
				err := s.finishMigrationOnTarget(ctx, &corrosion.VMRecord{Name: "guest", HostName: target.Name}, migrationFinish{
					target: target, armed: &armedMigration{s: s, target: *target, vm: "guest", paused: paused},
				})
				if err != nil {
					t.Fatal(err)
				}
				<-entered
				joined := make(chan struct{})
				go func() { s.WaitGatewayAnnouncements(); close(joined) }()
				synctest.Wait()
				select {
				case <-joined:
					t.Error("gateway join returned before the committed move's target announcement terminated")
				default:
				}
				close(release)
				<-exited
				<-joined
				synctest.Wait()
				if !delivered.Load() {
					t.Error("the canceled caller prevented the target announcement")
				}
			})
		})
	}
}
