// Fleet scenarios for a start of a VM while a move of it is under way, or
// after one left its row `migrating`: the start never makes a second copy.
package fleet

import (
	"context"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// countOp is how many of log's events are op on domain.
func countOp(log []libvirtfake.Event, op, domain string) int {
	n := 0
	for _, e := range log {
		if e.Op == op && e.Domain == domain {
			n++
		}
	}
	return n
}

// `lv start` of a VM asked on its source while a cold move of it runs. In the
// copy (before the handoff) the start waits for the move on the VM's lock
// and is then refused, the VM being the target's. Between the handoff and
// the source's cleanup the row already names the target, so the start goes
// there. Either way the source's domain is never started and is gone at the
// end, and the guest runs on one host at most.
//
// Mutation: StartVM without the VM's lock — the start runs mid-move and the
// move fails on the active source domain, red.
func TestFleet_AStartDuringAColdMoveWaitsForItAndMakesNoSecondCopy(t *testing.T) {
	for _, window := range []string{"copy", "handoff"} {
		t.Run(window, func(t *testing.T) {
			sc := newColdStoppedScenario(t)
			startErr := make(chan error, 1)
			var once sync.Once
			midMove := func() {
				once.Do(func() {
					go func() {
						_, err := sc.c.SelfClient(sc.src).StartVM(context.Background(), &pb.StartVMRequest{Name: "os1"})
						startErr <- err
					}()
					// The start is given time to act before the move goes on.
					select {
					case err := <-startErr:
						startErr <- err
					case <-time.After(time.Second):
					}
				})
			}
			if window == "copy" {
				sc.dst.Virt.FailDefineDomain = func(string) error { midMove(); return nil }
			} else {
				sc.src.Server.SetColdMoveAfterHandoffForTest(func(string) { midMove() })
			}
			if err := sc.migrateCold(t); err != nil {
				t.Fatalf("migrate --cold with a start asked mid-move: %v", err)
			}
			var err error
			select {
			case err = <-startErr:
			case <-time.After(15 * time.Second):
				t.Fatal("the start asked mid-move never ended")
			}
			wantState := "running" // the start went to the target, which owns os1
			if window == "copy" {
				if status.Code(err) != codes.Aborted {
					t.Fatalf("start asked in the copy = %v; want Aborted, the VM having moved", err)
				}
				wantState = "stopped"
			} else if err != nil {
				t.Fatalf("start asked after the handoff = %v; want it started on the target", err)
			}
			if vm := sc.vm(t); vm.HostName != sc.dst.Name || vm.State != wantState {
				t.Fatalf("os1 = %s on %s; want %s on %s", vm.State, vm.HostName, wantState, sc.dst.Name)
			}
			if sc.src.Virt.DomainExists("os1") {
				t.Errorf("os1 is still defined on the source")
			}
			if countOp(sc.src.Virt.EventLog(), "start", "os1") != 0 {
				t.Errorf("os1 was started on the source")
			}
		})
	}
}
