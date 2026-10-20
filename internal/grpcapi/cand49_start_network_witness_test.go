package grpcapi

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// Replacing startDomainWithin's answerLibvirtCall callback with raw
// virt.StartDomain lets the real transition writer enter while libvirt is
// blocked. Losing the deferred answer or transition release strands Goexit.
func TestStartVM_AHeldAnswerKeepsTheNetworkTransitionUntilLibvirtEnds(t *testing.T) {
	for _, tc := range []struct {
		name       string
		unanswered bool
		wantState  string
	}{
		{name: "late success", wantState: "running"},
		{name: "Goexit", unanswered: true, wantState: "stopped"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st := newStuckStart(t)
			entered := make(chan struct{}, 1)
			var once sync.Once
			unblock := func() { once.Do(func() { close(st.release) }) }
			t.Cleanup(func() {
				unblock()
				st.waitLockFree(t, "cleanup after libvirt ends")
			})
			st.s.virt.(*libvirtfake.Fake).FailStartDomain = func(string) error {
				st.calls.Add(1)
				select {
				case entered <- struct{}{}:
				default:
				}
				<-st.release
				if tc.unanswered {
					runtime.Goexit()
				}
				return nil
			}
			err := within(t, 5*time.Second, "held start", func() error {
				_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
				return err
			})
			wantStartInFlight(t, "held start", err)
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("libvirt start did not enter")
			}
			flight, ok := st.s.startFlightOf("web")
			if !ok || !flight.heldUnanswered() {
				t.Fatal("blocked libvirt start has no held flight")
			}
			if unlock, ok := st.s.tryLockVM("web"); ok {
				unlock()
				t.Fatal("held start released the VM lock")
			}
			if vm := st.row(t); vm.State != "starting" {
				t.Fatalf("held row = %s, want starting", vm.State)
			}
			if n := st.openReservations(t); n != 1 {
				t.Fatalf("held capacity reservations = %d, want 1", n)
			}

			// This is the actual exclusive permit used by a network move,
			// synchronously attempted after libvirt entered and before release.
			// Its context must expire while the runtime owns the read permit.
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			release, err := st.s.netDevs.acquireTransition(ctx, true)
			cancel()
			if release != nil {
				release()
				t.Fatal("network transition entered while libvirt start was blocked")
			}
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("contending transition = %v, want DeadlineExceeded", err)
			}
			err = within(t, 5*time.Second, "second held start", func() error {
				_, err := st.s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "web"})
				return err
			})
			wantStartInFlight(t, "second start", err)
			if n := st.calls.Load(); n != 1 {
				t.Fatalf("native start attempts = %d, want 1", n)
			}

			unblock()
			select {
			case <-flight.settled:
			case <-time.After(5 * time.Second):
				t.Fatal("libvirt answer did not settle its flight")
			}
			st.waitLockFree(t, "after libvirt ended")
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			release, err = st.s.netDevs.acquireTransition(ctx, true)
			if err != nil {
				t.Fatalf("network transition after libvirt ended: %v", err)
			}
			release()
			if vm := st.row(t); vm.State != tc.wantState || (tc.unanswered && vm.StateDetail != "operator-stop") {
				t.Fatalf("settled row = %s/%s, want %s", vm.State, vm.StateDetail, tc.wantState)
			}
			if _, ok := st.s.startFlightOf("web"); ok {
				t.Error("settled flight remains registered")
			}
			if n := st.openReservations(t); n != 0 {
				t.Errorf("settled capacity reservations = %d, want 0", n)
			}
			if n := st.calls.Load(); n != 1 {
				t.Errorf("settled native start attempts = %d, want 1", n)
			}
			if tc.unanswered {
				found := false
				for _, ev := range vmEventsOf(t, st.s, "web", "vm.started") {
					if ev.Result == "error" && strings.Contains(ev.Detail, errLibvirtCallUnanswered.Error()) {
						found = true
					}
				}
				if !found {
					t.Error("Goexit settled without the unanswered-start failure event")
				}
			}
		})
	}
}
