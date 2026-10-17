package firewall

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestApplier_FailedBridgeRefreshKeepsGuestVRRPDrop(t *testing.T) {
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			f := &fakeNft{}
			a := NewApplier(f)
			p := sgPlan(mode, true)
			if _, err := a.Apply(ctx, p); err != nil {
				t.Fatal(err)
			}
			oldNIC := a.lastNIC
			p.NICs[0].NICDev = "vnet-changed"
			p.DefaultDeny = !p.DefaultDeny // require a real inet replacement even in observe mode
			f.failNext = errors.New("injected atomic bridge replacement refusal")
			if _, err := a.Apply(ctx, p); !errors.Is(err, ErrNICTableRefused) {
				t.Fatalf("bridge failure: %v", err)
			}
			if a.lastNIC != oldNIC {
				t.Fatal("failed atomic replacement forgot still-installed bridge table")
			}
			inet := f.applies[len(f.applies)-1]
			drop := fmt.Sprintf("meta mark & %#x == %#x meta l4proto 112 drop", guestVRRPMark, guestVRRPMark)
			if !strings.Contains(inet, drop) {
				t.Error("failed bridge refresh removed protection from the still-marking table")
			}
			if strings.Contains(inet, fmt.Sprintf("meta mark & %#x == %#x accept", judgedMark, judgedMark)) {
				t.Error("failed refresh trusted obsolete positive allow marks")
			}
			if _, err := a.Apply(ctx, p); err != nil {
				t.Fatal(err)
			}
			if a.lastNIC == oldNIC || !strings.Contains(a.lastInet, drop) {
				t.Fatal("successful retry did not restore current bridge and guest drop")
			}
			if _, err := a.Apply(ctx, Plan{}); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(a.lastInet, "guest_vrrp") {
				t.Fatal("no-NIC plan retained guest drop after removal")
			}
		})
	}
}

// Both callers invalidate knowledge without deleting the installed bridge table.
func TestApplier_UnknownPriorBridgeKeepsGuestVRRPDrop(t *testing.T) {
	for _, path := range []string{"forced-reload", "new-daemon"} {
		for _, mode := range []string{NICModeEnforce, NICModeObserve, NICModeGuardsOnly} {
			t.Run(path+"/"+mode, func(t *testing.T) {
				ctx := context.Background()
				f := &fakeNft{}
				a := NewApplier(f)
				if _, err := a.Apply(ctx, sgPlan(NICModeEnforce, true)); err != nil {
					t.Fatal(err)
				}
				p := sgPlan(mode, true)
				p.DefaultDeny = !p.DefaultDeny
				f.failNext = errors.New("injected atomic bridge replacement refusal")
				var err error
				if path == "forced-reload" {
					r := NewReconciler(func(context.Context) (Plan, error) { return p, nil }, a, time.Hour)
					err = r.ReconcileForce(ctx)
				} else {
					a = NewApplier(f)
					_, err = a.Apply(ctx, p)
				}
				if !errors.Is(err, ErrNICTableRefused) {
					t.Fatalf("bridge failure: %v", err)
				}
				inet := f.applies[len(f.applies)-1]
				drop := fmt.Sprintf("meta mark & %#x == %#x meta l4proto 112 drop", guestVRRPMark, guestVRRPMark)
				if !strings.Contains(inet, drop) {
					t.Error("unknown prior bridge state removed drop for still-installed marking table")
				}
				if strings.Contains(inet, fmt.Sprintf("meta mark & %#x == %#x accept", judgedMark, judgedMark)) {
					t.Error("unknown prior bridge trusted positive allow marks")
				}
				if _, err := a.Apply(ctx, p); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(a.lastInet, drop) != (mode != NICModeGuardsOnly) {
					t.Fatal("successful replacement did not apply the intended guest-drop policy")
				}
			})
		}
	}
}
