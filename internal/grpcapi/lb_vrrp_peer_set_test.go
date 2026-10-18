package grpcapi

import (
	"context"
	"testing"
)

func TestVRRPRefusal_PeerSetChangeDiscardsCachedServing(t *testing.T) {
	f := newRefusalFixture(t)
	ctx := context.Background()
	if _, err := peerApply(t, f.s, []string{"self", "peer-1"}); err != nil {
		t.Fatal(err)
	}
	f.serving = true
	f.s.checkVRRPServing(ctx)
	if !f.s.vrrpPeerServing("lbr-lb") {
		t.Fatal("seed did not retain actual answer")
	}
	// Order, duplication, and this host do not change the questioned peer set.
	if _, err := peerApply(t, f.s, []string{"peer-1", "self", "peer-1"}); err == nil || len(f.stopped) != 1 {
		t.Fatal("equivalent peer set lost known serving", err, f.stopped)
	}
	f.serving = false
	applied, err := peerApply(t, f.s, []string{"self", "peer-2"})
	if err != nil || len(applied) != 1 || applied[0].VRRPUnicast || len(f.stopped) != 1 {
		t.Errorf("removed peer's cached answer demoted the new set: err=%v applied=%+v stopped=%v", err, applied, f.stopped)
	}
	if f.s.vrrpPeerServing("lbr-lb") {
		t.Error("old peer set still owns serving evidence")
	}
	f.serving = true
	f.s.checkVRRPServing(ctx)
	if _, err := peerApply(t, f.s, []string{"self", "peer-2"}); err == nil || len(f.stopped) != 2 {
		t.Error("fresh answer for new set did not regain serving", err, f.stopped)
	}
}

func TestVRRPRefusal_PeerSetChangeDiscardsInflightServing(t *testing.T) {
	f := newRefusalFixture(t)
	ctx := context.Background()
	if _, err := peerApply(t, f.s, []string{"self", "peer-1"}); err != nil {
		t.Fatal(err)
	}
	changed := false
	f.s.lbServingOverride = func(_ context.Context, host, name string) bool {
		if host != "peer-1" || name != "lbr-lb" {
			t.Errorf("unexpected real ask %s/%s", host, name)
			return false
		}
		// The actual ask has snapshotted the old epoch/set and has not delivered
		// its answer. Keep the refusal continuous while the public apply changes it.
		applied, err := peerApply(t, f.s, []string{"self", "peer-2"})
		if err != nil || len(applied) != 1 || applied[0].VRRPUnicast {
			t.Errorf("new set did not start with multicast fallback: %v %+v", err, applied)
		}
		changed = true
		return true
	}
	f.s.checkVRRPServing(ctx)
	if !changed {
		t.Fatal("actual old-set ask never entered")
	}
	if f.s.vrrpPeerServing("lbr-lb") {
		t.Error("late old-set serving answer entered current refusal")
	}
	applied, err := peerApply(t, f.s, []string{"self", "peer-2"})
	if err != nil || len(applied) != 1 || applied[0].VRRPUnicast || len(f.stopped) != 0 {
		t.Errorf("late old-set answer demoted new-set fallback: %v %+v %v", err, applied, f.stopped)
	}
}
