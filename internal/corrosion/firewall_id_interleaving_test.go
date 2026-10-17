package corrosion

import (
	"context"
	"errors"
	"testing"
)

// The target and its real binding proof arrive after the move precheck, before
// the holder query. No client answer or database result is substituted.
func TestMintFirewallID_MoveAppearingBeforeHolderQueryIsRefused(t *testing.T) {
	f := newTagGroupFixture(t)
	ctx := context.Background()
	f.c.SetRepointReady(func(context.Context) bool { return true })
	f.moveCT("node-1", "mig", tgID(1), "stopped", "operator-stop", "")
	f.tags(TagMemberCT, tgID(1), `{"tags":{"role":"web"},"name":"mig","host":"node-1"}`)
	source := storedCreateSpec(t, f.c, "node-1", "mig")
	called := false
	f.c.firewallIDAfterMoveCheck = func() {
		called = true
		f.c.firewallIDAfterMoveCheck = nil
		f.moveCT("node-2", "mig", tgID(1), "running", "", "tok-new")
		f.relocationProof("p-new", "mig", "node-2", "node-1", "tok-new", ProofInProgress, false)
	}
	id, abandoned, err := MintFirewallID(ctx, f.c, mintGrant(t), TagMemberCT, "node-1", "mig")
	if !called {
		t.Fatal("real move interleaving was not reached")
	}
	if !errors.Is(err, ErrFirewallIDMoveOpen) || id != "" || abandoned != "" {
		t.Errorf("move appeared before holder query: (%q,%q,%v), want refused without abandonment", id, abandoned, err)
	}
	if got := storedCreateSpec(t, f.c, "node-1", "mig"); got != source {
		t.Errorf("move source spec changed: %q -> %q", source, got)
	}
	if got := firewallIDOf(TagMemberCT, storedCreateSpec(t, f.c, "node-2", "mig")); got != tgID(1) {
		t.Errorf("real target identity changed: %q", got)
	}
}
