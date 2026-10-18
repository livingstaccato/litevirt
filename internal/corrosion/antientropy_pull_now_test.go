package corrosion

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The currency pull's candidates (re-review 1, m-1): the target is never
// asked; with nobody else to ask it proceeds, but a skipped voter is named and
// refuses.
func TestPullTableNow_Candidates(t *testing.T) {
	ctx := context.Background()
	c := newTestDB(t)
	for _, h := range []string{c.hostName, "target", "voter-x"} {
		if err := InsertHost(ctx, c, HostRecord{Name: h, Address: "10.0.0.1", State: "active", CertSerial: "s-" + h}); err != nil {
			t.Fatal(err)
		}
	}
	ae := NewAntiEntropy(c, "", 0)

	// Only the target besides this node: nobody to confirm with, proceed.
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "target"}} })
	if peer, _, err := ae.PullTableNow(ctx, "hosts", "target"); err != nil || peer != "" {
		t.Fatalf("alone with the target: (%q, %v), want to proceed", peer, err)
	}

	// Another voter, isolated: refused, and named.
	if _, err := c.DB().Exec(`UPDATE hosts SET isolation_epoch = 3, isolation_reason = 'manual' WHERE name = 'voter-x'`); err != nil {
		t.Fatal(err)
	}
	c.SetMembersForTests(func() []PeerInfo { return []PeerInfo{{Name: "target"}, {Name: "voter-x"}} })
	_, skipped, err := ae.PullTableNow(ctx, "hosts", "target")
	if !errors.Is(err, ErrNoPeerConfirmed) || !strings.Contains(err.Error(), "voter-x (isolated)") {
		t.Errorf("every other voter skipped: %v, want the refusal naming voter-x", err)
	}
	if len(skipped) != 1 {
		t.Errorf("skipped = %v", skipped)
	}
}
