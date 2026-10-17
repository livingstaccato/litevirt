package corrosion

import (
	"context"
	"testing"
	"time"
)

// NoteLeaseNoQuorum reports a stand-down only when this replica shows no live
// holder: an absent or expired lease is a takeover that cannot happen; a lease
// live for a peer, or this node's own live lease, is not a takeover at all and
// is reported only with Live set.
//
// Mutation: drop the live-holder check — the live cases are reported as
// stalls. Return silently over a live holder — no Live report, and this goes
// red.
func TestNoteLeaseNoQuorum_OnlyALeaseWithNoLiveHolder(t *testing.T) {
	ctx := context.Background()
	c := testClient(t)
	var got, live []LeaseNoMajority
	c.SetLeaseNoMajorityObserver(func(_ context.Context, ev LeaseNoMajority) {
		if ev.Live {
			live = append(live, ev)
			return
		}
		got = append(got, ev)
	})
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	ttl := 30 * time.Second

	NoteLeaseNoQuorum(ctx, c, LeaseKeyFailover, "me", ttl, now)
	if len(got) != 1 || got[0].Key != LeaseKeyFailover || got[0].TTL != ttl || !got[0].Now.Equal(now) || got[0].Why == "" {
		t.Fatalf("a lease nobody holds: reported %+v, want one stall", got)
	}

	seedLease(t, c, LeaseKeyFailover, "peer", now.Add(ttl))
	NoteLeaseNoQuorum(ctx, c, LeaseKeyFailover, "me", ttl, now.Add(ttl/2))
	if len(got) != 1 {
		t.Fatalf("a lease live for a peer was reported as a stalled takeover: %+v", got)
	}
	NoteLeaseNoQuorum(ctx, c, LeaseKeyFailover, "peer", ttl, now.Add(ttl/2))
	if len(got) != 1 {
		t.Fatalf("a holder's own live lease was reported as a stalled takeover: %+v", got)
	}
	if len(live) != 2 || live[0].Key != LeaseKeyFailover || live[1].Key != LeaseKeyFailover {
		t.Fatalf("a live lease was not reported as live, so the stall it ends is kept: %+v", live)
	}
	NoteLeaseNoQuorum(ctx, c, LeaseKeyFailover, "me", ttl, now.Add(ttl+time.Second))
	if len(got) != 2 {
		t.Fatalf("an expired lease was not reported as a stalled takeover: %+v", got)
	}
}
