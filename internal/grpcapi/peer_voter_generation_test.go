package grpcapi

import (
	"testing"
	"time"
)

// A peer's reported voter generation is evidence of what it had adopted by
// the time this node received the report (the bounded partition-pause hold,
// docs/design/partition-pause.md §4.2 step 3). Only a report received before
// the asked moment counts; 0 is no report (an older build, or no adoption
// pass yet); a lower generation than the last means the peer's adoption state
// was replaced, and the earlier reports no longer stand.
//
// Mutations: return the latest report whatever its time — "before the
// second report" reads 3; record 0 — "after a zero report" loses 3; keep
// earlier reports past a lower one — "after a lower report" reads 3.
func TestPeerVoterGeneration_OnlyReportsReceivedBeforeCount(t *testing.T) {
	t0 := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	s := &Server{}
	if _, ok := s.PeerVoterGeneration("p", t0.Add(time.Hour)); ok {
		t.Fatal("a peer never heard from has a generation")
	}
	s.notePeerVoterGeneration("p", 0, t0)
	if g, ok := s.PeerVoterGeneration("p", t0.Add(time.Hour)); ok {
		t.Fatalf("a zero report: %d, want no evidence", g)
	}
	s.notePeerVoterGeneration("p", 2, t0.Add(time.Minute))
	s.notePeerVoterGeneration("p", 2, t0.Add(2*time.Minute)) // the first receipt dates it
	s.notePeerVoterGeneration("p", 3, t0.Add(10*time.Minute))
	for _, tc := range []struct {
		name   string
		before time.Time
		want   int64
		ok     bool
	}{
		{"before any report", t0.Add(time.Minute), 0, false},
		{"before the second report", t0.Add(90 * time.Second), 2, true},
		{"after both", t0.Add(11 * time.Minute), 3, true},
	} {
		if g, ok := s.PeerVoterGeneration("p", tc.before); g != tc.want || ok != tc.ok {
			t.Errorf("%s: %d %v, want %d %v", tc.name, g, ok, tc.want, tc.ok)
		}
	}
	if _, ok := s.PeerVoterGeneration("q", t0.Add(time.Hour)); ok {
		t.Error("another peer's report counts for q")
	}
	// A restarted peer reports 0 until its first adoption pass; what it
	// adopted is still in its database.
	s.notePeerVoterGeneration("p", 0, t0.Add(15*time.Minute))
	if g, ok := s.PeerVoterGeneration("p", t0.Add(16*time.Minute)); g != 3 || !ok {
		t.Errorf("after a zero report: %d %v, want 3", g, ok)
	}
	s.notePeerVoterGeneration("p", 1, t0.Add(20*time.Minute))
	if g, ok := s.PeerVoterGeneration("p", t0.Add(15*time.Minute)); ok {
		t.Errorf("after a lower report, before it: %d, want no evidence", g)
	}
	if g, ok := s.PeerVoterGeneration("p", t0.Add(time.Hour)); g != 1 || !ok {
		t.Errorf("after a lower report: %d %v, want 1", g, ok)
	}
}
