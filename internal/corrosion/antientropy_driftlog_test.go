package corrosion

import (
	"bytes"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
)

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) count(sub string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Count(s.b.String(), sub)
}

// TestDriftLog_ARepeatedDriftIsLoggedOnce: a drift that persists pass after
// pass — on the kvm003 lab, leader_lease_terms between node-1 and node-2 with
// the same local and remote hash every minute — is reported when it is first
// seen and then once per driftRepeatInterval, not on every pass. Anything
// that changes it is reported at once: another hash on either side, another
// table or another peer, and the same drift again after the tables agreed.
//
// Mutations, each red: log every mismatch (the old behaviour) — the second
// pass logs; key on the table alone — the second peer is silent; keep the
// entry when the tables agree — the reappearing drift is silent; never
// repeat — the hourly reminder is silent.
func TestDriftLog_ARepeatedDriftIsLoggedOnce(t *testing.T) {
	buf := &syncBuf{}
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelInfo})))
	t.Cleanup(func() { slog.SetDefault(prev) })

	now := time.Unix(1_800_000_000, 0)
	d := &driftLog{now: func() time.Time { return now }}
	const msg = "anti-entropy: drift detected"
	remote := func(h string) []*pb.TableDigest {
		return []*pb.TableDigest{{Name: "leader_lease_terms", Hash: h, Count: 3}}
	}
	local := func(h string) map[string]TableDigest {
		return map[string]TableDigest{"leader_lease_terms": {Name: "leader_lease_terms", Hash: h, Count: 3}}
	}
	pass := func(peer, lh, rh string) []string {
		now = now.Add(time.Minute)
		return d.mismatches(peer, remote(rh), local(lh))
	}
	want := func(step string, n int) {
		t.Helper()
		if got := buf.count(msg); got != n {
			t.Fatalf("%s: %d drift lines logged, want %d:\n%s", step, got, n, buf.b.String())
		}
	}

	if got := pass("node-2", "320f", "84ef"); len(got) != 1 {
		t.Fatalf("a drifted table was not reported as a mismatch: %v", got)
	}
	want("first sight", 1)
	for i := 0; i < 5; i++ {
		if got := pass("node-2", "320f", "84ef"); len(got) != 1 {
			t.Fatalf("a repeated drift stopped being a mismatch: the pull must not be hidden with the log (%v)", got)
		}
	}
	want("the same drift, five more passes", 1)
	pass("node-2", "320f", "9999")
	want("the peer's hash moved", 2)
	pass("node-3", "320f", "9999")
	want("another peer", 3)

	pass("node-2", "aaaa", "aaaa") // agree
	pass("node-2", "320f", "9999")
	want("the same drift after the tables agreed", 4)

	now = now.Add(driftRepeatInterval)
	pass("node-2", "320f", "9999")
	want("a drift still there after the repeat interval", 5)
}
