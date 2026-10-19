package firewall

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/testkit/slogtest"
)

// countingLog is a LogCounter that records each outcome's total.
type countingLog struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *countingLog) LogRecords(outcome string, n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[string]int{}
	}
	c.n[outcome] += n
}

func (c *countingLog) get(outcome string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n[outcome]
}

type fakeClock struct{ t time.Time }

func (f *fakeClock) now() time.Time { return f.t }

func testRecord(i int) LogRecord {
	return LogRecord{Workload: fmt.Sprintf("vm%d", i%3), Device: "lvt0", Side: "in", RuleID: "r1", Verdict: "drop",
		Family: "ip", Proto: "tcp", Src: "10.0.0.1", Sport: 1234, Dst: "10.0.0.2", Dport: 22, Length: 60}
}

func openStore(t *testing.T, opts LogStoreOptions) *LogStore {
	t.Helper()
	s, err := OpenLogStore(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// C4a (L-5): the host-wide cap keeps at most max_rate records a second (a
// burst of one second's worth) and counts the rest as rate_limited.
//
// Mutation: skip the bucket — all 50 are kept, red.
func TestLogStore_RateCap(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	cnt := &countingLog{}
	s := openStore(t, LogStoreOptions{MaxRate: 10, Now: clk.now, Counter: cnt})
	kept := 0
	for i := 0; i < 50; i++ {
		if s.Add(testRecord(i)) {
			kept++
		}
	}
	if kept != 10 || cnt.get(LogOutcomeKept) != 10 || cnt.get(LogOutcomeRateLimited) != 40 {
		t.Errorf("kept %d (counted %d), rate_limited %d; want 10 and 40", kept, cnt.get(LogOutcomeKept), cnt.get(LogOutcomeRateLimited))
	}
	clk.t = clk.t.Add(500 * time.Millisecond)
	kept = 0
	for i := 0; i < 50; i++ {
		if s.Add(testRecord(i)) {
			kept++
		}
	}
	if kept != 5 {
		t.Errorf("half a second later %d kept, want 5", kept)
	}
	if got := len(s.List(LogFilter{})); got != 15 {
		t.Errorf("listed %d, want 15", got)
	}
}

// C4a (L-5): the in-memory ring holds the newest 10,000 records; sequence
// numbers keep counting.
//
// Mutation: grow the ring without bound — 10,050 listed, red.
func TestLogStore_RingBound(t *testing.T) {
	s := openStore(t, LogStoreOptions{MaxRate: 1 << 30})
	for i := 0; i < LogRingSize+50; i++ {
		s.Add(testRecord(i))
	}
	if len(s.ring) != LogRingSize {
		t.Errorf("the ring holds %d records, want %d", len(s.ring), LogRingSize)
	}
	got := s.List(LogFilter{Limit: LogRingSize * 2})
	if len(got) != LogRingSize {
		t.Fatalf("listed %d, want %d", len(got), LogRingSize)
	}
	if got[0].Seq != 51 || got[len(got)-1].Seq != LogRingSize+50 {
		t.Errorf("seq %d..%d, want 51..%d", got[0].Seq, got[len(got)-1].Seq, LogRingSize+50)
	}
}

// C4a: List filters by workload, time and per-host cursor, and returns the
// newest limit records oldest first.
//
// Mutation: return the oldest limit records — red.
func TestLogStore_ListFilters(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s := openStore(t, LogStoreOptions{MaxRate: 1 << 30, Now: clk.now})
	for i := 0; i < 30; i++ {
		clk.t = clk.t.Add(time.Second)
		s.Add(testRecord(i))
	}
	got := s.List(LogFilter{Workload: "vm1", Limit: 3})
	if len(got) != 3 || got[0].Seq != 23 || got[2].Seq != 29 {
		t.Errorf("vm1 limit 3 = %+v, want seqs 23, 26, 29", got)
	}
	if got := s.List(LogFilter{AfterSeq: 27}); len(got) != 3 || got[0].Seq != 28 {
		t.Errorf("after 27 = %d records from %v, want 28..30", len(got), got)
	}
	since := time.Date(2026, 10, 18, 12, 0, 25, 0, time.UTC)
	if got := s.List(LogFilter{Since: since}); len(got) != 6 || got[0].Seq != 25 {
		t.Errorf("since :25 = %d records, want 25..30", len(got))
	}
}

func dirBytes(t *testing.T, dir string) (int64, int) {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var n int64
	for _, e := range ents {
		fi, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		n += fi.Size()
	}
	return n, len(ents)
}

// C4a (L-5, m-16): records are appended as JSON lines under the log
// directory, mode 0700 for the directory and 0600 for each file, and the
// files are rotated so the directory never exceeds its cap; the newest
// records are on disk.
//
// Mutations: never rotate — the directory passes the cap, red; create files
// 0644 — red.
func TestLogStore_RotationAtTheCapAndMode(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "firewall-log")
	const capBytes = 64 << 10
	s := openStore(t, LogStoreOptions{Dir: dir, MaxRate: 1 << 30, RetainBytes: capBytes})
	maxSeen := int64(0)
	for i := 0; i < 3000; i++ {
		s.Add(testRecord(i))
		if i%50 == 0 {
			if n, _ := dirBytes(t, dir); n > maxSeen {
				maxSeen = n
			}
		}
	}
	n, files := dirBytes(t, dir)
	if n > capBytes || maxSeen > capBytes {
		t.Errorf("directory holds %d bytes (max seen %d), over the %d cap", n, maxSeen, capBytes)
	}
	if files < 2 {
		t.Errorf("%d file(s): nothing was rotated", files)
	}
	if n < capBytes/2 {
		t.Errorf("directory holds only %d bytes of a %d cap", n, capBytes)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("directory mode = %v, %v; want 0700", fi.Mode().Perm(), err)
	}
	ents, _ := os.ReadDir(dir)
	for _, e := range ents {
		fi, _ := e.Info()
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", e.Name(), fi.Mode().Perm())
		}
	}
	// Reopened, the store resumes from the files: the newest record and the
	// sequence carry on, so a --follow cursor does not go backwards.
	s.Close()
	s2 := openStore(t, LogStoreOptions{Dir: dir, MaxRate: 1 << 30, RetainBytes: capBytes})
	got := s2.List(LogFilter{Limit: 1})
	if len(got) != 1 || got[0].Seq != 3000 {
		t.Fatalf("after reopen the newest record is %+v, want seq 3000", got)
	}
	s2.Add(testRecord(0))
	if got := s2.List(LogFilter{Limit: 1}); got[0].Seq != 3001 {
		t.Errorf("after reopen the next seq is %d, want 3001", got[0].Seq)
	}
}

// C4a (privacy): with an age bound, files whose newest record is older than
// it are removed, and the ring lists nothing older.
//
// Mutation: ignore the age — the old file stays, red.
func TestLogStore_AgeBound(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "firewall-log")
	s := openStore(t, LogStoreOptions{Dir: dir, MaxRate: 1 << 30, RetainBytes: 64 << 10, RetainAge: 24 * time.Hour, Now: clk.now})
	for i := 0; i < 2000; i++ {
		s.Add(testRecord(i))
	}
	_, before := dirBytes(t, dir)
	clk.t = clk.t.Add(48 * time.Hour)
	s.Add(testRecord(0))
	s.Prune()
	_, after := dirBytes(t, dir)
	if after >= before || after > 1 {
		t.Errorf("files %d before, %d after the age passed; want only the newest", before, after)
	}
	if got := s.List(LogFilter{Limit: 100}); len(got) != 1 {
		t.Errorf("listed %d after the age passed, want only the new record", len(got))
	}
}

// C4a (L-5): socket overflow is counted as overflow.
func TestLogStore_OverflowCounted(t *testing.T) {
	cnt := &countingLog{}
	s := openStore(t, LogStoreOptions{MaxRate: 10, Counter: cnt})
	s.Overflow(7)
	if cnt.get(LogOutcomeOverflow) != 7 {
		t.Errorf("overflow = %d, want 7", cnt.get(LogOutcomeOverflow))
	}
}

// captureHandler counts every slog record.
type captureHandler struct {
	mu sync.Mutex
	n  int
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *captureHandler) Handle(context.Context, slog.Record) error {
	h.mu.Lock()
	h.n++
	h.mu.Unlock()
	return nil
}
func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// C4a (L-5, "no journal"): records never pass through slog, kept, rate
// limited or overflowed; a failing file is reported once, not per record.
//
// Mutation: slog each record — red.
func TestLogStore_NoSlogPerRecord(t *testing.T) {
	slogtest.SaveRestore(t)
	h := &captureHandler{}
	slog.SetDefault(slog.New(h))
	dir := filepath.Join(t.TempDir(), "firewall-log")
	clk := &fakeClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s := openStore(t, LogStoreOptions{Dir: dir, MaxRate: 100, RetainBytes: 64 << 10, Now: clk.now})
	for i := 0; i < 500; i++ { // 100 kept, 400 rate limited
		s.Add(testRecord(i))
	}
	s.Overflow(10)
	if h.n != 0 {
		t.Errorf("slog saw %d record(s) for 500 log records", h.n)
	}
	// The directory goes away under the store: one report, not one per record.
	os.RemoveAll(dir)
	os.WriteFile(dir, nil, 0o600) // a file where the directory was: rotation fails
	for i := 0; i < 5000; i++ {
		clk.t = clk.t.Add(10 * time.Millisecond) // one token each
		s.Add(testRecord(i))
	}
	if h.n > 1 {
		t.Errorf("slog saw %d record(s) for a failing file, want at most one", h.n)
	}
}
