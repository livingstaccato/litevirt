package firewall

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Round 1 m-1: the age bound holds within the documented slack. The current
// file rotates once it spans an hour (at most RetainAge/24), so a file never
// keeps a record past the bound by more than that; aged records leave the
// in-memory ring as well as the files.
//
// Mutations: rotate only at RetainAge/4 — the second write stays in the
// first file, red; keep aged records in the ring — red.
func TestLogStore_AgeBoundSlackAndRing(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	dir := filepath.Join(t.TempDir(), "firewall-log")
	s := openStore(t, LogStoreOptions{Dir: dir, MaxRate: 1 << 30, RetainBytes: 64 << 20, RetainAge: 7 * 24 * time.Hour, Now: clk.now})
	s.Add(testRecord(0))
	clk.t = clk.t.Add(61 * time.Minute)
	s.Add(testRecord(1))
	if _, files := dirBytes(t, dir); files != 2 {
		t.Errorf("files after an hour = %d, want the current file rotated (2)", files)
	}
	clk.t = clk.t.Add(7*24*time.Hour - 30*time.Minute) // the first record is 7d+31m old
	s.Prune()
	if _, files := dirBytes(t, dir); files != 1 {
		t.Errorf("files once the first record aged out = %d, want 1", files)
	}
	if len(s.ring) != 1 {
		t.Errorf("ring holds %d records, want only the one within the bound", len(s.ring))
	}
}

// Round 1 m-2: the byte cap is applied by size, so lowering
// firewall.log_retain_mib across a restart shrinks the directory at once.
//
// Mutation: keep files by count — the directory stays over the new cap, red.
func TestLogStore_LoweredCapPrunesBySize(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "firewall-log")
	s, err := OpenLogStore(LogStoreOptions{Dir: dir, MaxRate: 1 << 30, RetainBytes: 256 << 10})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3000; i++ {
		s.Add(testRecord(i))
	}
	s.Close()
	if n, _ := dirBytes(t, dir); n < 128<<10 {
		t.Fatalf("setup: directory holds only %d bytes", n)
	}
	openStore(t, LogStoreOptions{Dir: dir, MaxRate: 1 << 30, RetainBytes: 32 << 10})
	if n, _ := dirBytes(t, dir); n > 32<<10 {
		t.Errorf("after lowering the cap to 32 KiB the directory holds %d bytes", n)
	}
}

// Round 1 m-3: a store with no files (memory only, or every file aged out)
// does not restart its sequence at 1: with SeqFromClock it starts at the
// clock in microseconds, above any sequence an earlier run reached; and a
// cursor ahead of the store's newest sequence is read as stale, so --follow
// never stalls.
//
// Mutations: start at 0 — the restarted sequence is below the cursor, red;
// honour a stale cursor — nothing is listed, red.
func TestLogStore_SequenceSurvivesARestart(t *testing.T) {
	clk := &fakeClock{t: time.Date(2026, 10, 18, 12, 0, 0, 0, time.UTC)}
	s1 := openStore(t, LogStoreOptions{MaxRate: 1 << 30, Now: clk.now, SeqFromClock: true})
	for i := 0; i < 100; i++ {
		s1.Add(testRecord(i))
	}
	cursor := s1.List(LogFilter{Limit: 1})[0].Seq
	clk.t = clk.t.Add(time.Second)
	s2 := openStore(t, LogStoreOptions{MaxRate: 1 << 30, Now: clk.now, SeqFromClock: true})
	s2.Add(testRecord(0))
	if got := s2.List(LogFilter{AfterSeq: cursor}); len(got) != 1 || got[0].Seq <= cursor {
		t.Errorf("after a restart, records after cursor %d = %+v, want the new one", cursor, got)
	}
	s3 := openStore(t, LogStoreOptions{MaxRate: 1 << 30})
	s3.Add(testRecord(0))
	if got := s3.List(LogFilter{AfterSeq: cursor}); len(got) != 1 {
		t.Errorf("a cursor ahead of the store's newest = %d records, want the store read from its start", len(got))
	}
}

// Codex cand36 review I3: lowering firewall.log_retain_mib to 0 (memory
// only) on a host whose directory already holds log files must not exempt
// them from both bounds: the zero cap keeps no file of ours, so they go at
// open. A file the store does not own is left alone, and new records make no
// file.
//
// Mutation: drop disk ownership before removing the owned files — they stay:
// red.
func TestLogStore_ZeroCapRemovesTheOwnedFilesAtOpen(t *testing.T) {
	dir := t.TempDir()
	clk := &fakeClock{t: time.Unix(1_700_000_000, 0)}
	s, err := OpenLogStore(LogStoreOptions{Dir: dir, MaxRate: 1000, RetainBytes: 1 << 20, RetainAge: 24 * time.Hour, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		s.Add(testRecord(i))
	}
	s.Close()
	owned, _ := filepath.Glob(filepath.Join(dir, logFilePrefix+"*"+logFileSuffix))
	if len(owned) == 0 {
		t.Fatal("the disk-backed store wrote no file")
	}
	foreign := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(foreign, []byte("not ours"), 0o600); err != nil {
		t.Fatal(err)
	}

	clk.t = clk.t.Add(time.Hour)
	z, err := OpenLogStore(LogStoreOptions{Dir: dir, MaxRate: 1000, RetainBytes: 0, RetainAge: 24 * time.Hour, Now: clk.now})
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	if left, _ := filepath.Glob(filepath.Join(dir, logFilePrefix+"*"+logFileSuffix)); len(left) != 0 {
		t.Errorf("with a zero cap, %d log file(s) remain on disk: %v", len(left), left)
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("a file the store does not own was touched: %v", err)
	}
	z.Add(testRecord(99))
	clk.t = clk.t.Add(48 * time.Hour)
	z.Prune()
	if left, _ := filepath.Glob(filepath.Join(dir, logFilePrefix+"*"+logFileSuffix)); len(left) != 0 {
		t.Errorf("a memory-only store wrote a file: %v", left)
	}
}
