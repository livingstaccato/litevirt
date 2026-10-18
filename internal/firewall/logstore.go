package firewall

// The firewall log store (docs/firewall.md, "Logging"; spec §3.5, L-5): the
// records this host's NFLOG listener reads, kept under three bounds.
//
//   - A host-wide token bucket at firewall.log_max_rate records a second (a
//     burst of one second's worth); the rest are counted and discarded.
//   - An in-memory ring of the newest LogRingSize records, which
//     ListFirewallLog reads.
//   - Append-only JSON-lines files under <data_dir>/firewall-log/ (directory
//     0700, files 0600), rotated so the directory never holds more than
//     firewall.log_retain_mib, and, with firewall.log_retain_days, never a
//     file whose newest record is older than that.
//
// Records are tenant flow metadata. They are never passed to slog, so they
// never reach the journal; a failing file is reported once per transition.

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// LogRingSize is how many records the in-memory ring keeps.
const LogRingSize = 10000

// LogRecord outcomes, the outcome label of
// litevirt_firewall_log_records_total.
const (
	LogOutcomeKept        = "kept"
	LogOutcomeRateLimited = "rate_limited"
	LogOutcomeOverflow    = "overflow"
)

// LogCounter counts log records by outcome (metrics.FirewallMetrics).
type LogCounter interface {
	LogRecords(outcome string, n int)
}

// LogRecord is one logged packet.
type LogRecord struct {
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	Workload string    `json:"workload,omitempty"`
	MAC      string    `json:"mac,omitempty"`
	Device   string    `json:"device"`
	Side     string    `json:"side"`             // in | out | -
	RuleID   string    `json:"rule"`             // a rule id, "rule" or "default"
	Tier     string    `json:"tier,omitempty"`   // nic | routed
	Verdict  string    `json:"verdict"`          // accept | drop | would-drop
	Family   string    `json:"family,omitempty"` // ip | ip6
	Proto    string    `json:"proto,omitempty"`  // tcp | udp | icmp | ... or the number
	Src      string    `json:"src,omitempty"`    // source address
	Sport    uint16    `json:"sport,omitempty"`  // source port
	Dst      string    `json:"dst,omitempty"`    // destination address
	Dport    uint16    `json:"dport,omitempty"`  // destination port
	Length   uint32    `json:"len,omitempty"`    // packet length
	TCPFlags string    `json:"tcp_flags,omitempty"`
}

// LogStoreOptions configures a LogStore.
type LogStoreOptions struct {
	// Dir holds the JSON-lines files; "" keeps the ring only.
	Dir string
	// MaxRate is the records kept a second; 0 or less keeps none.
	MaxRate int
	// RetainBytes caps the directory; 0 or less keeps no file.
	RetainBytes int64
	// RetainAge removes a file whose newest record is older; 0 is no bound.
	RetainAge time.Duration
	// Now is the clock (time.Now when nil).
	Now func() time.Time
	// Counter counts records by outcome (none when nil).
	Counter LogCounter
}

// LogFilter selects records for List.
type LogFilter struct {
	Workload string    // "" is every workload
	Since    time.Time // zero is no lower bound
	AfterSeq uint64    // only records after this sequence
	Limit    int       // the newest Limit records; 0 or less is LogRingSize
}

// logSegments is how many files the directory cap is split over: the current
// one fills to RetainBytes/logSegments before it is rotated, and the oldest
// are removed so at most logSegments are kept.
const logSegments = 4

const (
	logFilePrefix = "fwlog-"
	logFileSuffix = ".jsonl"
)

// LogStore keeps this host's firewall log records. It is safe for concurrent
// use.
type LogStore struct {
	opts LogStoreOptions

	mu      sync.Mutex
	ring    []LogRecord // circular, len <= LogRingSize
	start   int         // index of the oldest record in ring
	seq     uint64
	tokens  float64
	lastAt  time.Time
	file    *os.File
	w       *bufio.Writer
	segSize int64
	segAt   time.Time // first record of the current file
	// newest is each file's newest record's time, for the age bound.
	newest  map[string]time.Time
	failing bool // the file is failing; reported once
	retryAt time.Time
}

// OpenLogStore opens the store, creating its directory, and resumes from the
// files already there: the ring holds their newest records and the sequence
// carries on, so a reader's per-host cursor never goes backwards.
func OpenLogStore(opts LogStoreOptions) (*LogStore, error) {
	if opts.Now == nil {
		opts.Now = time.Now
	}
	s := &LogStore{opts: opts, tokens: float64(max(opts.MaxRate, 0)), lastAt: opts.Now(), newest: map[string]time.Time{}}
	if opts.Dir == "" || opts.RetainBytes <= 0 {
		s.opts.Dir = ""
		return s, nil
	}
	s.segSize = max(opts.RetainBytes/logSegments, 1)
	if err := os.MkdirAll(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("firewall log directory: %w", err)
	}
	// MkdirAll leaves an existing directory's mode alone.
	if err := os.Chmod(opts.Dir, 0o700); err != nil {
		return nil, fmt.Errorf("firewall log directory: %w", err)
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	s.pruneLocked(opts.Now())
	return s, nil
}

// segments lists the directory's log files, oldest first.
func (s *LogStore) segments() ([]string, error) {
	ents, err := os.ReadDir(s.opts.Dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if n := e.Name(); !e.IsDir() && strings.HasPrefix(n, logFilePrefix) && strings.HasSuffix(n, logFileSuffix) {
			out = append(out, n)
		}
	}
	sort.Strings(out) // the names carry the first sequence, zero-padded
	return out, nil
}

// load reads the files' records into the ring, oldest first, and sets the
// sequence from the newest. A line that does not decode is skipped.
func (s *LogStore) load() error {
	names, err := s.segments()
	if err != nil {
		return fmt.Errorf("firewall log directory: %w", err)
	}
	for _, n := range names {
		p := filepath.Join(s.opts.Dir, n)
		if err := os.Chmod(p, 0o600); err != nil {
			return fmt.Errorf("firewall log file: %w", err)
		}
		f, err := os.Open(p)
		if err != nil {
			return fmt.Errorf("firewall log file: %w", err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			var r LogRecord
			if json.Unmarshal(sc.Bytes(), &r) != nil || r.Seq <= s.seq {
				continue
			}
			s.seq = r.Seq
			s.push(r)
			s.newest[n] = r.Time
		}
		f.Close()
	}
	return nil
}

// push adds r to the ring, dropping the oldest when full.
func (s *LogStore) push(r LogRecord) {
	if len(s.ring) < LogRingSize {
		s.ring = append(s.ring, r)
		return
	}
	s.ring[s.start] = r
	s.start = (s.start + 1) % LogRingSize
}

func (s *LogStore) count(outcome string, n int) {
	if s.opts.Counter != nil && n > 0 {
		s.opts.Counter.LogRecords(outcome, n)
	}
}

// take spends one token of the host-wide bucket, refilled at MaxRate a
// second up to one second's worth.
func (s *LogStore) take(now time.Time) bool {
	rate := float64(max(s.opts.MaxRate, 0))
	if el := now.Sub(s.lastAt).Seconds(); el > 0 {
		s.tokens = min(rate, s.tokens+el*rate)
	}
	s.lastAt = now
	if s.tokens < 1 {
		return false
	}
	s.tokens--
	return true
}

// Add keeps r unless the host-wide rate cap is spent, stamping its sequence
// (and its time, when zero). It reports whether r was kept.
func (s *LogStore) Add(r LogRecord) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	if !s.take(now) {
		s.count(LogOutcomeRateLimited, 1)
		return false
	}
	s.seq++
	r.Seq = s.seq
	if r.Time.IsZero() {
		r.Time = now
	}
	s.push(r)
	s.count(LogOutcomeKept, 1)
	s.write(r, now)
	return true
}

// Overflow counts n records the kernel dropped before the listener read them
// (the socket's ENOBUFS).
func (s *LogStore) Overflow(n int) { s.count(LogOutcomeOverflow, n) }

// write appends r to the current file, rotating first when it is full or
// (with an age bound) old enough that it would keep aged records on disk.
func (s *LogStore) write(r LogRecord, now time.Time) {
	if s.opts.Dir == "" {
		return
	}
	line, err := json.Marshal(r)
	if err != nil {
		return
	}
	line = append(line, '\n')
	if s.file != nil && s.rotateDue(int64(len(line)), now) {
		s.closeFile()
	}
	if s.file == nil {
		if s.failing && now.Before(s.retryAt) {
			return
		}
		if err := s.openFile(r.Seq, now); err != nil {
			s.fail(err, now)
			return
		}
		s.pruneLocked(now)
	}
	if _, err := s.w.Write(line); err != nil {
		s.fail(err, now)
		s.closeFile()
		return
	}
	if err := s.w.Flush(); err != nil {
		s.fail(err, now)
		s.closeFile()
		return
	}
	s.newest[filepath.Base(s.file.Name())] = r.Time
	s.recovered()
}

func (s *LogStore) rotateDue(n int64, now time.Time) bool {
	fi, err := s.file.Stat()
	if err != nil || fi.Size()+n > s.segSize {
		return true
	}
	return s.opts.RetainAge > 0 && now.Sub(s.segAt) > s.opts.RetainAge/logSegments
}

func (s *LogStore) openFile(firstSeq uint64, now time.Time) error {
	p := filepath.Join(s.opts.Dir, fmt.Sprintf("%s%020d%s", logFilePrefix, firstSeq, logFileSuffix))
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	s.file, s.w, s.segAt = f, bufio.NewWriter(f), now
	return nil
}

func (s *LogStore) closeFile() {
	if s.file == nil {
		return
	}
	s.w.Flush()
	s.file.Close()
	s.file, s.w = nil, nil
}

// fail reports a failing file once, then retries opening one at most every
// ten seconds.
func (s *LogStore) fail(err error, now time.Time) {
	if !s.failing {
		slog.Warn("firewall log: cannot write the log file; records are kept in memory only until it can be written",
			"dir", s.opts.Dir, "error", err)
	}
	s.failing = true
	s.retryAt = now.Add(10 * time.Second)
}

func (s *LogStore) recovered() {
	if s.failing {
		slog.Info("firewall log: the log file is written again", "dir", s.opts.Dir)
	}
	s.failing = false
}

// Prune removes the files the bounds no longer allow, and is called on every
// rotation; the daemon also calls it periodically so the age bound holds
// while no record arrives.
func (s *LogStore) Prune() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.opts.Now()
	if s.file != nil && s.opts.RetainAge > 0 && now.Sub(s.segAt) > s.opts.RetainAge/logSegments {
		s.closeFile()
	}
	s.pruneLocked(now)
}

// pruneLocked keeps the newest files within the byte cap (the current one
// counts as full) and, with an age bound, removes every closed file whose
// newest record is older than it.
func (s *LogStore) pruneLocked(now time.Time) {
	if s.opts.Dir == "" {
		return
	}
	names, err := s.segments()
	if err != nil {
		return
	}
	current := ""
	if s.file != nil {
		current = filepath.Base(s.file.Name())
	}
	keep := int(max(s.opts.RetainBytes/s.segSize, 1))
	if current != "" {
		keep-- // the current file may still grow to segSize
	}
	var closed []string
	for _, n := range names {
		if n != current {
			closed = append(closed, n)
		}
	}
	for i, n := range closed {
		p := filepath.Join(s.opts.Dir, n)
		drop := i < len(closed)-keep
		if !drop && s.opts.RetainAge > 0 {
			last, ok := s.newest[n]
			if !ok {
				if fi, err := os.Stat(p); err == nil {
					last = fi.ModTime()
				}
			}
			drop = now.Sub(last) > s.opts.RetainAge
		}
		if drop {
			if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
				s.fail(err, now)
				continue
			}
			delete(s.newest, n)
		}
	}
}

// List returns the newest f.Limit records f selects, oldest first. With an
// age bound, a record older than it is never returned.
func (s *LogStore) List(f LogFilter) []LogRecord {
	s.mu.Lock()
	defer s.mu.Unlock()
	limit := f.Limit
	if limit <= 0 || limit > LogRingSize {
		limit = LogRingSize
	}
	var floor time.Time
	if s.opts.RetainAge > 0 {
		floor = s.opts.Now().Add(-s.opts.RetainAge)
	}
	var out []LogRecord
	for i := len(s.ring) - 1; i >= 0 && len(out) < limit; i-- {
		r := s.ring[(s.start+i)%len(s.ring)]
		if r.Seq <= f.AfterSeq {
			break
		}
		if (f.Workload != "" && r.Workload != f.Workload) || r.Time.Before(f.Since) || r.Time.Before(floor) {
			continue
		}
		out = append(out, r)
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Close flushes and closes the current file.
func (s *LogStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeFile()
	return nil
}
