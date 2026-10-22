package pressure

import (
	"context"
	"errors"
	"log/slog"
	"sort"
	"sync"
	"time"
)

// Level is a resource's grade. Higher is worse.
type Level int

const (
	OK Level = iota
	Warn
	Degrade
	Critical
)

// String is the wire name (ReadyResponse.pressure.level).
func (l Level) String() string {
	switch l {
	case OK:
		return "ok"
	case Warn:
		return "warn"
	case Degrade:
		return "degrade"
	case Critical:
		return "critical"
	}
	return "unknown"
}

// FSStat is the part of statfs the sampler reads. AvailBytes is free to an
// unprivileged writer (f_bavail), TotalInodes 0 means the filesystem has no
// inode count (btrfs, some network filesystems).
type FSStat struct {
	AvailBytes, TotalBytes  uint64
	FreeInodes, TotalInodes uint64
}

// FS is the statfs seam. Production is OSFS, under storage.Bounded.
type FS interface {
	Statfs(path string) (FSStat, error)
}

// Pool is one storage pool whose filesystem is graded.
type Pool struct {
	Name, Path string
}

// Options are the sampler's seams. A nil field takes the production source.
type Options struct {
	FS    FS
	Now   func() time.Time
	Pools func(context.Context) []Pool
	// FDs returns the daemon's open descriptors and its limit; ok false
	// leaves the resource out.
	FDs func() (used, limit uint64, ok bool)
	// Mem returns the daemon's memory in bytes; ok false leaves it out.
	Mem func() (used uint64, ok bool)
	// RAM returns the host's memory in bytes, for the auto limit; 0 unknown.
	RAM func() uint64
}

// ResourceReport is one resource's state.
type ResourceReport struct {
	Name  string
	Level Level
	Since time.Time
	// Free and Total are in Unit: "bytes", "inodes" or "fds". For memory
	// and fds, Free is the limit less what is in use.
	Free, Total uint64
	Unit        string
	FreePct     float64
	// TimeToFull is the projection at the current fill rate over the trend
	// window; 0 when nothing is filling (or the window is too short).
	TimeToFull time.Duration
	// Err is why the latest sample failed; the level is then the last one
	// known.
	Err string
}

// Report is a host's pressure: its level is the worst over its resources.
type Report struct {
	Level      Level
	Since      time.Time
	Resources  []ResourceReport // sorted by name
	TimeToFull time.Duration    // the shortest over the resources; 0 none
	// SampledAt is when the last sample completed; zero before the first.
	SampledAt time.Time
	// PoolsStale: the latest read of this host's pool list did not return
	// in time, so the pools graded are the last list read.
	PoolsStale bool
	// Stale: PoolsStale, or no sample has completed for more than
	// staleIntervals sample intervals (a frozen sampler). The levels are
	// then the last ones known.
	Stale bool
}

// staleIntervals is how many sample intervals without a completed sample
// make a report stale.
const staleIntervals = 3

// defaultPoolsWait bounds how long a sample waits for the pool list. A read
// still outstanding past it is abandoned: the sample grades the last list,
// and later samples do not wait on that read again.
const defaultPoolsWait = 2 * time.Second

// defaultStopWait bounds how long a stopping sampler waits for its pool-list
// read to return. The read honours its context, but the daemon's waits on the
// client lock before it does; past this the read is abandoned, and logged.
const defaultStopWait = 5 * time.Second

// Pressured names every resource above ok, sorted.
func (r Report) Pressured() []string {
	var out []string
	for _, res := range r.Resources {
		if res.Level > OK {
			out = append(out, res.Name)
		}
	}
	return out
}

// rule grades one resource from its free percentage and free amount.
type rule struct {
	pct [4]float64 // free-percentage threshold per level (index Warn..Critical); 0 off
	abs [4]float64 // free-amount floor per level; 0 off
}

func fsSpaceRule(t FSThresholds) rule {
	var r rule
	r.pct[Warn], r.pct[Degrade], r.pct[Critical] = t.WarnFreePct, t.DegradeFreePct, t.CriticalFreePct
	r.abs[Warn], r.abs[Degrade], r.abs[Critical] = float64(t.WarnFreeMiB<<20), float64(t.DegradeFreeMiB<<20), float64(t.CriticalFreeMiB<<20)
	return r
}

func fsInodeRule(t FSThresholds) rule {
	var r rule
	r.pct[Warn], r.pct[Degrade], r.pct[Critical] = t.WarnFreeInodesPct, t.DegradeFreeInodesPct, t.CriticalFreeInodesPct
	return r
}

// usageRule turns used-percentage thresholds into free-percentage ones.
func usageRule(t UsageThresholds) rule {
	var r rule
	for l, v := range map[Level]float64{Warn: t.WarnPct, Degrade: t.DegradePct, Critical: t.CriticalPct} {
		if v > 0 {
			r.pct[l] = 100 - v
		}
	}
	return r
}

// grade is the worst level whose threshold the sample is under. shift
// raises every percentage threshold by that many points, and mult scales
// every floor: grading with the clear margin asks whether the sample is
// better than a level by the margin.
func (r rule) grade(freePct, free, shift, mult float64) Level {
	for l := Critical; l >= Warn; l-- {
		if (r.pct[l] > 0 && freePct < r.pct[l]+shift) || (r.abs[l] > 0 && free < r.abs[l]*mult) {
			return l
		}
	}
	return OK
}

// absClearMult is how far past a floor a sample must be to count toward
// leaving its level: 25 % of the floor.
const absClearMult = 1.25

// machine is one resource's level with hysteresis: a level is entered only
// after enterN consecutive samples past it, and left only after every sample
// for clearAfter has been past the margin.
type machine struct {
	level      Level
	since      time.Time
	upRun      int
	upMin      Level
	clearSince time.Time
	clearTo    Level
}

// observe takes one sample's grade without (raw) and with (clear) the clear
// margin, and reports whether the level changed.
func (m *machine) observe(now time.Time, raw, clear Level, enterN int, clearAfter time.Duration) bool {
	if raw > m.level {
		m.clearSince = time.Time{}
		if m.upRun == 0 || raw < m.upMin {
			m.upMin = raw
		}
		m.upRun++
		if m.upRun >= enterN {
			// The level held over the whole run, not the worst sample in it.
			m.level, m.since, m.upRun = m.upMin, now, 0
			return true
		}
		return false
	}
	m.upRun = 0
	if clear >= m.level {
		m.clearSince = time.Time{}
		return false
	}
	if m.clearSince.IsZero() {
		m.clearSince, m.clearTo = now, clear
	} else if clear > m.clearTo {
		m.clearTo = clear
	}
	if now.Sub(m.clearSince) < clearAfter {
		return false
	}
	m.level, m.since, m.clearSince = m.clearTo, now, time.Time{}
	return true
}

// broken is a sample that failed: it continues neither run.
func (m *machine) broken() {
	m.upRun = 0
	m.clearSince = time.Time{}
}

type point struct {
	t    time.Time
	free float64
}

type resource struct {
	name, unit string
	m          machine
	last       ResourceReport
	trend      []point
	seen       bool // sampled (or failed) this pass
}

// Sampler samples this host's resources and keeps their levels.
type Sampler struct {
	cfg     Config
	dataDir string
	fs      FS
	now     func() time.Time
	pools   func(context.Context) []Pool
	fds     func() (uint64, uint64, bool)
	mem     func() (uint64, bool)
	memLim  uint64

	poolsWait  time.Duration
	stopWait   time.Duration
	poolMu     sync.Mutex
	poolFlight *poolFlight // the outstanding pool-list read, nil when none
	lastPools  []Pool

	mu         sync.Mutex
	res        map[string]*resource
	hostLevel  Level
	hostSince  time.Time
	sampledAt  time.Time
	poolsStale bool
	observer   func(Report)

	// life is the run Start began: Stop cancels it and joins it.
	lifeMu sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

// poolFlight is one pool-list read. pools is written before done is closed.
type poolFlight struct {
	started time.Time
	done    chan struct{}
	pools   []Pool
}

// NewSampler builds a sampler over dataDir. cfg must have been validated.
func NewSampler(cfg Config, dataDir string, o Options) *Sampler {
	s := &Sampler{cfg: cfg, dataDir: dataDir, fs: o.FS, now: o.Now, pools: o.Pools, fds: o.FDs, mem: o.Mem, res: map[string]*resource{}, poolsWait: defaultPoolsWait, stopWait: defaultStopWait}
	if s.fs == nil {
		s.fs = OSFS{}
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.pools == nil {
		s.pools = func(context.Context) []Pool { return nil }
	}
	if s.fds == nil {
		s.fds = processFDs
	}
	if s.mem == nil {
		s.mem = daemonMemory
	}
	ram := o.RAM
	if ram == nil {
		ram = hostRAM
	}
	s.memLim = uint64(cfg.Memory.DaemonLimitMiB) << 20
	if s.memLim == 0 {
		s.memLim = autoDaemonLimit(ram())
	}
	s.hostSince = s.now()
	return s
}

// autoDaemonLimit is 10 % of RAM, clamped to [1 GiB, 4 GiB]; 4 GiB when RAM
// is unknown.
func autoDaemonLimit(ram uint64) uint64 {
	const lo, hi = uint64(1) << 30, uint64(4) << 30
	if ram == 0 {
		return hi
	}
	return min(hi, max(lo, ram/10))
}

// SetObserver registers fn to receive the report after every sample
// (metrics). It runs on the sampling goroutine.
func (s *Sampler) SetObserver(fn func(Report)) {
	s.mu.Lock()
	s.observer = fn
	s.mu.Unlock()
}

// Start runs the sampler on its own goroutine until Stop, or until ctx ends.
// The run owns its lifetime: Stop ends it whatever ctx does.
func (s *Sampler) Start(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	s.lifeMu.Lock()
	s.cancel, s.done = cancel, done
	s.lifeMu.Unlock()
	go func() {
		defer close(done)
		s.Run(ctx)
	}()
}

// Stop ends the run Start began and returns once it has returned, its pool
// read included (Run): nothing the sampler reads through is used after Stop,
// unless that read ignored its context for stopWait, which is logged. Stop
// without Start does nothing.
func (s *Sampler) Stop() {
	s.lifeMu.Lock()
	cancel, done := s.cancel, s.done
	s.lifeMu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

// Run samples every interval until ctx ends. The first sample is at once. The
// pool-list read runs under ctx, and Run returns only once an outstanding one
// has returned, or after stopWait.
func (s *Sampler) Run(ctx context.Context) {
	tk := time.NewTicker(time.Duration(s.cfg.SampleIntervalSec) * time.Second)
	defer tk.Stop()
	defer s.joinPoolRead()
	for {
		s.Sample(ctx)
		select {
		case <-ctx.Done():
			return
		case <-tk.C:
		}
	}
}

// joinPoolRead waits, at most stopWait, for the outstanding pool-list read.
func (s *Sampler) joinPoolRead() {
	s.poolMu.Lock()
	f := s.poolFlight
	s.poolMu.Unlock()
	if f == nil {
		return
	}
	t := time.NewTimer(s.stopWait)
	defer t.Stop()
	select {
	case <-f.done:
	case <-t.C:
		slog.Warn("resource pressure: the pool-list read did not return on stop; abandoning it", "wait", s.stopWait)
	}
}

// currentPools is the pool list for this sample, and whether it is stale.
//
// The read runs on its own goroutine, never on the sampling path: the
// daemon's read is a replicated query, and Query takes the client lock before
// it honours any context, so a writer stuck in a commit (a stalled disk, the
// case this package exists to see) would otherwise freeze every resource's
// grade. As boundedReadyQuery does for Ready, a sample waits at most poolsWait
// for a read, a read already outstanding longer than that is not waited on
// again, and the sample grades the last list it has.
func (s *Sampler) currentPools(ctx context.Context) ([]Pool, bool) {
	s.poolMu.Lock()
	f := s.poolFlight
	switch {
	case f != nil && time.Since(f.started) > s.poolsWait:
		last := s.lastPools
		s.poolMu.Unlock()
		return last, true
	case f == nil:
		f = &poolFlight{started: time.Now(), done: make(chan struct{})}
		s.poolFlight = f
		read := s.pools
		// The read is detached from this sample's wait, not from the
		// sampler's lifetime: it runs under ctx, which ends with the run.
		go func() {
			f.pools = read(ctx)
			s.poolMu.Lock()
			s.lastPools = f.pools
			if s.poolFlight == f {
				s.poolFlight = nil
			}
			s.poolMu.Unlock()
			close(f.done)
		}()
	}
	s.poolMu.Unlock()
	t := time.NewTimer(s.poolsWait)
	defer t.Stop()
	select {
	case <-f.done:
		return f.pools, false
	case <-t.C:
	case <-ctx.Done():
	}
	s.poolMu.Lock()
	defer s.poolMu.Unlock()
	return s.lastPools, true
}

// Sample takes one sample of every resource.
func (s *Sampler) Sample(ctx context.Context) {
	type fsTarget struct {
		prefix string
		path   string
		th     FSThresholds
	}
	targets := []fsTarget{{prefix: "data_dir", path: s.dataDir, th: s.cfg.DataDir}}
	pools, poolsStale := s.currentPools(ctx)
	for _, p := range pools {
		targets = append(targets, fsTarget{prefix: "pool." + p.Name, path: p.Path, th: s.cfg.PoolThresholds(p.Name)})
	}
	type fsResult struct {
		st  FSStat
		err error
	}
	// The statfs calls run outside the lock: a slow mount must not hold
	// Report (the readiness probe) behind it.
	results := make([]fsResult, len(targets))
	for i, t := range targets {
		results[i].st, results[i].err = s.fs.Statfs(t.path)
	}
	fdUsed, fdLimit, fdOK := s.fds()
	memUsed, memOK := s.mem()

	now := s.now()
	s.mu.Lock()
	for _, r := range s.res {
		r.seen = false
	}
	for i, t := range targets {
		res := results[i]
		if res.err != nil {
			s.fail(now, t.prefix+".space", "bytes", res.err)
			if r := s.res[t.prefix+".inodes"]; r != nil {
				s.fail(now, t.prefix+".inodes", "inodes", res.err)
			}
			continue
		}
		s.observe(now, t.prefix+".space", "bytes", fsSpaceRule(t.th), res.st.AvailBytes, res.st.TotalBytes, true)
		if res.st.TotalInodes > 0 {
			s.observe(now, t.prefix+".inodes", "inodes", fsInodeRule(t.th), res.st.FreeInodes, res.st.TotalInodes, true)
		}
	}
	// A count that cannot be read keeps the resource and its level, as a
	// failed statfs does: counting descriptors itself needs one, so the read
	// fails at exactly the moment the resource is exhausted. Only a platform
	// that never had the resource leaves it out.
	switch {
	case fdOK && fdLimit > 0:
		s.observe(now, "fds.daemon", "fds", usageRule(s.cfg.FDs), fdLimit-min(fdUsed, fdLimit), fdLimit, false)
	case s.res["fds.daemon"] != nil:
		s.fail(now, "fds.daemon", "fds", errFDCount)
	}
	switch {
	case memOK && s.memLim > 0:
		s.observe(now, "memory.daemon", "bytes", usageRule(s.cfg.Memory.UsageThresholds), s.memLim-min(memUsed, s.memLim), s.memLim, false)
	case s.res["memory.daemon"] != nil:
		s.fail(now, "memory.daemon", "bytes", errMemRead)
	}
	for name, r := range s.res {
		if !r.seen {
			delete(s.res, name)
		}
	}
	host := OK
	for _, r := range s.res {
		host = max(host, r.m.level)
	}
	if host != s.hostLevel {
		slog.Info("resource pressure: host level changed", "from", s.hostLevel.String(), "to", host.String())
		s.hostLevel, s.hostSince = host, now
	}
	s.sampledAt, s.poolsStale = now, poolsStale
	rep := s.reportLocked()
	obs := s.observer
	s.mu.Unlock()
	if obs != nil {
		obs(rep)
	}
}

func (s *Sampler) resource(now time.Time, name, unit string) *resource {
	r := s.res[name]
	if r == nil {
		r = &resource{name: name, unit: unit}
		r.m.since = now
		s.res[name] = r
	}
	r.seen = true
	return r
}

func (s *Sampler) fail(now time.Time, name, unit string, err error) {
	r := s.resource(now, name, unit)
	r.m.broken()
	r.last.Err = err.Error()
}

func (s *Sampler) observe(now time.Time, name, unit string, ru rule, free, total uint64, trend bool) {
	r := s.resource(now, name, unit)
	pct := 100.0
	if total > 0 {
		pct = 100 * float64(free) / float64(total)
	}
	raw := ru.grade(pct, float64(free), 0, 1)
	clear := ru.grade(pct, float64(free), s.cfg.ClearMarginPct, absClearMult)
	if r.m.observe(now, raw, clear, s.cfg.EnterSamples, time.Duration(s.cfg.ClearAfterSec)*time.Second) {
		slog.Info("resource pressure: level changed", "resource", name, "level", r.m.level.String(),
			"free", free, "total", total, "unit", unit, "free_pct", pct)
	}
	r.last = ResourceReport{Free: free, Total: total, FreePct: pct}
	if trend {
		window := time.Duration(s.cfg.TrendWindowSec) * time.Second
		r.trend = append(r.trend, point{t: now, free: float64(free)})
		cut := 0
		for cut < len(r.trend) && now.Sub(r.trend[cut].t) > window {
			cut++
		}
		r.trend = r.trend[cut:]
		r.last.TimeToFull = timeToFull(r.trend, float64(free))
	}
}

var (
	errFDCount = errors.New("the descriptor count could not be read (at the descriptor limit?)")
	errMemRead = errors.New("the daemon's memory could not be read")
)

// minTrendSpan is the shortest history a projection is made from.
const minTrendSpan = time.Minute

// timeToFull fits a least-squares line to the points and projects when free
// reaches 0; 0 when it is not falling or the history is too short.
func timeToFull(pts []point, free float64) time.Duration {
	if len(pts) < 3 || pts[len(pts)-1].t.Sub(pts[0].t) < minTrendSpan {
		return 0
	}
	t0 := pts[0].t
	var sx, sy, sxx, sxy float64
	n := float64(len(pts))
	for _, p := range pts {
		x := p.t.Sub(t0).Seconds()
		sx += x
		sy += p.free
		sxx += x * x
		sxy += x * p.free
	}
	den := n*sxx - sx*sx
	if den == 0 {
		return 0
	}
	slope := (n*sxy - sx*sy) / den // per second
	if slope >= 0 {
		return 0
	}
	secs := free / -slope
	const maxProjection = 10 * 365 * 24 * time.Hour
	if secs > maxProjection.Seconds() {
		return 0
	}
	return time.Duration(secs * float64(time.Second))
}

// Report is the current state. It never samples.
func (s *Sampler) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	rep := s.reportLocked()
	frozen := rep.SampledAt.IsZero() || s.now().Sub(rep.SampledAt) > staleIntervals*time.Duration(s.cfg.SampleIntervalSec)*time.Second
	rep.Stale = rep.Stale || frozen
	return rep
}

func (s *Sampler) reportLocked() Report {
	rep := Report{Level: s.hostLevel, Since: s.hostSince, SampledAt: s.sampledAt, PoolsStale: s.poolsStale, Stale: s.poolsStale}
	for _, r := range s.res {
		rr := r.last
		rr.Name, rr.Unit, rr.Level, rr.Since = r.name, r.unit, r.m.level, r.m.since
		rep.Resources = append(rep.Resources, rr)
		if rr.TimeToFull > 0 && (rep.TimeToFull == 0 || rr.TimeToFull < rep.TimeToFull) {
			rep.TimeToFull = rr.TimeToFull
		}
	}
	sort.Slice(rep.Resources, func(i, j int) bool { return rep.Resources[i].Name < rep.Resources[j].Name })
	return rep
}
