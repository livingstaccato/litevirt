package pressure

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

const gib = uint64(1) << 30

// fakeFS is a per-node statfs: each path answers what the test set.
type fakeFS struct {
	mu   sync.Mutex
	stat map[string]FSStat
	err  map[string]error
}

func newFakeFS() *fakeFS { return &fakeFS{stat: map[string]FSStat{}, err: map[string]error{}} }

func (f *fakeFS) Statfs(path string) (FSStat, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.err[path]; err != nil {
		return FSStat{}, err
	}
	st, ok := f.stat[path]
	if !ok {
		return FSStat{}, errors.New("no such path")
	}
	return st, nil
}

// setFree gives path a filesystem of total bytes with pct percent free, and
// plenty of inodes.
func (f *fakeFS) setFree(path string, total uint64, pct float64) {
	f.set(path, FSStat{TotalBytes: total, AvailBytes: uint64(float64(total) * pct / 100), TotalInodes: 1000, FreeInodes: 900})
}

func (f *fakeFS) set(path string, st FSStat) {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.err, path)
	f.stat[path] = st
}

func (f *fakeFS) fail(path string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.err[path] = err
}

// fakeClock is a manual clock.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) step(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type rig struct {
	fs    *fakeFS
	clk   *fakeClock
	s     *Sampler
	pools []Pool
}

// newRig is a sampler over /data on a fake FS (100 GiB, 50% free), the
// default config, a fake clock, no fd or memory resources.
func newRig(t *testing.T, mutate func(*Config)) *rig {
	t.Helper()
	cfg := DefaultConfig()
	if mutate != nil {
		mutate(&cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}
	r := &rig{fs: newFakeFS(), clk: &fakeClock{t: time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)}}
	r.fs.setFree("/data", 100*gib, 50)
	r.s = NewSampler(cfg, "/data", Options{
		FS:    r.fs,
		Now:   r.clk.now,
		Pools: func(context.Context) []Pool { return r.pools },
		FDs:   func() (uint64, uint64, bool) { return 0, 0, false },
		Mem:   func() (uint64, bool) { return 0, false },
	})
	return r
}

// tick takes one sample, then moves the clock one interval.
func (r *rig) tick(t *testing.T) Report {
	t.Helper()
	r.s.Sample(context.Background())
	rep := r.s.Report()
	r.clk.step(time.Duration(r.s.cfg.SampleIntervalSec) * time.Second)
	return rep
}

func resourceLevel(t *testing.T, rep Report, name string) Level {
	t.Helper()
	for _, res := range rep.Resources {
		if res.Name == name {
			return res.Level
		}
	}
	t.Fatalf("report has no resource %q: %+v", name, rep.Resources)
	return OK
}

func findResource(rep Report, name string) (ResourceReport, bool) {
	for _, res := range rep.Resources {
		if res.Name == name {
			return res, true
		}
	}
	return ResourceReport{}, false
}

func TestDefaultConfig_IsTheOwnersDefaults(t *testing.T) {
	cfg := DefaultConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, th := range map[string]FSThresholds{"data_dir": cfg.DataDir, "pools": cfg.Pools} {
		if th.WarnFreePct != 15 || th.DegradeFreePct != 8 || th.CriticalFreePct != 3 {
			t.Errorf("%s: percent defaults %v/%v/%v, want 15/8/3", name, th.WarnFreePct, th.DegradeFreePct, th.CriticalFreePct)
		}
		if th.WarnFreeMiB != 4096 || th.DegradeFreeMiB != 2048 || th.CriticalFreeMiB != 512 {
			t.Errorf("%s: floor defaults %v/%v/%v MiB, want 4096/2048/512", name, th.WarnFreeMiB, th.DegradeFreeMiB, th.CriticalFreeMiB)
		}
	}
	if !cfg.Enabled || cfg.EnterSamples != 2 || cfg.ClearAfterSec != 120 || cfg.ClearMarginPct != 2 || cfg.SampleIntervalSec != 5 {
		t.Errorf("defaults %+v", cfg)
	}
}

func TestLevel_EntersOnlyAfterEnterSamples(t *testing.T) {
	r := newRig(t, nil)
	r.fs.setFree("/data", 100*gib, 6) // degrade: < 8 %
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != OK {
		t.Fatalf("after 1 sample past the threshold: %v, want ok (enter_samples 2)", l)
	}
	rep := r.tick(t)
	if l := resourceLevel(t, rep, "data_dir.space"); l != Degrade {
		t.Fatalf("after 2 samples: %v, want degrade", l)
	}
	if rep.Level != Degrade {
		t.Fatalf("host level %v, want degrade", rep.Level)
	}
	if got := rep.Pressured(); len(got) != 1 || got[0] != "data_dir.space" {
		t.Fatalf("pressured resources %v, want [data_dir.space]", got)
	}
}

func TestLevel_OneSampleBackInsideResetsTheEnterRun(t *testing.T) {
	r := newRig(t, func(c *Config) { c.EnterSamples = 3 })
	for i, pct := range []float64{6, 6, 50, 6, 6} {
		r.fs.setFree("/data", 100*gib, pct)
		if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != OK {
			t.Fatalf("sample %d: %v, want ok: no 3 consecutive samples past the threshold", i, l)
		}
	}
	r.tick(t)
	if l := resourceLevel(t, r.s.Report(), "data_dir.space"); l != Degrade {
		t.Fatalf("third consecutive sample: %v, want degrade", l)
	}
}

func TestLevel_EntersTheLevelSustainedOverTheRun(t *testing.T) {
	r := newRig(t, nil)
	r.fs.setFree("/data", 100*gib, 1) // critical
	r.tick(t)
	r.fs.setFree("/data", 100*gib, 6) // degrade
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Degrade {
		t.Fatalf("critical then degrade: entered %v, want degrade (the level held for the whole run)", l)
	}
	r2 := newRig(t, nil)
	r2.fs.setFree("/data", 100*gib, 6) // degrade
	r2.tick(t)
	r2.fs.setFree("/data", 100*gib, 1) // critical
	if l := resourceLevel(t, r2.tick(t), "data_dir.space"); l != Degrade {
		t.Fatalf("degrade then critical: entered %v, want degrade (critical held for one sample only)", l)
	}
}

func TestLevel_ClearsOnlyAfterMarginAndDwell(t *testing.T) {
	r := newRig(t, nil)
	r.fs.setFree("/data", 100*gib, 6)
	r.tick(t)
	r.tick(t)
	// Better than the degrade threshold (8 %), but inside the 2-point margin:
	// never clears, however long it stays.
	r.fs.setFree("/data", 100*gib, 9)
	for i := 0; i < 60; i++ {
		if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Degrade {
			t.Fatalf("inside the clear margin after %d samples: %v, want degrade", i, l)
		}
	}
	// Past the margin: clears only after clear_after_sec (120 s = 24 samples
	// of 5 s), and then to warn, the level 10.5 % is at.
	r.fs.setFree("/data", 100*gib, 10.5)
	for i := 0; i < 24; i++ {
		if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Degrade {
			t.Fatalf("sample %d past the margin (%v in): %v, want degrade until 120 s", i, time.Duration(i*5)*time.Second, l)
		}
	}
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Warn {
		t.Fatalf("after 120 s past the margin: %v, want warn", l)
	}
}

func TestLevel_ARelapseRestartsTheClearDwell(t *testing.T) {
	r := newRig(t, nil)
	r.fs.setFree("/data", 100*gib, 6)
	r.tick(t)
	r.tick(t)
	r.fs.setFree("/data", 100*gib, 50)
	for i := 0; i < 20; i++ { // 100 s clean
		r.tick(t)
	}
	r.fs.setFree("/data", 100*gib, 9) // one sample back inside the margin
	r.tick(t)
	r.fs.setFree("/data", 100*gib, 50)
	for i := 0; i < 24; i++ {
		if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Degrade {
			t.Fatalf("sample %d after the relapse: %v, want degrade: the dwell starts again", i, l)
		}
	}
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != OK {
		t.Fatalf("a full dwell after the relapse: %v, want ok", l)
	}
}

func TestLevel_FlappingAroundAThresholdDoesNotOscillate(t *testing.T) {
	r := newRig(t, nil)
	changes, last := 0, OK
	for i := 0; i < 200; i++ {
		pct := 7.9
		if i%2 == 1 {
			pct = 8.1
		}
		r.fs.setFree("/data", 100*gib, pct)
		l := resourceLevel(t, r.tick(t), "data_dir.space")
		if l != last {
			changes++
			last = l
		}
	}
	// It enters warn on the first two samples (both are under 15 %) and
	// never degrade (7.9 % is never two samples running); it never clears.
	if changes != 1 || last != Warn {
		t.Fatalf("flapping 7.9/8.1 %%: %d level changes ending at %v, want exactly one (to warn)", changes, last)
	}
	r2 := newRig(t, nil)
	r2.fs.setFree("/data", 100*gib, 6)
	r2.tick(t)
	r2.tick(t)
	for i := 0; i < 200; i++ {
		pct := 7.9
		if i%2 == 1 {
			pct = 8.1
		}
		r2.fs.setFree("/data", 100*gib, pct)
		if l := resourceLevel(t, r2.tick(t), "data_dir.space"); l != Degrade {
			t.Fatalf("flapping across 8 %% at degrade, sample %d: %v, want degrade held", i, l)
		}
	}
}

func TestLevel_AbsoluteFloorEntersOnASmallFilesystem(t *testing.T) {
	r := newRig(t, nil)
	// 10 GiB with 3 GiB free is 30 %: no percentage is crossed, but the
	// 4 GiB warn floor is.
	r.fs.set("/data", FSStat{TotalBytes: 10 * gib, AvailBytes: 3 * gib, TotalInodes: 10, FreeInodes: 9})
	r.tick(t)
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Warn {
		t.Fatalf("3 GiB free of 10: %v, want warn by the 4 GiB floor", l)
	}
	// Clearing a floor needs 25 % of it beyond: 4.5 GiB free is past the
	// floor but not by 1 GiB, so it holds.
	r.fs.set("/data", FSStat{TotalBytes: 10 * gib, AvailBytes: 9 * gib / 2, TotalInodes: 10, FreeInodes: 9})
	for i := 0; i < 40; i++ {
		if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Warn {
			t.Fatalf("4.5 GiB free: %v, want warn held inside the floor's margin", l)
		}
	}
	r.fs.set("/data", FSStat{TotalBytes: 10 * gib, AvailBytes: 6 * gib, TotalInodes: 10, FreeInodes: 9})
	for i := 0; i < 25; i++ {
		r.tick(t)
	}
	if l := resourceLevel(t, r.s.Report(), "data_dir.space"); l != OK {
		t.Fatalf("6 GiB free for 125 s: %v, want ok", l)
	}
}

func TestLevel_ZeroThresholdIsOff(t *testing.T) {
	r := newRig(t, func(c *Config) {
		c.DataDir.WarnFreePct, c.DataDir.WarnFreeMiB = 0, 0
	})
	r.fs.setFree("/data", 100*gib, 10)
	r.tick(t)
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != OK {
		t.Fatalf("warn off, 10 %% free: %v, want ok", l)
	}
}

func TestSampler_Inodes(t *testing.T) {
	r := newRig(t, nil)
	r.fs.set("/data", FSStat{TotalBytes: 100 * gib, AvailBytes: 50 * gib, TotalInodes: 1000, FreeInodes: 40}) // 4 %
	r.tick(t)
	if l := resourceLevel(t, r.tick(t), "data_dir.inodes"); l != Degrade {
		t.Fatalf("4 %% inodes free: %v, want degrade (< 5 %%)", l)
	}
	// A filesystem without an inode count (btrfs) has no inode resource.
	r.fs.set("/data", FSStat{TotalBytes: 100 * gib, AvailBytes: 50 * gib})
	if _, ok := findResource(r.tick(t), "data_dir.inodes"); ok {
		t.Fatal("f_files 0: data_dir.inodes still reported, want it skipped")
	}
}

func TestSampler_StatfsErrorKeepsTheLevelAndBreaksBothRuns(t *testing.T) {
	r := newRig(t, nil)
	r.fs.setFree("/data", 100*gib, 6)
	r.tick(t)
	r.fs.fail("/data", errors.New("statfs: no answer"))
	rep := r.tick(t)
	res, _ := findResource(rep, "data_dir.space")
	if res.Level != OK || !strings.Contains(res.Err, "no answer") {
		t.Fatalf("after an error: %+v, want ok with the error recorded", res)
	}
	r.fs.setFree("/data", 100*gib, 6)
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != OK {
		t.Fatalf("one sample after the error: %v, want ok: the error broke the run", l)
	}
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Degrade {
		t.Fatalf("two clean samples: %v, want degrade", l)
	}
	r.fs.fail("/data", errors.New("statfs: no answer"))
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Degrade {
		t.Fatalf("an error at degrade: %v, want degrade kept", l)
	}
}

func TestSampler_PoolsAndPerPoolOverride(t *testing.T) {
	twenty, twentyFive := 20.0, 25.0
	r := newRig(t, func(c *Config) {
		c.PoolOverrides = map[string]FSOverride{"fast": {WarnFreePct: &twentyFive, DegradeFreePct: &twenty}}
	})
	r.pools = []Pool{{Name: "fast", Path: "/pools/fast"}, {Name: "slow", Path: "/pools/slow"}}
	r.fs.setFree("/pools/fast", 1000*gib, 18)
	r.fs.setFree("/pools/slow", 1000*gib, 18)
	r.tick(t)
	rep := r.tick(t)
	if l := resourceLevel(t, rep, "pool.fast.space"); l != Degrade {
		t.Errorf("pool fast at 18 %% with degrade_free_pct 20: %v, want degrade", l)
	}
	if l := resourceLevel(t, rep, "pool.slow.space"); l != OK {
		t.Errorf("pool slow at 18 %% with the defaults: %v, want ok", l)
	}
	if rep.Level != Degrade {
		t.Errorf("host level %v, want degrade (the max)", rep.Level)
	}
	// A pool that goes away takes its resources with it.
	r.pools = r.pools[1:]
	rep = r.tick(t)
	if _, ok := findResource(rep, "pool.fast.space"); ok {
		t.Error("pool fast removed: still reported")
	}
	if rep.Level != OK {
		t.Errorf("host level %v after the pressured pool went, want ok", rep.Level)
	}
}

func TestSampler_TimeToFull(t *testing.T) {
	r := newRig(t, nil)
	// 1000 GiB, falling 1 GiB per 5 s sample from 500 GiB free.
	free := 500 * gib
	var rep Report
	for i := 0; i < 20; i++ {
		r.fs.set("/data", FSStat{TotalBytes: 1000 * gib, AvailBytes: free, TotalInodes: 10, FreeInodes: 9})
		rep = r.tick(t)
		free -= gib
	}
	res, _ := findResource(rep, "data_dir.space")
	// 481 GiB left at 1 GiB / 5 s: 2405 s.
	want := 2405 * time.Second
	if d := res.TimeToFull - want; d < -10*time.Second || d > 10*time.Second {
		t.Fatalf("time to full %v, want about %v", res.TimeToFull, want)
	}
	if rep.TimeToFull != res.TimeToFull {
		t.Fatalf("host time to full %v, want the shortest resource's %v", rep.TimeToFull, res.TimeToFull)
	}
	// Steady: no projection.
	for i := 0; i < 200; i++ {
		rep = r.tick(t)
	}
	if res, _ := findResource(rep, "data_dir.space"); res.TimeToFull != 0 {
		t.Fatalf("steady for the whole window: time to full %v, want 0", res.TimeToFull)
	}
}

func TestSampler_FDsAndDaemonMemory(t *testing.T) {
	r := newRig(t, func(c *Config) { c.Memory.DaemonLimitMiB = 1000 })
	used := uint64(90)
	mem := uint64(500 << 20)
	r.s.fds = func() (uint64, uint64, bool) { return used, 100, true }
	r.s.mem = func() (uint64, bool) { return mem, true }
	r.tick(t)
	rep := r.tick(t)
	if l := resourceLevel(t, rep, "fds.daemon"); l != Degrade {
		t.Errorf("90 of 100 fds: %v, want degrade (> 85 %%)", l)
	}
	if l := resourceLevel(t, rep, "memory.daemon"); l != OK {
		t.Errorf("500 of 1000 MiB: %v, want ok (warn > 60 %%)", l)
	}
	mem = 950 << 20
	r.tick(t)
	if l := resourceLevel(t, r.tick(t), "memory.daemon"); l != Critical {
		t.Errorf("950 of 1000 MiB: %v, want critical (> 90 %%)", l)
	}
}

func TestSampler_HostLevelSince(t *testing.T) {
	r := newRig(t, nil)
	r.fs.setFree("/data", 100*gib, 6)
	r.tick(t)
	entered := r.clk.now()
	rep := r.tick(t)
	if !rep.Since.Equal(entered) {
		t.Fatalf("since %v, want the sample that entered degrade (%v)", rep.Since, entered)
	}
	rep = r.tick(t)
	if !rep.Since.Equal(entered) {
		t.Fatalf("since moved to %v while the level held", rep.Since)
	}
}

func TestConfig_ValidateRejects(t *testing.T) {
	for name, mutate := range map[string]func(*Config){
		"interval":         func(c *Config) { c.SampleIntervalSec = 0 },
		"enter":            func(c *Config) { c.EnterSamples = 0 },
		"margin":           func(c *Config) { c.ClearMarginPct = -1 },
		"clear after":      func(c *Config) { c.ClearAfterSec = -1 },
		"trend window":     func(c *Config) { c.TrendWindowSec = 30 },
		"pct over 100":     func(c *Config) { c.DataDir.WarnFreePct = 101 },
		"order pct":        func(c *Config) { c.DataDir.DegradeFreePct = 20 },
		"order mib":        func(c *Config) { c.Pools.CriticalFreeMiB = 9000 },
		"order inodes":     func(c *Config) { c.DataDir.CriticalFreeInodesPct = 50 },
		"order fds":        func(c *Config) { c.FDs.WarnPct = 99 },
		"memory negative":  func(c *Config) { c.Memory.DaemonLimitMiB = -1 },
		"override order":   func(c *Config) { v := 90.0; c.PoolOverrides = map[string]FSOverride{"p": {CriticalFreePct: &v}} },
		"override over100": func(c *Config) { v := 101.0; c.PoolOverrides = map[string]FSOverride{"p": {WarnFreePct: &v}} },
	} {
		cfg := DefaultConfig()
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s: Validate accepted %+v", name, cfg)
		}
	}
	// Off levels do not take part in the ordering.
	cfg := DefaultConfig()
	cfg.DataDir.DegradeFreePct, cfg.DataDir.DegradeFreeMiB = 0, 0
	if err := cfg.Validate(); err != nil {
		t.Errorf("degrade off: %v", err)
	}
}

// Run samples on its own goroutine while Ready reads the report from others.
func TestSampler_RunAndReportConcurrently(t *testing.T) {
	cfg := DefaultConfig()
	cfg.SampleIntervalSec = 1
	fs := newFakeFS()
	fs.setFree("/data", 100*gib, 6)
	s := NewSampler(cfg, "/data", Options{FS: fs, Pools: func(context.Context) []Pool { return []Pool{{Name: "p", Path: "/data"}} }})
	s.SetObserver(func(Report) {})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = s.Report().Pressured()
				s.Sample(context.Background())
			}
		}()
	}
	wg.Wait()
	cancel()
	<-done
	if l := s.Report().Level; l != Degrade {
		t.Fatalf("level %v after many samples at 6 %%, want degrade", l)
	}
}

// B1: a descriptor count that cannot be read (EMFILE: counting needs a
// descriptor) keeps the last level, as a failed statfs does. It never drops
// the resource, which would take the host from critical to ok in one sample.
func TestSampler_FDReadFailureKeepsTheLevel(t *testing.T) {
	r := newRig(t, nil)
	ok := true
	r.s.fds = func() (uint64, uint64, bool) { return 99, 100, ok }
	r.tick(t)
	if l := resourceLevel(t, r.tick(t), "fds.daemon"); l != Critical {
		t.Fatalf("99 of 100: %v, want critical", l)
	}
	ok = false
	rep := r.tick(t)
	res, found := findResource(rep, "fds.daemon")
	if !found || res.Level != Critical || res.Err == "" {
		t.Fatalf("count unreadable: %+v (found %v), want critical kept with the error recorded", res, found)
	}
	if rep.Level != Critical {
		t.Fatalf("host level %v, want critical kept", rep.Level)
	}
	// The same for the daemon's memory.
	r.s.mem = func() (uint64, bool) { return 0, false }
	r2 := newRig(t, func(c *Config) { c.Memory.DaemonLimitMiB = 100 })
	memOK := true
	r2.s.mem = func() (uint64, bool) { return 99 << 20, memOK }
	r2.tick(t)
	r2.tick(t)
	memOK = false
	if res, found := findResource(r2.tick(t), "memory.daemon"); !found || res.Level != Critical {
		t.Fatalf("memory unreadable: %+v (found %v), want critical kept", res, found)
	}
}

// B1 against the kernel: in a child process with RLIMIT_NOFILE 64, fill the
// table to the last descriptor. The real counter still answers (it reads a
// descriptor it holds open) and the level stays critical.
func TestSampler_FDsAtRealExhaustion(t *testing.T) {
	if os.Getenv("PRESSURE_FD_CHILD") != "1" {
		if runtime.GOOS != "linux" {
			t.Skip("counts /proc/self/fd")
		}
		cmd := exec.Command(os.Args[0], "-test.run=^TestSampler_FDsAtRealExhaustion$", "-test.v")
		cmd.Env = append(os.Environ(), "PRESSURE_FD_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		if !strings.Contains(string(out), "CHILD-OK") {
			t.Fatalf("child did not run the check:\n%s", out)
		}
		return
	}
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &syscall.Rlimit{Cur: 64, Max: 64}); err != nil {
		t.Fatalf("setrlimit: %v", err)
	}
	cfg := DefaultConfig()
	fs := newFakeFS()
	fs.setFree("/data", 100*gib, 50)
	s := NewSampler(cfg, "/data", Options{FS: fs, Mem: func() (uint64, bool) { return 0, false }})
	s.Sample(context.Background()) // opens the held counting descriptor while there is room
	var held []*os.File
	defer func() {
		for _, f := range held {
			f.Close()
		}
	}()
	for {
		f, err := os.Open("/dev/null")
		if err != nil {
			if !errors.Is(err, syscall.EMFILE) {
				t.Fatalf("open: %v", err)
			}
			break
		}
		held = append(held, f)
	}
	s.Sample(context.Background())
	s.Sample(context.Background())
	res, found := findResource(s.Report(), "fds.daemon")
	if !found || res.Level != Critical || res.Err != "" || res.Free != 0 {
		t.Fatalf("at EMFILE: %+v (found %v), want critical, counted, nothing free", res, found)
	}
	fmt.Println("CHILD-OK")
}

// B2: a pools read that does not return (a replica whose writer is stuck in a
// commit) does not stop the sample. The data directory is still graded, the
// last pool list is kept and marked stale, and the next completed read
// replaces it.
func TestSampler_StuckPoolsReadIsAbandoned(t *testing.T) {
	r := newRig(t, nil)
	r.s.poolsWait = 50 * time.Millisecond
	release := make(chan struct{})
	var stuck atomic.Bool
	r.s.pools = func(context.Context) []Pool {
		if stuck.Load() {
			<-release
		}
		return []Pool{{Name: "p", Path: "/pools/p"}}
	}
	r.fs.setFree("/pools/p", 100*gib, 50)
	r.tick(t)
	if r.s.Report().PoolsStale {
		t.Fatal("pools stale after a read that completed")
	}
	stuck.Store(true)
	r.fs.setFree("/data", 100*gib, 6)
	done := make(chan struct{})
	go func() {
		r.tick(t)
		r.tick(t)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Sample blocked behind a pools read that does not return")
	}
	rep := r.s.Report()
	if l := resourceLevel(t, rep, "data_dir.space"); l != Degrade {
		t.Fatalf("data_dir while the pools read hangs: %v, want degrade (still graded)", l)
	}
	if _, ok := findResource(rep, "pool.p.space"); !ok {
		t.Fatal("the last pool list was dropped while the read hangs")
	}
	if !rep.PoolsStale || !rep.Stale {
		t.Fatalf("report %+v, want pools stale and the report stale", rep)
	}
	close(release)
	stuck.Store(false)
	deadline := time.Now().Add(5 * time.Second)
	for r.s.Report().PoolsStale && time.Now().Before(deadline) {
		r.tick(t)
		time.Sleep(10 * time.Millisecond)
	}
	if r.s.Report().PoolsStale {
		t.Fatal("pools still stale after the read returned")
	}
}

// B2: the report says when it was sampled, and a sampler that stopped
// sampling (a frozen goroutine) reports stale.
func TestSampler_ReportIsStampedAndGoesStale(t *testing.T) {
	r := newRig(t, nil)
	at := r.clk.now()
	r.s.Sample(context.Background())
	rep := r.s.Report()
	if !rep.SampledAt.Equal(at) || rep.Stale {
		t.Fatalf("fresh report %+v, want sampled at %v and not stale", rep, at)
	}
	r.clk.step(3 * time.Duration(r.s.cfg.SampleIntervalSec) * time.Second)
	if r.s.Report().Stale {
		t.Fatal("stale at three intervals, want only past three")
	}
	r.clk.step(time.Second)
	if !r.s.Report().Stale {
		t.Fatal("no sample for more than three intervals: not stale")
	}
}

// P7: leaving a level goes to the WORST level seen during the dwell, not the
// mildest.
func TestLevel_ClearGoesToTheWorstLevelSeenInTheDwell(t *testing.T) {
	r := newRig(t, nil)
	r.fs.setFree("/data", 100*gib, 1)
	r.tick(t)
	r.tick(t)
	r.fs.setFree("/data", 100*gib, 50) // clear to ok...
	r.tick(t)
	r.fs.setFree("/data", 100*gib, 14) // ...then warn for the rest of the dwell
	// The dwell started at the 50 % sample; the 24th sample after it is 120 s
	// on, and the one that leaves critical. Checked there: a level that left
	// to ok would re-enter warn two samples later.
	for i := 0; i < 23; i++ {
		if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Critical {
			t.Fatalf("sample %d of the dwell: %v, want critical", i, l)
		}
	}
	if l := resourceLevel(t, r.tick(t), "data_dir.space"); l != Warn {
		t.Fatalf("critical cleared during a dwell that touched warn: %v, want warn", l)
	}
}

// P6: the auto daemon-memory limit is 10 % of RAM within [1 GiB, 4 GiB].
func TestAutoDaemonLimit(t *testing.T) {
	for ram, want := range map[uint64]uint64{0: 4 * gib, 4 * gib: gib, 16 * gib: 16 * gib / 10, 64 * gib: 4 * gib} {
		if got := autoDaemonLimit(ram); got != want {
			t.Errorf("RAM %d: limit %d, want %d", ram, got, want)
		}
	}
}

// Stop joins the run it ends, its pool-list read included: the read is
// cancelled with the sampler, and Stop returns only once it has returned, so
// nothing the read uses (the daemon's database) is used after Stop.
func TestSampler_StopJoinsAnInFlightPoolsRead(t *testing.T) {
	r := newRig(t, nil)
	r.s.poolsWait = 20 * time.Millisecond
	entered := make(chan struct{})
	var once sync.Once
	var sawCancel, returned atomic.Bool
	r.s.pools = func(ctx context.Context) []Pool {
		once.Do(func() { close(entered) })
		select {
		case <-ctx.Done():
			sawCancel.Store(true)
		case <-time.After(3 * time.Second):
		}
		// The read's tail still runs after it sees the cancel.
		time.Sleep(50 * time.Millisecond)
		returned.Store(true)
		return nil
	}
	r.s.Start(context.Background())
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the sampler never read its pool list")
	}
	r.s.Stop()
	if !returned.Load() {
		t.Fatal("Stop returned while the pool-list read was still running")
	}
	if !sawCancel.Load() {
		t.Fatal("the pool-list read never saw its context cancelled: it is not bound to the sampler's lifetime")
	}
}
