package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirt"
)

// failedVars makes a vars file and a flush failure that identifies it.
func failedVars(t *testing.T, dir, vm string) libvirt.NvramFlushFailure {
	t.Helper()
	p := filepath.Join(dir, vm+"_VARS.fd")
	if err := os.WriteFile(p, []byte("v"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	return libvirt.NvramFlushFailure{Path: p, VM: vm, Error: "input/output error", Dev: uint64(st.Dev), Ino: st.Ino}
}

func nvramTestDaemon(t *testing.T) (*Daemon, *corrosion.Client) {
	t.Helper()
	db := corrosion.NewTestClientT(t)
	if err := corrosion.InitSchema(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	return &Daemon{db: db, cfg: &Config{HostName: "h1"}}, db
}

func nvramCondition(t *testing.T, db *corrosion.Client, code string) (corrosion.HealthCondition, bool) {
	t.Helper()
	row, found, err := corrosion.GetHealthCondition(context.Background(), db, nvramFlushEvaluator, code, "host", "h1")
	if err != nil {
		t.Fatal(err)
	}
	return row, found && row.Lifecycle != corrosion.ConditionResolved
}

// A vars file whose fsync failed raises nvram_flush_failed (critical) about
// this host, naming the file, its VM and a remedy that names real commands;
// the failure survives a daemon restart through the condition's evidence; the
// condition resolves once the file is gone.
func TestNvramFlushCondition_RaisedSurvivesRestartAndResolves(t *testing.T) {
	ctx := context.Background()
	d, db := nvramTestDaemon(t)
	dir := t.TempDir()
	fail := failedVars(t, dir, "web-1")

	f := libvirt.NewNvramFlusher(dir)
	f.Seed([]libvirt.NvramFlushFailure{fail})
	var st nvramConditionState
	d.nvramFlushTick(ctx, f, &st)

	row, open := nvramCondition(t, db, CondNvramFlushFailed)
	if !open {
		t.Fatalf("condition after a failed flush: %+v", row)
	}
	if row.Severity != corrosion.SeverityCritical {
		t.Fatalf("severity %q, want critical", row.Severity)
	}
	for _, want := range []string{fail.Path, `"vm":"web-1"`, "lv rm", "lv snapshot restore", "lv backup restore-from", "does not clear"} {
		if !strings.Contains(row.Evidence, want) {
			t.Fatalf("evidence lacks %q: %s", want, row.Evidence)
		}
	}

	// A restart: the new flusher knows nothing until it is seeded from the
	// open condition.
	g := libvirt.NewNvramFlusher(dir)
	var st2 nvramConditionState
	d.nvramFlushTick(ctx, g, &st2)
	if got := g.Failures(); len(got) != 1 || got[0].Path != fail.Path {
		t.Fatalf("after a restart the flusher holds %+v; want %s", got, fail.Path)
	}

	// The file is removed: the condition resolves.
	g.Sweep()
	if err := os.Remove(fail.Path); err != nil {
		t.Fatal(err)
	}
	g.Sweep()
	d.nvramFlushTick(ctx, g, &st2)
	if row, open := nvramCondition(t, db, CondNvramFlushFailed); open {
		t.Fatalf("condition after the file was removed: %+v", row)
	}
}

// A condition write that fails is retried on the next tick, although the
// failures have not changed.
func TestNvramFlushCondition_FailedWriteIsRetried(t *testing.T) {
	ctx := context.Background()
	d, db := nvramTestDaemon(t)
	dir := t.TempDir()
	f := libvirt.NewNvramFlusher(dir)
	f.Seed([]libvirt.NvramFlushFailure{failedVars(t, dir, "web-1")})

	for _, q := range []string{
		`CREATE TRIGGER nvd_block_i BEFORE INSERT ON health_conditions BEGIN SELECT RAISE(ABORT, 'disk gone'); END`,
		`CREATE TRIGGER nvd_block_u BEFORE UPDATE ON health_conditions BEGIN SELECT RAISE(ABORT, 'disk gone'); END`,
	} {
		if _, err := db.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	var st nvramConditionState
	d.nvramFlushTick(ctx, f, &st)
	if _, open := nvramCondition(t, db, CondNvramFlushFailed); open {
		t.Fatal("condition written through a failing database")
	}
	for _, q := range []string{`DROP TRIGGER nvd_block_i`, `DROP TRIGGER nvd_block_u`} {
		if _, err := db.DB().Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	d.nvramFlushTick(ctx, f, &st)
	if row, open := nvramCondition(t, db, CondNvramFlushFailed); !open {
		t.Fatalf("a failed condition write was not retried: %+v", row)
	}
}

// A failure carried over a restart is not dropped by a database read that
// fails at startup: nothing is resolved until the condition has been read,
// and the seed is retried. Evidence that cannot be parsed keeps the
// condition raised.
func TestNvramFlushCondition_UnreadSeedNeverResolves(t *testing.T) {
	ctx := context.Background()
	d, db := nvramTestDaemon(t)
	dir := t.TempDir()
	fail := failedVars(t, dir, "web-1")
	f := libvirt.NewNvramFlusher(dir)
	f.Seed([]libvirt.NvramFlushFailure{fail})
	var st nvramConditionState
	d.nvramFlushTick(ctx, f, &st)

	readErr := errors.New("database is locked")
	old := readNvramFlushCondition
	t.Cleanup(func() { readNvramFlushCondition = old })
	readNvramFlushCondition = func(ctx context.Context, c *corrosion.Client, ev, code, kind, id string) (corrosion.HealthCondition, bool, error) {
		if readErr != nil {
			return corrosion.HealthCondition{}, false, readErr
		}
		return old(ctx, c, ev, code, kind, id)
	}

	g := libvirt.NewNvramFlusher(dir)
	var st2 nvramConditionState
	d.nvramFlushTick(ctx, g, &st2)
	if _, open := nvramCondition(t, db, CondNvramFlushFailed); !open {
		t.Fatal("a failed read at startup resolved the carried-over failure")
	}
	readErr = nil
	d.nvramFlushTick(ctx, g, &st2)
	if got := g.Failures(); len(got) != 1 {
		t.Fatalf("seed not retried after the read recovered: %+v", got)
	}

	// Unparseable evidence: kept raised.
	if _, err := db.DB().Exec(`UPDATE health_conditions SET evidence = 'not json' WHERE code = ?`, CondNvramFlushFailed); err != nil {
		t.Fatal(err)
	}
	h := libvirt.NewNvramFlusher(dir)
	var st3 nvramConditionState
	d.nvramFlushTick(ctx, h, &st3)
	d.nvramFlushTick(ctx, h, &st3)
	if _, open := nvramCondition(t, db, CondNvramFlushFailed); !open {
		t.Fatal("unparseable evidence resolved the condition")
	}
}

// A vars file blocked from being flushed raises nvram_flush_blocked
// (warning), naming it, and resolves once it is flushed again.
func TestNvramFlushCondition_BlockedFileRaisesAWarning(t *testing.T) {
	ctx := context.Background()
	d, db := nvramTestDaemon(t)
	var st nvramConditionState
	st.seeded = true
	d.syncNvramCondition(ctx, CondNvramFlushBlocked, corrosion.SeverityWarning,
		[]libvirt.NvramFlushFailure{{Path: "/x/vm1_VARS.fd", VM: "vm1", Error: "permission denied"}}, nvramFlushBlockedRemedy, &st.lastBlocked)
	row, open := nvramCondition(t, db, CondNvramFlushBlocked)
	if !open || row.Severity != corrosion.SeverityWarning || !strings.Contains(row.Evidence, "vm1_VARS.fd") {
		t.Fatalf("blocked condition: open=%v %+v", open, row)
	}
	d.syncNvramCondition(ctx, CondNvramFlushBlocked, corrosion.SeverityWarning, nil, nvramFlushBlockedRemedy, &st.lastBlocked)
	if _, open := nvramCondition(t, db, CondNvramFlushBlocked); open {
		t.Fatal("blocked condition not resolved once nothing is blocked")
	}
}

// The daemon flushes litevirt's vars directory and libvirt's.
func TestNvramDirs(t *testing.T) {
	got := nvramDirs("/srv/lv")
	want := []string{"/var/lib/libvirt/qemu/nvram", "/srv/lv/nvram"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("nvramDirs = %v, want %v", got, want)
	}
	if got := nvramDirs(""); len(got) != 1 {
		t.Fatalf("no data dir: nvramDirs = %v, want libvirt's only", got)
	}
}

// Stopping the flusher waits for its last sweep, but not forever.
func TestStopAndWait_WaitsForDoneWithinTheBound(t *testing.T) {
	done := make(chan struct{})
	cancelled := false
	go func() { time.Sleep(100 * time.Millisecond); close(done) }()
	start := time.Now()
	stopAndWait(func() { cancelled = true }, done, 5*time.Second)
	if !cancelled {
		t.Fatal("stopAndWait did not cancel")
	}
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Fatalf("returned after %v, before the last sweep finished", el)
	}

	start = time.Now()
	stopAndWait(func() {}, make(chan struct{}), 50*time.Millisecond)
	if el := time.Since(start); el > 2*time.Second {
		t.Fatalf("a stuck sweep held the stop for %v", el)
	}
}
