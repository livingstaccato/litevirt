package daemon

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/watchdog"
)

func loadWithYAML(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	cp := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITEVIRT_CONFIG", cp)
	if err := os.WriteFile(cp, []byte("host_name: h\n"+yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	return LoadConfig()
}

// The watchdog block's defaults are the owner's ruling (300 s, 5 boots,
// 120 s per boot, a 120 s liveness threshold), a partial block keeps the
// defaults it omits, and the keeper's options map one to one.
//
// Mutation: change any default, or the mapping in bootKeeperOptions, and
// this goes red.
func TestWatchdogConfig_Defaults(t *testing.T) {
	cfg, err := loadWithYAML(t, "")
	if err != nil {
		t.Fatal(err)
	}
	want := WatchdogConfig{BootKeeperStreakWindowSec: 300, BootKeeperMaxBoots: 5, BootKeeperMaxSec: 120, LivenessStaleSec: 120}
	if cfg.Watchdog != want {
		t.Fatalf("defaults = %+v, want %+v", cfg.Watchdog, want)
	}
	cfg, err = loadWithYAML(t, "watchdog:\n  boot_keeper_max_boots: 3\n")
	if err != nil {
		t.Fatal(err)
	}
	want.BootKeeperMaxBoots = 3
	if cfg.Watchdog != want {
		t.Fatalf("a partial block = %+v, want %+v", cfg.Watchdog, want)
	}
	o := bootKeeperOptions(cfg)
	if o.RunDir != watchdog.RunDir || o.Configured || o.StreakWindow != 300*time.Second || o.MaxBoots != 3 || o.MaxDuration != 120*time.Second {
		t.Fatalf("bootKeeperOptions = %+v", o)
	}
	cfg.WatchdogDev = "/dev/watchdog0"
	if !bootKeeperOptions(cfg).Configured {
		t.Fatal("bootKeeperOptions: a configured watchdog_dev is not Configured")
	}
}

// Load refuses a negative bound and a liveness threshold inside twice the
// hardware timeout; 0 (off) and the minimum load.
//
// Mutation: drop cfg.Watchdog.validate() from LoadConfig and this goes red.
func TestWatchdogConfig_Validation(t *testing.T) {
	for _, bad := range []string{
		"watchdog:\n  boot_keeper_streak_window_sec: -1\n",
		"watchdog:\n  boot_keeper_max_boots: -1\n",
		"watchdog:\n  boot_keeper_max_sec: -1\n",
		"watchdog:\n  liveness_stale_sec: -1\n",
		"watchdog:\n  liveness_stale_sec: 60\n",
		"watchdog:\n  liveness_stale_sec: 119\n",
	} {
		if _, err := loadWithYAML(t, bad); err == nil {
			t.Errorf("LoadConfig accepted %q", bad)
		}
	}
	for _, ok := range []string{
		"watchdog:\n  liveness_stale_sec: 0\n",
		"watchdog:\n  liveness_stale_sec: 120\n",
		"watchdog:\n  boot_keeper_max_boots: 0\n",
	} {
		if _, err := loadWithYAML(t, ok); err != nil {
			t.Errorf("LoadConfig refused %q: %v", ok, err)
		}
	}
}

// startWatchdog wires the heartbeat's controller before it starts the
// heartbeat on it, and wirePauserLiveness adds the pauser to that same
// controller. Pinned by behaviour: a daemon restarted after its host
// self-fenced must not pet the watchdog (the marker in the run directory
// reaches the heartbeat only if wiring came first), and the controller
// startWatchdog returns carries the DB probe, the configured threshold and,
// once wired, the pauser. Run calls both.
//
// Mutations: start the heartbeat before wireWatchdog, or on another
// controller — the restarted daemon pets past its marker; wire the pauser or
// the DB probe into another controller, or drop a Set call or a call from
// Run — the matching check goes red.
func TestRun_WiresTheWatchdogController(t *testing.T) {
	dev := filepath.Join(t.TempDir(), "watchdog0")
	if err := os.WriteFile(dev, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(runDir, "self-fenced"), []byte("earlier run\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d := &Daemon{cfg: &Config{WatchdogDev: dev, Watchdog: WatchdogConfig{LivenessStaleSec: 300}},
		db: corrosion.NewTestClientT(t), watchdogRunDir: runDir}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctrl := d.startWatchdog(ctx, func() bool { return true })
	deadline := time.Now().Add(2 * time.Second)
	for !ctrl.Fenced() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !ctrl.Fenced() {
		t.Fatal("a daemon restarted after a self-fence did not start fenced")
	}
	time.Sleep(50 * time.Millisecond)
	if b, _ := os.ReadFile(dev); len(b) != 0 {
		t.Fatalf("a daemon restarted after a self-fence wrote %q to the watchdog", b)
	}
	if ctrl.RunDir() != runDir {
		t.Fatalf("run dir = %q, want %q", ctrl.RunDir(), runDir)
	}
	db, pauser, stale := ctrl.LivenessWiring()
	if !db || pauser || stale != 300*time.Second {
		t.Fatalf("after startWatchdog: db=%v pauser=%v stale=%v, want db, no pauser yet, 300s", db, pauser, stale)
	}
	d.wirePauserLiveness(health.NewPartitionPauser("h", t.TempDir(), d.db))
	if _, pauser, _ := ctrl.LivenessWiring(); !pauser {
		t.Fatal("wirePauserLiveness did not wire the pauser into the heartbeat's controller")
	}

	// liveness_stale_sec 0 turns the gate off.
	d.cfg.Watchdog.LivenessStaleSec = 0
	off := watchdog.NewController()
	d.wireWatchdog(off)
	if _, _, stale := off.LivenessWiring(); stale >= 0 {
		t.Fatalf("liveness_stale_sec 0 left the gate on (stale %v)", stale)
	}

	// Run itself calls both.
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	calls := map[string]bool{}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Run" || fn.Recv == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
					if x, ok := sel.X.(*ast.Ident); ok && x.Name == "d" {
						calls[sel.Sel.Name] = true
					}
				}
			}
			return true
		})
	}
	for _, want := range []string{"startWatchdog", "wirePauserLiveness"} {
		if !calls[want] {
			t.Errorf("Daemon.Run does not call d.%s", want)
		}
	}
}

// The DB probe the daemon wires is a real round trip through the state
// store's client: it completes on an idle client, and while a writer holds
// the client's lock it waits behind it past its own timeout, so the gate's
// counter stands still (watchdog.SetDBProbe) and a lock left held past the
// threshold self-fences.
//
// Mutations: make the probe a no-op, or have it stop waiting for the lock at
// its timeout, and the held-lock check goes red; have it drop Query's error
// and the deadline check goes red.
func TestWireWatchdog_DBProbeWaitsBehindAHeldWriteLock(t *testing.T) {
	d := &Daemon{cfg: &Config{Watchdog: WatchdogConfig{LivenessStaleSec: 120}},
		db: corrosion.NewTestClientT(t), watchdogRunDir: t.TempDir()}
	ctrl := watchdog.NewController()
	d.wireWatchdog(ctrl)
	probe := ctrl.LivenessDBProbe()
	if probe == nil {
		t.Fatal("wireWatchdog wired no DB probe")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := probe(ctx); err != nil {
		t.Fatalf("the probe failed on an idle client: %v", err)
	}

	mu := d.db.Mu()
	mu.Lock()
	locked := true
	defer func() {
		if locked {
			mu.Unlock()
		}
	}()
	const timeout = 50 * time.Millisecond
	done := make(chan error, 1)
	go func() {
		pctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		done <- probe(pctx)
	}()
	select {
	case err := <-done:
		t.Fatalf("the probe returned (%v) while a writer held the client's lock: the gate would count a held lock as progress", err)
	case <-time.After(10 * timeout):
	}
	mu.Unlock()
	locked = false
	select {
	case err := <-done:
		// It got the lock past its timeout: an error, which the gate does not
		// count as progress (watchdog.SetDBProbe).
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("the probe that waited past its timeout returned %v, want a deadline error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the probe did not return once the writer released the lock")
	}
}
