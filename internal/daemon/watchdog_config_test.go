package daemon

import (
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

// wireWatchdog gives the heartbeat's controller the marker directory, the
// DB round trip and the configured threshold, and wirePauserLiveness the
// pauser's progress; Run calls both.
//
// Mutations: drop any Set call from wireWatchdog or wirePauserLiveness, or
// either call from Run, and this goes red.
func TestRun_WiresTheWatchdogController(t *testing.T) {
	d := &Daemon{cfg: &Config{Watchdog: WatchdogConfig{LivenessStaleSec: 300}}, db: corrosion.NewTestClientT(t),
		watchdogRunDir: t.TempDir()}
	ctrl := watchdog.NewController()
	d.wireWatchdog(ctrl)
	if ctrl.RunDir() != d.watchdogRunDir {
		t.Fatalf("run dir = %q, want %q", ctrl.RunDir(), d.watchdogRunDir)
	}
	db, pauser, stale := ctrl.LivenessWiring()
	if !db || pauser || stale != 300*time.Second {
		t.Fatalf("after wireWatchdog: db=%v pauser=%v stale=%v, want db, no pauser yet, 300s", db, pauser, stale)
	}
	wirePauserLiveness(ctrl, health.NewPartitionPauser("h", t.TempDir(), d.db))
	if _, pauser, _ := ctrl.LivenessWiring(); !pauser {
		t.Fatal("wirePauserLiveness did not wire the pauser's progress")
	}
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
				switch fun := c.Fun.(type) {
				case *ast.SelectorExpr:
					calls[fun.Sel.Name] = true
				case *ast.Ident:
					calls[fun.Name] = true
				}
			}
			return true
		})
	}
	for _, want := range []string{"wireWatchdog", "wirePauserLiveness"} {
		if !calls[want] {
			t.Errorf("Daemon.Run does not call %s", want)
		}
	}
}
