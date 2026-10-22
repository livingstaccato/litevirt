package daemon

import (
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pressure"
)

// The pressure block defaults to the owner's thresholds, a partial block keeps
// every default it does not name, an explicit false turns sampling off, and
// a pool override replaces only the fields it sets.
func TestLoadConfig_Pressure(t *testing.T) {
	if got := mustLoadConfigText(t, "").Pressure; !got.Enabled || got.DataDir != pressure.DefaultConfig().DataDir || got.Pools != pressure.DefaultConfig().Pools {
		t.Fatalf("no block: %+v, want the defaults", got)
	}
	got := mustLoadConfigText(t, "pressure:\n  data_dir:\n    warn_free_pct: 20\n").Pressure
	if !got.Enabled || got.DataDir.WarnFreePct != 20 || got.DataDir.DegradeFreePct != 8 || got.DataDir.WarnFreeMiB != 4096 || got.ClearAfterSec != 120 {
		t.Fatalf("partial block: %+v, want warn 20 and every other default", got)
	}
	if mustLoadConfigText(t, "pressure:\n  enabled: false\n").Pressure.Enabled {
		t.Fatal("enabled: false did not turn it off")
	}
	got = mustLoadConfigText(t, "pressure:\n  pool_overrides:\n    fast:\n      warn_free_pct: 30\n      degrade_free_pct: 20\n").Pressure
	if th := got.PoolThresholds("fast"); th.WarnFreePct != 30 || th.DegradeFreePct != 20 || th.CriticalFreePct != 3 || th.CriticalFreeMiB != 512 {
		t.Fatalf("pool override: %+v, want 30/20/3 with the default floors", th)
	}
	if th := got.PoolThresholds("slow"); th != pressure.DefaultConfig().Pools {
		t.Fatalf("a pool without an override: %+v, want the pools defaults", th)
	}
	_, err := loadConfigText(t, "pressure:\n  data_dir:\n    degrade_free_pct: 30\n")
	if err == nil || !strings.Contains(err.Error(), "pressure.data_dir") {
		t.Fatalf("degrade looser than warn: err %v, want a pressure.data_dir refusal", err)
	}
}
