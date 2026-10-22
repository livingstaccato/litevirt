package daemon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// memory_snapshot.* parse as positive Go durations; empty keeps the
// built-in default (zero here); anything else fails the config load.
func TestMemorySnapshotConfig_Durations(t *testing.T) {
	b, d, err := MemorySnapshotConfig{}.Durations()
	if err != nil || b != 0 || d != 0 {
		t.Fatalf("empty: %v %v %v, want zeros", b, d, err)
	}
	b, d, err = MemorySnapshotConfig{PauseBudget: "500ms", LiveDeadline: "3m"}.Durations()
	if err != nil || b != 500*time.Millisecond || d != 3*time.Minute {
		t.Fatalf("set: %v %v %v", b, d, err)
	}
	for _, bad := range []MemorySnapshotConfig{
		{PauseBudget: "fast"}, {LiveDeadline: "10"}, {PauseBudget: "0s"}, {LiveDeadline: "-1s"},
	} {
		if err := bad.validate(); err == nil {
			t.Errorf("%+v validated", bad)
		}
	}
}

// LoadConfig refuses a memory_snapshot value that does not validate, so the
// daemon does not start on it; a good value loads.
//
// Mutation: drop cfg.MemorySnapshot.validate() from LoadConfig — red.
func TestLoadConfig_MemorySnapshotKeys(t *testing.T) {
	cp := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("LITEVIRT_CONFIG", cp)
	load := func(body string) (*Config, error) {
		t.Helper()
		if err := os.WriteFile(cp, []byte("host_name: h\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		return LoadConfig()
	}
	cfg, err := load("memory_snapshot:\n  pause_budget: 750ms\n  live_deadline: 90s\n")
	if err != nil {
		t.Fatal(err)
	}
	if b, d, err := cfg.MemorySnapshot.Durations(); err != nil || b != 750*time.Millisecond || d != 90*time.Second {
		t.Fatalf("loaded %v %v %v", b, d, err)
	}
	for _, bad := range []string{
		"memory_snapshot:\n  pause_budget: fast\n",
		"memory_snapshot:\n  live_deadline: 0s\n",
		"memory_snapshot:\n  live_deadline: 2h\n",
	} {
		if _, err := load(bad); err == nil {
			t.Errorf("LoadConfig accepted %q", bad)
		}
	}
}
