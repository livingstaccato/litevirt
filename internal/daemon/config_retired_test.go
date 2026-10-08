package daemon

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureSlog routes the default logger into a buffer for the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

func loadConfigYAML(t *testing.T, yaml string) (*Config, error) {
	t.Helper()
	cp := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(cp, []byte(yaml), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", cp)
	return LoadConfig()
}

// TestLoadConfig_RetiredCanonicalRegistryFlagLoadsAndWarns: enforcement.canonical_registry
// was retired with its token (canonical_registry_v1). A node whose config still sets it —
// every node that ever opted in — must keep starting, so the key is accepted and ignored,
// and the operator is told, by name, that it no longer does anything.
//
// Mutation: drop the retired-key check — the load still succeeds (yaml ignores the key)
// but nothing is logged, and the WARN assertion goes red.
func TestLoadConfig_RetiredCanonicalRegistryFlagLoadsAndWarns(t *testing.T) {
	for _, val := range []string{"true", "false"} {
		t.Run(val, func(t *testing.T) {
			logs := captureSlog(t)
			cfg, err := loadConfigYAML(t, "host_name: h\nenforcement:\n  canonical_registry: "+val+"\n  vm_replace: true\n")
			if err != nil {
				t.Fatalf("a config that still sets enforcement.canonical_registry refused to load: %v", err)
			}
			if !cfg.Enforcement.VMReplace {
				t.Error("a sibling enforcement flag was lost beside the retired key")
			}
			out := logs.String()
			if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "enforcement.canonical_registry") ||
				!strings.Contains(out, "retired") {
				t.Errorf("no WARN naming the retired enforcement.canonical_registry; log:\n%s", out)
			}
		})
	}
}

// A config without the retired key logs nothing about it.
func TestLoadConfig_NoRetiredKeyNoWarn(t *testing.T) {
	logs := captureSlog(t)
	if _, err := loadConfigYAML(t, "host_name: h\nenforcement:\n  vm_replace: true\n"); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(logs.String(), "retired") {
		t.Errorf("a retired-key WARN without the key; log:\n%s", logs.String())
	}
}
