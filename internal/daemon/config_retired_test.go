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

// TestLoadConfig_RetiredPCIUdevHookLoadsAndWarns: pci.udev_hook was retired. Host
// init wrote it into every config it produced, so a node whose config still sets it
// must keep starting, with the sibling PCI settings intact, and the operator is told
// by name that it no longer does anything.
//
// Mutation: drop the pci.udev_hook entry from retiredConfigKeys — the load still
// succeeds but nothing is logged, and the WARN assertion goes red.
func TestLoadConfig_RetiredPCIUdevHookLoadsAndWarns(t *testing.T) {
	for _, val := range []string{"true", "false"} {
		t.Run(val, func(t *testing.T) {
			logs := captureSlog(t)
			cfg, err := loadConfigYAML(t, "host_name: h\npci:\n  rescan_interval: \"5m\"\n  udev_hook: "+val+"\n")
			if err != nil {
				t.Fatalf("a config that still sets pci.udev_hook refused to load: %v", err)
			}
			if cfg.PCI.RescanInterval != "5m" {
				t.Errorf("a sibling pci setting was lost beside the retired key: rescan_interval = %q", cfg.PCI.RescanInterval)
			}
			out := logs.String()
			if !strings.Contains(out, "level=WARN") || !strings.Contains(out, "pci.udev_hook") ||
				!strings.Contains(out, "retired") {
				t.Errorf("no WARN naming the retired pci.udev_hook; log:\n%s", out)
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

// enforcement.canonical_registry was readable only up to v1.9.0, which does not
// upgrade in place to 1.10, so it is not on the retired-key list: a config that
// sets it loads like one with any unknown key, and its sibling flags survive.
func TestLoadConfig_CanonicalRegistryKeyStillLoads(t *testing.T) {
	cfg, err := loadConfigYAML(t, "host_name: h\nenforcement:\n  canonical_registry: true\n  vm_replace: true\n")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Enforcement.VMReplace {
		t.Error("a sibling enforcement flag was lost beside the unknown key")
	}
}
