package daemon

import (
	"strings"
	"testing"
	"time"
)

// TestLoadConfig_FenceSSH: enforcement.fence_ssh takes managed or auto
// (unset is auto), and a typo fails load rather than fencing in a mode
// nobody chose; the probe runs every 15 minutes unless set, and 0 disables it.
func TestLoadConfig_FenceSSH(t *testing.T) {
	for _, mode := range []string{"", "managed", "auto"} {
		body := ""
		if mode != "" {
			body = "enforcement:\n  fence_ssh: " + mode + "\n"
		}
		cfg, err := loadContainersConfig(t, body)
		if err != nil || cfg.Enforcement.FenceSSH != mode {
			t.Fatalf("fence_ssh %q: %+v %v", mode, cfg, err)
		}
	}
	if _, err := loadContainersConfig(t, "enforcement:\n  fence_ssh: manged\n"); err == nil ||
		!strings.Contains(err.Error(), "enforcement.fence_ssh") {
		t.Fatalf("a typo'd fence_ssh loaded: %v", err)
	}
	// legacy was a mode once and is gone: a config still naming it fails at
	// start with the fix, rather than fence in some mode its operator did not
	// pick.
	_, err := loadContainersConfig(t, "enforcement:\n  fence_ssh: legacy\n")
	if err == nil {
		t.Fatal("fence_ssh: legacy loaded")
	}
	for _, want := range []string{"enforcement.fence_ssh", `"legacy"`, "removed", "set enforcement.fence_ssh to auto or managed"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("fence_ssh: legacy refusal %q does not name %s", err, want)
		}
	}
	cfg, err := loadContainersConfig(t, "")
	if err != nil || cfg.FenceSSHProbeInterval() != 15*time.Minute {
		t.Fatalf("default probe interval: %v %v", cfg.FenceSSHProbeInterval(), err)
	}
	cfg, err = loadContainersConfig(t, "fence_ssh_probe_interval_sec: 0\n")
	if err != nil || cfg.FenceSSHProbeInterval() != 0 {
		t.Fatalf("probe interval 0: %v %v", cfg.FenceSSHProbeInterval(), err)
	}
	if _, err := loadContainersConfig(t, "fence_ssh_probe_interval_sec: -5\n"); err == nil {
		t.Fatal("a negative probe interval loaded")
	}
}
