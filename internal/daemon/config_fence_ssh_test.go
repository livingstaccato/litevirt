package daemon

import (
	"strings"
	"testing"
)

// TestLoadConfig_FenceSSH: enforcement.fence_ssh takes managed, auto or
// legacy (unset is auto), and a typo fails load rather than fencing in a mode
// nobody chose.
func TestLoadConfig_FenceSSH(t *testing.T) {
	for _, mode := range []string{"", "managed", "auto", "legacy"} {
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
}
