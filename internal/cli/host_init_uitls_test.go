package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A new node is initialised with ui_tls: on; a node being re-initialised keeps
// what its config already says, and one whose config predates the key keeps
// the historical default (auto).
//
// Mutations: make the no-config branch write auto — a fresh node's UI is plain
// HTTP again; read the key with grep (which exits 1 when it is absent) — the
// "no key" re-init aborts under the script's set -euo pipefail.
func TestSetupScript_UITLS(t *testing.T) {
	if !strings.Contains(setupScriptContent, "ui_tls: ${UI_TLS}") {
		t.Fatal("the setup script does not write ui_tls")
	}
	if !strings.Contains(setupScriptContent, "set -euo pipefail") {
		t.Fatal("fixture: the setup script's shell options changed; run the snippet under the new ones")
	}
	for name, tc := range map[string]struct{ existing, want string }{
		"new node":        {"", "on"},
		"no key":          {"host_name: x\n", "auto"},
		"kept on":         {"host_name: x\nui_tls: on\n", "on"},
		"kept auto":       {"ui_tls: auto\n", "auto"},
		"quoted on value": {"ui_tls: \"on\"\n", "on"},
	} {
		dir := t.TempDir()
		cfg := filepath.Join(dir, "config.yaml")
		if tc.existing != "" {
			if err := os.WriteFile(cfg, []byte(tc.existing), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		// Exactly the setup script's shell options: under pipefail a grep that
		// finds nothing fails the pipeline, and set -e then aborts the script.
		out, err := exec.Command("bash", "-euo", "pipefail", "-c", "CONFIG="+cfg+"\n"+uiTLSScript+"\necho \"$UI_TLS\"").CombinedOutput()
		if err != nil {
			t.Fatalf("%s: %v %s", name, err, out)
		}
		if got := strings.TrimSpace(string(out)); got != tc.want {
			t.Errorf("%s: ui_tls %q, want %q", name, got, tc.want)
		}
	}
}
