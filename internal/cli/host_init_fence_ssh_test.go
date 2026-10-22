package cli

import (
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/litevirt/litevirt/internal/fencessh"
)

// TestSetupEnv_FenceSSH: the setup script is told every join peer's address
// and this host's own, so the drop-in is evaluated for a fence from each, and
// --no-fence-ssh turns the drop-in off.
func TestSetupEnv_FenceSSH(t *testing.T) {
	env := setupScriptEnvWith("node-3", "10.77.0.3", `["10.77.0.1:7946","10.77.0.2:7946"]`, "")
	for _, want := range []string{"FENCE_SSH_DROPIN=1", "FENCE_SSH_PEERS=10.77.0.1 10.77.0.2", "FENCE_SSH_SELF=10.77.0.3"} {
		if !slices.Contains(env, want) {
			t.Errorf("setup env lacks %q: %q", want, env)
		}
	}
	SetFenceSSHDropIn(false)
	defer SetFenceSSHDropIn(true)
	if env := setupScriptEnvWith("node-3", "10.77.0.3", "[]", ""); !slices.Contains(env, "FENCE_SSH_DROPIN=0") {
		t.Errorf("--no-fence-ssh: %q", env)
	}
	if !strings.Contains(setupScriptContent, "lv_fence_ssh_install") ||
		strings.Index(setupScriptContent, "lv_fence_ssh_install ||") > strings.Index(setupScriptContent, "systemctl restart litevirt.service") {
		t.Error("the setup script does not install the drop-in before it starts the daemon")
	}
}

// TestNewClusterEnforcement_FenceSSHManaged: a new cluster fences over the
// managed path only; a host added to it inherits that with the block, and an
// upgraded cluster (no key) stays auto.
func TestNewClusterEnforcement_FenceSSHManaged(t *testing.T) {
	var cfg struct {
		Enforcement struct {
			FenceSSH string `yaml:"fence_ssh"`
		} `yaml:"enforcement"`
	}
	if err := yaml.Unmarshal([]byte(newClusterEnforcement), &cfg); err != nil || cfg.Enforcement.FenceSSH != "managed" {
		t.Fatalf("newClusterEnforcement fence_ssh = %q (%v), want managed", cfg.Enforcement.FenceSSH, err)
	}
	if block := enforcementBlockOf("host_name: a\n" + newClusterEnforcement); !strings.Contains(block, "fence_ssh: managed") {
		t.Fatalf("a joiner's inherited block lacks fence_ssh: %q", block)
	}
}

// TestOwedRevocationNote_SaysWhyItIsHeld: a revocation held for the host's
// fence ssh row says so, not that some node does not pin.
func TestOwedRevocationNote_SaysWhyItIsHeld(t *testing.T) {
	fenceHold := strings.Join(owedRevocationNote("node-1", "ab", fencessh.RevocationHoldPrefix+"node-1's row is still signed by ab"), "\n")
	if !strings.Contains(fenceHold, "re-signs its fence ssh row") || strings.Contains(fenceHold, "does not pin") {
		t.Fatalf("fence ssh hold note:\n%s", fenceHold)
	}
	pinHold := strings.Join(owedRevocationNote("node-1", "ab", "hosts run different builds"), "\n")
	if !strings.Contains(pinHold, "does not pin") || strings.Contains(pinHold, "fence ssh row") {
		t.Fatalf("pin hold note:\n%s", pinHold)
	}
}
