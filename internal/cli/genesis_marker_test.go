package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The founder marker is the only licence a daemon has to mint the cluster's first
// admin credential (internal/daemon seedAdminUser, colonelpanik/litevirt#186). It
// must be written by exactly one thing — `lv host init` founding a node whose
// data dir has never held a database — and cleared by everything else.

// runGenesisSnippet runs the marker fragment of the setup script against dataDir.
func runGenesisSnippet(t *testing.T, dataDir string, env ...string) {
	t.Helper()
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash not available")
	}
	cmd := exec.Command("bash", "-c", "set -euo pipefail\n"+genesisMarkerScript)
	cmd.Env = append([]string{"PATH=" + os.Getenv("PATH"), "LV_DATA_DIR=" + dataDir}, env...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("genesis snippet failed: %v\n%s", err, out)
	}
}

func markerExists(t *testing.T, dataDir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dataDir, "genesis-pending"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatalf("stat marker: %v", err)
	}
	return err == nil
}

func TestGenesisMarker_FoundingAFreshNodeWritesIt(t *testing.T) {
	dir := t.TempDir()
	runGenesisSnippet(t, dir, foundingSetupEnv)
	if !markerExists(t, dir) {
		t.Fatal("`lv host init` on a fresh node wrote no founder marker; its daemon then " +
			"mints no admin account and the new cluster has no way to log in")
	}
}

// Re-running `lv host init` against a live member must not re-arm minting. The
// member's users table is not empty, but the next time its state.db is lost the
// marker would put it straight back on the mint path — the #186 failure by
// another route.
func TestGenesisMarker_ReInitialisingANodeWithAStateDBDoesNotWriteIt(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "state.db"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	runGenesisSnippet(t, dir, foundingSetupEnv)
	if markerExists(t, dir) {
		t.Fatal("re-initialising a node that already has a state.db wrote a founder marker; " +
			"a later state.db rebuild there mints a fresh admin over the cluster's")
	}
}

// A founder whose state.db was LOST is not a fresh node. Its capability latches
// (data_dir/split_brain_activated.<token>) survive the loss, and every daemon
// that has run long enough to latch a mandatory token has them. Re-running
// `lv host init` there — with --force, or while the cluster is unreachable so the
// membership check cannot answer — must not arm a mint of a second admin.
func TestGenesisMarker_ANodeWithCapabilityLatchesIsNotFresh(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "split_brain_activated.voter_config_v1"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	runGenesisSnippet(t, dir, foundingSetupEnv)
	if markerExists(t, dir) {
		t.Fatal("`lv host init` wrote a founder marker on a node holding capability latches; " +
			"it has run as a cluster member before, and minting there replaces the cluster's admin")
	}
}

// Every non-founding setup clears a marker left behind, e.g. by a `host init`
// whose daemon never started before the node was `host add`ed elsewhere.
func TestGenesisMarker_NonFoundingSetupClearsAStaleOne(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "genesis-pending"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	runGenesisSnippet(t, dir)
	if markerExists(t, dir) {
		t.Fatal("a non-founding setup left a stale founder marker in place")
	}
}

func TestGenesisMarker_TheSetupScriptRunsTheSnippet(t *testing.T) {
	if !strings.Contains(setupScriptContent, genesisMarkerScript) {
		t.Fatal("setupScriptContent does not include genesisMarkerScript, so no " +
			"provisioning path writes or clears the founder marker")
	}
}

// Only founding sets the flag. `lv host add` builds its environment from
// setupScriptEnv alone; if the flag ever reached it, every added node would mint.
func TestGenesisMarker_OnlyFoundingSetsTheFlag(t *testing.T) {
	for _, kv := range setupScriptEnv("node-5", "10.0.0.5", `["10.0.0.1:7946"]`) {
		if strings.HasPrefix(kv, strings.SplitN(foundingSetupEnv, "=", 2)[0]+"=") {
			t.Fatalf("setupScriptEnv (the `lv host add` environment) carries %q; every added "+
				"node would write a founder marker and mint its own admin", kv)
		}
	}
	if !hasEnv(localInitSetupEnv("node-1", "10.0.0.1"), foundingSetupEnv) {
		t.Error("`lv host init --local` does not set the founding flag; the founder mints " +
			"no admin account")
	}
	// The remote form shell-quotes every value (shellEnvPrefix).
	if !strings.Contains(remoteInitSetupCommand("node-1", "10.0.0.1", ""), "LITEVIRT_GENESIS='1' ") {
		t.Error("remote `lv host init` does not set the founding flag; the founder mints " +
			"no admin account")
	}
}
