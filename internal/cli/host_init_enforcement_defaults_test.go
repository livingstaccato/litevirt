package cli

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func enforcementBlockFor(t *testing.T, env []string) string {
	t.Helper()
	for _, kv := range env {
		if rest, ok := strings.CutPrefix(kv, "ENFORCEMENT_B64="); ok {
			raw, err := base64.StdEncoding.DecodeString(rest)
			if err != nil {
				t.Fatalf("decode ENFORCEMENT_B64: %v", err)
			}
			return string(raw)
		}
	}
	t.Fatal("setupScriptEnv produced no ENFORCEMENT_B64")
	return ""
}

// useConfig points daemonConfigPath at a throwaway file (empty body = no file).
func useConfig(t *testing.T, body string) {
	t.Helper()
	old := daemonConfigPath
	t.Cleanup(func() { daemonConfigPath = old })
	if body == "" {
		daemonConfigPath = filepath.Join(t.TempDir(), "absent.yaml")
		return
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	daemonConfigPath = p
}

// A NEW cluster starts with the shared-storage protections on.
//
// The default-off design is right for an existing cluster: a flag flip must
// never change behaviour mid-roll. It is not right for a cluster that has no
// behaviour yet. Shipped off, a best-effort SSH fence that never landed reports
// success, the coordinator reschedules, and a VM with a writable shared disk
// runs on two hosts at once — the protections against exactly that sitting in
// the binary, switched off.
func TestSetupScriptEnv_NewClusterDefaultsFenceSafetyOn(t *testing.T) {
	useConfig(t, "")

	block := enforcementBlockFor(t, setupScriptEnv("node-1", "10.0.0.1", ""))

	for _, want := range []string{"safe_fence_default: true", "shared_storage_fence: true"} {
		if !strings.Contains(block, want) {
			t.Errorf("new-cluster enforcement block is missing %q; got:\n%s", want, block)
		}
	}
	if !strings.HasPrefix(block, "enforcement:\n") {
		t.Errorf("block is not a YAML enforcement mapping:\n%s", block)
	}
}

// Joining an EXISTING cluster propagates that cluster's block verbatim and
// invents nothing. The adding node's config is the cluster's config; writing a
// different one is how a host silently weakens a latch.
func TestSetupScriptEnv_JoiningPropagatesTheClustersOwnBlock(t *testing.T) {
	useConfig(t, "enforcement:\n  safe_fence_default: false\n  hlc_lww: true\n\nlog_level: info\n")

	block := enforcementBlockFor(t, setupScriptEnv("node-2", "10.0.0.2", "10.0.0.1:7443"))

	if !strings.Contains(block, "safe_fence_default: false") {
		t.Errorf("the joining host did not inherit the cluster's flag; got:\n%s", block)
	}
	if !strings.Contains(block, "hlc_lww: true") {
		t.Errorf("the joining host lost a flag the cluster has set; got:\n%s", block)
	}
	if strings.Contains(block, "shared_storage_fence") {
		t.Errorf("a flag the cluster never set was invented for a joining host:\n%s", block)
	}
}

// A host joining a cluster whose seed config has no enforcement block at all
// gets nothing. Turning protections on for one member of an existing cluster is
// the silent mid-roll behaviour change the default-off design exists to
// prevent; the migration path for those clusters is a deliberate operator flip.
func TestSetupScriptEnv_JoiningANonEnforcingClusterInventsNothing(t *testing.T) {
	useConfig(t, "log_level: info\n")

	block := enforcementBlockFor(t, setupScriptEnv("node-2", "10.0.0.2", "10.0.0.1:7443"))

	if block != "" {
		t.Errorf("a joining host was handed an enforcement block its cluster does not have:\n%s", block)
	}
}
