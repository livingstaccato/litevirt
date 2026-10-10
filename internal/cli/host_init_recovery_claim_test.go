package cli

import (
	"testing"

	"gopkg.in/yaml.v3"
)

// A new cluster's hosts carry enforcement.recovery_claim: true EXPLICITLY,
// although this build reads a missing key as true. The key is for the build
// before it: a host rolled back to one after recovery_claim_v1 has latched
// knows the token, so the rollback preflight does not WAL-quarantine it, and
// with no key it reads the flag as false — the uncertified second owner the
// token exists to prevent (colonelpanik/litevirt#250). An explicit true keeps
// it enforcing.
//
// Mutation: drop the recovery_claim line from newClusterEnforcement — the
// key is missing and the test goes red.
func TestNewClusterEnforcement_PinsRecoveryClaimExplicitly(t *testing.T) {
	var cfg struct {
		Enforcement map[string]any `yaml:"enforcement"`
	}
	if err := yaml.Unmarshal([]byte(newClusterEnforcement), &cfg); err != nil {
		t.Fatalf("newClusterEnforcement is not valid YAML: %v", err)
	}
	v, ok := cfg.Enforcement["recovery_claim"]
	if !ok {
		t.Fatalf("a new cluster's enforcement block has no recovery_claim key: %v", cfg.Enforcement)
	}
	if v != true {
		t.Fatalf("enforcement.recovery_claim = %v, want an explicit true", v)
	}
}
