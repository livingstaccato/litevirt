package corrosion_test

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

func init() {
	corrosion.RegisterContinuityStorageOwner(func(t *testing.T, c *corrosion.Client, pkiDir string, verifier *corrosion.ClaimVerifier) corrosion.ContinuityStorageOwner {
		t.Helper()
		dataDir := t.TempDir()
		checker := health.NewChecker("a", pkiDir, c)
		base := health.ActivationMarkerBase(dataDir)
		checker.SetActivationMarker(base)
		c.SetClaimCertificateVerifier(func() *corrosion.ClaimVerifier { return verifier })
		// This fixture supports the ordinary policy storage lane. Release
		// restoration and the feature grant still belong to the real checker.
		c.SetClusterPolicyGate(func() bool { return true })
		c.SetAutomationContinuityReleaseRestorer(checker.RestoreAutomationContinuityReleaseUse)
		c.SetReleaseFeatureGate(checker.WithFeature)
		return corrosion.ContinuityStorageOwner{
			Restore:             checker.RestoreAutomationContinuityReleaseUse,
			Gate:                checker.WithFeature,
			SetActivationMarker: checker.SetActivationMarker,
			DurablyLatched:      func() bool { return checker.DurablyLatched(capabilities.Release202702V1) },
			MarkerBase:          base,
			MarkerPath:          health.ActivationMarkerPath(dataDir, capabilities.Release202702V1),
		}
	})
}
