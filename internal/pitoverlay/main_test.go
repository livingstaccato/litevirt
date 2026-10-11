package pitoverlay

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// openGate is a host that holds the pit_overlay release feature; closedGate
// one that does not (the release token has not latched there).
var (
	openGate   Gate = func() (bool, string) { return true, "" }
	closedGate Gate = func() (bool, string) {
		return false, "the cluster upgrade must finish first (pit_overlay needs " + capabilities.ReleaseToken + ")"
	}
)

// grant is the pit_overlay grant a test hands OpenWindow.
func grant(t testing.TB) capabilities.FeatureGrant {
	return capabilities.GrantForTest(t, capabilities.FeaturePITOverlay)
}
