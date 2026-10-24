package corrosion

import (
	"context"
	"testing"
)

// ContinuityStorageOwner exposes only the existing owner's fixture controls.
// The external test package supplies health without creating an import cycle.
type ContinuityStorageOwner struct {
	Restore             func(context.Context, *AutomationContinuityReleaseEvidence) error
	Gate                ReleaseFeatureGate
	SetActivationMarker func(string)
	DurablyLatched      func() bool
	MarkerBase          string
	MarkerPath          string
}

var continuityStorageOwnerConfigurator func(*testing.T, *Client, string, *ClaimVerifier) ContinuityStorageOwner

// RegisterContinuityStorageOwner is called once by the external package's init.
// Tests only read this registration; individual fixtures own all mutable state.
func RegisterContinuityStorageOwner(fn func(*testing.T, *Client, string, *ClaimVerifier) ContinuityStorageOwner) {
	if fn == nil || continuityStorageOwnerConfigurator != nil {
		panic("continuity storage owner must be registered exactly once")
	}
	continuityStorageOwnerConfigurator = fn
}

func configureContinuityStorageOwner(t *testing.T, c *Client, pkiDir string, verifier *ClaimVerifier) ContinuityStorageOwner {
	t.Helper()
	if continuityStorageOwnerConfigurator == nil {
		t.Fatal("continuity storage fixture requires external real health owner registration")
	}
	return continuityStorageOwnerConfigurator(t, c, pkiDir, verifier)
}
