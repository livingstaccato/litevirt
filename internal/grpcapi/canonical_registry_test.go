package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestCanonicalRegistry_RetiredIsNeverAdvertisedOrDriven: canonical_registry_v1 is retired. With
// every kill switch on, this build neither advertises it (so no cluster can latch it again) nor
// treats it as enabled (so it is never reported as not-enforcing or degraded), and a node that
// still holds its latch in memory does not drive it: there is nothing left to enforce.
func TestCanonicalRegistry_RetiredIsNeverAdvertisedOrDriven(t *testing.T) {
	const tok = capabilities.RetiredCanonicalRegistryV1

	s := testServer(t)
	enforceEveryToken(s)
	if hasCap(s.advertisedCapabilities(), tok) {
		t.Errorf("%s is advertised; a cluster could latch the retired token again", tok)
	}
	if s.tokenEnabled(tok) {
		t.Errorf("tokenEnabled(%s) = true; a retired token has no flag to be on", tok)
	}

	g := &recordingGate{latched: map[string]bool{tok: true}}
	d := &Server{gate: g}
	for i := 0; i < 3; i++ {
		d.driveCapabilityActivation(context.Background())
	}
	if g.drivenUnique()[tok] {
		t.Errorf("the retired %s was driven; nothing on this build enforces it", tok)
	}
}
