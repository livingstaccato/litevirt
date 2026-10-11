package grpcapi

import (
	"context"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestAdvertise_CredentialsClearWaitsForTheFirstPass: credentials_clear_v1 is
// advertised only once this node has completed a credentials split pass, so no
// clear can latch anywhere before every recipient's first pass — the pass that
// gives legacy external users their credential rows.
func TestAdvertise_CredentialsClearWaitsForTheFirstPass(t *testing.T) {
	s := testServer(t)
	if slices.Contains(s.advertisedCapabilities(), capabilities.CredentialsClearV1) {
		t.Fatal("credentials_clear_v1 advertised before this node completed a credentials split pass")
	}
	s.db.SetCredentialsSplitGate(func() bool { return true })
	if _, err := s.db.SplitCredentials(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(s.advertisedCapabilities(), capabilities.CredentialsClearV1) {
		t.Error("credentials_clear_v1 still withheld after the first complete pass")
	}
}
