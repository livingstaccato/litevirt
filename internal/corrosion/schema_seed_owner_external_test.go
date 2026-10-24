package corrosion_test

import (
	"context"
	"sync"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
)

func init() {
	corrosion.RegisterPrivateSchemaSeedOwner(func(t *testing.T, c *corrosion.Client, pkiDir string, verifier *corrosion.ClaimVerifier, ping corrosion.PrivateSchemaSeedPing, confirm corrosion.PrivateSchemaSeedConfirm) corrosion.PrivateSchemaSeedOwner {
		t.Helper()
		if c.HostName() != "test-node" {
			t.Fatal("private memory constructor host changed")
		}
		dir := t.TempDir()
		checker := health.NewChecker(c.HostName(), pkiDir, c)
		checker.SetActivationMarker(health.ActivationMarkerBase(dir))
		checker.SetPeerPinger(health.PeerPinger(ping))
		checker.SetReleaseUseConfirmer(health.ReleaseUseConfirmer(confirm))
		c.SetClaimCertificateVerifier(func() *corrosion.ClaimVerifier { return verifier })
		c.SetAutomationContinuityReleaseRestorer(checker.RestoreAutomationContinuityReleaseUse)
		var mu sync.Mutex
		calls := map[capabilities.Feature]int{}
		c.SetReleaseFeatureGate(func(ctx context.Context, f capabilities.Feature, write func(context.Context, capabilities.FeatureGrant) error) error {
			return checker.WithFeature(ctx, f, func(ctx context.Context, g capabilities.FeatureGrant) error {
				mu.Lock()
				calls[f]++
				mu.Unlock()
				return write(ctx, g)
			})
		})
		return corrosion.PrivateSchemaSeedOwner{
			MarkerPath:    func(token string) string { return health.ActivationMarkerPath(dir, token) },
			Latched:       checker.DurablyLatched,
			CallbackCount: func(f capabilities.Feature) int { mu.Lock(); defer mu.Unlock(); return calls[f] },
		}
	})
}
