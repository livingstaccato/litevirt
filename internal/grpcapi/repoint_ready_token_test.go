package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// splitTokenGate is a release gate after a later build moved one feature to a
// token of its own: that feature is available while the release token itself
// has not latched here.
type splitTokenGate struct {
	fakeFeatureGate
	feature  capabilities.Feature
	released bool
}

func (g splitTokenGate) FeatureAvailable(f capabilities.Feature) bool { return f == g.feature }
func (g splitTokenGate) DurablyLatched(tok string) bool {
	return g.released && tok == capabilities.ReleaseToken
}

// Switch review B m-1: the compare-and-set switch's readiness (which a VM's
// switch reads too) is the release token's own latch, the token whose build
// decodes the statement, not whichever token container_replication happens to
// belong to.
func TestRepointReady_ReadsTheReleaseTokenNotAFeature(t *testing.T) {
	s := testServer(t)
	ctx := context.Background()
	s.SetReleaseFeatureGate(splitTokenGate{fakeFeatureGate: fakeFeatureGate{t: t, grant: true}, feature: capabilities.FeatureContainerReplication})
	if s.repointReady(ctx) {
		t.Fatal("container_replication is available on a token of its own, but the release token has not latched: the switch must not be a compare-and-set")
	}
	s.SetReleaseFeatureGate(splitTokenGate{fakeFeatureGate: fakeFeatureGate{t: t, grant: true}, feature: "some_other_feature", released: true})
	if !s.repointReady(ctx) {
		t.Fatal("the release token has latched: the switch may be a compare-and-set, whatever container_replication's token says")
	}
	if !s.ReleaseTokenLatched() {
		t.Fatal("ReleaseTokenLatched disagrees with repointReady")
	}
}
