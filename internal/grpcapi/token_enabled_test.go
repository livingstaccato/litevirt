package grpcapi

import (
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// tokenEnabled is what the HA monitor uses to decide which tokens to
// latch-drive and to report as config intent. A token missing from its switch
// falls to `default: false`, so the fleet never latches it and the rollout
// gauge reads 0 even with the operator's flag on — which is exactly what the
// 2026-08-02 lab run hit for owner_epoch_v1: the backfill ran (proving the
// flag parsed), yet the cluster would not latch and
// litevirt_enforcement_config_enabled{feature="owner_epoch_v1"} stayed 0.
//
// Every ADVERTISED token needs a case; a silent default is how a capability
// ships dark.
func TestTokenEnabledCoversEverySupportedToken(t *testing.T) {
	s := testServer(t)
	// Turn every kill-switch on, so any token still reporting false is one
	// tokenEnabled does not know about rather than one merely switched off.
	s.enfSafeFence.Store(true)
	s.enfLWWSkew.Store(true)
	s.enfHLCLww.Store(true)
	s.enfVIPSelfDemote.Store(true)
	s.enfVIPProofReclaim.Store(true)
	s.strictMTLSIdentity.Store(true)
	s.forwardedIdentity.Store(true)
	s.enfSharedStorageFence.Store(true)
	s.rbacRealm.Store(true)
	s.enfOperationProtocol.Store(true)
	s.enfLiveResize.Store(true)
	s.enfConsolePassword.Store(true)
	s.enfCanonicalIdentity.Store(true)
	s.enfProjectAuthority.Store(true)
	s.enfAuditSignature.Store(true)
	s.enfOwnerEpoch.Store(true)
	s.enfIsolationEpoch.Store(true)
	s.enfNetBoxIPAM.Store(true)
	s.enfNetBoxMirror.Store(true)
	s.enfLeaseTerm.Store(true)
	s.enfRecoveryClaim.Store(true)
	s.enfPartitionPause.Store(true)
	s.enfVMReplace.Store(true)
	s.hwV2Ready.Store(true)

	for _, tok := range capabilities.Supported() {
		// hardware_v2 is deliberately excluded: it is "the one capability with
		// no kill switch" (docs/diagnostics.md) — its advertisement is gated on
		// backfill readiness rather than a config flag, so it has no case here.
		// This is a PRE-EXISTING gap surfaced by this test, not one this test
		// is asserting away: its rollout gauge reads 0 regardless of state, and
		// giving it a case would change whether it can contribute to
		// HA-degraded, which is a behavioural decision for its owner.
		if tok == capabilities.HardwareV2 {
			continue
		}
		if !s.tokenEnabled(tok) {
			t.Errorf("tokenEnabled(%q) = false with every kill-switch on — the token is "+
				"missing a case, so the HA monitor will not latch-drive it and its rollout "+
				"gauge reads 0 regardless of config", tok)
		}
	}
}
