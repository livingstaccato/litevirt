package grpcapi

import (
	"context"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
)

// TestCheckOneCapabilityHealth_DetectsPostLatchRegression proves the bounded freshness
// check surfaces a regression the one-way durable latch cannot: a token latched locally
// whose peer support later disappears. Latched stays true, but CapabilityActiveForHealth
// now returns false → evaluateHADegraded must raise unsupported_member.
func TestCheckOneCapabilityHealth_DetectsPostLatchRegression(t *testing.T) {
	ctx := context.Background()
	g := &recordingGate{}
	// Both configured-on tokens already latched; split_brain still confirms active,
	// but lww's peer support regressed (CapabilityActiveForHealth → false).
	//
	// vm_snapshot_claim_v1, lease_term_ledger_v1, credentials_split_v1, credentials_clear_v1,
	// host_membership_split_v1, host_membership_retire_v1, host_runtime_split_v1, host_runtime_retire_v1, failover_scope_v1, voter_config_v1,
	// claim_incarnation_v1, lease_term_claim_v1, fence_state_v1, relay_health_v1, spec_conflict_v1, netbox_ip_repoint_v1, user_incarnation_v1, project_incarnation_v1 and release_2026_11_v1 are latched too, not because this
	// test is about them but because they
	// have no kill switch: an unlatched one would consume the driver's
	// one-per-cycle budget and the loop below would never reach the freshness
	// check it is actually asserting on.
	g.latched = map[string]bool{
		capabilities.VMSnapshotClaimV1:      true,
		capabilities.SplitBrainGateV1:       true,
		capabilities.LeaseTermLedgerV1:      true,
		capabilities.CredentialsSplitV1:     true,
		capabilities.CredentialsClearV1:     true,
		capabilities.HostMembershipSplitV1:  true,
		capabilities.HostMembershipRetireV1: true,
		capabilities.HostRuntimeSplitV1:     true,
		capabilities.HostRuntimeRetireV1:    true,
		capabilities.FailoverScopeV1:        true,
		capabilities.VoterConfigV1:          true,
		capabilities.ClaimIncarnationV1:     true,
		capabilities.LeaseTermClaimV1:       true,
		capabilities.FenceStateV1:           true,
		capabilities.RelayHealthV1:          true,
		capabilities.SpecConflictV1:         true,
		capabilities.NetBoxIPRepointV1:      true,
		capabilities.UserIncarnationV1:      true,
		capabilities.ProjectIncarnationV1:   true,
		capabilities.Release202611V1:        true,
		capabilities.Release202612V1:        true,
		capabilities.Release202701V1:        true,
		capabilities.Release202702V1:        true,
		capabilities.LWWSkewGuardV1:         true,
	}
	g.enforcedTok = map[string]bool{
		capabilities.VMSnapshotClaimV1:      true, // binary support is still active
		capabilities.SplitBrainGateV1:       true, // still active
		capabilities.LeaseTermLedgerV1:      true, // still active
		capabilities.CredentialsSplitV1:     true, // still active
		capabilities.CredentialsClearV1:     true, // still active
		capabilities.HostMembershipSplitV1:  true, // still active
		capabilities.HostMembershipRetireV1: true, // still active
		capabilities.HostRuntimeSplitV1:     true, // still active
		capabilities.HostRuntimeRetireV1:    true, // still active
		capabilities.FailoverScopeV1:        true, // still active
		capabilities.VoterConfigV1:          true, // still active
		capabilities.ClaimIncarnationV1:     true, // still active
		capabilities.LeaseTermClaimV1:       true, // still active
		capabilities.FenceStateV1:           true, // still active
		capabilities.RelayHealthV1:          true, // still active
		capabilities.SpecConflictV1:         true, // still active
		capabilities.NetBoxIPRepointV1:      true, // still active
		capabilities.UserIncarnationV1:      true, // still active
		capabilities.ProjectIncarnationV1:   true, // still active
		capabilities.Release202611V1:        true, // still active
		capabilities.Release202612V1:        true, // still active
		capabilities.Release202701V1:        true,
		capabilities.Release202702V1:        true,  // still active
		capabilities.LWWSkewGuardV1:         false, // regressed: a peer stopped advertising
	}
	s := testServer(t) // real db so evaluateHADegraded's stranded-pending query is safe
	s.SetGate(g)
	s.SetEnforcementConfig(false, true, false, false, false, false) // lww configured-on (safeFence,lww,hlcLww,vipSelfDemote,vipProofReclaim,sharedStorageFence)

	// Nothing to latch (all latched) ⇒ each cycle spends its peer op on a freshness
	// check; round-robin covers both configured tokens within a few cycles.
	for i := 0; i < 4; i++ {
		if s.driveCapabilityActivation(ctx) {
			t.Fatal("no unlatched token should be driven when all are latched")
		}
		s.checkOneCapabilityHealth(ctx)
	}
	if got, _ := s.evaluateHADegraded(ctx); !got[haUnsupportedMember] {
		t.Fatalf("a post-latch regression on lww must raise unsupported_member; got %v", got)
	}
}
