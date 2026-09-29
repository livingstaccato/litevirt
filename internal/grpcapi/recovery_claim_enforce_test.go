package grpcapi

import (
	"context"
	"slices"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// recoveryClaimServer is a voter-ready server whose gate latches exactly the
// given tokens.
func recoveryClaimServer(t *testing.T, flag bool, latched ...string) *Server {
	t.Helper()
	s := voterTestServer(t)
	tok := map[string]bool{}
	for _, l := range latched {
		tok[l] = true
	}
	s.SetGate(fakeServerGate{execOK: true, enforcedTok: tok})
	s.SetRecoveryClaimEnforce(flag)
	return s
}

// adoptTestGeneration writes and adopts a first voter generation with the
// given members, without a certificate — the shape a unit test needs to put a
// node under an adopted generation without running genesis.
func adoptTestGeneration(t *testing.T, s *Server, members []corrosion.VoterMember) {
	t.Helper()
	ctx := context.Background()
	s.db.SetVoterConfigGate(func() bool { return true })
	val := corrosion.VoterConfigValue{Generation: 1, Members: corrosion.SortMembers(members),
		Change: corrosion.VoterChangeGenesis, CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, val, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 1); err != nil {
		t.Fatal(err)
	}
}

// TestAdvertise_RecoveryClaimWithheldWhileOff pins docs/design/recovery-claims.md
// §5.2 where a future reviewer will look, beside
// TestAdvertise_SharedStorageFenceIsUnconditional, because the two tokens look
// alike and are advertised in opposite ways for one reason: where the
// guarantee is enforced.
//
// shared_storage_fence_v1 is enforced where a transfer is CREATED, so no node
// relies on a peer and it is advertised whatever the flag says.
// recovery_claim_v1 is enforced at EXECUTION: a coordinator cannot stop
// another coordinator from minting, so every flag-on node relies on every
// peer claiming before it mints and verifying before it executes. A flag-off
// peer is the uncertified second owner, not merely permissive, so the latch
// has to mean config uniformity and the token is withheld while the flag is
// off.
//
// Mutation: drop the flag half of the advertisement filter — the flag-off
// node advertises and the first subtest goes red.
func TestAdvertise_RecoveryClaimWithheldWhileOff(t *testing.T) {
	ready := []string{capabilities.SplitBrainGateV1}
	t.Run("flag off", func(t *testing.T) {
		s := recoveryClaimServer(t, false, ready...)
		if slices.Contains(s.advertisedCapabilities(), capabilities.RecoveryClaimV1) {
			t.Fatalf("%s is advertised with enforcement.recovery_claim off; the cluster could latch "+
				"across a node that mints uncertified proofs", capabilities.RecoveryClaimV1)
		}
	})
	t.Run("flag on and ready", func(t *testing.T) {
		s := recoveryClaimServer(t, true, ready...)
		if !slices.Contains(s.advertisedCapabilities(), capabilities.RecoveryClaimV1) {
			ok, why := s.RecoveryClaimReadiness(context.Background())
			t.Fatalf("a ready flag-on node does not advertise %s (ready=%v: %s)", capabilities.RecoveryClaimV1, ok, why)
		}
	})
}

// TestRecoveryClaimReadiness_NeedsTheSplitBrainGateAndAVoter: the certificate
// rides on a runtime-action proof, so a node whose split_brain_gate_v1 has not
// latched has nothing to carry it on; and a node that cannot vote durably
// cannot take part in a claim. Either withholds the token (§5.1).
//
// Mutations: drop the split_brain_gate_v1 predicate — the unlatched node
// advertises; drop the voter predicate — the keyless node advertises.
func TestRecoveryClaimReadiness_NeedsTheSplitBrainGateAndAVoter(t *testing.T) {
	unlatched := recoveryClaimServer(t, true)
	if slices.Contains(unlatched.advertisedCapabilities(), capabilities.RecoveryClaimV1) {
		t.Errorf("%s is advertised before %s has latched", capabilities.RecoveryClaimV1, capabilities.SplitBrainGateV1)
	}
	if ok, why := unlatched.RecoveryClaimReadiness(context.Background()); ok || why == "" {
		t.Errorf("readiness passed without the split-brain gate (ok=%v, %q)", ok, why)
	}

	keyless := testServer(t)
	keyless.SetGate(fakeServerGate{execOK: true, enforcedTok: map[string]bool{capabilities.SplitBrainGateV1: true}})
	keyless.SetRecoveryClaimEnforce(true)
	if slices.Contains(keyless.advertisedCapabilities(), capabilities.RecoveryClaimV1) {
		t.Errorf("%s is advertised by a node that cannot sign an accept", capabilities.RecoveryClaimV1)
	}
}

// TestRecoveryClaimEnforced_IsFlagLatchAndAConfig: the enforcement predicate
// is the flag AND the latch AND an adopted voter generation with members —
// without a config there is no majority to certify anything (§5.1, §5.3).
//
// Mutations: drop any one conjunct and the matching row goes red.
func TestRecoveryClaimEnforced_IsFlagLatchAndAConfig(t *testing.T) {
	ctx := context.Background()
	all := []string{capabilities.SplitBrainGateV1, capabilities.RecoveryClaimV1}
	adopt := func(t *testing.T, s *Server) {
		t.Helper()
		inc, err := s.db.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		adoptTestGeneration(t, s, []corrosion.VoterMember{{Name: s.hostName, Incarnation: inc}})
	}
	for _, tc := range []struct {
		name    string
		flag    bool
		latched []string
		config  bool
		want    bool
	}{
		{"flag latch config", true, all, true, true},
		{"no flag", false, all, true, false},
		{"not latched", true, []string{capabilities.SplitBrainGateV1}, true, false},
		{"no config", true, all, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := recoveryClaimServer(t, tc.flag, tc.latched...)
			if tc.config {
				adopt(t, s)
			}
			if got := s.RecoveryClaimEnforced(ctx); got != tc.want {
				t.Errorf("RecoveryClaimEnforced = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestNotEnforcing_ReportsARecoveryClaimStandDown: a node that has latched
// recovery_claim_v1 and then turned its flag off stops advertising the token
// — that is what keeps a fresh latch from forming across it — but its peers'
// view of the stand-down must not depend on noticing an absence. It reports
// the token in not_enforcing, which is where an operator looks (§5.3).
//
// Mutation: drop the latched-but-withheld arm of notEnforcingTokens — the
// stood-down node reports nothing.
func TestNotEnforcing_ReportsARecoveryClaimStandDown(t *testing.T) {
	down := recoveryClaimServer(t, false, capabilities.SplitBrainGateV1, capabilities.RecoveryClaimV1)
	if !slices.Contains(down.notEnforcingTokens(), capabilities.RecoveryClaimV1) {
		t.Errorf("a node with %s latched and its flag off does not report it in not_enforcing: %v",
			capabilities.RecoveryClaimV1, down.notEnforcingTokens())
	}
	up := recoveryClaimServer(t, true, capabilities.SplitBrainGateV1, capabilities.RecoveryClaimV1)
	if slices.Contains(up.notEnforcingTokens(), capabilities.RecoveryClaimV1) {
		t.Errorf("a flag-on node reports %s as not enforced", capabilities.RecoveryClaimV1)
	}
	never := recoveryClaimServer(t, false, capabilities.SplitBrainGateV1)
	if slices.Contains(never.notEnforcingTokens(), capabilities.RecoveryClaimV1) {
		t.Errorf("a node that never latched %s reports it as not enforced", capabilities.RecoveryClaimV1)
	}
}
