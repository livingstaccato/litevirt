package grpcapi

import (
	"context"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// TestCheckSupersede_RefusesAPriorCertificateAForcedGenerationReplaced: the
// prior certificate a supersede rests on must be one a destination would
// still execute (§3.10 step 4, §4.6). A certificate at a generation a forced
// reconfiguration replaced certifies nothing any more, so it cannot prove what
// attempt n decided either: the coordinator re-decides attempt n under the
// current generation first, which learns the imported value and certifies it
// again, and supersedes with THAT certificate.
//
// Mutation: drop the ReplacedByForcedGeneration check in checkSupersede — the
// replaced certificate is accepted and the refusal is about the destination's
// removal instead.
func TestCheckSupersede_RefusesAPriorCertificateAForcedGenerationReplaced(t *testing.T) {
	ctx := context.Background()
	s := claimingServer(t)
	proof := corrosion.ActionProof{ID: "p-old", Action: corrosion.ActionReschedule, TargetKind: "vm",
		TargetName: "vm-f", DestHost: "gone", Coordinator: s.hostName, OwnerEpoch: "0"}
	key, err := corrosion.ClaimKeyForProof(proof, 0)
	if err != nil {
		t.Fatal(err)
	}
	value := corrosion.ClaimValue{Proof: &proof, SourceHost: "dead-host"}
	out, err := s.DecideRecoveryClaim(ctx, key, value, 1, nil)
	if err != nil {
		t.Fatalf("decide attempt 0: %v", err)
	}
	cert, err := out.Certificate.Encode()
	if err != nil {
		t.Fatal(err)
	}
	ev := &corrosion.SupersedeEvidence{PriorCertificate: cert, PriorValue: &value}
	next := key
	next.Attempt = 1

	forced := corrosion.VoterConfigValue{Generation: 2, Members: []corrosion.VoterMember{{Name: s.hostName}},
		Change: "force:gone", CreatedBy: "test", CreatedAt: "test"}
	if err := corrosion.WriteVoterConfig(ctx, s.db, forced, corrosion.ClaimCertificate{}); err != nil {
		t.Fatal(err)
	}
	if err := corrosion.RecordVoterAdoption(ctx, s.db, 2); err != nil {
		t.Fatal(err)
	}
	reason, detail := s.checkSupersede(ctx, next, ev)
	if reason != corrosion.RefusalSupersedeUnproven || !strings.Contains(detail, "forced generation 2 replaced") {
		t.Fatalf("a prior certificate from a replaced generation was not refused as such: %q %q", reason, detail)
	}
}
