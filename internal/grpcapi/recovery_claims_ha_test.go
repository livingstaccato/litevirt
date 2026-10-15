package grpcapi

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/capabilities"
	"github.com/litevirt/litevirt/internal/claims"
	"github.com/litevirt/litevirt/internal/corrosion"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func claimHA(t *testing.T, s *Server, state string) {
	t.Helper()
	ctx := context.Background()
	s.db.SetClusterPolicyGate(func() bool { return true })
	cur, _ := corrosion.GetHAPolicy(ctx, s.db)
	if _, err := corrosion.SetHAPolicy(ctx, s.db, capabilities.GrantForTest(t, capabilities.FeatureHADisarm), state, "", "alice", cur.UpdatedAt); err != nil {
		t.Fatal(err)
	}
}

func haRefused(err error) bool {
	var nm *claims.NoMajorityError
	if !errors.As(err, &nm) {
		return false
	}
	for _, r := range nm.Refusals {
		if r.Reason == corrosion.RefusalHADisarmed {
			return true
		}
	}
	return false
}

// L3: a voter whose replica says disarmed (or cannot read the policy) does not
// accept an automatic workload recovery; an operator's promotion is accepted;
// armed, everything is.
//
// Mutation: drop the IsOperatorPromoteValue exemption — the operator's
// promotion is refused and this goes red; drop the check — the automatic value
// is decided while disarmed and this goes red.
func TestClaimVoter_RefusesAutomaticRecoveryWhileDisarmed(t *testing.T) {
	ctx := context.Background()
	s := claimingServer(t)
	auto := func(name string) (corrosion.ClaimKey, corrosion.ClaimValue) {
		p := corrosion.ActionProof{ID: "p-" + name, Action: corrosion.ActionReschedule, TargetKind: "vm",
			TargetName: name, DestHost: "elsewhere", Coordinator: s.hostName, OwnerEpoch: "0"}
		key, err := corrosion.ClaimKeyForProof(p, 0)
		if err != nil {
			t.Fatal(err)
		}
		return key, corrosion.ClaimValue{Proof: &p, SourceHost: "dead-host"}
	}

	claimHA(t, s, corrosion.HADisarmed)
	key, v := auto("vm-a")
	if _, err := s.DecideRecoveryClaim(ctx, key, v, 1, nil); !haRefused(err) {
		t.Fatalf("automatic recovery decided while disarmed: %v", err)
	}
	op := corrosion.ActionProof{ID: "p-op", Action: corrosion.ActionPromote, TargetKind: "vm", TargetName: "vm-b",
		DestHost: s.hostName, Coordinator: corrosion.OperatorClaimPrefix + s.hostName, LeaseHolder: s.hostName, OwnerEpoch: "0"}
	opKey, err := corrosion.ClaimKeyForProof(op, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.DecideRecoveryClaim(ctx, opKey, corrosion.ClaimValue{Proof: &op, SourceHost: "dead-host"}, 1, nil); err != nil {
		t.Fatalf("an operator's promotion was refused while disarmed: %v", err)
	}
	// A config value and a LUN value are not this rule's to refuse.
	for name, val := range map[string]corrosion.ClaimValue{
		"config": {Config: &corrosion.VoterConfigValue{Generation: 9}},
		"lun":    {LUN: &corrosion.LUNAllocation{LUN: "x", Generation: 1}},
	} {
		res, err := s.localAccept(ctx, corrosion.ClaimKey{TargetKind: "vm", TargetName: "cfg-" + name}, corrosion.Ballot{Round: 5, Coordinator: s.hostName}, val, 1)
		if err == nil && res.Refusal == corrosion.RefusalHADisarmed {
			t.Errorf("a %s value was refused as an HA disarm", name)
		}
	}

	claimHA(t, s, corrosion.HAArmed)
	key, v = auto("vm-c")
	if _, err := s.DecideRecoveryClaim(ctx, key, v, 1, nil); err != nil {
		t.Fatalf("armed: automatic recovery refused: %v", err)
	}

	// Unreadable holds it too.
	if err := s.db.Execute(ctx, `INSERT INTO cluster_policies (key, value, set_by, updated_at, deleted_at)
	 VALUES (?, ?, ?, ?, NULL)
	 ON CONFLICT(key) DO UPDATE SET value = excluded.value, set_by = excluded.set_by,
	   updated_at = excluded.updated_at, deleted_at = NULL`, "ha", `{"state":"?"}`, "x", s.db.NowTS()); err != nil {
		t.Fatal(err)
	}
	key, v = auto("vm-d")
	if _, err := s.DecideRecoveryClaim(ctx, key, v, 1, nil); !haRefused(err) {
		t.Fatalf("automatic recovery decided with an unreadable policy: %v", err)
	}
}

// An operator promotion that must re-propose an automatic value refused for
// the disarm says so, and names the way out.
func TestOperatorPromote_ReproposalRefusalNamesTheArm(t *testing.T) {
	err := &claims.NoMajorityError{Phase: "accept", Need: 2, Refusals: []claims.Refusal{
		{Voter: "b", Reason: corrosion.RefusalHADisarmed}, {Voter: "c", Reason: corrosion.RefusalHADisarmed}}}
	if !refusedForHADisarm(err) {
		t.Fatal("the disarm refusal was not recognised")
	}
	got := haDisarmPromoteRefusal("vm1")
	if status.Code(got) != codes.FailedPrecondition ||
		!strings.Contains(got.Error(), "the workload has an automatic recovery claim in flight; HA is disarmed — run lv cluster ha arm, or wait") {
		t.Fatalf("refusal = %v", got)
	}
}
