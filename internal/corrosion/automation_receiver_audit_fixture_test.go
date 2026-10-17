package corrosion

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
)

// This fixture chooses ordinary membership with actual persisted votes from
// three old voters, applies genuinely certified native automation, freezes G,
// and adopts G+1 before publishing to a new receiver lifetime. Authority setup
// is test-only; it does not implement a production bootstrap/import writer.
func receiverAuditFixture(t *testing.T, n int, beforeFreeze func(*claimTestVoter, []*claimTestVoter)) (*AutomationSourcePreparer, *AutomationReceiver, AutomationExportRequest, context.Context, string) {
	return receiverAuditFixtureOptions(t, n, receiverAuditOptions{beforeFreeze: beforeFreeze})
}

type receiverAuditOptions struct {
	initial        func(*claimTestVoter, []*claimTestVoter)
	beforeApply    func(*claimTestVoter, []*claimTestVoter, AutomationRecord)
	beforeFreeze   func(*claimTestVoter, []*claimTestVoter)
	recovery       bool
	legacy         bool
	legacyLease    bool
	legacyAccepted func(ClaimVoterState)
	explicitSeal   bool
	uniqueRequests bool
}

func receiverAuditFixtureOptions(t *testing.T, n int, options receiverAuditOptions) (*AutomationSourcePreparer, *AutomationReceiver, AutomationExportRequest, context.Context, string) {
	t.Helper()
	ctx := context.Background()
	ca := newClaimTestCA(t)
	a, c, d, b := newClaimTestVoter(t, ca, "a"), newClaimTestVoter(t, ca, "c"), newClaimTestVoter(t, ca, "d"), newClaimTestVoter(t, ca, "b")
	voters := []*claimTestVoter{a, c, d}
	if err := copyTestFile(ca.key, filepath.Join(a.pki, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if options.initial != nil {
		options.initial(a, voters)
	}
	choose := func(prev *VoterConfig, value VoterConfigValue) *VoterConfig {
		key := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: value.Generation - 1}
		ballot := testBallot(1, "a")
		cert := ClaimCertificate{Key: key, ConfigGeneration: key.OwnerEpoch, Ballot: ballot, ValueDigest: (ClaimValue{Config: &value}).MustDigest()}
		for _, voter := range voters {
			result, err := voter.c.ClaimAccept(ctx, key, ballot, ClaimValue{Config: &value}, key.OwnerEpoch, voter.signer, nil)
			if err != nil || !result.Accepted || result.Accept == nil {
				t.Fatal("real ordinary membership vote", result, err)
			}
			cert.Accepts = append(cert.Accepts, *result.Accept)
		}
		raw, err := cert.Encode()
		if err != nil {
			t.Fatal(err)
		}
		row := &VoterConfig{VoterConfigValue: value, MembersHash: MembersHash(value.Members), Certificate: raw}
		view, err := pki.CaptureHostTrust(ctx, a.pki, "a")
		if err != nil {
			t.Fatal(err)
		}
		if err = VerifyVoterConfigRow(&ClaimVerifier{sourceTrust: view, pinned: true}, prev, row); err != nil {
			t.Fatal("verified ordinary membership", err)
		}
		return row
	}
	first := choose(nil, VoterConfigValue{Generation: 1, Members: membersOf(a, c, d), Change: VoterChangeGenesis, CreatedBy: "a", CreatedAt: "t"})
	cert, _ := DecodeClaimCertificate(first.Certificate)
	for _, voter := range voters {
		if err := WriteVoterConfig(ctx, voter.c, first.VoterConfigValue, cert); err != nil {
			t.Fatal(err)
		}
		if err := RecordVoterAdoption(ctx, voter.c, 1); err != nil {
			t.Fatal(err)
		}
	}
	generation := int64(1)
	if options.legacy {
		if n != 0 {
			t.Fatal("legacy fixture isolates ordinary claims from future active automation import")
		}
		k := workloadKey()
		value := workloadValue("original-legacy", "a", "ghost")
		if options.legacyLease {
			k = LeaseTermClaimKey("future_lease", 7)
			value = ClaimValue{LeaseTerm: &LeaseTermValue{Key: k.TargetName, Term: k.OwnerEpoch, Holder: "a"}}
		}
		accepted, err := a.c.ClaimAccept(ctx, k, testBallot(2, "a"), value, 1, a.signer, unreachable)
		if err != nil || !accepted.Accepted {
			t.Fatal(err)
		}
		if reply, err := c.c.ClaimPrepare(ctx, k, testBallot(9, "c"), 1); err != nil || !reply.Promised {
			t.Fatal("actual higher imported promise", err)
		}
		e := newClaimTestVoter(t, ca, "e")
		next := choose(first, VoterConfigValue{Generation: 2, Members: membersOf(a, c, d, e), Change: "add:e", CreatedBy: "a", CreatedAt: "t2"})
		var states []ClaimVoterState
		for _, voter := range voters {
			state, found, err := voter.c.ClaimState(ctx, ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 1})
			if err != nil || !found {
				t.Fatal(err)
			}
			states = append(states, state)
		}
		original, found, err := a.c.ClaimState(ctx, k)
		if err != nil || !found {
			t.Fatal(err)
		}
		if options.legacyAccepted != nil {
			options.legacyAccepted(original)
		}
		states = append(states, original)
		promise, found, err := c.c.ClaimState(ctx, k)
		if err != nil || !found {
			t.Fatal(err)
		}
		states = append(states, promise)
		cert, _ := DecodeClaimCertificate(next.Certificate)
		for _, voter := range voters {
			if err = WriteVoterConfig(ctx, voter.c, next.VoterConfigValue, cert); err != nil {
				t.Fatal(err)
			}
			if _, err = voter.c.ImportClaimsAndAdopt(ctx, 2, []string{"a", "c", "d"}, states); err != nil {
				t.Fatal(err)
			}
		}
		first = next
		generation = 2
	}
	if n > 0 {
		key, _ := AutomationClaimKey(1)
		installAutomationEvidence(t, a.c, key, "", 1)
	}
	verifier, err := LoadClaimVerifier(a.pki)
	if err != nil {
		t.Fatal(err)
	}
	var recoveryRecords []AutomationRecord // test fixture only; production readers remain bounded
	parent := ""
	for i := 1; i <= n; i++ {
		request, operation := "req", "op"
		if i > 1 {
			request, operation = "barrier", "barrier-op"
			if options.uniqueRequests && i > 2 {
				request = "operation-collision"
			}
		}
		record := sharedAutomationRecord(t, uint64(i), parent, request, operation, voters...)
		if options.beforeApply != nil {
			options.beforeApply(a, voters, record)
		}
		if options.recovery {
			recoveryRecords = append(recoveryRecords, record)
		} else if _, err = a.c.AutomationApply(ctx, record, verifier, contract.Reduce); err != nil {
			t.Fatal("genuine native application", err)
		}
		parent = record.Value.MustDigest()
	}
	if options.recovery {
		if len(recoveryRecords) < 2 {
			t.Fatal("recovery fixture requires ancestry")
		}
		if err = a.c.AutomationBeginRecovery(ctx, recoveryRecords[len(recoveryRecords)-1], verifier); err != nil {
			t.Fatal(err)
		}
		for i := len(recoveryRecords) - 2; i >= 0; i-- {
			if err = a.c.AutomationStagePredecessor(ctx, recoveryRecords[i]); err != nil {
				t.Fatal(err)
			}
		}
		if err = a.c.AutomationFinishRecovery(ctx, contract.Reduce, n+1); err != nil {
			t.Fatal(err)
		}
	}
	if options.beforeFreeze != nil {
		options.beforeFreeze(a, voters)
	}
	second := choose(first, VoterConfigValue{Generation: generation + 1, Members: SortMembers(append(append([]VoterMember(nil), first.Members...), VoterMember{Name: b.name, Incarnation: b.inc})), Change: "add:b", CreatedBy: "a", CreatedAt: "t2"})
	if options.explicitSeal {
		if err = a.c.SealVoterGeneration(ctx, generation, "native frozen audit fixture"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = a.c.FreezeAutomationCut(ctx, generation, contract.Reduce); err != nil {
		t.Fatal("freeze complete native history", err)
	}
	cert, _ = DecodeClaimCertificate(second.Certificate)
	if err = WriteVoterConfig(ctx, a.c, second.VoterConfigValue, cert); err != nil {
		t.Fatal(err)
	}
	var states []ClaimVoterState
	for _, voter := range voters {
		state, found, e := voter.c.ClaimState(ctx, ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: generation})
		if e != nil || !found {
			t.Fatal(e)
		}
		states = append(states, state)
	}
	if _, err = a.c.ImportClaimsAndAdopt(ctx, generation+1, []string{"a", "c", "d"}, states); err != nil {
		t.Fatal("real successor adoption", err)
	}
	intent := AutomationSourceRequest{Generation: generation, Target: "b", Job: "owned", Revision: 1, Sources: first.Members}
	return receiverFixtureProducer(t, NewAutomationSourcePreparer(a.c, a.pki), intent, b)
}
