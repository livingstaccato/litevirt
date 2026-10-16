package corrosion

import (
	"context"
	"testing"
)

func TestAutomationAnchorSharedSignedPredicates(t *testing.T) {
	_, a, b, _ := threeVoters(t)
	original := sharedAutomationRecord(t, 1, "", "original", "operation", a, b)
	target := sharedAutomationRecord(t, 2, original.Value.MustDigest(), "barrier", "barrier-operation", a, b)
	cfg, err := AdoptedVoterConfig(context.Background(), a.c)
	if err != nil {
		t.Fatal(err)
	}
	base := automationAnchorInput{Sequence: 1, AnchorSequence: 2, Digest: original.Value.MustDigest(), AnchorDigest: original.Value.MustDigest(), Generation: 1, MembersHash: cfg.MembersHash, Certificate: target.Certificate, Target: target.Value, TargetDigest: target.Value.MustDigest(), Membership: cfg}
	for _, mode := range []string{"later-target", "own-target", "target-digest", "target-value", "target-before-slot", "member-incarnation", "duplicate-member", "duplicate-incarnation", "signature", "minority", "generation"} {
		t.Run(mode, func(t *testing.T) {
			in := base
			in.Certificate.Accepts = append([]ClaimAccept(nil), base.Certificate.Accepts...)
			members := *cfg
			members.Members = append([]VoterMember(nil), cfg.Members...)
			in.Membership = &members
			switch mode {
			case "own-target":
				in.AnchorSequence = 1
				in.Certificate = original.Certificate
				in.Target = original.Value
				in.TargetDigest = original.Value.MustDigest()
			case "target-digest":
				in.TargetDigest = "corrupt"
			case "target-value":
				in.Target = original.Value
			case "target-before-slot":
				in.AnchorSequence = 0
			case "member-incarnation":
				in.Certificate.Accepts[0].VoterIncarnation = "wrong"
			case "duplicate-member":
				in.Certificate.Accepts[1] = in.Certificate.Accepts[0]
			case "duplicate-incarnation":
				members.Members[1].Incarnation = members.Members[0].Incarnation
				members.MembersHash = MembersHash(members.Members)
				in.MembersHash = members.MembersHash
				signed, err := b.signer.Sign(in.Certificate.Key, 1, in.Certificate.Ballot, in.Certificate.ValueDigest, a.inc)
				if err != nil {
					t.Fatal(err)
				}
				in.Certificate.Accepts[1] = signed
			case "signature":
				in.Certificate.Accepts[0].Signature = []byte{1}
			case "minority":
				in.Certificate.Accepts = in.Certificate.Accepts[:1]
			case "generation":
				in.Generation = 2
			}
			err := validateAutomationAnchor(in)
			valid := mode == "later-target" || mode == "own-target"
			if valid && err != nil {
				t.Fatal(err)
			}
			if !valid && err == nil {
				t.Fatal("corrupt anchor passed", mode)
			}
		})
	}
}
