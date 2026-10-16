package corrosion

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func TestRetainedClaimPredicatesSignedState(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	key, value := automationFixture(t, 1, "")
	installAutomationEvidence(t, a.c, key, "", 1)
	accepted, err := a.c.ClaimAccept(ctx, key, testBallot(2, "a"), value, 1, a.signer, nil)
	if err != nil || !accepted.Accepted {
		t.Fatal(accepted, err)
	}
	st, found, err := a.c.ClaimState(ctx, key)
	if err != nil || !found || st.Accept == nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"valid", "legacy-unsigned", "key", "ballot-shape", "ballot-order", "digest", "generation", "signature", "signature-domain", "promise-only", "value-without-acceptance"} {
		t.Run(mode, func(t *testing.T) {
			in := st
			if st.Accept != nil {
				copy := *st.Accept
				in.Accept = &copy
			}
			switch mode {
			case "legacy-unsigned":
				in.Accept = nil
			case "key":
				in.Key.Incarnation = "wrong"
			case "ballot-shape":
				in.Promised.Round = 0
			case "ballot-order":
				in.Promised = testBallot(1, "a")
			case "digest":
				in.ValueDigest = "corrupt"
			case "generation":
				in.ConfigGeneration = 2
			case "signature":
				in.Accept.Signature = []byte{1}
			case "signature-domain":
				in.Accept.VoterIncarnation = "other"
			case "promise-only":
				in.Accepted = Ballot{}
				in.Accept = nil
				in.Value = nil
				in.ValueDigest = ""
			case "value-without-acceptance":
				in.Accepted = Ballot{}
			}
			err := validateRetainedClaimState(in)
			valid := mode == "valid" || mode == "legacy-unsigned" || mode == "promise-only"
			if valid && err != nil {
				t.Fatal(err)
			}
			if !valid && err == nil {
				t.Fatal("retained corruption accepted", mode)
			}
		})
	}
	// Exercise the existing source reader with the same signed accepted state.
	if err = a.c.SealVoterGeneration(ctx, 1, "shared-state"); err != nil {
		t.Fatal(err)
	}
	if _, err = a.c.FreezeAutomationCut(ctx, 1, nil); err != nil {
		t.Fatal(err)
	}
	// A different cut source must fail before publishing malformed signatures.
	_, other, _, _ := threeVoters(t)
	installAutomationEvidence(t, other.c, key, "", 1)
	accepted, err = other.c.ClaimAccept(ctx, key, testBallot(2, "a"), value, 1, other.signer, nil)
	if err != nil || !accepted.Accepted {
		t.Fatal(err)
	}
	bad := *accepted.Accept
	bad.Signature = []byte{1}
	raw, _ := json.Marshal(bad)
	if _, err = other.c.db.Exec(`UPDATE local_recovery_claims SET accept_json=?`, string(raw)); err != nil {
		t.Fatal(err)
	}
	if err = other.c.SealVoterGeneration(ctx, 1, "corrupt-state"); err != nil {
		t.Fatal(err)
	}
	if _, err = other.c.FreezeAutomationCut(ctx, 1, nil); err == nil {
		t.Fatal("source adapter accepted corrupt retained signature")
	}
}

func TestRetainedAutomationParentLosingAcceptance(t *testing.T) {
	parent := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	_, value := automationFixture(t, 2, parent)
	d, err := automationDecision(value)
	if err != nil {
		t.Fatal(err)
	}
	head := AutomationPrefix{ClusterUID: "established-cluster", Sequence: 2, Digest: "chosen-value-is-different"}
	for _, mode := range []string{"losing", "frontier", "parent", "missing", "uid", "unsupported"} {
		t.Run(mode, func(t *testing.T) {
			in := d
			found := true
			switch mode {
			case "frontier":
				in.Sequence = 4
			case "parent":
				in.ParentDigest = "wrong"
			case "missing":
				found = false
			case "uid":
				in.Command.ClusterUID = "other"
			case "unsupported":
				in.Command.Body = []byte(`{"version":2}`)
			}
			err := validateRetainedAutomationParent(in, head, parent, found)
			if mode == "losing" && err != nil {
				t.Fatal("losing acceptance falsely treated as chosen-slot fork", err)
			}
			if mode != "losing" && err == nil {
				t.Fatal("invalid accepted predecessor passed", mode)
			}
		})
	}
}

func TestRetainedClaimSourceLosingAndParentRefusals(t *testing.T) {
	for _, mode := range []string{"losing", "parent", "uid", "frontier"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			_, a, b, _ := threeVoters(t)
			genesis := sharedAutomationRecord(t, 1, "", "genesis", "genesis-operation", a, b)
			key, _ := AutomationClaimKey(1)
			installAutomationEvidence(t, a.c, key, "", 1)
			if _, err := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); err != nil {
				t.Fatal(err)
			}
			loser := sharedAutomationRecord(t, 2, genesis.Value.MustDigest(), "loser", "loser-operation", a, b)
			key, _ = AutomationClaimKey(2)
			accepted, err := a.c.ClaimAccept(ctx, key, testBallot(1, "a"), loser.Value, 1, a.signer, nil)
			if err != nil || !accepted.Accepted {
				t.Fatal("losing acceptance fixture", accepted, err)
			}
			chosen := sharedAutomationRecord(t, 2, genesis.Value.MustDigest(), "chosen", "chosen-operation", a, b)
			if _, err = applySharedAutomation(t, a.c, chosen, contract.Reduce, automationFreshAnchor); err != nil {
				t.Fatal(err)
			}
			// Live chosen-slot admission remains stricter than retained source audit.
			live, err := a.c.ClaimAccept(ctx, key, testBallot(3, "a"), loser.Value, 1, a.signer, nil)
			if err != nil || live.Accepted || live.Refusal != RefusalInvalidValue {
				t.Fatal("live chosen-slot equality weakened", live, err)
			}
			if mode != "losing" {
				d, err := automationDecision(loser.Value)
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case "parent":
					d.ParentDigest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
				case "uid":
					d.Command.ClusterUID = "other-cluster"
					assignment, _ := contract.DecodeAssignment(d)
					assignment.ClusterUID = "other-cluster"
					d.Assignment, _ = json.Marshal(assignment)
				case "frontier":
					d.Sequence = 4
					d.ParentDigest = chosen.Value.MustDigest()
				}
				loser.Value.Automation.Envelope, err = contract.EncodeDecision(d)
				if err != nil {
					t.Fatal(err)
				}
				newKey, _ := AutomationClaimKey(d.Sequence)
				signed, err := a.signer.Sign(newKey, 1, testBallot(1, "a"), loser.Value.MustDigest(), a.inc)
				if err != nil {
					t.Fatal(err)
				}
				value, _ := json.Marshal(loser.Value)
				signature, _ := json.Marshal(signed)
				if _, err = a.c.db.Exec(`UPDATE local_recovery_claims SET owner_epoch=?,value_json=?,value_digest=?,accept_json=? WHERE target_kind='automation' AND owner_epoch=2`, d.Sequence, string(value), loser.Value.MustDigest(), string(signature)); err != nil {
					t.Fatal(err)
				}
			}
			if err = a.c.SealVoterGeneration(ctx, 1, "shared losing acceptance"); err != nil {
				t.Fatal(err)
			}
			before := sharedActiveRows(t, a.c)
			_, err = a.c.FreezeAutomationCut(ctx, 1, contract.Reduce)
			if mode == "losing" && err != nil {
				t.Fatal("legitimate source loser refused", err)
			}
			if mode != "losing" && err == nil {
				t.Fatal("source accepted invalid retained predecessor", mode)
			}
			if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
				t.Fatal("source audit changed retained active history")
			}
		})
	}
}

func TestAutomationStateLegacySignatureDomain(t *testing.T) {
	for _, mode := range []string{"nonempty", "empty"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			_, a, _, _ := threeVoters(t)
			key, value := automationFixture(t, 1, "")
			ballot := testBallot(2, "a")
			incarnation := a.inc
			if mode == "empty" {
				incarnation = ""
			}
			signed, err := a.signer.Sign(key, 1, ballot, value.MustDigest(), incarnation)
			if err != nil {
				t.Fatal(err)
			}
			state := ClaimVoterState{Key: key, Promised: ballot, Accepted: ballot, Value: &value, ValueDigest: value.MustDigest(), ConfigGeneration: 1, Accept: &signed}
			if err = ValidateAutomationState(state); err != nil {
				t.Fatal("BASE-compatible live/load signature domain refused", err)
			}
			if err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return saveClaimRowTx(ctx, tx, state) }); err != nil {
				t.Fatal("BASE-compatible retained state could not be stored", err)
			}
			loaded, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found || loaded.Accept == nil || loaded.Accept.VoterIncarnation != incarnation {
				t.Fatal("BASE-compatible retained state could not be loaded", err)
			}
			strictErr := validateRetainedAutomationAccept(*loaded.Accept, key, ballot, 1, value.MustDigest())
			if (strictErr == nil) != (mode == "nonempty") {
				t.Fatal("retained-source binding changed its nonempty domain rule", strictErr)
			}
			if err = a.c.SealVoterGeneration(ctx, 1, "legacy signature domain"); err != nil {
				t.Fatal(err)
			}
			_, err = a.c.FreezeAutomationCut(ctx, 1, nil)
			if (err == nil) != (mode == "nonempty") {
				t.Fatal("source adapter changed its nonempty domain rule", err)
			}
			after, found, err := a.c.ClaimState(ctx, key)
			if err != nil || !found || after.Accept == nil || after.ValueDigest != state.ValueDigest || after.Accept.VoterIncarnation != incarnation || string(after.Accept.Signature) != string(signed.Signature) || after.Accept.CertPEM != signed.CertPEM {
				t.Fatal("source audit changed retained signed state", err)
			}
		})
	}
}
