package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Real signed 1 MiB ciphertext, independently stored in history and claim rows.
func ciphertextState(t *testing.T, a *claimTestVoter) ClaimVoterState {
	t.Helper()
	key, value := automationFixture(t, 2, strings.Repeat("a", 64))
	d, err := contract.DecodeDecision(value.Automation.Envelope)
	if err != nil {
		t.Fatal(err)
	}
	d.Command.Ciphertext = bytes.Repeat([]byte{103}, 1<<20)
	value.Automation.Envelope, err = contract.EncodeDecision(d)
	if err != nil {
		t.Fatal(err)
	}
	ballot := testBallot(3, "b")
	digest := value.MustDigest()
	accept, err := a.signer.Sign(key, 1, ballot, digest, a.inc)
	if err != nil {
		t.Fatal(err)
	}
	return ClaimVoterState{Key: key, Promised: ballot, Accepted: ballot, Value: &value, ValueDigest: digest, ConfigGeneration: 1, Accept: &accept}
}

func mutateCiphertextEnvelope(t *testing.T, b []byte, kind string) []byte {
	t.Helper()
	switch kind {
	case "unknown":
		return append([]byte(`{"unknown":0,`), b[1:]...)
	case "duplicate":
		return append([]byte(`{"Version":1,`), b[1:]...)
	case "noncanonical":
		return append(bytes.Clone(b), ' ')
	case "canonical-ciphertext":
		d, err := contract.DecodeDecision(b)
		if err != nil {
			t.Fatal(err)
		}
		d.Command.Ciphertext[0] ^= 1
		out, err := contract.EncodeDecision(d)
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	t.Fatal("unknown mutation")
	return nil
}

// A successful validation/read cannot authorize saving bytes mutated later.
// Removing saveClaimRowTx's independent validator must make this test fail.
func TestAutomationCiphertextIndependentSaveMutation(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	base := ciphertextState(t, a)
	base.Promised = testBallot(5, "b")
	if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return saveClaimRowTx(ctx, tx, base) }); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"unknown", "duplicate", "noncanonical", "canonical-ciphertext", "signature"} {
		for _, order := range []string{"stale", "increasing"} {
			t.Run(kind+"/"+order, func(t *testing.T) {
				state, found, err := a.c.ClaimState(ctx, base.Key)
				if err != nil || !found {
					t.Fatal("actual valid load", err)
				}
				if err = ValidateAutomationState(state); err != nil {
					t.Fatal("actual independent validation", err)
				}
				if order == "stale" {
					state.Promised = testBallot(4, "b")
				} else {
					state.Promised = testBallot(6, "b")
				}
				if err = ValidateAutomationState(state); err != nil {
					t.Fatal("valid candidate after promise adjustment", err)
				}
				if kind == "signature" {
					state.Accept.Signature[0] ^= 1
				} else {
					state.Value.Automation.Envelope = mutateCiphertextEnvelope(t, state.Value.Automation.Envelope, kind)
				}
				before := receiverActive(t, a.c)
				err = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return saveClaimRowTx(ctx, tx, state) })
				if err == nil {
					t.Fatal("independent save accepted mutated actual state")
				}
				if receiverActive(t, a.c) != before {
					t.Fatal("rejected save changed exact ACTIVE snapshot")
				}
			})
		}
	}
}

// Trust in one original must never authorize the separately stored other one.
func TestAutomationCiphertextOriginalMutation(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	base := ciphertextState(t, a)
	original, err := json.Marshal(base.Value)
	if err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"history", "claim"} {
		for _, kind := range []string{"unknown", "duplicate", "noncanonical", "canonical-ciphertext", "signature"} {
			if owner == "history" && kind == "signature" {
				continue
			}
			t.Run(owner+"/"+kind, func(t *testing.T) {
				if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					if _, err := tx.Exec(ctx, `DELETE FROM local_automation_history`); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `DELETE FROM local_automation_anchors`); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `INSERT INTO local_automation_history(sequence,digest,value_json,certificate,receipt_json,anchor_sequence) VALUES(2,?,?,'','',2)`, base.ValueDigest, string(original)); err != nil {
						return err
					}
					if _, err := tx.Exec(ctx, `INSERT INTO local_automation_anchors(sequence,digest,generation,members_hash,certificate) VALUES(2,?,1,'','')`, base.ValueDigest); err != nil {
						return err
					}
					return saveClaimRowTx(ctx, tx, base)
				}); err != nil {
					t.Fatal(err)
				}
				if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					if kind == "signature" {
						accept := *base.Accept
						accept.Signature = bytes.Clone(accept.Signature)
						accept.Signature[0] ^= 1
						raw, err := json.Marshal(accept)
						if err != nil {
							return err
						}
						_, err = tx.Exec(ctx, `UPDATE local_recovery_claims SET accept_json=? WHERE target_kind=? AND target_name=? AND owner_epoch=? AND attempt=?`, string(raw), base.Key.TargetKind, base.Key.TargetName, base.Key.OwnerEpoch, base.Key.Attempt)
						return err
					}
					bad := ClaimValue{Automation: &AutomationClaimValue{Envelope: mutateCiphertextEnvelope(t, base.Value.Automation.Envelope, kind)}}
					raw, err := json.Marshal(bad)
					if err != nil {
						return err
					}
					if owner == "history" {
						_, err = tx.Exec(ctx, `UPDATE local_automation_history SET value_json=? WHERE sequence=2`, string(raw))
					} else {
						_, err = tx.Exec(ctx, `UPDATE local_recovery_claims SET value_json=? WHERE target_kind=? AND target_name=? AND owner_epoch=? AND attempt=?`, string(raw), base.Key.TargetKind, base.Key.TargetName, base.Key.OwnerEpoch, base.Key.Attempt)
					}
					return err
				}); err != nil {
					t.Fatal(err)
				}
				before := receiverActive(t, a.c)
				if err := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
					digest, found, herr := automationTrustedDigestTx(ctx, tx, 2)
					_, claimFound, cerr := loadClaimRowTx(ctx, tx, base.Key)
					if owner == "history" {
						if herr == nil || found || digest != "" {
							t.Error("corrupt history accepted")
						}
						if cerr != nil || !claimFound {
							t.Error("separate valid claim refused", cerr)
						}
					} else {
						if herr != nil || !found || digest != base.ValueDigest {
							t.Error("separate valid history refused", herr)
						}
						if cerr == nil || claimFound {
							t.Error("corrupt claim accepted")
						}
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				if receiverActive(t, a.c) != before {
					t.Fatal("read of corrupt original changed exact ACTIVE snapshot")
				}
			})
		}
	}
}
