package corrosion

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// These deliberately corrupted retained rows exercise the private trusted-read
// boundary, not installation or certificate authority. No fresh admission is
// inferred from the test rows. Removing any canonical, union, binding or bound
// check must change the actual stored-read result below.
func TestAutomationTrustedHistoryCanonicalBoundary(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	c := a.c
	ctx := context.Background()
	_, valid := automationFixture(t, 2, strings.Repeat("a", 64))
	digest := valid.MustDigest()
	rawValue := func(v ClaimValue) string {
		b, e := json.Marshal(v)
		if e != nil {
			t.Fatal(e)
		}
		return string(b)
	}
	raw := rawValue(valid)
	inner := func(s string) string {
		return rawValue(ClaimValue{Automation: &AutomationClaimValue{Envelope: []byte(s)}})
	}
	type specimen struct {
		name, raw, digest, anchor string
		sequence                  uint64
		absent, bad               bool
	}
	cases := []specimen{
		{name: "valid", raw: raw},
		{name: "outer-unknown", raw: `{"unknown":1,` + raw[1:], bad: true},
		{name: "outer-duplicate", raw: `{"automation":null,` + raw[1:], bad: true},
		{name: "outer-trailing", raw: raw + ` {}`, bad: true},
		{name: "inner-unknown", raw: inner(`{"unknown":1,` + string(valid.Automation.Envelope[1:])), bad: true},
		{name: "inner-duplicate", raw: inner(`{"Version":1,` + string(valid.Automation.Envelope[1:])), bad: true},
		{name: "inner-trailing", raw: inner(string(valid.Automation.Envelope) + ` {}`), bad: true},
		{name: "inner-empty", raw: inner(""), bad: true},
		{name: "inner-native-bound", raw: inner(strings.Repeat(" ", contract.MaxDecisionBytes+1)), bad: true},
		{name: "outer-native-bound", raw: strings.Repeat(" ", MaxAutomationClaimBytes+1), absent: true},
		{name: "key-sequence", raw: raw, sequence: 3, bad: true},
		{name: "digest-corruption", raw: raw, digest: strings.Repeat("b", 64), anchor: strings.Repeat("b", 64), bad: true},
		{name: "anchor-corruption", raw: raw, anchor: strings.Repeat("b", 64), bad: true},
		{name: "missing-anchor", raw: raw, anchor: "missing", absent: true},
		{name: "short-digest", raw: raw, digest: "short", absent: true},
		{name: "short-anchor", raw: raw, anchor: "short", absent: true},
	}
	for name, extra := range map[string]ClaimValue{
		"empty-present-proof": {Proof: &ActionProof{}}, "config": {Config: &VoterConfigValue{}},
		"lun": {LUN: &LUNAllocation{}}, "lease": {LeaseTerm: &LeaseTermValue{}}, "source": {SourceHost: "host"},
	} {
		extra.Automation = valid.Automation
		cases = append(cases, specimen{name: name, raw: rawValue(extra), bad: true})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			seq := tc.sequence
			if seq == 0 {
				seq = 2
			}
			stored := tc.digest
			if stored == "" {
				stored = digest
			}
			anchor := tc.anchor
			if anchor == "" {
				anchor = digest
			}
			e := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if _, e := tx.Exec(ctx, `DELETE FROM local_automation_history`); e != nil {
					return e
				}
				if _, e := tx.Exec(ctx, `DELETE FROM local_automation_anchors`); e != nil {
					return e
				}
				if _, e := tx.Exec(ctx, `INSERT INTO local_automation_history(sequence,digest,value_json,certificate,receipt_json,anchor_sequence) VALUES(?,?,?,'','',?)`, seq, stored, tc.raw, seq); e != nil {
					return e
				}
				if anchor != "missing" {
					if _, e := tx.Exec(ctx, `INSERT INTO local_automation_anchors(sequence,digest,generation,members_hash,certificate) VALUES(?,?,1,'','')`, seq, anchor); e != nil {
						return e
					}
				}
				got, found, e := automationTrustedDigestTx(ctx, tx, seq)
				if tc.bad {
					if e == nil || found || got != "" {
						t.Errorf("corrupt original accepted: digest=%q found=%v err=%v", got, found, e)
					}
					var corrupt *automationProofCorruptionError
					if !errors.As(e, &corrupt) || errors.Unwrap(e) == nil || e.Error() != errors.Unwrap(e).Error() {
						t.Errorf("stored validation lost typed cause or changed error text: %T %v", e, e)
					}
				} else if tc.absent {
					if e != nil || found || got != "" {
						t.Errorf("filtered original changed absence: %q %v %v", got, found, e)
					}
				} else if e != nil || !found || got != digest {
					t.Errorf("exact original digest changed: %q %v %v", got, found, e)
				}
				if !tc.bad && !tc.absent {
					head, e := automationRetainedHeadTx(ctx, tx)
					if e != nil || head.Sequence != 2 || head.ClusterUID != "established-cluster" || head.Digest != digest {
						t.Errorf("retained identity changed: %+v %v", head, e)
					}
				}
				return nil
			})
			if e != nil {
				t.Fatal(e)
			}
		})
	}
}

// A generic canonical genesis envelope can have an assignment that is invalid
// for the typed head. Digest-only callers must keep their previous behavior;
// retained-head authority must continue to require DecodeAssignment.
func TestAutomationTrustedGenesisAssignmentBoundary(t *testing.T) {
	_, a, _, _ := threeVoters(t)
	ctx := context.Background()
	_, value := automationFixture(t, 1, "")
	d, e := contract.DecodeDecision(value.Automation.Envelope)
	if e != nil {
		t.Fatal(e)
	}
	d.Assignment = []byte(`{"version":1}`)
	value.Automation.Envelope, e = contract.EncodeDecision(d)
	if e != nil {
		t.Fatal(e)
	}
	digest := value.MustDigest()
	raw, e := json.Marshal(value)
	if e != nil {
		t.Fatal(e)
	}
	e = a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if _, e := tx.Exec(ctx, `INSERT INTO local_automation_history(sequence,digest,value_json,certificate,receipt_json,anchor_sequence) VALUES(1,?,?,'','',1)`, digest, string(raw)); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `INSERT INTO local_automation_anchors(sequence,digest,generation,members_hash,certificate) VALUES(1,?,1,'','')`, digest); e != nil {
			return e
		}
		got, found, e := automationTrustedDigestTx(ctx, tx, 1)
		if e != nil || !found || got != digest {
			t.Errorf("digest-only genesis tightened: %q %v %v", got, found, e)
		}
		if _, e := automationRetainedHeadTx(ctx, tx); e == nil {
			t.Error("malformed typed genesis assignment established head")
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}
