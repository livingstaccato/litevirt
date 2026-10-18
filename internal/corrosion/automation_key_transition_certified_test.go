package corrosion

import (
	"context"
	"fmt"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
	"reflect"
	"strings"
	"testing"
)

func keyCertifiedMismatch(t *testing.T) (*claimTestVoter, AutomationRecord, AutomationRecord) {
	t.Helper()
	ctx := context.Background()
	_, a, b, c := threeVoters(t)
	genesis := sharedAutomationRecord(t, 1, "", "initialize", "initialize-operation", a, b)
	if _, e := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); e != nil {
		t.Fatal(e)
	}
	current := keyActivationRecordFor(t, a, genesis, []*claimTestVoter{a, b, c})
	cfgA, e := AdoptedVoterConfig(ctx, a.c)
	if e != nil {
		t.Fatal(e)
	}
	cfgB := VoterConfigValue{Generation: 2, Members: membersOf(a, b), Change: VoterChangeRm("c"), CreatedBy: "a", CreatedAt: "t2"}
	cfgKey := ClaimKey{TargetKind: ClaimKindVoterConfig, OwnerEpoch: 1}
	cfgValue := ClaimValue{Config: &cfgB}
	cfgCert := ClaimCertificate{Key: cfgKey, Ballot: testBallot(7, "a"), ConfigGeneration: 1, ValueDigest: cfgValue.MustDigest()}
	for _, voter := range []*claimTestVoter{a, b, c} {
		accept, e := voter.signer.Sign(cfgKey, 1, cfgCert.Ballot, cfgCert.ValueDigest, voter.inc)
		if e != nil {
			t.Fatal(e)
		}
		cfgCert.Accepts = append(cfgCert.Accepts, accept)
	}
	raw, e := cfgCert.Encode()
	if e != nil {
		t.Fatal(e)
	}
	view, e := pki.CaptureHostTrust(ctx, a.pki, "a")
	if e != nil {
		t.Fatal(e)
	}
	verifier := &ClaimVerifier{sourceTrust: view, pinned: true}
	if e = VerifyVoterConfigRow(verifier, cfgA, &VoterConfig{VoterConfigValue: cfgB, MembersHash: MembersHash(cfgB.Members), Certificate: raw}); e != nil {
		t.Fatal("real B membership certificate", e)
	}
	if e = WriteVoterConfig(ctx, a.c, cfgB, cfgCert); e != nil {
		t.Fatal(e)
	}
	original := current
	current.Certificate.ConfigGeneration = 2
	current.Certificate.Accepts = nil
	for _, voter := range []*claimTestVoter{a, b} {
		accept, e := voter.signer.Sign(current.Certificate.Key, 2, current.Certificate.Ballot, current.Certificate.ValueDigest, voter.inc)
		if e != nil {
			t.Fatal(e)
		}
		current.Certificate.Accepts = append(current.Certificate.Accepts, accept)
	}
	if e = verifier.Verify(current.Certificate, CertExpectation{Key: current.Certificate.Key, ValueDigest: current.Value.MustDigest(), ConfigGeneration: 2, Electorate: cfgB.Members, Quorum: MajorityOf(len(cfgB.Members))}); e != nil {
		t.Fatal("real B transition certificate", e)
	}
	return a, original, current
}

// Both certificates are authentic. The original is B while the independently
// valid recovery anchor remains A, so selecting the anchor would mask the bug.
func keyMismatchRetainedHistory(t *testing.T) *claimTestVoter {
	t.Helper()
	a, original, bad := keyCertifiedMismatch(t)
	if _, e := applySharedAutomation(t, a.c, original, contract.Reduce, automationFreshAnchor); e != nil {
		t.Fatal(e)
	}
	raw, e := bad.Certificate.Encode()
	if e != nil {
		t.Fatal(e)
	}
	if _, e = a.c.db.Exec(`UPDATE local_automation_history SET certificate=? WHERE sequence=2`, raw); e != nil {
		t.Fatal(e)
	}
	return a
}
func TestAutomationKeyTransitionOriginalElectorateReplay(t *testing.T) {
	a := keyMismatchRetainedHistory(t)
	ctx := context.Background()
	if e := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") }); e != nil {
		t.Fatal(e)
	}
	first, found, e := a.c.AutomationRecord(ctx, 1)
	if e != nil || !found {
		t.Fatal(e)
	}
	if _, e = applySharedAutomation(t, a.c, first, contract.Reduce, automationAnchoredReplay); e != nil {
		t.Fatal(e)
	}
	before := sharedActiveRows(t, a.c)
	keys := keyTransitionSnapshot(t, a.c)
	e = a.c.AutomationReplay(ctx, contract.Reduce, 3)
	if e == nil {
		t.Error("replay installed A transition with valid original B certificate")
	} else if !strings.Contains(e.Error(), "original certificate electorate") {
		t.Fatal("wrong replay refusal", e)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) || !reflect.DeepEqual(keys, keyTransitionSnapshot(t, a.c)) {
		t.Error("refused replay changed active state")
	}
}
func TestAutomationKeyTransitionOriginalElectorateReceiver(t *testing.T) {
	a := keyMismatchRetainedHistory(t)
	ctx := context.Background()
	before := sharedActiveRows(t, a.c)
	keys := keyTransitionSnapshot(t, a.c)
	e := a.c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		head, e := automationHeadTx(ctx, tx)
		if e != nil {
			return e
		}
		s := receiverAuditStore{tx: tx, attempt: "certified-negative", source: "a", id: "certified-negative", publication: receiverPublication{manifest: sourceManifest{Cut: automationCutMetadata{Head: head, Inventory: make([]automationCutInventory, len(automationCutSections))}}}}
		// Actual finite receiver frames/indexes from the explicitly certified
		// historical premise. No network or source-authentication success is claimed.
		for section, descriptor := range automationCutSections {
			if section != 2 && section != 3 && section != 4 && section != 8 {
				continue
			}
			rows, e := tx.Query(ctx, "SELECT "+descriptor.columns+" FROM "+descriptor.table+" ORDER BY rowid")
			if e != nil {
				return e
			}
			s.publication.manifest.Cut.Inventory[section].Records = int64(len(rows))
			for i, row := range rows {
				raw, e := encodeAutomationCutRecord(descriptor.name, int64(i+1), row)
				if e != nil {
					return e
				}
				if _, e = tx.Exec(ctx, `INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) VALUES(?,?,?,?,?)`, s.attempt, s.source, section+3, i+1, raw); e != nil {
					return e
				}
			}
		}
		if _, e = s.index(ctx); e != nil {
			return fmt.Errorf("index: %w", e)
		}
		_, _, e = s.history(ctx)
		return e
	})
	if e == nil {
		t.Error("receiver installed A transition with valid original B certificate")
	} else if !strings.Contains(e.Error(), "original certificate electorate") {
		t.Fatal("wrong receiver refusal", e)
	}
	if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) || !reflect.DeepEqual(keys, keyTransitionSnapshot(t, a.c)) {
		t.Error("refused receiver changed derived state")
	}

}
