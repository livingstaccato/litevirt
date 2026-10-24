package corrosion

import (
	"bytes"
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/automation/custody"
	"github.com/litevirt/litevirt/internal/pki"
)

// Only established electorate/authority/genesis are fixtures. The custody
// transition under test must subsequently use real native stores and votes.
func custodySeededAuthorityFixture(t *testing.T) ([]*claimTestVoter, []*AutomationCustodyProducer) {
	t.Helper()
	ctx := context.Background()
	ca := newClaimTestCA(t)
	var voters []*claimTestVoter
	for _, name := range []string{"a", "b", "c"} {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		db, err := NewLocalClient(dir, name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { db.Close() })
		if err = InitSchema(ctx, db); err != nil {
			t.Fatal(err)
		}
		db.SetVoterConfigGate(func() bool { return true })
		inc, err := db.VoterIncarnation(ctx)
		if err != nil {
			t.Fatal(err)
		}
		pd := ca.pkiDir(t, name)
		signer, err := LoadClaimSigner(pd, name)
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := LoadClaimVerifier(pd)
		if err != nil {
			t.Fatal(err)
		}
		db.SetClaimCertificateVerifier(func() *ClaimVerifier { return verifier })
		voters = append(voters, &claimTestVoter{name: name, c: db, pki: pd, signer: signer, inc: inc})
	}
	adoptHandBuilt(t, 1, membersOf(voters...), voters...)
	initial := sharedAutomationRecord(t, 1, "", "req", "genesis", voters[0], voters[1])
	key, _ := AutomationClaimKey(1)
	var producers []*AutomationCustodyProducer
	for _, v := range voters {
		installAutomationEvidence(t, v.c, key, "", 1)
		if _, err := applySharedAutomation(t, v.c, initial, contract.Reduce, automationFreshAnchor); err != nil {
			t.Fatal("seeded genesis", err)
		}
		for _, host := range voters {
			pair, err := pki.ServedHostKeyPair(host.pki)
			if err != nil {
				t.Fatal(err)
			}
			leaf, err := x509.ParseCertificate(pair.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			if err = InsertHost(ctx, v.c, HostRecord{Name: host.name, Address: "127.0.0.1", GRPCPort: 7443, State: "up", CertSerial: leaf.SerialNumber.Text(16)}); err != nil {
				t.Fatal(err)
			}
		}
		root := t.TempDir()
		if err := os.Chmod(root, 0700); err != nil {
			t.Fatal(err)
		}
		p, err := NewAutomationCustodyProducer(v.c, v.pki, filepath.Join(root, "automation-custody"))
		if err != nil {
			t.Fatal(err)
		}
		producers = append(producers, p)
	}
	return voters, producers
}

func TestCustodyNativePreparationWithSeededAuthorityGenesis(t *testing.T) {
	voters, producers := custodySeededAuthorityFixture(t)
	attempt, err := producers[0].PrepareInitialEpoch(context.Background())
	if err != nil || attempt == nil {
		t.Fatalf("native initial custody preparation unavailable: %v", err)
	}
	h, err := voters[0].c.AutomationHead(context.Background())
	if err != nil || h.Sequence != 1 {
		t.Fatal("preparation changed certified history")
	}
}

func TestCustodyNativePreparationRequiresActualAuthority(t *testing.T) {
	voters, producers := custodySeededAuthorityFixture(t)
	if _, err := voters[0].c.db.Exec(`DELETE FROM local_automation_authority`); err != nil {
		t.Fatal(err)
	}
	if attempt, err := producers[0].PrepareInitialEpoch(context.Background()); err == nil || attempt != nil {
		t.Fatal("missing authority manufactured a custody attempt")
	}
}

// Local delivery exercises the same physical/signature/FULL barrier as a peer,
// without manufacturing a TLS identity for the local host.
func TestCustodyNativeLocalRecipientAndImportSeededPrerequisites(t *testing.T) {
	voters, producers := custodySeededAuthorityFixture(t)
	p := producers[0]
	ctx := context.Background()
	attempt, err := p.PrepareInitialEpoch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var candidate contract.CustodyCandidate
	for _, c := range attempt.candidates {
		if c.Target.Host == "a" {
			candidate = c
		}
	}
	request, _ := json.Marshal(CustodyProvisionRequest{Version: 1, Purpose: "automation-custody-recipient-request", Candidate: candidate})
	raw, err := p.PrepareCustodyRecipient(ctx, request, nil)
	if err != nil {
		t.Fatalf("native recipient unavailable: %v", err)
	}
	var recipient contract.CustodyRecipientStatement
	if json.Unmarshal(raw, &recipient) != nil || contract.ValidateCustodyRecipient(recipient) != nil {
		t.Fatal("invalid recipient statement")
	}
	trust, err := pki.DecodeHostTrustEvidence(recipient.Trust)
	if err != nil {
		t.Fatal(err)
	}
	at, err := time.Parse(time.RFC3339Nano, recipient.RecordedAt)
	if err != nil {
		t.Fatal(err)
	}
	if err = trust.VerifyRecordedCustodyAt(recipient.Chain, "a", candidate.Target.AdmissionSerial, at); err != nil {
		t.Fatal("recipient provenance", err)
	}
	voterRef, sourceRef, targetRef := custodyRefs(candidate)
	key, err := p.store.OpenVoterIdentity(voterRef, recipient.Recipient)
	if err != nil || key == nil {
		t.Fatal("recipient not physically persisted")
	}
	if _, err = p.store.GenerateEqualityKey(sourceRef); err != nil {
		t.Fatal(err)
	}
	binding := custody.EqualityImportBinding{Source: custodyScope(candidate.ClusterUID, candidate.Source), Target: custodyScope(candidate.ClusterUID, candidate.Target), SourceVoter: candidate.Source.VoterIncarnation, TargetVoter: candidate.Target.VoterIncarnation, VoterRef: voterRef, SourceEquality: sourceRef, TargetEquality: targetRef, Recipient: recipient.Recipient, Attempt: candidate.Attempt, ExpiresAt: candidate.ExpiresAt}
	capsule, err := p.store.SealEqualityImport(sourceRef, binding, recipient.Recipient)
	if err != nil {
		t.Fatal(err)
	}
	importRequest, _ := json.Marshal(CustodyProvisionRequest{Version: 1, Purpose: "automation-custody-equality-request", Candidate: candidate, Recipient: &recipient, CapsuleDigest: contract.CiphertextDigest(capsule)})
	// A real final-transaction host-lifetime change must suppress publication.
	voters[0].c.automationSeams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE hosts SET created_at='2026-10-01T00:00:00Z' WHERE name='a'`)
		return err
	}}
	if result, err := p.CompleteCustodyImport(ctx, importRequest, capsule, nil); err == nil || result != nil {
		t.Fatal("stale final host lifetime published completion")
	}
	voters[0].c.automationSeams = nil
	first, err := p.CompleteCustodyImport(ctx, importRequest, capsule, nil)
	if err != nil {
		t.Fatal("matching import/revalidation failed", err)
	}
	second, err := p.CompleteCustodyImport(ctx, importRequest, capsule, nil)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatal("lost-reply retry changed completion")
	}
	var completion contract.CustodyImportCompletion
	if json.Unmarshal(first, &completion) != nil || contract.ValidateCustodyCompletion(completion) != nil {
		t.Fatal("invalid completed import")
	}
	stored, err := p.store.ReadProvisionRecord(custodyProvisionRef(candidate), "completion")
	if err != nil || !bytes.Equal(stored, first) {
		t.Fatal("completion was not durable before publication")
	}
	head, err := voters[0].c.AutomationHead(ctx)
	if err != nil || head.Sequence != 1 {
		t.Fatal("physical import activated a semantic epoch")
	}
}
