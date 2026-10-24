package corrosion

import (
	"bytes"
	"context"
	"sync"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"github.com/litevirt/litevirt/internal/pki"
)

// AutomationCustodyReady owns either bounded current member observations or an
// authenticated certified original. The historical variant grants no native vote;
// persisted transcripts alone cannot authorize fresh provisioning.
type AutomationCustodyReady struct {
	mu                sync.Mutex
	self              *AutomationCustodyReady
	owner             *AutomationCustodyProducer
	attempt           *AutomationInitialEpoch
	ctx               context.Context
	expires           time.Time
	record            contract.CustodyImportRecord
	activationCommand *contract.Command
	historical        *custodyCertifiedOriginal
}

func (r *AutomationCustodyReady) Release() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.self = nil
	r.owner = nil
	r.attempt = nil
	r.ctx = nil
	r.record = contract.CustodyImportRecord{}
}

type custodyMemberPlan struct {
	Request []byte
	Capsule []byte
}

// custodyExchange uses the actual expected-host connection for each response.
// No lease or transaction is held while performing peer RPCs.
func (p *AutomationCustodyProducer) custodyExchange(ctx context.Context, s custodySnapshot, candidate contract.CustodyCandidate, request, capsule []byte) ([]byte, error) {
	if candidate.Target.Host == p.client.hostName {
		if capsule == nil {
			return p.PrepareCustodyRecipient(ctx, request, nil)
		}
		return p.CompleteCustodyImport(ctx, request, capsule, nil)
	}
	host := s.hosts[candidate.Target.Host].endpoint
	peer, err := pki.DialExpectedHostPeer(ctx, p.pkiDir, host.Name, PeerTarget(host.Address, host.Port))
	if err != nil {
		return nil, err
	}
	defer peer.Close()
	var raw []byte
	if capsule == nil {
		response, e := pb.NewLiteVirtClient(peer).PrepareAutomationCustodyRecipient(ctx, &pb.PrepareAutomationCustodyRecipientRequest{RequestJson: request})
		if e != nil {
			return nil, e
		}
		raw = response.GetRecipientJson()
	} else {
		response, e := pb.NewLiteVirtClient(peer).ImportAutomationCustodyEquality(ctx, &pb.ImportAutomationCustodyEqualityRequest{RequestJson: request, Capsule: capsule})
		if e != nil {
			return nil, e
		}
		raw = response.GetCompletionJson()
	}
	_, _, chain, err := peer.Observation()
	if err != nil || len(chain) == 0 {
		return nil, errAutomationAuthority
	}
	// Observation plus ordinary current trust/admission are required even when
	// the response carries a valid old recorded-trust signature.
	view, err := pki.CaptureHostTrust(ctx, p.pkiDir, p.client.hostName)
	if err != nil {
		return nil, err
	}
	cap, err := view.ValidateHostCertificate(ctx, chain, host.Name)
	if err != nil {
		return nil, err
	}
	defer cap.Discard()
	if err = sourceAdmission(view, host, chain[0]); err != nil {
		return nil, err
	}
	if capsule == nil {
		var response contract.CustodyRecipientStatement
		if custodyProtocolDecode(raw, &response) != nil || response.Candidate != candidate || verifyCustodyRecipient(response) != nil || !bytes.Equal(response.Chain[0], chain[0]) {
			return nil, errAutomationAuthority
		}
	} else {
		var response contract.CustodyImportCompletion
		if custodyProtocolDecode(raw, &response) != nil || response.Candidate != candidate || contract.ValidateCustodyCompletion(response) != nil || !bytes.Equal(response.Chain[0], chain[0]) {
			return nil, errAutomationAuthority
		}
	}
	return raw, nil
}

func (p *AutomationCustodyProducer) ProvisionInitialEpoch(ctx context.Context, attempt *AutomationInitialEpoch) (ready *AutomationCustodyReady, err error) {
	defer func() {
		if err != nil {
			ready = nil
			err = errAutomationAuthority
		}
	}()
	if p == nil || attempt == nil {
		return nil, errAutomationAuthority
	}
	attempt.mu.Lock()
	defer attempt.mu.Unlock()
	if attempt.self != attempt || attempt.owner != p || attempt.ctx == nil || attempt.ctx.Err() != nil || ctx.Err() != nil || !time.Now().Before(attempt.expires) || len(attempt.candidates) == 0 {
		return nil, errAutomationAuthority
	}
	if attempt.historical != nil {
		if _, _, found, e := attempt.historical.CertifiedActivation(ctx); e != nil || !found {
			return nil, errAutomationAuthority
		}
		return attempt.historical, nil
	}
	ctx, cancel := context.WithDeadline(ctx, attempt.expires)
	defer cancel()
	stop := context.AfterFunc(attempt.ctx, cancel)
	defer stop()
	candidate := attempt.candidates[0]
	store, err := p.openStore(custodyScope(candidate.ClusterUID, candidate.Source), false)
	if err != nil {
		return nil, err
	}
	_, sourceRef, _ := custodyRefs(candidate)
	// Mark uncertainty before creation. A failed create is never followed by
	// absence-driven regeneration on a retry of this immutable attempt.
	if !attempt.sourceStarted {
		attempt.sourceStarted = true
		if _, err = store.GenerateEqualityKey(sourceRef); err != nil {
			return nil, err
		}
	}
	if _, err = store.OpenEqualityKey(sourceRef); err != nil {
		return nil, err
	}
	record := contract.CustodyImportRecord{Version: 1, ClusterUID: candidate.ClusterUID, Attempt: candidate.Attempt, MembershipGeneration: candidate.MembershipGeneration, ConfigDigest: candidate.ConfigDigest, RecipientEpoch: candidate.RecipientEpoch, EqualityEpoch: candidate.EqualityEpoch, Genesis: candidate.Genesis, ExpiresAt: candidate.ExpiresAt}
	for _, candidate = range attempt.candidates {
		request, err := custodyProtocolEncode(CustodyProvisionRequest{Version: 1, Purpose: "automation-custody-recipient-request", Candidate: candidate})
		if err != nil {
			return nil, err
		}
		raw, err := p.custodyExchange(ctx, attempt.snapshot, candidate, request, nil)
		if err != nil {
			return nil, err
		}
		var recipient contract.CustodyRecipientStatement
		if custodyProtocolDecode(raw, &recipient) != nil || recipient.Candidate != candidate || verifyCustodyRecipient(recipient) != nil {
			return nil, errAutomationAuthority
		}
		ref := custodyProvisionRef(candidate)
		if err = store.SaveProvisionRecord(ref, "recipient", raw); err != nil {
			return nil, err
		}
		exists, err := store.HasProvisionRecord(ref, "plan")
		if err != nil {
			return nil, err
		}
		var plan custodyMemberPlan
		if exists {
			raw, err = store.ReadProvisionRecord(ref, "plan")
			if err != nil || custodyProtocolDecode(raw, &plan) != nil {
				return nil, errAutomationAuthority
			}
			parsed, e := decodeCustodyRequest(plan.Request, "automation-custody-equality-request")
			expected, _ := custodyProtocolEncode(recipient)
			var saved []byte
			if parsed.Recipient != nil {
				saved, _ = custodyProtocolEncode(parsed.Recipient)
			}
			if e != nil || parsed.Candidate != candidate || !bytes.Equal(saved, expected) || parsed.CapsuleDigest != contract.CiphertextDigest(plan.Capsule) {
				return nil, errAutomationAuthority
			}
		} else {
			plan.Capsule, err = store.SealEqualityImport(sourceRef, custodyImportBinding(candidate, recipient.Recipient), recipient.Recipient)
			if err != nil {
				return nil, err
			}
			plan.Request, err = custodyProtocolEncode(CustodyProvisionRequest{Version: 1, Purpose: "automation-custody-equality-request", Candidate: candidate, Recipient: &recipient, CapsuleDigest: contract.CiphertextDigest(plan.Capsule)})
			if err != nil {
				return nil, err
			}
			raw, err = custodyProtocolEncode(plan)
			if err != nil {
				return nil, err
			}
			if err = store.SaveProvisionRecord(ref, "plan", raw); err != nil {
				return nil, err
			}
		}
		raw, err = p.custodyExchange(ctx, attempt.snapshot, candidate, plan.Request, plan.Capsule)
		if err != nil {
			return nil, err
		}
		var completion contract.CustodyImportCompletion
		if custodyProtocolDecode(raw, &completion) != nil || completion.CapsuleDigest != contract.CiphertextDigest(plan.Capsule) || verifyCustodyCompletion(completion, recipient) != nil {
			return nil, errAutomationAuthority
		}
		if err = store.SaveProvisionRecord(ref, "completion", raw); err != nil {
			return nil, err
		}
		record.Members = append(record.Members, contract.CustodyMemberImport{Recipient: recipient, Completion: completion})
	}
	// All-member completion is followed by a new local current/FULL barrier.
	// This creates no semantic epoch and grants no Accept by itself.
	var local contract.CustodyCandidate
	for _, c := range attempt.candidates {
		if c.Target.Host == p.client.hostName {
			local = c
		}
	}
	live, err := p.beginCustody(ctx, local, nil)
	if err != nil {
		return nil, err
	}
	defer live.lease.Release()
	if err = live.barrier(ctx, func() error { _, err := store.OpenEqualityKey(sourceRef); return err }); err != nil {
		return nil, err
	}
	ready = &AutomationCustodyReady{owner: p, attempt: attempt, ctx: attempt.ctx, expires: attempt.expires, record: record}
	ready.self = ready
	return ready, nil
}
