package corrosion

import (
	"context"
	"errors"
)

// This is immutable audit context, never a live receiver attempt or capability.
// Current holder authorization and the original directory/binding select it.
type receiverAuditContext struct {
	id      string
	request AutomationSourceRequest
	facts   receiverFacts
}

type retainedSourceAudit struct {
	head                        AutomationPrefix
	lineage, coverage           string
	records, payloads, requests int64
}

func (s receiverAuditStore) auditRetainedSource(ctx context.Context, original receiverAuditContext) (retainedSourceAudit, error) {
	var out retainedSourceAudit
	m := s.publication.manifest
	if !receiverDigest(original.id) || original.facts.Old == nil || original.facts.Next == nil ||
		!sameSourceRequest(m.Request, original.request) || m.OldValue != sourceConfigDigest(original.facts.Old) ||
		m.NextValue != sourceConfigDigest(original.facts.Next) || m.Target.Host != original.request.Target ||
		m.Target.Incarnation != original.facts.Incarnation || s.evidenceIdentity() != sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(original.id), []byte(s.source), []byte(s.publication.id), []byte(m.Root)) {
		return out, errors.New("retained original source context differs")
	}
	if err := receiverVerifyInventory(ctx, s.tx, s.attempt, s.source, s.publication); err != nil {
		return out, err
	}
	var err error
	if out.records, err = s.index(ctx); err != nil {
		return out, err
	}
	if out.lineage, err = s.lineageContext(ctx, original); err != nil {
		return out, err
	}
	if out.head, out.requests, err = s.history(ctx); err != nil {
		return out, err
	}
	out.coverage, out.payloads, err = s.claimsAndCoverage(ctx, out.head)
	return out, err
}
