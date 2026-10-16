package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// Finite metadata reconstruction holds at most one source's bounded public
// evidence, never one bundle per source or any history-sized map/slice. Query
// lengths and exact indexed ordinals precede body materialization.
func (r *AutomationReceiver) metadata(ctx context.Context, a *AutomationReceiverAttempt, source string, component uint32, request AutomationExportRequest, page AutomationExportPage) ([]byte, error) {
	rows, err := r.client.sourceExportQuery(ctx, `SELECT CASE WHEN length(CAST(publication AS BLOB))=64 THEN publication END AS publication FROM local_automation_receiver_sources WHERE attempt=? AND source=? LIMIT 1`, a.id, source)
	if err != nil || len(rows) != 1 || rows[0].String("publication") != request.Publication {
		return nil, errors.New("receiver metadata source pin unavailable")
	}
	rows, err = r.client.sourceExportQuery(ctx, `SELECT CASE WHEN length(CAST(state AS BLOB))<=? THEN state END AS state,terminal FROM local_automation_receiver_components WHERE attempt=? AND source=? AND component=? LIMIT 1`, receiverStateBytes, a.id, source, component)
	if err != nil {
		return nil, err
	}
	appendPage := component == 2 && request.Component == 2 && page.Terminal
	var state sourceExportCursor
	terminal := false
	if len(rows) > 0 {
		if json.Unmarshal(rows[0].Bytes("state"), &state) != nil {
			return nil, errors.New("receiver metadata state invalid")
		}
		terminal = rows[0].Int64("terminal") == 1
		if terminal {
			appendPage = false
		}
	}
	if !terminal && !appendPage {
		return nil, errors.New("receiver metadata component incomplete")
	}
	limit := receiverMetadataLimits[component]
	total := state.TotalBytes
	if appendPage {
		total = page.TerminalBytes
	}
	if total <= 0 || total > limit {
		return nil, errors.New("receiver metadata total exceeds bound")
	}
	raw := make([]byte, 0, int(total))
	var ordinal int64
	for {
		rows, err = r.client.sourceExportQuery(ctx, `SELECT ordinal,length(CAST(record AS BLOB)) AS size FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal>? ORDER BY ordinal LIMIT 1`, a.id, source, component, ordinal)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			break
		}
		n := rows[0].Int64("size")
		if rows[0].Int64("ordinal") != ordinal+1 || n < 1 || n > AutomationExportChunkBytes || n > total-int64(len(raw)) {
			return nil, errors.New("receiver metadata retained chunk exceeds bound")
		}
		ordinal++
		rows, err = r.client.sourceExportQuery(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? AND length(CAST(record AS BLOB))=? LIMIT 1`, a.id, source, component, ordinal, n)
		if err != nil || len(rows) != 1 {
			return nil, errors.New("receiver metadata retained chunk missing")
		}
		raw = append(raw, rows[0].Bytes("record")...)
	}
	if appendPage {
		if int64(len(page.Chunk)) > total-int64(len(raw)) {
			return nil, errors.New("receiver metadata suffix exceeds bound")
		}
		raw = append(raw, page.Chunk...)
	}
	if int64(len(raw)) != total {
		return nil, errors.New("receiver metadata incomplete length")
	}
	return raw, nil
}
func (r *AutomationReceiver) authenticatePublication(ctx context.Context, a *AutomationReceiverAttempt, source string, request AutomationExportRequest, page AutomationExportPage, peer sourceTarget) (receiverPublication, error) {
	var result receiverPublication
	var raw [3][]byte
	for component := uint32(0); component < 3; component++ {
		b, err := r.metadata(ctx, a, source, component, request, page)
		if err != nil {
			return result, err
		}
		raw[component] = b
		result.metadataBytes[component] = int64(len(b))
		result.metadataDigests[component] = sha256.Sum256(b)
	}
	p, err := decodeSourcePublication(request.Publication, raw[0], raw[1], raw[2])
	if err != nil {
		return result, err
	}
	m := p.manifest
	root := a.view.RootDigest()
	target := sha256.Sum256(a.pair.Certificate[0])
	member, _ := a.facts.Old.Member(source)
	if !sameSourceRequest(m.Request, a.request) || m.Source != source || m.Incarnation != member.Incarnation || m.Incarnation != peer.Incarnation || m.OldValue != sourceConfigDigest(a.facts.Old) || m.NextValue != sourceConfigDigest(a.facts.Next) || m.OldMembers != a.facts.Old.MembersHash || m.NextMembers != a.facts.Next.MembersHash || m.Cut.MembersHash != a.facts.Old.MembersHash || m.TrustDomain != hex.EncodeToString(root[:]) || m.Target.Host != r.client.hostName || m.Target.Incarnation != a.facts.Incarnation || m.Target.Certificate != hex.EncodeToString(target[:]) || m.Signer != peer.Fingerprint {
		return result, errors.New("receiver authenticated publication context differs")
	}
	var signed sourceSignedArtifact
	if json.Unmarshal(raw[0], &signed) != nil || sourceChainBounds(signed.Chain) != nil || !bytes.Equal(signed.Chain[0], peer.Chain[0]) {
		return result, errors.New("receiver publication signer is not observed current source")
	}
	// Local membership was verified independently in Begin. These exact values
	// must also carry the real ordinary successor certificate under local trust.
	var membership sourceMembershipEvidence
	if json.Unmarshal(raw[2], &membership) != nil {
		return result, errors.New("receiver publication membership invalid")
	}
	next := *a.facts.Next
	next.Certificate = membership.Certificate
	if _, _, err = verifySourceTransition(a.view, a.facts.Old, &next); err != nil {
		return result, err
	}
	result.id = p.id
	result.manifest = m
	result.chain = signed.Chain
	return result, nil
}
func receiverCheckPublicationRows(ctx context.Context, tx *LocalTx, attempt, source string, p receiverPublication) error {
	for component := uint32(0); component < 3; component++ {
		c := sourceExportCursor{TotalRecords: (p.metadataBytes[component] + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes, TotalBytes: p.metadataBytes[component], Digest: p.metadataDigests[component]}
		if err := receiverVerifyRows(ctx, tx, attempt, source, component, c); err != nil {
			return err
		}
	}
	return nil
}
