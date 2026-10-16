package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

const receiverStateBytes = 2048

var receiverMetadataLimits = [3]int64{maxSourceArtifactBytes, pki.MaxHostTrustEvidenceBytes, maxSourceMembershipEvidenceBytes}

func receiverDigest(raw string) bool {
	if len(raw) != 64 {
		return false
	}
	b, e := hex.DecodeString(raw)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == raw
}
func receiverPageBounds(r AutomationExportRequest, p AutomationExportPage) error {
	if r.Publication == "" || p.Publication != r.Publication || p.Component != r.Component || len(p.Cursor) > AutomationExportMaxCursor || p.TerminalRecords < 0 || p.TerminalBytes < 0 || !receiverDigest(p.TerminalDigest) {
		return errors.New("receiver page binding or inventory invalid")
	}
	if p.Terminal != (p.Cursor == "") {
		return errors.New("receiver page terminal/cursor shape differs")
	}
	if r.Component < 3 {
		bound := receiverMetadataLimits[r.Component]
		if len(p.Metadata) != 0 || len(p.Records) != 0 || len(p.Chunk) == 0 || len(p.Chunk) > AutomationExportChunkBytes || uint64(len(p.Chunk)) > uint64(r.MaxBytes) || p.TerminalBytes < 1 || p.TerminalBytes > bound || p.TerminalRecords != (p.TerminalBytes+AutomationExportChunkBytes-1)/AutomationExportChunkBytes {
			return errors.New("receiver pending metadata exceeds shape/bound")
		}
	} else {
		if len(p.Chunk) != 0 || len(p.Metadata) == 0 || len(p.Metadata) > maxAutomationCutMetadataBytes || len(p.Records) > int(r.MaxRecords) {
			return errors.New("receiver content wrapper exceeds bound")
		}
		remaining := int(r.MaxBytes)
		for _, raw := range p.Records {
			if len(raw) == 0 || len(raw) > remaining {
				return errors.New("receiver record bytes exceed page budget")
			}
			remaining -= len(raw)
		}
		if !p.Terminal && len(p.Records) == 0 {
			return errors.New("receiver nonterminal EOF")
		}
	}
	return nil
}
func receiverPageDigest(r AutomationExportRequest, p AutomationExportPage) string {
	request, _ := json.Marshal(r)
	h := sha256.New()
	sourceHash(h, []byte("litevirt/receiver-exact-page/v1"), request, []byte(p.Publication), automationCutInteger(int64(p.Component)), p.Metadata, p.Chunk, []byte(p.Cursor), automationCutInteger(p.TerminalRecords), automationCutInteger(p.TerminalBytes), []byte(p.TerminalDigest))
	if p.Terminal {
		sourceHash(h, []byte{1})
	} else {
		sourceHash(h, []byte{0})
	}
	for _, raw := range p.Records {
		sourceHash(h, raw)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Stage accepts one real exporter response. Before even pending metadata is
// persisted, the current receiver, configured PKI owner, admitted expected-host
// TLS peer and its actual current SQLite incarnation all authorize this attempt.
func (r *AutomationReceiver) Stage(ctx context.Context, a *AutomationReceiverAttempt, source string, request AutomationExportRequest, page AutomationExportPage) (AutomationReceiverProgress, error) {
	var out AutomationReceiverProgress
	if err := r.lock(ctx); err != nil {
		return out, err
	}
	defer r.mu.Unlock()
	if a == nil || a.self != a || a.owner != r {
		return out, errors.New("foreign receiver attempt")
	}
	request, err := sourceExportRequest(request)
	if err != nil {
		return out, err
	}
	if !sameSourceRequest(request.Intent, a.request) {
		return out, errors.New("receiver request context differs")
	}
	var member VoterMember
	for _, m := range a.request.Sources {
		if m.Name == source {
			member = m
			break
		}
	}
	if member.Name == "" {
		return out, errors.New("receiver source is not in fixed old roster")
	}
	if err = receiverPageBounds(request, page); err != nil {
		return out, err
	}
	// Read-only authorization before metadata/body loading or network acquisition.
	if err = r.client.sourceExportReadLock(ctx); err != nil {
		return out, err
	}
	tx, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		r.client.mu.RUnlock()
		return out, err
	}
	local := &LocalTx{tx: tx}
	err = r.currentTx(ctx, local, a)
	var host sourceHost
	if err == nil {
		host, err = sourceReadHost(ctx, local, source)
	}
	if err == nil {
		var facts receiverFacts
		facts, _, _, err = r.factsTx(ctx, local, a.request, nil)
		if err == nil && !sameReceiverFacts(facts, a.facts) {
			err = errors.New("receiver current dependencies changed")
		}
	}
	tx.Rollback()
	r.client.mu.RUnlock()
	if err != nil {
		return out, err
	}
	observed := time.Now()
	var peer sourceTarget
	if source == r.client.hostName {
		fp := sha256.Sum256(a.pair.Certificate[0])
		peer = sourceTarget{Host: host, Incarnation: a.facts.Incarnation, Chain: a.pair.Certificate, Fingerprint: hex.EncodeToString(fp[:]), Local: true}
	} else {
		_, peer, err = sourceQueryPeer(ctx, r.dir, host, a.request.Generation, false)
		if err != nil {
			return out, err
		}
	}
	if peer.Incarnation != member.Incarnation {
		return out, errors.New("receiver source current incarnation differs")
	}
	if err = sourceAdmission(a.view, host, peer.Chain[0]); err != nil {
		return out, err
	}
	sourceCap, err := a.view.ValidateHostCertificate(ctx, peer.Chain, source)
	if err != nil {
		return out, err
	}
	defer sourceCap.Discard()
	targetCap, err := a.view.ValidateServedHost(ctx, a.pair)
	if err != nil {
		return out, err
	}
	defer targetCap.Discard()
	leaf, err := x509.ParseCertificate(peer.Chain[0])
	if err != nil {
		return out, err
	}
	key, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return out, errors.New("unsupported receiver source signer")
	}

	// Initial metadata may span many bounded chunks. Only one finite evidence
	// bundle is reconstructed, once on promotion (or once after process restart).
	publication, hasPublication := a.publications[source]
	if hasPublication && publication.id != request.Publication {
		return out, errors.New("receiver source publication pin differs")
	}
	if !hasPublication && (request.Component >= 3 || (request.Component == 2 && page.Terminal)) {
		publication, err = r.authenticatePublication(ctx, a, source, request, page, peer)
		if err != nil {
			return out, err
		}
		hasPublication = true
	}
	if hasPublication {
		if publication.manifest.Signer != peer.Fingerprint || !bytes.Equal(publication.chain[0], peer.Chain[0]) {
			return out, errors.New("receiver publication is not current source attestation")
		}
		if request.Component >= 3 {
			metadata, _ := json.Marshal(publication.manifest.Cut)
			inv := publication.manifest.Cut.Inventory[request.Component-3]
			if !bytes.Equal(metadata, page.Metadata) || inv.Records != page.TerminalRecords || inv.Bytes != page.TerminalBytes || inv.Digest != page.TerminalDigest {
				return out, errors.New("receiver authenticated inventory differs")
			}
		}
	}
	var start sourceExportCursor
	start.Binding = sourceExportBinding(request)
	start.TotalRecords = page.TerminalRecords
	start.TotalBytes = page.TerminalBytes
	digest, _ := hex.DecodeString(page.TerminalDigest)
	copy(start.Digest[:], digest)
	h := sha256.New()
	if request.Component >= 3 {
		prefix, _ := automationCutFrame("section/v1", []byte(automationCutSections[request.Component-3].name))
		h.Write(prefix)
	}
	if err = start.setHash(h); err != nil {
		return out, err
	}
	if request.Cursor != "" {
		start, err = decodeSourceExportCursor(request.Cursor, key)
		if err != nil {
			return out, err
		}
		if start.Binding != sourceExportBinding(request) || start.TotalRecords != page.TerminalRecords || start.TotalBytes != page.TerminalBytes || !bytes.Equal(start.Digest[:], digest) {
			return out, errors.New("receiver incoming cursor binding differs")
		}
	}
	next := start
	h, err = next.hash()
	if err != nil {
		return out, err
	}
	records := page.Records
	if request.Component < 3 {
		records = [][]byte{page.Chunk}
	}
	for _, raw := range records {
		if next.Position == math.MaxInt64 || next.Position >= next.TotalRecords || int64(len(raw)) > next.TotalBytes-next.Bytes {
			return out, errors.New("receiver progress exceeds signed inventory")
		}
		if request.Component < 3 {
			n := next.TotalBytes - next.Bytes
			if n > AutomationExportChunkBytes {
				n = AutomationExportChunkBytes
			}
			if int64(len(raw)) != n {
				return out, errors.New("receiver metadata chunk position differs")
			}
		} else {
			if _, err = decodeSourceCutRow(int(request.Component)-3, next.Position+1, raw); err != nil {
				return out, err
			}
		}
		next.Position++
		next.Bytes += int64(len(raw))
		h.Write(raw)
	}
	if page.Terminal {
		if next.Position != next.TotalRecords || next.Bytes != next.TotalBytes || !bytes.Equal(h.Sum(nil), next.Digest[:]) {
			return out, errors.New("receiver terminal count/bytes/digest differs")
		}
	} else if next.Position >= next.TotalRecords || next.Bytes >= next.TotalBytes {
		return out, errors.New("receiver nonterminal EOF or exhausted inventory")
	}
	if err = next.setHash(h); err != nil {
		return out, err
	}
	if !page.Terminal {
		signed, err := decodeSourceExportCursor(page.Cursor, key)
		if err != nil {
			return out, err
		}
		if signed != next {
			return out, errors.New("receiver outgoing cursor progress differs")
		}
	}
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, sourceCap, targetCap)
	if err != nil {
		return out, err
	}
	defer lease.Release()
	pageDigest := receiverPageDigest(request, page)
	err = r.transaction(ctx, a, lease, observed, func(tx *LocalTx) error {
		if err := r.currentTx(ctx, tx, a); err != nil {
			return err
		}
		current, err := sourceReadHost(ctx, tx, source)
		if err != nil || current != host {
			return errors.New("receiver source admission changed")
		}
		rows, err := tx.Query(ctx, `SELECT CASE WHEN length(CAST(publication AS BLOB))=64 THEN publication END AS publication,authenticated FROM local_automation_receiver_sources WHERE attempt=? AND source=? LIMIT 1`, a.id, source)
		if err != nil {
			return err
		}
		authenticated := false
		if len(rows) == 0 {
			if request.Component != 0 || request.Cursor != "" {
				return errors.New("receiver source must start with pending artifact")
			}
			if _, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_sources(attempt,source,publication,authenticated,metadata) VALUES(?,?,?,0,?)`, a.id, source, request.Publication, []byte{}); err != nil {
				return err
			}
		} else {
			if rows[0].String("publication") != request.Publication {
				return errors.New("receiver source immutable publication differs")
			}
			authenticated = rows[0].Int64("authenticated") == 1
		}
		rows, err = tx.Query(ctx, `SELECT CASE WHEN length(CAST(request AS BLOB))<=? THEN request END AS request,CASE WHEN length(CAST(digest AS BLOB))=64 THEN digest END AS digest,CASE WHEN length(CAST(progress AS BLOB))<=? THEN progress END AS progress FROM local_automation_receiver_pages WHERE attempt=? AND source=? AND component=? AND position=? LIMIT 1`, AutomationExportMaxCursor, receiverStateBytes, a.id, source, request.Component, start.Position)
		if err != nil {
			return err
		}
		if len(rows) > 0 {
			row := rows[0]
			if row.get("request") == nil || row.String("request") != request.Cursor || row.String("digest") != pageDigest || json.Unmarshal(row.Bytes("progress"), &out) != nil {
				return errors.New("receiver contradictory page retry")
			}
			return nil
		}
		if request.Component >= 3 && (!authenticated || !hasPublication) {
			return errors.New("receiver content before full publication authentication")
		}
		// Metadata components and content sections are ordered. An authenticated
		// empty inventory still owns its terminal component row; EOF does not.
		if request.Component > 0 {
			prev, err := tx.Query(ctx, `SELECT terminal FROM local_automation_receiver_components WHERE attempt=? AND source=? AND component=? LIMIT 1`, a.id, source, request.Component-1)
			if err != nil || len(prev) != 1 || prev[0].Int64("terminal") != 1 {
				return errors.New("receiver prior component missing")
			}
		}
		rows, err = tx.Query(ctx, `SELECT CASE WHEN length(CAST(state AS BLOB))<=? THEN state END AS state,CASE WHEN length(CAST(cursor AS BLOB))<=? THEN cursor END AS cursor,terminal FROM local_automation_receiver_components WHERE attempt=? AND source=? AND component=? LIMIT 1`, receiverStateBytes, AutomationExportMaxCursor, a.id, source, request.Component)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			if request.Cursor != "" || start.Position != 0 {
				return errors.New("receiver missing prior page")
			}
		} else {
			var old sourceExportCursor
			if rows[0].get("cursor") == nil || json.Unmarshal(rows[0].Bytes("state"), &old) != nil || old != start || rows[0].String("cursor") != request.Cursor || rows[0].Int64("terminal") != 0 {
				return errors.New("receiver page is reordered or spliced")
			}
		}
		for i, raw := range records {
			if _, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) VALUES(?,?,?,?,?)`, a.id, source, request.Component, start.Position+int64(i)+1, raw); err != nil {
				return err
			}
		}
		if page.Terminal {
			if err = receiverVerifyRows(ctx, tx, a.id, source, request.Component, next); err != nil {
				return err
			}
		}
		if request.Component == 2 && page.Terminal {
			if !hasPublication {
				return errors.New("receiver publication authentication missing")
			}
			// Recheck all exact metadata inventories inside this FULL commit. The
			// outside-SQL crypto result cannot authenticate different persisted bytes.
			if err = receiverCheckPublicationRows(ctx, tx, a.id, source, publication); err != nil {
				return err
			}
			metadata, _ := json.Marshal(publication.manifest.Cut)
			if _, err = tx.Exec(ctx, `UPDATE local_automation_receiver_sources SET authenticated=1,metadata=? WHERE attempt=? AND source=? AND publication=?`, metadata, a.id, source, publication.id); err != nil {
				return err
			}
			authenticated = true
		}
		if request.Component == 11 && page.Terminal {
			if err = receiverVerifyInventory(ctx, tx, a.id, source, publication); err != nil {
				return err
			}
		}
		state, _ := json.Marshal(next)
		if _, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_components(attempt,source,component,state,cursor,terminal) VALUES(?,?,?,?,?,?) ON CONFLICT(attempt,source,component) DO UPDATE SET state=excluded.state,cursor=excluded.cursor,terminal=excluded.terminal`, a.id, source, request.Component, state, page.Cursor, page.Terminal); err != nil {
			return err
		}
		out = AutomationReceiverProgress{Component: request.Component, Records: next.Position, Bytes: next.Bytes, Cursor: page.Cursor, Terminal: page.Terminal, Authenticated: authenticated}
		progress, _ := json.Marshal(out)
		_, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_pages(attempt,source,component,position,request,digest,progress) VALUES(?,?,?,?,?,?,?)`, a.id, source, request.Component, start.Position, request.Cursor, pageDigest, progress)
		return err
	})
	if err != nil {
		return AutomationReceiverProgress{}, err
	}
	if hasPublication {
		a.publications[source] = publication
	}
	return out, nil
}

// Verify the actual immutable rows at each terminal, once per component. This
// is a bounded keyset walk, not a whole-source replay for every incoming page.
func receiverVerifyRows(ctx context.Context, tx *LocalTx, attempt, source string, component uint32, want sourceExportCursor) error {
	h := sha256.New()
	if component >= 3 {
		prefix, _ := automationCutFrame("section/v1", []byte(automationCutSections[component-3].name))
		h.Write(prefix)
	}
	var ordinal, total int64
	bad, err := tx.Query(ctx, `SELECT ordinal FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal<=0 LIMIT 1`, attempt, source, component)
	if err != nil || len(bad) != 0 {
		return errors.New("receiver invalid retained ordinal")
	}
	for {
		rows, err := tx.Query(ctx, `SELECT ordinal,length(CAST(record AS BLOB)) AS size FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal>? ORDER BY ordinal LIMIT 1`, attempt, source, component, ordinal)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		n := rows[0].Int64("size")
		bound := int64(maxAutomationCutRecordBytes)
		if component < 3 {
			bound = AutomationExportChunkBytes
		}
		if ordinal == math.MaxInt64 || rows[0].Int64("ordinal") != ordinal+1 || ordinal >= want.TotalRecords || n <= 0 || n > bound || n > want.TotalBytes-total {
			return errors.New("receiver retained inventory length/order differs")
		}
		ordinal++
		rows, err = tx.Query(ctx, `SELECT record FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component=? AND ordinal=? AND length(CAST(record AS BLOB))=? LIMIT 1`, attempt, source, component, ordinal, n)
		if err != nil || len(rows) != 1 {
			return errors.New("receiver retained record missing")
		}
		raw := rows[0].Bytes("record")
		if component >= 3 {
			if _, err = decodeSourceCutRow(int(component)-3, ordinal, raw); err != nil {
				return err
			}
		}
		total += n
		h.Write(raw)
	}
	if ordinal != want.TotalRecords || total != want.TotalBytes || !bytes.Equal(h.Sum(nil), want.Digest[:]) {
		return errors.New("receiver actual stored inventory differs")
	}
	return nil
}

// Last transport terminal audits every pinned inventory from actual rows. This
// is not the semantic aggregate audit or any completion/adoption capability.
func receiverVerifyInventory(ctx context.Context, tx *LocalTx, attempt, source string, p receiverPublication) error {
	for _, q := range []string{
		`SELECT component FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component<0 LIMIT 1`,
		`SELECT component FROM local_automation_receiver_records WHERE attempt=? AND source=? AND component>=12 LIMIT 1`,
	} {
		rows, err := tx.Query(ctx, q, attempt, source)
		if err != nil || len(rows) != 0 {
			return errors.New("receiver unsupported retained component")
		}
	}
	if err := receiverCheckPublicationRows(ctx, tx, attempt, source, p); err != nil {
		return err
	}
	for section, inv := range p.manifest.Cut.Inventory {
		digest, err := hex.DecodeString(inv.Digest)
		if err != nil {
			return err
		}
		want := sourceExportCursor{TotalRecords: inv.Records, TotalBytes: inv.Bytes}
		copy(want.Digest[:], digest)
		if err = receiverVerifyRows(ctx, tx, attempt, source, uint32(section+3), want); err != nil {
			return err
		}
	}
	return nil
}
