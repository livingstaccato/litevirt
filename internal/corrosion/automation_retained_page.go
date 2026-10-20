package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"github.com/litevirt/litevirt/internal/pki"
)

type retainedPage struct {
	Object    int64
	Component int
	Position  int64
	Records   [][]byte
	Terminal  bool
}
type retainedProgress struct {
	Delivery       string
	Object         int64
	Component      int
	Records, Bytes int64
	Terminal       bool
}
type retainedPageState struct {
	Binding        string
	Records, Bytes int64
	Terminal       bool
}
type retainedTransactionGuard struct {
	holder retainedHolder
	host   sourceHost
}

func (g *retainedTransactionGuard) checkTx(ctx context.Context, tx *LocalTx) error {
	host, err := sourceReadHost(ctx, tx, g.holder.body.Donor)
	if err != nil {
		return err
	}
	if host != g.host {
		return errors.New("retained current holder admission changed")
	}
	h, found, err := retainedDeliveryTx(ctx, tx, g.holder.id)
	if err != nil {
		return err
	}
	if !found || !bytes.Equal(h.raw, g.holder.raw) {
		return errors.New("retained delivery changed before commit")
	}
	return nil
}

// Inert page delivery uses the same receiver owner, current selection, FULL
// transaction, final admission guard and real certificate lease as D. It has
// no publication-authenticated bit, adoption or completion side effect.
func (r *AutomationReceiver) stageRetained(ctx context.Context, a *AutomationReceiverAttempt, raw []byte, page retainedPage) (out retainedProgress, err error) {
	if err = r.lock(ctx); err != nil {
		return out, err
	}
	defer r.mu.Unlock()
	h, err := decodeRetainedHolder(raw)
	if err != nil {
		return out, err
	}
	auth, err := r.authorizeRetainedHolder(ctx, a, h)
	if err != nil {
		return out, err
	}
	defer auth.discard()
	lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, auth.source, auth.target)
	if err != nil {
		return out, err
	}
	defer lease.Release()
	guard := retainedTransactionGuard{h, auth.host}
	err = r.transactionGuarded(ctx, a, lease, auth.observed, nil, nil, &guard, func(tx *LocalTx) error {
		if err := aggregateVerifySchemaTx(ctx, tx); err != nil {
			return err
		}
		if err := pinRetainedDeliveryTx(ctx, tx, h); err != nil {
			return err
		}
		var e error
		out, e = retainedStagePageTx(ctx, tx, h, page)
		return e
	})
	if err != nil {
		return retainedProgress{}, err
	}
	return out, nil
}
func retainedStateTx(ctx context.Context, tx *LocalTx, a retainedFrameAddress, component int) (retainedPageState, bool, error) {
	var state retainedPageState
	rows, err := tx.Query(ctx, `SELECT typeof(state) AS st,length(CAST(state AS BLOB)) AS sn,typeof(cursor) AS ct,length(CAST(cursor AS BLOB)) AS cn,typeof(terminal) AS tt,terminal FROM local_automation_receiver_components WHERE attempt=? AND source=? AND component=? LIMIT 1`, a.namespace, a.source, component)
	if err != nil || len(rows) == 0 {
		return state, false, err
	}
	row := rows[0]
	if row.String("st") != "blob" || row.Int64("sn") <= 0 || row.Int64("sn") > receiverStateBytes || row.String("ct") != "text" || row.Int64("cn") != 0 || row.String("tt") != "integer" || (row.Int64("terminal") != 0 && row.Int64("terminal") != 1) {
		return state, false, errors.New("retained component stored shape differs")
	}
	rows, err = tx.Query(ctx, `SELECT state FROM local_automation_receiver_components WHERE attempt=? AND source=? AND component=? AND typeof(state)='blob' AND length(CAST(state AS BLOB))=? LIMIT 1`, a.namespace, a.source, component, row.Int64("sn"))
	if err != nil {
		return state, false, err
	}
	if len(rows) != 1 {
		return state, false, errors.New("retained component changed during read")
	}
	if err = retainedCanonical(rows[0].Bytes("state"), receiverStateBytes, &state); err != nil {
		return state, false, err
	}
	if !receiverDigest(state.Binding) || state.Records < 0 || state.Bytes < 0 || state.Terminal != (row.Int64("terminal") == 1) {
		return state, false, errors.New("retained progress state differs")
	}
	return state, true, nil
}
func retainedStagePageTx(ctx context.Context, tx *LocalTx, h retainedHolder, p retainedPage) (out retainedProgress, err error) {
	if p.Object < 0 || p.Object > h.body.DirectoryObjects || p.Position < 0 || p.Component < 0 || len(p.Records) > 64 {
		return out, errors.New("retained page shape exceeds bound")
	}
	directoryAddress, err := retainedAddress(h.id, 0, h.body.Donor, h.body.DirectoryRoot, retainedMetadataStream)
	if err != nil {
		return out, err
	}
	address := directoryAddress
	var d retainedObjectDescriptor
	var inv automationCutInventory
	var metadata bool
	prev := -1
	if p.Object == 0 {
		if p.Component != 0 {
			return out, errors.New("retained directory component differs")
		}
		inv = automationCutInventory{"directory/v1", 1, h.body.DirectoryObjects, h.body.DirectoryBytes, h.body.DirectoryRoot}
	} else {
		state, found, e := retainedStateTx(ctx, tx, directoryAddress, 0)
		if e != nil {
			return out, e
		}
		if !found || !state.Terminal {
			return out, errors.New("retained object before complete directory")
		}
		var foundObject bool
		d, address, foundObject, err = retainedObjectTx(ctx, tx, h.id, p.Object)
		if err != nil {
			return out, err
		}
		if !foundObject {
			return out, errors.New("retained object pin missing")
		}
		_, limits, kind := retainedDescriptorSections(d)
		index := p.Component
		prev = p.Component - 1
		if kind == retainedNativeStream {
			if p.Component == 1 || p.Component == 2 {
				return out, errors.New("retained native component differs")
			}
			if p.Component >= 3 {
				index = p.Component - 2
			}
			if p.Component == 3 {
				prev = 0
			}
		}
		if index < 0 || index >= len(d.ComponentInventories) {
			return out, errors.New("retained component outside descriptor")
		}
		inv = d.ComponentInventories[index]
		metadata = limits[index] > 0
	}
	limit := maxAutomationCutRecordBytes
	if address.kind == retainedLocalStream {
		limit = maxAggregateLocalRecordBytes
		if len(p.Records) > 1 {
			return out, errors.New("retained local page exceeds one-body bound")
		}
	}
	if metadata && len(p.Records) > 1 {
		return out, errors.New("retained metadata page exceeds one chunk")
	}
	remaining := limit
	for i, raw := range p.Records {
		bound := limit
		if metadata {
			bound = AutomationExportChunkBytes
		}
		if p.Object == 0 {
			bound = maxAutomationCutMetadataBytes
		}
		if len(raw) == 0 || len(raw) > bound || len(raw) > remaining || p.Position > math.MaxInt64-int64(i)-1 {
			return out, errors.New("retained page body exceeds bound")
		}
		remaining -= len(raw)
	}
	if !p.Terminal && len(p.Records) == 0 {
		return out, errors.New("retained nonterminal page empty")
	}
	binding := retainedComponentBinding(h.id, p.Object, address.kind, p.Component, inv)
	hash := sha256.New()
	sourceHash(hash, []byte("litevirt/retained-exact-page/v1"), []byte(binding), automationCutInteger(p.Position))
	if p.Terminal {
		sourceHash(hash, []byte{1})
	} else {
		sourceHash(hash, []byte{0})
	}
	for _, raw := range p.Records {
		sourceHash(hash, raw)
	}
	pageDigest := hex.EncodeToString(hash.Sum(nil))
	// Exact retries are immutable even when a component has subsequently advanced.
	rows, err := tx.Query(ctx, `SELECT typeof(request) AS rt,length(CAST(request AS BLOB)) AS rn,typeof(digest) AS dt,length(CAST(digest AS BLOB)) AS dn,typeof(progress) AS pt,length(CAST(progress AS BLOB)) AS pn FROM local_automation_receiver_pages WHERE attempt=? AND source=? AND component=? AND position=? LIMIT 1`, address.namespace, address.source, p.Component, p.Position)
	if err != nil {
		return out, err
	}
	if len(rows) > 0 {
		row := rows[0]
		if row.String("rt") != "text" || row.Int64("rn") != 64 || row.String("dt") != "text" || row.Int64("dn") != 64 || row.String("pt") != "blob" || row.Int64("pn") <= 0 || row.Int64("pn") > receiverStateBytes {
			return out, errors.New("retained retry stored shape differs")
		}
		rows, err = tx.Query(ctx, `SELECT request,digest,progress FROM local_automation_receiver_pages WHERE attempt=? AND source=? AND component=? AND position=? AND typeof(request)='text' AND length(CAST(request AS BLOB))=64 AND typeof(digest)='text' AND length(CAST(digest AS BLOB))=64 AND typeof(progress)='blob' AND length(CAST(progress AS BLOB))=? LIMIT 1`, address.namespace, address.source, p.Component, p.Position, row.Int64("pn"))
		if err != nil {
			return out, err
		}
		if len(rows) != 1 || rows[0].String("request") != binding || rows[0].String("digest") != pageDigest {
			return out, errors.New("retained contradictory page retry")
		}
		if err = retainedCanonical(rows[0].Bytes("progress"), receiverStateBytes, &out); err != nil {
			return out, err
		}
		if out.Delivery != h.id || out.Object != p.Object || out.Component != p.Component || out.Records != p.Position+int64(len(p.Records)) || out.Bytes < 0 || out.Bytes > inv.Bytes || out.Terminal != p.Terminal {
			return out, errors.New("retained retry progress differs")
		}
		state, found, e := retainedStateTx(ctx, tx, address, p.Component)
		if e != nil {
			return out, e
		}
		if !found || state.Binding != binding || state.Records < out.Records || state.Bytes < out.Bytes || state.Records > inv.Records || state.Bytes > inv.Bytes || out.Terminal && !state.Terminal {
			return out, errors.New("retained exact retry durable progress missing or changed")
		}
		for i, raw := range p.Records {
			stored, e := address.read(ctx, tx, p.Component, p.Position+int64(i)+1)
			if e != nil {
				return out, e
			}
			if !bytes.Equal(raw, stored) {
				return out, errors.New("retained retry original bytes differ")
			}
		}
		return out, nil
	}
	if prev >= 0 {
		state, found, e := retainedStateTx(ctx, tx, address, prev)
		if e != nil {
			return out, e
		}
		if !found || !state.Terminal {
			return out, errors.New("retained prior component missing")
		}
	}
	state, found, err := retainedStateTx(ctx, tx, address, p.Component)
	if err != nil {
		return out, err
	}
	if !found {
		state = retainedPageState{Binding: binding}
	}
	if state.Binding != binding || state.Terminal || state.Records != p.Position || state.Bytes > inv.Bytes || state.Records > inv.Records {
		return out, errors.New("retained page progress reordered or spliced")
	}
	for i, raw := range p.Records {
		if state.Records == math.MaxInt64 || state.Records >= inv.Records || int64(len(raw)) > inv.Bytes-state.Bytes {
			return out, errors.New("retained page exceeds inventory")
		}
		n := p.Position + int64(i) + 1
		if p.Object == 0 {
			var entry retainedDirectoryEntry
			if err = retainedCanonical(raw, maxAutomationCutMetadataBytes, &entry); err != nil {
				return out, err
			}
			if entry.Ordinal != n {
				return out, errors.New("retained directory entry reordered")
			}
			if err = pinRetainedObjectTx(ctx, tx, h.id, entry); err != nil {
				return out, err
			}
		}
		if err = address.save(ctx, tx, p.Component, n, raw); err != nil {
			return out, err
		}
		state.Records++
		state.Bytes += int64(len(raw))
	}
	if p.Terminal != (state.Records == inv.Records) || p.Terminal && state.Bytes != inv.Bytes {
		return out, errors.New("retained terminal inventory differs")
	}
	if p.Terminal {
		if p.Object == 0 {
			if err = retainedDirectoryTerminal(ctx, tx, h, directoryAddress); err != nil {
				return out, err
			}
		} else if err = retainedComponentTerminal(ctx, tx, address, d, p.Component, inv, metadata); err != nil {
			return out, err
		}
	}
	state.Terminal = p.Terminal
	encoded, _ := json.Marshal(state)
	if _, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_components(attempt,source,component,state,cursor,terminal) VALUES(?,?,?,?,?,?) ON CONFLICT(attempt,source,component) DO UPDATE SET state=excluded.state,cursor=excluded.cursor,terminal=excluded.terminal`, address.namespace, address.source, p.Component, encoded, "", p.Terminal); err != nil {
		return out, err
	}
	out = retainedProgress{h.id, p.Object, p.Component, state.Records, state.Bytes, p.Terminal}
	progress, _ := json.Marshal(out)
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_pages(attempt,source,component,position,request,digest,progress) VALUES(?,?,?,?,?,?,?)`, address.namespace, address.source, p.Component, p.Position, binding, pageDigest, progress)
	return out, err
}
func retainedDirectoryTerminal(ctx context.Context, tx *LocalTx, h retainedHolder, address retainedFrameAddress) error {
	var digest retainedDirectoryDigest
	directory := retainedDirectoryReader{address, h.body.DirectoryObjects}
	err := directory.walk(ctx, tx, func(n int64, d retainedObjectDescriptor) error {
		raw, _ := json.Marshal(d)
		if err := digest.add(n, raw); err != nil {
			return err
		}
		stored, _, found, err := retainedObjectTx(ctx, tx, h.id, n)
		if err != nil {
			return err
		}
		other, _ := json.Marshal(stored)
		if !found || !bytes.Equal(raw, other) {
			return errors.New("retained directory pin differs")
		}
		return nil
	})
	if err != nil {
		return err
	}
	root, _, count, _, _, _, err := digest.finish()
	if err != nil {
		return err
	}
	if root != h.body.DirectoryRoot || count != h.body.DirectoryObjects || digest.descriptorBytes != h.body.DirectoryBytes {
		return errors.New("retained signed directory inventory differs")
	}
	return nil
}
func retainedComponentTerminal(ctx context.Context, tx *LocalTx, a retainedFrameAddress, descriptor retainedObjectDescriptor, component int, inv automationCutInventory, metadata bool) error {
	h := sha256.New()
	if !metadata {
		prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
		h.Write(prefix)
	}
	table, scope, column, args, limit := "local_automation_receiver_records", "attempt=? AND source=? AND component=?", "component", []any{a.namespace, a.source, component}, int64(maxAutomationCutRecordBytes)
	if a.kind == retainedLocalStream {
		table, scope, column, args, limit = "local_automation_local_rows", "local_id=? AND section=?", "section", []any{a.localID, component}, maxAggregateLocalRecordBytes
	}
	var count, total int64
	err := walkAutomationStoredFrames(ctx, tx, table, scope, args, column, limit, func(s int, n int64, raw []byte) error {
		if s != component || count == math.MaxInt64 || n != count+1 || n > inv.Records || int64(len(raw)) > inv.Bytes-total {
			return errors.New("retained terminal record inventory differs")
		}
		if !metadata {
			if a.kind == retainedLocalStream {
				layout, e := retainedLocalTablesForDigest(descriptor.LayoutDigest)
				if e != nil || component < 0 || component >= len(layout) {
					return errors.New("retained local terminal layout differs")
				}
				row, e := decodeAutomationFramedRow(layout[component].descriptor(), n, raw, maxAggregateLocalRecordBytes)
				if e != nil {
					return e
				}
				encoded, e := encodeAggregateLocalRecord(inv.Section, n, row)
				if e != nil || !bytes.Equal(encoded, raw) {
					return errors.New("retained local frame differs")
				}
			} else {
				row, e := decodeSourceCutRow(component-3, n, raw)
				if e != nil {
					return e
				}
				encoded, e := encodeAutomationCutRecord(inv.Section, n, row)
				if e != nil || !bytes.Equal(encoded, raw) {
					return errors.New("retained source frame differs")
				}
			}
		}
		h.Write(raw)
		count = n
		total += int64(len(raw))
		return nil
	})
	if err != nil {
		return err
	}
	if count != inv.Records || total != inv.Bytes || hex.EncodeToString(h.Sum(nil)) != inv.Digest {
		return errors.New("retained terminal body commitment differs")
	}
	return nil
}
