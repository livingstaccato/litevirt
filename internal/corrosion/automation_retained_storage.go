package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"math"
	"strconv"
	"strings"
)

type retainedStreamKind uint8

const (
	retainedSourceStream retainedStreamKind = iota + 1
	retainedLocalStream
	retainedNativeStream
	retainedMetadataStream
)

// Closed storage addresses are distinct from current receiver attempt IDs.
// Only local snapshot bodies route to local_rows at their existing larger bound.
type retainedFrameAddress struct {
	namespace, source, localID string
	kind                       retainedStreamKind
}

func (a retainedFrameAddress) walk(ctx context.Context, tx *LocalTx, descriptor retainedObjectDescriptor, visit func(int, int64, []byte) error) error {
	raw, _ := json.Marshal(descriptor)
	d, err := decodeRetainedObject(raw)
	if err != nil {
		return err
	}
	_, limits, kind := retainedObjectSections(d.Kind)
	if kind != a.kind || d.Source != a.source || (kind == retainedLocalStream && a.localID != sourceDigest([]byte("litevirt/retained-local-storage/v1"), []byte(a.namespace), []byte(d.OriginalIdentity))) {
		return errors.New("retained frame descriptor address differs")
	}
	if _, _, _, _, err = a.location(0, 1); err != nil {
		return err
	}
	hashes := make([]hash.Hash, len(d.ComponentInventories))
	counts := make([]int64, len(hashes))
	sizes := make([]int64, len(hashes))
	for i, inv := range d.ComponentInventories {
		h := sha256.New()
		if limits[i] == 0 {
			prefix, _ := automationCutFrame("section/v1", []byte(inv.Section))
			h.Write(prefix)
		}
		hashes[i] = h
	}
	table, scope, column, args, limit := "local_automation_receiver_records", "attempt=? AND source=?", "component", []any{a.namespace, a.source}, int64(maxAutomationCutRecordBytes)
	if kind == retainedLocalStream {
		table, scope, column, args, limit = "local_automation_local_rows", "local_id=?", "section", []any{a.localID}, int64(maxAggregateLocalRecordBytes)
	}
	frameBound := func(component int, n int64) int64 {
		i := component
		if kind == retainedNativeStream && component >= 3 {
			i = component - 2
		}
		if i < 0 || i >= len(hashes) || (kind == retainedNativeStream && (component == 1 || component == 2)) || counts[i] == math.MaxInt64 || n != counts[i]+1 || n > d.ComponentInventories[i].Records {
			return 0
		}
		_, _, _, bound, err := a.location(component, n)
		if err != nil {
			return 0
		}
		return min(int64(bound), d.ComponentInventories[i].Bytes-sizes[i])
	}
	err = walkAutomationStoredFramesBounded(ctx, tx, table, scope, args, column, limit, frameBound, func(component int, n int64, raw []byte) error {
		i := component
		if kind == retainedNativeStream && component >= 3 {
			i = component - 2
		}
		if i < 0 || i >= len(hashes) || (kind == retainedNativeStream && (component == 1 || component == 2)) || counts[i] == math.MaxInt64 || n != counts[i]+1 || n > d.ComponentInventories[i].Records || int64(len(raw)) > d.ComponentInventories[i].Bytes-sizes[i] {
			return errors.New("retained frame ordinal/component/bytes differ")
		}
		_, _, _, bound, err := a.location(component, n)
		if err != nil || len(raw) > bound {
			return errors.New("retained component body exceeds bound")
		}
		if limits[i] == 0 {
			var row Row
			var canonical []byte
			if kind == retainedLocalStream {
				layout := aggregateLocalTables()[i]
				row, err = decodeAutomationFramedRow(layout.descriptor(), n, raw, maxAggregateLocalRecordBytes)
				if err == nil {
					canonical, err = encodeAggregateLocalRecord(layout.descriptor().name, n, row)
				}
			} else {
				row, err = decodeSourceCutRow(component-3, n, raw)
				if err == nil {
					canonical, err = encodeAutomationCutRecord(automationCutSections[component-3].name, n, row)
				}
			}
			if err != nil || !bytes.Equal(canonical, raw) {
				return errors.New("retained original frame is not canonical")
			}
		}
		counts[i] = n
		sizes[i] += int64(len(raw))
		hashes[i].Write(raw)
		if visit != nil {
			return visit(component, n, raw)
		}
		return nil
	})
	if err != nil {
		return err
	}
	for i, inv := range d.ComponentInventories {
		if counts[i] != inv.Records || sizes[i] != inv.Bytes || hex.EncodeToString(hashes[i].Sum(nil)) != inv.Digest {
			return errors.New("retained complete frame inventory differs")
		}
	}
	return nil
}

func retainedAddress(delivery string, object int64, source, original string, kind retainedStreamKind) (retainedFrameAddress, error) {
	var a retainedFrameAddress
	ns, err := retainedNamespace(delivery, object)
	if err != nil {
		return a, err
	}
	validOriginal := receiverDigest(original)
	if kind == retainedNativeStream {
		validOriginal = retainedNativeIdentity(original)
	}
	if !retainedField(source, 253) || !validOriginal || kind < retainedSourceStream || kind > retainedMetadataStream || (object == 0 && kind != retainedMetadataStream) {
		return a, errors.New("invalid retained frame address")
	}
	a = retainedFrameAddress{namespace: ns, source: source, kind: kind}
	if kind == retainedLocalStream {
		a.localID = sourceDigest([]byte("litevirt/retained-local-storage/v1"), []byte(ns), []byte(original))
	}
	return a, nil
}

func (a retainedFrameAddress) save(ctx context.Context, tx *LocalTx, component int, ordinal int64, raw []byte) error {
	table, where, args, bound, err := a.location(component, ordinal)
	if err != nil {
		return err
	}
	if len(raw) == 0 || len(raw) > bound {
		return errors.New("retained frame exceeds storage bound")
	}
	if a.kind == retainedLocalStream {
		return aggregateLocalSaveRow(ctx, tx, a.localID, component, ordinal, raw)
	}
	rows, err := tx.Query(ctx, "SELECT 1 AS present FROM "+table+" WHERE "+where+" LIMIT 1", args...)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		old, err := a.read(ctx, tx, component, ordinal)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, raw) {
			return errors.New("retained immutable frame retry differs")
		}
		return nil
	}
	_, err = tx.Exec(ctx, `INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record) VALUES(?,?,?,?,?)`, a.namespace, a.source, component, ordinal, raw)
	return err
}

func (a retainedFrameAddress) read(ctx context.Context, tx *LocalTx, component int, ordinal int64) ([]byte, error) {
	table, where, args, bound, err := a.location(component, ordinal)
	if err != nil {
		return nil, err
	}
	rows, err := tx.Query(ctx, "SELECT typeof(record) AS kind,length(CAST(record AS BLOB)) AS size FROM "+table+" WHERE "+where+" LIMIT 1", args...)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 || rows[0].String("kind") != "blob" || rows[0].Int64("size") <= 0 || rows[0].Int64("size") > int64(bound) {
		return nil, errors.New("retained frame missing or outside typed bound")
	}
	args = append(args, rows[0].Int64("size"))
	rows, err = tx.Query(ctx, "SELECT record FROM "+table+" WHERE "+where+" AND typeof(record)='blob' AND length(CAST(record AS BLOB))=? LIMIT 1", args...)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errors.New("retained frame changed during bounded read")
	}
	return rows[0].Bytes("record"), nil
}

// SQL identifiers and per-stream bounds come exclusively from this closed
// discriminator. The 96-byte namespace never becomes a receiver job/audit ID.
func (a retainedFrameAddress) location(component int, ordinal int64) (string, string, []any, int, error) {
	fail := func() (string, string, []any, int, error) {
		return "", "", nil, 0, errors.New("invalid retained frame location")
	}
	parts := strings.Split(a.namespace, ":")
	if len(parts) != 3 || parts[0] != "retained-v1" || !receiverDigest(parts[1]) || !retainedField(a.source, 253) || ordinal <= 0 {
		return fail()
	}
	n, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != parts[2] {
		return fail()
	}
	bound := maxAutomationCutRecordBytes
	switch a.kind {
	case retainedLocalStream:
		if n == 0 || !receiverDigest(a.localID) || component < 0 || component >= len(aggregateLocalTables()) {
			return fail()
		}
		return "local_automation_local_rows", "local_id=? AND section=? AND ordinal=?", []any{a.localID, component, ordinal}, maxAggregateLocalRecordBytes, nil
	case retainedSourceStream:
		if n == 0 || component < 0 || component > 11 {
			return fail()
		}
		if component < 3 {
			bound = AutomationExportChunkBytes
		}
	case retainedNativeStream:
		if n == 0 || component < 0 || component > 11 || component == 1 || component == 2 {
			return fail()
		}
		if component == 0 {
			bound = maxAutomationCutMetadataBytes
		}
	case retainedMetadataStream:
		if component != 0 {
			return fail()
		}
		bound = AutomationExportChunkBytes
		if n == 0 {
			bound = maxAutomationCutMetadataBytes
		}
	default:
		return fail()
	}
	if a.localID != "" {
		return fail()
	}
	return "local_automation_receiver_records", "attempt=? AND source=? AND component=? AND ordinal=?", []any{a.namespace, a.source, component, ordinal}, bound, nil
}
