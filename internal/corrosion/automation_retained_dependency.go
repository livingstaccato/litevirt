package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
)

type retainedDirectoryReader struct {
	address retainedFrameAddress
	objects int64
}

func retainedOriginalLocalDependency(ctx context.Context, tx *LocalTx, h retainedAggregateHeader, binding []byte, a retainedFrameAddress, d retainedObjectDescriptor, directory retainedDirectoryReader) (string, error) {
	if h.BindingDigest != sourceDigest(binding) || !receiverDigest(h.Attempt) || h.Host != d.Source || h.Incarnation != d.Incarnation || h.LocalID != d.OriginalIdentity || d.Kind != "local" || h.LayoutDigest != d.LayoutDigest {
		return "", errors.New("retained original local binding differs")
	}
	listed, address, err := directory.find(ctx, tx, "local", h.LocalID)
	if err != nil {
		return "", err
	}
	want, _ := json.Marshal(d)
	got, _ := json.Marshal(listed)
	if address != a || !bytes.Equal(want, got) {
		return "", errors.New("retained local directory differs")
	}
	result := sha256.New()
	sourceHash(result, []byte("litevirt/local-dependencies/v1"), []byte(h.Attempt), binding, []byte(h.Host))
	layout, err := retainedLocalTablesForDigest(h.LayoutDigest)
	if err != nil {
		return "", err
	}
	section := 0
	var count, nativeRecords, referenceRecords int64
	var previous []any
	start := func() {
		table := layout[section]
		sourceHash(result, []byte("table"), []byte(table.table), []byte(table.columns), []byte(table.keys))
	}
	end := func() {
		sourceHash(result, []byte("end"), automationCutInteger(count))
		count = 0
		previous = nil
		section++
	}
	start()
	err = a.walk(ctx, tx, d, func(s int, n int64, raw []byte) error {
		for section < s {
			end()
			start()
		}
		table := layout[s]
		row, err := decodeAutomationFramedRow(table.descriptor(), n, raw, maxAggregateLocalRecordBytes)
		if err != nil {
			return err
		}
		previous, err = retainedLocalRowKeys(table, row, previous)
		if err != nil {
			return err
		}
		switch table.table {
		case "local_automation_cuts":
			m, err := readAutomationCutMetadata(row)
			if err != nil {
				return err
			}
			object, original, err := directory.find(ctx, tx, "native", m.ID)
			if err != nil {
				return err
			}
			if m.Source != h.Host || object.Source != m.Source || object.Incarnation != m.Incarnation {
				return errors.New("retained owned cut identity differs")
			}
			metadata, err := original.read(ctx, tx, 0, 1)
			if err != nil {
				return err
			}
			if !bytes.Equal(metadata, row.Bytes("metadata")) {
				return errors.New("retained owned metadata differs")
			}
			inventories, _ := json.Marshal(m.Inventory)
			retained, _ := json.Marshal(object.ComponentInventories[1:])
			if !bytes.Equal(inventories, retained) {
				return errors.New("retained owned inventory differs")
			}
			if err = original.walk(ctx, tx, object, nil); err != nil {
				return err
			}
			for _, inv := range m.Inventory {
				if inv.Records > math.MaxInt64-nativeRecords {
					return errors.New("retained native count overflow")
				}
				nativeRecords += inv.Records
			}
		case "local_automation_cut_records":
			object, original, err := directory.find(ctx, tx, "native", row.String("cut_id"))
			if err != nil {
				return err
			}
			s, n := row.Int64("section"), row.Int64("ordinal")
			if s < 0 || s >= int64(len(automationCutSections)) || n <= 0 || n > object.ComponentInventories[s+1].Records || object.Source != h.Host {
				return errors.New("retained original record reference differs")
			}
			body, err := original.read(ctx, tx, int(s)+3, n)
			if err != nil {
				return err
			}
			if !bytes.Equal(row.Bytes("record"), []byte(sourceDigest(body))) {
				return errors.New("retained original record digest differs")
			}
			sourceHash(result, []byte("original-record-bytes"), body)
			if referenceRecords == math.MaxInt64 {
				return errors.New("retained reference count overflow")
			}
			referenceRecords++
		}
		sourceHash(result, raw)
		count = n
		return nil
	})
	if err != nil {
		return "", err
	}
	for section < len(layout) {
		end()
		if section < len(layout) {
			start()
		}
	}
	if nativeRecords != referenceRecords {
		return "", errors.New("retained owned record coverage differs")
	}
	digest := hex.EncodeToString(result.Sum(nil))
	if h.LocalDependency != digest || h.LocalID != sourceDigest([]byte("litevirt/local-audit/v1"), []byte(h.Attempt), []byte(digest)) {
		return "", errors.New("retained original local dependency differs")
	}
	return digest, nil
}

// Every directory row is visited with the same one-body length-first reader.
// No caller-selected SQL, unbounded descriptor slice, or trusted ID map exists.
func (d retainedDirectoryReader) walk(ctx context.Context, tx *LocalTx, visit func(int64, retainedObjectDescriptor) error) error {
	if d.objects <= 0 || d.address.kind != retainedMetadataStream {
		return errors.New("invalid retained directory")
	}
	parts := strings.Split(d.address.namespace, ":")
	if len(parts) != 3 || parts[2] != "0" {
		return errors.New("invalid retained directory namespace")
	}
	if _, _, _, _, err := d.address.location(0, 1); err != nil {
		return err
	}
	var seen int64
	err := walkAutomationStoredFrames(ctx, tx, "local_automation_receiver_records", "attempt=? AND source=?", []any{d.address.namespace, d.address.source}, "component", maxAutomationCutMetadataBytes, func(component int, n int64, raw []byte) error {
		if component != 0 || seen == math.MaxInt64 || n != seen+1 || n > d.objects {
			return errors.New("retained directory inventory differs")
		}
		seen = n
		var entry retainedDirectoryEntry
		if err := retainedCanonical(raw, maxAutomationCutMetadataBytes, &entry); err != nil {
			return err
		}
		if entry.Ordinal != n {
			return errors.New("retained directory object ordinal differs")
		}
		encoded, _ := json.Marshal(entry.Descriptor)
		descriptor, err := decodeRetainedObject(encoded)
		if err != nil {
			return err
		}
		return visit(n, descriptor)
	})
	if err == nil && seen != d.objects {
		err = errors.New("retained directory incomplete")
	}
	return err
}

func (d retainedDirectoryReader) find(ctx context.Context, tx *LocalTx, kind, identity string) (retainedObjectDescriptor, retainedFrameAddress, error) {
	var found retainedObjectDescriptor
	var address retainedFrameAddress
	err := d.walk(ctx, tx, func(n int64, descriptor retainedObjectDescriptor) error {
		if descriptor.Kind != kind || descriptor.OriginalIdentity != identity {
			return nil
		}
		if found.Kind != "" {
			return errors.New("duplicate retained original identity")
		}
		_, _, stream := retainedObjectSections(descriptor.Kind)
		var err error
		address, err = retainedAddress(strings.Split(d.address.namespace, ":")[1], n, descriptor.Source, descriptor.OriginalIdentity, stream)
		if err != nil {
			return err
		}
		found = descriptor
		return nil
	})
	if err == nil && found.Kind == "" {
		err = errors.New("retained directory original unavailable")
	}
	return found, address, err
}

// C captured SQL's nonnegative integer / BINARY text keys. Check that exact
// ordering while retaining only the preceding bounded primary-key tuple.
func retainedLocalRowKeys(d aggregateLocalTable, row Row, previous []any) ([]any, error) {
	if len(row.Values) != len(d.shape) {
		return nil, errors.New("retained local shape differs")
	}
	for i, v := range row.Values {
		valid := false
		limit := aggregateLocalLimit(row.Columns[i])
		if row.Columns[i] == "value_json" && (d.table == "local_recovery_claims" || d.table == "local_incarnation_claims") {
			limit = maxAutomationCutRecordBytes
		}
		switch d.shape[i] {
		case 'i':
			n, ok := v.(int64)
			valid = ok && n >= 0
		case 't', 'T':
			s, ok := v.(string)
			valid = (ok && int64(len(s)) <= limit) || (d.shape[i] == 'T' && v == nil)
		case 'b':
			b, ok := v.([]byte)
			valid = ok && int64(len(b)) <= limit
		}
		if !valid {
			return nil, errors.New("retained local field type or bound differs")
		}
	}
	keys := aggregateLocalColumns(d.keys)
	next := make([]any, len(keys))
	comparison := 0
	for i, key := range keys {
		for j, column := range row.Columns {
			if column == key {
				next[i] = row.Values[j]
				break
			}
		}
		if next[i] == nil {
			return nil, errors.New("retained local primary key missing")
		}
		if previous == nil || comparison != 0 {
			continue
		}
		switch value := next[i].(type) {
		case int64:
			old, ok := previous[i].(int64)
			if !ok {
				return nil, errors.New("retained key type differs")
			}
			if value < old {
				comparison = -1
			} else if value > old {
				comparison = 1
			}
		case string:
			old, ok := previous[i].(string)
			if !ok {
				return nil, errors.New("retained key type differs")
			}
			comparison = strings.Compare(value, old)
		default:
			return nil, errors.New("unsupported retained primary key")
		}
	}
	if previous != nil && comparison <= 0 {
		return nil, errors.New("retained local primary keys reordered or duplicate")
	}
	return next, nil
}
