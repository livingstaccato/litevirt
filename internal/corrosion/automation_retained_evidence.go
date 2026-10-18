package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
)

func retainedComponentBinding(delivery string, object int64, kind retainedStreamKind, component int, inv automationCutInventory) string {
	raw, _ := json.Marshal(struct {
		Delivery  string
		Object    int64
		Kind      retainedStreamKind
		Component int
		Inventory automationCutInventory
	}{delivery, object, kind, component, inv})
	return sourceDigest([]byte("litevirt/retained-component/v1"), raw)
}

// Complete typed transport evidence excludes its own completion row. Current
// receiver dependencies are captured separately after completion is inserted.
// Every read is a bounded primary-key step, including malformed first keys.
func retainedDeliveryEvidenceTx(ctx context.Context, tx *LocalTx, holder retainedHolder) (string, retainedDirectoryReader, error) {
	address, err := retainedAddress(holder.id, 0, holder.body.Donor, holder.body.DirectoryRoot, retainedMetadataStream)
	directory := retainedDirectoryReader{address, holder.body.DirectoryObjects}
	if err != nil {
		return "", directory, err
	}
	state, found, err := retainedStateTx(ctx, tx, address, 0)
	if err != nil {
		return "", directory, err
	}
	if !found || !state.Terminal {
		return "", directory, errors.New("retained directory incomplete")
	}
	if err = retainedDirectoryTerminal(ctx, tx, holder, address); err != nil {
		return "", directory, err
	}
	h := sha256.New()
	sourceHash(h, []byte("litevirt/retained-complete-evidence/v1"), holder.raw)
	objects := aggregateLocalTable{"local_automation_retained_objects", "delivery,ordinal,namespace,descriptor", "delivery,ordinal", "titb", false}
	var count int64
	err = retainedHashScopedTable(ctx, tx, h, objects, "delivery=?", []any{holder.id}, func(n int64, row Row) error {
		if row.String("delivery") != holder.id || row.Int64("ordinal") != n || n > directory.objects {
			return errors.New("retained object pin directory differs")
		}
		count = n
		_, _, found, err := retainedObjectTx(ctx, tx, holder.id, n)
		if err != nil {
			return err
		}
		if !found {
			return errors.New("retained object pin disappeared")
		}
		return nil
	})
	if err != nil {
		return "", directory, err
	}
	if count != directory.objects {
		return "", directory, errors.New("retained object pin count differs")
	}
	for object := int64(0); ; object++ {
		a := address
		inventories := []automationCutInventory{{"directory/v1", 1, holder.body.DirectoryObjects, holder.body.DirectoryBytes, holder.body.DirectoryRoot}}
		if object > 0 {
			d, stored, found, e := retainedObjectTx(ctx, tx, holder.id, object)
			if e != nil {
				return "", directory, e
			}
			if !found {
				return "", directory, errors.New("retained object pin unavailable")
			}
			a = stored
			inventories = d.ComponentInventories
		}
		extra, e := tx.Query(ctx, `SELECT 1 AS present FROM local_automation_receiver_sources WHERE attempt=? LIMIT 1`, a.namespace)
		if e != nil {
			return "", directory, e
		}
		if len(extra) != 0 {
			return "", directory, errors.New("retained namespace has foreign source publication")
		}
		if a.kind == retainedLocalStream {
			extra, e = tx.Query(ctx, `SELECT 1 AS present FROM local_automation_receiver_records WHERE attempt=? LIMIT 1`, a.namespace)
			if e != nil {
				return "", directory, e
			}
			if len(extra) != 0 {
				return "", directory, errors.New("retained local namespace has ordinary body")
			}
		}
		componentIndex := func(component int) (int, error) {
			i := component
			if a.kind == retainedNativeStream {
				if component == 1 || component == 2 {
					return 0, errors.New("retained native progress component differs")
				}
				if component >= 3 {
					i = component - 2
				}
			}
			if i < 0 || i >= len(inventories) {
				return 0, errors.New("retained progress component outside inventory")
			}
			return i, nil
		}
		var components int64
		var lastComponent = -1
		componentTable := aggregateLocalTable{"local_automation_receiver_components", "attempt,source,component,state,cursor,terminal", "attempt,source,component", "ttibti", false}
		err = retainedHashScopedTable(ctx, tx, h, componentTable, "attempt=?", []any{a.namespace}, func(n int64, row Row) error {
			component := row.Int("component")
			i, e := componentIndex(component)
			if e != nil {
				return e
			}
			if row.String("source") != a.source || i != int(n-1) || row.String("cursor") != "" || row.Int64("terminal") != 1 {
				return errors.New("retained component terminal inventory differs")
			}
			var s retainedPageState
			if e = retainedCanonical(row.Bytes("state"), receiverStateBytes, &s); e != nil {
				return e
			}
			inv := inventories[i]
			if s.Binding != retainedComponentBinding(holder.id, object, a.kind, component, inv) || s.Records != inv.Records || s.Bytes != inv.Bytes || !s.Terminal {
				return errors.New("retained complete component state differs")
			}
			components = n
			return nil
		})
		if err != nil {
			return "", directory, err
		}
		if components != int64(len(inventories)) {
			return "", directory, errors.New("retained object component incomplete")
		}
		pages := aggregateLocalTable{"local_automation_receiver_pages", "attempt,source,component,position,request,digest,progress", "attempt,source,component,position", "ttiittb", false}
		var position, total int64
		terminal := true
		seenComponents := 0
		err = retainedHashScopedTable(ctx, tx, h, pages, "attempt=?", []any{a.namespace}, func(_ int64, row Row) error {
			component := row.Int("component")
			i, e := componentIndex(component)
			if e != nil {
				return e
			}
			inv := inventories[i]
			if row.String("source") != a.source {
				return errors.New("retained page source differs")
			}
			if component != lastComponent {
				if !terminal || i != seenComponents {
					return errors.New("retained page component gap")
				}
				seenComponents++
				lastComponent = component
				position, total, terminal = 0, 0, false
			}
			if terminal || row.Int64("position") != position {
				return errors.New("retained page position gap")
			}
			binding := retainedComponentBinding(holder.id, object, a.kind, component, inv)
			if row.String("request") != binding || !receiverDigest(row.String("digest")) {
				return errors.New("retained page binding differs")
			}
			var progress retainedProgress
			if e = retainedCanonical(row.Bytes("progress"), receiverStateBytes, &progress); e != nil {
				return e
			}
			if progress.Delivery != holder.id || progress.Object != object || progress.Component != component || progress.Records < position || progress.Records > inv.Records || progress.Bytes < total || progress.Bytes > inv.Bytes || progress.Records-position > 64 || a.kind == retainedLocalStream && progress.Records-position > 1 {
				return errors.New("retained page stored progress differs")
			}
			pageHash := sha256.New()
			sourceHash(pageHash, []byte("litevirt/retained-exact-page/v1"), []byte(binding), automationCutInteger(position))
			if progress.Terminal {
				sourceHash(pageHash, []byte{1})
			} else {
				sourceHash(pageHash, []byte{0})
			}
			limit := int64(maxAutomationCutRecordBytes)
			if a.kind == retainedLocalStream {
				limit = maxAggregateLocalRecordBytes
			}
			var pageBytes int64
			for n := position; n < progress.Records; {
				n++
				raw, e := a.read(ctx, tx, component, n)
				if e != nil {
					return e
				}
				if int64(len(raw)) > limit-pageBytes {
					return errors.New("retained stored page exceeds body budget")
				}
				pageBytes += int64(len(raw))
				sourceHash(pageHash, raw)
			}
			if progress.Bytes-total != pageBytes || hex.EncodeToString(pageHash.Sum(nil)) != row.String("digest") || progress.Terminal != (progress.Records == inv.Records) || progress.Terminal && progress.Bytes != inv.Bytes || !progress.Terminal && progress.Records == position {
				return errors.New("retained page exact body inventory differs")
			}
			position, total, terminal = progress.Records, progress.Bytes, progress.Terminal
			return nil
		})
		if err != nil {
			return "", directory, err
		}
		if seenComponents != len(inventories) || !terminal {
			return "", directory, errors.New("retained page terminal missing")
		}
		table := aggregateLocalTable{"local_automation_receiver_records", "attempt,source,component,ordinal,record", "attempt,source,component,ordinal", "ttiib", false}
		scope, args := "attempt=?", []any{a.namespace}
		if a.kind == retainedLocalStream {
			table = aggregateLocalTable{"local_automation_local_rows", "local_id,section,ordinal,record", "local_id,section,ordinal", "tiib", false}
			scope, args = "local_id=?", []any{a.localID}
		}
		err = retainedHashScopedTable(ctx, tx, h, table, scope, args, func(_ int64, row Row) error {
			if a.kind != retainedLocalStream && row.String("source") != a.source {
				return errors.New("retained extra frame source")
			}
			return nil
		})
		if err != nil {
			return "", directory, err
		}
		if object == directory.objects {
			break
		}
	}
	return hex.EncodeToString(h.Sum(nil)), directory, nil
}
func retainedHashScopedTable(ctx context.Context, tx *LocalTx, h hash.Hash, d aggregateLocalTable, scope string, args []any, visit func(int64, Row) error) error {
	sourceHash(h, []byte("table"), []byte(d.table), []byte(d.columns), []byte(d.keys))
	var count int64
	limit := currentEvidenceLimit
	if d.table == "local_automation_local_rows" {
		limit = func(column string) int64 {
			if column == "record" {
				return maxAggregateLocalRecordBytes
			}
			return currentEvidenceLimit(column)
		}
	}
	err := walkAggregateBoundedTableFiltered(ctx, tx, d, "", limit, maxAggregateLocalRecordBytes+maxSourcePublicationBytes+1024, nil, scope, args, func(n int64, row Row) error {
		if visit != nil {
			if err := visit(n, row); err != nil {
				return err
			}
		}
		sourceHash(h, automationCutInteger(n))
		for i, v := range row.Values {
			sourceHash(h, []byte(row.Columns[i]))
			switch value := v.(type) {
			case string:
				sourceHash(h, []byte("text"), []byte(value))
			case []byte:
				sourceHash(h, []byte("blob"), value)
			case int64:
				sourceHash(h, []byte("integer"), automationCutInteger(value))
			default:
				return errors.New("retained evidence field type differs")
			}
		}
		count = n
		return nil
	})
	if err != nil {
		return err
	}
	sourceHash(h, []byte("end"), automationCutInteger(count))
	return nil
}
func sameRetainedCompletion(a, b retainedCompletion) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
