package corrosion

import (
	"context"
	"errors"
	"github.com/litevirt/litevirt/internal/automation/contract"
	"math"
)

type aggregateLocalObservation struct {
	retained       bool
	layoutDigest   string
	cursor, prefix AutomationPrefix
	incarnation    string
	inventory      [9]int64
	counts         []int64
}

func (o *aggregateLocalObservation) observe(out *aggregateLocalAudit, section int, n int64, row Row) error {
	if o.counts == nil {
		layout := aggregateLocalTables()
		if o.layoutDigest != "" {
			var err error
			layout, err = retainedLocalTablesForDigest(o.layoutDigest)
			if err != nil {
				return err
			}
		}
		o.counts = make([]int64, len(layout))
	}
	if section < 0 || section >= len(o.counts) {
		return errors.New("local snapshot component outside admitted layout")
	}
	o.counts[section] = n
	if section < 9 {
		o.inventory[section] = n
	}
	switch section {
	case 2:
		value, _, err := receiverHistoryValue(row)
		if err != nil {
			return err
		}
		d, err := automationDecision(value)
		if err != nil {
			return err
		}
		cluster := d.Command.ClusterUID
		if d.Sequence == 1 {
			assignment, err := contract.DecodeAssignment(d)
			if err != nil {
				return err
			}
			cluster = assignment.ClusterUID
		}
		out.head = AutomationPrefix{ClusterUID: cluster, Sequence: d.Sequence, Digest: row.String("digest")}
	case 9:
		if n != 1 || row.Int64("id") != 1 {
			return errors.New("local snapshot prefix singleton")
		}
		o.prefix = AutomationPrefix{ClusterUID: row.String("cluster_uid"), Sequence: uint64(row.Int64("sequence")), Digest: row.String("digest")}
	case 10:
		if n != 1 || row.Int64("id") != 1 {
			return errors.New("local snapshot incarnation singleton")
		}
		o.incarnation = row.String("incarnation")
	case 11, 12, 13:
		return errors.New("local snapshot pending recovery or staging")
	case 14:
		if n != 1 || row.Int64("id") != 1 || row.Int64("generation") != 0 {
			return errors.New("local snapshot reseed lineage unavailable")
		}
	case 15:
		if o.layoutDigest != "" {
			if o.layoutDigest == retainedLocalLayout83Digest() && row.Int64("version") == 84 {
				return errors.New("local snapshot schema/layout differs")
			}
			if o.layoutDigest == retainedLocalLayoutDigest() && row.Int64("version") != 84 {
				return errors.New("local snapshot schema/layout differs")
			}
		}
		// Current proof inventories the live schema. Retained originals keep
		// their pre-metadata, host-incarnation union or prior live80/81/82/83 bytes.
		if n != 1 || row.Int64("id") != 1 || (row.Int64("version") != 84 && !(o.retained && (row.Int64("version") == 78 || row.Int64("version") == 79 || row.Int64("version") == 80 || row.Int64("version") == 81 || row.Int64("version") == 82 || row.Int64("version") == 83))) {
			return errors.New("local snapshot schema unavailable")
		}
	case 21:
		if n != 1 {
			return errors.New("local snapshot semantic singleton")
		}
		o.cursor = AutomationPrefix{ClusterUID: row.String("cluster_uid"), Sequence: uint64(row.Int64("sequence")), Digest: row.String("digest")}
	}
	if out.records == math.MaxInt64 {
		return errors.New("local snapshot record overflow")
	}
	out.records++
	return nil
}

func (o *aggregateLocalObservation) audit(ctx context.Context, tx *LocalTx, original receiverAuditContext, host, namespace, localID string, projection bool, out *aggregateLocalAudit) error {
	if o.incarnation != original.facts.Incarnation {
		return errors.New("local snapshot lifetime differs")
	}
	if o.cursor.Sequence > out.head.Sequence || o.prefix.Sequence > out.head.Sequence {
		return errors.New("local snapshot cursor beyond certified head")
	}
	for _, p := range []AutomationPrefix{o.cursor, o.prefix} {
		if p.Sequence == 0 && (p.ClusterUID != "" || p.Digest != "") {
			return errors.New("local snapshot malformed empty cursor")
		}
	}
	s := receiverAuditStore{tx: tx, attempt: original.id, source: host, id: namespace, evidenceID: out.id, localID: localID, localCursor: &o.cursor}
	if projection {
		s.localProjectionID = localID
		s.localLayoutDigest = o.layoutDigest
	}
	s.publication.manifest.Cut.Head = out.head
	s.publication.manifest.Cut.Generation = original.request.Generation
	for i, n := range o.inventory {
		s.publication.manifest.Cut.Inventory = append(s.publication.manifest.Cut.Inventory, automationCutInventory{Section: automationCutSections[i].name, Records: n})
	}
	out.store = s
	var err error
	if _, err = s.index(ctx); err != nil {
		return err
	}
	if err = s.localLineageContext(ctx, original, o.incarnation); err != nil {
		return err
	}
	if o.prefix.Sequence > 0 {
		row, err := s.sequence(ctx, 5, int64(o.prefix.Sequence))
		if err != nil {
			return err
		}
		if o.prefix.Digest != row.String("digest") || o.prefix.ClusterUID != out.head.ClusterUID {
			return errors.New("local prefix differs from certified history")
		}
	}
	if _, _, err = s.history(ctx); err != nil {
		return err
	}
	out.coverage, _, err = s.claimsAndCoverage(ctx, out.head)
	if err != nil {
		return err
	}
	return nil
}
