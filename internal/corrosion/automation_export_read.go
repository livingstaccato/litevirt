package corrosion

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

func sourceExportReadPage(ctx context.Context, tx *LocalTx, r AutomationExportRequest, p sourcePublication, c *sourceExportCursor) (AutomationExportPage, error) {
	page := AutomationExportPage{Publication: p.id, Component: r.Component, TerminalRecords: c.TotalRecords, TerminalBytes: c.TotalBytes, TerminalDigest: hex.EncodeToString(c.Digest[:])}
	h, err := c.hash()
	if err != nil {
		return page, err
	}
	if r.Component < 3 {
		column := []string{"artifact", "evidence", "membership"}[r.Component]
		rows, e := tx.Query(ctx, `SELECT length(`+column+`) AS size FROM local_automation_publications WHERE id=? LIMIT 1`, p.id)
		if e != nil || len(rows) != 1 || rows[0].Int64("size") != c.TotalBytes {
			return page, errors.New("evidence terminal length differs")
		}
		remaining := c.TotalBytes - c.Bytes
		n := int64(AutomationExportChunkBytes)
		if remaining < n {
			n = remaining
		}
		if n <= 0 || c.Position >= c.TotalRecords || uint64(n) > uint64(r.MaxBytes) {
			return page, errors.New("evidence chunk exceeds requested budget or terminal")
		}
		rows, e = tx.Query(ctx, `SELECT substr(`+column+`,?,?) AS chunk FROM local_automation_publications WHERE id=? AND length(`+column+`)=? LIMIT 1`, c.Bytes+1, n, p.id, c.TotalBytes)
		if e != nil || len(rows) != 1 || int64(len(rows[0].Bytes("chunk"))) != n {
			return page, errors.New("missing evidence chunk")
		}
		page.Chunk = rows[0].Bytes("chunk")
		h.Write(page.Chunk)
		c.Bytes += n
		c.Position++
	} else {
		section := int(r.Component) - 3
		page.Metadata, _ = json.Marshal(p.manifest.Cut)
		used := uint32(0)
		for len(page.Records) < int(r.MaxRecords) {
			rows, e := tx.Query(ctx, `SELECT ordinal,length(record) AS size FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal>? ORDER BY ordinal LIMIT 1`, p.manifest.Cut.ID, section, c.Position)
			if e != nil {
				return page, e
			}
			if len(rows) == 0 {
				if c.Position != c.TotalRecords {
					return page, errors.New("missing published cut record")
				}
				break
			}
			ordinal, n := rows[0].Int64("ordinal"), rows[0].Int64("size")
			if c.Position >= c.TotalRecords || ordinal != c.Position+1 || n <= 0 || n > AutomationExportMaxBytes || n > c.TotalBytes-c.Bytes {
				return page, errors.New("cut record exceeds signed inventory or storage bound")
			}
			// Subtract before loading or appending a body. There is never a
			// slice of 64 maximum bodies allocated just to discover its size.
			if uint64(n) > uint64(r.MaxBytes-used) {
				if len(page.Records) == 0 {
					return page, errors.New("one cut record exceeds requested byte budget")
				}
				break
			}
			rows, e = tx.Query(ctx, `SELECT record FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal=? AND length(record)=? LIMIT 1`, p.manifest.Cut.ID, section, ordinal, n)
			if e != nil || len(rows) != 1 || int64(len(rows[0].Bytes("record"))) != n {
				return page, errors.New("published cut record disappeared")
			}
			raw := rows[0].Bytes("record")
			if _, e = decodeSourceCutRow(section, ordinal, raw); e != nil {
				return page, e
			}
			page.Records = append(page.Records, raw)
			used += uint32(n)
			c.Position = ordinal
			c.Bytes += n
			h.Write(raw)
		}
		if c.Position == c.TotalRecords {
			rows, e := tx.Query(ctx, `SELECT ordinal FROM local_automation_cut_records WHERE cut_id=? AND section=? AND ordinal>? ORDER BY ordinal LIMIT 1`, p.manifest.Cut.ID, section, c.Position)
			if e != nil || len(rows) != 0 {
				return page, errors.New("records beyond signed terminal")
			}
		}
	}
	if c.Position == c.TotalRecords {
		if c.Bytes != c.TotalBytes || !bytes.Equal(h.Sum(nil), c.Digest[:]) {
			return page, errors.New("export terminal count/bytes/digest mismatch")
		}
		page.Terminal = true
	} else if c.Position > c.TotalRecords || c.Bytes >= c.TotalBytes {
		return page, fmt.Errorf("export position exceeds terminal")
	}
	if err = c.setHash(h); err != nil {
		return page, err
	}
	return page, nil
}
