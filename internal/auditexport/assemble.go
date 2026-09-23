// Package auditexport assembles a paginated audit-chain export into the single
// document its consumers need.
//
// ExportAuditChain pages, because the whole chain does not fit in one unary
// message. Every caller therefore has to walk the cursor, and a caller that
// forgets does not fail — it returns page one, which looks exactly like a
// complete export and is the artifact an operator then ships to WORM storage.
// That silent-truncation shape is why the walk lives here instead of at each
// call site: there is one implementation to get right, and a consumer that
// wants the chain cannot express "the first 5000 rows" by accident.
package auditexport

import (
	"context"
	"encoding/json"
	"fmt"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"sort"
	"strings"
)

// FetchPage returns one export page for the given cursor. The empty cursor asks
// for the first page.
type FetchPage func(ctx context.Context, cursor string) (*pb.ExportAuditChainResponse, error)

// MaxAssembledBytes bounds the in-memory audit-chain document.
//
// This package assembles the WHOLE chain in the daemon's own heap for the web
// UI and the REST gateway. audit_log is append-only with no retention prune, so
// there is no natural bound on the input and the peak allocation is several
// times the document size once marshalling doubles it.
//
// A var, not a const, only so a test can shrink it; nothing in production
// reassigns it.
var MaxAssembledBytes = 256 << 20

// Assemble follows the cursor to the end and merges every page into one JSON
// document, returning it alongside the total row count.
//
// Rows are concatenated in the order the server emitted them, which is the
// verifier's own order — a chain is only checkable in the order its links were
// built. Keys other than "rows" are taken from the first page that carries
// them: the evidence tables and the CA ride on page one, and a later page must
// not be able to replace them.
func Assemble(ctx context.Context, fetch FetchPage) ([]byte, int, error) {
	doc := map[string]json.RawMessage{}
	rows := []json.RawMessage{}
	total := 0
	bytesHeld := 0

	for cursor, seen := "", map[string]bool{}; ; {
		resp, err := fetch(ctx, cursor)
		if err != nil {
			return nil, 0, fmt.Errorf("export audit chain: %w", err)
		}

		var page map[string]json.RawMessage
		if err := json.Unmarshal([]byte(resp.Json), &page); err != nil {
			return nil, 0, fmt.Errorf("decode export page: %w", err)
		}
		if raw, ok := page["rows"]; ok {
			var pageRows []json.RawMessage
			if err := json.Unmarshal(raw, &pageRows); err != nil {
				return nil, 0, fmt.Errorf("decode export rows: %w", err)
			}
			rows = append(rows, pageRows...)
			bytesHeld += len(raw)
			// audit_log is append-only with no retention prune, so the input is
			// unbounded: a two-year-old cluster asked for its whole chain walks
			// every page into this slice and then DOUBLES the allocation twice
			// to marshal it. The daemon is killed by the OOM killer, and
			// because that is SIGKILL the watchdog Heartbeat's deferred disarm
			// never runs -- on a host that still owns workloads the watchdog is
			// left counting while the control plane is down.
			//
			// Refusing with a message naming the streaming alternative is a
			// worse export and a much better failure than letting the kernel
			// decide which process dies.
			if bytesHeld > MaxAssembledBytes {
				return nil, 0, fmt.Errorf(
					"audit chain is too large to assemble in memory (%d MiB of rows so far, "+
						"limit %d MiB); narrow the window with --since/--until, or use "+
						"`lv audit export` which writes pages as they arrive",
					bytesHeld>>20, MaxAssembledBytes>>20)
			}
		}
		for k, v := range page {
			if k == "rows" {
				continue
			}
			if _, already := doc[k]; !already {
				doc[k] = v
			}
		}
		total += int(resp.RowCount)

		if resp.NextCursor == "" {
			break
		}
		// The walk is driven by a value the server chooses, so a server that
		// stops advancing must end it rather than hold the request open
		// forever. Erroring beats returning what was collected: a partial
		// document here is the very thing this package exists to prevent.
		if seen[resp.NextCursor] {
			return nil, 0, fmt.Errorf("export audit chain: server repeated cursor %q; refusing to return a partial chain", resp.NextCursor)
		}
		seen[resp.NextCursor] = true
		cursor = resp.NextCursor
	}

	// COMPLETENESS, before returning something that looks authoritative.
	//
	// The evidence tables -- signing_keys, key_lifecycle, chain_heads -- ride on
	// page ONE. A host that rotates its signing key after that page produces
	// rows on later pages signed by a key whose certificate is not in the
	// document, and an external verifier cannot check them at all. It is the
	// same class as a seq gap: the artifact replays as broken, and the operator
	// cannot tell that from tampering.
	//
	// This package exists to refuse a partial chain -- it already errors when a
	// server repeats a cursor -- so an uncheckable one is refused here too,
	// naming the key and the remedy rather than writing a document whose
	// verification will fail later for reasons nobody can attribute.
	if err := checkKeyCoverage(doc, rows); err != nil {
		return nil, 0, err
	}
	if raw, ok := doc["seq_gaps"]; ok {
		return nil, 0, fmt.Errorf("export audit chain: the server reported gaps in a host's "+
			"seq sequence (%s); the rows below a gap replay as a chain break, which is "+
			"indistinguishable from tampering. Re-run once replication has caught up", raw)
	}

	merged, err := json.Marshal(rows)
	if err != nil {
		return nil, 0, fmt.Errorf("encode export rows: %w", err)
	}
	doc["rows"] = merged
	body, err := json.Marshal(doc)
	if err != nil {
		return nil, 0, fmt.Errorf("encode export: %w", err)
	}
	return body, total, nil
}

// checkKeyCoverage refuses a document whose rows reference a signing key the
// page-one evidence does not carry.
//
// Rows written before v45 have no key_id: they are chain-verified but not
// tamper-evident, and the verifier reports them as such, so an empty key_id is
// not a coverage failure.
func checkKeyCoverage(doc map[string]json.RawMessage, rows []json.RawMessage) error {
	raw, ok := doc["signing_keys"]
	if !ok {
		return nil // no evidence section at all: page one carried none
	}
	var keys []struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(raw, &keys); err != nil {
		return fmt.Errorf("decode signing_keys evidence: %w", err)
	}
	known := make(map[string]bool, len(keys))
	for _, k := range keys {
		known[k.KeyID] = true
	}

	missing := map[string]bool{}
	for _, r := range rows {
		var row struct {
			KeyID    string `json:"key_id"`
			HostName string `json:"host_name"`
		}
		if err := json.Unmarshal(r, &row); err != nil {
			return fmt.Errorf("decode export row: %w", err)
		}
		if row.KeyID != "" && !known[row.KeyID] {
			missing[row.KeyID+" ("+row.HostName+")"] = true
		}
	}
	if len(missing) == 0 {
		return nil
	}
	names := make([]string, 0, len(missing))
	for k := range missing {
		names = append(names, k)
	}
	sort.Strings(names)
	return fmt.Errorf("export audit chain: %d row signing key(s) have no certificate in the "+
		"exported evidence: %s. The evidence tables ride on page one, so a key rotated "+
		"mid-export is absent and those rows cannot be verified offline at all. Re-run the "+
		"export", len(names), strings.Join(names, ", "))
}
