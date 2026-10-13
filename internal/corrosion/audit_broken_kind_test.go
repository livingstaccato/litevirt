package corrosion

import (
	"context"
	"testing"
)

// TestVerifyAuditChain_NamesWhatKindOfBreak pins what the first broken link IS,
// not only where it is.
//
// The verifier reported every broken link as "row content does not match its
// recorded hash". On lab 1 the broken row was the first row of a FORKED chain:
// a host rebuilt under its old name appended at seq 1 with an empty prev_hash
// before its history had replicated back (docs/audit-log.md, "Rebuilding a host
// under its old name"). That row hashes correctly against its own stored
// prev_hash and its signature verifies; nothing about its content is wrong.
// Labelling it an edit sent the investigation looking for tampering that had
// not happened. It is still a verification failure — a fork is a finding — it
// just has to be called what it is.
func TestVerifyAuditChain_NamesWhatKindOfBreak(t *testing.T) {
	seed := func(t *testing.T) (context.Context, *Client) {
		t.Helper()
		ctx := context.Background()
		c := newAuditTestClient(t)
		for i, id := range []string{"r1", "r2", "r3"} {
			if err := InsertAuditLog(ctx, c, AuditRecord{
				ID: id, Username: "admin", HostName: "node-3", Action: "vm.start",
				Target: "vm-1", Result: "ok", Timestamp: "2026-10-03T22:16:0" + string(rune('1'+i)) + ".000000000Z",
			}); err != nil {
				t.Fatalf("InsertAuditLog %s: %v", id, err)
			}
		}
		return ctx, c
	}
	insertRaw := func(t *testing.T, ctx context.Context, c *Client, r AuditRecord, seq int64) {
		t.Helper()
		if err := c.Execute(ctx,
			`INSERT INTO audit_log (id, timestamp, username, host_name, action, target, detail,
			 result, prev_hash, content_hash, key_id, signature, seq)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', '', ?)`,
			r.ID, r.Timestamp, r.Username, r.HostName, r.Action, r.Target, r.Detail, r.Result,
			r.PrevHash, r.ContentHash, seq); err != nil {
			t.Fatalf("insert %s: %v", r.ID, err)
		}
	}
	fork := AuditRecord{
		ID: "fork-1", Timestamp: "2026-10-03T22:16:30.767241380Z", Username: "admin", HostName: "node-3",
		Action: "cluster.lease_term_tie.acknowledge", Target: "failover:1", Result: "ok",
	}

	for _, tc := range []struct {
		name   string
		mutate func(t *testing.T, ctx context.Context, c *Client)
		at     string
		kind   string
	}{
		{"a second chain opened under the same name", func(t *testing.T, ctx context.Context, c *Client) {
			f := fork
			f.ContentHash = HashAuditRow(f) // PrevHash "": a genesis row, correctly hashed
			insertRaw(t, ctx, c, f, 1)
		}, "fork-1", AuditBrokenForked},
		{"an edited row", func(t *testing.T, ctx context.Context, c *Client) {
			if err := c.Execute(ctx, `UPDATE audit_log SET detail = 'tampered' WHERE id = 'r2'`); err != nil {
				t.Fatal(err)
			}
		}, "r2", AuditBrokenContent},
		{"an edited fork row is an edit, not a fork", func(t *testing.T, ctx context.Context, c *Client) {
			f := fork
			f.ContentHash = HashAuditRow(f)
			f.Detail = "tampered"
			insertRaw(t, ctx, c, f, 1)
		}, "fork-1", AuditBrokenContent},
		{"a row missing before it", func(t *testing.T, ctx context.Context, c *Client) {
			if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id = 'r2'`); err != nil {
				t.Fatal(err)
			}
		}, "r3", AuditBrokenUnlinked},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, c := seed(t)
			tc.mutate(t, ctx, c)
			res, err := VerifyAuditChain(ctx, c)
			if err != nil {
				t.Fatalf("VerifyAuditChain: %v", err)
			}
			if res.BrokenAt != tc.at {
				t.Fatalf("BrokenAt = %q, want %q", res.BrokenAt, tc.at)
			}
			if res.BrokenKind != tc.kind {
				t.Errorf("BrokenKind = %q, want %q", res.BrokenKind, tc.kind)
			}
			if !res.Tampered() {
				t.Errorf("a broken link must still fail verification")
			}
		})
	}

	t.Run("an intact chain has no kind", func(t *testing.T) {
		ctx, c := seed(t)
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.BrokenAt != "" || res.BrokenKind != "" {
			t.Errorf("intact chain: BrokenAt=%q BrokenKind=%q", res.BrokenAt, res.BrokenKind)
		}
	})
}
