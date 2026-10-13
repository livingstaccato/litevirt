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
		// An edit to an unsigned row mid-chain that also blanks prev_hash and
		// recomputes the hash is self-consistent, like a fork. It is not a
		// second genesis (seq 2, no repeated seq 1), and it must not be given
		// the label that says no row was edited.
		{"a mid-chain row rewritten with its prev_hash blanked", func(t *testing.T, ctx context.Context, c *Client) {
			rows, err := c.Query(ctx, `SELECT id, timestamp, username, host_name, action, target, detail, result FROM audit_log WHERE id = 'r2'`)
			if err != nil || len(rows) != 1 {
				t.Fatalf("read r2: %v", err)
			}
			r := rows[0]
			ed := AuditRecord{ID: "r2", Timestamp: r.String("timestamp"), Username: r.String("username"),
				HostName: r.String("host_name"), Action: r.String("action"), Target: r.String("target"),
				Detail: "rewritten", Result: r.String("result")}
			if err := c.Execute(ctx, `UPDATE audit_log SET detail = ?, prev_hash = '', content_hash = ? WHERE id = 'r2'`,
				ed.Detail, HashAuditRow(ed)); err != nil {
				t.Fatal(err)
			}
		}, "r2", AuditBrokenUnlinked},
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
			if res.Forked() != (tc.kind == AuditBrokenForked) {
				t.Errorf("Forked() = %v for a %s break", res.Forked(), tc.kind)
			}
		})
	}

	// A fork beside a deleted row is not a fork alone: the jump in seq is a
	// deletion, and the verdict stays tampering.
	//
	// Mutation: Forked not checking the seq jumps — red.
	t.Run("a fork beside a deleted row is not a fork alone", func(t *testing.T) {
		ctx, c := seed(t)
		f := fork
		f.ContentHash = HashAuditRow(f)
		insertRaw(t, ctx, c, f, 1)
		if err := c.Execute(ctx, `DELETE FROM audit_log WHERE id = 'r2'`); err != nil {
			t.Fatal(err)
		}
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.BrokenKind != AuditBrokenForked || res.SeqDuplicates != 1 || len(res.SeqGaps) != 2 {
			t.Fatalf("setup: kind %q, %d duplicates of %v", res.BrokenKind, res.SeqDuplicates, res.SeqGaps)
		}
		if res.Forked() || !res.Tampered() {
			t.Errorf("Forked() = %v, Tampered() = %v: want a tamper verdict, not a fork alone", res.Forked(), res.Tampered())
		}
	})

	// A seq-1 row with an empty prev_hash is a fork only when it REPEATS a seq 1
	// the host already has. The first numbered row after a host's seq-0 legacy
	// rows, rewritten with its prev_hash blanked and its hash recomputed, is
	// seq 1 with an empty prev_hash too, and it is not a second genesis.
	t.Run("a first numbered row rewritten with its prev_hash blanked", func(t *testing.T) {
		ctx := context.Background()
		c := newAuditTestClient(t)
		prev := ""
		for i, id := range []string{"legacy-1", "legacy-2"} {
			r := AuditRecord{ID: id, Timestamp: "2026-09-15T06:39:0" + string(rune('1'+i)) + "Z", Username: "admin",
				HostName: "node-3", Action: "vm.start", Target: "vm-1", Result: "ok", PrevHash: prev}
			r.ContentHash = HashAuditRow(r)
			insertRaw(t, ctx, c, r, 0)
			prev = r.ContentHash
		}
		r1 := AuditRecord{ID: "r1", Timestamp: "2026-10-03T22:16:01.000000000Z", Username: "admin",
			HostName: "node-3", Action: "vm.start", Target: "vm-1", Detail: "rewritten", Result: "ok"}
		r1.ContentHash = HashAuditRow(r1) // PrevHash "" where legacy-2's hash belongs
		insertRaw(t, ctx, c, r1, 1)
		res, err := VerifyAuditChain(ctx, c)
		if err != nil {
			t.Fatal(err)
		}
		if res.BrokenAt != "r1" || res.BrokenKind != AuditBrokenUnlinked {
			t.Errorf("BrokenAt=%q BrokenKind=%q, want r1 / %q", res.BrokenAt, res.BrokenKind, AuditBrokenUnlinked)
		}
	})

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
