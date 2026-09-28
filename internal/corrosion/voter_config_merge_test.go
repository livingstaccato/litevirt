package corrosion

import (
	"context"
	"testing"
)

func putVoterConfigRow(t *testing.T, c *Client, gen int64, members, cert string) {
	t.Helper()
	if _, err := c.db.Exec(`INSERT OR REPLACE INTO voter_configs
		(generation, members_json, members_hash, change, certificate, created_by, created_at, updated_at)
		VALUES (?, ?, 'h', 'genesis', ?, 'a', 't', 't')`, gen, members, cert); err != nil {
		t.Fatal(err)
	}
}

func voterConfigCert(t *testing.T, c *Client, gen int64) (string, string) {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT members_json, certificate FROM voter_configs WHERE generation = ?`, gen)
	if err != nil || len(rows) != 1 {
		t.Fatalf("read voter_configs %d: %v %v", gen, rows, err)
	}
	return rows[0].String("members_json"), rows[0].String("certificate")
}

// TestVoterConfigMerge_CertificateConvergesValueNever: two equally valid
// certificates for one decided value converge on both sides, so the table's
// digest settles; a different value for the same generation is never taken and
// is flagged.
//
// Mutations: keep the local certificate unconditionally — the two nodes stay
// apart; take the incoming row when the members differ — the decided value is
// overwritten.
func TestVoterConfigMerge_CertificateConvergesValueNever(t *testing.T) {
	ctx := context.Background()
	a, b := NewTestClientT(t), NewTestClientT(t)
	for _, c := range []*Client{a, b} {
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	putVoterConfigRow(t, a, 1, `[{"name":"a"}]`, `cert-from-a`)
	putVoterConfigRow(t, b, 1, `[{"name":"a"}]`, `cert-from-b`)
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeStateBytesLWW(a.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	_, ca := voterConfigCert(t, a, 1)
	_, cb := voterConfigCert(t, b, 1)
	if ca != cb {
		t.Fatalf("certificates for one decision did not converge: a=%s b=%s", ca, cb)
	}
	if a.UnresolvedTieCount() != 0 || b.UnresolvedTieCount() != 0 {
		t.Fatal("two certificates for one value were flagged as a conflict")
	}

	putVoterConfigRow(t, a, 2, `[{"name":"a"}]`, `x`)
	putVoterConfigRow(t, b, 2, `[{"name":"b"}]`, `y`)
	if err := a.MergeStateBytesLWW(b.DumpStateBytes()); err != nil {
		t.Fatal(err)
	}
	if m, _ := voterConfigCert(t, a, 2); m != `[{"name":"a"}]` {
		t.Fatalf("a different value for an existing generation replaced the local one: %s", m)
	}
	if a.UnresolvedTieCount() == 0 {
		t.Fatal("two different values for one generation were not flagged")
	}
}
