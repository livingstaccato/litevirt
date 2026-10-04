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

// TestVoterConfigMerge_AForcedRowNeverReplacesAnAdoptedOrdinaryOne: a forced
// generation replaces an ordinary row for the same generation on a node that
// has not adopted that generation — the survivors never saw it, and a lost
// majority may have decided it unseen (§4.6). A node that HAS adopted the
// ordinary row was told by a majority of the previous generation that it was
// decided; swapping its electorate underneath it by a merge, without the
// forced row's checks or the import, would let two electorates decide one
// generation. It keeps its row, the conflict is flagged, and the refusal is
// reported for ha.voter.forced.
//
// Mutation: drop the adopted-generation check in voterConfigMergeKeepLocalRow
// — the adopted ordinary row is replaced by the forced one.
func TestVoterConfigMerge_AForcedRowNeverReplacesAnAdoptedOrdinaryOne(t *testing.T) {
	ctx := context.Background()
	adoptedNode, fresh, survivor := NewTestClientT(t), NewTestClientT(t), NewTestClientT(t)
	for _, c := range []*Client{adoptedNode, fresh, survivor} {
		if err := InitSchema(ctx, c); err != nil {
			t.Fatal(err)
		}
		putVoterConfigRow(t, c, 1, `[{"name":"a"},{"name":"b"},{"name":"c"}]`, `g1`)
		if err := RecordVoterAdoption(ctx, c, 1); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []*Client{adoptedNode, fresh} {
		putVoterConfigRow(t, c, 2, `[{"name":"b"},{"name":"c"}]`, `ordinary`)
	}
	if err := RecordVoterAdoption(ctx, adoptedNode, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := survivor.db.Exec(`INSERT INTO voter_configs
		(generation, members_json, members_hash, change, certificate, created_by, created_at, updated_at)
		VALUES (2, '[{"name":"a"}]', 'h', 'force:b,c', 'forced-evidence', 'a', 't', 't')`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []*Client{adoptedNode, fresh} {
		if err := c.MergeStateBytesLWW(survivor.DumpStateBytes()); err != nil {
			t.Fatal(err)
		}
	}
	if m, cert := voterConfigCert(t, fresh, 2); m != `[{"name":"a"}]` || cert != `forced-evidence` {
		t.Fatalf("a node that had not adopted generation 2 did not take the forced row: %s %s", m, cert)
	}
	if m, _ := voterConfigCert(t, adoptedNode, 2); m != `[{"name":"b"},{"name":"c"}]` {
		t.Fatalf("the ordinary generation 2 this node adopted was replaced by a merge: %s", m)
	}
	if adoptedNode.UnresolvedTieCount() == 0 {
		t.Fatal("the refused forced row was not flagged as a conflict")
	}
	if got := adoptedNode.RefusedForcedVoterConfigs(); got[2] == "" {
		t.Fatalf("the refusal was not reported for ha.voter.forced: %v", got)
	}
}
