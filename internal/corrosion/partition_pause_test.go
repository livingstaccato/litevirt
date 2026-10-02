package corrosion

import (
	"context"
	"testing"
)

// CertifiedTransferProofs lists TOMBSTONED proofs too: ReapSpentProofs
// tombstones a spent proof after a day, and a host that comes back later still
// needs its certificate to settle (docs/design/partition-pause.md §6). It lists
// only transfer actions with a certificate.
//
// Mutation: restore the deleted_at filter (in the list or in the read) — the
// reaped proof is missing and this goes red.
func TestCertifiedTransferProofs_IncludesReapedProofs(t *testing.T) {
	ctx := context.Background()
	c := NewTestClientT(t)
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	ins := func(id, action, cert string, deleted bool) {
		t.Helper()
		var del interface{}
		if deleted {
			del = "2026-10-01T00:00:00Z"
		}
		if err := c.execLocal(ctx,
			`INSERT INTO runtime_action_proofs (id, action, target_kind, target_name, dest_host, coordinator,
			   claim_certificate, status, executor_host, created_at, updated_at, deleted_at)
			 VALUES (?, ?, 'vm', 'vm-a', 'node-b', 'node-c', ?, 'completed', 'node-b', 'x', 'x', ?)`,
			id, action, cert, del); err != nil {
			t.Fatal(err)
		}
	}
	ins("live", ActionReschedule, "{}", false)
	ins("reaped", ActionReschedule, "{}", true)
	ins("uncertified", ActionReschedule, "", false)
	ins("not-a-transfer", "lb_apply", "{}", false)
	got, err := CertifiedTransferProofs(ctx, c, ClaimKindVM, "vm-a")
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, p := range got {
		ids = append(ids, p.ID)
	}
	if len(ids) != 2 || ids[0] != "live" || ids[1] != "reaped" {
		t.Fatalf("CertifiedTransferProofs = %v, want [live reaped]", ids)
	}
	if got[1].Status != ProofCompleted || got[1].ExecutorHost != "node-b" {
		t.Fatalf("the reaped proof lost its execution record: %+v", got[1])
	}
}
