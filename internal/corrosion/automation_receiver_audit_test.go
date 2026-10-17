package corrosion

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

// Removing the concrete source audit must leave a real complete signed spool
// unaudited. Transport terminal alone cannot satisfy this assertion.
func TestReceiverSourceAuditCompleteAndInert(t *testing.T) {
	p, r, q, exportCtx, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 11)
	before := receiverActive(t, r.client)
	if err := r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatalf("complete genuine frozen source cannot be audited: %v", err)
	}
	if receiverActive(t, r.client) != before {
		t.Fatal("source audit changed active state")
	}
	rows, err := r.client.Query(ctx, `SELECT source,publication,records,requests FROM local_automation_receiver_audits WHERE attempt=?`, a.id)
	if err != nil || len(rows) != 1 || rows[0].String("source") != "a" || rows[0].String("publication") != q.Publication || rows[0].Int64("records") < 1 || rows[0].Int64("requests") != 0 {
		t.Fatal("actual inert source audit missing", err)
	}
}

// Using supplied future requests or dropping any original receipt field changes
// the later duplicate's exact original receipt and must fail this assertion.
func TestReceiverSourceAuditCausalHistory(t *testing.T) {
	p, r, q, exportCtx, _ := receiverAuditFixture(t, 3, nil)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	receiverThrough(t, p, r, a, q, exportCtx, 11)
	before := receiverActive(t, r.client)
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal("complete native causal history refused", err)
	}
	rows, err := r.client.Query(ctx, `SELECT head,requests FROM local_automation_receiver_audits WHERE attempt=?`, a.id)
	if err != nil || len(rows) != 1 || rows[0].Int64("requests") != 2 {
		t.Fatal("causal originals missing", err)
	}
	var head AutomationPrefix
	if json.Unmarshal(rows[0].Bytes("head"), &head) != nil || head.Sequence != 3 || head.ClusterUID != "established-cluster" {
		t.Fatal("wrong derived head")
	}
	rows, err = r.client.Query(ctx, `SELECT receipt FROM local_automation_receiver_requests WHERE request_id='barrier'`)
	var receipt contract.Receipt
	if err != nil || len(rows) != 1 || json.Unmarshal(rows[0].Bytes("receipt"), &receipt) != nil || receipt.Sequence != 2 || receipt.OperationID != "barrier-op" || receipt.ResourceUID != "established-cluster" {
		t.Fatal("entire original receipt lost", err)
	}
	if receiverActive(t, r.client) != before {
		t.Fatal("causal audit changed active state")
	}
}
