package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
)

func TestReceiverBindingIgnoresVoterRowStamp(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	a, err := r.Begin(context.Background(), q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	before := receiverBinding(a.request, a.facts, a.view)
	f := a.facts
	old, next := *f.Old, *f.Next
	old.UpdatedAt, next.UpdatedAt = "incidental-old", "incidental-next"
	f.Old, f.Next = &old, &next
	if !bytes.Equal(before, receiverBinding(a.request, f, a.view)) || !sameReceiverFacts(a.facts, f) {
		t.Fatal("incidental voter row stamp changed durable v1 binding")
	}
	if sourceConfigDigest(a.facts.Old) != sourceConfigDigest(f.Old) {
		t.Fatal("chosen membership digest changed with stamp")
	}
	if _, err = r.client.db.Exec(`UPDATE voter_configs SET updated_at='incidental-row-stamp'`); err != nil {
		t.Fatal(err)
	}
	fresh := NewAutomationReceiver(r.client, r.dir)
	retried, err := fresh.Begin(context.Background(), q.Intent, nil)
	if err != nil || retried.id != a.id {
		t.Fatal("row stamp changed actual source read or exact retry", err)
	}
	var decoded receiverAttemptBinding
	if err = json.Unmarshal(before, &decoded); err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(decoded)
	if err != nil || !bytes.Equal(before, encoded) || bytes.Contains(encoded, []byte("UpdatedAt")) {
		t.Fatal("durable v1 binding shape changed", err)
	}
}
