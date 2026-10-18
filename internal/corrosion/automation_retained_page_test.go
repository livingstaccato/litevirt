package corrosion

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRetainedAllocatedMetadataSchema(t *testing.T) {
	c := NewTestClientT(t)
	if err := InitSchema(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"local_automation_retained_deliveries", "local_automation_retained_objects", "local_automation_retained_completions"} {
		rows, err := c.Query(context.Background(), `SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table)
		if err != nil || len(rows) != 1 {
			t.Errorf("actual allocated retained table absent: %s %v", table, err)
		}
		if !IsNodeLocalClaimTable(table) || IsReplicatedTable(table) {
			t.Errorf("retained pin not strictly local: %s", table)
		}
	}
}

// Signed adversarial statement and incomplete raw storage only. No actual
// adoption receipt, successful graph audit, or completion is fabricated.
func retainedPendingPages(t *testing.T, a *AutomationReceiverAttempt) ([]byte, [][]byte) {
	t.Helper()
	body := retainedAdversarialHolder(t, a)
	body.Key = LeaseTermClaimKey("retained_pending", 1)
	full, _ := json.Marshal(ClaimValue{LeaseTerm: &LeaseTermValue{Key: "retained_pending", Term: 1, Holder: a.request.Target}})
	body.ValueDigest = sourceDigest([]byte("litevirt/aggregate-full-value/v1"), full)
	var entries [][]byte
	var digest retainedDirectoryDigest
	for i, kind := range []string{"header", "receipt", "binding", "local"} {
		d := retainedDescriptorInput(kind)
		d.Source = body.Donor
		d.Incarnation = body.DonorIncarnation
		raw, _ := json.Marshal(d)
		if err := digest.add(int64(i+1), raw); err != nil {
			t.Fatal(err)
		}
		entry, _ := json.Marshal(retainedDirectoryEntry{int64(i + 1), d})
		entries = append(entries, entry)
	}
	root, _, objects, _, _, _, err := digest.finish()
	if err != nil {
		t.Fatal(err)
	}
	body.DirectoryRoot, body.DirectoryObjects, body.DirectoryBytes = root, objects, digest.descriptorBytes
	return retainedSignAdversarial(t, a.pair, body, retainedHolderDomain), entries
}
func TestRetainedDurablePagesExactRetry(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, entries := retainedPendingPages(t, a)
	before := receiverActive(t, r.client)
	first := retainedPage{Object: 0, Component: 0, Position: 0, Records: entries[:2]}
	got, err := r.stageRetained(ctx, a, raw, first)
	if err != nil {
		t.Fatalf("durable authenticated inert directory page refused: %v", err)
	}
	retry, err := r.stageRetained(ctx, a, raw, first)
	if err != nil || retry != got {
		t.Fatal("exact durable retry differs", err)
	}
	altered := first
	altered.Records = [][]byte{bytes.Replace(entries[0], []byte("header"), []byte("receipt"), 1), entries[1]}
	if _, err = r.stageRetained(ctx, a, raw, altered); err == nil {
		t.Fatal("contradictory page retry accepted")
	}
	// A new owner reloads current selection and pinned progress from SQLite.
	fresh := NewAutomationReceiver(r.client, r.dir)
	defer fresh.Close()
	resumed, err := fresh.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	final := retainedPage{Object: 0, Component: 0, Position: 2, Records: entries[2:], Terminal: true}
	done, err := fresh.stageRetained(ctx, resumed, raw, final)
	if err != nil || !done.Terminal || done.Records != 4 {
		t.Fatal("durable directory resume failed", err)
	}
	object := retainedPage{Object: 1, Component: 0, Position: 0, Records: [][]byte{[]byte("x")}, Terminal: true}
	if _, err = fresh.stageRetained(ctx, resumed, raw, object); err != nil {
		t.Fatal("pinned object page refused", err)
	}
	if _, err = fresh.stageRetained(ctx, resumed, raw, object); err != nil {
		t.Fatal("pinned object retry refused", err)
	}
	rows, err := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_retained_completions`)
	if err != nil || rows[0].Int64("n") != 0 {
		t.Fatal("raw pages manufactured completion", err)
	}
	if receiverActive(t, r.client) != before {
		t.Fatal("inert page storage changed ACTIVE")
	}
}

func TestRetainedIncompleteDeliveryCannotComplete(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	raw, entries := retainedPendingPages(t, a)
	h, err := decodeRetainedHolder(raw)
	if err != nil {
		t.Fatal(err)
	}
	first := retainedPage{Object: 0, Component: 0, Records: entries[:2]}
	if _, err = r.stageRetained(ctx, a, raw, first); err != nil {
		t.Fatal(err)
	}
	full, _ := json.Marshal(ClaimValue{LeaseTerm: &LeaseTermValue{Key: "retained_pending", Term: 1, Holder: a.request.Target}})
	active := receiverActive(t, r.client)
	proof, err := r.lookupRetainedCandidate(ctx, a, h.id, h.body.Key, h.body.Accepted, full)
	if err == nil || proof != nil || !strings.Contains(err.Error(), "retained directory incomplete") {
		t.Fatalf("storage lookup did not reach actual incomplete directory gate: proof=%v err=%v", proof, err)
	}

	// Complete every raw transport component with deliberately invalid header
	// metadata. Transport completion must still reach the strict semantic codec.
	if _, err = r.stageRetained(ctx, a, raw, retainedPage{Object: 0, Component: 0, Position: 2, Records: entries[2:], Terminal: true}); err != nil {
		t.Fatal(err)
	}
	for object := int64(1); object <= 4; object++ {
		components := 1
		if object == 4 {
			components = len(aggregateLocalTables())
		}
		for component := 0; component < components; component++ {
			var records [][]byte
			if object < 4 {
				records = [][]byte{[]byte("x")}
			}
			if _, err = r.stageRetained(ctx, a, raw, retainedPage{Object: object, Component: component, Records: records, Terminal: true}); err != nil {
				t.Fatal("inert terminal setup", err)
			}
		}
	}
	proof, err = r.lookupRetainedCandidate(ctx, a, h.id, h.body.Key, h.body.Accepted, full)
	if err == nil || proof != nil || !strings.Contains(err.Error(), "invalid character") {
		t.Fatalf("complete raw transport did not reach actual header codec: proof=%v err=%v", proof, err)
	}
	rows, e := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_retained_completions`)
	if e != nil || rows[0].Int64("n") != 0 {
		t.Fatal("incomplete graph published completion", e)
	}
	if len(r.proofs) != 0 {
		t.Fatal("incomplete graph left registered proof")
	}
	if receiverActive(t, r.client) != active {
		t.Fatal("incomplete graph changed ACTIVE")
	}
}
