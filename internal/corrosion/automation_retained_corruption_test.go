package corrosion

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func retainedStagePendingComplete(t *testing.T, r *AutomationReceiver, a *AutomationReceiverAttempt) (retainedHolder, retainedPage) {
	t.Helper()
	ctx := context.Background()
	raw, entries := retainedPendingPages(t, a)
	h, err := decodeRetainedHolder(raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.stageRetained(ctx, a, raw, retainedPage{Object: 0, Component: 0, Records: entries, Terminal: true}); err != nil {
		t.Fatal(err)
	}
	var first retainedPage
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
			page := retainedPage{Object: object, Component: component, Records: records, Terminal: true}
			if _, err = r.stageRetained(ctx, a, raw, page); err != nil {
				t.Fatal(err)
			}
			if object == 1 {
				first = page
			}
		}
	}
	return h, first
}
func TestRetainedTransportRejectsForeignStorage(t *testing.T) {
	_, r, q, _, _ := receiverFixture(t)
	ctx := context.Background()
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	h, _ := retainedStagePendingComplete(t, r, a)
	tx0, err := r.client.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx0.Rollback()
	tx := &LocalTx{tx: tx0}
	if _, _, err = retainedDeliveryEvidenceTx(ctx, tx, h); err != nil {
		t.Fatal("complete inert transport setup", err)
	}
	local, _ := retainedNamespace(h.id, 4)
	for _, mode := range []string{"local-leaked-ordinary-body", "foreign-source-pin"} {
		t.Run(mode, func(t *testing.T) {
			if _, err := tx0.Exec(`SAVEPOINT retained_foreign`); err != nil {
				t.Fatal(err)
			}
			defer tx0.Exec(`ROLLBACK TO retained_foreign`)
			switch mode {
			case "local-leaked-ordinary-body":
				_, err = tx0.Exec(`INSERT INTO local_automation_receiver_records(attempt,source,component,ordinal,record)VALUES(?,?,0,1,x'61')`, local, h.body.Donor)
			case "foreign-source-pin":
				_, err = tx0.Exec(`INSERT INTO local_automation_receiver_sources(attempt,source,publication,authenticated,metadata)VALUES(?,?,?,0,x'')`, local, h.body.Donor, strings.Repeat("a", 64))
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = retainedDeliveryEvidenceTx(ctx, tx, h); err == nil {
				t.Fatal("unreferenced retained storage accepted")
			}
		})
	}
}
func TestRetainedRetryRequiresDurableProgress(t *testing.T) {
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
	page := retainedPage{Object: 0, Component: 0, Records: entries[:2]}
	if _, err = r.stageRetained(ctx, a, raw, page); err != nil {
		t.Fatal(err)
	}
	ns, _ := retainedNamespace(h.id, 0)
	if _, err = r.client.db.Exec(`DELETE FROM local_automation_receiver_components WHERE attempt=?`, ns); err != nil {
		t.Fatal(err)
	}
	if _, err = r.stageRetained(ctx, a, raw, page); err == nil {
		t.Fatal("exact retry fabricated missing durable progress")
	}
}
func TestRetainedPinsInvalidateOrdinaryCurrentProof(t *testing.T) {
	for _, kind := range []string{"delivery", "object", "completion"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{1, 1}})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Discard()
			active := receiverActive(t, f.local.c)
			d := strings.Repeat("a", 64)
			switch kind {
			case "delivery":
				_, err = f.local.c.db.Exec(`INSERT INTO local_automation_retained_deliveries(id,attempt,envelope)VALUES(?,?,?)`, d, f.attempt.id, []byte("changed"))
			case "object":
				raw, _ := json.Marshal(retainedDescriptorInput("header"))
				ns, _ := retainedNamespace(d, 1)
				_, err = f.local.c.db.Exec(`INSERT INTO local_automation_retained_objects(delivery,ordinal,namespace,descriptor)VALUES(?,1,?,?)`, d, ns, raw)
			case "completion":
				_, err = f.local.c.db.Exec(`INSERT INTO local_automation_retained_completions(delivery,evidence_digest,candidate_ref,coverage_digest)VALUES(?,?,?,?)`, d, d, []byte("changed"), d)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err = f.receiver.consumeCurrent(ctx, p); err == nil {
				t.Fatal("ordinary proof omitted retained table dependency")
			}
			if receiverActive(t, f.local.c) != active {
				t.Fatal("dependency refusal changed ACTIVE")
			}
		})
	}
}
