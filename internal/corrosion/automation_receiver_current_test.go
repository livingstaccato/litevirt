package corrosion

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func TestReceiverCurrentExactJobRevision(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	if _, err := f.receiver.auditAggregate(ctx, f.attempt); err != nil {
		t.Fatal(err)
	}
	if _, err := f.local.c.db.ExecContext(ctx, `UPDATE local_automation_receiver_jobs SET revision=revision+1 WHERE id=?`, f.attempt.id); err != nil {
		t.Fatal(err)
	}
	cap, err := f.attempt.view.ValidateServedHost(ctx, f.attempt.pair)
	if err != nil {
		t.Fatal(err)
	}
	defer cap.Discard()
	lease, err := pki.AcquireHostCertificateLease(ctx, f.local.pki, cap)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	err = f.receiver.transaction(ctx, f.attempt, lease, time.Time{}, func(tx *LocalTx) error { return f.receiver.currentTx(ctx, tx, f.attempt) })
	if err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("changed original job/revision with unchanged binding must refuse; got %v", err)
	}
}

func TestReceiverCurrentFirstProof(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	if _, err := f.receiver.auditAggregate(ctx, f.attempt); err != nil {
		t.Fatal(err)
	}
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil || p == nil {
		t.Fatalf("actual complete B/C evidence did not issue current proof: %v", err)
	}
	p.Discard()
}

func TestReceiverCurrentProofOwnership(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, Continuing: true, LocalHead: 3, BeforeFreeze: currentNativeClaim})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
	fresh := func() *AutomationCurrentProof {
		t.Helper()
		p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := fresh()
	copied := *p
	if err := f.receiver.consumeCurrent(ctx, &copied); err == nil {
		t.Fatal("copied proof accepted")
	}
	if err := f.receiver.consumeCurrent(ctx, &AutomationCurrentProof{}); err == nil {
		t.Fatal("zero proof accepted")
	}
	foreign := NewAutomationReceiver(f.local.c, f.local.pki)
	if err := foreign.consumeCurrent(ctx, p); err == nil {
		t.Fatal("foreign owner accepted")
	}
	if err := f.receiver.consumeCurrent(ctx, p); err != nil {
		t.Fatal("genuine current proof failed", err)
	}
	if err := f.receiver.consumeCurrent(ctx, p); err == nil {
		t.Fatal("consumed proof revived")
	}
	p = fresh()
	p.Discard()
	if err := f.receiver.consumeCurrent(ctx, p); err == nil {
		t.Fatal("discarded proof revived")
	}
	p = fresh()
	f.receiver.Close()
	if err := f.receiver.consumeCurrent(ctx, p); err == nil {
		t.Fatal("closed owner accepted")
	}
	if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
		t.Fatal("current proof changed active/spool state")
	}
}

func TestReceiverCurrentFullDependencyMutation(t *testing.T) {
	for _, query := range []string{
		`UPDATE local_automation_prefix SET digest='changed'`,
		`UPDATE local_recovery_claims SET updated_at='changed'`,
		`UPDATE local_automation_receiver_components SET terminal=0 WHERE component=11`,
		`UPDATE local_automation_aggregate_maxima SET promise_ref=x'00'`,
		`UPDATE local_automation_aggregates SET roster=x'00'`,
		`DELETE FROM local_automation_local_rows WHERE section=0`,
	} {
		t.Run(query, func(t *testing.T) {
			ctx := context.Background()
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, Continuing: true, LocalHead: 3, BeforeFreeze: currentNativeClaim})
			for i := range f.producers {
				f.stage(t, i, 11, true)
			}
			p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
			if err != nil {
				t.Fatal(err)
			}
			result, err := f.local.c.db.ExecContext(ctx, query)
			if err != nil {
				t.Fatal(err)
			}
			n, err := result.RowsAffected()
			if err != nil || n == 0 {
				t.Fatal("mutation did not reach actual dependency", n, err)
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			if err = f.receiver.consumeCurrent(ctx, p); err == nil || !strings.Contains(err.Error(), "binding changed") {
				t.Fatalf("complete dependency mutation accepted or wrong refusal: %v", err)
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("refusal mutated state")
			}
		})
	}
}

func currentNativeClaim(t *testing.T, voters []*claimTestVoter, local *claimTestVoter) {
	t.Helper()
	key := LeaseTermClaimKey("current_proof_native", 1)
	value := ClaimValue{LeaseTerm: &LeaseTermValue{Key: key.TargetName, Term: 1, Holder: local.name}}
	for i, v := range voters {
		reply, err := v.c.ClaimAccept(context.Background(), key, testBallot(uint64(i+2), v.name), value, 1, v.signer, unreachable)
		if err != nil || !reply.Accepted {
			t.Fatalf("native original claim missing: %+v %v", reply, err)
		}
	}
}
