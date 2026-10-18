package corrosion

import (
	"context"
	"database/sql"
	"strings"
	"testing"
)

func TestReceiverCurrentPreservesActualLocalFrameBound(t *testing.T) {
	ctx := context.Background()
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Continuing: true, BeforeFreeze: func(t *testing.T, _ []*claimTestVoter, local *claimTestVoter) {
		key := workloadKey()
		payload := maxAutomationCutRecordBytes - (64 << 10)
		for round := uint64(2); round <= 3; round++ {
			value := workloadValue(strings.Repeat("x", payload), local.name, "ghost")
			reply, err := local.c.ClaimAccept(ctx, key, testBallot(round, local.name), value, 1, local.signer, unreachable)
			if err != nil || !reply.Accepted {
				t.Fatal("genuine native near-bound acceptance", err)
			}
			rows, err := local.c.Query(ctx, "SELECT "+automationCutSections[0].columns+" FROM local_recovery_claims WHERE target_kind=? AND target_name=? AND owner_epoch=? AND attempt=?", key.TargetKind, key.TargetName, key.OwnerEpoch, key.Attempt)
			if err != nil || len(rows) != 1 {
				t.Fatal(rows, err)
			}
			raw, err := encodeAutomationCutRecord(automationCutSections[0].name, 1, rows[0])
			if err != nil {
				t.Fatal(err)
			}
			if round == 3 && (len(raw) < maxAutomationCutRecordBytes-128 || len(raw) > maxAutomationCutRecordBytes) {
				t.Fatal("native boundary not exercised", len(raw))
			}
			payload += maxAutomationCutRecordBytes - 32 - len(raw)
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	if _, err := f.receiver.auditAggregate(ctx, f.attempt); err != nil {
		t.Fatal("actual C rejected legal local original", err)
	}
	rows, err := f.local.c.Query(ctx, `SELECT MAX(length(record)) AS n FROM local_automation_local_rows`)
	if err != nil || len(rows) != 1 || rows[0].Int64("n") <= maxAutomationCutRecordBytes || rows[0].Int64("n") > maxAggregateLocalRecordBytes {
		t.Fatal("actual legal local overhead not exercised", rows, err)
	}
	t.Logf("actual C local frame=%d native=%d local=%d", rows[0].Int64("n"), maxAutomationCutRecordBytes, maxAggregateLocalRecordBytes)
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	if err != nil {
		t.Fatal("current proof narrowed accepted local bound", err)
	}
	if err = f.receiver.consumeCurrent(ctx, p); err != nil {
		t.Fatal("consume narrowed accepted local bound", err)
	}
	for _, local := range []bool{true, false} {
		p, err = f.receiver.VerifyCurrent(ctx, f.attempt)
		if err != nil {
			t.Fatal(err)
		}
		reached := false
		f.receiver.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
			reached = true
			if local {
				_, err := tx.Exec(`UPDATE local_automation_local_rows SET record=zeroblob(?)`, maxAggregateLocalRecordBytes+1)
				return err
			}
			_, err := tx.Exec(`UPDATE local_automation_receiver_records SET record=zeroblob(?)`, maxAutomationCutRecordBytes+1)
			return err
		}}
		err = f.receiver.consumeCurrent(ctx, p)
		f.receiver.seams = nil
		if !reached || err == nil || !strings.Contains(err.Error(), "bound") {
			t.Fatal("exact local/public over-bound refusal missing", local, reached, err)
		}
	}
}
