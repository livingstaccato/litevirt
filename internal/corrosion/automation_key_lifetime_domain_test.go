package corrosion

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/litevirt/litevirt/internal/automation/contract"
)

func TestAutomationKeyTransitionStoredLifetimeScalars(t *testing.T) {
	ctx := context.Background()
	for _, n := range []int64{0, 17, 9223372036854775807} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			c := custodyLifetimeFileClient(t, t.TempDir())
			t.Cleanup(func() { _ = c.Close() })
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			if err := custodyLifetimeInsertRecipient(t, c, "reader-domain", "host", n); err != nil {
				t.Fatal(err)
			}
			if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				rows, err := automationKeyRowsTx(ctx, tx, "local_automation_key_recipients", "reader-domain")
				if err == nil && (len(rows) != 1 || rows[0].Int64("host_incarnation") != n) {
					return fmt.Errorf("stored host scalar changed")
				}
				return err
			}); err != nil {
				t.Fatal("valid stored host refused", err)
			}
		})
	}
	for _, tc := range []struct {
		name, column, value, wantType string
	}{
		{"negative", "host_incarnation", "-1", "integer"},
		{"real", "host_incarnation", "17.5", "real"},
		{"overflow", "host_incarnation", "9223372036854775808", "real"},
		{"text", "host_incarnation", "'not-a-number'", "text"},
		{"membership_zero", "membership_generation", "0", "integer"},
		{"first_sequence_zero", "first_sequence", "0", "integer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := custodyLifetimeFileClient(t, t.TempDir())
			t.Cleanup(func() { _ = c.Close() })
			if err := InitSchema(ctx, c); err != nil {
				t.Fatal(err)
			}
			if err := custodyLifetimeInsertRecipient(t, c, "reader-domain", "host", 17); err != nil {
				t.Fatal(err)
			}
			conn, err := c.db.Conn(ctx)
			if err != nil {
				t.Fatal(err)
			}
			// Corrupt scalar negatives only. Restore CHECK enforcement on the
			// same connection before exercising the real typed reader.
			for _, sql := range []string{`PRAGMA ignore_check_constraints=ON`, "UPDATE local_automation_key_recipients SET " + tc.column + "=" + tc.value + " WHERE stage='reader-domain'", `PRAGMA ignore_check_constraints=OFF`} {
				if _, err := conn.ExecContext(ctx, sql); err != nil {
					_ = conn.Close()
					t.Fatal(err)
				}
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			probe, err := c.Query(ctx, "SELECT typeof("+tc.column+") AS kind FROM local_automation_key_recipients WHERE stage='reader-domain'")
			if err != nil || len(probe) != 1 || probe[0].String("kind") != tc.wantType {
				t.Fatal("wrong malformed scalar fixture type", probe, err)
			}
			err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				_, err := automationKeyRowsTx(ctx, tx, "local_automation_key_recipients", "reader-domain")
				return err
			})
			if err == nil || !strings.Contains(err.Error(), "key projection exceeds typed bounds") {
				t.Fatal("malformed scalar was not refused by typed preflight", err)
			}
			// The refusal remains local to the requested reconstruction stage.
			if err := custodyLifetimeInsertRecipient(t, c, "other-stage", "valid-zero", 0); err != nil {
				t.Fatal(err)
			}
			if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				_, err := automationKeyRowsTx(ctx, tx, "local_automation_key_recipients", "other-stage")
				return err
			}); err != nil {
				t.Fatal("unrelated corrupt stage contaminated N0 reader", err)
			}
		})
	}
}

func TestAutomationKeyTransitionStoredLifetimeAt(t *testing.T) {
	ctx := context.Background()
	for _, at := range []string{"2026-10-18T00:00:00.123400Z", "2026-10-18T01:00:00+01:00", "2099-01-01T00:00:00Z"} {
		t.Run(at, func(t *testing.T) {
			voters, _ := custodyLifetimeN0History(t, at)
			projection, err := custodyLifetimeReadProjection(voters[0].c)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, recipient := range projection.KeyTransition.Recipients {
				if recipient.Binding.Host == "a" {
					found = recipient.Binding.HostIncarnation == 0 && recipient.Binding.AdmittedAt == at && recipient.Binding.AdmissionSerial == "a0"
				}
			}
			if !found {
				t.Fatal("stored lifetime was normalized or ordered against recorded/current time")
			}
		})
	}
	for _, tc := range []struct {
		name, at, wantError string
	}{
		{"empty", "", "key projection exceeds typed bounds"},
		{"malformed", "not-a-time", "invalid historical recipient admission timestamp"},
		{"whitespace", " 2026-10-18T00:00:00Z", "invalid historical recipient admission timestamp"},
		{"oversized", "2026-10-18T00:00:00." + strings.Repeat("1", contract.MaxStringBytes) + "Z", "key projection exceeds typed bounds"},
		{"nul", "2026-10-18T00:00:00Z\x00", "invalid historical recipient lifetime"},
		{"invalid_utf8", "2026-10-18T00:00:00Z\xff", "invalid historical recipient lifetime"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			voters, _ := custodyLifetimeN0History(t, "2026-10-18T00:00:00Z")
			a := voters[0]
			if _, err := custodyLifetimeReadProjection(a.c); err != nil {
				t.Fatal("valid N0 baseline did not reconstruct", err)
			}
			before := sharedActiveRows(t, a.c)
			// Only derived projection corruption, never a valid history fixture.
			if err := a.c.execLocal(ctx, `UPDATE local_automation_key_recipients SET admitted_at=? WHERE stage='' AND host='a'`, tc.at); err != nil {
				t.Fatal(err)
			}
			if _, err := custodyLifetimeReadProjection(a.c); err == nil || !strings.Contains(err.Error(), tc.wantError) {
				t.Fatal("invalid stored At was not refused at its proper boundary", err)
			}
			if !reflect.DeepEqual(before, sharedActiveRows(t, a.c)) {
				t.Fatal("stored At refusal changed immutable certified history/receipts")
			}
		})
	}
}

// Historical test signatures/membership are the same existing premise as
// keyActivationHistory; no current enrollment/class/custody authority is issued.
func custodyLifetimeN0History(t *testing.T, at string) ([]*claimTestVoter, AutomationRecord) {
	t.Helper()
	voters := custodyLifetimeHistoricalVoters(t, false)
	a := voters[0]
	genesis := sharedAutomationRecord(t, 1, "", "initialize", "initialize-operation", voters...)
	if _, err := applySharedAutomation(t, a.c, genesis, contract.Reduce, automationFreshAnchor); err != nil {
		t.Fatal(err)
	}
	record := keyActivationRecordFor(t, a, genesis, voters)
	d, err := automationDecision(record.Value)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := contract.DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	assignment.KeyTransition.Recipients[0].HostIncarnation = 0
	assignment.KeyTransition.Recipients[0].AdmittedAt = at
	d.Assignment, err = json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	record = keyCertifiedDecision(t, d, voters...)
	if receipt, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor); err != nil || receipt.Code != "" {
		t.Fatal("valid historical N0 persistence refused", receipt, err)
	}
	return voters, record
}

func custodyLifetimeReadProjection(c *Client) (AutomationProjection, error) {
	ctx := context.Background()
	var projection AutomationProjection
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		head, err := automationHeadTx(ctx, tx)
		if err != nil {
			return err
		}
		request, err := automationLocalKeyLookupTx(ctx, tx, 2)
		if err != nil {
			return err
		}
		projection.Head = head
		return automationResolveKeyProjectionTx(ctx, tx, "", &projection, request, nil)
	})
	return projection, err
}

func custodyLifetimeRotate(t *testing.T, a *claimTestVoter, original AutomationRecord, voters []*claimTestVoter) (AutomationRecord, contract.Receipt) {
	t.Helper()
	d, err := automationDecision(original.Value)
	if err != nil {
		t.Fatal(err)
	}
	body, err := contract.DecodeActivateKeyEpochBody(d.Command)
	if err != nil {
		t.Fatal(err)
	}
	body.RecipientEpoch, body.EqualityEpoch = "recipient-2", "equality-2"
	body.PreviousActivation = 2
	body.Prefix = contract.HistoryReference{Sequence: 2, Digest: original.Value.MustDigest()}
	d.Sequence, d.ParentDigest, d.Command.RequestID = 3, original.Value.MustDigest(), "lifetime-rotation"
	d.Command.Body, err = json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	assignment, err := contract.DecodeAssignment(d)
	if err != nil {
		t.Fatal(err)
	}
	assignment.OperationID = "lifetime-rotation-operation"
	assignment.KeyTransition.Class, assignment.KeyTransition.Bootstrap = "protocol", nil
	for i := range assignment.KeyTransition.Recipients {
		r := &assignment.KeyTransition.Recipients[i]
		r.RecipientEpoch = body.RecipientEpoch
		r.KeyID += "-rotated"
		identity, err := age.GenerateX25519Identity()
		if err != nil {
			t.Fatal(err)
		}
		r.Recipient = identity.Recipient().String()
	}
	d.Assignment, err = json.Marshal(assignment)
	if err != nil {
		t.Fatal(err)
	}
	record := keyCertifiedDecision(t, d, voters...)
	receipt, err := applySharedAutomation(t, a.c, record, contract.Reduce, automationFreshAnchor)
	if err != nil || receipt.Code != "" {
		t.Fatal("historical N0 rotation refused", receipt, err)
	}
	return record, receipt
}
