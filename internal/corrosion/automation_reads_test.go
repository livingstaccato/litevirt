package corrosion

import (
	"context"
	"database/sql"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/automation/contract"
)

func observeStorageFixture(t *testing.T, disk bool) *Client {
	t.Helper()
	ca, a, b, c := threeVoters(t)
	if disk {
		file, err := NewLocalClient(t.TempDir(), "a")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		if err := InitSchema(context.Background(), file); err != nil {
			t.Fatal(err)
		}
		file.SetVoterConfigGate(func() bool { return true })
		inc, err := file.VoterIncarnation(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		a = &claimTestVoter{name: "a", c: file, signer: a.signer, pki: a.pki, inc: inc}
		adoptHandBuilt(t, 1, membersOf(a, b, c), a)
	}
	v, err := LoadClaimVerifier(ca.pkiDir(t, "observe-storage-verifier"))
	if err != nil {
		t.Fatal(err)
	}
	automationTypedHistoryFixture(t, a, b, c, v)
	return a.c
}

func TestAutomationObserveStorageCertifiedFrontier(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	got, found, err := c.AutomationObserve(ctx, "established-cluster", "resource-uid", 11)
	want := contract.View{ClusterUID: "established-cluster", ResourceUID: "resource-uid", Name: "machine", DomainUUID: "domain-uuid", Generation: 1, ResourceRevision: "new-opaque-resource-uid", AppliedSequence: 12}
	if err != nil || !found || got != want {
		t.Fatalf("certified resource = %+v %v %v; want %+v", got, found, err, want)
	}
	if got, found, err := c.AutomationObserve(ctx, "established-cluster", "never-enrolled", 12); err != nil || found || got != (contract.View{}) {
		t.Fatalf("complete certified absence = %+v %v %v", got, found, err)
	}
	for _, tc := range []struct {
		cluster string
		minimum uint64
	}{{"other-cluster", 12}, {"established-cluster", 13}} {
		if _, found, err := c.AutomationObserve(ctx, tc.cluster, "never-enrolled", tc.minimum); found || contract.Code(err) != contract.CodeUnavailable {
			t.Fatalf("unmet certified context %+v became absence: found=%v err=%v", tc, found, err)
		}
	}
	// The view owns only scalar copies, and current ownership must not rewrite
	// the historical create's immutable revision or operation evidence.
	got.Name = "caller mutation"
	original, found, err := c.AutomationOperation(ctx, "create-op")
	if err != nil || !found || original.ResourceUID != "resource-uid" || original.ResourceRevision != "rev:opaque-alpha" || original.Sequence != 7 {
		t.Fatalf("read changed original create evidence: %+v %v %v", original, found, err)
	}
	again, found, err := c.AutomationObserve(ctx, "established-cluster", "resource-uid", 12)
	if err != nil || !found || again != want {
		t.Fatalf("caller mutation escaped copied view: %+v %v %v", again, found, err)
	}
	// Scalar mapping fixture only: there is no fresh retirement producer in
	// this component. Roll back the coherent retired projection variation.
	rollback := errors.New("rollback retired scalar fixture")
	err = c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, table := range []string{"local_automation_resources", "local_automation_identities"} {
			if _, err := tx.Exec(ctx, "UPDATE "+table+" SET retired=1 WHERE stage='' AND uid='resource-uid'"); err != nil {
				return err
			}
		}
		view, found, err := automationObserveTx(ctx, tx, "established-cluster", "resource-uid", 12)
		if err != nil || !found || !view.Retired || view.ResourceRevision != "new-opaque-resource-uid" {
			return errors.New("retired scalar projection was not copied")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
}

func TestAutomationObserveStorageRejectsPartialAndCorruptProjection(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	for _, tc := range []struct {
		name, sql string
		args      []any
	}{
		{"missing-resource", `DELETE FROM local_automation_resources WHERE stage='' AND uid='resource-uid'`, nil},
		{"missing-semantic-frontier", `DELETE FROM local_automation_semantic_heads WHERE stage=''`, nil},
		{"partial-semantic-frontier", `UPDATE local_automation_semantic_heads SET sequence=11 WHERE stage=''`, nil},
		{"fractional-prefix", `UPDATE local_automation_prefix SET sequence=? WHERE id=1`, []any{12.5}},
		{"fractional-semantic-frontier", `UPDATE local_automation_semantic_heads SET sequence=? WHERE stage=''`, []any{12.5}},
		{"wrong-resource-cluster", `UPDATE local_automation_resources SET cluster_uid='other' WHERE uid='resource-uid'`, nil},
		{"wrong-project-context", `UPDATE local_automation_resources SET project_uid='other' WHERE uid='resource-uid'`, nil},
		{"missing-vm-identity", `DELETE FROM local_automation_identities WHERE uid='resource-uid'`, nil},
		{"identity-context-drift", `UPDATE local_automation_identities SET alias='another-name' WHERE uid='resource-uid'`, nil},
		{"empty-identity-witness", `UPDATE local_automation_identities SET witness='' WHERE uid='resource-uid'`, nil},
		{"oversized-identity-witness", `UPDATE local_automation_identities SET witness=? WHERE uid='resource-uid'`, []any{strings.Repeat("w", contract.MaxStringBytes+1)}},
		{"invalid-utf8-identity-witness", `UPDATE local_automation_identities SET witness=? WHERE uid='resource-uid'`, []any{string([]byte{0xff})}},
		{"nul-identity-witness", `UPDATE local_automation_identities SET witness=? WHERE uid='resource-uid'`, []any{"witness\x00suffix"}},
		{"future-resource-sequence", `UPDATE local_automation_resources SET applied_sequence=13 WHERE uid='resource-uid'`, nil},
		{"fractional-resource-sequence", `UPDATE local_automation_resources SET applied_sequence=? WHERE uid='resource-uid'`, []any{10.5}},
		{"fractional-generation", `UPDATE local_automation_resources SET binding_generation=? WHERE uid='resource-uid'`, []any{1.5}},
		{"text-generation", `UPDATE local_automation_resources SET binding_generation='not-an-integer' WHERE uid='resource-uid'`, nil},
		{"ownership-generation-drift", `UPDATE local_automation_resources SET binding_generation=0 WHERE uid='resource-uid'`, nil},
		{"retired-context-drift", `UPDATE local_automation_resources SET retired=1 WHERE uid='resource-uid'`, nil},
		{"oversized-name", `UPDATE local_automation_resources SET name=? WHERE uid='resource-uid'`, []any{strings.Repeat("n", contract.MaxStringBytes+1)}},
		{"blob-name", `UPDATE local_automation_resources SET name=? WHERE uid='resource-uid'`, []any{[]byte("machine")}},
		{"invalid-utf8", `UPDATE local_automation_resources SET name=? WHERE uid='resource-uid'`, []any{string([]byte{0xff})}},
		{"nul-domain", `UPDATE local_automation_resources SET domain_uuid=? WHERE uid='resource-uid'`, []any{"domain\x00suffix"}},
		{"missing-operation", `UPDATE local_automation_resources SET last_operation_id='' WHERE uid='resource-uid'`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rollback := errors.New("rollback corruption fixture")
			var readErr error
			var found bool
			err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
				if _, err := tx.Exec(ctx, tc.sql, tc.args...); err != nil {
					return err
				}
				if strings.HasPrefix(tc.name, "fractional-") {
					var probe string
					switch tc.name {
					case "fractional-prefix":
						probe = `SELECT typeof(sequence) AS storage FROM local_automation_prefix WHERE id=1`
					case "fractional-semantic-frontier":
						probe = `SELECT typeof(sequence) AS storage FROM local_automation_semantic_heads WHERE stage=''`
					case "fractional-resource-sequence":
						probe = `SELECT typeof(applied_sequence) AS storage FROM local_automation_resources WHERE uid='resource-uid'`
					case "fractional-generation":
						probe = `SELECT typeof(binding_generation) AS storage FROM local_automation_resources WHERE uid='resource-uid'`
					}
					rows, err := tx.Query(ctx, probe)
					if err != nil || len(rows) != 1 || rows[0].String("storage") != "real" {
						return errors.New("fractional fixture did not store an actual SQL REAL")
					}
				}
				_, found, readErr = automationObserveTx(ctx, tx, "established-cluster", "resource-uid", 12)
				return rollback
			})
			if !errors.Is(err, rollback) {
				t.Fatalf("corruption fixture did not reach guarded reader: %v", err)
			}
			if readErr == nil || found {
				t.Fatalf("corrupt/partial projection became a resource or absence: found=%v err=%v", found, readErr)
			}
		})
	}
	// Both matching counters can lie about cluster identity; authenticated
	// retained history must still prevent that from becoming absence.
	rollback := errors.New("rollback contradictory context")
	err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		for _, table := range []string{"local_automation_prefix", "local_automation_semantic_heads"} {
			if _, err := tx.Exec(ctx, "UPDATE "+table+" SET cluster_uid='other-cluster'"); err != nil {
				return err
			}
		}
		if _, found, err := automationObserveTx(ctx, tx, "other-cluster", "never-enrolled", 12); err == nil || found {
			return errors.New("matching forged projection heads became absence")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
}

func TestAutomationObserveStorageResetSerialization(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	readHeld, releaseRead := make(chan struct{}), make(chan struct{})
	readDone, resetDone := make(chan error, 1), make(chan error, 1)
	go func() {
		readDone <- c.executeLocal(ctx, func(tx *LocalTx) error {
			view, found, err := automationObserveTx(ctx, tx, "established-cluster", "resource-uid", 12)
			if err != nil || !found || view.ResourceUID != "resource-uid" {
				return errors.New("complete read lost resource before reset")
			}
			return nil
		}, &localCommitSeams{beforeCommit: func(*sql.Tx) error {
			close(readHeld)
			select {
			case <-releaseRead:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}})
	}()
	select {
	case <-readHeld:
	case err := <-readDone:
		t.Fatalf("reader failed before transaction seam: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	go func() {
		resetDone <- c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") })
	}()
	select {
	case err := <-resetDone:
		close(releaseRead)
		t.Fatalf("reset interleaved with certified read transaction: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseRead)
	if err := <-readDone; err != nil {
		t.Fatal(err)
	}
	if err := <-resetDone; err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.AutomationObserve(ctx, "established-cluster", "resource-uid", 12); found || contract.Code(err) != contract.CodeUnavailable {
		t.Fatalf("actual semantic reset became authoritative absence: found=%v err=%v", found, err)
	}
	if err := c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.AutomationObserve(ctx, "established-cluster", "resource-uid", 12); err != nil || !found {
		t.Fatalf("actual replay did not restore read: found=%v err=%v", found, err)
	}
}

func TestAutomationObserveStoragePartialReplayAndRollback(t *testing.T) {
	c := observeStorageFixture(t, false)
	ctx := context.Background()
	abort := errors.New("abort semantic reset")
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error {
		if err := automationResetSemanticProjectionTx(ctx, tx, ""); err != nil {
			return err
		}
		return abort
	}); !errors.Is(err, abort) {
		t.Fatal(err)
	}
	if _, found, err := c.AutomationObserve(ctx, "established-cluster", "resource-uid", 12); err != nil || !found {
		t.Fatalf("rolled-back reset lost authoritative resource: %v %v", found, err)
	}
	if err := c.ExecuteLocal(ctx, func(tx *LocalTx) error { return automationResetSemanticProjectionTx(ctx, tx, "") }); err != nil {
		t.Fatal(err)
	}
	if err := c.AutomationReplay(ctx, contract.Reduce, 1); err == nil {
		t.Fatal("one-decision replay unexpectedly reconstructed twelve decisions")
	}
	if _, found, err := c.AutomationObserve(ctx, "established-cluster", "never-enrolled", 12); found || contract.Code(err) != contract.CodeUnavailable {
		t.Fatalf("actual partial reconstruction became absence: %v %v", found, err)
	}
	if err := c.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal(err)
	}
	if _, found, err := c.AutomationObserve(ctx, "established-cluster", "resource-uid", 12); err != nil || !found {
		t.Fatalf("resumed actual reconstruction lost resource: %v %v", found, err)
	}
}

func TestAutomationObserveStorageReopenAndErrors(t *testing.T) {
	c := observeStorageFixture(t, true)
	ctx := context.Background()
	// The accepted migration deliberately records separate source-witness and
	// runtime-incarnation facts. Neither close/reopen nor Observe may equate them.
	checkLegacy := func(c *Client) {
		t.Helper()
		rows, err := c.Query(ctx, `SELECT i.witness,r.incarnation FROM local_automation_identities i JOIN local_automation_resources r ON r.stage=i.stage AND r.uid=i.uid WHERE i.stage='' AND i.uid='legacy-uid'`)
		if err != nil || len(rows) != 1 || rows[0].String("witness") != "positive-legacy-witness" || rows[0].String("incarnation") != "legacy-incarnation" {
			t.Fatalf("recorded independent legacy facts changed: %+v %v", rows, err)
		}
		want := contract.View{ClusterUID: "established-cluster", ResourceUID: "legacy-uid", Name: "legacy-machine", DomainUUID: "legacy-domain", ResourceRevision: "new-opaque-legacy-uid", Generation: 1, AppliedSequence: 12}
		view, found, err := c.AutomationObserve(ctx, "established-cluster", "legacy-uid", 12)
		if err != nil || !found || view != want {
			t.Fatalf("independent legacy facts were not observed: %+v %v %v; want %+v", view, found, err, want)
		}
	}
	checkLegacy(c)
	beforeHistory, beforeTyped := sharedActiveRows(t, c), automationTypedSnapshot(t, c)
	dir := c.dataDir
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, reopened)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, reopened)) {
		t.Fatal("close/reopen changed actual retained history/anchors/receipts or typed projections")
	}
	if err := reopened.AutomationReplay(ctx, contract.Reduce, 256); err != nil {
		t.Fatal("reopened retained anchors did not support actual local replay", err)
	}
	if !reflect.DeepEqual(beforeHistory, sharedActiveRows(t, reopened)) || !reflect.DeepEqual(beforeTyped, automationTypedSnapshot(t, reopened)) {
		t.Fatal("reopened replay changed original certified history or typed facts")
	}
	checkLegacy(reopened)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, found, err := reopened.AutomationObserve(canceled, "established-cluster", "never-enrolled", 12); found || !errors.Is(err, context.Canceled) {
		t.Fatalf("context error became absence/classification loss: %v %v", found, err)
	}
	if _, err := reopened.db.Exec(`ALTER TABLE local_automation_resources RENAME TO local_automation_resources_hidden`); err != nil {
		t.Fatal(err)
	}
	if _, found, err := reopened.AutomationObserve(ctx, "established-cluster", "never-enrolled", 12); found || err == nil || !strings.Contains(err.Error(), "local_automation_resources") || contract.Code(err) != "" {
		t.Fatalf("SQL error became absence or lost original cause: %v %v", found, err)
	}
}
