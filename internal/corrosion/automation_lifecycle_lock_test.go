package corrosion

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

// The real guard leaves the parent readable but makes before's lifetime read
// fail inside the same SQLite transaction. Rollback must restore even that DDL.
func TestAutomationLifecycleGuardedBeforeFailureReleasesLock(t *testing.T) {
	ctx := context.Background()
	c := lifecycleDB(t)
	c.SetUserIncarnationGate(func() bool { return true })
	c.SetCredentialsSplitGate(func() bool { return true })
	if err := InsertUser(ctx, c, "alice", "operator", "old-hash"); err != nil {
		t.Fatal(err)
	}
	if proof, err := AutomationLifetime(ctx, c, "principal", "alice"); err != nil || proof.Witness == "" {
		t.Fatalf("real birth proof missing: %+v %v", proof, err)
	}
	capture := func(ctx context.Context) ([]byte, error) {
		var state []interface{}
		for _, query := range []string{
			`SELECT * FROM users WHERE username='alice'`,
			`SELECT * FROM user_credentials WHERE username='alice'`,
			`SELECT * FROM local_automation_lifetimes ORDER BY witness`,
			`SELECT * FROM local_automation_credential_issuance ORDER BY kind,credential_id`,
			`SELECT * FROM mutation_log ORDER BY seq`,
		} {
			rows, err := c.Query(ctx, query)
			if err != nil {
				return nil, err
			}
			state = append(state, rows)
		}
		return json.Marshal(state)
	}
	before, err := capture(ctx)
	if err != nil {
		t.Fatal(err)
	}
	guarded := false
	applied, err := c.executeGuardedLifecycleBatch(ctx, func(tx *sql.Tx) (bool, error) {
		if _, err := tx.ExecContext(ctx, `ALTER TABLE local_automation_lifetimes RENAME COLUMN witness TO unavailable_witness`); err != nil {
			return false, err
		}
		parent, err := lifecycleParentTx(ctx, tx, "principal", "alice")
		if err != nil || !parent.exists {
			return false, fmt.Errorf("parent unavailable before callback: %+v %v", parent, err)
		}
		guarded = true
		t.Log("guard passed with a readable real parent and transaction-local lifetime read failure")
		return true, nil
	}, []Statement{{SQL: `UPDATE users SET role='admin' WHERE username='alice'`}}, "principal", "alice", "rotate")
	if !guarded || applied || err == nil || !strings.Contains(err.Error(), "no such column: witness") {
		t.Fatalf("guarded-before failure not returned: guard=%t applied=%t err=%v", guarded, applied, err)
	}
	followCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		after, err := capture(followCtx)
		if err != nil {
			done <- err
			return
		}
		if !bytes.Equal(before, after) {
			done <- fmt.Errorf("before failure changed parent/credential/private observation/log: %s -> %s", before, after)
			return
		}
		if err := UpdateUserPassword(followCtx, c, "alice", "next-hash"); err != nil {
			done <- err
			return
		}
		user, err := GetUser(followCtx, c, "alice")
		if err == nil && user.PasswordHash != "next-hash" {
			err = fmt.Errorf("subsequent client write not visible: %+v", user)
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-followCtx.Done():
		t.Fatal("same-client query/write blocked after guarded-before failure:", followCtx.Err())
	}
}
