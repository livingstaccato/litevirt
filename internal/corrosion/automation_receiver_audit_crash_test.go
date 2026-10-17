package corrosion

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Actual process death while the audit owns SQLite FULL and the real PKI file
// lease. This supplements the unchanged page-ingress SIGKILL evidence; neither
// test claims hardware power-loss simulation.
func TestReceiverSourceAuditSIGKILL(t *testing.T) {
	for _, boundary := range []string{"before", "after"} {
		t.Run(boundary, func(t *testing.T) {
			p, r, q, peer, dir := receiverAuditFixture(t, 3, nil)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, p, r, a, q, peer, 11)
			for name, value := range map[string]any{"audit-request": q, "audit-active": receiverActive(t, r.client), "audit-spool": receiverStored(t, r.client)} {
				raw, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(filepath.Join(dir, name), raw, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err = r.client.Close(); err != nil {
				t.Fatal(err)
			}
			command := func(mode string) *exec.Cmd {
				cmd := exec.Command(os.Args[0], "-test.run=^TestReceiverSourceAuditProcess$", "-test.timeout=45s")
				cmd.Env = append(os.Environ(), "RECEIVER_AUDIT_DIR="+dir, "RECEIVER_AUDIT_PKI="+r.dir, "RECEIVER_AUDIT_MODE="+mode, "RECEIVER_AUDIT_BOUNDARY="+boundary)
				return cmd
			}
			child := command("audit")
			var log bytes.Buffer
			child.Stdout = &log
			child.Stderr = &log
			if err = child.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			t.Cleanup(func() {
				if !waited {
					child.Process.Kill()
					child.Wait()
				}
			})
			publicationWaitFile(t, filepath.Join(dir, "audit-paused"))
			if err = child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = child.Wait()
			waited = true
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("audit child did not die", err, log.String())
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not actual SIGKILL", err)
			}
			out, err := command("resume").CombinedOutput()
			if err != nil {
				t.Fatalf("fresh audit process resume: %v\n%s", err, out)
			}
			t.Logf("audit PID %d killed %s actual FULL commit; fresh process checked atomic result/refs/causal rows, unchanged spool/ACTIVE, current reauthorization and exact retry", child.Process.Pid, boundary)
		})
	}
}
func TestReceiverSourceAuditProcess(t *testing.T) {
	dir := os.Getenv("RECEIVER_AUDIT_DIR")
	if dir == "" {
		t.Skip("subprocess helper exercised by TestReceiverSourceAuditSIGKILL")
	}
	ctx := context.Background()
	client, err := NewLocalClient(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetVoterConfigGate(func() bool { return true })
	read := func(name string, out any) {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	var q AutomationExportRequest
	var active, spool string
	read("audit-request", &q)
	read("audit-active", &active)
	read("audit-spool", &spool)
	r := NewAutomationReceiver(client, os.Getenv("RECEIVER_AUDIT_PKI"))
	if err = r.AuditSource(ctx, &AutomationReceiverAttempt{id: "persisted-row"}, "a"); err == nil {
		t.Fatal("durable audit identity revived process authority")
	}
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal(err)
	}
	if os.Getenv("RECEIVER_AUDIT_MODE") == "audit" {
		pause := func() {
			if err := os.WriteFile(filepath.Join(dir, "audit-paused"), []byte("paused"), 0600); err != nil {
				panic(err)
			}
			select {}
		}
		r.seams = &localCommitSeams{}
		r.seams.beforeCommit = func(tx *sql.Tx) error {
			expected := receiverAuditCrashInventory(t, tx.QueryContext)
			raw, err := json.Marshal(expected)
			if err != nil {
				return err
			}
			if err = os.WriteFile(filepath.Join(dir, "audit-expected"), raw, 0600); err != nil {
				return err
			}
			if os.Getenv("RECEIVER_AUDIT_BOUNDARY") == "before" {
				pause()
			}
			return nil
		}
		if os.Getenv("RECEIVER_AUDIT_BOUNDARY") == "after" {
			r.seams.afterCommit = pause
		}
	} else {
		after := os.Getenv("RECEIVER_AUDIT_BOUNDARY") == "after"
		var expected []receiverAuditCrashTable
		read("audit-expected", &expected)
		actual := receiverAuditCrashInventory(t, client.db.QueryContext)
		if len(expected) != len(actual) {
			t.Fatal("missing pending audit inventory")
		}
		for i, table := range actual {
			if expected[i].Rows == 0 || (after && table != expected[i]) || (!after && table.Rows != 0) {
				t.Fatal("torn audit transaction before retry", table, expected[i])
			}
		}
		if receiverActive(t, client) != active || receiverStored(t, client) != spool {
			t.Fatal("crash altered active/original evidence")
		}
	}
	if err = r.AuditSource(ctx, a, "a"); err != nil {
		t.Fatal(err)
	}
	derived := receiverAudited(t, client)
	if err = r.AuditSource(ctx, a, "a"); err != nil || receiverAudited(t, client) != derived {
		t.Fatal("exact audited restart retry differs", err)
	}
	if receiverActive(t, client) != active || receiverStored(t, client) != spool {
		t.Fatal("audit resume changed ACTIVE or original source spool")
	}
}

// Stream the small fixture's exact pending contents rather than accepting merely
// nonempty tables. The independent process compares these before any re-audit.
type receiverAuditCrashTable struct {
	Name   string
	Rows   int
	Digest string
}

func receiverAuditCrashInventory(t *testing.T, query func(context.Context, string, ...any) (*sql.Rows, error)) []receiverAuditCrashTable {
	t.Helper()
	var result []receiverAuditCrashTable
	for _, table := range []string{"audits", "refs", "requests"} {
		rows, err := query(context.Background(), `SELECT * FROM local_automation_receiver_`+table+` ORDER BY rowid`)
		if err != nil {
			t.Fatal(err)
		}
		cols, err := rows.Columns()
		if err != nil {
			rows.Close()
			t.Fatal(err)
		}
		entry := receiverAuditCrashTable{Name: table}
		h := sha256.New()
		for rows.Next() {
			values := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range values {
				ptrs[i] = &values[i]
			}
			if err = rows.Scan(ptrs...); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			raw, err := json.Marshal(values)
			if err != nil {
				rows.Close()
				t.Fatal(err)
			}
			sourceHash(h, raw)
			entry.Rows++
			if entry.Rows > 1000 {
				rows.Close()
				t.Fatal("crash fixture inventory unexpectedly large")
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			t.Fatal(err)
		}
		entry.Digest = hex.EncodeToString(h.Sum(nil))
		result = append(result, entry)
	}
	return result
}
