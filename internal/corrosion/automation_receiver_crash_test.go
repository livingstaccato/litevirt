package corrosion

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
)

// Real SIGKILL of the process holding the SQLite transaction/WAL and PKI file
// lease. This is process-crash evidence, not hardware power-loss simulation.
func TestReceiverPageSIGKILL(t *testing.T) {
	for _, boundary := range []string{"before", "after"} {
		t.Run(boundary, func(t *testing.T) {
			p, r, q, exportCtx, dir := receiverFixture(t)
			ctx := context.Background()
			if _, err := r.Begin(ctx, q.Intent, nil); err != nil {
				t.Fatal(err)
			}
			page, err := p.ExportAutomationSource(exportCtx, q)
			if err != nil {
				t.Fatal(err)
			}
			for name, value := range map[string]any{"receiver-request": q, "receiver-page": page, "receiver-active": receiverActive(t, r.client)} {
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
				cmd := exec.Command(os.Args[0], "-test.run=^TestReceiverProcess$", "-test.timeout=30s")
				cmd.Env = append(os.Environ(), "RECEIVER_DIR="+dir, "RECEIVER_PKI="+r.dir, "RECEIVER_MODE="+mode, "RECEIVER_BOUNDARY="+boundary)
				return cmd
			}
			child := command("stage")
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
					waited = true
				}
			})
			publicationWaitFile(t, filepath.Join(dir, "receiver-paused"))
			if err = child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = child.Wait()
			waited = true
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("receiver process did not die", err, log.String())
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("receiver was not SIGKILLed", err)
			}
			out, err := command("resume").CombinedOutput()
			if err != nil {
				t.Fatalf("fresh receiver process resume: %v\n%s", err, out)
			}
			t.Logf("receiver PID %d SIGKILL %s actual page commit; fresh process verified atomic rows/progress and exact resume", child.Process.Pid, boundary)
		})
	}
}
func TestReceiverProcess(t *testing.T) {
	dir := os.Getenv("RECEIVER_DIR")
	if dir == "" {
		t.Skip("subprocess helper exercised by TestReceiverPageSIGKILL")
	}
	ctx := context.Background()
	c, err := NewLocalClient(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	read := func(name string, out any) {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(raw, out); err != nil {
			t.Fatal(err)
		}
	}
	var q AutomationExportRequest
	var page AutomationExportPage
	var active string
	read("receiver-request", &q)
	read("receiver-page", &page)
	read("receiver-active", &active)
	r := NewAutomationReceiver(c, os.Getenv("RECEIVER_PKI"))
	if _, err = r.Stage(ctx, &AutomationReceiverAttempt{id: "persisted-row"}, "a", q, page); err == nil {
		t.Fatal("stored identity revived process capability")
	}
	a, err := r.Begin(ctx, q.Intent, nil)
	if err != nil {
		t.Fatal("fresh process must reverify current membership and trust", err)
	}
	if os.Getenv("RECEIVER_MODE") == "stage" {
		pause := func() {
			if err := os.WriteFile(filepath.Join(dir, "receiver-paused"), []byte("paused"), 0600); err != nil {
				panic(err)
			}
			select {}
		}
		r.seams = &localCommitSeams{}
		if os.Getenv("RECEIVER_BOUNDARY") == "before" {
			r.seams.beforeCommit = func(*sql.Tx) error { pause(); return nil }
		} else {
			r.seams.afterCommit = pause
		}
	} else {
		expected := int64(0)
		if os.Getenv("RECEIVER_BOUNDARY") == "after" {
			expected = 1
		}
		for _, table := range []string{"records", "pages", "components", "sources"} {
			rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_receiver_`+table)
			if err != nil || len(rows) != 1 || rows[0].Int64("n") != expected {
				t.Fatalf("torn receiver %s after crash: expected %d (%v)", table, expected, err)
			}
		}
	}
	progress, err := r.Stage(ctx, a, "a", q, page)
	if err != nil || progress.Records != 1 || !progress.Terminal || progress.Authenticated {
		t.Fatal("exact pending page resume failed", progress, err)
	}
	retry, err := r.Stage(ctx, a, "a", q, page)
	if err != nil || retry != progress {
		t.Fatal("restart retry double-counted", err)
	}
	if receiverActive(t, c) != active {
		t.Fatal("receiver crash/reopen mutated active state")
	}
}
