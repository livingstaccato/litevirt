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

// Real file-backed SQLite/WAL and PKI lease process death; this does not claim
// hardware power-loss evidence or a successfully adopted donor.
func TestRetainedPageSIGKILL(t *testing.T) {
	if dir := os.Getenv("RETAINED_CRASH_DIR"); dir != "" {
		retainedCrashChild(t, dir)
		return
	}
	for _, boundary := range []string{"before", "after"} {
		t.Run(boundary, func(t *testing.T) {
			_, r, q, _, dir := receiverFixture(t)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			envelope, entries := retainedPendingPages(t, a)
			input := struct {
				Intent   AutomationSourceRequest
				Envelope []byte
				Entries  [][]byte
				Active   string
			}{q.Intent, envelope, entries, receiverActive(t, r.client)}
			raw, _ := json.Marshal(input)
			if err = os.WriteFile(filepath.Join(dir, "retained-input"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = r.client.Close(); err != nil {
				t.Fatal(err)
			}
			command := func(mode string) *exec.Cmd {
				cmd := exec.Command(os.Args[0], "-test.run=^TestRetainedPageSIGKILL$", "-test.timeout=45s")
				cmd.Env = append(os.Environ(), "RETAINED_CRASH_DIR="+dir, "RETAINED_CRASH_PKI="+r.dir, "RETAINED_CRASH_MODE="+mode, "RETAINED_CRASH_BOUNDARY="+boundary)
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
				}
			})
			publicationWaitFile(t, filepath.Join(dir, "retained-paused"))
			if err = child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = child.Wait()
			waited = true
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatal("retained child did not die", err, log.String())
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("not actual SIGKILL", err)
			}
			output, err := command("resume").CombinedOutput()
			if err != nil {
				t.Fatalf("fresh retained process resume: %v\n%s", err, output)
			}
			t.Logf("retained PID %d SIGKILL %s real FULL commit; fresh process reauthenticated, verified atomic pins/frames/progress and exact retry/resume", child.Process.Pid, boundary)
		})
	}
}
func retainedCrashChild(t *testing.T, dir string) {
	ctx := context.Background()
	c, err := NewLocalClient(dir, "b")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err = InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	var input struct {
		Intent   AutomationSourceRequest
		Envelope []byte
		Entries  [][]byte
		Active   string
	}
	raw, err := os.ReadFile(filepath.Join(dir, "retained-input"))
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	r := NewAutomationReceiver(c, os.Getenv("RETAINED_CRASH_PKI"))
	defer r.Close()
	first := retainedPage{Object: 0, Component: 0, Records: input.Entries[:2]}
	if _, err = r.stageRetained(ctx, &AutomationReceiverAttempt{id: "persisted"}, input.Envelope, first); err == nil {
		t.Fatal("disk rows revived process attempt")
	}
	a, err := r.Begin(ctx, input.Intent, nil)
	if err != nil {
		t.Fatal("fresh reauthorization", err)
	}
	if os.Getenv("RETAINED_CRASH_MODE") == "stage" {
		pause := func() {
			if err := os.WriteFile(filepath.Join(dir, "retained-paused"), []byte("paused"), 0600); err != nil {
				panic(err)
			}
			select {}
		}
		r.seams = &localCommitSeams{}
		if os.Getenv("RETAINED_CRASH_BOUNDARY") == "before" {
			r.seams.beforeCommit = func(*sql.Tx) error { pause(); return nil }
		} else {
			r.seams.afterCommit = pause
		}
	} else {
		multiplier := int64(0)
		if os.Getenv("RETAINED_CRASH_BOUNDARY") == "after" {
			multiplier = 1
		}
		for table, count := range map[string]int64{"local_automation_retained_deliveries": 1, "local_automation_retained_objects": 2, "local_automation_retained_completions": 0, "local_automation_receiver_records": 2, "local_automation_receiver_components": 1, "local_automation_receiver_pages": 1} {
			rows, e := c.Query(ctx, `SELECT COUNT(*) AS n FROM `+table)
			if e != nil || len(rows) != 1 || rows[0].Int64("n") != count*multiplier {
				t.Fatal("torn retained commit", table, rows, e)
			}
		}
	}
	progress, err := r.stageRetained(ctx, a, input.Envelope, first)
	if err != nil || progress.Records != 2 || progress.Terminal {
		t.Fatal("exact pending resume", progress, err)
	}
	retry, err := r.stageRetained(ctx, a, input.Envelope, first)
	if err != nil || retry != progress {
		t.Fatal("exact process retry", err)
	}
	terminal, err := r.stageRetained(ctx, a, input.Envelope, retainedPage{Object: 0, Component: 0, Position: 2, Records: input.Entries[2:], Terminal: true})
	if err != nil || !terminal.Terminal || terminal.Records != 4 {
		t.Fatal("subsequent resume", err)
	}
	if receiverActive(t, c) != input.Active {
		t.Fatal("retained crash changed ACTIVE")
	}
}

func TestRetainedPageAtomicGuards(t *testing.T) {
	for _, mode := range []string{"progress-sql", "cancel", "failed-commit", "not-full", "selection"} {
		t.Run(mode, func(t *testing.T) {
			_, r, q, _, _ := receiverFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			raw, entries := retainedPendingPages(t, a)
			active := receiverActive(t, r.client)
			stored := receiverStored(t, r.client)
			switch mode {
			case "progress-sql":
				_, err = r.client.db.Exec(`CREATE TRIGGER retained_page_fail BEFORE INSERT ON local_automation_receiver_components BEGIN SELECT RAISE(ABORT,'retained progress failure');END`)
			case "cancel":
				r.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { cancel(); return nil }}
			case "failed-commit":
				r.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error { return tx.Rollback() }}
			case "not-full":
				_, err = r.client.db.Exec(`PRAGMA synchronous=NORMAL`)
			case "selection":
				r.seams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
					_, err := tx.Exec(`UPDATE local_automation_receiver_current SET attempt='changed'`)
					return err
				}}
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.stageRetained(ctx, a, raw, retainedPage{Object: 0, Component: 0, Records: entries[:2]}); err == nil {
				t.Fatal("failed retained final guard committed")
			}
			r.seams = nil
			if receiverStored(t, r.client) != stored || receiverActive(t, r.client) != active {
				t.Fatal("failed FULL retained page changed rows")
			}
			for _, table := range []string{"local_automation_retained_deliveries", "local_automation_retained_objects", "local_automation_retained_completions"} {
				rows, e := r.client.Query(context.Background(), `SELECT COUNT(*) AS n FROM `+table)
				if e != nil || rows[0].Int64("n") != 0 {
					t.Fatal("failed FULL retained page left pin", table, e)
				}
			}
		})
	}
}
