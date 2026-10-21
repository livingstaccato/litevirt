package opjournal

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"testing/synctest"
	"time"
)

// A filename is not operation authority: op:bound aliases op_bound after
// sanitization. Removing the stored identity comparison must break these tests.
func executionIdentityFixture(t *testing.T) (*Journal, string, []byte) {
	t.Helper()
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	owner := Entry{OperationID: "op_bound", OwnerEpoch: 2, SpecGeneration: 5,
		ResourceID: "original-vm", Kind: "restart", Stage: "journaled",
		Artifacts: map[string]string{"old_domain_xml": "<original/>"}, CreatedAt: "2026-07-14T00:00:00Z"}
	if err := j.Write(owner); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "op_bound.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return j, path, original
}

func TestExecutionJournalReadRejectsFilenameAlias(t *testing.T) {
	j, path, original := executionIdentityFixture(t)
	got, _, err := j.Read("op:bound")
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err == nil || got != nil || !bytes.Equal(after, original) {
		t.Fatal("JOURNAL_READ_ALIAS: a different operation identity accessed the retained owner")
	}
}

func TestExecutionJournalWriteRejectsFilenameAlias(t *testing.T) {
	j, path, original := executionIdentityFixture(t)
	err := j.Write(Entry{OperationID: "op:bound", OwnerEpoch: 99, SpecGeneration: 99,
		ResourceID: "successor-vm", Kind: "restart", Stage: "journaled",
		Artifacts: map[string]string{"old_domain_xml": "<successor/>"}, CreatedAt: "2026-07-15T00:00:00Z"})
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if err == nil || !bytes.Equal(after, original) {
		t.Fatal("JOURNAL_WRITE_ALIAS: a different operation identity overwrote the retained owner")
	}
}

func TestExecutionJournalRemoveRejectsFilenameAlias(t *testing.T) {
	j, path, original := executionIdentityFixture(t)
	err := j.Remove("op:bound")
	after, readErr := os.ReadFile(path)
	if err == nil || readErr != nil || !bytes.Equal(after, original) {
		t.Fatal("JOURNAL_REMOVE_ALIAS: a different operation identity deleted the retained owner")
	}
}

// Checksum corruption must not expose a different operation's decoded value.
// The matching owner still receives its decoded entry with ErrCorrupt, as before.
func TestExecutionJournalCorruptAliasDoesNotReturnForeignEntry(t *testing.T) {
	j, path, original := executionIdentityFixture(t)
	var damaged Entry
	if err := json.Unmarshal(original, &damaged); err != nil {
		t.Fatal(err)
	}
	damaged.Checksum = "bad-checksum"
	corrupt, err := json.Marshal(damaged)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, corrupt, filePerm); err != nil {
		t.Fatal(err)
	}
	owner, found, err := j.Read("op_bound")
	if !found || !errors.Is(err, ErrCorrupt) || owner == nil || owner.OperationID != "op_bound" || owner.ResourceID != "original-vm" {
		t.Fatal("matching-owner corruption control lost its decoded entry or ErrCorrupt")
	}
	foreign, found, err := j.Read("op:bound")
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if foreign != nil || !found || !errors.Is(err, ErrCorrupt) || !bytes.Equal(after, corrupt) {
		t.Fatal("JOURNAL_CORRUPT_ALIAS: checksum corruption exposed a foreign operation entry")
	}
}

// Literal prior encoding/checksum, independently recorded before production
// changes. An omitted optional execution field must not alter legacy bytes.
func TestExecutionJournalLegacyBytesUnchanged(t *testing.T) {
	dir := t.TempDir()
	j, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := Entry{OperationID: "op-legacy", OwnerEpoch: 2, SpecGeneration: 5,
		ResourceID: "vm1", Kind: "restart", Stage: "journaled",
		Artifacts: map[string]string{"old_domain_xml": "<domain>...</domain>"}, CreatedAt: "2026-07-14T00:00:00Z"}
	if err := j.Write(e); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "op-legacy.json"))
	if err != nil {
		t.Fatal(err)
	}
	const want = `{"version":1,"operation_id":"op-legacy","owner_epoch":2,"spec_generation":5,"resource_id":"vm1","kind":"restart","stage":"journaled","artifacts":{"old_domain_xml":"\u003cdomain\u003e...\u003c/domain\u003e"},"created_at":"2026-07-14T00:00:00Z","checksum":"8657c5f67529404559e3f1b26976c65cf6bc865d7e28e1ac947693dc2306d13e"}`
	if string(got) != want {
		t.Fatal("JOURNAL_LEGACY_BYTES: existing serialized entry or checksum changed")
	}
	retained, found, err := j.Read("op-legacy")
	if err != nil || !found || retained.OperationID != "op-legacy" {
		t.Fatal("legacy owner is not readable")
	}
}

func controllerTarget() ExecutionTarget {
	return ExecutionTarget{OperationID: "operation-original", Name: "web", CreatedAt: "2026-10-20T00:00:00Z", HostName: "host-a", HostIncarnation: "host-incarnation-a", OwnerEpoch: 3, SpecGeneration: 7, DomainUUID: "11111111-1111-4111-8111-111111111111"}
}

func controllerFixture(t *testing.T) (*Journal, *ExecutionController, Preparation) {
	t.Helper()
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenExecutionController(j)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := c.Close(); err != nil {
			t.Error(err)
		}
	})
	p, err := c.PrepareTarget(context.Background(), controllerTarget())
	if err != nil {
		t.Fatal(err)
	}
	return j, c, p
}

// Only this test-package fixture creates admission. No production constructor
// or exported permit exists: ordinary prepared state must always refuse effects.
func controllerFixtureAdmission(p Preparation) executionAdmission {
	return executionAdmission{preparation: p.ID, target: p.Target, generation: 1}
}

func TestExecutionControllerProcessOwner(t *testing.T) {
	if dir := os.Getenv("LITEVIRT_EXECUTION_LOCK_CHILD"); dir != "" {
		j, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, err := OpenExecutionController(j)
		if err != nil {
			if !errors.Is(err, ErrExecutionOwner) {
				t.Fatal(err)
			}
			t.Log("EXECUTION_OWNER_REFUSED")
			return
		}
		defer c.Close()
		t.Log("EXECUTION_OWNER_ACQUIRED")
		return
	}
	j, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	c, err := OpenExecutionController(j)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	probe := func() string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutionControllerProcessOwner$", "-test.v", "-test.count=1")
		cmd.Env = append(os.Environ(), "LITEVIRT_EXECUTION_LOCK_CHILD="+j.dir)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("owner child did not complete: %v %s", err, out)
		}
		return string(out)
	}
	if out := probe(); !strings.Contains(out, "EXECUTION_OWNER_REFUSED") || strings.Contains(out, "EXECUTION_OWNER_ACQUIRED") {
		t.Fatal("EXECUTION_PROCESS_OWNER: second process acquired the live controller directory")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if out := probe(); !strings.Contains(out, "EXECUTION_OWNER_ACQUIRED") {
		t.Fatal("released controller directory cannot be acquired")
	}
}

func TestExecutionControllerUngrantAndGenericBypass(t *testing.T) {
	j, c, p := controllerFixture(t)
	called := false
	if err := c.execute(context.Background(), p, "effect-1", executionAdmission{}, func() error { called = true; return nil }); !errors.Is(err, ErrExecutionUngrant) || called {
		t.Fatal("ungranted preparation issued a real callback")
	}
	entry, found, err := j.Read(p.RecordID)
	if err != nil || !found {
		t.Fatal("prepared record missing")
	}
	before, err := os.ReadFile(j.path(p.RecordID))
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Write(*entry); !errors.Is(err, ErrExecutionControlled) {
		t.Fatal("generic write admitted execution class")
	}
	legacy := *entry
	legacy.Execution = nil
	if err := j.Write(legacy); !errors.Is(err, ErrExecutionControlled) {
		t.Fatal("legacy-shaped overwrite erased execution class")
	}
	if err := j.Remove(p.RecordID); !errors.Is(err, ErrExecutionControlled) {
		t.Fatal("generic remove erased execution class")
	}
	after, err := os.ReadFile(j.path(p.RecordID))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("generic bypass changed protected bytes")
	}
	conflict := p.Target
	conflict.CreatedAt = "replacement"
	conflict.DomainUUID = "22222222-2222-4222-8222-222222222222"
	if _, err := c.PrepareTarget(context.Background(), conflict); !errors.Is(err, ErrExecutionConflict) {
		t.Fatal("same-name successor crossed retained target preparation")
	}
}

func TestExecutionControllerIssuedCallBlocksClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		j, c, p := controllerFixture(t)
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		go func() {
			done <- c.execute(context.Background(), p, "effect-1", controllerFixtureAdmission(p), func() error { close(entered); <-release; return nil })
		}()
		<-entered
		entry, found, err := j.Read(p.RecordID)
		if err != nil || !found || entry.Execution.Effect == nil || entry.Execution.Effect.State != "issued" || entry.Execution.Effect.Generation != 1 {
			t.Fatal("callback preceded actual durable issued record")
		}
		closed := make(chan error, 1)
		go func() { _, err := c.CloseTarget(context.Background(), p); closed <- err }()
		synctest.Wait()
		early := false
		var closeErr error
		select {
		case closeErr = <-closed:
			early = true
			t.Error("EXECUTION_CLOSE_BARRIER: closure returned while issued mutation still runs")
		default:
		}
		state, err := c.RecoverTarget(context.Background(), p)
		if err != nil || state.State != "closing" {
			t.Fatal("close did not durably close admission")
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		if !early {
			closeErr = <-closed
			if closeErr != nil {
				t.Fatal(closeErr)
			}
		}
		state, err = c.RecoverTarget(context.Background(), p)
		if err != nil || state.Effect == nil || state.Effect.State != "completed" || (!early && state.State != "closed") {
			t.Fatal("close did not wait for durable outcome")
		}
	})
}

func TestExecutionControllerCloseBeforeIssue(t *testing.T) {
	_, c, p := controllerFixture(t)
	closure, err := c.CloseTarget(context.Background(), p)
	if err != nil || !closure.NoNewIssuance || !closure.CallsResolved || closure.RuntimeExcluded {
		t.Fatal("local closure claimed incorrect scope")
	}
	calls := 0
	if err := c.execute(context.Background(), p, "effect-1", controllerFixtureAdmission(p), func() error { calls++; return nil }); err == nil || calls != 0 {
		t.Fatal("EXECUTION_CLOSED_ISSUE: closed target issued mutation")
	}
}

func TestExecutionControllerPersistenceUncertain(t *testing.T) {
	for _, stage := range []string{"before-write", "file-sync", "before-rename", "after-rename", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			j, c, p := controllerFixture(t)
			calls := 0
			j.writeFailure = func(at, id string) error {
				if at == stage {
					return errors.New("injected durability uncertainty")
				}
				return nil
			}
			if err := c.execute(context.Background(), p, "effect-1", controllerFixtureAdmission(p), func() error { calls++; return nil }); err == nil || calls != 0 {
				t.Fatal("failed issued persistence permitted mutation")
			}
			j.writeFailure = nil
			if _, err := c.CloseTarget(context.Background(), p); !errors.Is(err, ErrExecutionUnknown) {
				t.Fatal("uncertain persistence authorized closure")
			}
		})
	}
}

func TestExecutionControllerOutcomeFailureAndReopen(t *testing.T) {
	j, c, p := controllerFixture(t)
	calls := 0
	err := c.execute(context.Background(), p, "effect-1", controllerFixtureAdmission(p), func() error {
		calls++
		j.writeFailure = func(at, id string) error {
			if at == "directory-sync" {
				return errors.New("outcome directory sync failed")
			}
			return nil
		}
		return nil
	})
	if err == nil || calls != 1 {
		t.Fatal("missing actual successful call before outcome persistence failure")
	}
	j.writeFailure = nil
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenExecutionController(j)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	// A readable renamed outcome is not authorization on reopen. No admission
	// fixture is restored, and loaded records remain unavailable for execution.
	if err := reopened.execute(context.Background(), p, "effect-2", controllerFixtureAdmission(p), func() error { calls++; return nil }); err == nil || calls != 1 {
		t.Fatal("reopen forgot outcome uncertainty and resumed effects")
	}
}

func TestExecutionControllerCrashReopen(t *testing.T) {
	if dir := os.Getenv("LITEVIRT_EXECUTION_CRASH_DIR"); dir != "" {
		j, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		c, err := OpenExecutionController(j)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		p, err := c.PrepareTarget(context.Background(), controllerTarget())
		if err != nil {
			t.Fatal(err)
		}
		park := func() {
			if _, err := os.Stdout.WriteString("EXECUTION_CHECKPOINT\n"); err != nil {
				t.Fatal(err)
			}
			var b [1]byte
			_, _ = os.Stdin.Read(b[:])
			t.Fatal("crash helper unexpectedly released")
		}
		artifact := func() error {
			f, err := os.OpenFile(filepath.Join(dir, "effect-artifact"), os.O_CREATE|os.O_WRONLY, 0600)
			if err != nil {
				return err
			}
			if _, err = f.WriteString("original-domain-effect"); err != nil {
				f.Close()
				return err
			}
			if err = f.Sync(); err != nil {
				f.Close()
				return err
			}
			return f.Close()
		}
		step := os.Getenv("LITEVIRT_EXECUTION_CRASH_STEP")
		if step == "prepared" {
			park()
			return
		}
		err = c.execute(context.Background(), p, "effect-1", controllerFixtureAdmission(p), func() error {
			if step == "issued" {
				park()
			}
			if err := artifact(); err != nil {
				return err
			}
			if step == "call-success" {
				park()
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if step != "outcome" {
			t.Fatal("invalid crash schedule")
		}
		park()
		return
	}
	for _, step := range []string{"prepared", "issued", "call-success", "outcome"} {
		t.Run(step, func(t *testing.T) {
			dir := t.TempDir()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestExecutionControllerCrashReopen$", "-test.count=1")
			cmd.Env = append(os.Environ(), "LITEVIRT_EXECUTION_CRASH_DIR="+dir, "LITEVIRT_EXECUTION_CRASH_STEP="+step)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdin.Close()
			stdout, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waited := false
			readDone := make(chan struct{})
			defer func() {
				if !waited {
					_ = cmd.Process.Kill()
					_ = cmd.Wait()
				}
				select {
				case <-readDone:
				case <-time.After(time.Second):
					t.Error("crash observer reader did not join")
				}
			}()
			ready := make(chan string, 1)
			go func() { defer close(readDone); line, _ := bufio.NewReader(stdout).ReadString('\n'); ready <- line }()
			select {
			case line := <-ready:
				if line != "EXECUTION_CHECKPOINT\n" {
					t.Fatalf("child failed setup: %q", line)
				}
			case <-ctx.Done():
				t.Fatal("child did not reach actual durable crash checkpoint")
			}
			if err := cmd.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = cmd.Wait()
			waited = true
			if err == nil {
				t.Fatal("crash did not kill child")
			}
			status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("actual child did not terminate by SIGKILL")
			}
			j, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			c, err := OpenExecutionController(j)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			entries, corrupt, err := j.List()
			if err != nil || len(corrupt) != 0 || len(entries) != 1 || entries[0].Execution == nil {
				t.Fatal("crash lost durable execution record")
			}
			p := entries[0].Execution.Preparation
			r, err := c.RecoverTarget(context.Background(), p)
			if err != nil {
				t.Fatal(err)
			}
			if step == "prepared" {
				if r.Effect != nil {
					t.Fatal("prepared crash invented issued call")
				}
			} else {
				want := "issued"
				if step == "outcome" {
					want = "completed"
				}
				if r.Effect == nil || r.Effect.State != want {
					t.Fatal("crash changed durable effect stage")
				}
			}
			if step == "call-success" || step == "outcome" {
				raw, err := os.ReadFile(filepath.Join(dir, "effect-artifact"))
				if err != nil || string(raw) != "original-domain-effect" {
					t.Fatal("real effect artifact absent")
				}
			}
			calls := 0
			if err := c.execute(context.Background(), p, "effect-2", controllerFixtureAdmission(p), func() error { calls++; return nil }); err == nil || calls != 0 {
				t.Fatal("EXECUTION_REOPEN_UNKNOWN: cold owner resumed a retained target without reconciliation")
			}
			if _, err := c.CloseTarget(context.Background(), p); !errors.Is(err, ErrExecutionUnknown) {
				t.Fatal("process death supplied false closure")
			}
		})
	}
}

func TestExecutionControllerInvalidRecordRefusesOpen(t *testing.T) {
	j, c, p := controllerFixture(t)
	entry, found, err := j.Read(p.RecordID)
	if err != nil || !found {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	entry.Execution.Version = 99
	entry.Checksum = entry.checksum()
	raw, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(j.path(p.RecordID), raw, filePerm); err != nil {
		t.Fatal(err)
	}
	if opened, err := OpenExecutionController(j); err == nil {
		opened.Close()
		t.Fatal("unknown execution record version enabled controller")
	}
}

func TestExecutionControllerCanceledCloseRetainsAdmission(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, c, p := controllerFixture(t)
		entered, release := make(chan struct{}), make(chan struct{})
		done := make(chan error, 1)
		defer func() {
			select {
			case <-release:
			default:
				close(release)
			}
		}()
		go func() {
			done <- c.execute(context.Background(), p, "effect-1", controllerFixtureAdmission(p), func() error { close(entered); <-release; return nil })
		}()
		<-entered
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := c.CloseTarget(ctx, p); !errors.Is(err, context.Canceled) {
			t.Fatal("canceled waiter supplied closure")
		}
		state, err := c.RecoverTarget(context.Background(), p)
		if err != nil || state.State != "closing" {
			t.Fatal("canceled close reopened admission")
		}
		calls := 0
		if err := c.execute(context.Background(), p, "effect-2", controllerFixtureAdmission(p), func() error { calls++; return nil }); err == nil || calls != 0 {
			t.Fatal("canceled close admitted a new effect")
		}
		close(release)
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		closure, err := c.CloseTarget(context.Background(), p)
		if err != nil || !closure.CallsResolved || closure.RuntimeExcluded {
			t.Fatal("completed original call did not permit local closure")
		}
	})
}

// Abnormal backend returns must not convert an issued effect into success or
// leak the active-call accounting that Close waits for. No production recover.
func TestExecutionAbnormalReturnRetainsUnknown(t *testing.T) {
	for _, mode := range []string{"panic", "goexit"} {
		t.Run(mode, func(t *testing.T) {
			j, c, p := controllerFixture(t)
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan any, 1)
			defer func() {
				select {
				case <-release:
				default:
					close(release)
				}
			}()
			sentinel := &struct{ message string }{"backend panic"}
			go func() {
				defer func() { done <- recover() }()
				_ = c.execute(context.Background(), p, "abnormal-effect", controllerFixtureAdmission(p), func() error {
					close(entered)
					<-release
					if mode == "panic" {
						panic(sentinel)
					}
					runtime.Goexit()
					return nil
				})
				done <- "execute unexpectedly returned"
			}()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Fatal("effect did not start")
			}
			retained, found, err := j.Read(p.RecordID)
			if err != nil || !found || retained.Execution.Effect.State != "issued" {
				t.Fatal("effect was not durably issued")
			}
			close(release)
			select {
			case got := <-done:
				if mode == "panic" && got != sentinel || mode == "goexit" && got != nil {
					t.Fatalf("abnormal propagation changed: %v", got)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("abnormal effect did not unwind")
			}
			record, err := c.RecoverTarget(context.Background(), p)
			if err != nil || record.Effect == nil || record.Effect.State != "unknown" {
				t.Fatalf("abnormal effect not unknown: %+v %v", record, err)
			}
			retained, found, err = j.Read(p.RecordID)
			if err != nil || !found || retained.Execution.Effect.State != "unknown" {
				t.Fatal("unknown outcome not durable")
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if closure, err := c.CloseTarget(ctx, p); !errors.Is(err, ErrExecutionUnknown) || closure != (LocalClosure{}) {
				t.Fatalf("abnormal effect falsely closed: %+v %v", closure, err)
			}
			closed := make(chan error, 1)
			go func() { closed <- c.Close() }()
			select {
			case err := <-closed:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("abnormal accounting blocked owner Close")
			}
			next, err := OpenExecutionController(j)
			if err != nil {
				t.Fatal("owner not released", err)
			}
			defer next.Close()
			cold, err := next.RecoverTarget(context.Background(), p)
			if err != nil || cold.Effect.State != "unknown" {
				t.Fatal("reopen lost unknown outcome", err)
			}
		})
	}
}
