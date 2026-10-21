package daemon

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/opjournal"
)

func TestExecutionOwnerRefusesBeforeStartup(t *testing.T) {
	for _, which := range []string{"file-in-place", "live-owner", "invalid-record"} {
		t.Run(which, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "journal")
			if which == "file-in-place" {
				if err := os.WriteFile(dir, []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				j, err := opjournal.Open(dir)
				if err != nil {
					t.Fatal(err)
				}
				if which == "live-owner" {
					owner, err := opjournal.OpenExecutionController(j)
					if err != nil {
						t.Fatal(err)
					}
					defer owner.Close()
				} else {
					if err := os.WriteFile(filepath.Join(dir, "unknown.json"), []byte(`{"execution":{"Version":999}}`), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			calls := 0
			err := withExecutionOwner(dir, func(*opjournal.Journal, *opjournal.ExecutionController) error { calls++; return nil })
			if err == nil || calls != 0 {
				t.Fatalf("EXECUTION_EARLY_OWNER: startup reached without exclusive valid owner: calls=%d err=%v", calls, err)
			}
		})
	}
}
func TestExecutionOwnerLifetimeIncludesStartupContinuation(t *testing.T) {
	for _, outcome := range []string{"success", "error"} {
		t.Run(outcome, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "journal")
			entered := make(chan struct{})
			release := make(chan struct{})
			done := make(chan error, 1)
			var sentinel error
			if outcome == "error" {
				sentinel = errors.New("startup stopped")
			}
			go func() {
				done <- withExecutionOwner(dir, func(j *opjournal.Journal, c *opjournal.ExecutionController) error {
					if j == nil || c == nil {
						return errors.New("missing owner")
					}
					close(entered)
					<-release
					return sentinel
				})
			}()
			released := false
			defer func() {
				if !released {
					close(release)
				}
			}()
			select {
			case <-entered:
			case err := <-done:
				t.Fatalf("startup failed: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("startup never entered")
			}
			j, err := opjournal.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			second, err := opjournal.OpenExecutionController(j)
			if second != nil {
				second.Close()
			}
			if !errors.Is(err, opjournal.ErrExecutionOwner) {
				t.Fatalf("EXECUTION_OWNER_LIFETIME: second owner acquired while startup lives: %v", err)
			}
			close(release)
			released = true
			select {
			case err := <-done:
				if !errors.Is(err, sentinel) {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("owner continuation did not finish")
			}
			next, err := opjournal.OpenExecutionController(j)
			if err != nil {
				t.Fatal("owner not released", err)
			}
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}
func TestExecutionRunOwnerFailurePrecedesDaemonStartup(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "opjournal"), []byte("blocked"), 0600); err != nil {
		t.Fatal(err)
	}
	// No DB, libvirt, PKI or workers are installed. Real Run must return at the
	// filesystem owner boundary before touching any startup dependency.
	d := &Daemon{cfg: &Config{DataDir: dir}}
	if err := d.Run(context.Background()); err == nil {
		t.Fatal("Run continued without journal owner")
	}
	if d.opJournal != nil || d.executionController != nil {
		t.Fatal("failed Run published owner fields")
	}
}
func executionRecoveryTarget() opjournal.ExecutionTarget {
	return opjournal.ExecutionTarget{OperationID: "original-operation", Name: "web", CreatedAt: "2026-10-20T00:00:00Z", HostName: "host-a", HostIncarnation: "host-incarnation-a", OwnerEpoch: 3, SpecGeneration: 7, DomainUUID: "11111111-1111-4111-8111-111111111111"}
}
func TestExecutionRecoveryRetainsControlledJournal(t *testing.T) {
	for _, state := range []string{"prepared", "issued", "unknown"} {
		t.Run(state, func(t *testing.T) {
			dir := t.TempDir()
			j, err := opjournal.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			c, err := opjournal.OpenExecutionController(j)
			if err != nil {
				t.Fatal(err)
			}
			p, err := c.PrepareTarget(context.Background(), executionRecoveryTarget())
			if err != nil {
				t.Fatal(err)
			}
			if err := c.Close(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, p.RecordID+".json")
			if state != "prepared" {
				// Retained cold-load fixture, not an exported execution grant or a generic
				// journal Write bypass. Use the real prepared entry and exact checksum
				// encoding to model an already-issued/uncertain durable record.
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				var e opjournal.Entry
				if err := json.Unmarshal(raw, &e); err != nil {
					t.Fatal(err)
				}
				e.Execution.Effect = &opjournal.ExecutionEffect{ID: "effect-original", State: state, Generation: 1}
				e.Checksum = ""
				body, err := json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				sum := sha256.Sum256(body)
				e.Checksum = hex.EncodeToString(sum[:])
				body, err = json.Marshal(e)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, body, 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if err := withExecutionOwner(dir, func(owned *opjournal.Journal, controller *opjournal.ExecutionController) error {
				plan, corrupt, err := owned.PlanRecovery(func(string) (bool, int64, bool, error) {
					t.Error("controlled record reached ordinary lookup")
					return false, 0, false, nil
				})
				if err != nil || len(corrupt) != 0 || len(plan) != 1 || plan[0].Action != opjournal.RecoveryControlled {
					t.Fatalf("invalid controlled plan: %v %v %v", plan, corrupt, err)
				}
				db := corrosion.NewTestClientT(t)
				if err := corrosion.InitSchema(context.Background(), db); err != nil {
					t.Fatal(err)
				}
				legacy := opjournal.Entry{OperationID: "legacy-gone", ResourceID: "ordinary", Kind: "restart", Stage: "prepared", OwnerEpoch: 1, SpecGeneration: 1, CreatedAt: "2026-10-20T00:00:00Z"}
				if err := owned.Write(legacy); err != nil {
					t.Fatal(err)
				}
				d := &Daemon{db: db, opJournal: owned, executionController: controller}
				d.runOperationRecovery(context.Background())
				after, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(after, before) {
					t.Fatalf("EXECUTION_RECOVERY_RETAIN: controlled bytes removed/changed: %v", err)
				}
				if _, found, err := owned.Read(legacy.OperationID); err != nil || found {
					t.Fatalf("ordinary absent-operation cleanup changed: found=%v err=%v", found, err)
				}
				record, err := controller.RecoverTarget(context.Background(), p)
				if err != nil || record.Preparation != p {
					t.Fatalf("cold record lost: %v", err)
				}
				if _, err := controller.CloseTarget(context.Background(), p); !errors.Is(err, opjournal.ErrExecutionUnknown) {
					t.Fatalf("cold record granted closure: %v", err)
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// CLI dispatch compares these exact sentinels, not merely errors.Is. Real
// owner cleanup must leave their identity intact and release the directory.
func TestExecutionOwnerPreservesRunSentinels(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result error
	}{
		{"reexec", ErrReExec}, {"uninstalled", ErrUninstalled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "journal")
			calls := 0
			got := withExecutionOwner(dir, func(j *opjournal.Journal, c *opjournal.ExecutionController) error {
				calls++
				if j == nil || c == nil {
					t.Fatal("missing actual owner")
				}
				second, err := opjournal.OpenExecutionController(j)
				if second != nil {
					second.Close()
				}
				if !errors.Is(err, opjournal.ErrExecutionOwner) {
					t.Fatalf("owner not retained during sentinel return: %v", err)
				}
				return tc.result
			})
			if got != tc.result || calls != 1 {
				t.Fatalf("EXECUTION_RUN_SENTINEL: got=%v identity=%t calls=%d", got, got == tc.result, calls)
			}
			j, err := opjournal.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			next, err := opjournal.OpenExecutionController(j)
			if err != nil {
				t.Fatal("sentinel return retained owner", err)
			}
			if err := next.Close(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// This is the error-combination policy, not a claim to have injected an OS
// flock/descriptor failure. Real acquisition/release is exercised above.
func TestExecutionOwnerCleanupFailureResult(t *testing.T) {
	cleanup := errors.New("owner cleanup failed")
	for _, tc := range []struct {
		name   string
		result error
	}{
		{"success", nil}, {"reexec", ErrReExec}, {"uninstalled", ErrUninstalled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := executionOwnerResult(tc.result, nil); got != tc.result {
				t.Fatal("successful cleanup changed return identity")
			}
			got := executionOwnerResult(tc.result, cleanup)
			if got == nil || !errors.Is(got, cleanup) {
				t.Fatal("cleanup failure was hidden")
			}
			if tc.result != nil && (got == tc.result || !errors.Is(got, tc.result)) {
				t.Fatal("cleanup failure must block exact sentinel dispatch while preserving both causes")
			}
		})
	}
}
