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
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func publicationWaitFile(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("process boundary not reached", path)
}

// The parent kills the actual source process with SIGKILL at production
// publication seams. A separate OS process must read the WAL and restore floors;
// no retained memory handle, graceful Stop, rollback, or os.Exit substitutes.
func TestSourcePublicationSIGKILL(t *testing.T) {
	for _, stage := range []string{"before_commit", "after_commit"} {
		t.Run(stage, func(t *testing.T) {
			dir := t.TempDir()
			producer, request := sourcePreparationFixtureAt(t, dir)
			if err := pki.GenerateCRL(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), filepath.Join(producer.dir, "crl.pem"), []string{"ab01"}); err != nil {
				t.Fatal(err)
			}
			// Establish a real unrelated signed successor, so disappearance
			// cannot be repaired implicitly by reopening the source identity.
			peerDir := t.TempDir()
			for _, name := range []string{"ca.crt", "ca.key"} {
				if err := copyTestFile(filepath.Join(producer.dir, name), filepath.Join(peerDir, name)); err != nil {
					t.Fatal(err)
				}
			}
			if err := pki.GenerateHostCert(filepath.Join(peerDir, "ca.crt"), filepath.Join(peerDir, "ca.key"), filepath.Join(peerDir, "host.crt"), filepath.Join(peerDir, "host.key"), "historical-peer", nil); err != nil {
				t.Fatal(err)
			}
			if _, _, err := pki.RenewLocal(filepath.Join(peerDir, "ca.crt"), filepath.Join(peerDir, "ca.key"), peerDir, "historical-peer"); err != nil {
				t.Fatal(err)
			}
			successor, err := pki.ServedHostCertificate(peerDir)
			if err != nil {
				t.Fatal(err)
			}
			pki.NoteSuccessor(producer.dir, successor)
			raw, err := json.Marshal(request)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "request.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := producer.client.Close(); err != nil {
				t.Fatal(err)
			}
			command := func(mode string) *exec.Cmd {
				cmd := exec.Command(os.Args[0], "-test.run=^TestSourcePublicationProcess$", "-test.timeout=25s")
				cmd.Env = append(os.Environ(), "SOURCE_PUBLICATION_DIR="+dir, "SOURCE_PUBLICATION_PKI="+producer.dir, "SOURCE_PUBLICATION_MODE="+mode, "SOURCE_PUBLICATION_STAGE="+stage)
				return cmd
			}
			source := command("publish")
			var sourceLog bytes.Buffer
			source.Stdout = &sourceLog
			source.Stderr = &sourceLog
			if err := source.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = source.Process.Kill() })
			publicationWaitFile(t, filepath.Join(dir, "source-ready"))
			writer := command("writer")
			var writerLog bytes.Buffer
			writer.Stdout = &writerLog
			writer.Stderr = &writerLog
			if err := writer.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = writer.Process.Kill() })
			publicationWaitFile(t, filepath.Join(dir, "writer-ready"))
			time.Sleep(150 * time.Millisecond)
			if _, err := os.Stat(filepath.Join(dir, "writer-done")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("separate PKI writer escaped publication Commit lease", err)
			}
			if err := source.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			err = source.Wait()
			var exit *exec.ExitError
			if !errors.As(err, &exit) {
				t.Fatalf("source did not die abruptly: %v %s", err, sourceLog.String())
			}
			status, ok := exit.Sys().(syscall.WaitStatus)
			if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
				t.Fatal("source was not SIGKILLed", err)
			}
			if err := writer.Wait(); err != nil {
				t.Fatalf("writer did not progress after source death: %v %s", err, writerLog.String())
			}
			t.Logf("actual source PID %d killed at %s; independent writer PID %d waited and completed", source.Process.Pid, stage, writer.Process.Pid)
			if out, err := command("verify").CombinedOutput(); err != nil {
				t.Fatalf("fresh process reopen: %v\n%s", err, out)
			} else {
				t.Log(string(out))
			}
			// A fresh owner must not accept a different configured CA merely
			// because that file is structurally valid.
			rootPath := filepath.Join(producer.dir, "ca.crt")
			originalRoot, err := os.ReadFile(rootPath)
			if err != nil {
				t.Fatal(err)
			}
			foreign := t.TempDir()
			if err := pki.GenerateCA(filepath.Join(foreign, "ca.crt"), filepath.Join(foreign, "ca.key")); err != nil {
				t.Fatal(err)
			}
			if err := copyTestFile(filepath.Join(foreign, "ca.crt"), rootPath); err != nil {
				t.Fatal(err)
			}
			if out, err := command("floor-refuse").CombinedOutput(); err != nil {
				t.Fatalf("fresh process replaced configured domain: %v\n%s", err, out)
			}
			if err := os.WriteFile(rootPath, originalRoot, 0600); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"crl.pem", "superseded.pem", "ca.crt"} {
				path := filepath.Join(producer.dir, name)
				saved, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if out, err := command("floor-refuse").CombinedOutput(); err != nil {
					t.Fatalf("fresh process missing %s floor: %v\n%s", name, err, out)
				}
				if err := os.WriteFile(path, saved, 0600); err != nil {
					t.Fatal(err)
				}
				if out, err := command("repair").CombinedOutput(); err != nil {
					t.Fatalf("fresh process repaired %s floor: %v\n%s", name, err, out)
				}
				t.Logf("fresh processes refused missing and accepted restored %s", name)
			}

		})
	}
}

func TestSourcePublicationProcess(t *testing.T) {
	dir := os.Getenv("SOURCE_PUBLICATION_DIR")
	if dir == "" {
		t.Skip("subprocess helper: exercised only by named SIGKILL parent")
	}
	ctx := context.Background()
	pkiDir := os.Getenv("SOURCE_PUBLICATION_PKI")
	mode := os.Getenv("SOURCE_PUBLICATION_MODE")
	if mode == "writer" {
		if err := os.WriteFile(filepath.Join(dir, "writer-ready"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := pki.GenerateCRL(filepath.Join(pkiDir, "ca.crt"), filepath.Join(pkiDir, "ca.key"), filepath.Join(pkiDir, "crl.pem"), []string{"ab02"}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "writer-done"), []byte("done"), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	c, err := NewLocalClient(dir, "a")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := InitSchema(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.SetVoterConfigGate(func() bool { return true })
	rows, err := c.Query(ctx, `PRAGMA journal_mode`)
	if err != nil || len(rows) != 1 || rows[0].Values[0] != "wal" {
		t.Fatal("actual file-backed WAL required", err)
	}
	if level, err := c.SynchronousLevel(ctx); err != nil || level != SynchronousFull {
		t.Fatal("actual FULL required", level, err)
	}
	producer := NewAutomationSourcePreparer(c, pkiDir)
	var request AutomationSourceRequest
	raw, err := os.ReadFile(filepath.Join(dir, "request.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &request); err != nil {
		t.Fatal(err)
	}
	if mode == "floor-refuse" {
		if err := producer.InitializePublication(ctx); err == nil {
			t.Fatal("fresh process lost established completed trust floor")
		}
		return
	}
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	if mode == "repair" {
		return
	}
	if mode == "verify" {
		rows, err := c.Query(ctx, `SELECT artifact FROM local_automation_publications`)
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		if os.Getenv("SOURCE_PUBLICATION_STAGE") == "after_commit" {
			count = 1
		}
		if len(rows) != count {
			t.Fatalf("wrong committed artifact count after SIGKILL: got %d want %d", len(rows), count)
		}
		if count == 1 {
			expected, err := os.ReadFile(filepath.Join(dir, "expected-artifact"))
			if err != nil || !bytes.Equal(expected, rows[0].Bytes("artifact")) {
				t.Fatal("exact completed signed artifact lost after SIGKILL", err)
			}
		}
		// A serialized old preparation has no process pointer/registry/PKI authority.
		pending := &AutomationSourcePreparation{}
		ticket, err := os.ReadFile(filepath.Join(dir, "pending-ticket"))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(ticket, pending); err != nil {
			t.Fatal(err)
		}
		if _, err := producer.Publish(ctx, pending); err == nil {
			t.Fatal("old process ticket revived after crash")
		}
		p, err := producer.Prepare(ctx, request)
		if err != nil {
			t.Fatal("fresh verification did not progress", err)
		}
		defer p.Discard()
		if _, err := producer.Publish(ctx, p); err != nil {
			t.Fatal("fresh publication did not progress", err)
		}
		t.Log("fresh process verified exact commit outcome, restored signed floors, refused old ticket and published after fresh verification")
		return
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	ticket, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pending-ticket"), ticket, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "expected-artifact"), p.artifact, 0600); err != nil {
		t.Fatal(err)
	}
	pause := func() {
		if err := os.WriteFile(filepath.Join(dir, "source-ready"), []byte("ready"), 0600); err != nil {
			t.Fatal(err)
		}
		select {}
	}
	c.automationPublicationSeams = &localCommitSeams{}
	if os.Getenv("SOURCE_PUBLICATION_STAGE") == "before_commit" {
		c.automationPublicationSeams.beforeCommit = func(_ *sql.Tx) error { pause(); return nil }
	} else {
		c.automationPublicationSeams.afterCommit = pause
	}
	if _, err := producer.Publish(ctx, p); err != nil {
		t.Fatal(err)
	}
	t.Fatal("source escaped parent SIGKILL seam")
}
