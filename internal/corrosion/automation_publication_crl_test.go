package corrosion

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// This is an oracle copied from a genuine completed transaction, never an
// input to the publisher or a manufactured terminal row.
type publicationCRLOriginal struct {
	Request                             AutomationSourceRequest
	ID                                  string
	Artifact, Evidence, Membership, Pin []byte
}

func publicationCRLReadOriginal(t *testing.T, c *Client, original publicationCRLOriginal) int {
	t.Helper()
	rows, err := c.Query(context.Background(), `SELECT artifact,evidence,membership FROM local_automation_publications WHERE id=?`, original.ID)
	if err != nil || len(rows) != 1 {
		t.Fatal("original completed publication missing", err)
	}
	if !bytes.Equal(rows[0].Bytes("artifact"), original.Artifact) || !bytes.Equal(rows[0].Bytes("evidence"), original.Evidence) || !bytes.Equal(rows[0].Bytes("membership"), original.Membership) {
		t.Fatal("compaction changed immutable historical publication")
	}
	rows, err = c.Query(context.Background(), `SELECT binding,publications FROM local_automation_source_jobs WHERE job=? AND revision=?`, original.Request.Job, original.Request.Revision)
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("binding"), original.Pin) {
		t.Fatal("compaction changed immutable job/roster/cut pin", err)
	}
	n := rows[0].Int("publications")
	counts, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM local_automation_publications`)
	if err != nil || counts[0].Int("n") != n {
		t.Fatal("completed row count differs from job pin", err)
	}
	return n
}

// Every case starts from an actual completed WAL/FULL publication containing
// two incomparable same-number signed CRLs. Supported writers operate AFTER
// that completion; separate OS processes select the SQL evidence at startup.
func TestSourcePublicationCRLCompactionRestart(t *testing.T) {
	for _, mode := range []string{"generate", "append", "covering-install", "omitted-equal-branch", "higher-incomplete-union", "missing-established-file"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			producer, request := sourcePreparationFixtureAt(t, dir)
			crlPath := filepath.Join(producer.dir, "crl.pem")
			caPath, keyPath := filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key")
			readPEM := func(path string) []byte {
				t.Helper()
				raw, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				block, _ := pem.Decode(raw)
				if block == nil {
					t.Fatal("fixture PEM missing", path)
				}
				return block.Bytes
			}
			ca, err := x509.ParseCertificate(readPEM(caPath))
			if err != nil {
				t.Fatal(err)
			}
			key, err := x509.ParseECPrivateKey(readPEM(keyPath))
			if err != nil {
				t.Fatal(err)
			}
			signedCRL := func(number int64, serials ...int64) []byte {
				t.Helper()
				entries := make([]x509.RevocationListEntry, 0, len(serials))
				for _, serial := range serials {
					entries = append(entries, x509.RevocationListEntry{SerialNumber: big.NewInt(serial), RevocationTime: time.Now().Add(-time.Minute)})
				}
				raw, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(number), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: entries}, ca, key)
				if err != nil {
					t.Fatal(err)
				}
				return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: raw})
			}
			left, right := signedCRL(77, 101), signedCRL(77, 102)
			if _, _, err := pki.InstallCRLs(producer.dir, [][]byte{left, right}); err != nil {
				t.Fatal(err)
			}
			// Authenticate the on-disk union independently and assert actual compaction,
			// rather than crediting writer return alone as a covering-union result.
			assertCurrent := func(wantCount int, wantSerials ...int64) {
				t.Helper()
				raw, err := os.ReadFile(crlPath)
				if err != nil {
					t.Fatal(err)
				}
				serials := map[int64]bool{}
				count := 0
				for rest := bytes.TrimSpace(raw); len(rest) > 0; {
					block, tail := pem.Decode(rest)
					if block == nil || block.Type != "X509 CRL" {
						t.Fatal("invalid current CRL PEM")
					}
					list, err := x509.ParseRevocationList(block.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					if err := list.CheckSignatureFrom(ca); err != nil {
						t.Fatal(err)
					}
					if wantCount == 2 && list.Number.Int64() != 77 {
						t.Fatal("initial branches do not share number77")
					}
					for _, entry := range list.RevokedCertificateEntries {
						serials[entry.SerialNumber.Int64()] = true
					}
					count++
					rest = bytes.TrimSpace(tail)
				}
				if count != wantCount || len(serials) != len(wantSerials) {
					t.Fatal("wrong verified current union", count, serials)
				}
				for _, serial := range wantSerials {
					if !serials[serial] {
						t.Fatal("verified current union lost serial", serial)
					}
				}
			}
			assertCurrent(2, 101, 102)
			if err := producer.InitializePublication(ctx); err != nil {
				t.Fatal(err)
			}
			p, err := producer.Prepare(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Discard()
			id, err := producer.Publish(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := producer.client.Query(ctx, `SELECT artifact,evidence,membership FROM local_automation_publications WHERE id=?`, id)
			if err != nil || len(rows) != 1 {
				t.Fatal(err)
			}
			pins, err := producer.client.Query(ctx, `SELECT binding FROM local_automation_source_jobs WHERE job=? AND revision=?`, request.Job, request.Revision)
			if err != nil || len(pins) != 1 {
				t.Fatal(err)
			}
			original := publicationCRLOriginal{request, id, rows[0].Bytes("artifact"), rows[0].Bytes("evidence"), rows[0].Bytes("membership"), pins[0].Bytes("binding")}
			if !bytes.Contains(original.Evidence, left) || !bytes.Contains(original.Evidence, right) {
				t.Fatal("completed evidence lost original incomparable signed CRLs")
			}
			if publicationCRLReadOriginal(t, producer.client, original) != 1 {
				t.Fatal("initial terminal count differs")
			}
			raw, err := json.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "crl-original.json"), raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err := producer.client.Close(); err != nil {
				t.Fatal(err)
			}
			child := func(childMode string) {
				t.Helper()
				cmd := exec.Command(os.Args[0], "-test.run=^TestSourcePublicationCRLProcess$", "-test.v", "-test.timeout=45s")
				cmd.Env = append(os.Environ(), "SOURCE_CRL_DIR="+dir, "SOURCE_CRL_PKI="+producer.dir, "SOURCE_CRL_MODE="+childMode)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("fresh process %s failed: %v\n%s", childMode, err, out)
				}
				t.Logf("%s completed in independent process:\n%s", childMode, out)
			}
			// Establish that the actual completed incomparable union is readable in a
			// fresh owner before applying a supported writer or deliberate regression.
			child("verify")
			switch mode {
			case "generate":
				err = pki.GenerateCRL(caPath, keyPath, crlPath, []string{"67"})
			case "append":
				err = pki.AppendToCRL(caPath, keyPath, crlPath, "67")
			case "covering-install":
				_, _, err = pki.InstallCRLs(producer.dir, [][]byte{signedCRL(78, 101, 102, 103)})
			case "omitted-equal-branch":
				err = os.WriteFile(crlPath, left, 0600)
			case "higher-incomplete-union":
				err = os.WriteFile(crlPath, signedCRL(999, 101), 0600)
			case "missing-established-file":
				err = os.Remove(crlPath)
			}
			if err != nil {
				t.Fatal(err)
			}
			if mode == "omitted-equal-branch" || mode == "higher-incomplete-union" || mode == "missing-established-file" {
				child("refuse")
				// Repair through the real coordinated, durable covering installer, not a
				// direct reconciliation call or restoration of a fabricated terminal row.
				if _, _, err := pki.InstallCRLs(producer.dir, [][]byte{signedCRL(1000, 101, 102, 103)}); err != nil {
					t.Fatal("supported repair failed", err)
				}
			}
			assertCurrent(1, 101, 102, 103)
			child("progress")
			child("progress") // another new owner reads both completed evidence epochs
		})
	}
}

func TestSourcePublicationCRLProcess(t *testing.T) {
	dir := os.Getenv("SOURCE_CRL_DIR")
	if dir == "" {
		t.Skip("subprocess helper: exercised by CRL compaction restart matrix")
	}
	ctx := context.Background()
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
	raw, err := os.ReadFile(filepath.Join(dir, "crl-original.json"))
	if err != nil {
		t.Fatal(err)
	}
	var original publicationCRLOriginal
	if err := json.Unmarshal(raw, &original); err != nil {
		t.Fatal(err)
	}
	before := publicationCRLReadOriginal(t, c, original)
	producer := NewAutomationSourcePreparer(c, os.Getenv("SOURCE_CRL_PKI"))
	err = producer.InitializePublication(ctx)
	mode := os.Getenv("SOURCE_CRL_MODE")
	if mode == "refuse" {
		if err == nil || !strings.Contains(err.Error(), "CRL") {
			t.Fatal("fresh startup accepted regressed completed CRL floor or failed for unrelated reason", err)
		}
		if producer.client.automationPublicationReady {
			t.Fatal("failed floor reconciliation enabled publication")
		}
		if publicationCRLReadOriginal(t, c, original) != before || before != 1 {
			t.Fatal("refused startup changed completed rows")
		}
		t.Logf("PID %d refused actual completed CRL floor: %v", os.Getpid(), err)
		return
	}
	if err != nil {
		t.Fatal("completed publication startup refused covering union", err)
	}
	if mode == "verify" {
		if before != 1 {
			t.Fatal("baseline completed count differs")
		}
		t.Logf("PID %d restored exact incomparable completed evidence", os.Getpid())
		return
	}
	if mode != "progress" {
		t.Fatal("unknown subprocess mode", mode)
	}
	p, err := producer.Prepare(ctx, original.Request)
	if err != nil {
		t.Fatal("fresh preparation after covering writer refused", err)
	}
	defer p.Discard()
	expectedEvidence, err := p.trust.PublicEvidence()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(expectedEvidence, original.Evidence) {
		t.Fatal("fresh preparation reused uncompacted historical trust evidence")
	}
	id, err := producer.Publish(ctx, p)
	if err != nil || id == original.ID {
		t.Fatal("fresh source publication after covering writer refused or reused stale identity", id, err)
	}
	rows, err = c.Query(ctx, `SELECT evidence FROM local_automation_publications WHERE id=?`, id)
	if err != nil || len(rows) != 1 || !bytes.Equal(rows[0].Bytes("evidence"), expectedEvidence) {
		t.Fatal("new committed row did not retain actual current covering evidence", err)
	}
	if publicationCRLReadOriginal(t, c, original) != 2 {
		t.Fatal("fresh publication/retry changed exact expected completed count")
	}
	t.Logf("PID %d reconciled completed evidence, freshly prepared/published %s; original artifact/evidence/membership/pin unchanged, terminal count2", os.Getpid(), id)
}
