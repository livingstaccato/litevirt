package corrosion

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"github.com/litevirt/litevirt/internal/pki"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A signed process candidate alone cannot satisfy this: the terminal row and
// whole fixed request must survive a second read after actual Commit.
func TestSourcePublicationPersistsExactArtifact(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	want := string(p.artifact)
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal("publication startup unavailable:", err)
	}
	id, err := producer.Publish(ctx, p)
	if err != nil {
		t.Fatal("real prepared source did not publish:", err)
	}
	rows, err := producer.client.Query(ctx, `SELECT artifact,membership FROM local_automation_publications WHERE id=?`, id)
	if err != nil || len(rows) != 1 || string(rows[0].Bytes("artifact")) != want {
		t.Fatal("committed exact artifact missing", err)
	}
	var membership struct {
		Old, Next   VoterConfigValue
		Certificate string
	}
	if err := json.Unmarshal(rows[0].Bytes("membership"), &membership); err != nil || membership.Old.Generation != 1 || membership.Next.Generation != 2 || membership.Certificate == "" {
		t.Fatal("publication cannot reconstruct complete authenticated transition", err)
	}
	if err := ValidateVoterChange(&VoterConfig{VoterConfigValue: membership.Old}, membership.Next); err != nil {
		t.Fatal("retained full transition cannot be verified", err)
	}
}

// Cached valid preparation is insufficient: the FULL owner independently reads
// actual current DB dependencies and checks eligibility after every pause.
func TestSourcePublicationRejectsChangedDependencies(t *testing.T) {
	for _, mode := range []string{"incarnation", "adoption", "config", "cut", "admission", "reseed", "expiry", "context", "full", "capability"} {
		t.Run(mode, func(t *testing.T) {
			producer, request := sourcePreparationFixture(t)
			ctx := context.Background()
			if err := producer.InitializePublication(ctx); err != nil {
				t.Fatal(err)
			}
			p, err := producer.Prepare(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Discard()
			c := producer.client
			update := func(q string, args ...any) {
				t.Helper()
				if err := c.ExecOutOfProcessForTest(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "incarnation":
				update(`UPDATE local_voter_incarnation SET incarnation='changed' WHERE id=1`)
			case "adoption":
				update(`DELETE FROM local_voter_adoption WHERE generation=1`)
			case "config":
				update(`UPDATE voter_configs SET created_by='changed' WHERE generation=2`)
			case "cut":
				update(`UPDATE local_automation_cut_records SET record=x'00' WHERE section=0`)
			case "admission":
				update(`UPDATE hosts SET deleted_at='changed' WHERE name='a'`)
			case "reseed":
				if _, err := c.BeginReseed(ctx, "b"); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				c.automationPublicationSeams = &localCommitSeams{beforeCommit: func(_ *sql.Tx) error { p.expires = time.Now().Add(-time.Second); return nil }}
			case "context":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				defer cancel()
				c.automationPublicationSeams = &localCommitSeams{beforeCommit: func(_ *sql.Tx) error { cancel(); return nil }}
			case "full":
				c.db.SetMaxOpenConns(1)
				if _, err := c.db.Exec(`PRAGMA synchronous=NORMAL`); err != nil {
					t.Fatal(err)
				}
			case "capability":
				p.validations = nil
			}
			if id, err := producer.Publish(ctx, p); err == nil || id != "" {
				t.Fatal("stale dependency published", mode, err)
			}
			rows, err := c.Query(context.Background(), `SELECT COUNT(*) AS n FROM local_automation_publications`)
			if err != nil || rows[0].Int("n") != 0 {
				t.Fatal("failed publication left successful artifact", err)
			}
		})
	}
}

func TestSourcePublicationRetryRenewalAndStartup(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	publish := func() string {
		t.Helper()
		p, err := producer.Prepare(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Discard()
		id, err := producer.Publish(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	first := publish()
	if retry := publish(); retry != first {
		t.Fatal("exact retry created another artifact")
	}
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal("completed startup refused", err)
	}
	before, err := producer.client.Query(ctx, `SELECT artifact FROM local_automation_publications WHERE id=?`, first)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := pki.RenewLocal(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), producer.dir, "a"); err != nil {
		t.Fatal(err)
	}
	next := publish()
	if next == first {
		t.Fatal("renewal relabeled old artifact")
	}
	after, err := producer.client.Query(ctx, `SELECT artifact FROM local_automation_publications WHERE id=?`, first)
	if err != nil || !bytes.Equal(before[0].Bytes("artifact"), after[0].Bytes("artifact")) {
		t.Fatal("renewal changed old signed bytes", err)
	}
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal("renewed completed startup refused", err)
	}
	if err := producer.client.ExecOutOfProcessForTest(`UPDATE local_automation_source_jobs SET binding=x'00' WHERE job=?`, request.Job); err != nil {
		t.Fatal(err)
	}
	if err := producer.InitializePublication(ctx); err == nil {
		t.Fatal("corrupt established pin enabled publisher")
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	if _, err := producer.Publish(ctx, p); err == nil {
		t.Fatal("failed startup retained readiness")
	}
}

func TestSourcePublicationCancelledDBWaitReleases(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	c := producer.client
	c.mu.Lock()
	locked := true
	defer func() {
		if locked {
			c.mu.Unlock()
		}
	}()
	attempt, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { _, err := producer.Publish(attempt, p); done <- err }()
	time.Sleep(40 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled publication succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		c.mu.Unlock()
		locked = false
		<-done
		t.Fatal("cancelled DB wait retained publication and PKI lease")
	}
	c.mu.Unlock()
	locked = false
	// Releasing the SQL waiter also releases its PKI registrations and admission.
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal("cancelled waiter did not release owner", err)
	}
}

func TestSourcePublicationMissingCompletedEvidenceRefuses(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	publish := func() string {
		t.Helper()
		p, err := producer.Prepare(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		defer p.Discard()
		id, err := producer.Publish(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	_ = publish()
	if _, _, err := pki.RenewLocal(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), producer.dir, "a"); err != nil {
		t.Fatal(err)
	}
	newer := publish()
	if err := producer.client.ExecOutOfProcessForTest(`DELETE FROM local_automation_publications WHERE id=?`, newer); err != nil {
		t.Fatal(err)
	}
	if err := producer.InitializePublication(ctx); err == nil {
		t.Fatal("missing established signed evidence was hidden by older artifact")
	}
}

func TestSourcePublicationRealCertificateExpiryAtPrecommit(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	caPEM, err := os.ReadFile(filepath.Join(producer.dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(caPEM)
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(producer.dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ = pem.Decode(keyPEM)
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := pki.ServedHostKeyPair(producer.dir)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = time.Now().Truncate(time.Second).Add(3 * time.Second)
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(producer.dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	producer.client.automationPublicationSeams = &localCommitSeams{beforeCommit: func(_ *sql.Tx) error { time.Sleep(time.Until(leaf.NotAfter) + 30*time.Millisecond); return nil }}
	if _, err := producer.Publish(ctx, p); err == nil {
		t.Fatal("actual served certificate expired during precommit pause but publication committed")
	}
	rows, err := producer.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_publications`)
	if err != nil || rows[0].Int("n") != 0 {
		t.Fatal("expired real signer left committed artifact", err)
	}
}

func TestSourcePublicationCorruptCompletedWrapper(t *testing.T) {
	for _, mode := range []string{"signature", "trust", "membership", "pin", "missing-cut"} {
		t.Run(mode, func(t *testing.T) {
			producer, request := sourcePreparationFixture(t)
			ctx := context.Background()
			if err := producer.InitializePublication(ctx); err != nil {
				t.Fatal(err)
			}
			p, err := producer.Prepare(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			id, err := producer.Publish(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			c := producer.client
			update := func(q string, args ...any) {
				t.Helper()
				if err := c.ExecOutOfProcessForTest(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			switch mode {
			case "signature":
				rows, err := c.Query(ctx, `SELECT artifact FROM local_automation_publications WHERE id=?`, id)
				if err != nil {
					t.Fatal(err)
				}
				var signed sourceSignedArtifact
				if err := json.Unmarshal(rows[0].Bytes("artifact"), &signed); err != nil {
					t.Fatal(err)
				}
				signed.Signature[len(signed.Signature)-1] ^= 1
				raw, err := json.Marshal(signed)
				if err != nil {
					t.Fatal(err)
				}
				update(`UPDATE local_automation_publications SET artifact=? WHERE id=?`, raw, id)
			case "trust":
				update(`UPDATE local_automation_publications SET evidence=x'00' WHERE id=?`, id)
			case "membership":
				update(`UPDATE local_automation_publications SET membership=x'00' WHERE id=?`, id)
			case "pin":
				update(`UPDATE local_automation_source_jobs SET binding=x'00'`)
			case "missing-cut":
				update(`DELETE FROM local_automation_cut_records WHERE section=0`)
			}
			if err := producer.InitializePublication(ctx); err == nil {
				t.Fatal("corrupt completed evidence enabled source", mode)
			}
		})
	}
}

func TestSourcePublicationFailedCommitReleases(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	c := producer.client
	c.db.SetMaxOpenConns(1)
	if _, err := c.db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	if _, err := c.db.Exec(`CREATE TABLE source_commit_failure(id INTEGER PRIMARY KEY, ref INTEGER REFERENCES source_commit_failure(id) DEFERRABLE INITIALLY DEFERRED)`); err != nil {
		t.Fatal(err)
	}
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	injected := false
	c.automationPublicationSeams = &localCommitSeams{beforeCommit: func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `INSERT INTO source_commit_failure(id,ref) VALUES(1,999)`)
		injected = err == nil
		return err
	}}
	if _, err := producer.Publish(ctx, p); err == nil || !strings.Contains(err.Error(), "commit source publication") || !injected {
		t.Fatal("actual SQLite Commit failure was not exercised", err, injected)
	}
	rows, err := c.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_publications`)
	if err != nil || rows[0].Int("n") != 0 {
		t.Fatal("failed Commit left completed artifact", err)
	}
	c.automationPublicationSeams = nil
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal("failed Commit retained lease or pin", err)
	}
	p, err = producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	if _, err := producer.Publish(ctx, p); err != nil {
		t.Fatal("fresh publication after failed Commit did not progress", err)
	}
}

func TestSourcePublicationCloseDuringCommitWait(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	c := producer.client
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	reached := make(chan struct{})
	release := make(chan struct{})
	c.automationPublicationSeams = &localCommitSeams{beforeCommit: func(_ *sql.Tx) error { close(reached); <-release; return nil }}
	done := make(chan error, 1)
	go func() { _, err := producer.Publish(ctx, p); done <- err }()
	<-reached
	closed := make(chan error, 1)
	go func() { closed <- c.Close() }()
	deadline := time.Now().Add(time.Second)
	for {
		c.automationSourceMu.Lock()
		closing := c.automationSourceClosed
		c.automationSourceMu.Unlock()
		if closing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Close did not close registration")
		}
		time.Sleep(time.Millisecond)
	}
	close(release)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Close-during-wait publication committed")
		}
	case <-time.After(time.Second):
		t.Fatal("publication and Close deadlocked")
	}
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close retained publication capability")
	}
}

func TestSourcePublicationRetainsObservedTargetChain(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
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
	rows, err := producer.client.Query(ctx, `SELECT membership FROM local_automation_publications WHERE id=?`, id)
	if err != nil {
		t.Fatal(err)
	}
	var wrapper struct{ TargetChain [][]byte }
	if err := json.Unmarshal(rows[0].Bytes("membership"), &wrapper); err != nil {
		t.Fatal(err)
	}
	if len(wrapper.TargetChain) == 0 {
		t.Fatal("completed publication lost actual observed target chain")
	}
}

func TestSourcePublicationTargetEvidenceBinding(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	want := bytes.Clone(p.targetChain[0])
	body := bytes.Clone(p.body)
	pin := sourcePin(p.manifest)
	id, err := producer.Publish(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if p.targetChain != nil || p.targetChainDigest != "" {
		t.Fatal("consumption retained private target chain")
	}
	rows, err := producer.client.Query(ctx, `SELECT artifact,evidence,membership FROM local_automation_publications WHERE id=?`, id)
	if err != nil {
		t.Fatal(err)
	}
	row := rows[0]
	var membership sourceMembershipEvidence
	if err := json.Unmarshal(row.Bytes("membership"), &membership); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, membership.TargetChain[0]) {
		t.Fatal("retained chain differs from observed chain")
	}
	if _, _, err := pki.RenewLocal(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), producer.dir, "a"); err != nil {
		t.Fatal(err)
	}
	renewed, err := pki.ServedHostKeyPair(producer.dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"missing", "corrupt", "count", "bytes", "different-valid-leaf"} {
		t.Run(mode, func(t *testing.T) {
			var m sourceMembershipEvidence
			if err := json.Unmarshal(row.Bytes("membership"), &m); err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing":
				m.TargetChain = nil
			case "corrupt":
				m.TargetChain[0][0] ^= 1
			case "count":
				for len(m.TargetChain) <= maxSourceChainCertificates {
					m.TargetChain = append(m.TargetChain, want)
				}
			case "different-valid-leaf":
				m.TargetChain = renewed.Certificate
			case "bytes":
				m.TargetChain = [][]byte{make([]byte, maxSourceChainBytes+1)}
			}
			raw, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			changedID := sourceDigest(body, row.Bytes("evidence"), raw)
			if _, err := decodeSourcePublication(changedID, row.Bytes("artifact"), row.Bytes("evidence"), raw); err == nil {
				t.Fatal("changed recorded target accepted", mode)
			}
		})
	}
	var signed sourceSignedArtifact
	if err := json.Unmarshal(row.Bytes("artifact"), &signed); err != nil {
		t.Fatal(err)
	}
	sourceSize, targetSize := 0, 0
	for _, raw := range signed.Chain {
		sourceSize += len(raw)
	}
	for _, raw := range membership.TargetChain {
		targetSize += len(raw)
	}
	logical := len(id) + len(request.Job) + 8 + len(row.Bytes("artifact")) + len(row.Bytes("evidence")) + len(row.Bytes("membership")) + len(pin)
	t.Logf("actual typed artifact=%d trust=%d membership+target=%d sourceChain=%d targetChain=%d SQL logical row+pin payload=%d wrapperMax=%d (excludes DB page overhead; no export RPC exists)", len(row.Bytes("artifact")), len(row.Bytes("evidence")), len(row.Bytes("membership")), sourceSize, targetSize, logical, maxSourcePublicationBytes)
}

func TestSourcePublicationCancelledSerializationWait(t *testing.T) {
	producer, request := sourcePreparationFixture(t)
	ctx := context.Background()
	if err := producer.InitializePublication(ctx); err != nil {
		t.Fatal(err)
	}
	p, err := producer.Prepare(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Discard()
	producer.client.automationPublicationMu.Lock()
	locked := true
	defer func() {
		if locked {
			producer.client.automationPublicationMu.Unlock()
		}
	}()
	attempt, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := producer.Publish(attempt, p); done <- err }()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("cancelled serialized publication succeeded")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("cancelled publication blocked behind publication serialization")
	}
	producer.client.automationPublicationMu.Unlock()
	locked = false
}
