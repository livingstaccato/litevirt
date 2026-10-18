package corrosion

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

func currentShortSigner(t *testing.T, caFiles claimTestCA, v *claimTestVoter, expires time.Time) *ClaimSigner {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(caFiles.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal(name)
		}
		return block.Bytes
	}
	ca, err := x509.ParseCertificate(read("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(read("ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := parseCertPEM([]byte(v.signer.certPEM))
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = expires
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	signer := *v.signer
	signer.certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw}))
	return &signer
}

func TestReceiverCurrentPublicationOnlySignerExpiry(t *testing.T) {
	var expires time.Time
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, BeforePublish: func(t *testing.T, f *aggregateFixture) {
		expires = time.Now().Truncate(time.Second).Add(8 * time.Second)
		// The real extra ordinary signer is absent from the receiver's certificate
		// metadata and from the two directly observed source serving chains.
		signer := currentShortSigner(t, f.ca, f.voters[2], expires)
		for _, v := range f.voters[:2] {
			cfg, err := GetVoterConfig(context.Background(), v.c, 2)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := sourceCertificate(cfg.Certificate)
			if err != nil {
				t.Fatal(err)
			}
			for i, a := range cert.Accepts {
				if a.Voter == signer.name {
					cert.Accepts[i], err = signer.Sign(cert.Key, cert.ConfigGeneration, cert.Ballot, cert.ValueDigest, a.VoterIncarnation)
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			raw, err := cert.Encode()
			if err != nil {
				t.Fatal(err)
			}
			if _, err = v.c.db.Exec(`UPDATE voter_configs SET certificate=? WHERE generation=2`, raw); err != nil {
				t.Fatal(err)
			}
		}
	}})
	for i := range f.producers {
		f.stage(t, i, 11, true)
	}
	p, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	if !p.attempt.notAfter.Equal(expires) || !f.attempt.notAfter.After(expires) {
		t.Fatal("publication-only real signer interval was not retained", p.attempt.notAfter, f.attempt.notAfter)
	}
	active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
	reached := false
	f.receiver.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { reached = true; time.Sleep(time.Until(expires) + 25*time.Millisecond); return nil }}
	err = f.receiver.consumeCurrent(context.Background(), p)
	if !reached || err == nil || !strings.Contains(err.Error(), "current counted signer expired") {
		t.Fatal("publication-only signer survived actual leased SQL wait", reached, err)
	}
	if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
		t.Fatal("expiry mutated durable state")
	}
}

func TestReceiverCurrentTrustWriterWaitsForTerminal(t *testing.T) {
	f := currentProofFixture(t)
	p, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	entered, release, terminal := make(chan struct{}), make(chan struct{}), make(chan struct{})
	f.receiver.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { close(entered); <-release; return nil }, afterCommit: func() { close(terminal) }}
	consumed := make(chan error, 1)
	go func() { consumed <- f.receiver.consumeCurrent(context.Background(), p) }()
	<-entered
	writer := make(chan error, 1)
	var policy atomic.Bool
	go func() { writer <- pki.PublishHostTrustPolicy(f.local.pki, &policy, true) }()
	select {
	case e := <-writer:
		t.Fatal("supported trust writer escaped held FULL lease", e)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	// The pending effective policy may itself cause refusal, which also has to
	// roll back before the writer can acquire the real trust owner.
	e := <-consumed
	if e == nil {
		select {
		case <-terminal:
		default:
			t.Fatal("consumer released before actual commit")
		}
	}
	if err = <-writer; err != nil {
		t.Fatal(err)
	}
	if !policy.Load() {
		t.Fatal("writer did not complete")
	}
}

func TestReceiverCurrentCanceledOwnerWaitConsumesProof(t *testing.T) {
	f := currentProofFixture(t)
	p, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	f.receiver.mu.Lock()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.receiver.consumeCurrent(ctx, p) }()
	cancel()
	err = <-done
	f.receiver.mu.Unlock()
	if err == nil {
		t.Fatal("canceled owner wait succeeded")
	}
	if err = f.receiver.consumeCurrent(context.Background(), p); err == nil {
		t.Fatal("canceled owner wait revived same current proof")
	}
}

func TestReceiverCurrentActualHostExpiry(t *testing.T) {
	for _, mode := range []string{"source", "receiver"} {
		t.Run(mode, func(t *testing.T) {
			var expires, installed time.Time
			f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, BeforePublish: func(t *testing.T, f *aggregateFixture) {
				v := f.voters[0]
				if mode == "receiver" {
					v = f.local
				}
				expires = time.Now().Truncate(time.Second).Add(8 * time.Second)
				short := currentShortSigner(t, f.ca, v, expires)
				if err := os.WriteFile(filepath.Join(v.pki, "host.crt"), []byte(short.certPEM), 0600); err != nil {
					t.Fatal(err)
				}
				installed = time.Now()
			}})
			target := sha256.Sum256(f.attempt.pair.Certificate[0])
			staging := time.Now()
			for i := range f.producers {
				// Use the real exporter's native page size in both modes while
				// retaining every original and the signed target certificate binding.
				f.requests[i].MaxRecords = AutomationExportMaxRecords
				f.stage(t, i, 11, true)
			}
			staged := time.Now()
			p, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
			verified := time.Now()
			t.Logf("actual host expiry mode=%s installToStage=%s stageAllOriginals=%s VerifyCurrent=%s remainingNativeAtReturn=%s nativeInterval=8s observationLifetime=%s", mode, staging.Sub(installed), staged.Sub(staging), verified.Sub(staged), expires.Sub(verified), sourceTargetObservationLifetime)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Discard()
			if sha256.Sum256(p.attempt.pair.Certificate[0]) != target {
				t.Fatal("current proof changed original receiver certificate")
			}
			for i, publication := range p.publications {
				if publication.id != f.requests[i].Publication || publication.manifest.Target.Certificate != hex.EncodeToString(target[:]) {
					t.Fatal("original publication target binding changed")
				}
			}
			active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
			reached := false
			f.receiver.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { reached = true; time.Sleep(time.Until(expires) + 25*time.Millisecond); return nil }}
			err = f.receiver.consumeCurrent(context.Background(), p)
			if !reached || err == nil || !strings.Contains(err.Error(), "host certificate not currently valid") {
				t.Fatal("actual host certificate survived leased SQL wait", reached, err)
			}
			if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
				t.Fatal("native expiry refusal changed ACTIVE/original spool")
			}
		})
	}
}

func TestReceiverCurrentConcurrentClientClose(t *testing.T) {
	f := currentProofFixture(t)
	p, err := f.receiver.VerifyCurrent(context.Background(), f.attempt)
	if err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	f.receiver.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error { close(entered); <-release; return nil }}
	consumed := make(chan error, 1)
	go func() { consumed <- f.receiver.consumeCurrent(context.Background(), p) }()
	<-entered
	closed := make(chan error, 1)
	go func() { closed <- f.local.c.Close() }()
	select {
	case e := <-closed:
		t.Fatal("client close escaped executing FULL owner", e)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err = <-consumed; err != nil {
		t.Fatal(err)
	}
	if err = <-closed; err != nil {
		t.Fatal(err)
	}
	if len(f.receiver.proofs) != 0 || len(p.caps) != 0 {
		t.Fatal("close retained authority after terminal")
	}
}
