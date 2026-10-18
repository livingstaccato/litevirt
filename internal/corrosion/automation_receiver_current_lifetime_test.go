package corrosion

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

const currentLifetimeFixtureTTL = 30 * time.Second
const currentLifetimeCrossingPad = 25 * time.Millisecond

// These waits run synchronously: cancellation never leaves a sleeping owner.
func currentLifetimeWait(ctx context.Context, until time.Time) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	timer := time.NewTimer(time.Until(until))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}

func currentLifetimeContext(t *testing.T, deadline time.Time) (context.Context, context.CancelFunc) {
	t.Helper()
	if enclosing, ok := t.Deadline(); ok && enclosing.Before(deadline) {
		deadline = enclosing
	}
	return context.WithDeadline(context.Background(), deadline)
}

// Include every authenticated original field, but exclude freshly derived bounds.
func currentLifetimeOriginal(t *testing.T, p receiverPublication) [32]byte {
	t.Helper()
	raw, err := json.Marshal(struct {
		ID       string
		Manifest sourceManifest
		Chain    [][]byte
		Bytes    [3]int64
		Digests  [3][32]byte
	}{p.id, p.manifest, p.chain, p.metadataBytes, p.metadataDigests})
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(raw)
}

func currentLifetimeConsume(t *testing.T, f *aggregateFixture, expires, issued time.Time, mode string) {
	t.Helper()
	staged := time.Now()
	target := sha256.Sum256(f.attempt.pair.Certificate[0])
	originals := make(map[string][32]byte)
	for name, publication := range f.attempt.publications {
		originals[name] = currentLifetimeOriginal(t, publication)
	}
	// Retain exact installed PEM bytes as well as authenticated original DER.
	installed := make(map[string][32]byte)
	for _, v := range append(append([]*claimTestVoter(nil), f.voters...), f.local) {
		path := filepath.Join(v.pki, "host.crt")
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		installed[path] = sha256.Sum256(raw)
	}
	ctx, cancel := currentLifetimeContext(t, expires.Add(10*time.Second))
	defer cancel()
	if !staged.Before(expires.Add(-7 * time.Second)) {
		t.Fatalf("setup exhausted native reserve: issued=%s staged=%s expiry=%s", issued, staged, expires)
	}
	if err := currentLifetimeWait(ctx, expires.Add(-8*time.Second)); err != nil {
		t.Fatal("pre-Verify wait", err)
	}
	entry := time.Now()
	remaining := expires.Sub(entry)
	if remaining < 7*time.Second || remaining > 8*time.Second {
		t.Fatalf("pre-Verify native reserve missed: entry=%s expiry=%s remaining=%s", entry, expires, remaining)
	}
	p, err := f.receiver.VerifyCurrent(ctx, f.attempt)
	verified := time.Now()
	if err != nil {
		t.Fatalf("fresh VerifyCurrent at %s (expiry %s): %v", verified, expires, err)
	}
	defer p.Discard()
	if p.attempt == f.attempt || p.attempt.at.Before(entry) || !p.attempt.at.After(f.attempt.at) || p.attempt.id != f.attempt.id || !bytes.Equal(p.attempt.binding, f.attempt.binding) || !sameSourceRequest(p.attempt.request, f.attempt.request) || !sameReceiverFacts(p.attempt.facts, f.attempt.facts) || p.attempt.view.RootDigest() != f.attempt.view.RootDigest() {
		t.Fatal("fresh verification changed durable binding or reused old authority")
	}
	if !verified.Before(expires) || sha256.Sum256(p.attempt.pair.Certificate[0]) != target || !bytes.Equal(p.attempt.pair.Certificate[0], f.attempt.pair.Certificate[0]) {
		t.Fatal("native certificate expired during Verify or receiver certificate changed")
	}
	if len(p.publications) != len(originals) || len(p.sources) != len(f.producers) || p.observed.Before(entry) {
		t.Fatal("missing originals or fresh observations")
	}
	unrelatedBound := f.attempt.notAfter
	retainUnrelated := func(bound time.Time) {
		if bound.Before(unrelatedBound) {
			unrelatedBound = bound
		}
	}
	for i, publication := range p.publications {
		if currentLifetimeOriginal(t, publication) != originals[publication.manifest.Source] || publication.id != f.requests[i].Publication || publication.manifest.Target.Certificate != hex.EncodeToString(target[:]) {
			t.Fatal("authenticated original publication/source/target bytes changed")
		}
		if mode == "counted" && !publication.notAfter.Equal(expires) {
			t.Fatal("original short ordinary accept was not counted", publication.notAfter, expires)
		}
		if mode != "counted" {
			retainUnrelated(publication.notAfter)
		}
	}
	for _, s := range p.sources {
		if s.observed.Before(entry) || s.observed.Before(p.observed) || s.observed.After(verified) || !bytes.Equal(s.peer.Chain[0], f.attempt.publications[s.peer.Host.Name].chain[0]) {
			t.Fatal("source observation was stale or original source certificate changed")
		}
		_, bound, e := p.attempt.view.VerifyHostCertificate(s.peer.Chain, s.peer.Host.Name)
		if e != nil || !bound.After(expires) && !(mode == "source" && s.peer.Host.Name == f.voters[0].name && bound.Equal(expires)) {
			t.Fatal("unexpected native source interval", s.peer.Host.Name, bound, e)
		}
		if mode == "source" && s.peer.Host.Name == f.voters[0].name && !bound.Equal(expires) {
			t.Fatal("short strict source chain bound lost", bound, expires)
		}
		if mode != "source" || s.peer.Host.Name != f.voters[0].name {
			retainUnrelated(bound)
		}
	}
	_, receiverBound, e := p.attempt.view.VerifyHostCertificate(p.attempt.pair.Certificate, f.local.name)
	if e != nil || mode == "receiver" && !receiverBound.Equal(expires) || mode != "receiver" && !receiverBound.After(expires) {
		t.Fatal("unexpected strict receiver chain bound", receiverBound, e)
	}
	if mode != "receiver" {
		retainUnrelated(receiverBound)
	}
	if mode == "counted" {
		if !p.attempt.notAfter.Equal(expires) || !f.attempt.notAfter.After(expires) {
			t.Fatal("publication-only real signer interval was not retained", p.attempt.notAfter, f.attempt.notAfter)
		}
	} else if !p.attempt.notAfter.After(expires) {
		t.Fatal("unrelated counted interval would mask native expiry", p.attempt.notAfter)
	}
	active, spool := receiverActive(t, f.local.c), receiverStored(t, f.local.c)
	var seamEntry, seamExit time.Time
	f.receiver.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error {
		seamEntry = time.Now()
		if !seamEntry.Before(expires) {
			return fmt.Errorf("native certificate already expired at FULL seam: %s >= %s", seamEntry, expires)
		}
		if e := currentLifetimeWait(ctx, expires.Add(currentLifetimeCrossingPad)); e != nil {
			return e
		}
		seamExit = time.Now()
		return nil
	}}
	err = f.receiver.consumeCurrent(ctx, p)
	terminal := time.Now()
	observationDeadline := p.observed.Add(sourceTargetObservationLifetime)
	t.Logf("expiry mode=%s fixtureCertificateTTL=%s issued=%s expiry=%s actualIssuedLifetime=%s stageComplete=%s setupElapsed=%s VerifyEntry=%s nativeAtEntry=%s VerifyReturn=%s VerifyElapsed=%s nativeAtReturn=%s observation=%s observationDeadline=%s seamEntry=%s seamExit=%s terminal=%s targetSHA256=%x originals=%v", mode, currentLifetimeFixtureTTL, issued, expires, expires.Sub(issued), staged, staged.Sub(issued), entry, remaining, verified, verified.Sub(entry), expires.Sub(verified), p.observed, observationDeadline, seamEntry, seamExit, terminal, target, originals)
	want := "host certificate not currently valid"
	if mode == "counted" {
		want = "current counted signer expired"
	}
	if seamEntry.IsZero() || seamEntry.Before(verified) || !seamEntry.Before(expires) || seamExit.Before(expires.Add(currentLifetimeCrossingPad)) || terminal.Before(seamExit) || !seamExit.Before(observationDeadline) || !terminal.Before(observationDeadline) || !terminal.Before(unrelatedBound) || ctx.Err() != nil {
		t.Fatal("expiry not causally isolated from setup/observation/cancellation", err, ctx.Err())
	}
	if err == nil || err.Error() != want {
		t.Fatal("expiry survived actual leased FULL wait or had wrong cause", want, err)
	}
	if receiverActive(t, f.local.c) != active || receiverStored(t, f.local.c) != spool {
		t.Fatal("expiry refusal changed ACTIVE/original spool")
	}
	for path, fingerprint := range installed {
		raw, e := os.ReadFile(path)
		if e != nil || sha256.Sum256(raw) != fingerprint {
			t.Fatal("installed certificate changed after initial issuance", path, e)
		}
	}
}

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
	var expires, issued time.Time
	shortAccepts := make(map[string]ClaimAccept)
	f := newAggregateFixture(t, aggregateFixtureOptions{Old: 3, Sources: 2, Heads: []int{2, 1}, BeforePublish: func(t *testing.T, f *aggregateFixture) {
		issued = time.Now()
		expires = issued.Truncate(time.Second).Add(currentLifetimeFixtureTTL)
		// The real extra ordinary signer is absent from the receiver's certificate
		// metadata and from the two directly observed source serving chains.
		signer := currentShortSigner(t, f.ca, f.voters[2], expires)
		leaf, err := parseCertPEM([]byte(signer.certPEM))
		if err != nil || !leaf.NotAfter.Equal(expires) {
			t.Fatal("parsed signer expiry differs", err)
		}
		expires = leaf.NotAfter
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
					shortAccepts[v.name] = cert.Accepts[i]
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
		raw, err := f.receiver.metadata(context.Background(), f.attempt, f.voters[i].name, 2, f.requests[i], AutomationExportPage{})
		if err != nil {
			t.Fatal(err)
		}
		var membership sourceMembershipEvidence
		if err = json.Unmarshal(raw, &membership); err != nil {
			t.Fatal(err)
		}
		cert, err := sourceCertificate(membership.Certificate)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, accept := range cert.Accepts {
			if accept.Voter == f.voters[2].name {
				want := shortAccepts[f.voters[i].name]
				if accept.CertPEM != want.CertPEM || !bytes.Equal(accept.Signature, want.Signature) {
					t.Fatal("original short accept bytes changed")
				}
				found = true
			}
		}
		if !found {
			t.Fatal("original publication omitted short ordinary accept")
		}
	}
	currentLifetimeConsume(t, f, expires, issued, "counted")
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
				installed = time.Now()
				expires = installed.Truncate(time.Second).Add(currentLifetimeFixtureTTL)
				short := currentShortSigner(t, f.ca, v, expires)
				leaf, err := parseCertPEM([]byte(short.certPEM))
				if err != nil || !leaf.NotAfter.Equal(expires) {
					t.Fatal("parsed host expiry differs", err)
				}
				expires = leaf.NotAfter
				if err := os.WriteFile(filepath.Join(v.pki, "host.crt"), []byte(short.certPEM), 0600); err != nil {
					t.Fatal(err)
				}
			}})
			for i := range f.producers {
				// Use the real exporter's native page size in both modes while
				// retaining every original and the signed target certificate binding.
				f.requests[i].MaxRecords = AutomationExportMaxRecords
				f.stage(t, i, 11, true)
			}
			currentLifetimeConsume(t, f, expires, installed, mode)
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
