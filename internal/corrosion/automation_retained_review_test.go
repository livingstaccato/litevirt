package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// Copy actual published immutable bytes only; no receipt/completion/adoption.
func retainedReviewPublication(t *testing.T, ctx context.Context, tx *LocalTx, a *AutomationReceiverAttempt, publication receiverPublication, view *pki.HostTrust) (receiverPublication, error) {
	t.Helper()
	m := publication.manifest
	address, err := retainedAddress(strings.Repeat("e", 64), 1, m.Source, publication.id, retainedSourceStream)
	if err != nil {
		t.Fatal(err)
	}
	d := retainedObjectDescriptor{1, "source", retainedObjectLayout("source"), publication.id, m.Source, m.Incarnation, nil}
	sections, _, _ := retainedObjectSections("source")
	for i := 0; i < 3; i++ {
		n := publication.metadataBytes[i]
		sum := publication.metadataDigests[i]
		d.ComponentInventories = append(d.ComponentInventories, automationCutInventory{sections[i], 1, (n + AutomationExportChunkBytes - 1) / AutomationExportChunkBytes, n, hex.EncodeToString(sum[:])})
	}
	d.ComponentInventories = append(d.ComponentInventories, m.Cut.Inventory...)
	if err = walkAutomationStoredFrames(ctx, tx, "local_automation_receiver_records", "attempt=? AND source=?", []any{a.id, m.Source}, "component", maxAutomationCutRecordBytes, func(c int, n int64, body []byte) error { return address.save(ctx, tx, c, n, body) }); err != nil {
		t.Fatal(err)
	}
	original, err := decodeReceiverBinding(a.id, a.request.Job, a.request.Revision, a.binding)
	if err != nil {
		t.Fatal(err)
	}
	roster := aggregateRosterEntry{m.Source, m.Incarnation, sourceDigest([]byte("litevirt/receiver-source-audit/v1"), []byte(a.id), []byte(m.Source), []byte(publication.id), []byte(m.Root)), publication.id, m.Root, m.Cut.ID, strings.Repeat("a", 64)}
	return address.publication(ctx, tx, d, original, roster, view)
}

func TestRetainedOriginalLaterRetirement(t *testing.T) {
	for _, mode := range []string{"unexpired-revoked", "unexpired-superseded"} {
		t.Run(mode, func(t *testing.T) {
			producer, r, q, exportCtx, _ := receiverFixture(t)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, producer, r, a, q, exportCtx, 11)
			publication := a.publications["a"]
			original := append([]byte(nil), publication.chain[0]...)
			leaf, err := x509.ParseCertificate(original)
			if err != nil {
				t.Fatal(err)
			}
			if !time.Now().Before(leaf.NotAfter) {
				t.Fatal("original already expired")
			}
			if mode == "unexpired-revoked" {
				err = pki.GenerateCRL(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), filepath.Join(r.dir, "crl.pem"), []string{leaf.SerialNumber.Text(16)})
			} else {
				_, _, err = pki.RenewLocal(filepath.Join(producer.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), producer.dir, "a")
				if err == nil {
					successor, e := pki.ServedHostCertificate(producer.dir)
					err = e
					if e == nil && !pki.NoteSuccessor(r.dir, successor) {
						t.Fatal("real successor was not recorded")
					}
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			view, err := pki.CaptureHostTrust(ctx, r.dir, r.client.hostName)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = view.VerifyHostCertificate(publication.chain, "a"); err == nil {
				t.Fatal("ordinary live retired original accepted")
			}
			active, stored := receiverActive(t, r.client), receiverStored(t, r.client)
			tx0, err := r.client.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx0.Rollback()
			got, err := retainedReviewPublication(t, ctx, &LocalTx{tx: tx0}, a, publication, view)
			if err != nil {
				t.Fatalf("unchanged previously authorized original lost provenance after later retirement: %v", err)
			}
			if got.id != publication.id || !bytes.Equal(got.chain[0], original) {
				t.Fatal("original provenance bytes changed")
			}
			if err = tx0.Rollback(); err != nil {
				t.Fatal(err)
			}
			if receiverActive(t, r.client) != active || receiverStored(t, r.client) != stored {
				t.Fatal("inert original provenance changed state")
			}
		})
	}
}

// Issue two actual intermediate certificates for the same issuer key. The
// exact same leaf verifies through either; TLS serves the long path while the
// signed envelope can carry the short path. Nothing manufactures adoption.
func retainedReviewChains(t *testing.T, v *claimTestVoter, leafExpiry, shortExpiry time.Time) (*tls.Certificate, time.Time) {
	t.Helper()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(v.pki, name))
		if err != nil {
			t.Fatal(err)
		}
		b, _ := pem.Decode(raw)
		if b == nil {
			t.Fatal("PEM missing")
		}
		return b.Bytes
	}
	ca, err := x509.ParseCertificate(read("ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.ParseECPrivateKey(read("ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(read("host.crt"))
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(77001), Subject: pkix.Name{CommonName: "retained selected issuer"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	issue := func(c *x509.Certificate, parent *x509.Certificate, pub any, signer any) []byte {
		der, err := x509.CreateCertificate(rand.Reader, c, parent, pub, signer)
		if err != nil {
			t.Fatal(err)
		}
		return der
	}
	longDER := issue(template, ca, &issuerKey.PublicKey, key)
	issuer, err := x509.ParseCertificate(longDER)
	if err != nil {
		t.Fatal(err)
	}
	template.NotAfter = shortExpiry
	shortDER := issue(template, ca, &issuerKey.PublicKey, key)
	if !leafExpiry.IsZero() {
		leaf.NotAfter = leafExpiry
	}
	leaf.AuthorityKeyId = nil
	leafDER := issue(leaf, issuer, leaf.PublicKey, issuerKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: longDER})...)
	if err = os.WriteFile(filepath.Join(v.pki, "host.crt"), chain, 0600); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(v.pki, "host.crt"), filepath.Join(v.pki, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	pair.Certificate = [][]byte{leafDER, shortDER}
	return &pair, shortExpiry
}

func TestRetainedHolderExactChainHandoff(t *testing.T) {
	for _, name := range []string{"stable", "signed-intermediate-expires", "observed-intermediate-expires"} {
		expire := name != "stable"
		t.Run(name, func(t *testing.T) {
			var signedPair *tls.Certificate
			var expires time.Time
			producer, intent, target := sourcePreparationFixtureWithInitialSeed(t, "", func(v *claimTestVoter) {
				expires = time.Now().Truncate(time.Second).Add(6 * time.Second)
				if !expire {
					expires = time.Now().Truncate(time.Second).Add(time.Hour)
				}
				signedPair, _ = retainedReviewChains(t, v, time.Time{}, expires)
				if name == "observed-intermediate-expires" {
					longPair, err := tls.LoadX509KeyPair(filepath.Join(v.pki, "host.crt"), filepath.Join(v.pki, "host.key"))
					if err != nil {
						t.Fatal(err)
					}
					var shortPEM []byte
					for _, der := range signedPair.Certificate {
						shortPEM = append(shortPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
					}
					if err = os.WriteFile(filepath.Join(v.pki, "host.crt"), shortPEM, 0600); err != nil {
						t.Fatal(err)
					}
					signedPair = &longPair
				}

			}, nil)
			producer, r, q, _, _ := receiverFixtureProducer(t, producer, intent, target)
			_ = producer
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			body := retainedAdversarialHolder(t, a)
			member, _ := a.facts.Next.Member("a")
			tx0, err := r.client.db.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			host, err := sourceReadHost(ctx, &LocalTx{tx: tx0}, "a")
			tx0.Rollback()
			if err != nil {
				t.Fatal(err)
			}
			admission, _ := json.Marshal(host)
			fp := sha256.Sum256(signedPair.Certificate[0])
			body.Donor, body.DonorIncarnation, body.Signer = "a", member.Incarnation, hex.EncodeToString(fp[:])
			body.AdmissionDigest = sourceDigest([]byte("litevirt/retained-admission/v1"), admission)
			holder, err := decodeRetainedHolder(retainedSignAdversarial(t, signedPair, body, retainedHolderDomain))
			if err != nil {
				t.Fatal(err)
			}
			auth, err := r.authorizeRetainedHolder(ctx, a, holder)
			if err != nil {
				t.Fatal("actual current holder authorization", err)
			}
			if len(auth.peer.Chain) < 2 || !bytes.Equal(auth.peer.Chain[0], holder.signed.Chain[0]) || bytes.Equal(auth.peer.Chain[1], holder.signed.Chain[1]) {
				t.Fatal("real observed and signed paths did not differ")
			}
			first, err := pki.AcquireHostCertificateLease(ctx, r.dir, auth.source, auth.target)
			if err != nil {
				t.Fatal(err)
			}
			first.Release()
			caps, err := renewRetainedHolderCapabilities(ctx, a, holder)
			if err != nil {
				t.Fatal(err)
			}
			for _, cap := range caps {
				defer cap.Discard()
			}
			lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, caps...)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			active, stored := receiverActive(t, r.client), receiverStored(t, r.client)
			reached := false
			r.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error {
				reached = true
				if expire {
					time.Sleep(time.Until(expires) + 25*time.Millisecond)
				}
				return nil
			}}
			err = r.transactionGuarded(ctx, a, lease, time.Now(), nil, nil, nil, func(tx *LocalTx) error { return pinRetainedDeliveryTx(ctx, tx, holder) })
			if !reached {
				t.Fatal("actual final commit seam not reached", err)
			}
			if expire && err == nil {
				t.Fatal("exact signed holder intermediate expiry lost across capability handoff")
			}
			if !expire && err != nil {
				t.Fatal("stable exact selected chain refused", err)
			}
			// The renewed capability itself must retain the exact signed path;
			// the attempt interval separately guards the observed peer path.
			if name == "signed-intermediate-expires" && lease.Check() == nil {
				t.Fatal("renewed capability substituted observed chain for signed chain")
			}
			if name == "observed-intermediate-expires" && !a.notAfter.Equal(expires) {
				t.Fatal("actual observed intermediate interval was not retained", a.notAfter, expires)
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("holder handoff changed ACTIVE")
			}
			if expire && receiverStored(t, r.client) != stored {
				t.Fatal("expired holder did not roll back")
			}
			rows, e := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_retained_completions`)
			if e != nil || rows[0].Int64("n") != 0 {
				t.Fatal("helper test created completion", e)
			}
		})
	}
}

func TestRetainedOriginalSelectedChainFinalGuard(t *testing.T) {
	for _, expire := range []bool{false, true} {
		name := "stable"
		if expire {
			name = "original-intermediate-expires"
		}
		t.Run(name, func(t *testing.T) {
			var leafExpiry, expires, issued time.Time
			var originalChain [][]byte
			var installed [32]byte
			producer, intent, target := sourcePreparationFixtureWithInitialSeed(t, "", func(v *claimTestVoter) {
				issued = time.Now()
				leafExpiry = issued.Truncate(time.Second).Add(currentLifetimeFixtureTTL)
				expires = leafExpiry.Add(3 * time.Second)
				if !expire {
					expires = leafExpiry.Add(time.Hour)
				}
				pair, _ := retainedReviewChains(t, v, leafExpiry, expires)
				leaf, e := x509.ParseCertificate(pair.Certificate[0])
				if e != nil {
					t.Fatal(e)
				}
				issuer, e := x509.ParseCertificate(pair.Certificate[1])
				if e != nil {
					t.Fatal(e)
				}
				if !leaf.NotAfter.Equal(leafExpiry) || !issuer.NotAfter.Equal(expires) {
					t.Fatal("parsed original chain expiry differs")
				}
				leafExpiry, expires = leaf.NotAfter, issuer.NotAfter
				originalChain = pair.Certificate
				var pemChain []byte
				for _, raw := range pair.Certificate {
					pemChain = append(pemChain, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: raw})...)
				}
				if err := os.WriteFile(filepath.Join(v.pki, "host.crt"), pemChain, 0600); err != nil {
					t.Fatal(err)
				}
				installed = sha256.Sum256(pemChain)
			}, nil)
			producer, r, q, exportCtx, _ := receiverFixtureProducer(t, producer, intent, target)
			ctx := context.Background()
			a, err := r.Begin(ctx, q.Intent, nil)
			if err != nil {
				t.Fatal(err)
			}
			receiverThrough(t, producer, r, a, q, exportCtx, 11)
			publication := a.publications["a"]
			staged := time.Now()
			if !staged.Before(leafExpiry) || !staged.Before(expires) {
				t.Fatal("setup exhausted original chain lifetime", staged, leafExpiry, expires)
			}
			if _, _, err = a.view.VerifyHostCertificate(publication.chain, "a"); err != nil {
				t.Fatal("actual publication not staged while current", err)
			}
			if len(publication.chain) != len(originalChain) {
				t.Fatal("original selected path changed")
			}
			for i, der := range originalChain {
				if !bytes.Equal(publication.chain[i], der) {
					t.Fatal("original selected chain bytes changed", i)
				}
			}
			original := currentLifetimeOriginal(t, publication)
			receiverDER := sha256.Sum256(a.pair.Certificate[0])
			if publication.id != q.Publication || publication.manifest.Target.Certificate != hex.EncodeToString(receiverDER[:]) {
				t.Fatal("original source/target publication binding changed")
			}
			// Stable's issuer lasts an hour, but its positive flow is still finite.
			deadline := leafExpiry.Add(10 * time.Second)
			if expire {
				deadline = expires.Add(10 * time.Second)
			}
			ctx, cancel := currentLifetimeContext(t, deadline)
			defer cancel()
			if err = currentLifetimeWait(ctx, leafExpiry.Add(currentLifetimeCrossingPad)); err != nil {
				t.Fatal("pre-provenance wait", err)
			}
			woke := time.Now()
			remaining := expires.Sub(woke)
			if woke.Before(leafExpiry.Add(currentLifetimeCrossingPad)) || remaining <= 0 || expire && (remaining < 2*time.Second || remaining >= 3*time.Second) {
				t.Fatal("original expiry/selected issuer reserve missed", woke, leafExpiry, expires, remaining)
			}
			active, stored := receiverActive(t, r.client), receiverStored(t, r.client)
			_, receiverBound, err := a.view.VerifyHostCertificate(a.pair.Certificate, r.client.hostName)
			if err != nil || !receiverBound.After(deadline) || !a.notAfter.After(expires) {
				t.Fatal("unrelated current authority could mask original issuer expiry", receiverBound, a.notAfter, err)
			}
			cap, err := a.view.ValidateServedHost(ctx, a.pair)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := pki.AcquireHostCertificateLease(ctx, r.dir, cap)
			if err != nil {
				cap.Discard()
				t.Fatal(err)
			}
			defer lease.Release()
			var verifiedAt, seamEntry, seamExit time.Time
			r.seams = &localCommitSeams{beforeCommit: func(*sql.Tx) error {
				seamEntry = time.Now()
				if !seamEntry.After(leafExpiry) || !seamEntry.Before(expires) {
					return fmt.Errorf("original leaf/issuer invalid at FULL seam: %s, leaf %s, issuer %s", seamEntry, leafExpiry, expires)
				}
				if expire {
					if e := currentLifetimeWait(ctx, expires.Add(currentLifetimeCrossingPad)); e != nil {
						return e
					}
				}
				seamExit = time.Now()
				return nil
			}}
			var verified receiverPublication
			observed := time.Now()
			err = r.transactionGuarded(ctx, a, lease, observed, nil, nil, nil, func(tx *LocalTx) error {
				var e error
				verified, e = retainedReviewPublication(t, ctx, tx, a, publication, a.view)
				if e != nil {
					return e
				}
				verifiedAt = time.Now()
				if !verifiedAt.After(leafExpiry) || !verifiedAt.Before(expires) || currentLifetimeOriginal(t, verified) != original || !verified.notAfter.Equal(expires) {
					return fmt.Errorf("original provenance/selected live interval changed at %s: returned %s, issuer %s", verifiedAt, verified.notAfter, expires)
				}
				// Exercise the same final guard as completion, using only the actual
				// verified publication interval. No completed/adopted proof is constructed.
				if verified.notBefore.After(a.notBefore) {
					a.notBefore = verified.notBefore
				}
				if !verified.notAfter.IsZero() && verified.notAfter.Before(a.notAfter) {
					a.notAfter = verified.notAfter
				}
				if !a.notAfter.Equal(expires) {
					return fmt.Errorf("verified selected issuer did not narrow final interval: %s != %s", a.notAfter, expires)
				}
				return nil
			})
			terminal := time.Now()
			observationDeadline := observed.Add(sourceTargetObservationLifetime)
			t.Logf("selected chain mode=%s fixtureCertificateTTL=%s issued=%s leafExpiry=%s issuerExpiry=%s actualIssuedLifetime=%s stageComplete=%s setupElapsed=%s wake=%s issuerReserve=%s observation=%s observationDeadline=%s originalVerified=%s seamEntry=%s seamExit=%s terminal=%s leafSHA256=%x issuerSHA256=%x targetSHA256=%x originalSHA256=%x", name, currentLifetimeFixtureTTL, issued, leafExpiry, expires, leafExpiry.Sub(issued), staged, staged.Sub(issued), woke, remaining, observed, observationDeadline, verifiedAt, seamEntry, seamExit, terminal, sha256.Sum256(originalChain[0]), sha256.Sum256(originalChain[1]), receiverDER, original)
			if seamEntry.IsZero() || seamExit.IsZero() {
				t.Fatal("original verification/final commit seam not reached", err)
			}
			if ctx.Err() != nil || !seamExit.Before(observationDeadline) || !terminal.Before(observationDeadline) || !terminal.Before(receiverBound) || !terminal.After(leafExpiry) {
				t.Fatal("original issuer outcome not isolated from observation/context/unrelated native expiry", err, ctx.Err())
			}
			if expire && (err == nil || err.Error() != "receiver membership authorization expired" || seamExit.Before(expires.Add(currentLifetimeCrossingPad))) {
				t.Fatal("required original intermediate interval lost or wrong final refusal", err)
			}
			if !expire && (err != nil || !terminal.Before(expires)) {
				t.Fatal("stable original selected chain refused", err)
			}
			if !verified.notAfter.Equal(expires) {
				t.Error("effective required nonleaf interval not returned", verified.notAfter, expires)
			}
			if receiverActive(t, r.client) != active {
				t.Fatal("original interval changed ACTIVE")
			}
			if expire && receiverStored(t, r.client) != stored {
				t.Fatal("expired original did not roll back")
			}
			if !expire {
				address, e := retainedAddress(strings.Repeat("e", 64), 1, "a", publication.id, retainedSourceStream)
				if e != nil {
					t.Fatal(e)
				}
				originalRows, e := r.client.Query(ctx, `SELECT component,ordinal,record FROM local_automation_receiver_records WHERE attempt=? AND source=? ORDER BY component,ordinal`, a.id, "a")
				if e != nil {
					t.Fatal(e)
				}
				retainedRows, e := r.client.Query(ctx, `SELECT component,ordinal,record FROM local_automation_receiver_records WHERE attempt=? AND source=? ORDER BY component,ordinal`, address.namespace, address.source)
				if e != nil {
					t.Fatal(e)
				}
				want, e := json.Marshal(originalRows)
				if e != nil {
					t.Fatal(e)
				}
				got, e := json.Marshal(retainedRows)
				if e != nil || len(originalRows) == 0 || !bytes.Equal(got, want) {
					t.Fatal("stable expired-leaf FULL commit did not preserve every original frame", e)
				}
			}
			raw, e := os.ReadFile(filepath.Join(producer.dir, "host.crt"))
			if e != nil || sha256.Sum256(raw) != installed {
				t.Fatal("original source chain changed after issuance", e)
			}
			rows, e := r.client.Query(ctx, `SELECT COUNT(*) AS n FROM local_automation_retained_completions`)
			if e != nil || rows[0].Int64("n") != 0 {
				t.Fatal("original interval test created completion", e)
			}
		})
	}
}
