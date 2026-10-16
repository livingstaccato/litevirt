package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestHostTrustRefusesInvalidInstalledIdentity(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	if _, err := CaptureHostTrust(ctx, dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	foreign := setupPKI(t)
	mintInto(t, foreign, dir, "test-host")
	if _, err := ServedHostKeyPair(dir); err != nil {
		t.Fatal("legacy handshake availability changed", err)
	}
	if _, err := CaptureHostTrust(ctx, dir, "test-host"); err == nil {
		t.Fatal("strict capture vouched for a refused on-disk identity")
	}
}

func TestHostTrustLearnsServedRenewalBeforeCapture(t *testing.T) {
	dir := setupPKI(t)
	old, err := ServedHostCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	staging, cert := signForStaging(t, dir)
	if _, _, err := InstallRenewal(dir, staging, cert); err != nil {
		t.Fatal(err)
	}
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.ValidateHostCertificate(context.Background(), [][]byte{old.Raw}, "test-host"); err == nil {
		t.Fatal("strict capture ignored its authenticated served successor")
	}
	if _, err := os.Stat(filepath.Join(dir, supersededFile)); err != nil {
		t.Fatal("served successor was not durable before capture", err)
	}
}

func TestHostTrustRejectsCAAsHostAndCancelledValidation(t *testing.T) {
	dir := setupPKI(t)
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf.IsCA = true
	leaf.BasicConstraintsValid = true
	leaf.KeyUsage |= x509.KeyUsageCertSign
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.ValidateHostCertificate(context.Background(), [][]byte{der}, "test-host"); err == nil {
		t.Error("CA certificate was accepted as a proper host leaf")
	}
	good := readLeaf(t, filepath.Join(dir, "host.crt"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Repetition distinguishes deterministic cancellation from select choosing
	// a ready gate at random when both cases are ready.
	for i := 0; i < 32; i++ {
		if _, err := view.ValidateHostCertificate(ctx, [][]byte{good.Raw}, "test-host"); err == nil {
			t.Error("cancelled validation minted a process capability")
			break
		}
	}
}

func TestHostTrustUnsavedSuccessorAndDurability(t *testing.T) {
	dir := setupPKI(t)
	obs := observerPKI(t, dir, "observer")
	ctx := context.Background()
	if _, err := CaptureHostTrust(ctx, obs, "observer"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	cert, err := ServedHostCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	trustDurabilitySeam = func(string) error { return errors.New("injected durability failure") }
	t.Cleanup(func() { trustDurabilitySeam = nil })
	if !NoteSuccessor(obs, cert) {
		t.Fatal("failed save discarded memory evidence")
	}
	if _, err := CaptureHostTrust(ctx, obs, "observer"); err == nil {
		t.Fatal("unsaved successor minted strict evidence")
	}
	trustDurabilitySeam = nil
	view, err := CaptureHostTrust(ctx, obs, "observer")
	if err != nil {
		t.Fatal("repair did not establish durable snapshot", err)
	}
	prev, _ := RenewedFromSerial(cert)
	if !view.standing("test-host", prev, 0) {
		t.Fatal("repair lost the learned successor")
	}
	for _, stage := range []string{"file-sync", "directory-sync", "reopen"} {
		t.Run(stage, func(t *testing.T) {
			trustDurabilitySeam = func(at string) error {
				if at == stage {
					return errors.New("injected " + stage)
				}
				return nil
			}
			if _, err := CaptureHostTrust(ctx, obs, "observer"); err == nil {
				t.Fatal("failed durability minted stable snapshot")
			}
			trustDurabilitySeam = nil
			if _, err := CaptureHostTrust(ctx, obs, "observer"); err != nil {
				t.Fatal("durability repair failed", err)
			}
		})
	}
}

func TestHostTrustRejectsMalformedOrRegressedEvidence(t *testing.T) {
	for _, name := range []string{"ca.crt", "crl.pem", supersededFile} {
		t.Run(name, func(t *testing.T) {
			dir := setupPKI(t)
			ctx := context.Background()
			if _, err := CaptureHostTrust(ctx, dir, "test-host"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, name), []byte("not signed evidence"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := CaptureHostTrust(ctx, dir, "test-host"); err == nil {
				t.Fatal("malformed trust material accepted")
			}
		})
	}
}

func TestHostLeaseRechecksExpiryAfterWait(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = time.Now().Truncate(time.Second).Add(2 * time.Second)
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	cap1, err := view.ValidateHostCertificate(ctx, [][]byte{der}, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	cap2, err := view.ValidateHostCertificate(ctx, [][]byte{der}, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireHostCertificateLease(ctx, dir, cap1)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	waited := make(chan error, 1)
	go func() {
		next, e := AcquireHostCertificateLease(ctx, dir, cap2)
		if next != nil {
			next.Release()
		}
		waited <- e
	}()
	time.Sleep(time.Until(leaf.NotAfter) + 30*time.Millisecond)
	if err := lease.Check(); err == nil {
		t.Fatal("precommit check ignored current expiry")
	}
	lease.Release()
	if err := <-waited; err == nil {
		t.Fatal("certificate expiry during lease wait was ignored")
	}
}

func TestTrustSuccessorWriterPreservesMalformedEvidence(t *testing.T) {
	dir := setupPKI(t)
	obs := observerPKI(t, dir, "observer")
	if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	cert, err := ServedHostCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	damaged := []byte("unreadable retained evidence")
	path := filepath.Join(obs, supersededFile)
	if err := os.WriteFile(path, damaged, 0600); err != nil {
		t.Fatal(err)
	}
	if !NoteSuccessor(obs, cert) {
		t.Fatal("valid renewal observation was lost")
	}
	if got := mustReadFile(t, path); string(got) != string(damaged) {
		t.Fatal("successor writer replaced malformed retained evidence")
	}
	prev, _ := RenewedFromSerial(cert)
	if _, ok := SupersededBy(obs, "test-host", prev); !ok {
		t.Fatal("unsaved renewal no longer affects legacy pinning")
	}
	if _, err := CaptureHostTrust(context.Background(), obs, "observer"); err == nil {
		t.Fatal("malformed evidence yielded strict capture")
	}
}

func TestHostTrustOwnsServedIdentity(t *testing.T) {
	dir := setupPKI(t)
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	first := pair.Certificate[0][0]
	name := pair.Leaf.Subject.CommonName
	t.Cleanup(func() { pair.Certificate[0][0] = first; pair.Leaf.Subject.CommonName = name })
	pair.Certificate[0][0] ^= 0xff
	pair.Leaf.Subject.CommonName = "changed-by-caller"
	if view.served.Certificate[0][0] != first || view.served.Leaf.Subject.CommonName != name {
		t.Fatal("immutable trust snapshot aliases caller-visible served certificate")
	}
}

func TestHostLeasePeerValidationRetainsSourceExpiry(t *testing.T) {
	dir := setupPKI(t)
	peer := observerPKI(t, dir, "peer")
	ctx := context.Background()
	leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = time.Now().Truncate(time.Second).Add(2 * time.Second)
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(peer)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, "peer")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireHostCertificateLease(ctx, dir, cap)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	time.Sleep(time.Until(leaf.NotAfter) + 20*time.Millisecond)
	if err := lease.Check(); err == nil {
		t.Fatal("peer validation lease ignored source identity expiry before commit")
	}
}

func TestHostValidationRechecksSourceExpiryAfterRegistrationWait(t *testing.T) {
	dir := setupPKI(t)
	peer := observerPKI(t, dir, "peer")
	ctx := context.Background()
	leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	leaf.NotAfter = time.Now().Truncate(time.Second).Add(2 * time.Second)
	der, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "host.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatal(err)
	}
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(peer)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the actual registration gate while the source validity interval ends.
	view.owner.gate <- struct{}{}
	done := make(chan error, 1)
	go func() { _, err := view.ValidateHostCertificate(ctx, pair.Certificate, "peer"); done <- err }()
	time.Sleep(time.Until(leaf.NotAfter) + 20*time.Millisecond)
	<-view.owner.gate
	if err := <-done; err == nil {
		t.Fatal("source expired during registration wait but minted a capability")
	}
}
