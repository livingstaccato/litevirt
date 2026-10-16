package pki

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHostTrustStrictHostPredicates(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wrong-cn", "client-only", "server-only", "any-only", "expired", "future", "foreign-root"} {
		t.Run(name, func(t *testing.T) {
			leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
			signer, signingKey := ca, key
			switch name {
			case "wrong-cn":
				leaf.RawSubject = nil
				leaf.Subject.CommonName = "another-host"
			case "client-only":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			case "server-only":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			case "any-only":
				leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
			case "expired":
				leaf.NotAfter = time.Now().Add(-time.Minute)
			case "future":
				leaf.NotBefore = time.Now().Add(time.Hour)
			case "foreign-root":
				other := setupPKI(t)
				signer, signingKey, err = loadCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key"))
				if err != nil {
					t.Fatal(err)
				}
			}
			der, err := x509.CreateCertificate(rand.Reader, leaf, signer, leaf.PublicKey, signingKey)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := view.ValidateHostCertificate(ctx, [][]byte{der}, "test-host"); err == nil {
				t.Fatalf("strict host validation accepted %s", name)
			}
		})
	}
}

func TestHostTrustEqualNumberCRLUnionInvalidatesCapability(t *testing.T) {
	dir := setupPKI(t)
	a := observerPKI(t, dir, "a")
	b := observerPKI(t, dir, "b")
	ctx := context.Background()
	ca, key, err := loadCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	makeCRL := func(cert *x509.Certificate) []byte {
		t.Helper()
		der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{Number: big.NewInt(77), ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(time.Hour), RevokedCertificateEntries: []x509.RevocationListEntry{{SerialNumber: cert.SerialNumber, RevocationTime: time.Now().Add(-time.Minute)}}}, ca, key)
		if err != nil {
			t.Fatal(err)
		}
		return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
	}
	ac, bc := readLeaf(t, filepath.Join(a, "host.crt")), readLeaf(t, filepath.Join(b, "host.crt"))
	if _, _, err := InstallCRL(dir, makeCRL(ac)); err != nil {
		t.Fatal(err)
	}
	before, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	cap, err := before.ValidateHostCertificate(ctx, [][]byte{bc.Raw}, "b")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := InstallCRL(dir, makeCRL(bc)); err != nil {
		t.Fatal(err)
	}
	if lease, err := AcquireHostCertificateLease(ctx, dir, cap); err == nil {
		lease.Release()
		t.Fatal("equal-number CRL branch left capability active")
	}
	after, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if before.EvidenceDigest() == after.EvidenceDigest() {
		t.Fatal("incomparable CRL union did not change evidence identity")
	}
	for _, cert := range []*x509.Certificate{ac, bc} {
		if _, err := after.ValidateHostCertificate(ctx, [][]byte{cert.Raw}, cert.Subject.CommonName); err == nil {
			t.Fatal("strict snapshot omitted a signed equal-number CRL branch")
		}
	}
}

func TestHostTrustAbandonedAndContinuedSuccessor(t *testing.T) {
	dir := setupPKI(t)
	obs := observerPKI(t, dir, "observer")
	ctx := context.Background()
	old := readLeaf(t, filepath.Join(dir, "host.crt"))
	ca, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if _, _, err := RenewLocal(ca, key, dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	successor := readLeaf(t, filepath.Join(dir, "host.crt"))
	if !NoteSuccessor(obs, successor) {
		t.Fatal("successor not learned")
	}
	if _, _, err := RenewLocal(ca, key, dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	continuation := readLeaf(t, filepath.Join(dir, "host.crt"))
	if err := GenerateCRL(ca, key, filepath.Join(obs, "crl.pem"), []string{successor.SerialNumber.Text(16)}); err != nil {
		t.Fatal(err)
	}
	abandoned, err := CaptureHostTrust(ctx, obs, "observer")
	if err != nil {
		t.Fatal(err)
	}
	cap, err := abandoned.ValidateHostCertificate(ctx, [][]byte{old.Raw}, "test-host")
	if err != nil {
		t.Fatal("abandoned successor did not restore predecessor", err)
	}
	if !NoteSuccessor(obs, continuation) {
		t.Fatal("continuation not learned")
	}
	if lease, err := AcquireHostCertificateLease(ctx, obs, cap); err == nil {
		lease.Release()
		t.Fatal("standing continuation did not invalidate prior capability")
	}
	continued, err := CaptureHostTrust(ctx, obs, "observer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := continued.ValidateHostCertificate(ctx, [][]byte{old.Raw}, "test-host"); err == nil {
		t.Fatal("revoked successor with standing continuation restored predecessor")
	}
}

func TestHostTrustRestartProcess(t *testing.T) {
	dir := os.Getenv("LITEVIRT_TRUST_RESTART")
	if dir == "" {
		t.Skip("subprocess only")
	}
	var retained struct {
		Nonce      [32]byte
		Capability HostCertificateValidation
	}
	if err := json.Unmarshal(mustReadFile(t, filepath.Join(dir, "retained-validation.json")), &retained); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if lease, err := AcquireHostCertificateLease(ctx, dir, &retained.Capability); err == nil {
		lease.Release()
		t.Fatal("serialized prior-process capability resurrected")
	}
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if view.nonce == retained.Nonce {
		t.Fatal("new process reused previous owner nonce")
	}
	pair, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireHostCertificateLease(ctx, dir, cap)
	if err != nil {
		t.Fatal("fresh verification did not progress", err)
	}
	lease.Release()
}

func TestHostTrustRestartRequiresFreshVerification(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(struct {
		Nonce      [32]byte
		Capability *HostCertificateValidation
	}{view.nonce, cap})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "retained-validation.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestHostTrustRestartProcess$")
	child.Env = append(os.Environ(), "LITEVIRT_TRUST_RESTART="+dir)
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("restart process: %v\n%s", err, output)
	}
}
