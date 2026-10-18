package corrosion

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// Real signed chains exercise only the inert provenance predicate, never a
// fabricated adopted donor or completed proof. The actual receiver snapshot
// supplies the root, CRL and current trust policy.
func TestRetainedExpiredLeafRemainingChain(t *testing.T) {
	producer, r, _, _, _ := receiverFixture(t)
	ctx := context.Background()
	read := func(name string) []byte {
		raw, err := os.ReadFile(filepath.Join(producer.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Fatal("PEM missing")
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
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	for index, tc := range []struct {
		name string
		want bool
	}{
		{"current-chain-expired-leaf", true},
		{"expired-leaf-and-expired-intermediate", false},
		{"expired-leaf-and-future-intermediate", false},
		{"expired-leaf-invalid-signature", false},
		{"expired-leaf-foreign-root", false},
		{"valid-path-unused-expired-extra", true},
		{"current-leaf-valid-original", true},
		{"future-leaf-no-exception", false},
		{"expired-leaf-revoked-intermediate", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			intermediate := &x509.Certificate{SerialNumber: big.NewInt(int64(7000 + index)), Subject: pkix.Name{CommonName: "retained intermediate"}, NotBefore: now.Add(-3 * time.Hour), NotAfter: now.Add(3 * time.Hour), BasicConstraintsValid: true, IsCA: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
			switch tc.name {
			case "expired-leaf-and-expired-intermediate":
				intermediate.NotAfter = now.Add(-time.Minute)
			case "expired-leaf-and-future-intermediate":
				intermediate.NotBefore = now.Add(time.Hour)
			}
			parent, signer := ca, key
			if tc.name == "expired-leaf-foreign-root" {
				foreignKey, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if e != nil {
					t.Fatal(e)
				}
				foreign := *ca
				foreign.PublicKey = &foreignKey.PublicKey
				foreign.Subject = pkix.Name{CommonName: "foreign root"}
				foreign.RawSubject = nil
				foreign.SerialNumber = big.NewInt(9000)
				der, e := x509.CreateCertificate(rand.Reader, &foreign, &foreign, &foreignKey.PublicKey, foreignKey)
				if e != nil {
					t.Fatal(e)
				}
				parent, e = x509.ParseCertificate(der)
				if e != nil {
					t.Fatal(e)
				}
				signer = foreignKey
			}
			der, err := x509.CreateCertificate(rand.Reader, intermediate, parent, &intermediateKey.PublicKey, signer)
			if err != nil {
				t.Fatal(err)
			}
			intermediate, err = x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			leaf := &x509.Certificate{SerialNumber: big.NewInt(int64(8000 + index)), Subject: pkix.Name{CommonName: "old-source"}, NotBefore: now.Add(-2 * time.Hour), NotAfter: now.Add(-time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
			switch tc.name {
			case "current-leaf-valid-original":
				leaf.NotAfter = now.Add(time.Hour)
			case "future-leaf-no-exception":
				leaf.NotBefore = now.Add(time.Hour)
				leaf.NotAfter = now.Add(2 * time.Hour)
			}
			raw, err := x509.CreateCertificate(rand.Reader, leaf, intermediate, &leafKey.PublicKey, intermediateKey)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "expired-leaf-invalid-signature" {
				raw[len(raw)-1] ^= 1
			}
			chain := [][]byte{raw, der}
			if tc.name == "valid-path-unused-expired-extra" {
				extra := *intermediate
				extra.SerialNumber = big.NewInt(9500)
				extra.Subject = pkix.Name{CommonName: "unused expired intermediate"}
				extra.RawSubject = nil
				extra.NotAfter = now.Add(-time.Minute)
				unused, err := x509.CreateCertificate(rand.Reader, &extra, ca, &leafKey.PublicKey, key)
				if err != nil {
					t.Fatal(err)
				}
				chain = append(chain, unused)
			}
			if tc.name == "expired-leaf-revoked-intermediate" {
				if err = pki.GenerateCRL(filepath.Join(r.dir, "ca.crt"), filepath.Join(producer.dir, "ca.key"), filepath.Join(r.dir, "crl.pem"), []string{intermediate.SerialNumber.Text(16)}); err != nil {
					t.Fatal(err)
				}
			}
			view, err := pki.CaptureHostTrust(ctx, r.dir, r.client.hostName)
			if err != nil {
				t.Fatal(err)
			}
			_, _, strictErr := view.VerifyHostCertificate(chain, "old-source")
			if tc.name != "current-leaf-valid-original" && tc.name != "future-leaf-no-exception" {
				var invalid x509.CertificateInvalidError
				if !errors.As(strictErr, &invalid) || invalid.Reason != x509.Expired || invalid.Cert == nil || !bytes.Equal(invalid.Cert.Raw, raw) {
					t.Fatal("did not reach real first leaf expiry", strictErr)
				}
			}
			_, _, provenanceErr := view.VerifyOriginalHostProvenance(chain, "old-source")
			if got := provenanceErr == nil; got != tc.want {
				t.Fatalf("remaining-chain provenance accepted=%v, want=%v; first error=%v", got, tc.want, strictErr)
			}
		})
	}
}
