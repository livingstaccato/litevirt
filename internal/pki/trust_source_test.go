package pki

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// Using strict host EKUs for ordinary membership, bypassing Historical expiry,
// or consulting changed live files instead of the snapshot breaks this test.
func TestSourceTrustOrdinarySnapshot(t *testing.T) {
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
	leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
	leaf.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	raw, err := x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := view.VerifyOrdinaryCertificate(raw, false, true); err != nil {
		t.Fatalf("ordinary EKUAny certificate refused: %v", err)
	}
	if _, err := view.ValidateHostCertificate(ctx, [][]byte{raw}, "test-host"); err == nil {
		t.Fatal("ordinary-only certificate became a strict host")
	}
	if err := GenerateCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), []string{leaf.SerialNumber.Text(16)}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := view.VerifyOrdinaryCertificate(raw, false, true); err != nil {
		t.Fatal("immutable verification read changed live CRL", err)
	}
	leaf.NotAfter = time.Now().Add(-time.Minute)
	raw, err = x509.CreateCertificate(rand.Reader, leaf, ca, leaf.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := view.VerifyOrdinaryCertificate(raw, true, true); err == nil {
		t.Fatal("Historical bypassed current expiry")
	}
}

// A current peer certificate must not stand in for the captured served pair.
func TestSourceTrustBindsServedPair(t *testing.T) {
	dir := setupPKI(t)
	var policy atomic.Bool
	ctx := context.Background()
	old, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	view, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	siblingDir := t.TempDir()
	if err := GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(siblingDir, "host.crt"), filepath.Join(siblingDir, "host.key"), "test-host", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	sibling, err := tls.LoadX509KeyPair(filepath.Join(siblingDir, "host.crt"), filepath.Join(siblingDir, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	siblingCap, err := view.ValidateHostCertificate(ctx, sibling.Certificate, "test-host")
	if err != nil {
		t.Fatal("valid same-host sibling fixture refused", err)
	}
	siblingCap.Discard()
	if _, err := view.ValidateServedHost(ctx, &sibling); err == nil {
		t.Fatal("valid same-host sibling relabeled actual served key")
	}
	cap, err := view.ValidateServedHost(ctx, old)
	if err != nil {
		t.Fatalf("actual first-call served pair refused: %v", err)
	}
	held, err := AcquireHostCertificateLease(ctx, dir, cap)
	if err != nil {
		t.Fatal(err)
	}
	held.Release()
	if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	if err := PublishHostTrustPolicy(dir, &policy, true); err != nil {
		t.Fatal(err)
	}
	next, err := CaptureHostTrust(ctx, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	peerCap, err := next.ValidateHostCertificate(ctx, old.Certificate, "test-host")
	if err != nil {
		t.Fatal("policy-permitted old peer fixture", err)
	}
	peerCap.Discard()
	if _, err := next.ValidateServedHost(ctx, old); err == nil {
		t.Fatal("old captured pair relabeled current served signer")
	}
	fresh, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.ValidateServedHost(ctx, fresh); err != nil {
		t.Fatal("renewed served pair refused", err)
	}
}
