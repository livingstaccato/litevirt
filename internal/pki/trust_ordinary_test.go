package pki

import (
	"context"
	"crypto/x509"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestOrdinaryTrustPreservesDistinctCRLPredicates(t *testing.T) {
	dir := setupPKI(t)
	obs := observerPKI(t, dir, "observer")
	ctx := context.Background()
	old := readLeaf(t, filepath.Join(dir, "host.crt"))
	if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	successor := readLeaf(t, filepath.Join(dir, "host.crt"))
	check := func(revoked, superseded bool) {
		t.Helper()
		view, lease, err := AcquireOrdinaryClaimTrust(ctx, obs, []*x509.Certificate{old, successor}, nil, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		defer lease.Release()
		if view.Revoked(old) != revoked || (view.Superseded(old) != nil) != superseded {
			t.Fatalf("ordinary predicates: revoked=%v superseded=%v", view.Revoked(old), view.Superseded(old))
		}
	}
	check(false, true)
	foreign := setupPKI(t)
	if err := GenerateCRL(filepath.Join(foreign, "ca.crt"), filepath.Join(foreign, "ca.key"), filepath.Join(obs, "crl.pem"), []string{old.SerialNumber.Text(16), successor.SerialNumber.Text(16)}); err != nil {
		t.Fatal(err)
	}
	check(true, true) // ordinary revocation parses; successor standing authenticates
	if _, err := CaptureHostTrust(ctx, obs, "observer"); err == nil {
		t.Fatal("strict trust accepted foreign CRL")
	}
	if err := os.WriteFile(filepath.Join(obs, "crl.pem"), []byte("corrupt CRL"), 0600); err != nil {
		t.Fatal(err)
	}
	check(false, true)
	if _, err := CaptureHostTrust(ctx, obs, "observer"); err == nil {
		t.Fatal("strict trust accepted corrupt CRL")
	}
	// Replace the deliberately damaged fixture with a signed same-CA revocation.
	if err := os.Remove(filepath.Join(obs, "crl.pem")); err != nil {
		t.Fatal(err)
	}
	if err := GenerateCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(obs, "crl.pem"), []string{successor.SerialNumber.Text(16)}); err != nil {
		t.Fatal(err)
	}
	check(false, false) // a genuinely abandoned successor restores predecessor
}

func TestOrdinaryLeaseBlocksEffectivePolicyWriter(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	var policy atomic.Bool
	if err := PublishHostTrustPolicy(dir, &policy, false); err != nil {
		t.Fatal(err)
	}
	leaf := readLeaf(t, filepath.Join(dir, "host.crt"))
	view, lease, err := AcquireOrdinaryClaimTrust(ctx, dir, []*x509.Certificate{leaf}, &policy, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	done := make(chan error, 1)
	go func() { done <- PublishHostTrustPolicy(dir, &policy, true) }()
	select {
	case <-done:
		t.Fatal("effective policy writer crossed ordinary lease")
	case <-time.After(60 * time.Millisecond):
	}
	if view.TrustRotatedPeers() || policy.Load() {
		t.Fatal("held policy changed")
	}
	lease.Release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	next, held, err := AcquireOrdinaryClaimTrust(ctx, dir, []*x509.Certificate{leaf}, &policy, 64<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Release()
	if !next.TrustRotatedPeers() {
		t.Fatal("new ordinary view missed actual policy publication")
	}
}
