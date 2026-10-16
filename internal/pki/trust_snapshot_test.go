package pki

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHostTrustCapturesCurrentServedIdentity(t *testing.T) {
	dir := setupPKI(t)
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil || view == nil {
		t.Fatalf("current CA-issued served host cannot capture strict trust: %v", err)
	}
}

func TestHostTrustPolicyToggleBackInvalidates(t *testing.T) {
	dir := setupPKI(t)
	ctx := context.Background()
	var effective atomic.Bool
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
	if err := PublishHostTrustPolicy(dir, &effective, true); err != nil {
		t.Fatal(err)
	}
	if !effective.Load() {
		t.Fatal("actual policy cell not changed")
	}
	if err := PublishHostTrustPolicy(dir, &effective, false); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireHostCertificateLease(ctx, dir, cap); err == nil {
		t.Fatal("policy toggle-back revived old validation")
	}
}

func TestHostTrustLeaseRejectsForgedAndChangedEvidence(t *testing.T) {
	dir := setupPKI(t)
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := view.ValidateHostCertificate(context.Background(), pair.Certificate, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireHostCertificateLease(context.Background(), dir, cap)
	if err != nil {
		t.Fatalf("current host validation could not acquire lease: %v", err)
	}
	if err := lease.Check(); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if err := lease.Check(); err == nil {
		t.Fatal("released lease remained usable")
	}
	if _, err := AcquireHostCertificateLease(context.Background(), dir, cap); err == nil {
		t.Fatal("released validation revived")
	}
	if _, err := AcquireHostCertificateLease(context.Background(), dir, &HostCertificateValidation{}); err == nil {
		t.Fatal("zero validation minted authority")
	}
	view, err = CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	cap, err = view.ValidateHostCertificate(context.Background(), pair.Certificate, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	copyCap := *cap
	if _, err := AcquireHostCertificateLease(context.Background(), dir, &copyCap); err == nil {
		t.Fatal("copied validation minted authority")
	}
	if err := GenerateCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), []string{"ab01"}); err != nil {
		t.Fatal(err)
	}
	if _, err := AcquireHostCertificateLease(context.Background(), dir, cap); err == nil {
		t.Fatal("changed CRL evidence retained old capability")
	}
	if err := os.Remove(filepath.Join(dir, "crl.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := CaptureHostTrust(context.Background(), dir, "test-host"); err == nil {
		t.Fatal("missing established CRL silently restored weaker trust")
	}
}

func TestHostTrustPolicyCanPreconfigureUnavailableDirectory(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "not-yet-created")
	var effective atomic.Bool
	if err := PublishHostTrustPolicy(dir, &effective, true); err != nil {
		t.Fatal("policy could not be configured before PKI exists", err)
	}
	if !effective.Load() {
		t.Fatal("preconfigured effective cell not published")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("preconfiguration created a fake PKI directory", err)
	}
	source := setupPKI(t)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), mustReadFile(t, filepath.Join(source, name)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if !view.policy {
		t.Fatal("activated owner ignored the actual preconfigured policy")
	}
}

func TestHostTrustBoundPolicyCannotRebindOrBypassOwner(t *testing.T) {
	dir := setupPKI(t)
	other := setupPKI(t)
	var effective atomic.Bool
	if err := PublishHostTrustPolicy(dir, &effective, false); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing"), other} {
		if err := PublishHostTrustPolicy(path, &effective, true); err == nil {
			t.Fatal("bound policy changed domain without coordinated authority", path)
		}
		if effective.Load() {
			t.Fatal("failed bound policy update changed the effective cell")
		}
	}
	if _, err := CaptureHostTrust(context.Background(), other, "test-host"); err != nil {
		t.Fatal("refused policy rebind poisoned another domain", err)
	}
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if err := PublishHostTrustPolicy(alias, &effective, true); err != nil {
		t.Fatal("canonical alias did not reach the same owner", err)
	}
	view, err := CaptureHostTrust(context.Background(), dir, "test-host")
	if err != nil || !view.policy {
		t.Fatal("alias lost actual policy", err)
	}
}

func TestHostTrustInitialPolicyBindingRacesSetter(t *testing.T) {
	for i := 0; i < 20; i++ {
		dir := filepath.Join(t.TempDir(), "pending")
		var effective atomic.Bool
		if err := PublishHostTrustPolicy(dir, &effective, true); err != nil {
			t.Fatal(err)
		}
		source := setupPKI(t)
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
			if err := os.WriteFile(filepath.Join(dir, name), mustReadFile(t, filepath.Join(source, name)), 0600); err != nil {
				t.Fatal(err)
			}
		}
		start := make(chan struct{})
		var wait sync.WaitGroup
		wait.Add(2)
		var view *HostTrust
		var captureErr, writeErr error
		go func() {
			defer wait.Done()
			<-start
			view, captureErr = CaptureHostTrust(context.Background(), dir, "test-host")
		}()
		go func() { defer wait.Done(); <-start; writeErr = PublishHostTrustPolicy(dir, &effective, false) }()
		close(start)
		wait.Wait()
		if captureErr != nil || writeErr != nil {
			t.Fatal(captureErr, writeErr)
		}
		pair, err := ServedHostKeyPair(dir)
		if err != nil {
			t.Fatal(err)
		}
		cap, err := view.ValidateHostCertificate(context.Background(), pair.Certificate, "test-host")
		if err != nil {
			continue
		}
		lease, err := AcquireHostCertificateLease(context.Background(), dir, cap)
		if err != nil {
			continue
		}
		if view.policy != effective.Load() {
			lease.Release()
			t.Fatal("initial binding race issued capability for a different effective policy")
		}
		lease.Release()
	}
}
