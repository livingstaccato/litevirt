package pki

import (
	"context"
	"crypto/x509"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestTrustWriterProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_TRUST_WRITER") == "install" {
		dir := os.Getenv("LITEVIRT_TRUST_DIR")
		if err := os.WriteFile(filepath.Join(dir, "writer-ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		cert := mustReadFile(t, filepath.Join(dir, "incoming.pem"))
		if _, _, err := InstallRenewal(dir, os.Getenv("LITEVIRT_TRUST_STAGING"), cert); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "writer-done"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("LITEVIRT_TRUST_WRITER") == "crl" {
		dir := os.Getenv("LITEVIRT_TRUST_DIR")
		if err := os.WriteFile(filepath.Join(dir, "writer-ready"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		if err := GenerateCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), []string{"ab01"}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "writer-done"), nil, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getenv("LITEVIRT_TRUST_WRITER") != "successor" {
		t.Skip("subprocess only")
	}
	cert, err := ParseCertPEM(mustReadFile(t, os.Getenv("LITEVIRT_TRUST_CERT")))
	if err != nil {
		t.Fatal(err)
	}
	if !NoteSuccessor(os.Getenv("LITEVIRT_TRUST_DIR"), cert) {
		t.Fatal("successor writer did not learn evidence")
	}
}

func TestOrdinaryLeaseBlocksSeparateProcessCRLWriter(t *testing.T) {
	testHostLeaseBlocksWriter(t, "ordinary-crl")
}

func TestHostLeaseBlocksSeparateProcessCRLWriter(t *testing.T) {
	testHostLeaseBlocksWriter(t, "crl")
}

func TestHostLeaseBlocksSeparateProcessRenewal(t *testing.T) {
	testHostLeaseBlocksWriter(t, "install")
}

func TestHostLeaseBlocksServedIdentityReload(t *testing.T) {
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
	lease, err := AcquireHostCertificateLease(ctx, dir, cap)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	// Manual file replacement is outside the cooperative barrier; the served
	// source still must not publish its new pair while this lease is active.
	mintInto(t, dir, dir, "test-host")
	done := make(chan error, 1)
	go func() { _, err := ServedHostKeyPair(dir); done <- err }()
	select {
	case <-done:
		t.Fatal("served identity reloaded through held owner lease")
	case <-time.After(100 * time.Millisecond):
	}
	lease.Release()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func testHostLeaseBlocksWriter(t *testing.T, mode string) {
	dir := setupPKI(t)
	ctx := context.Background()
	staging := ""
	if mode == "install" {
		var cert []byte
		staging, cert = signForStaging(t, dir)
		if err := os.WriteFile(filepath.Join(dir, "incoming.pem"), cert, 0600); err != nil {
			t.Fatal(err)
		}
	}
	var release func()
	if mode == "ordinary-crl" {
		mode = "crl"
		_, lease, err := AcquireOrdinaryClaimTrust(ctx, dir, []*x509.Certificate{readLeaf(t, filepath.Join(dir, "host.crt"))}, nil, 64<<20)
		if err != nil {
			t.Fatal(err)
		}
		release = lease.Release
	} else {
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
		lease, err := AcquireHostCertificateLease(ctx, dir, cap)
		if err != nil {
			t.Fatal(err)
		}
		release = lease.Release
	}
	defer release()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestTrustWriterProcess$")
	child.Env = append(os.Environ(), "LITEVIRT_TRUST_WRITER="+mode, "LITEVIRT_TRUST_DIR="+dir, "LITEVIRT_TRUST_STAGING="+staging)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "writer-ready")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child did not reach writer")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "writer-done")); err == nil {
		t.Fatal("separate-process writer crossed held lease")
	}
	release()
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "writer-done")); err != nil {
		t.Fatal("writer did not progress after release")
	}
}

// Removing the destination-domain reread/merge loses the child's evidence
// when a daemon that has already loaded its store next learns a successor.
func TestTrustWritersMergeAcrossProcesses(t *testing.T) {
	dir := setupPKI(t)
	obs := observerPKI(t, dir, "observer")
	other := observerPKI(t, dir, "other")
	ca, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	prev, _, err := RenewLocal(ca, key, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	otherPrev, _, err := RenewLocal(ca, key, other, "other")
	if err != nil {
		t.Fatal(err)
	}
	SupersededBy(obs, "test-host", prev) // daemon cached the empty file
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestTrustWriterProcess$")
	child.Env = append(os.Environ(), "LITEVIRT_TRUST_WRITER=successor", "LITEVIRT_TRUST_DIR="+obs,
		"LITEVIRT_TRUST_CERT="+filepath.Join(dir, "host.crt"))
	if output, err := child.CombinedOutput(); err != nil {
		t.Fatalf("separate writer: %v\n%s", err, output)
	}
	cert, err := ServedHostCertificate(other)
	if err != nil || !NoteSuccessor(obs, cert) {
		t.Fatalf("parent learn: %v", err)
	}
	forgetSupersessionsForTests(obs)
	if _, ok := SupersededBy(obs, "test-host", prev); !ok {
		t.Fatal("parent overwrote separate-process successor evidence")
	}
	if _, ok := SupersededBy(obs, "other", otherPrev); !ok {
		t.Fatal("parent successor evidence absent after reopen")
	}
}
