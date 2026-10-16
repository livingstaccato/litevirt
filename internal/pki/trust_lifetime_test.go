package pki

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHostDomainProcess(t *testing.T) {
	if os.Getenv("LITEVIRT_DOMAIN_CHILD") == "" {
		t.Skip("subprocess only")
	}
	dir := os.Getenv("LITEVIRT_DOMAIN_CHILD")
	if err := os.WriteFile(filepath.Join(dir, "domain-entered"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireHostDomain(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err := os.WriteFile(filepath.Join(dir, "domain-held"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
}

func startHostDomainChild(t *testing.T, dir string) *exec.Cmd {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestHostDomainProcess$")
	child.Env = append(os.Environ(), "LITEVIRT_DOMAIN_CHILD="+dir)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stdin.Close(); _ = child.Process.Kill(); _ = child.Wait() })
	return child
}

func waitDomainMarker(t *testing.T, dir, name string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("process did not reach %s", name)
}

func TestHostDomainExcludesReinitUntilProcessDeath(t *testing.T) {
	dir := setupPKI(t)
	child := startHostDomainChild(t, dir)
	waitDomainMarker(t, dir, "domain-held")
	// Ordinary writers and a second daemon coexist with shared admission.
	shared, err := AcquireHostDomain(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := GenerateCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), nil); err != nil {
		t.Fatal(err)
	}
	shared.Release()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if lease, err := AcquireHostReinitialization(ctx, alias); !errors.Is(err, context.DeadlineExceeded) {
		if lease != nil {
			lease.Release()
		}
		t.Fatalf("live manual process did not exclude reinit: %v", err)
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("killed process reported clean exit")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	exclusive, err := AcquireHostReinitialization(ctx2, dir)
	if err != nil {
		t.Fatalf("kernel admission survived killed process: %v", err)
	}
	exclusive.Release()
}

func TestHostDomainStartWaitsForExclusiveReinit(t *testing.T) {
	dir := setupPKI(t)
	exclusive, err := AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer exclusive.Release()
	startHostDomainChild(t, dir)
	waitDomainMarker(t, dir, "domain-entered")
	time.Sleep(100 * time.Millisecond)
	if _, err := os.Stat(filepath.Join(dir, "domain-held")); !os.IsNotExist(err) {
		t.Fatalf("new daemon crossed exclusive reinit: %v", err)
	}
	exclusive.Release()
	waitDomainMarker(t, dir, "domain-held")
}
