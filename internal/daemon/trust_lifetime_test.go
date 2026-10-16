package daemon

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

func TestDaemonLifetimeProcess(t *testing.T) {
	dir := os.Getenv("LITEVIRT_DAEMON_DOMAIN_CHILD")
	if dir == "" {
		t.Skip("subprocess only")
	}
	cfg := &Config{PKIDir: dir, HostName: "test-host"}
	cfg.Enforcement.GossipEncryption = corrosion.GossipEncryptionEnforced
	// This actual constructor fails before opening libvirt or a database. The
	// conservative registration still outlives both its result and a full GC.
	if _, err := NewContext(context.Background(), cfg); err == nil {
		t.Fatal("fixture unexpectedly constructed daemon")
	}
	runtime.GC()
	runtime.GC()
	if err := os.WriteFile(filepath.Join(dir, "constructor-returned"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	var b [1]byte
	_, _ = os.Stdin.Read(b[:])
}

func TestDaemonLifetimeRetainedAfterConstructorErrorAndGC(t *testing.T) {
	dir := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(executable, "-test.run=^TestDaemonLifetimeProcess$")
	child.Env = append(os.Environ(), "LITEVIRT_DAEMON_DOMAIN_CHILD="+dir)
	stdin, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stdin.Close(); _ = child.Process.Kill(); _ = child.Wait() }()
	deadline := time.Now().Add(3 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "constructor-returned")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("child constructor did not return")
		}
		time.Sleep(5 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if lease, err := pki.AcquireHostReinitialization(ctx, dir); !errors.Is(err, context.DeadlineExceeded) {
		if lease != nil {
			lease.Release()
		}
		t.Fatalf("discarded daemon registration released before process death: %v", err)
	}
	initCtx, initCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if err := pki.InitializeOperatorCA(initCtx, dir); !errors.Is(err, context.DeadlineExceeded) {
		initCancel()
		t.Fatalf("operator first creation crossed separate daemon admission: %v", err)
	}
	initCancel()
	if _, err := os.Stat(filepath.Join(dir, "ca.crt")); !os.IsNotExist(err) {
		t.Fatal("cancelled operator initialization published a root")
	}
	if err := child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err == nil {
		t.Fatal("killed process returned success")
	}
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	lease, err := pki.AcquireHostReinitialization(ctx2, dir)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if err := pki.InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal("first operator creation did not progress after process death", err)
	}
}

func TestDaemonLifetimeAdmissionPrecedesConstruction(t *testing.T) {
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, ".active-domain.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	defer syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	cfg := &Config{PKIDir: dir, HostName: "test-host"}
	cfg.Enforcement.GossipEncryption = corrosion.GossipEncryptionEnforced
	done := make(chan error, 1)
	go func() { _, err := New(cfg); done <- err }()
	select {
	case err := <-done:
		t.Fatalf("daemon constructor accessed PKI before lifetime admission: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("fixture unexpectedly constructed a daemon without gossip credentials")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("daemon admission did not progress after exclusive holder released")
	}
}
