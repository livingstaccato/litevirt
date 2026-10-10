package pki

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// reinit writes a fresh host pair over host.crt/host.key as regular files, the
// way `lv host init` re-init does (mv -fT over the links), and returns its
// serial.
func reinit(t *testing.T, dir string) string {
	t.Helper()
	stage := t.TempDir()
	crt, key := filepath.Join(stage, "host.crt"), filepath.Join(stage, "host.key")
	if err := GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), crt, key,
		"test-host", net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"host.key", "host.crt"} {
		if err := os.Rename(filepath.Join(stage, f), filepath.Join(dir, f)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := CertSerial(filepath.Join(dir, "host.crt"))
	return strings.ToLower(s)
}

// After a re-init wrote regular files over the links, `current` still names
// the older pair. A renewal must treat the regular files as the identity: a
// crash mid-conversion leaves the re-init identity, and a rollback can reach
// it.
//
// Mutation: convert only when `current` is absent (the old rule) — the crash
// leaves the stale pre-re-init identity, and rollback finds no identity R.
func TestInstallRenewal_AfterAReinitKeepsTheReinitIdentity(t *testing.T) {
	dir := setupPKI(t)
	if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	r := reinit(t, dir)
	id, cert := signForStaging(t, dir)
	swapCrashHook = func(s string) error {
		if s == "linked-host.key" {
			return errCrash
		}
		return nil
	}
	_, _, err := InstallRenewal(dir, id, cert)
	swapCrashHook = nil
	if !errors.Is(err, errCrash) {
		t.Fatalf("install: %v", err)
	}
	if got := coldLoad(t, dir); got != r {
		t.Fatalf("after a crash the identity is %s, want the re-init identity %s", got, r)
	}
	prev, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if prev != r {
		t.Fatalf("the renewal replaced %s, not the re-init identity %s", prev, r)
	}
	if err := RollbackRenewal(dir, r); err != nil {
		t.Fatalf("rollback to the re-init identity: %v", err)
	}
	if got := coldLoad(t, dir); got != r {
		t.Fatalf("rolled back to %s, want %s", got, r)
	}
}

// Start-up recovery never comes back on a revoked identity, and sets aside
// regular files that do not load instead of overwriting them.
//
// Mutation: drop the IsCertRevoked skip in RecoverHostIdentity — recovery
// picks the revoked successor.
func TestRecoverHostIdentity_SkipsRevokedAndSetsFilesAside(t *testing.T) {
	dir := setupPKI(t)
	prev, next, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if err := RollbackRenewal(dir, prev); err != nil {
		t.Fatal(err)
	}
	if err := GenerateCRL(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "crl.pem"), []string{next}); err != nil {
		t.Fatal(err)
	}
	// Both files become regular and mismatched: a hand edit gone wrong.
	other := t.TempDir()
	if err := GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(other, "c"),
		filepath.Join(other, "k"), "test-host", nil); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "host.crt"))
	k, _ := os.ReadFile(filepath.Join(other, "k"))
	for name, data := range map[string][]byte{"host.crt": b, "host.key": k} {
		p := filepath.Join(dir, name)
		_ = os.Remove(p)
		if err := os.WriteFile(p, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := RecoverHostIdentity(dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"))
	if err != nil {
		t.Fatal(err)
	}
	got := readLeaf(t, filepath.Join(dir, "host.crt"))
	_ = pair
	if strings.EqualFold(got.SerialNumber.Text(16), next) {
		t.Fatal("recovery came back on a revoked identity")
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "host.key.unloadable-*")); len(m) != 1 {
		t.Fatalf("the unloadable key was not set aside: %v", m)
	}
}

// An abandoned successor's directory is discarded; the current one is refused.
// rollback --to validates its target.
//
// Mutations: let DiscardIdentity remove the current identity; drop the
// serial-equality check in checkStoredIdentity (a pair filed under another
// name becomes a rollback target). The hex check is defence in depth: with it
// removed, "../.." and "zz" are still refused by the pair check.
func TestDiscardAndRollbackValidation(t *testing.T) {
	dir := setupPKI(t)
	prev, next, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if err := DiscardIdentity(dir, next); err == nil {
		t.Fatal("discarded the current identity")
	}
	if err := RollbackRenewal(dir, prev); err != nil {
		t.Fatal(err)
	}
	if err := DiscardIdentity(dir, next); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, hostDirName, next)); !os.IsNotExist(err) {
		t.Fatal("the abandoned successor's pair is still on disk")
	}
	for _, bad := range []string{"../..", "zz", ""} {
		if err := RollbackRenewal(dir, bad); err == nil {
			t.Errorf("rollback --to %q accepted", bad)
		}
	}
	// A pair from another CA placed under host.d is not a rollback target.
	foreign := t.TempDir()
	if err := GenerateCA(filepath.Join(foreign, "ca.crt"), filepath.Join(foreign, "ca.key")); err != nil {
		t.Fatal(err)
	}
	stage := t.TempDir()
	if err := GenerateHostCert(filepath.Join(foreign, "ca.crt"), filepath.Join(foreign, "ca.key"),
		filepath.Join(stage, "host.crt"), filepath.Join(stage, "host.key"), "test-host", nil); err != nil {
		t.Fatal(err)
	}
	fs, _ := CertSerial(filepath.Join(stage, "host.crt"))
	fs = strings.ToLower(fs)
	if err := os.Rename(stage, filepath.Join(dir, hostDirName, fs)); err != nil {
		t.Fatal(err)
	}
	if err := RollbackRenewal(dir, fs); err == nil {
		t.Fatal("rolled back onto another CA's certificate")
	}
	// A valid pair filed under a name that is not its serial is not a target.
	if err := copyDir(filepath.Join(dir, hostDirName, prev), filepath.Join(dir, hostDirName, "abc")); err != nil {
		t.Fatal(err)
	}
	if err := renewLocalForTest(dir); err != nil {
		t.Fatal(err)
	}
	if err := RollbackRenewal(dir, "abc"); err == nil {
		t.Fatal("rolled back onto a pair filed under another serial")
	}
}

func copyDir(src, dst string) error {
	if err := os.MkdirAll(dst, 0o700); err != nil {
		return err
	}
	for _, f := range []string{"host.crt", "host.key"} {
		b, err := os.ReadFile(filepath.Join(src, f))
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(dst, f), b, 0o600); err != nil {
			return err
		}
	}
	return nil
}

// renewLocalForTest renews dir's identity so the current one is not prev.
func renewLocalForTest(dir string) error {
	_, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	return err
}

// The lenient path for an existing identity still bounds what it reads.
//
// Mutation: read with tls.LoadX509KeyPair in loadPairLenient — the oversized
// file (a valid PEM followed by a megabyte of padding) is read whole and loads.
func TestLenientLoad_IsBounded(t *testing.T) {
	dir := setupPKI(t)
	src := NewKeyPairSource(filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), nil)
	if _, err := src.Get(); err != nil {
		t.Fatal(err)
	}
	big := append(mustReadFile(t, filepath.Join(dir, "host.crt")), make([]byte, maxServingChainBytes)...)
	if err := os.WriteFile(filepath.Join(dir, ".big"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	src2 := NewKeyPairSource(filepath.Join(dir, ".big"), filepath.Join(dir, "host.key"), nil)
	if _, err := src2.Get(); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized certificate file was read whole: %v", err)
	}
}
