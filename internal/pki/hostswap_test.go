package pki

import (
	"crypto/tls"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// coldLoad is what a daemon starting from scratch does: recover, then load.
func coldLoad(t *testing.T, dir string) string {
	t.Helper()
	if _, err := RecoverHostIdentity(dir, "test-host"); err != nil {
		t.Fatalf("recover: %v", err)
	}
	pair, err := tls.LoadX509KeyPair(filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"))
	if err != nil {
		t.Fatalf("a daemon could not start on what the interrupted renewal left: %v", err)
	}
	c, err := ParseCertPEM(mustReadFile(t, filepath.Join(dir, "host.crt")))
	if err != nil {
		t.Fatal(err)
	}
	_ = pair
	return strings.ToLower(c.SerialNumber.Text(16))
}

func mustReadFile(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func signForStaging(t *testing.T, dir string) (string, []byte) {
	t.Helper()
	prev := readLeaf(t, filepath.Join(dir, "host.crt"))
	id, csr, err := GenerateRenewalCSR(dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignRenewal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), prev, "test-host", csr)
	if err != nil {
		t.Fatal(err)
	}
	return id, cert
}

var errCrash = errors.New("simulated crash")

// A crash at every step of an install — first renewal (legacy layout) and a
// second one (linked layout) — leaves a pair a cold-starting daemon loads, and
// it is the old identity before the switch and the new one after it.
//
// Mutation: switch `current` before converting the layout — a crash at
// "linked-host.key" leaves the NEW identity in place before the step that is
// supposed to switch, so a failed install is not a no-op.
func TestInstallRenewal_EveryCrashPointLeavesALoadablePair(t *testing.T) {
	steps := []string{"staged", "placed", "copied-legacy", "current-created", "linked-host.key", "linked-host.crt", "switched"}
	for _, second := range []bool{false, true} {
		for _, step := range steps {
			if second && (step == "copied-legacy" || step == "current-created" || strings.HasPrefix(step, "linked-")) {
				continue // only the first renewal converts the layout
			}
			name := step
			if second {
				name = "second/" + step
			}
			t.Run(name, func(t *testing.T) {
				dir := setupPKI(t)
				if second {
					if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
						t.Fatal(err)
					}
				}
				before := strings.ToLower(readLeaf(t, filepath.Join(dir, "host.crt")).SerialNumber.Text(16))
				id, cert := signForStaging(t, dir)
				next, _ := ParseCertPEM(cert)
				after := strings.ToLower(next.SerialNumber.Text(16))
				hit := false
				swapCrashHook = func(s string) error {
					if s == step {
						hit = true
						return errCrash
					}
					return nil
				}
				defer func() { swapCrashHook = nil }()
				if _, _, err := InstallRenewal(dir, id, cert); !errors.Is(err, errCrash) {
					t.Fatalf("install: %v", err)
				}
				if !hit {
					t.Fatalf("step %s never reached", step)
				}
				got := coldLoad(t, dir)
				want := before
				if step == "switched" {
					want = after
				}
				if got != want {
					t.Fatalf("after a crash at %s the identity is %s, want %s", step, got, want)
				}
				// And the node can still renew afterwards.
				swapCrashHook = nil
				if _, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host"); err != nil {
					t.Fatalf("renewal after a crash at %s: %v", step, err)
				}
				coldLoad(t, dir)
			})
		}
	}
}

// A dangling or mismatched identity is repaired from host.d at start.
//
// Mutation: make RecoverHostIdentity return early — the cold load fails.
func TestRecoverHostIdentity_RepairsADanglingCurrent(t *testing.T) {
	dir := setupPKI(t)
	prev, next, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	// The current identity's directory vanishes (a hand clean-up gone wrong).
	if err := os.RemoveAll(filepath.Join(dir, hostDirName, next)); err != nil {
		t.Fatal(err)
	}
	if got := coldLoad(t, dir); got != prev {
		t.Fatalf("recovered %s, want the remaining identity %s", got, prev)
	}
}

// Rollback is one rename back; commit leaves only the current identity.
func TestRollbackAndCommit(t *testing.T) {
	dir := setupPKI(t)
	prev, next, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	if err := RollbackRenewal(dir, prev); err != nil {
		t.Fatal(err)
	}
	if got := coldLoad(t, dir); got != prev {
		t.Fatalf("rollback left %s", got)
	}
	if err := RollbackRenewal(dir, next); err != nil {
		t.Fatal(err)
	}
	if err := CommitRenewal(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, hostDirName, prev)); !os.IsNotExist(err) {
		t.Fatal("commit kept the replaced key")
	}
	if got := coldLoad(t, dir); got != next {
		t.Fatalf("commit left %s", got)
	}
}

// A key readable by others is tightened on load; one resolving outside its
// directory is refused.
//
// Mutation: drop checkKeyFile from loadPairChecked — the 0644 key stays 0644.
func TestLoadPairChecked_KeyFileRules(t *testing.T) {
	dir := setupPKI(t)
	key := filepath.Join(dir, "host.key")
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPairChecked(filepath.Join(dir, "host.crt"), key); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(key); fi.Mode().Perm() != 0o600 {
		t.Fatalf("a world-readable key was served without tightening (%04o)", fi.Mode().Perm())
	}
	outside := filepath.Join(t.TempDir(), "elsewhere.key")
	if err := os.Rename(key, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, key); err != nil {
		t.Fatal(err)
	}
	if _, err := loadPairChecked(filepath.Join(dir, "host.crt"), key); err == nil {
		t.Fatal("served a key that resolves outside its directory")
	}
	big := filepath.Join(dir, "big.crt")
	if err := os.WriteFile(big, make([]byte, maxServingChainBytes+10), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(big); err == nil {
		t.Fatal("read an oversized file")
	}
}
