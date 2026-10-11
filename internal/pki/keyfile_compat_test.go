package pki

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// moveKeyOutside replaces dir/name with a symlink to a copy outside dir: an
// arrangement main served without complaint.
func moveKeyOutside(t *testing.T, dir, name string) string {
	t.Helper()
	key := filepath.Join(dir, name)
	outside := filepath.Join(t.TempDir(), name)
	if err := os.Rename(key, outside); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, key); err != nil {
		t.Fatal(err)
	}
	return key
}

// The host's EXISTING identity is never newly refused over its key file: a key
// that resolves outside the PKI directory (or belongs to another user) is
// served as before, and reported — KeyFileProblems names the file and the fix
// so the daemon can raise it as a degraded condition.
//
// Mutation: make the host identity source strict — the legacy key is refused
// and the listener has no identity.
func TestKeyFile_ALegacyHostKeyIsServedAndReported(t *testing.T) {
	dir := setupPKI(t)
	key := moveKeyOutside(t, dir, "host.key")
	if _, err := ServerTLSConfig(dir); err != nil {
		t.Fatalf("the existing host identity was refused over its key file: %v", err)
	}
	if _, err := ServedHostCertificate(dir); err != nil {
		t.Fatalf("the existing host identity is not served: %v", err)
	}
	probs := KeyFileProblems(key)
	if len(probs) == 0 || !strings.Contains(strings.Join(probs, " "), "outside") {
		t.Fatalf("the unsafe key file is not reported: %v", probs)
	}
	ok := setupPKI(t)
	if p := KeyFileProblems(filepath.Join(ok, "host.key")); len(p) != 0 {
		t.Fatalf("a correct key file is reported: %v", p)
	}
}

// A key introduced by this branch — a custom UI certificate — is still held to
// the strict rules: the same arrangement is refused with a clear error.
func TestKeyFile_ANewUIKeyIsStillRefused(t *testing.T) {
	dir := t.TempDir()
	p := newCorpPKI(t, leafOpts{dns: []string{"node-b"}})
	if err := os.WriteFile(filepath.Join(dir, UICertName), pemOf(p.leaf, p.inter), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, UIKeyName), keyPEMOf(t, p.leafKey), 0o600); err != nil {
		t.Fatal(err)
	}
	moveKeyOutside(t, dir, UIKeyName)
	_, err := UICertSource(dir).Get()
	if err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("a UI key resolving outside the PKI directory was served: %v", err)
	}
}

// A renewed key is written by this build, so a staged key that is not held
// safely is refused before anything is installed.
//
// Mutation: drop the checkKeyFile call in InstallRenewal.
func TestInstallRenewal_RefusesAnUnsafeStagedKey(t *testing.T) {
	dir := setupPKI(t)
	id, cert := signForStaging(t, dir)
	moveKeyOutside(t, filepath.Join(dir, hostDirName, stagingPrefix+id), "host.key")
	if _, _, err := InstallRenewal(dir, id, cert); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("installed a renewal whose staged key resolves outside the PKI directory: %v", err)
	}
}
