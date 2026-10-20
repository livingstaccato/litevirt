package pki

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// An install that changes nothing writes nothing: not the five credential
// files, and not the marker either. MigrationTLSStatus and every storage
// migration run the installer, so a rewrite here is a write on every call.
//
// Mutation: write the marker unconditionally in claimQemuTLSDir — its inode
// changes.
func TestInstallQemuMigrationTLS_LeavesTheMarkerAloneWhenUnchanged(t *testing.T) {
	pkiDir, qemu := t.TempDir(), filepath.Join(t.TempDir(), "qemu")
	provisionMigration(t, pkiDir)
	if _, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(qemu, qemuTLSManagedMarker)
	before, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(marker)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Fatal("an unchanged install rewrote the marker")
	}
}

// snapshotDir records each entry's inode, so a later call can show it wrote
// nothing (os.SameFile against the snapshot).
func snapshotDir(t *testing.T, dir string) map[string]os.FileInfo {
	t.Helper()
	out := map[string]os.FileInfo{}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		fi, err := os.Stat(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = fi
	}
	return out
}

func sameDir(t *testing.T, dir string, before map[string]os.FileInfo) {
	t.Helper()
	after := snapshotDir(t, dir)
	if len(after) != len(before) {
		t.Fatalf("%s holds %d entries; had %d", dir, len(after), len(before))
	}
	for name, fi := range before {
		if a, ok := after[name]; !ok || !os.SameFile(fi, a) || !a.ModTime().Equal(fi.ModTime()) {
			t.Errorf("%s was written", name)
		}
	}
}

// CheckQemuMigrationTLS answers what the installer would, and writes nothing:
// not into an absent directory, not over a set that changed under pki_dir.
//
// Mutation: call InstallQemuMigrationTLS from CheckQemuMigrationTLS — the
// absent directory is created and the reissued certificate is installed.
func TestCheckQemuMigrationTLS_WritesNothing(t *testing.T) {
	pkiDir, qemu := t.TempDir(), filepath.Join(t.TempDir(), "qemu")
	provisionMigration(t, pkiDir)
	if err := CheckQemuMigrationTLS(pkiDir, qemu); err != nil {
		t.Fatalf("check of a healthy set into an absent directory: %v", err)
	}
	if _, err := os.Stat(qemu); !os.IsNotExist(err) {
		t.Fatalf("the check created %s", qemu)
	}

	if _, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err != nil {
		t.Fatal(err)
	}
	before := snapshotDir(t, qemu)
	time.Sleep(10 * time.Millisecond)
	// A reissue lands under pki_dir; the check must not carry it into QEMU's
	// directory.
	provisionMigration(t, pkiDir)
	if err := CheckQemuMigrationTLS(pkiDir, qemu); err != nil {
		t.Fatalf("check of a reissued set: %v", err)
	}
	sameDir(t, qemu, before)
}

// The check refuses what the installer refuses, the same way: a torn set as a
// validation failure, a directory litevirt does not own as something a new
// set would not cure.
//
// Mutations: skip validation in the check — the torn set passes; skip the
// ownership test — the foreign directory passes.
func TestCheckQemuMigrationTLS_RefusesWhatTheInstallerRefuses(t *testing.T) {
	pkiDir := t.TempDir()
	provisionMigration(t, pkiDir)
	foreign := filepath.Join(t.TempDir(), "qemu")
	if err := os.MkdirAll(foreign, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(foreign, "ca-cert.pem"), []byte("the operator's own CA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := CheckQemuMigrationTLS(pkiDir, foreign)
	if err == nil || IsCredentialsInvalidText(err.Error()) {
		t.Fatalf("check over a foreign directory = %v; want a refusal that is not a validation failure", err)
	}

	torn := t.TempDir()
	provisionMigration(t, torn)
	other := t.TempDir()
	provisionMigration(t, other)
	if err := os.WriteFile(filepath.Join(MigrationDir(torn), MigrationHostKeyName),
		mustRead(t, filepath.Join(MigrationDir(other), MigrationHostKeyName)), 0o600); err != nil {
		t.Fatal(err)
	}
	err = CheckQemuMigrationTLS(torn, filepath.Join(t.TempDir(), "qemu"))
	if !errors.Is(err, ErrInvalidMigrationCredentials) || !IsCredentialsInvalidText(err.Error()) {
		t.Fatalf("check of a torn set = %v; want a validation refusal", err)
	}
}

// Some of the three files but not all is a set mid-push, not an unprovisioned
// host: the installer refuses it as unusable, so a storage copy is refused
// whatever the plaintext opt-in says, as lv doctor migration-tls reports it.
//
// Mutation: return (false, nil) for any missing file — the partial set reads
// as unprovisioned.
func TestInstallQemuMigrationTLS_RefusesAPartialSet(t *testing.T) {
	pkiDir, qemu := t.TempDir(), filepath.Join(t.TempDir(), "qemu")
	provisionMigration(t, pkiDir)
	if err := os.Remove(filepath.Join(MigrationDir(pkiDir), MigrationHostKeyName)); err != nil {
		t.Fatal(err)
	}
	ok, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1)
	if ok || !errors.Is(err, ErrInvalidMigrationCredentials) {
		t.Fatalf("install of a partial set = (%v, %v); want refused as unusable", ok, err)
	}
	if _, err := os.Stat(qemu); !os.IsNotExist(err) {
		t.Errorf("a refused install created %s", qemu)
	}
	if err := CheckQemuMigrationTLS(pkiDir, qemu); !errors.Is(err, ErrInvalidMigrationCredentials) {
		t.Errorf("check of a partial set = %v; want refused as unusable", err)
	}
}

// A key whose mode drifted (chmod 0444) is rewritten 0400 by the next
// install, even though its bytes did not change.
//
// Mutation: drop the mode comparison from upToDate — the key stays 0444.
func TestInstallQemuMigrationTLS_RestoresADriftedKeyMode(t *testing.T) {
	pkiDir, qemu := t.TempDir(), filepath.Join(t.TempDir(), "qemu")
	provisionMigration(t, pkiDir)
	if _, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(qemu, "server-key.pem")
	if err := os.Chmod(key, 0o444); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o400 {
		t.Fatalf("server-key.pem is %04o after a re-install; want 0400", fi.Mode().Perm())
	}
}

// Without root, a key's group can still change between two groups this user
// belongs to: the next install must rewrite it under the new group.
//
// Mutation: drop the owner comparison from upToDate — the old group stays.
func TestInstallQemuMigrationTLS_RewritesAKeyWhoseGroupChanged(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	var gids []int
	for _, g := range groups {
		if len(gids) == 0 || gids[0] != g {
			gids = append(gids, g)
		}
	}
	if len(gids) < 2 {
		t.Skip("this user belongs to fewer than two groups")
	}
	uid := os.Getuid()
	pkiDir, qemu := t.TempDir(), filepath.Join(t.TempDir(), "qemu")
	provisionMigration(t, pkiDir)
	if _, err := InstallQemuMigrationTLS(pkiDir, qemu, uid, gids[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := InstallQemuMigrationTLS(pkiDir, qemu, uid, gids[1]); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(qemu, "server-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if gid := int(st.Sys().(*syscall.Stat_t).Gid); gid != gids[1] {
		t.Fatalf("server-key.pem group %d; want %d", gid, gids[1])
	}
}
