package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// addOperatorPKI is an operator machine that holds the cluster CA (and its
// key) and the gossip key, but no migration CA.
func addOperatorPKI(t *testing.T) string {
	t.Helper()
	t.Setenv("LV_CONFIG_DIR", t.TempDir())
	dir := PKIDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ensureLocalGossipKey(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func stubMigrationProbe(t *testing.T, fn func(target string) (bool, error)) *[]string {
	t.Helper()
	old := peerHoldsMigrationCredentials
	t.Cleanup(func() { peerHoldsMigrationCredentials = old })
	var asked []string
	peerHoldsMigrationCredentials = func(target string) (bool, error) {
		asked = append(asked, target)
		return fn(target)
	}
	return &asked
}

// `lv host add` from a machine with the cluster CA but no migration CA used to
// mint a second migration CA while the cluster's hosts held credentials from
// the first. The new host then advertised migration TLS ready, and every
// storage migration to or from it failed the QEMU TLS handshake. It must refuse
// as `lv host install-migration-tls` does, before anything is minted or pushed.
func TestHostAdd_RefusesASecondMigrationCAWhenPeersHoldCredentials(t *testing.T) {
	dir := addOperatorPKI(t)
	useConfig(t, "")
	stubPeerConfig(t, func(string) (string, bool, error) {
		return "enforcement:\n  gossip_encryption: enforce\n", true, nil
	})
	asked := stubMigrationProbe(t, func(string) (bool, error) { return true, nil })

	err := HostAdd(context.Background(), nil, "root@10.0.0.9", "node-9", []string{"10.0.0.1:7946"})
	if err == nil || !strings.Contains(err.Error(), pki.MigrationCACertName) {
		t.Fatalf("err = %v; want a refusal telling the operator to bring the cluster's %s here",
			err, pki.MigrationCACertName)
	}
	if strings.Contains(err.Error(), "SSH connect") {
		t.Errorf("refused only after connecting to the target: %v", err)
	}
	if _, serr := os.Stat(filepath.Join(dir, pki.MigrationCACertName)); !os.IsNotExist(serr) {
		t.Errorf("a second migration CA was minted at %s (stat: %v)", dir, serr)
	}
	if len(*asked) == 0 || (*asked)[0] != "root@10.0.0.1" {
		t.Errorf("probed %v for migration credentials, want root@10.0.0.1", *asked)
	}
}

// When no peer can be asked, absence is not proven, so add refuses rather than
// risk the second CA.
func TestEnsureLocalMigrationCA_RefusesWhenNoPeerCanBeAsked(t *testing.T) {
	dir := t.TempDir()
	stubMigrationProbe(t, func(string) (bool, error) { return false, errors.New("connection refused") })

	_, _, _, err := ensureLocalMigrationCA(dir, peerMigrationHolder("root", []string{"10.0.0.1:7946", "10.0.0.2:7946"}))
	if err == nil {
		t.Fatal("minted a migration CA although no cluster host could be asked whether one exists")
	}
	if _, serr := os.Stat(filepath.Join(dir, pki.MigrationCACertName)); !os.IsNotExist(serr) {
		t.Errorf("minted %s anyway (stat: %v)", pki.MigrationCACertName, serr)
	}
}

// A cluster that never had migration TLS gets its CA minted by add, as before.
func TestEnsureLocalMigrationCA_MintsWhenNoPeerHoldsCredentials(t *testing.T) {
	dir := t.TempDir()
	stubMigrationProbe(t, func(string) (bool, error) { return false, nil })

	_, _, minted, err := ensureLocalMigrationCA(dir, peerMigrationHolder("root", []string{"10.0.0.1:7946"}))
	if err != nil || !minted {
		t.Fatalf("got (minted=%v, %v), want a fresh migration CA", minted, err)
	}
}

// Founding a cluster (`lv host init`) has no peers to ask and mints.
func TestEnsureLocalMigrationCA_FoundingMintsWithoutAsking(t *testing.T) {
	dir := t.TempDir()
	asked := stubMigrationProbe(t, func(string) (bool, error) { return true, nil })

	_, _, minted, err := ensureLocalMigrationCA(dir, nil)
	if err != nil || !minted {
		t.Fatalf("got (minted=%v, %v), want a fresh migration CA", minted, err)
	}
	if len(*asked) != 0 {
		t.Errorf("a founding init probed %v", *asked)
	}
}

// With the migration CA already here nothing is asked: the probe exists only
// to stop a mint.
func TestEnsureLocalMigrationCA_ExistingCAAsksNobody(t *testing.T) {
	dir := t.TempDir()
	if _, _, _, err := ensureLocalMigrationCA(dir, nil); err != nil {
		t.Fatal(err)
	}
	asked := stubMigrationProbe(t, func(string) (bool, error) { return true, nil })

	_, _, minted, err := ensureLocalMigrationCA(dir, peerMigrationHolder("root", []string{"10.0.0.1:7946"}))
	if err != nil || minted {
		t.Fatalf("got (minted=%v, %v), want the existing CA", minted, err)
	}
	if len(*asked) != 0 {
		t.Errorf("probed %v although the CA exists", *asked)
	}
}
