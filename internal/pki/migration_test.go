package pki

import (
	"crypto/x509"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// provisionMigration lays out a host's migration credentials the way
// `lv host init` / `lv host add` / `lv host install-migration-tls` push them.
func provisionMigration(t *testing.T, pkiDir string) {
	t.Helper()
	caDir := t.TempDir()
	caCert, caKey := filepath.Join(caDir, MigrationCACertName), filepath.Join(caDir, MigrationCAKeyName)
	if err := GenerateMigrationCA(caCert, caKey); err != nil {
		t.Fatalf("GenerateMigrationCA: %v", err)
	}
	dir := MigrationDir(pkiDir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := GenerateHostCert(caCert, caKey, filepath.Join(dir, MigrationHostCertName),
		filepath.Join(dir, MigrationHostKeyName), "node-1", net.ParseIP("10.0.0.1")); err != nil {
		t.Fatalf("GenerateHostCert with the migration CA: %v", err)
	}
	data, err := os.ReadFile(caCert)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, MigrationCAName), data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := pem.Decode(data)
	if b == nil {
		t.Fatalf("%s holds no PEM", path)
	}
	c, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// The migration CA is a separate root. QEMU reads migration credentials inside
// an unprivileged process a guest can escape into; if the migration CA were the
// cluster CA (or the migration key the host key), that escape would yield a
// credential every peer's mTLS accepts.
func TestMigrationCA_IsNotTheClusterCA(t *testing.T) {
	dir := t.TempDir()
	if err := GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if err := GenerateMigrationCA(filepath.Join(dir, MigrationCACertName), filepath.Join(dir, MigrationCAKeyName)); err != nil {
		t.Fatal(err)
	}
	cluster, mig := readCert(t, filepath.Join(dir, "ca.crt")), readCert(t, filepath.Join(dir, MigrationCACertName))
	if cluster.Subject.CommonName == mig.Subject.CommonName {
		t.Errorf("both CAs are named %q; an operator cannot tell them apart", mig.Subject.CommonName)
	}
	if !mig.IsCA {
		t.Fatal("the migration CA is not a CA")
	}
	pool := x509.NewCertPool()
	pool.AddCert(cluster)
	if _, err := mig.Verify(x509.VerifyOptions{Roots: pool}); err == nil {
		t.Fatal("the migration CA verifies against the cluster CA")
	}
}

func TestInstallQemuMigrationTLS_NotProvisionedInstallsNothing(t *testing.T) {
	qemu := filepath.Join(t.TempDir(), "qemu")
	ok, err := InstallQemuMigrationTLS(t.TempDir(), qemu, -1, -1)
	if err != nil || ok {
		t.Fatalf("install with no migration credentials = (%v, %v), want (false, nil)", ok, err)
	}
	if _, err := os.Stat(qemu); !os.IsNotExist(err) {
		t.Errorf("an unprovisioned host created %s", qemu)
	}
}

func TestInstallQemuMigrationTLS_InstallsUnderLibvirtNames(t *testing.T) {
	pkiDir := t.TempDir()
	provisionMigration(t, pkiDir)
	qemu := filepath.Join(t.TempDir(), "qemu")
	ok, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1)
	if err != nil || !ok {
		t.Fatalf("install = (%v, %v), want (true, nil)", ok, err)
	}
	for _, name := range []string{"ca-cert.pem", "server-cert.pem", "server-key.pem", "client-cert.pem", "client-key.pem"} {
		if _, err := os.Stat(filepath.Join(qemu, name)); err != nil {
			t.Errorf("libvirt reads %s for migration TLS and it is missing: %v", name, err)
		}
	}
	for _, name := range []string{"server-key.pem", "client-key.pem"} {
		fi, err := os.Stat(filepath.Join(qemu, name))
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s is mode %04o; the migration key must be readable by its owner only", name, fi.Mode().Perm())
		}
	}
	// The installed CA is the MIGRATION CA, never the cluster CA.
	got := readCert(t, filepath.Join(qemu, "ca-cert.pem"))
	want := readCert(t, filepath.Join(MigrationDir(pkiDir), MigrationCAName))
	if !got.Equal(want) {
		t.Error("ca-cert.pem is not the migration CA")
	}
	// Idempotent: a second install over its own files succeeds.
	if ok, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1); err != nil || !ok {
		t.Errorf("re-install = (%v, %v), want (true, nil)", ok, err)
	}
}

// /etc/pki/qemu is libvirt's default TLS directory, which an operator may
// already use (VNC TLS, their own migration PKI). litevirt must never overwrite
// files it did not put there.
func TestInstallQemuMigrationTLS_RefusesADirectoryItDoesNotOwn(t *testing.T) {
	pkiDir := t.TempDir()
	provisionMigration(t, pkiDir)
	qemu := filepath.Join(t.TempDir(), "qemu")
	if err := os.MkdirAll(qemu, 0o755); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(qemu, "ca-cert.pem")
	if err := os.WriteFile(foreign, []byte("the operator's own CA\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ok, err := InstallQemuMigrationTLS(pkiDir, qemu, -1, -1)
	if err == nil || ok {
		t.Fatalf("install over a foreign %s = (%v, %v), want a refusal", qemu, ok, err)
	}
	if data, _ := os.ReadFile(foreign); string(data) != "the operator's own CA\n" {
		t.Error("the refusal still overwrote the operator's ca-cert.pem")
	}
}
