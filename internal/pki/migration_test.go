package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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

// MigrationCAFingerprint is the SHA-256 of the installed migration CA's DER:
// two hosts provisioned from one CA agree, two from different CAs differ, and
// a host with no credentials reports none.
//
// Mutation: hash the PEM file instead of the DER — the want below goes red.
func TestMigrationCAFingerprint(t *testing.T) {
	if fp, err := MigrationCAFingerprint(t.TempDir()); err != nil || fp != "" {
		t.Fatalf("no credentials: fingerprint %q, err %v; want none", fp, err)
	}
	a, b := t.TempDir(), t.TempDir()
	provisionMigration(t, a)
	provisionMigration(t, b)
	fa, err := MigrationCAFingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := MigrationCAFingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	cert := readCert(t, filepath.Join(MigrationDir(a), MigrationCAName))
	sum := sha256.Sum256(cert.Raw)
	if want := hex.EncodeToString(sum[:]); fa != want {
		t.Fatalf("fingerprint = %q, want %q (sha256 of the CA's DER)", fa, want)
	}
	if fa == fb {
		t.Fatal("two different migration CAs have one fingerprint")
	}
	if err := os.WriteFile(filepath.Join(MigrationDir(a), MigrationCAName), []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrationCAFingerprint(a); err == nil {
		t.Fatal("a CA file with no certificate gave a fingerprint")
	}
}

// InstallQemuMigrationTLS validates a credential set before it writes any of
// it: a CA that is not a certificate, a CA that is a directory, or a host
// certificate another CA issued is refused as ErrInvalidMigrationCredentials,
// and QEMU's directory is left as it was. Lab 1 found a target that installed
// 30 bytes of garbage as ca-cert.pem and reported itself ready.
//
// Mutation: copy the CA unparsed — the garbage CA is installed, red.
func TestInstallQemuMigrationTLS_RefusesUnusableCredentials(t *testing.T) {
	for _, tc := range []struct {
		name  string
		spoil func(t *testing.T, pkiDir string)
	}{
		{"CA not PEM", func(t *testing.T, pkiDir string) {
			if err := os.WriteFile(filepath.Join(MigrationDir(pkiDir), MigrationCAName), []byte("this is not a certificate\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		}},
		{"CA a directory", func(t *testing.T, pkiDir string) {
			p := filepath.Join(MigrationDir(pkiDir), MigrationCAName)
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		}},
		{"host cert from another CA", func(t *testing.T, pkiDir string) {
			other := t.TempDir()
			provisionMigration(t, other)
			data, err := os.ReadFile(filepath.Join(MigrationDir(other), MigrationCAName))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(MigrationDir(pkiDir), MigrationCAName), data, 0o644); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pkiDir := t.TempDir()
			provisionMigration(t, pkiDir)
			tc.spoil(t, pkiDir)
			qemuDir := filepath.Join(t.TempDir(), "qemu")
			ok, err := InstallQemuMigrationTLS(pkiDir, qemuDir, -1, -1)
			if ok || !errors.Is(err, ErrInvalidMigrationCredentials) {
				t.Fatalf("install = %v, %v; want refused as ErrInvalidMigrationCredentials", ok, err)
			}
			if _, statErr := os.Stat(filepath.Join(qemuDir, "ca-cert.pem")); !os.IsNotExist(statErr) {
				t.Fatalf("an unusable credential set was installed for QEMU (stat err %v)", statErr)
			}
		})
	}
}

// writeLeaf writes a migration host certificate and key issued by the CA at
// caCert/caKey, valid from notBefore to notAfter.
func writeLeaf(t *testing.T, caCert, caKey, certPath, keyPath string, notBefore, notAfter time.Time) {
	t.Helper()
	ca, key, err := loadCA(caCert, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "node-1"},
		NotBefore: notBefore, NotAfter: notAfter, IPAddresses: []net.IP{net.ParseIP("10.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	kb, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
}

// An expired (or not yet valid) host certificate is refused before anything
// is installed: QEMU's handshake would reject it mid-copy. A CA bundle (an old
// and a new CA, as during a rotation) whose second certificate issued the host
// certificate is accepted.
//
// Mutations: no validity check — the expired case installs, red. Check only
// the first certificate of the bundle — the bundle case is refused, red.
func TestInstallQemuMigrationTLS_ChecksValidityAndReadsTheWholeBundle(t *testing.T) {
	newSet := func(t *testing.T) (pkiDir, caCert, caKey string) {
		pkiDir = t.TempDir()
		caDir := t.TempDir()
		caCert, caKey = filepath.Join(caDir, MigrationCACertName), filepath.Join(caDir, MigrationCAKeyName)
		if err := GenerateMigrationCA(caCert, caKey); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(MigrationDir(pkiDir), 0o700); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := func(pkiDir, name string) string { return filepath.Join(MigrationDir(pkiDir), name) }

	t.Run("expired host certificate", func(t *testing.T) {
		pkiDir, caCert, caKey := newSet(t)
		writeLeaf(t, caCert, caKey, dir(pkiDir, MigrationHostCertName), dir(pkiDir, MigrationHostKeyName),
			time.Now().Add(-48*time.Hour), time.Now().Add(-24*time.Hour))
		data, _ := os.ReadFile(caCert)
		if err := os.WriteFile(dir(pkiDir, MigrationCAName), data, 0o644); err != nil {
			t.Fatal(err)
		}
		ok, err := InstallQemuMigrationTLS(pkiDir, filepath.Join(t.TempDir(), "qemu"), -1, -1)
		if ok || !errors.Is(err, ErrInvalidMigrationCredentials) || !strings.Contains(err.Error(), "expired") {
			t.Fatalf("install = %v, %v; want refused, the host certificate expired", ok, err)
		}
	})
	t.Run("bundle whose second CA issued the host certificate", func(t *testing.T) {
		pkiDir, caCert, caKey := newSet(t)
		writeLeaf(t, caCert, caKey, dir(pkiDir, MigrationHostCertName), dir(pkiDir, MigrationHostKeyName),
			time.Now().Add(-time.Hour), time.Now().Add(24*time.Hour))
		_, otherCA, _ := newSet(t)
		a, _ := os.ReadFile(otherCA)
		b, _ := os.ReadFile(caCert)
		if err := os.WriteFile(dir(pkiDir, MigrationCAName), append(a, b...), 0o644); err != nil {
			t.Fatal(err)
		}
		if ok, err := InstallQemuMigrationTLS(pkiDir, filepath.Join(t.TempDir(), "qemu"), -1, -1); !ok || err != nil {
			t.Fatalf("install = %v, %v; want the bundle accepted", ok, err)
		}
	})
}

// The migration CA fingerprint is of the CA file's certificates as a set: a
// rotation bundle listed in another order on another host compares equal, and
// a single CA keeps the fingerprint an older build computes (its DER's
// SHA-256), so the comparison holds across the roll.
//
// Mutation: fingerprint the first certificate only — the reordered bundles
// differ, red.
func TestMigrationCAFingerprint_IsOfTheBundleAsASet(t *testing.T) {
	a, b := t.TempDir(), t.TempDir()
	provisionMigration(t, a)
	provisionMigration(t, b)
	caA, _ := os.ReadFile(filepath.Join(MigrationDir(a), MigrationCAName))
	caB, _ := os.ReadFile(filepath.Join(MigrationDir(b), MigrationCAName))

	single, err := MigrationCAFingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	cert := readCert(t, filepath.Join(MigrationDir(a), MigrationCAName))
	sum := sha256.Sum256(cert.Raw)
	if single != hex.EncodeToString(sum[:]) {
		t.Fatalf("single-CA fingerprint = %s, want its DER's SHA-256 (what an older build computes)", single)
	}

	write := func(dir string, data []byte) {
		if err := os.WriteFile(filepath.Join(MigrationDir(dir), MigrationCAName), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(a, append(append([]byte{}, caA...), caB...))
	write(b, append(append([]byte{}, caB...), caA...))
	fa, err := MigrationCAFingerprint(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := MigrationCAFingerprint(b)
	if err != nil {
		t.Fatal(err)
	}
	if fa != fb {
		t.Fatalf("the same CAs in another order fingerprint differently: %s vs %s", fa, fb)
	}
	if fa == single {
		t.Fatal("a two-CA bundle fingerprints like one of its CAs alone")
	}
}
