package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Migration TLS.
//
// A migration that copies disks cannot be tunnelled through libvirt's TLS
// connection: QEMU opens its own migration stream and NBD channel to the target.
// libvirt encrypts those (VIR_MIGRATE_TLS) with credentials QEMU itself reads
// from /etc/pki/qemu, inside an unprivileged process that a guest can escape
// into. So those credentials come from a SEPARATE migration CA, never the
// cluster CA: a compromised QEMU then holds a key that can only speak QEMU
// migration to peers, and nothing a peer's gRPC mTLS accepts.
const (
	// MigrationCACertName and MigrationCAKeyName are the migration CA, kept
	// beside the cluster CA on the machine that runs `lv host init`.
	MigrationCACertName = "migration-ca.crt"
	MigrationCAKeyName  = "migration-ca.key"

	// MigrationDirName is the per-host directory under pki_dir holding that
	// host's migration credentials.
	MigrationDirName      = "migration"
	MigrationCAName       = "ca.crt"
	MigrationHostCertName = "host.crt"
	MigrationHostKeyName  = "host.key"

	// QemuTLSDir is libvirt's default_tls_x509_cert_dir, which migration TLS
	// uses unless qemu.conf names another. Using it needs no qemu.conf change and
	// is already readable under the stock AppArmor/SELinux QEMU policies.
	QemuTLSDir = "/etc/pki/qemu"

	// qemuTLSManagedMarker marks QemuTLSDir as litevirt's to rewrite.
	qemuTLSManagedMarker = ".litevirt-migration-tls"
)

// ErrInvalidMigrationCredentials is a migration-credential set this host
// holds but cannot use: a CA that is not a certificate (or not a file), a host
// certificate the CA did not issue, a key that is not the certificate's. The
// fix is to reissue the set (`lv host install-migration-tls --reissue`).
var ErrInvalidMigrationCredentials = errors.New("migration-TLS credentials are unusable")

// MigrationDir is the host's migration-credential directory under pkiDir.
func MigrationDir(pkiDir string) string { return filepath.Join(pkiDir, MigrationDirName) }

// GenerateMigrationCA creates the migration CA: a self-signed ECDSA P-256 CA,
// distinct from the cluster CA. Host certificates are issued from it with
// GenerateHostCert.
func GenerateMigrationCA(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate migration CA key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"litevirt"},
			CommonName:   "litevirt Migration CA",
		},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create migration CA cert: %w", err)
	}
	if err := writePEM(certPath, "CERTIFICATE", certDER); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal migration CA key: %w", err)
	}
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER)
}

// MigrationCAFingerprint is the SHA-256 fingerprint (hex, of the DER) of the
// migration CA in this host's credential set under pkiDir: the CA its QEMU
// trusts and its migration certificate was issued from. "" with no error
// when the host has no migration credentials.
func MigrationCAFingerprint(pkiDir string) (string, error) {
	path := filepath.Join(MigrationDir(pkiDir), MigrationCAName)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("read migration CA: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return "", fmt.Errorf("%s holds no PEM certificate", path)
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", fmt.Errorf("%s holds no valid certificate: %v", path, err)
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

// InstallQemuMigrationTLS copies this host's migration credentials from
// pkiDir/migration into qemuDir under the names libvirt reads for migration TLS.
// The keys are written 0400 and, when keyUID >= 0, owned by keyUID:keyGID (the
// QEMU user), which is the only account that may read them.
//
// It returns false with no error when this host has no migration credentials
// (an older cluster not yet provisioned). It refuses, without writing, a
// qemuDir that holds files litevirt did not put there: that directory is
// libvirt's default and an operator may already use it.
func InstallQemuMigrationTLS(pkiDir, qemuDir string, keyUID, keyGID int) (bool, error) {
	src := MigrationDir(pkiDir)
	var ca, cert, key []byte
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{{MigrationCAName, &ca}, {MigrationHostCertName, &cert}, {MigrationHostKeyName, &key}} {
		data, err := os.ReadFile(filepath.Join(src, f.name))
		if errors.Is(err, fs.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			// A directory where the file should be, or a file that cannot be
			// read: the set is there and unusable, which reissuing fixes.
			return false, fmt.Errorf("%w: read migration credential %s: %v", ErrInvalidMigrationCredentials, f.name, err)
		}
		*f.dst = data
	}
	// QEMU parses these only when a migration opens its TLS channel, so a set
	// it cannot use failed mid-copy with a generic error. Check it here, before
	// anything is written, and report the host not ready.
	if err := validateMigrationCredentials(ca, cert, key); err != nil {
		return false, err
	}

	if err := claimQemuTLSDir(qemuDir); err != nil {
		return false, err
	}
	files := []struct {
		name  string
		data  []byte
		mode  os.FileMode
		isKey bool
	}{
		{"ca-cert.pem", ca, 0o444, false},
		{"server-cert.pem", cert, 0o444, false},
		{"client-cert.pem", cert, 0o444, false},
		{"server-key.pem", key, 0o400, true},
		{"client-key.pem", key, 0o400, true},
	}
	for _, f := range files {
		path := filepath.Join(qemuDir, f.name)
		uid, gid := -1, -1
		if f.isKey {
			// Owned by the QEMU user before it is renamed into place, so the key
			// is never readable by anyone else, even briefly.
			uid, gid = keyUID, keyGID
		}
		if err := secretfile.WriteOwned(path, f.data, f.mode, uid, gid); err != nil {
			return false, fmt.Errorf("install %s: %w", path, err)
		}
	}
	return true, nil
}

// validateMigrationCredentials checks a migration-credential set the way QEMU
// will use it: the CA is a CA certificate, the host certificate was issued by
// it, and the key is the certificate's. Any failure is
// ErrInvalidMigrationCredentials.
func validateMigrationCredentials(caPEM, certPEM, keyPEM []byte) error {
	ca, err := parsePEMCertificate(caPEM)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidMigrationCredentials, MigrationCAName, err)
	}
	if !ca.IsCA {
		return fmt.Errorf("%w: %s is not a CA certificate", ErrInvalidMigrationCredentials, MigrationCAName)
	}
	cert, err := parsePEMCertificate(certPEM)
	if err != nil {
		return fmt.Errorf("%w: %s: %v", ErrInvalidMigrationCredentials, MigrationHostCertName, err)
	}
	if err := cert.CheckSignatureFrom(ca); err != nil {
		return fmt.Errorf("%w: %s was not issued by the migration CA in %s: %v",
			ErrInvalidMigrationCredentials, MigrationHostCertName, MigrationCAName, err)
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return fmt.Errorf("%w: %s does not match %s: %v", ErrInvalidMigrationCredentials, MigrationHostKeyName, MigrationHostCertName, err)
	}
	return nil
}

// parsePEMCertificate parses the first PEM CERTIFICATE block of data.
func parsePEMCertificate(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("holds no PEM certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// claimQemuTLSDir makes qemuDir litevirt's: creates it if absent, accepts it if
// it is empty or already carries the marker, and refuses anything else.
func claimQemuTLSDir(qemuDir string) error {
	entries, err := os.ReadDir(qemuDir)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.MkdirAll(qemuDir, 0o755); err != nil {
			return fmt.Errorf("create %s: %w", qemuDir, err)
		}
	case err != nil:
		return fmt.Errorf("read %s: %w", qemuDir, err)
	case len(entries) > 0:
		if _, err := os.Stat(filepath.Join(qemuDir, qemuTLSManagedMarker)); err != nil {
			return fmt.Errorf("%s already holds files litevirt did not put there; refusing to "+
				"overwrite them, so storage migrations from or to this host stay unencrypted. "+
				"Move them aside (or point qemu.conf's migrate_tls_x509_cert_dir elsewhere for "+
				"them) and restart the litevirt daemon", qemuDir)
		}
	}
	marker := filepath.Join(qemuDir, qemuTLSManagedMarker)
	note := []byte("Managed by litevirt: migration TLS credentials, rewritten from " +
		"pki_dir/migration at daemon start. Do not edit.\n")
	if err := secretfile.Write(marker, note, 0o444); err != nil {
		return fmt.Errorf("mark %s as managed: %w", qemuDir, err)
	}
	return nil
}
