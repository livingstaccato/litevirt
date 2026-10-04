package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
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

// MigrationDir is the host's migration-credential directory under pkiDir.
func MigrationDir(pkiDir string) string { return filepath.Join(pkiDir, MigrationDirName) }

// parseCABundle returns every certificate in a PEM bundle, in order. During a
// rotation a host's ca.crt holds the old CA and the new one.
func parseCABundle(data []byte) ([]*x509.Certificate, error) {
	var cas []*x509.Certificate
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse a CA certificate: %w", err)
		}
		if !c.IsCA {
			return nil, fmt.Errorf("%q in the CA bundle is not a CA", c.Subject.CommonName)
		}
		cas = append(cas, c)
	}
	if len(cas) == 0 {
		return nil, errors.New("the CA bundle holds no certificate")
	}
	return cas, nil
}

// ValidateMigrationCredentials checks a host's migration set as QEMU will use
// it: the key belongs to the certificate, and the certificate was issued by a
// CA in the bundle and is valid at now. A push copies the files one at a time,
// so a set read mid-push fails here instead of failing QEMU's handshake.
func ValidateMigrationCredentials(ca, cert, key []byte, now time.Time) (*x509.Certificate, []*x509.Certificate, error) {
	cas, err := parseCABundle(ca)
	if err != nil {
		return nil, nil, err
	}
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, cas, fmt.Errorf("the host key does not match its certificate "+
			"(a credential push may be in progress): %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, cas, fmt.Errorf("parse the host certificate: %w", err)
	}
	pool := x509.NewCertPool()
	for _, c := range cas {
		pool.AddCert(c)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:       pool,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return leaf, cas, fmt.Errorf("the host certificate is not issued by a CA in %s, "+
			"or has expired: %w", MigrationCAName, err)
	}
	return leaf, cas, nil
}

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
			return false, fmt.Errorf("read migration credential %s: %w", f.name, err)
		}
		*f.dst = data
	}

	if _, _, err := ValidateMigrationCredentials(ca, cert, key, time.Now()); err != nil {
		return false, fmt.Errorf("not installing migration credentials: %w", err)
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
