package pki

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// MigrationExpiryWarning is how far ahead the daemon and `lv doctor
// migration-tls` warn that migration credentials expire.
const MigrationExpiryWarning = 90 * 24 * time.Hour

// MigrationCAInfo is one CA a host's migration credentials trust.
type MigrationCAInfo struct {
	Fingerprint string
	NotAfter    time.Time
}

// MigrationTLSInfo is what a host's migration credentials hold, read from the
// same files the installer uses. An invalid set still reports its contents.
type MigrationTLSInfo struct {
	Provisioned           bool
	ValidationError       string
	TrustedCAs            []MigrationCAInfo
	CertIssuerFingerprint string
	CertNotAfter          time.Time
}

// MigrationExpiry is one credential that expires within MigrationExpiryWarning.
type MigrationExpiry struct {
	What     string // "host certificate" or "CA <fingerprint>"
	NotAfter time.Time
	Expired  bool
}

// CertFingerprint is the lowercase hex SHA-256 of a certificate's DER.
func CertFingerprint(c *x509.Certificate) string {
	sum := sha256.Sum256(c.Raw)
	return hex.EncodeToString(sum[:])
}

// CAFileFingerprint fingerprints the first certificate in a PEM file.
func CAFileFingerprint(path string) (string, error) {
	cas, err := readCABundleFile(path)
	if err != nil {
		return "", err
	}
	return CertFingerprint(cas[0]), nil
}

func readCABundleFile(path string) ([]*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseCABundle(data)
}

// InspectMigrationTLS reports pkiDir's migration credentials. A host with none
// is not an error: Provisioned is false.
func InspectMigrationTLS(pkiDir string, now time.Time) (MigrationTLSInfo, error) {
	var info MigrationTLSInfo
	dir := MigrationDir(pkiDir)
	var ca, cert, key []byte
	for _, f := range []struct {
		name string
		dst  *[]byte
	}{{MigrationCAName, &ca}, {MigrationHostCertName, &cert}, {MigrationHostKeyName, &key}} {
		data, err := os.ReadFile(filepath.Join(dir, f.name))
		if errors.Is(err, fs.ErrNotExist) {
			return info, nil
		}
		if err != nil {
			return info, fmt.Errorf("read migration credential %s: %w", f.name, err)
		}
		*f.dst = data
	}
	info.Provisioned = true

	cas, caErr := parseCABundle(ca)
	for _, c := range cas {
		info.TrustedCAs = append(info.TrustedCAs, MigrationCAInfo{Fingerprint: CertFingerprint(c), NotAfter: c.NotAfter})
	}
	if b, _ := pem.Decode(cert); b != nil {
		if leaf, err := x509.ParseCertificate(b.Bytes); err == nil {
			info.CertNotAfter = leaf.NotAfter
			for _, c := range cas {
				if leaf.CheckSignatureFrom(c) == nil {
					info.CertIssuerFingerprint = CertFingerprint(c)
					break
				}
			}
		}
	}
	if caErr != nil {
		info.ValidationError = caErr.Error()
	} else if _, _, err := ValidateMigrationCredentials(ca, cert, key, now); err != nil {
		info.ValidationError = err.Error()
	}
	return info, nil
}

// Expiring lists the host certificate and each trusted CA that expires within
// MigrationExpiryWarning of now, certificate first.
func (i MigrationTLSInfo) Expiring(now time.Time) []MigrationExpiry {
	var out []MigrationExpiry
	add := func(what string, t time.Time) {
		if !t.IsZero() && t.Before(now.Add(MigrationExpiryWarning)) {
			out = append(out, MigrationExpiry{What: what, NotAfter: t, Expired: !t.After(now)})
		}
	}
	add("host certificate", i.CertNotAfter)
	for _, c := range i.TrustedCAs {
		add("CA "+c.Fingerprint, c.NotAfter)
	}
	return out
}
