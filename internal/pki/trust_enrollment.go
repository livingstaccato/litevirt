package pki

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// HostEnrollment owns bounded, validated staging bytes. It is neither a
// membership assertion nor authorization to replace an existing trust domain.
type HostEnrollment struct {
	host          string
	ca, cert, key []byte
	root, leaf    *x509.Certificate
}

func ValidateHostEnrollment(host string, ca, cert, key []byte) (*HostEnrollment, error) {
	return validateHostEnrollmentAt(host, ca, cert, key, time.Now())
}

func validateHostEnrollmentAt(host string, ca, cert, key []byte, at time.Time) (*HostEnrollment, error) {
	if host == "" || len(host) > 253 || len(ca) > 1<<20 || len(cert) > 1<<20 || len(key) > 1<<20 {
		return nil, errors.New("invalid or oversized enrollment input")
	}
	roots, err := strictCertificateBundle(ca, 1)
	if err != nil || !roots[0].IsCA {
		return nil, errors.New("invalid enrollment root")
	}
	chain, err := strictCertificateBundle(cert, maxTrustCertificates)
	if err != nil {
		return nil, err
	}
	block, tail := pem.Decode(key)
	if block == nil || len(block.Headers) != 0 || len(bytes.TrimSpace(tail)) != 0 {
		return nil, errors.New("invalid enrollment private key")
	}
	if _, err := tls.X509KeyPair(cert, key); err != nil {
		return nil, errors.New("enrollment certificate and private key do not match")
	}
	leaf := chain[0]
	if leaf.Subject.CommonName != host || leaf.IsCA {
		return nil, errors.New("enrollment host identity mismatch")
	}
	pool := x509.NewCertPool()
	pool.AddCert(roots[0])
	intermediates := x509.NewCertPool()
	for _, c := range chain[1:] {
		intermediates.AddCert(c)
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		explicit := false
		for _, u := range leaf.ExtKeyUsage {
			if u == usage {
				explicit = true
			}
		}
		if !explicit {
			return nil, errors.New("enrollment host requires explicit client and server usages")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: at}); err != nil {
			return nil, fmt.Errorf("enrollment certificate verification: %w", err)
		}
	}
	if !hexSerialRE.MatchString(leaf.SerialNumber.Text(16)) {
		return nil, errors.New("unsupported enrollment certificate serial")
	}
	return &HostEnrollment{host: host, ca: bytes.Clone(ca), cert: bytes.Clone(cert), key: bytes.Clone(key), root: roots[0], leaf: leaf}, nil
}

// InstallHostEnrollment permits first enrollment or same-root/same-host repair.
// Network, configuration, service control and administrative intent stay outside
// the local owner mutation boundary.
func InstallHostEnrollment(ctx context.Context, dir string, m *HostEnrollment) error {
	return installHostEnrollment(ctx, dir, m, false)
}

// ReinitializeHostDomain is the local PKI portion of an explicitly authorized
// quiescent reinitialization. The actual exclusive admission must remain held
// around all other pre-start effects. It never refreshes this process's owner.
func ReinitializeHostDomain(ctx context.Context, dir string, m *HostEnrollment, admission *HostDomainLease) error {
	if admission == nil {
		return errors.New("exclusive host domain admission required")
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if err := admission.checkLocked(dir); err != nil {
		return err
	}
	return installHostEnrollment(ctx, dir, m, true)
}

func installHostEnrollment(ctx context.Context, dir string, m *HostEnrollment, reinitialize bool) (err error) {
	if m == nil || m.root == nil || m.leaf == nil {
		return errors.New("validated enrollment input required")
	}
	// Revalidate current time at the actual mutation boundary, after any waits.
	if _, err := ValidateHostEnrollment(m.host, m.ca, m.cert, m.key); err != nil {
		return err
	}
	o, err := trustOwnerFor(dir)
	if err != nil {
		return err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return err
	}
	defer lock.release()
	return installHostEnrollmentLocked(ctx, o, m, reinitialize, nil)
}

func installHostEnrollmentLocked(ctx context.Context, o *trustOwner, m *HostEnrollment, reinitialize bool, undo *HostEnrollmentUndo) (err error) {
	if _, err := ValidateHostEnrollment(m.host, m.ca, m.cert, m.key); err != nil {
		return err
	}
	if !reinitialize {
		for _, name := range []string{"ca.crt", "host.crt", "host.key"} {
			path := filepath.Join(o.dir, name)
			if _, e := os.Lstat(path); e == nil {
				if _, e := os.Stat(path); e != nil {
					return errors.New("existing enrollment path is unreadable; quiescent repair required")
				}
			} else if !errors.Is(e, os.ErrNotExist) {
				return e
			}
		}
	}
	oldCA, err := readOptionalTrustFile(filepath.Join(o.dir, "ca.crt"), 1<<20)
	if err != nil {
		return err
	}
	oldCert, err := readOptionalTrustFile(filepath.Join(o.dir, "host.crt"), 1<<20)
	if err != nil {
		return err
	}
	oldKey, err := readOptionalTrustFile(filepath.Join(o.dir, "host.key"), 1<<20)
	if err != nil {
		return err
	}
	sameRoot := false
	if oldCA != nil {
		roots, e := strictCertificateBundle(oldCA, 1)
		if e == nil && roots[0].IsCA {
			sameRoot = bytes.Equal(roots[0].Raw, m.root.Raw)
		} else if !reinitialize {
			return errors.New("existing root is invalid; quiescent reinitialization required")
		}
	}
	var previous *x509.Certificate
	if oldCert != nil || oldKey != nil {
		pair, e := tls.X509KeyPair(oldCert, oldKey)
		if e == nil {
			previous, e = x509.ParseCertificate(pair.Certificate[0])
		}
		if e != nil && !reinitialize {
			return errors.New("existing host identity is invalid; quiescent reinitialization required")
		}
	}
	if !reinitialize {
		if o.retired {
			return errors.New("enrollment owner belongs to a reinitialized domain; restart required")
		}
		if len(o.root) != 0 && !bytes.Equal(o.root, m.root.Raw) {
			return errors.New("enrollment cannot replace the established owner root")
		}
		if (len(o.root) != 0 || o.servedFingerprint != [32]byte{}) && (oldCA == nil || oldCert == nil || oldKey == nil) {
			return errors.New("established host identity is missing; quiescent repair required")
		}
		if oldCA != nil && !sameRoot {
			return errors.New("enrollment cannot replace an existing root")
		}
		if previous != nil && (oldCA == nil || previous.Subject.CommonName != m.host) {
			return errors.New("enrollment cannot replace an existing host identity")
		}
		if previous != nil {
			if _, e := validateHostEnrollmentAt(m.host, oldCA, oldCert, oldKey, previous.NotAfter.Add(-time.Second)); e != nil {
				return fmt.Errorf("existing host identity needs quiescent repair: %w", e)
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if previous != nil && !reinitialize {
		if err := checkEnrollmentPrevious(o.dir, previous.SerialNumber.Text(16), oldCert, oldKey); err != nil {
			return err
		}
	}
	if undo != nil {
		if err := undo.prepare(m, previous); err != nil {
			return err
		}
	}
	o.invalidateLocked()
	if reinitialize {
		o.retired = true
	}
	defer func() {
		if err != nil {
			o.dirty = err
		}
	}()
	// Complete a new pair before touching any active path. A same-serial collision
	// refuses rather than overwriting a retained recovery candidate.
	if err := os.MkdirAll(hostDir(o.dir), 0700); err != nil {
		return err
	}
	serial := m.leaf.SerialNumber.Text(16)
	final := filepath.Join(hostDir(o.dir), serial)
	if fi, e := os.Lstat(final); e == nil {
		if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
			return errors.New("retained enrollment candidate is not canonical")
		}
		cert, e := readBounded(filepath.Join(final, "host.crt"))
		if e != nil {
			return e
		}
		key, e := readBounded(filepath.Join(final, "host.key"))
		if e != nil {
			return e
		}
		if !bytes.Equal(cert, m.cert) || !bytes.Equal(key, m.key) {
			return errors.New("enrollment serial collides with a retained identity")
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	} else {
		staging, e := os.MkdirTemp(hostDir(o.dir), stagingPrefix)
		if e != nil {
			return e
		}
		defer os.RemoveAll(staging)
		if err := writeTrustFile(filepath.Join(staging, "host.key"), m.key, 0600); err != nil {
			return err
		}
		if err := writeTrustFile(filepath.Join(staging, "host.crt"), m.cert, 0644); err != nil {
			return err
		}
		if err := enrollmentStep(undo, enrollmentPlaceNew, func() error {
			if err := os.Rename(staging, final); err != nil {
				return err
			}
			return syncTrustDirectory(hostDir(o.dir))
		}); err != nil {
			return err
		}
	}
	if previous != nil && !reinitialize {
		if err := ensureEnrollmentLinkedLayout(o.dir, previous.SerialNumber.Text(16), undo); err != nil {
			return err
		}
	}
	if err := enrollmentStep(undo, enrollmentSwitchNew, func() error { return switchCurrent(o.dir, serial) }); err != nil {
		return err
	}
	for _, name := range []string{"host.key", "host.crt"} {
		step := enrollmentLinkKey
		if name == "host.crt" {
			step = enrollmentLinkCert
		}
		if err := enrollmentStep(undo, step, func() error {
			return atomicSymlink(filepath.Join(hostDirName, currentLinkName, name), filepath.Join(o.dir, name))
		}); err != nil {
			return err
		}
	}
	if reinitialize && !sameRoot {
		// Old-root evidence is not valid in the new domain. No DB provenance or
		// use floor is erased here; future startup consumers must reconcile those.
		for _, name := range []string{"crl.pem", supersededFile} {
			if err := os.Remove(filepath.Join(o.dir, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		if err := syncTrustDirectory(o.dir); err != nil {
			return err
		}
	}
	if err := enrollmentStep(undo, enrollmentWriteCA, func() error { return writeTrustFile(filepath.Join(o.dir, "ca.crt"), m.ca, 0644) }); err != nil {
		return err
	}
	for _, item := range []struct {
		name string
		body []byte
	}{{"ca.crt", m.ca}, {"host.crt", m.cert}, {"host.key", m.key}} {
		if err := durableTrustReopen(filepath.Join(o.dir, item.name), item.body); err != nil {
			return err
		}
	}
	return nil
}
