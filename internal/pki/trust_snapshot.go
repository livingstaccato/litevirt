package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

const (
	maxTrustCRLBytes     = 16 << 20
	maxTrustCRLs         = 4096
	maxTrustSuccessors   = 16384
	maxTrustCertificates = 8
	maxHostValidations   = 256
)

// HostTrust is immutable local PKI evidence. It confers no membership,
// database incarnation, source-cut completeness or publication authority.
// Its private pools/maps never escape. Verification never learns evidence.
type HostTrust struct {
	publicEvidence                  *HostTrustEvidence
	owner                           *trustOwner
	nonce                           [32]byte
	revision                        uint64
	digest                          [32]byte
	at                              time.Time
	sourceNotBefore, sourceNotAfter time.Time
	host                            string
	root                            *x509.Certificate
	roots                           *x509.CertPool
	crls                            []*x509.RevocationList
	revoked                         map[string]bool
	successors                      map[string][]supersession
	served                          *tls.Certificate
	policy                          bool
}

// HostCertificateValidation is process-only PKI validation. Zero values,
// copied values and IDs retained from another process are not capabilities.
type HostCertificateValidation struct {
	view                *HostTrust
	host                string
	fingerprint         [32]byte
	notBefore, notAfter time.Time
}

func CaptureHostTrust(ctx context.Context, dir, host string) (*HostTrust, error) {
	o, err := trustOwnerFor(dir)
	if err != nil {
		return nil, err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	return o.captureLocked(host)
}

func strictCertificateBundle(raw []byte, limit int) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for rest := bytes.TrimSpace(raw); len(rest) != 0; {
		if len(certs) == limit || !bytes.HasPrefix(rest, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, errors.New("invalid or over-bound certificate evidence")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return nil, errors.New("invalid certificate PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		rest = bytes.TrimSpace(tail)
	}
	if len(certs) == 0 {
		return nil, errors.New("empty certificate evidence")
	}
	return certs, nil
}

func readOptionalTrustFile(path string, bound int) ([]byte, error) {
	b, err := readBoundedN(path, bound)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

func (o *trustOwner) captureLocked(host string) (*HostTrust, error) {
	if o.retired {
		return nil, errors.New("trust owner belongs to a reinitialized domain; restart required")
	}
	if o.policyCell != nil && o.policyCell.Load() != o.policy {
		return nil, errors.New("effective host policy changed outside owner")
	}
	if host == "" || len(host) > 253 {
		return nil, errors.New("invalid local host name")
	}
	rootPEM, err := readBounded(filepath.Join(o.dir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	roots, err := strictCertificateBundle(rootPEM, 1)
	if err != nil || len(roots) != 1 || !roots[0].IsCA {
		return nil, errors.New("invalid local root")
	}
	root := roots[0]
	if len(o.root) != 0 && !bytes.Equal(o.root, root.Raw) {
		return nil, errors.New("unproved local root replacement")
	}
	if len(o.root) == 0 {
		o.root = bytes.Clone(root.Raw)
	}
	v := &HostTrust{owner: o, nonce: o.nonce, host: host, at: time.Now(), root: root, roots: x509.NewCertPool(), revoked: make(map[string]bool), successors: make(map[string][]supersession), policy: o.policy}
	v.roots.AddCert(root)
	crlPEM, err := readOptionalTrustFile(filepath.Join(o.dir, "crl.pem"), maxTrustCRLBytes)
	if err != nil {
		return nil, err
	}
	if crlPEM == nil && o.crlEstablished {
		return nil, errors.New("established CRL is missing")
	}
	for rest := bytes.TrimSpace(crlPEM); len(rest) != 0; {
		if len(v.crls) == maxTrustCRLs || !bytes.HasPrefix(rest, []byte("-----BEGIN X509 CRL-----")) {
			return nil, errors.New("invalid or over-bound CRL evidence")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 {
			return nil, errors.New("invalid CRL PEM")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, err
		}
		if err := crl.CheckSignatureFrom(root); err != nil {
			return nil, err
		}
		if crl.Number == nil || crl.Number.Sign() < 0 || !crl.Number.IsInt64() {
			return nil, errors.New("invalid CRL number")
		}
		for _, entry := range crl.RevokedCertificateEntries {
			v.revoked[entry.SerialNumber.Text(16)] = true
		}
		v.crls = append(v.crls, crl)
		rest = bytes.TrimSpace(tail)
	}
	if crlPEM != nil && len(v.crls) == 0 {
		return nil, errors.New("empty installed CRL")
	}
	for serial := range o.revokedFloor {
		if !v.revoked[serial] {
			return nil, errors.New("installed CRL lost established revocations")
		}
	}
	v.served, err = hostIdentitySource(o.dir).getTrustLocked()
	if err != nil {
		return nil, err
	}
	fingerprint := sha256.Sum256(v.served.Certificate[0])
	if o.servedFingerprint != fingerprint {
		o.invalidateLocked()
		o.servedFingerprint = fingerprint
	}
	certPEM, err := readBounded(filepath.Join(o.dir, "host.crt"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := readBounded(filepath.Join(o.dir, "host.key"))
	if err != nil {
		return nil, err
	}
	installed, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	if len(installed.Certificate) != len(v.served.Certificate) {
		return nil, errors.New("served and installed identity differ")
	}
	for i, raw := range installed.Certificate {
		if !bytes.Equal(raw, v.served.Certificate[i]) {
			return nil, errors.New("served and installed identity differ")
		}
	}

	// X509KeyPair owns freshly parsed DER/key material; the served source's
	// caller-visible Certificate/Leaf values must never alias this snapshot.
	v.served = &installed
	if v.served.Leaf == nil {
		v.served.Leaf, err = x509.ParseCertificate(v.served.Certificate[0])
		if err != nil {
			return nil, err
		}
	}
	_, v.sourceNotBefore, v.sourceNotAfter, err = v.verifyHost(v.served.Certificate, host, true)
	if err != nil {
		return nil, fmt.Errorf("served identity: %w", err)
	}
	// The authenticated installed renewal is itself durable successor evidence.
	// Learn under the existing owner/file barrier before freezing the view;
	// pure validation below never learns or writes evidence.
	o.noteSuccessorLocked(v.served.Leaf)
	successorPEM, err := v.captureSuccessorsLocked()
	if err != nil {
		return nil, err
	}
	_, v.sourceNotBefore, v.sourceNotAfter, err = v.verifyHost(v.served.Certificate, host, true)
	if err != nil {
		return nil, fmt.Errorf("served identity: %w", err)
	}
	v.publicEvidence = &HostTrustEvidence{rootPEM: bytes.Clone(rootPEM), crlPEM: bytes.Clone(crlPEM), successorPEM: bytes.Clone(successorPEM), leaf: bytes.Clone(v.served.Leaf.Raw), policy: v.policy, root: root}
	v.digest = v.publicEvidence.Digest()
	for name, body := range map[string][]byte{"ca.crt": rootPEM, "crl.pem": crlPEM, supersededFile: successorPEM, "host.crt": certPEM, "host.key": keyPEM} {
		if body != nil {
			if err := durableTrustReopen(filepath.Join(o.dir, name), body); err != nil {
				o.dirty = err
				return nil, err
			}
		}
	}
	// Leaf and visible-parent syncs do not persist host.d/current. Reconcile
	// that intermediate directory entry before certifying an active switch.
	if _, err := os.Lstat(hostDir(o.dir)); err == nil {
		if err := syncTrustDirectory(hostDir(o.dir)); err != nil {
			o.dirty = err
			return nil, err
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		o.dirty = err
		return nil, err
	}
	if v.digest != o.digest {
		o.invalidateLocked()
		o.digest = v.digest
	}
	for serial := range v.revoked {
		o.revokedFloor[serial] = true
	}
	if crlPEM != nil {
		o.crlEstablished = true
	}
	o.dirty = nil
	v.revision = o.revision
	return v, nil
}

func (v *HostTrust) captureSuccessorsLocked() ([]byte, error) {
	store := supersessionsFor(v.owner.dir)
	store.mu.Lock()
	defer store.mu.Unlock()
	store.fileNext = time.Time{}
	if !store.loadLocked() || !store.fileRead || store.fileErr != "" || store.unsaved || !bytes.Equal(store.ca.Raw, v.root.Raw) {
		return nil, errors.New("successor evidence is unavailable or not durable")
	}
	raw, err := readOptionalTrustFile(filepath.Join(v.owner.dir, supersededFile), maxSupersededBytes)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	if raw != nil {
		certs, err = strictCertificateBundle(raw, maxTrustSuccessors)
		if err != nil {
			return nil, err
		}
	}
	disk := make(map[string]bool, len(certs))
	for _, cert := range certs {
		prev, ok := RenewedFromSerial(cert)
		if !ok || cert.Subject.CommonName == "" || !hasUsage(cert, x509.ExtKeyUsageServerAuth) {
			return nil, errors.New("invalid successor evidence")
		}
		if _, err := cert.Verify(x509.VerifyOptions{Roots: v.roots, CurrentTime: cert.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
			return nil, err
		}
		disk[cert.SerialNumber.Text(16)] = true
		v.successors[prev] = append(v.successors[prev], supersession{cn: cert.Subject.CommonName, successor: cert})
	}
	presentSuccessors := make(map[[32]byte]bool, len(certs))
	for _, cert := range certs {
		presentSuccessors[sha256.Sum256(cert.Raw)] = true
	}
	for digest := range v.owner.successorFloor {
		if !presentSuccessors[digest] {
			return nil, errors.New("installed successors lost completed signed evidence")
		}
	}
	for _, list := range store.byPrev {
		for _, proof := range list {
			if !disk[proof.successor.SerialNumber.Text(16)] {
				return nil, errors.New("successor evidence exists only in memory")
			}
		}
	}
	return raw, nil
}

func (o *trustOwner) invalidateLocked() {
	o.revision++
	o.capabilities = make(map[*HostCertificateValidation]bool)
}

func (v *HostTrust) standing(cn, serial string, depth int) bool {
	if depth > maxSupersessionChain {
		return false
	}
	for _, s := range v.successors[serial] {
		if s.cn != cn {
			continue
		}
		next := s.successor.SerialNumber.Text(16)
		if !v.revoked[next] || v.standing(cn, next, depth+1) {
			return true
		}
	}
	return false
}

func (v *HostTrust) verifyHost(chain [][]byte, host string, served bool) ([32]byte, time.Time, time.Time, error) {
	fail := func(err error) ([32]byte, time.Time, time.Time, error) {
		return [32]byte{}, time.Time{}, time.Time{}, err
	}
	if v == nil || v.owner == nil || host == "" || len(host) > 253 || len(chain) == 0 || len(chain) > maxTrustCertificates {
		return fail(errors.New("invalid host validation input"))
	}
	var certs []*x509.Certificate
	size := 0
	for _, raw := range chain {
		size += len(raw)
		if size > maxServingChainBytes {
			return fail(errors.New("host chain too large"))
		}
		cert, err := x509.ParseCertificate(bytes.Clone(raw))
		if err != nil {
			return fail(err)
		}
		certs = append(certs, cert)
	}
	leaf := certs[0]
	if leaf.IsCA || leaf.Subject.CommonName != host || !hasUsage(leaf, x509.ExtKeyUsageServerAuth) || !hasUsage(leaf, x509.ExtKeyUsageClientAuth) {
		return fail(errors.New("certificate is not expected host with both host EKUs"))
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	now := time.Now()
	before, after := leaf.NotBefore, leaf.NotAfter
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		paths, err := leaf.Verify(x509.VerifyOptions{Roots: v.roots, Intermediates: intermediates, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{usage}})
		if err != nil {
			return fail(err)
		}
		for _, cert := range paths[0] {
			if v.revoked[cert.SerialNumber.Text(16)] {
				return fail(errors.New("certificate is revoked"))
			}
			if cert.NotBefore.After(before) {
				before = cert.NotBefore
			}
			if cert.NotAfter.Before(after) {
				after = cert.NotAfter
			}
		}
	}
	if (served || !v.policy) && v.standing(host, leaf.SerialNumber.Text(16), 0) {
		return fail(errors.New("certificate has a standing successor"))
	}
	return sha256.Sum256(leaf.Raw), before, after, nil
}

// ValidateHostCertificate validates only PKI predicates. Transport identity,
// admission, database incarnation and membership belong to their real owners.
func (v *HostTrust) ValidateHostCertificate(ctx context.Context, chain [][]byte, host string) (*HostCertificateValidation, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fp, before, after, err := v.verifyHost(chain, host, false)
	if err != nil {
		return nil, err
	}
	if v.sourceNotBefore.After(before) {
		before = v.sourceNotBefore
	}
	if v.sourceNotAfter.Before(after) {
		after = v.sourceNotAfter
	}
	o := v.owner
	select {
	case o.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-o.gate }()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v.nonce != o.nonce || v.revision != o.revision || v.digest != o.digest || o.dirty != nil {
		return nil, errors.New("host trust changed")
	}
	now := time.Now()
	if now.Before(v.at) || now.Before(before) || !now.Before(after) {
		return nil, errors.New("host certificate validity changed during validation")
	}
	for cap := range o.capabilities {
		if !now.Before(cap.notAfter) {
			delete(o.capabilities, cap)
		}
	}
	if len(o.capabilities) >= maxHostValidations {
		return nil, errors.New("too many live host validations")
	}
	cap := &HostCertificateValidation{view: v, host: host, fingerprint: fp, notBefore: before, notAfter: after}
	o.capabilities[cap] = true
	return cap, nil
}

// EvidenceDigest identifies public evidence, not live or application authority.
func (v *HostTrust) EvidenceDigest() [32]byte {
	if v == nil {
		return [32]byte{}
	}
	return v.digest
}
