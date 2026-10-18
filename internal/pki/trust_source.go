package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"
)

// VerifyOrdinaryCertificate is a pure ordinary certificate check against this
// exact strict snapshot. It confers no claim or membership authority.
func (v *HostTrust) VerifyOrdinaryCertificate(raw []byte, historical, pinned bool) (time.Time, time.Time, error) {
	if v == nil || v.owner == nil || len(raw) == 0 || len(raw) > maxServingChainBytes {
		return time.Time{}, time.Time{}, errors.New("invalid ordinary certificate")
	}
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	paths, err := cert.Verify(x509.VerifyOptions{Roots: v.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	if !historical && v.revoked[cert.SerialNumber.Text(16)] {
		return time.Time{}, time.Time{}, errors.New("ordinary certificate revoked")
	}
	if !historical && pinned && !v.policy && v.standing(cert.Subject.CommonName, cert.SerialNumber.Text(16), 0) {
		return time.Time{}, time.Time{}, errors.New("ordinary certificate superseded")
	}
	before, after := cert.NotBefore, cert.NotAfter
	for _, c := range paths[0] {
		if c.NotBefore.After(before) {
			before = c.NotBefore
		}
		if c.NotAfter.Before(after) {
			after = c.NotAfter
		}
	}
	return before, after, nil
}

// ValidateServedHost binds a first-call captured pair to this snapshot's actual
// served identity, rather than merely validating another host certificate.
func (v *HostTrust) ValidateServedHost(ctx context.Context, pair *tls.Certificate) (*HostCertificateValidation, error) {
	if v == nil || v.served == nil || pair == nil || len(pair.Certificate) != len(v.served.Certificate) {
		return nil, errors.New("missing captured served identity")
	}
	for i, raw := range pair.Certificate {
		if !bytes.Equal(raw, v.served.Certificate[i]) {
			return nil, errors.New("captured signer is not the served identity")
		}
	}
	return v.ValidateHostCertificate(ctx, pair.Certificate, v.host)
}

// RootDigest names the actual local trust domain, not caller-selected roots.
func (v *HostTrust) RootDigest() [32]byte {
	if v == nil || v.root == nil {
		return [32]byte{}
	}
	return sha256.Sum256(v.root.Raw)
}
func (v *HostTrust) TrustRotatedPeers() bool { return v != nil && v.policy }

// Discard releases an unused registered validation. Call outside any lease;
// Release already consumes the registrations held by a lease.
func (v *HostCertificateValidation) Discard() {
	if v == nil || v.view == nil || v.view.owner == nil {
		return
	}
	o := v.view.owner
	o.gate <- struct{}{}
	delete(o.capabilities, v)
	<-o.gate
}

// VerifyHostCertificate checks a chain against this exact immutable snapshot
// without registering a live capability. It is suitable inside an existing
// lease; callers still own current capability/lease and signature validation.
func (v *HostTrust) VerifyHostCertificate(chain [][]byte, host string) (time.Time, time.Time, error) {
	_, before, after, err := v.verifyHost(chain, host, false)
	return before, after, err
}

// VerifyOriginalHostProvenance checks recorded-authorized original evidence
// against this exact current snapshot. The original leaf's later retirement,
// successor and expiry are historical; its signature, lower validity bound and
// every selected nonleaf/root predicate remain strict. Returned bounds cover
// all predicates that must remain current through the caller's final commit.
// No capability is registered. Current holders must use strict live validation.
func (v *HostTrust) VerifyOriginalHostProvenance(chain [][]byte, host string) (time.Time, time.Time, error) {
	_, before, after, err := v.verifyHostEvidence(chain, host, false, true)
	return before, after, err
}
