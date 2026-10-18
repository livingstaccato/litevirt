package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"path/filepath"
	"time"
)

// MaxHostTrustEvidenceBytes bounds the entire binary public wrapper, including
// framing. It is not a transport response limit. No private key is serialized.
const MaxHostTrustEvidenceBytes = 2*maxServingChainBytes + maxTrustCRLBytes + maxSupersededBytes + 29

// HostTrustEvidence is inert retained signed public evidence. Decoding it does
// not select local trust, create current validation, or prove DB completion.
type HostTrustEvidence struct {
	rootPEM, crlPEM, successorPEM, leaf []byte
	policy                              bool
	root                                *x509.Certificate
	crls                                []*x509.RevocationList
	successors                          []*x509.Certificate
}

func trustEvidenceDigest(root, crls, successors, leaf []byte, policy bool) [32]byte {
	h := sha256.New()
	for _, b := range [][]byte{[]byte("litevirt-host-trust-v1"), root, crls, successors, leaf, []byte(fmt.Sprint(policy))} {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func (v *HostTrust) PublicEvidence() ([]byte, error) {
	if v == nil || v.publicEvidence == nil {
		return nil, errors.New("missing captured public evidence")
	}
	e := v.publicEvidence
	if e.Digest() != v.digest {
		return nil, errors.New("captured evidence digest differs")
	}
	var b bytes.Buffer
	b.WriteString("LVTRUST1")
	policy := byte(0)
	if e.policy {
		policy = 1
	}
	for _, part := range [][]byte{e.rootPEM, e.crlPEM, e.successorPEM, e.leaf, {policy}} {
		if len(part) > MaxHostTrustEvidenceBytes-b.Len()-4 {
			return nil, errors.New("trust evidence exceeds bound")
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		b.Write(n[:])
		b.Write(part)
	}
	return b.Bytes(), nil
}

func DecodeHostTrustEvidence(raw []byte) (*HostTrustEvidence, error) {
	if len(raw) > MaxHostTrustEvidenceBytes || !bytes.HasPrefix(raw, []byte("LVTRUST1")) {
		return nil, errors.New("unsupported trust evidence")
	}
	rest := raw[8:]
	var parts [][]byte
	for _, limit := range []int{maxServingChainBytes, maxTrustCRLBytes, maxSupersededBytes, maxServingChainBytes, 1} {
		if len(rest) < 4 {
			return nil, errors.New("truncated trust evidence")
		}
		n := uint64(binary.BigEndian.Uint32(rest))
		rest = rest[4:]
		if n > uint64(limit) || n > uint64(len(rest)) {
			return nil, errors.New("over-bound trust evidence item")
		}
		parts = append(parts, bytes.Clone(rest[:int(n)]))
		rest = rest[int(n):]
	}
	if len(rest) != 0 || len(parts[4]) != 1 || parts[4][0] > 1 {
		return nil, errors.New("invalid trust evidence framing")
	}
	e := &HostTrustEvidence{rootPEM: parts[0], crlPEM: parts[1], successorPEM: parts[2], leaf: parts[3], policy: parts[4][0] == 1}
	roots, err := strictCertificateBundle(e.rootPEM, 1)
	if err != nil || !roots[0].IsCA {
		return nil, errors.New("invalid retained root")
	}
	e.root = roots[0]
	if _, err := x509.ParseCertificate(e.leaf); err != nil {
		return nil, err
	}
	for rest := bytes.TrimSpace(e.crlPEM); len(rest) != 0; {
		if len(e.crls) >= maxTrustCRLs || !bytes.HasPrefix(rest, []byte("-----BEGIN X509 CRL-----")) {
			return nil, errors.New("invalid retained CRL bundle")
		}
		block, tail := pem.Decode(rest)
		if block == nil || block.Type != "X509 CRL" || len(block.Headers) != 0 {
			return nil, errors.New("invalid retained CRL")
		}
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return nil, err
		}
		if err := crl.CheckSignatureFrom(e.root); err != nil {
			return nil, err
		}
		if crl.Number == nil || crl.Number.Sign() < 0 || !crl.Number.IsInt64() {
			return nil, errors.New("invalid retained CRL number")
		}
		e.crls = append(e.crls, crl)
		rest = bytes.TrimSpace(tail)
	}
	if len(e.crlPEM) != 0 && len(e.crls) == 0 {
		return nil, errors.New("empty retained CRL bundle")
	}
	if len(e.successorPEM) != 0 {
		e.successors, err = strictCertificateBundle(e.successorPEM, maxTrustSuccessors)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		pool.AddCert(e.root)
		for _, cert := range e.successors {
			if _, ok := RenewedFromSerial(cert); !ok || cert.Subject.CommonName == "" || !hasUsage(cert, x509.ExtKeyUsageServerAuth) {
				return nil, errors.New("invalid retained successor")
			}
			if _, err := cert.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: cert.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
				return nil, err
			}
		}
	}
	return e, nil
}
func (e *HostTrustEvidence) Digest() [32]byte {
	if e == nil {
		return [32]byte{}
	}
	return trustEvidenceDigest(e.rootPEM, e.crlPEM, e.successorPEM, e.leaf, e.policy)
}
func (e *HostTrustEvidence) RootDigest() [32]byte {
	if e == nil || e.root == nil {
		return [32]byte{}
	}
	return sha256.Sum256(e.root.Raw)
}

// VerifyRecordedHost authenticates retained evidence only. Its historical time
// cannot be used as a current host validation or lease. Storage must separately
// verify the exact signed artifact and that its row actually committed.
func (e *HostTrustEvidence) VerifyRecordedHost(chain [][]byte, host string) error {
	if e == nil || e.root == nil || len(chain) == 0 || len(chain) > maxTrustCertificates || !bytes.Equal(chain[0], e.leaf) {
		return errors.New("recorded served identity differs")
	}
	return e.VerifyRecordedPeer(chain, host)
}

// VerifyRecordedPeer authenticates an inert historical peer chain against this
// evidence's root. It does not validate a current peer or issue a capability.
func (e *HostTrustEvidence) VerifyRecordedPeer(chain [][]byte, host string) error {
	if e == nil || e.root == nil || len(chain) == 0 || len(chain) > maxTrustCertificates || host == "" || len(host) > 253 {
		return errors.New("invalid recorded peer chain")
	}
	roots := x509.NewCertPool()
	roots.AddCert(e.root)
	inter := x509.NewCertPool()
	var leaf *x509.Certificate
	at := e.root.NotBefore
	size := 0
	for i, raw := range chain {
		size += len(raw)
		if size > maxServingChainBytes {
			return errors.New("recorded host chain exceeds bound")
		}
		cert, err := x509.ParseCertificate(raw)
		if err != nil {
			return err
		}
		if cert.NotBefore.After(at) {
			at = cert.NotBefore
		}
		if i == 0 {
			leaf = cert
		} else {
			inter.AddCert(cert)
		}
	}
	if leaf.IsCA || leaf.Subject.CommonName != host || !hasUsage(leaf, x509.ExtKeyUsageClientAuth) || !hasUsage(leaf, x509.ExtKeyUsageServerAuth) {
		return errors.New("invalid recorded host")
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter, CurrentTime: at.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
			return err
		}
	}
	return nil
}

// ReconcileCompletedHostTrust compares inert evidence with the genuine local
// domain and installs monotone signed-object floors under the real owner/file
// lock. The storage startup owner alone selects completed publications. Missing
// files refuse; a supported durable repair and new capture can then progress.
func ReconcileCompletedHostTrust(ctx context.Context, dir, host string, e *HostTrustEvidence) error {
	if e == nil || e.root == nil {
		return errors.New("missing completed trust evidence")
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
	raw, err := readBounded(filepath.Join(o.dir, "ca.crt"))
	if err != nil {
		return err
	}
	roots, err := strictCertificateBundle(raw, 1)
	if err != nil || !bytes.Equal(roots[0].Raw, e.root.Raw) || (len(o.root) != 0 && !bytes.Equal(o.root, e.root.Raw)) {
		return errors.New("completed evidence differs from configured trust domain")
	}
	if o.successorFloor == nil {
		o.successorFloor = make(map[[32]byte][]byte)
	}
	// A failed reconciliation cannot accumulate an unbounded union across
	// repeated startup attempts. This exceeds the possible serial payload of a
	// supported 16 MiB current signed CRL bundle while bounding map overhead.
	revokedBytes := 0
	for serial := range o.revokedFloor {
		revokedBytes += len(serial)
	}
	// Full signed historical CRLs remain in completed rows. Current verified
	// CRLs may cover them with a newer signed union, as both supported minting
	// and installation prune covered members. Require every branch's effects.
	for _, crl := range e.crls {
		o.crlEstablished = true
		for _, entry := range crl.RevokedCertificateEntries {
			serial := entry.SerialNumber.Text(16)
			if !o.revokedFloor[serial] {
				if len(o.revokedFloor) >= 1<<20 || len(serial) > 2*maxTrustCRLBytes-revokedBytes {
					return errors.New("completed revocation floor exceeds bound")
				}
				o.revokedFloor[serial] = true
				revokedBytes += len(serial)
			}
		}
	}
	size := 0
	for _, raw := range o.successorFloor {
		size += len(raw)
	}
	for _, cert := range e.successors {
		digest := sha256.Sum256(cert.Raw)
		if _, ok := o.successorFloor[digest]; !ok {
			if len(o.successorFloor) >= maxTrustSuccessors || len(cert.Raw) > maxSupersededBytes-size {
				return errors.New("completed successor floor exceeds bound")
			}
			o.successorFloor[digest] = bytes.Clone(cert.Raw)
			size += len(cert.Raw)
		}
	}
	// A new snapshot revalidates current identity, effective policy, unsaved
	// evidence, and file/directory durability after the floors are installed.
	_, err = o.captureLocked(host)
	return err
}

// RecordedLocalHost authenticates the original public leaf of legacy local
// evidence under its original root, at their overlapping recorded interval.
// Legacy evidence did not retain intermediates: only a complete direct-root
// path is accepted. This authenticates inert provenance for storage-owned
// reestablishment, never current standing, policy, expiry or a lease. Ordinary
// Historical verification is deliberately unchanged.
func (e *HostTrustEvidence) RecordedLocalHost(host string) (*x509.Certificate, error) {
	if e == nil {
		return nil, errors.New("missing recorded local evidence")
	}
	if err := e.VerifyRecordedHost([][]byte{e.leaf}, host); err != nil {
		return nil, err
	}
	return x509.ParseCertificate(bytes.Clone(e.leaf))
}
