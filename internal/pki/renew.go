package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Host certificate renewal.
//
// A host certificate lasts five years and peers PIN it: each node records the
// serial its peers were admitted with (hosts.cert_serial) and refuses a peer
// presenting any other (grpcapi isTrustedHostCN). The pin is what keeps a
// re-admitted name's OLD certificate out, so it cannot simply be relaxed for a
// renewal — and a renewal that leans on replication to carry the new serial
// leaves a window in which every peer refuses the renewed node.
//
// So the renewed certificate says, with the CA's signature, which certificate
// it replaces: a non-critical extension carrying the predecessor's serial. A
// peer whose record still names the predecessor accepts the successor at once,
// and nothing else changes:
//
//   - only the CA can mint it, so a node cannot declare itself anyone's
//     successor;
//   - it names exactly one predecessor, so a re-admitted name's old certificate
//     — minted BEFORE the admission it would have to name — can never carry
//     the serial that admission recorded;
//   - once the renewed node re-records its own serial (the daemon does this
//     within a minute of adopting it), the record names the successor and the
//     extension stops mattering.
//
// It is non-critical so a verifier that does not know it — an older litevirt,
// libvirt's GnuTLS — still accepts the certificate. An older peer does not
// honour it; it refuses the renewed node until the re-recorded serial reaches
// it by anti-entropy, exactly as it would for any other reissue.

// hostCertRenewalOfOID carries the predecessor's serial (ASN.1 INTEGER).
// Same private arc as auditSigningGenerationOID.
var hostCertRenewalOfOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61117, 1, 2}

// hostCertValidity is the lifetime of a host certificate, minted or renewed.
const hostCertValidity = 5 * 365 * 24 * time.Hour

// RenewedFromSerial returns the serial (lower-case hex) of the certificate cert
// was issued to replace, and false when cert is not a renewal.
func RenewedFromSerial(cert *x509.Certificate) (string, bool) {
	if cert == nil {
		return "", false
	}
	for _, ext := range cert.Extensions {
		if !ext.Id.Equal(hostCertRenewalOfOID) {
			continue
		}
		var prev *big.Int
		if rest, err := asn1.Unmarshal(ext.Value, &prev); err != nil || len(rest) != 0 || prev == nil || prev.Sign() <= 0 {
			return "", false
		}
		return strings.ToLower(prev.Text(16)), true
	}
	return "", false
}

// SignRenewal signs a successor to prev for the host named hostName over the
// public key in csrPEM — a request the HOST generated (GenerateRenewalCSR), so
// the new private key never leaves it. The certificate keeps prev's subject
// and SANs (the request's own names are ignored: the CA decides what a host
// certificate says), gets a fresh five-year validity, and carries the
// predecessor's serial in the renewal extension.
//
// prev must be a host certificate this CA issued to hostName. Renewing anything
// else would either mint a certificate peers refuse (another CA's) or hand a
// host a certificate in another host's name. The request must be signed by its
// key (proof of possession) and carry a P-256 ECDSA key, the only kind every
// consumer of a host key accepts (the recovery-claim signer requires ECDSA).
func SignRenewal(caCertPath, caKeyPath string, prev *x509.Certificate, hostName string, csrPEM []byte) ([]byte, error) {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	if prev == nil {
		return nil, fmt.Errorf("no certificate to renew")
	}
	if prev.Subject.CommonName != hostName {
		return nil, fmt.Errorf("the installed certificate names %q, not %q", prev.Subject.CommonName, hostName)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	// Expiry is ignored here on purpose: renewing an EXPIRED certificate is the
	// recovery for a host that went past its date, and the chain and name are
	// what make it this host's.
	if _, err := prev.Verify(x509.VerifyOptions{
		Roots:       pool,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		CurrentTime: prev.NotAfter.Add(-time.Minute),
	}); err != nil {
		return nil, fmt.Errorf("the installed certificate was not issued by this cluster CA: %w", err)
	}
	if !hasUsage(prev, x509.ExtKeyUsageClientAuth) {
		return nil, fmt.Errorf("the installed certificate is not a host certificate (no client-auth usage)")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("no certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse the certificate request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("the certificate request is not signed by its key: %w", err)
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("the certificate request's key is not a P-256 ECDSA key")
	}
	if prevPub, ok := prev.PublicKey.(*ecdsa.PublicKey); ok && prevPub.Equal(pub) {
		return nil, fmt.Errorf("the certificate request reuses the installed key; a renewal needs a new one")
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	ext, err := asn1.Marshal(prev.SerialNumber)
	if err != nil {
		return nil, fmt.Errorf("encode predecessor serial: %w", err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: prev.Subject.Organization,
			CommonName:   hostName,
		},
		DNSNames:        prev.DNSNames,
		IPAddresses:     prev.IPAddresses,
		NotBefore:       time.Now().Add(-5 * time.Minute),
		NotAfter:        time.Now().Add(hostCertValidity),
		KeyUsage:        x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		ExtraExtensions: []pkix.Extension{{Id: hostCertRenewalOfOID, Critical: false, Value: ext}},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caKey)
	if err != nil {
		return nil, fmt.Errorf("create host cert: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), nil
}

func hasUsage(c *x509.Certificate, u x509.ExtKeyUsage) bool {
	for _, have := range c.ExtKeyUsage {
		if have == u {
			return true
		}
	}
	return false
}

// ParseCertPEM parses the first CERTIFICATE block in data.
func ParseCertPEM(data []byte) (*x509.Certificate, error) {
	for {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("no CERTIFICATE block")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}
