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

// RenewHostCert mints a successor to prev for the host named hostName: a new
// key, the same subject and SANs, a fresh five-year validity, and the
// predecessor's serial in the renewal extension. It returns the PEM-encoded
// certificate and private key; nothing is written.
//
// prev must be a host certificate this CA issued to hostName. Renewing anything
// else would either mint a certificate peers refuse (another CA's) or hand a
// host a certificate in another host's name.
func RenewHostCert(caCertPath, caKeyPath string, prev *x509.Certificate, hostName string) (certPEM, keyPEM []byte, err error) {
	caCert, caKey, err := loadCA(caCertPath, caKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load CA: %w", err)
	}
	if prev == nil {
		return nil, nil, fmt.Errorf("no certificate to renew")
	}
	if prev.Subject.CommonName != hostName {
		return nil, nil, fmt.Errorf("the installed certificate names %q, not %q", prev.Subject.CommonName, hostName)
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
		return nil, nil, fmt.Errorf("the installed certificate was not issued by this cluster CA: %w", err)
	}
	if !hasUsage(prev, x509.ExtKeyUsageClientAuth) {
		return nil, nil, fmt.Errorf("the installed certificate is not a host certificate (no client-auth usage)")
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate host key: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, nil, err
	}
	ext, err := asn1.Marshal(prev.SerialNumber)
	if err != nil {
		return nil, nil, fmt.Errorf("encode predecessor serial: %w", err)
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
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create host cert: %w", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal host key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
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
