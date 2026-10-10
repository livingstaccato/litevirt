package pki

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// Custom serving certificates — the web UI's certificate from an operator's own
// PKI (`lv host ui-cert set`).
//
// The operator supplies a chain (leaf first) and the leaf's key. Everything a
// browser would complain about, and everything that would make the daemon
// serve something other than what the operator thinks it serves, is checked
// before the files are installed and again by the daemon before it adopts them:
//
//   - the key is the leaf's key (and a strong one);
//   - the chain is in ORDER — each certificate signed by the next — because a
//     server sends it as given, and a shuffled or foreign intermediate is a
//     handshake failure in some clients and not others;
//   - nothing in it has expired or is not yet valid;
//   - the leaf is a server certificate, not a CA;
//   - its SANs cover a name the host is reached by (the installer's check —
//     the daemon cannot know the names an operator types into a browser).
//
// The file names are fixed: pki_dir/ui.crt and pki_dir/ui.key (0600, like every
// other private key in pki_dir).
const (
	UICertName = "ui.crt"
	UIKeyName  = "ui.key"
	// maxServingChainBytes bounds what the installer and the daemon will parse.
	maxServingChainBytes = 1 << 20
	minRSABits           = 2048
)

// ServingCertCheck says which names a serving certificate must cover.
type ServingCertCheck struct {
	// AnyOf: the SANs must cover at least one of these (the host's litevirt
	// name and address). Ignored when AllOf is set.
	AnyOf []string
	// AllOf: the SANs must cover every one of these (names the operator said
	// the UI is reached by).
	AllOf []string
	// Now is the validity reference; zero means time.Now().
	Now time.Time
}

// ValidateServingChain checks a chain + key pair for serving (see the package
// comment above) and returns the leaf. Error messages never include key
// material.
func ValidateServingChain(chainPEM, keyPEM []byte, chk ServingCertCheck) (*x509.Certificate, error) {
	if len(chainPEM) > maxServingChainBytes || len(keyPEM) > maxServingChainBytes {
		return nil, fmt.Errorf("certificate or key file is larger than %d bytes", maxServingChainBytes)
	}
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil {
		// tls's own errors describe the mismatch ("private key does not match
		// public key"), never the key.
		return nil, fmt.Errorf("certificate and key do not form a pair: %w", err)
	}
	leaf, err := checkServingPair(&pair, chk.Now)
	if err != nil {
		return nil, err
	}
	if err := checkCoverage(leaf, chk); err != nil {
		return nil, err
	}
	return leaf, nil
}

// checkServingPair is the structural half of ValidateServingChain — everything
// but name coverage — shared with the daemon, which re-checks a pair before it
// serves it.
func checkServingPair(pair *tls.Certificate, now time.Time) (*x509.Certificate, error) {
	if now.IsZero() {
		now = time.Now()
	}
	if len(pair.Certificate) == 0 {
		return nil, errors.New("no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(pair.Certificate))
	for i, der := range pair.Certificate {
		c, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("certificate %d in the chain does not parse: %w", i+1, err)
		}
		certs = append(certs, c)
	}
	leaf := certs[0]
	if leaf.IsCA {
		return nil, errors.New("the first certificate is a CA certificate; the chain must start with the server (leaf) certificate")
	}
	if len(leaf.ExtKeyUsage) > 0 && !hasUsage(leaf, x509.ExtKeyUsageServerAuth) && !hasUsage(leaf, x509.ExtKeyUsageAny) {
		return nil, errors.New("the leaf certificate is not valid for server authentication (its extended key usage lacks serverAuth)")
	}
	if err := checkKeyStrength(pair.PrivateKey); err != nil {
		return nil, err
	}
	for i, c := range certs {
		if now.Before(c.NotBefore) {
			return nil, fmt.Errorf("certificate %d (%s) is not valid until %s", i+1, c.Subject, c.NotBefore.UTC().Format(time.RFC3339))
		}
		if now.After(c.NotAfter) {
			return nil, fmt.Errorf("certificate %d (%s) expired %s", i+1, c.Subject, c.NotAfter.UTC().Format(time.RFC3339))
		}
		if i+1 < len(certs) {
			issuer := certs[i+1]
			if !issuer.IsCA {
				return nil, fmt.Errorf("certificate %d (%s) is followed by %s, which is not a CA: "+
					"the chain must be in order, leaf first, each certificate followed by its issuer", i+1, c.Subject, issuer.Subject)
			}
			if err := c.CheckSignatureFrom(issuer); err != nil {
				return nil, fmt.Errorf("certificate %d (%s) is not signed by the next certificate in the file (%s): "+
					"the chain must be in order, leaf first, each certificate followed by its issuer: %w",
					i+1, c.Subject, issuer.Subject, err)
			}
		}
	}
	pair.Leaf = leaf
	return leaf, nil
}

func checkKeyStrength(key any) error {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < minRSABits {
			return fmt.Errorf("the RSA key is %d bits; at least %d are required", k.N.BitLen(), minRSABits)
		}
	case *ecdsa.PrivateKey, ed25519.PrivateKey:
	default:
		return fmt.Errorf("unsupported private key type %T", key)
	}
	return nil
}

func checkCoverage(leaf *x509.Certificate, chk ServingCertCheck) error {
	sans := strings.Join(append(append([]string{}, leaf.DNSNames...), ipStrings(leaf)...), ", ")
	if len(chk.AllOf) > 0 {
		for _, n := range chk.AllOf {
			if err := leaf.VerifyHostname(n); err != nil {
				return fmt.Errorf("the certificate does not cover %q (its SANs: %s)", n, sans)
			}
		}
		return nil
	}
	for _, n := range chk.AnyOf {
		if n != "" && leaf.VerifyHostname(n) == nil {
			return nil
		}
	}
	return fmt.Errorf("the certificate covers none of %s (its SANs: %s); pass the name the UI is reached "+
		"by with --name if it is not one of those", strings.Join(chk.AnyOf, ", "), sans)
}

func ipStrings(c *x509.Certificate) []string {
	out := make([]string, 0, len(c.IPAddresses))
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// UICertSource returns the source for pkiDir's custom UI certificate. Every
// load — the first one included — must pass the structural checks, so the
// daemon never serves a chain the installer would have refused, even one
// written by hand.
func UICertSource(dir string) *KeyPairSource {
	src := NewKeyPairSource(filepath.Join(dir, UICertName), filepath.Join(dir, UIKeyName), nil)
	src.strictKeyFile = true // introduced by this build: held to the strict rules
	return src.withPairCheck(func(p *tls.Certificate) error {
		_, err := checkServingPair(p, time.Time{})
		return err
	})
}
