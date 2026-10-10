package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
)

// ServerTLSConfig returns a TLS config for the litevirtd gRPC server.
// Requires mTLS: server presents its cert, requires client certs from the same CA.
func ServerTLSConfig(pkiDir string) (*tls.Config, error) {
	caCert, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// The identity is served from disk at handshake time (identity.go), so a
	// renewed host.crt/host.key is presented from the next handshake on. The
	// load here only keeps the boot-time contract: no usable pair, no listener.
	src := hostIdentitySource(pkiDir)
	if _, err := src.Get(); err != nil {
		return nil, fmt.Errorf("load host cert/key: %w", err)
	}

	// Certificates stays EMPTY. crypto/tls consults GetCertificate only when
	// Certificates is empty or the client sent SNI, and peers dial IP literals,
	// which carry no SNI — a static entry here would pin the boot-time
	// certificate for every peer handshake.
	tlsCfg := &tls.Config{
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return src.Get() },
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		MinVersion:     tls.VersionTLS13,
	}

	// Always install the revocation check (not only when a CRL exists at
	// startup) so a CRL added/updated later takes effect without a restart.
	// The checker is fail-safe: no CRL or an unverifiable one ⇒ allow.
	tlsCfg.VerifyPeerCertificate = revocationVerifier(pkiDir, caCert)

	return tlsCfg, nil
}

// revocationVerifier builds a VerifyPeerCertificate callback backed by a
// signature-verifying, mtime-cached CRL checker. Shared by the server and
// peer TLS configs.
func revocationVerifier(pkiDir string, caPEM []byte) func([][]byte, [][]*x509.Certificate) error {
	checker := newCRLChecker(pkiDir, parseCACert(caPEM))
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				continue
			}
			if checker.isRevoked(cert.SerialNumber) {
				return fmt.Errorf("certificate serial %s has been revoked", cert.SerialNumber.Text(16))
			}
		}
		return nil
	}
}

// ClientTLSConfig returns a TLS config for connecting to litevirtd.
// Used by both CLI and host-to-host communication.
// Loads host.crt/host.key if present (daemon nodes), otherwise falls back
// to client.crt/client.key (remote CLI machines).
func ClientTLSConfig(pkiDir string) (*tls.Config, error) {
	caCert, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	// Try host cert first (daemon node), then client cert (remote CLI).
	cfg := &tls.Config{
		RootCAs:    caPool,
		MinVersion: tls.VersionTLS13,
	}
	for _, name := range []string{"host", "client"} {
		certFile := filepath.Join(pkiDir, name+".crt")
		if _, err := os.Stat(certFile); err != nil {
			continue
		}
		var src *KeyPairSource
		if name == "host" {
			src = hostIdentitySource(pkiDir)
		} else {
			src = sharedSource(pkiDir, name, x509.ExtKeyUsageClientAuth)
		}
		cert, err := src.Get()
		if err != nil {
			return nil, fmt.Errorf("load %s cert/key: %w", name, err)
		}
		// Certificates documents what was loaded; the getter is what a handshake
		// uses (crypto/tls ignores Certificates once GetClientCertificate is set).
		// An established connection keeps the certificate it was made with; the
		// server's ConnTracker closes one the cluster no longer accepts, and the
		// redial here presents the renewed certificate.
		cfg.Certificates = []tls.Certificate{*cert}
		cfg.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return src.Get() }
		break
	}
	return cfg, nil
}

// PeerTLSConfig returns a TLS config for host-to-host gRPC calls.
// Both sides present certs from the cluster CA.
func PeerTLSConfig(pkiDir string) (*tls.Config, error) {
	caCert, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse CA cert")
	}

	src := hostIdentitySource(pkiDir)
	if _, err := src.Get(); err != nil {
		return nil, fmt.Errorf("load host cert/key: %w", err)
	}

	// Both directions read the identity at handshake time (see ServerTLSConfig):
	// the health checker caches this config for the life of the process, and its
	// peer probes must carry a renewed certificate without a restart.
	return &tls.Config{
		GetCertificate:        func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return src.Get() },
		GetClientCertificate:  func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return src.Get() },
		RootCAs:               caPool,
		ClientAuth:            tls.RequireAndVerifyClientCert,
		ClientCAs:             caPool,
		MinVersion:            tls.VersionTLS13,
		VerifyPeerCertificate: revocationVerifier(pkiDir, caCert),
	}, nil
}
