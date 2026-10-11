package daemon

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"

	"github.com/litevirt/litevirt/internal/acmedns"
	"github.com/litevirt/litevirt/internal/pki"
)

// uiTLS decides what the web UI listener serves.
//
// Certificate, in order: a custom certificate installed with `lv host ui-cert
// set` (pki_dir/ui.crt + ui.key), else ACME's (HTTP-01 via autocert, or
// DNS-01), else this host's cluster certificate. The custom pair is re-read
// when its files change and must pass the same structural checks the installer
// applies (pki.UICertSource), so a renewal of a corporate certificate needs no
// restart and a broken one is never served; clearing it hands the UI straight
// back to ACME or the cluster certificate.
//
// Mode: TLS when ui_tls is "on", when ACME is configured, or while a custom
// certificate is installed; plain HTTP otherwise (the historical default, for a
// UI behind a TLS-terminating proxy). ui.Server.ServeSupervised re-asks
// wantTLS while running.
type uiTLS struct {
	pkiDir string
	always bool // ui_tls: on
	acmeOn bool
	acme   func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	alpn   bool // ACME TLS-ALPN-01 proto (autocert)
	custom *pki.KeyPairSource

	mu      sync.Mutex
	lastLog string
}

func newUITLS(pkiDir, mode string) *uiTLS {
	return &uiTLS{pkiDir: pkiDir, always: mode == "on", custom: pki.UICertSource(pkiDir)}
}

// customInstalled reports whether both custom files are present.
func (u *uiTLS) customInstalled() bool {
	_, e1 := os.Stat(filepath.Join(u.pkiDir, pki.UICertName))
	_, e2 := os.Stat(filepath.Join(u.pkiDir, pki.UIKeyName))
	return e1 == nil && e2 == nil
}

// customPair is the custom certificate to serve, or nil when none is installed
// or it cannot be served (unloadable, failed checks, or expired — then ACME or
// the cluster certificate answers instead).
func (u *uiTLS) customPair() *tls.Certificate {
	if !u.customInstalled() {
		return nil
	}
	p, err := u.custom.Get()
	if err != nil {
		u.logOnce("the custom UI certificate cannot be served; using the next certificate source", err)
		return nil
	}
	if time.Now().After(p.Leaf.NotAfter) {
		u.logOnce("the custom UI certificate has expired; using the next certificate source",
			fmt.Errorf("expired %s", p.Leaf.NotAfter.UTC().Format(time.RFC3339)))
		return nil
	}
	return p
}

// CustomLeaf is the custom certificate being served, for the certificate watch.
func (u *uiTLS) CustomLeaf() (*x509.Certificate, error) {
	if !u.customInstalled() {
		return nil, os.ErrNotExist
	}
	p, err := u.custom.Get()
	if err != nil {
		return nil, err
	}
	return p.Leaf, nil
}

func (u *uiTLS) logOnce(msg string, err error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	key := msg + err.Error()
	if key == u.lastLog {
		return
	}
	u.lastLog = key
	slog.Warn(msg, "error", err)
}

func (u *uiTLS) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if p := u.customPair(); p != nil {
		return p, nil
	}
	if u.acme != nil {
		c, err := u.acme(hello)
		if err == nil {
			return c, nil
		}
		slog.Debug("acme: serving the cluster certificate", "server_name", hello.ServerName, "error", err)
	}
	return pki.ServedHostKeyPair(u.pkiDir)
}

func (u *uiTLS) wantTLS() bool { return u.always || u.acmeOn || u.customInstalled() }

func (u *uiTLS) tlsConfig() *tls.Config {
	protos := []string{"h2", "http/1.1"}
	if u.alpn {
		protos = append(protos, acme.ALPNProto)
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: u.getCertificate, NextProtos: protos}
}

// buildUITLS assembles the UI's certificate sources. With HTTP-01 it returns
// the challenge handler that must be served on :80; with DNS-01 it starts the
// issuer under ctx.
func (d *Daemon) buildUITLS(ctx context.Context) (*uiTLS, http.Handler) {
	u := newUITLS(d.cfg.PKIDir, d.cfg.UITLS)
	if !d.cfg.ACME.Enabled() {
		return u, nil
	}
	cacheDir := d.cfg.ACME.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(d.cfg.DataDir, "acme")
	}
	u.acmeOn = true
	if d.cfg.ACME.DNS01() {
		iss, err := d.dns01Issuer(cacheDir)
		if err != nil {
			slog.Error("acme dns-01: not starting; the UI serves its other certificates", "error", err)
			return u, nil
		}
		u.acme = iss.GetCertificate
		go iss.Run(ctx)
		slog.Info("acme: UI TLS enabled (dns-01)", "directory", d.cfg.ACME.DirectoryURL,
			"domains", d.cfg.ACME.Domains, "cache", cacheDir, "nameserver", iss.Provider.(*acmedns.RFC2136).Nameserver)
		return u, nil
	}
	mgr := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(d.cfg.ACME.Domains...),
		Email:      d.cfg.ACME.Email,
		Client:     &acme.Client{DirectoryURL: d.cfg.ACME.DirectoryURL},
	}
	u.acme, u.alpn = mgr.GetCertificate, true
	slog.Info("acme: UI TLS enabled (http-01)", "directory", d.cfg.ACME.DirectoryURL, "domains", d.cfg.ACME.Domains, "cache", cacheDir)
	return u, mgr.HTTPHandler(nil)
}

// dns01Issuer builds the DNS-01 issuer from config, reading the TSIG secret.
func (d *Daemon) dns01Issuer(cacheDir string) (*acmedns.Issuer, error) {
	r := d.cfg.ACME.DNS.RFC2136
	secret, err := readTSIGSecret(r.TSIGSecretPath)
	if err != nil {
		return nil, err
	}
	alg, err := acmedns.TSIGAlgorithm(r.TSIGAlgorithm)
	if err != nil {
		return nil, err
	}
	ttl := r.TTL
	if ttl <= 0 {
		ttl = 60
	}
	transport := r.Transport
	if transport == "" {
		transport = "udp"
	}
	timeout := time.Duration(d.cfg.ACME.DNS.PropagationTimeoutSec) * time.Second
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	return &acmedns.Issuer{
		DirectoryURL: d.cfg.ACME.DirectoryURL,
		Email:        d.cfg.ACME.Email,
		Domains:      d.cfg.ACME.Domains,
		CacheDir:     filepath.Join(cacheDir, "dns01"),
		Provider: &acmedns.RFC2136{
			Nameserver: acmedns.NormalizeNameserver(r.Nameserver),
			Zone:       r.Zone,
			KeyName:    r.TSIGKeyName,
			Algorithm:  alg,
			Secret:     secret,
			TTL:        uint32(ttl),
			Net:        transport,
		},
		PropagationTimeout: timeout,
		PropagationDelay:   time.Duration(d.cfg.ACME.DNS.PropagationDelaySec) * time.Second,
	}, nil
}

// bindSecretRE finds the secret in a BIND key file (`secret "<base64>";`).
var bindSecretRE = regexp.MustCompile(`(?m)^\s*secret\s+"([^"]+)"\s*;`)

// readTSIGSecret reads a base64 TSIG secret, tightening its file to 0600 first
// like every private key on the host. It accepts the bare secret or a BIND key
// file's `secret "...";` line. Errors never include the file's contents.
func readTSIGSecret(path string) (string, error) {
	if err := pki.TightenKeyMode(path); err != nil {
		return "", fmt.Errorf("acme.dns.rfc2136.tsig_secret_path: %w", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("acme.dns.rfc2136.tsig_secret_path: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if m := bindSecretRE.FindStringSubmatch(s); m != nil {
		s = m[1]
	}
	if s == "" {
		return "", errors.New("acme.dns.rfc2136.tsig_secret_path: the file is empty")
	}
	if _, err := base64.StdEncoding.DecodeString(s); err != nil {
		return "", errors.New("acme.dns.rfc2136.tsig_secret_path: the secret is not base64")
	}
	return s, nil
}

// warnPlainUI says so when the UI serves plain HTTP on an address other
// machines can reach: logins and session cookies then cross the network in
// clear unless a TLS-terminating proxy is in front. Plain HTTP stays the
// default — changing it would break every deployment behind such a proxy — so
// this is a warning, with the two ways out.
func warnPlainUI(bind string, tlsOn bool) {
	if tlsOn {
		return
	}
	if ip := net.ParseIP(bind); ip != nil && ip.IsLoopback() || bind == "localhost" {
		return
	}
	slog.Warn("the web UI serves plain HTTP on a non-loopback address; logins and session cookies "+
		"cross the network unencrypted unless a TLS proxy is in front. Set ui_tls: on (cluster "+
		"certificate), install a certificate with `lv host ui-cert set`, or configure acme:",
		"ui_bind", bind)
}

// startACMEChallengeServer serves the autocert HTTP-01 challenge on :80. autocert
// only answers /.well-known/acme-challenge/… there; its default handler 302s
// everything else to https, which is fine. Best-effort: a bind failure (port in
// use) is logged, not fatal — issuance just can't complete via HTTP-01 then.
func startACMEChallengeServer(ctx context.Context, h http.Handler) {
	if h == nil {
		return
	}
	srv := &http.Server{Addr: ":80", Handler: h, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		_ = srv.Close()
	}()
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Warn("acme: HTTP-01 challenge server stopped", "error", err)
		}
	}()
}
