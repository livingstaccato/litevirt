package ui

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

func selfSignedTLS(t *testing.T) *tls.Config {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ui"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil }}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// speaks reports which protocol the listener at addr answers: "tls", "http"
// or "" (neither yet).
func speaks(addr string) string {
	c := &http.Client{Timeout: time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // probing the protocol only
	}}
	if r, err := c.Get("https://" + addr + "/static/none"); err == nil {
		r.Body.Close()
		return "tls"
	}
	if r, err := c.Get("http://" + addr + "/static/none"); err == nil {
		r.Body.Close()
		return "http"
	}
	return ""
}

func waitSpeaks(t *testing.T, addr, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	got := ""
	for time.Now().Before(deadline) {
		if got = speaks(addr); got == want {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("listener at %s speaks %q, want %q", addr, got, want)
}

// The listener follows wantTLS while running: plain HTTP -> TLS when a
// certificate source appears, and back when it goes — no restart of anything
// but the listener itself.
//
// Mutation: make waitSwitch ignore wantTLS — the listener stays plain HTTP.
func TestServeSupervised_SwitchesModeWhileRunning(t *testing.T) {
	s, err := NewServer(nil, "test-cluster")
	if err != nil {
		t.Fatal(err)
	}
	addr := freeAddr(t)
	var tlsOn atomic.Bool
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.ServeSupervised(ctx, addr, selfSignedTLS(t), tlsOn.Load, 50*time.Millisecond) }()

	waitSpeaks(t, addr, "http")
	tlsOn.Store(true)
	waitSpeaks(t, addr, "tls")
	tlsOn.Store(false)
	waitSpeaks(t, addr, "http")

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeSupervised returned %v on shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("ServeSupervised did not stop with its context")
	}
}
