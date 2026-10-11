package e2e

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
)

// Certificates on a live cluster.
//
// The fleet tier proves the renewal protocol against in-process daemons. What
// only real hosts can show is the deployed effect: the daemon's gRPC listener,
// libvirt's TLS listener (qemu+tls:// migration, port 16514) and the web UI
// actually presenting the new certificate, with the host staying a healthy
// member throughout. These change cluster state — a renewal revokes the old
// certificate — so each needs its own opt-in, and they run on the node that
// holds the cluster CA key (the one that ran `lv host init`), as root.

// presentedCert completes a TLS handshake with addr and returns the leaf it
// presents. Verification is skipped on purpose: this reads what is served.
func presentedCert(t *testing.T, addr string, cfg *tls.Config) (*x509.Certificate, error) {
	t.Helper()
	if cfg == nil {
		cfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // inspection only
	}
	d := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", addr, cfg)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.ConnectionState().PeerCertificates[0], nil
}

func operatorPKIDir() string {
	if d := os.Getenv("LV_CONFIG_DIR"); d != "" {
		return filepath.Join(d, "pki")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "litevirt", "pki")
}

// TestCert_RenewHostCertificateInPlace renews a peer's cluster certificate and
// checks, on the real hosts: the daemon presents the successor at once; libvirt
// presents it too after the reload; the old serial is revoked; and the host
// stays an active, healthy member — no restart, no fence.
//
// Opt-in: E2E_CERT_RENEW=1 (it revokes the host's current certificate).
func TestCert_RenewHostCertificateInPlace(t *testing.T) {
	if os.Getenv("E2E_CERT_RENEW") != "1" {
		t.Skip("set E2E_CERT_RENEW=1 to renew a host certificate on this cluster")
	}
	requireHosts(t, 2)
	if _, err := os.Stat(filepath.Join(operatorPKIDir(), "ca.key")); err != nil {
		t.Skip("run on the machine that holds the cluster CA key")
	}
	var target string
	for _, h := range hostNames {
		if h != localHost {
			target = h
			break
		}
	}
	addr := hostIPs[target]
	if addr == "" {
		t.Fatalf("no address for %s", target)
	}
	clientCfg, err := pki.ClientTLSConfig(operatorPKIDir())
	if err != nil {
		t.Fatal(err)
	}
	before, err := presentedCert(t, net.JoinHostPort(addr, "7443"), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	oldSerial := strings.ToLower(before.SerialNumber.Text(16))

	out := lv(t, "host", "renew-cert", target, "--ssh", "root@"+addr)
	t.Log(out)

	after, err := presentedCert(t, net.JoinHostPort(addr, "7443"), clientCfg)
	if err != nil {
		t.Fatal(err)
	}
	if from, ok := pki.RenewedFromSerial(after); !ok || from != oldSerial {
		t.Fatalf("%s presents %s on 7443, not a successor of %s", target, after.SerialNumber.Text(16), oldSerial)
	}
	// libvirt's TLS listener: the reload is best-effort, so report rather
	// than fail when the host's libvirt cannot do it.
	if lc, err := presentedCert(t, net.JoinHostPort(addr, "16514"), nil); err != nil {
		t.Logf("could not read libvirt's TLS certificate on %s:16514: %v", addr, err)
	} else if lc.SerialNumber.Cmp(after.SerialNumber) != 0 {
		t.Errorf("libvirt on %s still presents %s after the renewal (want %s); `virt-admin server-update-tls` "+
			"did not take", target, lc.SerialNumber.Text(16), after.SerialNumber.Text(16))
	}
	revoked, err := pki.LoadCRL(filepath.Join(operatorPKIDir(), "crl.pem"))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, s := range revoked {
		found = found || strings.EqualFold(s, oldSerial)
	}
	if !found {
		t.Errorf("the replaced certificate %s is not in the CRL", oldSerial)
	}
	// A minute and a half: two failure-detector windows. The host must still
	// be active — peers never refused it, so nothing suspected it.
	time.Sleep(90 * time.Second)
	for _, line := range strings.Split(lv(t, "host", "ls"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[0] == target && !strings.Contains(strings.ToLower(line), "active") {
			t.Errorf("%s is not active after the renewal: %s", target, line)
		}
	}
	if out, err := lvErr(t, "health"); err != nil {
		t.Errorf("lv health after the renewal: %v\n%s", err, out)
	}
}

// TestCert_UICertificateSetAndClear installs a custom UI certificate on this
// node, checks the UI serves it without a restart, then clears it.
//
// Opt-in: E2E_UI_CERT=1. Runs on a cluster node (the UI binds 127.0.0.1).
func TestCert_UICertificateSetAndClear(t *testing.T) {
	if os.Getenv("E2E_UI_CERT") != "1" {
		t.Skip("set E2E_UI_CERT=1 to install a UI certificate on this node")
	}
	if !localMode || localHost == "" {
		t.Skip("run on a cluster node")
	}
	addr := hostIPs[localHost]
	dir := t.TempDir()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caT := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "e2e corp CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caT, caT, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial := big.NewInt(time.Now().UnixNano())
	leafT := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: localHost},
		DNSNames: []string{localHost}, IPAddresses: []net.IP{net.ParseIP(addr), net.IPv4(127, 0, 0, 1)},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(20 * 24 * time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafT, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	kder, _ := x509.MarshalECPrivateKey(key)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	crt, kp := filepath.Join(dir, "chain.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(crt, chain, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600); err != nil {
		t.Fatal(err)
	}

	lv(t, "host", "ui-cert", "set", localHost, "--cert", crt, "--key", kp, "--ssh", "root@"+addr)
	t.Cleanup(func() { _, _ = lvErr(t, "host", "ui-cert", "clear", localHost, "--ssh", "root@"+addr) })

	deadline := time.Now().Add(30 * time.Second)
	for {
		c, err := presentedCert(t, "127.0.0.1:7445", nil)
		if err == nil && c.SerialNumber.Cmp(serial) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the UI does not serve the installed certificate after 30s (last: %v, %v)", c, err)
		}
		time.Sleep(time.Second)
	}
	if fi, err := os.Stat("/etc/litevirt/pki/" + pki.UIKeyName); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("ui.key: %v mode %v", err, fi)
	}

	lv(t, "host", "ui-cert", "clear", localHost, "--ssh", "root@"+addr)
	deadline = time.Now().Add(30 * time.Second)
	for {
		c, err := presentedCert(t, "127.0.0.1:7445", nil)
		if err != nil || c.SerialNumber.Cmp(serial) != 0 {
			break // plain HTTP again, or another certificate source
		}
		if time.Now().After(deadline) {
			t.Fatal("the UI still serves the cleared certificate after 30s")
		}
		time.Sleep(time.Second)
	}
}
