package fencessh

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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

	"golang.org/x/crypto/ssh"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// testCA is a cluster CA in a temp dir that mints host identities.
type testCA struct {
	t   *testing.T
	dir string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	return &testCA{t: t, dir: dir}
}

// host mints name's certificate for ip (nil: loopback only) and returns its
// PEM and signer.
func (ca *testCA) host(name string, ip net.IP) (string, crypto.Signer) {
	ca.t.Helper()
	cp := filepath.Join(ca.dir, name+".crt")
	kp := filepath.Join(ca.dir, name+".key")
	if err := pki.GenerateHostCert(filepath.Join(ca.dir, "ca.crt"), filepath.Join(ca.dir, "ca.key"), cp, kp, name, ip); err != nil {
		ca.t.Fatal(err)
	}
	certPEM, err := os.ReadFile(cp)
	if err != nil {
		ca.t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(kp)
	if err != nil {
		ca.t.Fatal(err)
	}
	blk, _ := pem.Decode(keyPEM)
	k, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		ca.t.Fatal(err)
	}
	return string(certPEM), k
}

func (ca *testCA) trust(revoked ...string) Trust {
	ca.t.Helper()
	tr, err := TrustFromPKIDir(ca.dir)
	if err != nil {
		ca.t.Fatal(err)
	}
	tr.Revoked = func(s *big.Int) bool {
		for _, r := range revoked {
			if strings.EqualFold(r, s.Text(16)) {
				return true
			}
		}
		return false
	}
	return tr
}

func testKeyLine(t *testing.T) string {
	t.Helper()
	_, pub, err := NewFenceKey()
	if err != nil {
		t.Fatal(err)
	}
	return KeyLine(pub)
}

func signedRow(t *testing.T, name, certPEM string, signer crypto.Signer) corrosion.HostFenceSSHRow {
	t.Helper()
	row, err := Sign(Publication{
		HostName: name, Generation: 1, FencePubkeys: testKeyLine(t), SSHDHostkeys: testKeyLine(t),
		Accepting: true, CertPEM: certPEM,
	}, signer)
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestVerify_AcceptsASignedRowAndTakesTheAddressFromTheCertificate(t *testing.T) {
	ca := newTestCA(t)
	certPEM, signer := ca.host("node-2", net.ParseIP("10.77.0.2"))
	v, err := Verify(signedRow(t, "node-2", certPEM, signer), ca.trust())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if v.Addr.String() != "10.77.0.2" || !v.Accepting || len(v.FenceKeys) != 1 || len(v.HostKeys) != 1 {
		t.Fatalf("verified = %+v", v)
	}
}

// TestVerify_Refusals: each way a row can be wrong is refused, and each for
// its own reason.
func TestVerify_Refusals(t *testing.T) {
	ca := newTestCA(t)
	certPEM, signer := ca.host("node-2", net.ParseIP("10.77.0.2"))
	cert3, signer3 := ca.host("node-3", net.ParseIP("10.77.0.3"))
	loopPEM, loopSigner := ca.host("node-4", nil)
	other := newTestCA(t)
	foreignPEM, foreignSigner := other.host("node-2", net.ParseIP("10.77.0.2"))
	parsed, err := pki.ParseCertPEM([]byte(certPEM))
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		row  func() corrosion.HostFenceSSHRow
		tr   Trust
		want string
	}{
		{"tampered key", func() corrosion.HostFenceSSHRow {
			r := signedRow(t, "node-2", certPEM, signer)
			r.FencePubkeys = testKeyLine(t)
			return r
		}, ca.trust(), "signature does not match"},
		{"tampered accepting", func() corrosion.HostFenceSSHRow {
			r := signedRow(t, "node-2", certPEM, signer)
			r.Accepting = false
			return r
		}, ca.trust(), "signature does not match"},
		{"another CA", func() corrosion.HostFenceSSHRow {
			return signedRow(t, "node-2", foreignPEM, foreignSigner)
		}, ca.trust(), "does not chain"},
		{"another host's certificate", func() corrosion.HostFenceSSHRow {
			// node-3 publishing a row for node-2 under its own certificate.
			return signedRow(t, "node-2", cert3, signer3)
		}, ca.trust(), "is \"node-3\"'s, not \"node-2\"'s"},
		{"revoked", func() corrosion.HostFenceSSHRow {
			return signedRow(t, "node-2", certPEM, signer)
		}, ca.trust(parsed.SerialNumber.Text(16)), "is revoked"},
		{"tombstone", func() corrosion.HostFenceSSHRow {
			r := signedRow(t, "node-2", certPEM, signer)
			r.Deleted = true
			return r
		}, ca.trust(), "retired"},
		{"loopback-only certificate", func() corrosion.HostFenceSSHRow {
			return signedRow(t, "node-4", loopPEM, loopSigner)
		}, ca.trust(), "names no IPv4 address besides 127.0.0.1"},
		{"key with options", func() corrosion.HostFenceSSHRow {
			r, err := Sign(Publication{HostName: "node-2", FencePubkeys: `command="/bin/sh" ` + testKeyLine(t),
				SSHDHostkeys: testKeyLine(t), CertPEM: certPEM}, signer)
			if err != nil {
				t.Fatal(err)
			}
			return r
		}, ca.trust(), "carries options"},
		{"no signature", func() corrosion.HostFenceSSHRow {
			r := signedRow(t, "node-2", certPEM, signer)
			r.Signature = ""
			return r
		}, ca.trust(), "signature is missing"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Verify(tc.row(), tc.tr)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Verify = %+v, %v; want an error containing %q", v, err, tc.want)
			}
		})
	}
}

// TestHexName_KeepsAShellMetacharacterNameOutOfTheShell: an older release
// admitted names safename would refuse; they reach the forced command and the
// pin only hex-encoded.
func TestHexName_KeepsAShellMetacharacterNameOutOfTheShell(t *testing.T) {
	name := `a'b;$(reboot)`
	h := HexName(name)
	if strings.ContainsAny(h, `'";$() `) || h != "6127623b24287265626f6f7429" {
		t.Fatalf("HexName(%q) = %q", name, h)
	}
	if Alias(name) != "litevirt-fence."+h {
		t.Fatalf("Alias = %q", Alias(name))
	}
}

func TestNewFenceKey_ParsesAsAnOpenSSHPrivateKey(t *testing.T) {
	priv, pub, err := NewFenceKey()
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.ParsePrivateKey(priv)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if KeyLine(s.PublicKey()) != KeyLine(pub) || pub.Type() != ssh.KeyAlgoED25519 {
		t.Fatalf("public key %q / %q", KeyLine(s.PublicKey()), KeyLine(pub))
	}
}

// TestVerify_AnExpiredCertificateStillPins: a host's certificate expiring is
// no evidence its keys are not its own, so its row still verifies (marked
// Expired, for `lv doctor fence`) and its peers keep fencing it pinned rather
// than refuse it in every mode.
func TestVerify_AnExpiredCertificateStillPins(t *testing.T) {
	ca := newTestCA(t)
	caPEM, _ := os.ReadFile(filepath.Join(ca.dir, "ca.crt"))
	caCert, err := pki.ParseCertPEM(caPEM)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, _ := os.ReadFile(filepath.Join(ca.dir, "ca.key"))
	blk, _ := pem.Decode(keyPEM)
	caKey, err := x509.ParseECPrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242), Subject: pkix.Name{CommonName: "node-2"}, DNSNames: []string{"node-2"},
		// Valid for one second just after the CA's own start, and long expired.
		NotBefore: caCert.NotBefore, NotAfter: caCert.NotBefore.Add(time.Second),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("10.77.0.2"), net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &hostKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	v, err := Verify(signedRow(t, "node-2", certPEM, hostKey), ca.trust())
	if err != nil || !v.Expired || v.Addr.String() != "10.77.0.2" {
		t.Fatalf("Verify of a row under an expired certificate = %+v, %v; want verified, marked expired", v, err)
	}
	if _, err := Verify(signedRow(t, "node-2", certPEM, hostKey), ca.trust("1092")); err == nil {
		t.Fatal("a revoked expired certificate verified")
	}
}
