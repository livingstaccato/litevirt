package ssh

import (
	"crypto/rand"
	"crypto/rsa"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func rsaSigner(t *testing.T) ssh.Signer {
	t.Helper()
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := ssh.NewSignerFromKey(rk)
	if err != nil {
		t.Fatal(err)
	}
	return rs
}

func hostCert(t *testing.T, ca, host ssh.Signer, principal string) ssh.Signer {
	t.Helper()
	cert := &ssh.Certificate{
		Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{principal},
		ValidBefore: ssh.CertTimeInfinity,
	}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	cs, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func caLine(addr string, ca ssh.PublicKey) string {
	return "@cert-authority " + knownhosts.Line([]string{knownhosts.Normalize(addr)}, ca)
}

// Host known ONLY via @cert-authority, server presents a CA-signed cert (and its plain key, as sshd does).
func TestHostKeyCA_CAOnlyHostWithCert(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, hostCert(t, ca, ed, "127.0.0.1"), ed)
	writeKnownHosts(t, caLine(addr, ca.PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("CA-only host presenting a valid CA-signed cert refused: %v", err)
	}
}

// A wildcard CA line (the common enterprise form), with a server that presents
// ONLY its certificate, so first contact cannot be what lets it in. x/crypto's
// matcher pins a bare pattern to port 22, so the test port is spelled out.
func TestHostKeyCA_WildcardCAHostWithCert(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, hostCert(t, ca, ed, "127.0.0.1"))
	_, port, _ := net.SplitHostPort(addr)
	writeKnownHosts(t, "@cert-authority "+knownhosts.Line([]string{"[127.0.0.*]:" + port}, ca.PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("wildcard-CA host presenting a valid cert refused: %v", err)
	}
}

// Impostor with a cert signed by a DIFFERENT CA must be refused (both base and head).
func TestHostKeyCA_CAOnlyHostWrongCA(t *testing.T) {
	ca, other, ed := ed25519Signer(t), ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, hostCert(t, other, ed, "127.0.0.1"), ed)
	writeKnownHosts(t, caLine(addr, ca.PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("cert from an unknown CA accepted")
	}
}

// Mixed plain + CA: plain ed25519 recorded correctly, plus CA line.
func TestHostKeyCA_MixedPlainAndCA(t *testing.T) {
	ca, ed, ec := ed25519Signer(t), ed25519Signer(t), ecdsaSigner(t)
	addr := testServer(t, hostCert(t, ca, ed, "127.0.0.1"), ec, ed)
	writeKnownHosts(t, caLine(addr, ca.PublicKey()), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("mixed plain+CA refused: %v", err)
	}
}

// @revoked only: the host is otherwise unknown; presenting the revoked key must be refused.
func TestHostKey_RevokedKeyRefused(t *testing.T) {
	ed := ed25519Signer(t)
	addr := testServer(t, ed)
	writeKnownHosts(t, "@revoked "+knownhosts.Line([]string{"*"}, ed.PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("revoked key accepted")
	}
}

// Recorded RSA; impostor offers only ed25519 + ecdsa: refused (no downgrade).
func TestHostKeyRSA_RecordedRSA_ImpostorOtherTypes(t *testing.T) {
	rs := rsaSigner(t)
	addr := testServer(t, ed25519Signer(t), ecdsaSigner(t))
	writeKnownHosts(t, knownhosts.Line([]string{knownhosts.Normalize(addr)}, rs.PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("impostor without an rsa key accepted")
	}
}

// Recorded RSA, genuine server restricted to SHA-1 ssh-rsa signatures: head must not negotiate ssh-rsa.
func TestHostKeyRSA_RSANoSHA1(t *testing.T) {
	rs := rsaSigner(t)
	only1, err := ssh.NewSignerWithAlgorithms(rs.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	addr := testServer(t, only1)
	writeKnownHosts(t, knownhosts.Line([]string{knownhosts.Normalize(addr)}, rs.PublicKey()))
	err = dialTest(t, addr)
	t.Logf("sha1-only server: %v", err)
	if err == nil {
		t.Fatal("negotiated SHA-1 ssh-rsa with a known RSA host")
	}
}

// Recorded RSA, genuine server: accepted with SHA-2.
func TestHostKeyRSA_RSAGenuine(t *testing.T) {
	rs := rsaSigner(t)
	addr := testServer(t, ecdsaSigner(t), rs)
	writeKnownHosts(t, knownhosts.Line([]string{knownhosts.Normalize(addr)}, rs.PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("genuine rsa refused: %v", err)
	}
}

// A host trusted only through a CA that presents a plain key and no
// certificate is refused: no plain entry vouches for that key.
func TestHostKeyCA_CAOnlyHostPlainKeyRefused(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, ed, ecdsaSigner(t))
	writeKnownHosts(t, caLine(addr, ca.PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("a plain host key was accepted for a host known_hosts trusts only through a CA")
	}
}

// The certificate type follows the HOST key, not the CA's: an ed25519 CA
// signing an ecdsa host key yields an ecdsa certificate.
func TestHostKeyCA_CertTypeFollowsHostKey(t *testing.T) {
	ca, ec := ed25519Signer(t), ecdsaSigner(t)
	addr := testServer(t, hostCert(t, ca, ec, "127.0.0.1"))
	writeKnownHosts(t, caLine(addr, ca.PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("an ecdsa host certificate from a trusted ed25519 CA was refused: %v", err)
	}
}

// A stale plain entry beside a valid CA line: the certificate is still asked
// for first and verified against the CA, as before the narrowing.
func TestHostKeyCA_StalePlainPlusCA(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, hostCert(t, ca, ed, "127.0.0.1"), ed)
	writeKnownHosts(t, caLine(addr, ca.PublicKey()),
		knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("a valid CA-signed cert was refused because a stale plain entry exists: %v", err)
	}
}

// A certificate for an unknown host is not a way past first contact: with no
// CA line nothing asks for certificates, the plain key is presented, and
// accept-new applies to it exactly as to any other new host.
func TestHostKeyCA_UnknownHostWithCertIsFirstContact(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, hostCert(t, ca, ed, "127.0.0.1"), ed)
	writeKnownHosts(t, knownhosts.Line([]string{"10.9.9.9"}, ed25519Signer(t).PublicKey()))
	if err := dialTest(t, addr); err != nil {
		t.Fatalf("first contact with a cert-bearing host was refused: %v", err)
	}
}

func TestKnownHostKeyAlgorithms_CertAuthority(t *testing.T) {
	ca, ed := ecdsaSigner(t), ed25519Signer(t)
	writeKnownHosts(t,
		"@cert-authority "+knownhosts.Line([]string{"10.0.0.5"}, ca.PublicKey()),
		knownhosts.Line([]string{"10.0.0.5"}, ed.PublicKey()),
		"@cert-authority "+knownhosts.Line([]string{"10.0.0.6"}, ca.PublicKey()))
	raw, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	certs := strings.Join(sha2CertAlgorithms, ",")
	// The CA's own type (ecdsa) is not asked for as a plain host key.
	if got := strings.Join(knownHostKeyAlgorithms(raw, "10.0.0.5:22"), ","); got != certs+",ssh-ed25519" {
		t.Fatalf("CA + plain ed25519: algorithms = %v", got)
	}
	if got := strings.Join(knownHostKeyAlgorithms(raw, "10.0.0.6:22"), ","); got != certs {
		t.Fatalf("CA only: algorithms = %v", got)
	}
	for _, a := range sha2CertAlgorithms {
		if strings.Contains(a, "dss") || a == ssh.CertAlgoRSAv01 {
			t.Fatalf("a SHA-1 or DSA certificate algorithm is offered: %s", a)
		}
	}
}

// An unknown host is offered SHA-2 signatures only, so a server that can only
// sign with SHA-1 ssh-rsa is refused even on first contact.
func TestHostKeyRSA_UnknownHostNoSHA1(t *testing.T) {
	rs := rsaSigner(t)
	only1, err := ssh.NewSignerWithAlgorithms(rs.(ssh.AlgorithmSigner), []string{ssh.KeyAlgoRSA})
	if err != nil {
		t.Fatal(err)
	}
	addr := testServer(t, only1)
	writeKnownHosts(t, knownhosts.Line([]string{"10.9.9.9"}, ed25519Signer(t).PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("negotiated SHA-1 ssh-rsa with an unknown host")
	}
}

// signedHostCert is a host certificate for host from ca valid for 127.0.0.1,
// changed by mod before signing; tamper changes it after, so the signature no
// longer verifies.
func signedHostCert(t *testing.T, ca, host ssh.Signer, mod func(*ssh.Certificate), tamper bool) ssh.Signer {
	t.Helper()
	c := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert,
		ValidPrincipals: []string{"127.0.0.1"}, ValidBefore: ssh.CertTimeInfinity}
	if mod != nil {
		mod(c)
	}
	if err := c.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	if tamper {
		c.Serial++
	}
	cs, err := ssh.NewCertSigner(c, host)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

// Every invalid certificate from the trusted CA is refused, whether the
// server also offers plain keys or not, and none of the refusals can reach
// the accept-new path (reviewer probes, hostkey re-review r1-m1). A valid one
// is accepted by the same harness.
func TestHostKeyCA_InvalidCertificatesRefused(t *testing.T) {
	now := uint64(time.Now().Unix())
	cases := []struct {
		name   string
		mod    func(*ssh.Certificate)
		tamper bool
	}{
		{"expired", func(c *ssh.Certificate) { c.ValidAfter = now - 7200; c.ValidBefore = now - 3600 }, false},
		{"not-yet-valid", func(c *ssh.Certificate) { c.ValidAfter = now + 3600 }, false},
		{"wrong-principal", func(c *ssh.Certificate) { c.ValidPrincipals = []string{"10.0.0.99"} }, false},
		{"user-cert", func(c *ssh.Certificate) { c.CertType = ssh.UserCert }, false},
		{"bad-signature", nil, true},
		{"unknown-critical-option", func(c *ssh.Certificate) { c.CriticalOptions = map[string]string{"force-command": "x"} }, false},
	}
	for _, tc := range cases {
		for _, withPlain := range []bool{false, true} {
			name := tc.name + map[bool]string{false: "/cert-only", true: "/cert+plain"}[withPlain]
			t.Run(name, func(t *testing.T) {
				ca, ed := ed25519Signer(t), ed25519Signer(t)
				keys := []ssh.Signer{signedHostCert(t, ca, ed, tc.mod, tc.tamper)}
				if withPlain {
					keys = append(keys, ed, ecdsaSigner(t))
				}
				addr := testServer(t, keys...)
				writeKnownHosts(t, caLine(addr, ca.PublicKey()))
				if err := dialTest(t, addr); err == nil {
					t.Fatal("an invalid host certificate was accepted for a CA-only host")
				}
			})
		}
	}
	t.Run("valid", func(t *testing.T) {
		ca, ed := ed25519Signer(t), ed25519Signer(t)
		addr := testServer(t, signedHostCert(t, ca, ed, nil, false), ed)
		writeKnownHosts(t, caLine(addr, ca.PublicKey()))
		if err := dialTest(t, addr); err != nil {
			t.Fatalf("a valid certificate was refused: %v", err)
		}
	})
}

// A host key listed @revoked is refused even inside a valid certificate.
func TestHostKeyCA_RevokedKeyInValidCert(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, signedHostCert(t, ca, ed, nil, false), ed)
	writeKnownHosts(t, caLine(addr, ca.PublicKey()), "@revoked "+knownhosts.Line([]string{"*"}, ed.PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("a revoked host key inside a valid certificate was accepted")
	}
}

// A certificate from a CA whose line covers a different host is refused for
// this one.
func TestHostKeyCA_CAForAnotherHostOnly(t *testing.T) {
	ca, ed, rec := ed25519Signer(t), ed25519Signer(t), ed25519Signer(t)
	addr := testServer(t, signedHostCert(t, ca, ed, nil, false))
	writeKnownHosts(t, "@cert-authority "+knownhosts.Line([]string{"10.1.1.1"}, ca.PublicKey()),
		knownhosts.Line([]string{knownhosts.Normalize(addr)}, rec.PublicKey()))
	if err := dialTest(t, addr); err == nil {
		t.Fatal("a certificate from a CA scoped to another host was accepted")
	}
}

// isHostAuthority classifies each kind of entry: ed25519, ecdsa (hashed line)
// and RSA (wildcard) CA keys as authorities, plain ed25519 and RSA entries as
// not, and a CA as no authority for an address its line does not cover.
func TestIsHostAuthority_Classification(t *testing.T) {
	edCA, ecCA, rsCA := ed25519Signer(t), ecdsaSigner(t), rsaSigner(t)
	plainEd, plainRS := ed25519Signer(t), rsaSigner(t)
	hashed := knownhosts.HashHostname("10.0.0.9")
	writeKnownHosts(t,
		"@cert-authority "+knownhosts.Line([]string{"10.0.0.9"}, edCA.PublicKey()),
		"@cert-authority "+hashed+" "+strings.TrimPrefix(knownhosts.Line([]string{"x"}, ecCA.PublicKey()), "x "),
		"@cert-authority "+knownhosts.Line([]string{"10.0.0.*"}, rsCA.PublicKey()),
		knownhosts.Line([]string{"10.0.0.9"}, plainEd.PublicKey()),
		knownhosts.Line([]string{"10.0.0.9"}, plainRS.PublicKey()))
	raw, err := knownhosts.New(filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts"))
	if err != nil {
		t.Fatal(err)
	}
	probe := ed25519Signer(t).PublicKey()
	for _, c := range []struct {
		k    ssh.PublicKey
		want bool
		n    string
	}{{edCA.PublicKey(), true, "edCA"}, {ecCA.PublicKey(), true, "ecCA hashed"}, {rsCA.PublicKey(), true, "rsaCA wildcard"},
		{plainEd.PublicKey(), false, "plain ed"}, {plainRS.PublicKey(), false, "plain rsa"}} {
		if got := isHostAuthority(raw, "10.0.0.9:22", probe, c.k); got != c.want {
			t.Errorf("%s: isHostAuthority = %v, want %v", c.n, got, c.want)
		}
	}
	if isHostAuthority(raw, "10.0.1.9:22", probe, edCA.PublicKey()) {
		t.Error("edCA classified as an authority for an address its line does not cover")
	}
}
