package cli

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// keyProofKind is the Shell kind of the possession challenge.
const keyProofKind = "key-proof"

// openSSLBin is the openssl the possession challenge runs on the machine. A
// var so a test can name one that does not exist.
var openSSLBin = "openssl"

// proveHostIdentity is the proof refuseForeignState asks of a machine that
// keeps state: its host.crt (crtPEM, read from dir) is a host certificate of
// this cluster's, and the machine holds the key that pairs with it. It
// returns "" when proven, and otherwise what is wrong.
//
// A certificate alone proves nothing: every member serves its host
// certificate in each TLS handshake, the lv-cli client certificate sits on
// every CLI machine, and audit certificates are published. So the
// certificate must chain to ours, name ServerAuth (a host certificate: the
// client certificate names ClientAuth only, the audit one no usage), and
// host.key beside it must be its key.
//
// Possession is proven without moving the key where the machine has
// openssl: it signs a fresh random nonce with host.key, and the signature is
// verified here against the certificate's public key. A machine that only
// printed what it was asked to could not make that signature. Where openssl
// is absent, or cannot sign with the key, the key is read over the root SSH
// session the command already holds, kept in memory only, compared with the
// certificate by its public half, and the buffer is zeroed; it is never
// written or logged.
func proveHostIdentity(m stateProbe, dir string, crtPEM []byte, ours []*x509.Certificate) string {
	crtPath, keyPath := path.Join(dir, "host.crt"), path.Join(dir, "host.key")
	certs := parseCerts(crtPEM)
	if len(certs) == 0 {
		return fmt.Sprintf("%s, which holds no certificate this command can read", crtPath)
	}
	cert := certs[0]
	if !issuedBy(crtPEM, ours) {
		return fmt.Sprintf("%s, a host certificate this cluster's CA did not issue", crtPath)
	}
	if !hasServerAuth(cert) || pki.IsClientOnlyCert(cert) {
		return fmt.Sprintf("%s, a certificate of this cluster's CA that is not a host certificate (no ServerAuth usage): "+
			"a client or audit certificate, which anyone may hold", crtPath)
	}
	switch proved, err := signedChallenge(m, keyPath, cert); {
	case err != nil:
		return fmt.Sprintf("%s does not sign as %s's key: %v", keyPath, crtPath, err)
	case proved:
		return ""
	}
	// No openssl, or none that can sign with this key: compare in memory.
	key, ok, err := m.ReadFile(keyPath)
	defer zero(key)
	switch {
	case err != nil:
		return fmt.Sprintf("%s could not be read (%v), so the machine is not proven to hold %s's key", keyPath, err, crtPath)
	case !ok:
		return fmt.Sprintf("no host key at %s beside %s: a certificate without its key proves nothing", keyPath, crtPath)
	}
	if err := keyMatchesCert(key, cert); err != nil {
		return fmt.Sprintf("%s is not %s's key (%v)", keyPath, crtPath, err)
	}
	return ""
}

// signedChallenge asks the machine to sign a fresh nonce with keyPath. It
// returns proved when the signature verifies against cert, an error when the
// machine has no key there or its signature does not verify, and neither
// when the machine cannot make one (no openssl, or a key it cannot sign
// with), so the caller falls back to reading the key.
func signedChallenge(m stateProbe, keyPath string, cert *x509.Certificate) (proved bool, err error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, err
	}
	challenge := keyProofDomain + hex.EncodeToString(nonce[:])
	out, err := shellWithin(m, keyProofKind, keyProofCmd(m.Path(keyPath), challenge), keyProofDeadline)
	if err != nil {
		return false, fmt.Errorf("the challenge did not run: %w", err)
	}
	line := strings.TrimSpace(string(out))
	switch {
	case line == "NOKEY":
		return false, fmt.Errorf("there is no key")
	case line == "NOTFILE":
		// A device, FIFO or directory (or a link to one): openssl would
		// block on it, and no host key is one.
		return false, fmt.Errorf("it is not a regular file")
	case line == "NOSIGN":
		return false, nil
	case !strings.HasPrefix(line, "SIG "):
		return false, fmt.Errorf("unexpected answer %q", line)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(line, "SIG "))
	if err != nil {
		return false, fmt.Errorf("the signature does not decode: %w", err)
	}
	digest := sha256.Sum256([]byte(challenge))
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return false, fmt.Errorf("its signature does not verify against the certificate")
		}
	case *rsa.PublicKey:
		if rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig) != nil {
			return false, fmt.Errorf("its signature does not verify against the certificate")
		}
	default:
		return false, nil
	}
	return true, nil
}

// shellWithin runs m.Shell and gives up after d, whatever the machine has.
// A deadline is an error, not NOSIGN: a connection that does not answer is
// not trusted to answer the key read the in-memory fallback would make. The
// abandoned run ends when its connection is closed.
func shellWithin(m stateProbe, kind, cmd string, d time.Duration) ([]byte, error) {
	type result struct {
		out []byte
		err error
	}
	ch := make(chan result, 1)
	go func() {
		out, err := m.Shell(kind, cmd)
		ch <- result{out, err}
	}()
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.out, r.err
	case <-timer.C:
		return nil, fmt.Errorf("no answer before the %v deadline", d)
	}
}

// keyProofDomain prefixes every challenge, so a signature made for this
// proof can never stand for one another signer of the host key asks for.
const keyProofDomain = "litevirt-host-add-proof-v1:"

// keyProofTimeout bounds the openssl run on the machine, in seconds (where
// it has `timeout`); a run it ends is NOSIGN, and the key is compared in
// memory. A var so a test can shorten it.
var keyProofTimeout = 30

// keyProofDeadline bounds the whole challenge on the client, whatever the
// machine has: with no `timeout` binary the remote bound is dropped, and a
// hung openssl (or a hostile machine) would block the add forever. It
// outlasts keyProofTimeout, so a machine that does have `timeout` still
// answers NOSIGN first. A var so a test can shorten it.
var keyProofDeadline = 45 * time.Second

// keyProofCmd signs challenge with keyPath (as the shell names it) and
// prints "SIG <base64>", "NOKEY" when there is no key, "NOTFILE" when the
// key path (followed through links) is not a regular file, or "NOSIGN" when
// the machine cannot sign (no openssl, a key it cannot sign with, or a run
// past keyProofTimeout). The key never leaves openssl.
func keyProofCmd(keyPath, challenge string) string {
	k := ssh.ShellQuote(keyPath)
	o := ssh.ShellQuote(openSSLBin)
	return fmt.Sprintf(`if [ ! -e %s ]; then echo NOKEY; `+
		`elif [ ! -f %s ]; then echo NOTFILE; `+
		`elif ! command -v %s >/dev/null 2>&1; then echo NOSIGN; `+
		`else t=; if command -v timeout >/dev/null 2>&1; then t="timeout %d"; fi; `+
		`if s=$(printf '%%s' %s | $t %s dgst -sha256 -sign %s 2>/dev/null | base64 | tr -d '\n') && [ -n "$s" ]; then echo "SIG $s"; `+
		`else echo NOSIGN; fi; fi`, k, k, o, keyProofTimeout, ssh.ShellQuote(challenge), o, k)
}

// keyMatchesCert reports whether the PEM private key keyPEM is cert's: the
// public halves are compared.
func keyMatchesCert(keyPEM []byte, cert *x509.Certificate) error {
	blk, _ := pem.Decode(keyPEM)
	if blk == nil {
		return fmt.Errorf("it holds no PEM key")
	}
	var signer crypto.Signer
	if k, err := x509.ParsePKCS8PrivateKey(blk.Bytes); err == nil {
		s, ok := k.(crypto.Signer)
		if !ok {
			return fmt.Errorf("a key of a type this command does not know")
		}
		signer = s
	} else if k, err := x509.ParseECPrivateKey(blk.Bytes); err == nil {
		signer = k
	} else if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		signer = k
	} else {
		return fmt.Errorf("it does not parse as a private key")
	}
	pub, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !pub.Equal(cert.PublicKey) {
		return fmt.Errorf("its public key is not the certificate's")
	}
	return nil
}

func hasServerAuth(c *x509.Certificate) bool {
	for _, u := range c.ExtKeyUsage {
		if u == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

// zero overwrites b, a key read into memory, once it is no longer needed.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
