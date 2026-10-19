package corrosion

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// clientSignerDir is a pki directory whose host.crt/host.key are the
// distributable client pair (pki.GenerateClientCert, ClientAuth only) with
// Common Name cn, so LoadClaimSigner signs with the client key.
func clientSignerDir(t *testing.T, ca claimTestCA, cn string) string {
	t.Helper()
	dir := t.TempDir()
	if err := copyTestFile(ca.cert, filepath.Join(dir, "ca.crt")); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateClientCert(ca.cert, ca.key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), cn); err != nil {
		t.Fatal(err)
	}
	return dir
}

// The claim verifiers matched a signer to a voter by the certificate's Common
// Name alone. On a cluster where an older build admitted a voter named
// "lv-cli", the distributable lv-cli client key (handed to every operator)
// signed accepts, forced-generation signatures and abandonments as that voter.
// A genuine voter's host certificate still verifies in all three.
//
// Mutation: drop the pki.IsClientOnlyCert check in verifyAccept,
// verifySigned or VerifyAbandonment — that subtest accepts the client key.
func TestClaimVerifiers_RefuseAClientCertificateNamedAsAVoter(t *testing.T) {
	ca := newClaimTestCA(t)
	verifier, err := LoadClaimVerifier(ca.dir)
	if err != nil {
		t.Fatal(err)
	}
	client, err := LoadClaimSigner(clientSignerDir(t, ca, "lv-cli"), "lv-cli")
	if err != nil {
		t.Fatal(err)
	}
	host, err := LoadClaimSigner(ca.pkiDir(t, "node-1"), "node-1")
	if err != nil {
		t.Fatal(err)
	}
	key, ballot, digest, inc := workloadKey(), testBallot(1, "node-1"), "digest", "inc-1"

	t.Run("accept", func(t *testing.T) {
		for _, tc := range []struct {
			s      *ClaimSigner
			refuse bool
		}{{client, true}, {host, false}} {
			a, err := tc.s.Sign(key, 2, ballot, digest, inc)
			if err != nil {
				t.Fatal(err)
			}
			cert := ClaimCertificate{Key: key, ConfigGeneration: 2, Ballot: ballot, ValueDigest: digest}
			err = verifier.verifyAccept(cert, a, map[string]string{tc.s.Name(): inc})
			if tc.refuse && (err == nil || !strings.Contains(err.Error(), "client certificate")) {
				t.Errorf("%s's accept with the client key = %v, want refused", tc.s.Name(), err)
			}
			if !tc.refuse && err != nil {
				t.Errorf("%s's accept with its host certificate = %v", tc.s.Name(), err)
			}
		}
	})
	// A generation a later one vouches for is judged by Historical(), which
	// forgives revocation since, and nothing else.
	//
	// Mutation: skip the check when v.historical — the client key's accept is
	// counted in history.
	t.Run("historical accept", func(t *testing.T) {
		hist := verifier.Historical()
		for _, tc := range []struct {
			s      *ClaimSigner
			refuse bool
		}{{client, true}, {host, false}} {
			a, err := tc.s.Sign(key, 2, ballot, digest, inc)
			if err != nil {
				t.Fatal(err)
			}
			cert := ClaimCertificate{Key: key, ConfigGeneration: 2, Ballot: ballot, ValueDigest: digest}
			err = hist.verifyAccept(cert, a, map[string]string{tc.s.Name(): inc})
			if tc.refuse && (err == nil || !strings.Contains(err.Error(), "client certificate")) {
				t.Errorf("historical: %s's accept with the client key = %v, want refused", tc.s.Name(), err)
			}
			if !tc.refuse && err != nil {
				t.Errorf("historical: %s's accept with its host certificate = %v", tc.s.Name(), err)
			}
		}
	})
	t.Run("forced", func(t *testing.T) {
		payload := sha256.Sum256([]byte("forced"))
		for _, tc := range []struct {
			s      *ClaimSigner
			refuse bool
		}{{client, true}, {host, false}} {
			sig, err := ecdsa.SignASN1(rand.Reader, tc.s.key, payload[:])
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.verifySigned(tc.s.certPEM, tc.s.Name(), payload[:], sig)
			if tc.refuse && (err == nil || !strings.Contains(err.Error(), "client certificate")) {
				t.Errorf("%s's signature with the client key = %v, want refused", tc.s.Name(), err)
			}
			if !tc.refuse && err != nil {
				t.Errorf("%s's signature with its host certificate = %v", tc.s.Name(), err)
			}
		}
	})
	t.Run("abandonment", func(t *testing.T) {
		for _, tc := range []struct {
			s      *ClaimSigner
			refuse bool
		}{{client, true}, {host, false}} {
			a, err := tc.s.SignAbandonment("proof-1", key, "test")
			if err != nil {
				t.Fatal(err)
			}
			err = verifier.VerifyAbandonment(a, tc.s.Name(), "proof-1", key)
			if tc.refuse && (err == nil || !strings.Contains(err.Error(), "client certificate")) {
				t.Errorf("%s's abandonment with the client key = %v, want refused", tc.s.Name(), err)
			}
			if !tc.refuse && err != nil {
				t.Errorf("%s's abandonment with its host certificate = %v", tc.s.Name(), err)
			}
		}
	})
}
