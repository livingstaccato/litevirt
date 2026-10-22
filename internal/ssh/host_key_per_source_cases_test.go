package ssh

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Per-source cases from the sshpersource review: two sources,
// ~/.ssh/known_hosts and a GlobalKnownHostsFile, each scenario with the
// outcome litevirt must give. "accept" cases are genuine hosts; "refuse" ones
// either present a key some source contradicts or are a documented case where
// litevirt is stricter than ssh.

func perSourceDial(t *testing.T, extra string, keys []ssh.Signer, def, glob func(addr string) []string) error {
	t.Helper()
	home, addr := configServer(t, extra+"  GlobalKnownHostsFile %H/global_kh\n", keys...)
	if def != nil {
		writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), def(addr)...)
	}
	if glob != nil {
		writeFile(t, filepath.Join(home, "global_kh"), glob(addr)...)
	}
	return dialLabnode(t)
}

func plainLine(addr string, k ssh.PublicKey) string {
	return knownhosts.Line([]string{knownhosts.Normalize(addr)}, k)
}

func TestPerSource_Cases(t *testing.T) {
	type tc struct {
		extra     string
		keys      func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string)
		accept    bool
		wantInErr string
	}
	cases := map[string]tc{
		// I1: a cert-rollout via a global CA line on top of existing plain
		// entries for the same key in ~/.ssh/known_hosts.
		"CA global, same plain key in default, cert presented": {accept: true, keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			ca, ed := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{hostCert(t, ca, ed, "127.0.0.1"), ed},
				func(a string) []string { return []string{plainLine(a, ed.PublicKey())} },
				func(a string) []string { return []string{caLine(a, ca.PublicKey())} }
		}},
		// I1's other half: a different plain key in the default still refuses.
		"CA global, different plain key in default, cert presented": {keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			ca, ed := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{hostCert(t, ca, ed, "127.0.0.1"), ed},
				func(a string) []string { return []string{plainLine(a, ed25519Signer(t).PublicKey())} },
				func(a string) []string { return []string{caLine(a, ca.PublicKey())} }
		}},
		// Documented: a host without a certificate while another file's CA line
		// covers it.
		"CA global, plain genuine default, host has no cert": {keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			ca, ed := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{ed},
				func(a string) []string { return []string{plainLine(a, ed.PublicKey())} },
				func(a string) []string { return []string{caLine(a, ca.PublicKey())} }
		}},
		// Documented: a CA rotation split across files.
		"CA rotation across files": {keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			oldCA, newCA, ed := ed25519Signer(t), ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{hostCert(t, newCA, ed, "127.0.0.1"), ed},
				func(a string) []string { return []string{caLine(a, newCA.PublicKey())} },
				func(a string) []string { return []string{caLine(a, oldCA.PublicKey())} }
		}},
		// I2: every source records the RSA key; the offer must ask for it.
		"default all types, global RSA only": {accept: true, keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			ed, rs := ed25519Signer(t), rsaSigner(t)
			return []ssh.Signer{ed, rs},
				func(a string) []string { return []string{plainLine(a, ed.PublicKey()), plainLine(a, rs.PublicKey())} },
				func(a string) []string { return []string{plainLine(a, rs.PublicKey())} }
		}},
		// (b), kept: no type in common refuses.
		"default ed25519 only, global RSA only": {keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			ed, rs := ed25519Signer(t), rsaSigner(t)
			return []ssh.Signer{ed, rs},
				func(a string) []string { return []string{plainLine(a, ed.PublicKey())} },
				func(a string) []string { return []string{plainLine(a, rs.PublicKey())} }
		}},
		// The bypass (b) prevents: a planted ed25519 entry beside an RSA pin.
		"planted ed25519 default, RSA pin global": {keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			att, rs := ed25519Signer(t), rsaSigner(t)
			return []ssh.Signer{att},
				func(a string) []string { return []string{plainLine(a, att.PublicKey())} },
				func(a string) []string { return []string{plainLine(a, rs.PublicKey())} }
		}},
		"planted plain default, CA pin global": {keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			ca, att := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{att},
				func(a string) []string { return []string{plainLine(a, att.PublicKey())} },
				func(a string) []string { return []string{caLine(a, ca.PublicKey())} }
		}},
		"alias: planted default, genuine global": {extra: "  HostKeyAlias pa\n", keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			att, gen := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{att},
				func(string) []string { return []string{knownhosts.Line([]string{"pa"}, att.PublicKey())} },
				func(string) []string { return []string{knownhosts.Line([]string{"pa"}, gen.PublicKey())} }
		}},
		// As ssh: with the alias known, the address is never looked up.
		"alias known, pin only under the address": {accept: true, extra: "  HostKeyAlias pa\n", keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			k, other := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{k},
				func(string) []string { return []string{knownhosts.Line([]string{"pa"}, k.PublicKey())} },
				func(a string) []string { return []string{plainLine(a, other.PublicKey())} }
		}},
		"hashed planted default, pin global": {keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			att, gen := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{att},
				func(a string) []string {
					return []string{knownhosts.Line([]string{knownhosts.HashHostname(knownhosts.Normalize(a))}, att.PublicKey())}
				},
				func(a string) []string { return []string{plainLine(a, gen.PublicKey())} }
		}},
		// m2: x/crypto never matches a wildcard port, so such a pin would be
		// silently unenforced; it refuses, naming the pattern.
		"wildcard-port pin global, planted default": {wantInErr: "wildcard port", keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			att, gen := ed25519Signer(t), ed25519Signer(t)
			return []ssh.Signer{att},
				func(a string) []string { return []string{plainLine(a, att.PublicKey())} },
				func(string) []string { return []string{knownhosts.Line([]string{"[127.0.0.*]:*"}, gen.PublicKey())} }
		}},
		"wildcard-port pin alone": {wantInErr: "wildcard port", keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			k := ed25519Signer(t)
			return []ssh.Signer{k}, nil,
				func(string) []string {
					return []string{knownhosts.Line([]string{"other.example", "[127.0.0.?]:2*"}, k.PublicKey())}
				}
		}},
		// An @revoked line's host field is not consulted, so a wildcard port
		// there is harmless.
		"wildcard port on an @revoked line": {accept: true, keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			k := ed25519Signer(t)
			return []ssh.Signer{k},
				func(a string) []string { return []string{plainLine(a, k.PublicKey())} },
				func(string) []string {
					return []string{"@revoked " + knownhosts.Line([]string{"[127.0.0.*]:*"}, ed25519Signer(t).PublicKey())}
				}
		}},
		// A wildcard-port pattern for some other host does not get in the way.
		"wildcard-port pattern for another host": {accept: true, keys: func(t *testing.T) ([]ssh.Signer, func(string) []string, func(string) []string) {
			k := ed25519Signer(t)
			return []ssh.Signer{k},
				func(a string) []string { return []string{plainLine(a, k.PublicKey())} },
				func(string) []string {
					return []string{knownhosts.Line([]string{"[10.9.*]:*"}, ed25519Signer(t).PublicKey())}
				}
		}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			keys, def, glob := c.keys(t)
			err := perSourceDial(t, c.extra, keys, def, glob)
			switch {
			case c.accept && err != nil:
				t.Fatalf("genuine host refused: %v", err)
			case !c.accept && err == nil:
				t.Fatal("accepted, want a refusal")
			case c.wantInErr != "" && !strings.Contains(err.Error(), c.wantInErr):
				t.Fatalf("err = %v, want it to mention %q", err, c.wantInErr)
			}
		})
	}
}

// A plain-only file that records a different key of the same type as the
// certificate's inner key reports CHANGED, naming itself -- not the
// type-mismatch wording, which would describe the certificate's type.
func TestPerSource_CertInnerKeyChangedMessage(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	home, addr := configServer(t, "  GlobalKnownHostsFile %H/global_kh\n", hostCert(t, ca, ed, "127.0.0.1"), ed)
	def := filepath.Join(home, ".ssh", "known_hosts")
	writeFile(t, def, plainLine(addr, ed25519Signer(t).PublicKey()))
	writeFile(t, filepath.Join(home, "global_kh"), caLine(addr, ca.PublicKey()))
	err := dialLabnode(t)
	if err == nil || !strings.Contains(err.Error(), "CHANGED") || !strings.Contains(err.Error(), def) ||
		strings.Contains(err.Error(), "cannot be verified") {
		t.Fatalf("err = %v, want CHANGED naming %s", err, def)
	}
}
