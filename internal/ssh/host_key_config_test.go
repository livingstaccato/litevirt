package ssh

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// How the ssh config and the host-key policy compose: the key types offered
// and the verification come from the same known_hosts files, looked up under
// the address actually dialled.

// configServer starts a server offering hostKeys and points a "labnode" alias
// at it, with extra config lines. It returns HOME and the server's address.
// "%H" in extra is replaced by HOME (ssh -G expands ~ and %d with the passwd
// home, not $HOME).
func configServer(t *testing.T, extra string, hostKeys ...ssh.Signer) (home, addr string) {
	t.Helper()
	home, _ = sshHome(t, "id_ed25519")
	extra = strings.ReplaceAll(extra, "%H", home)
	addr = testServer(t, hostKeys...)
	_, port, _ := net.SplitHostPort(addr)
	writeSSHConfig(t, home, fmt.Sprintf("Host labnode\n  HostName 127.0.0.1\n  User deploy\n  Port %s\n%s", port, extra))
	return home, addr
}

func dialLabnode(t *testing.T) error {
	t.Helper()
	c, err := NewClient("labnode")
	if err == nil {
		c.Close()
	}
	return err
}

func writeFile(t *testing.T, path string, lines ...string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// I4: a key pinned only in a configured UserKnownHostsFile is enforced: a
// different key is refused as CHANGED, not taken as first contact.
func TestNewClient_UserKnownHostsFilePinEnforced(t *testing.T) {
	ed := ed25519Signer(t)
	home, addr := configServer(t, "  UserKnownHostsFile %H/pinned_kh\n", ed)
	pin := filepath.Join(home, "pinned_kh")
	writeFile(t, pin, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	err := dialLabnode(t)
	if err == nil || !strings.Contains(err.Error(), "CHANGED") || !strings.Contains(err.Error(), pin) {
		t.Fatalf("err = %v, want a CHANGED refusal naming %s", err, pin)
	}

	// The genuine key in the same file is accepted.
	writeFile(t, pin, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("the key pinned in UserKnownHostsFile was refused: %v", err)
	}
}

// The offer is narrowed by the configured file too: a host recorded only
// there, under its ecdsa key, is asked for ecdsa although it also offers
// ed25519 (which first contact would take first).
func TestNewClient_UserKnownHostsFileNarrowsTheOffer(t *testing.T) {
	ed, ec := ed25519Signer(t), ecdsaSigner(t)
	home, addr := configServer(t, "  UserKnownHostsFile %H/pinned_kh\n", ed, ec)
	writeFile(t, filepath.Join(home, "pinned_kh"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ec.PublicKey()))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("host recorded (ecdsa) only in UserKnownHostsFile was refused: %v", err)
	}
}

// A host trusted only through a @cert-authority line in a configured
// UserKnownHostsFile is asked for its certificate and accepted; a cert from
// another CA is still refused.
func TestNewClient_CertAuthorityInUserKnownHostsFile(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	home, addr := configServer(t, "  UserKnownHostsFile %H/ca_kh\n", hostCert(t, ca, ed, "127.0.0.1"), ed)
	writeFile(t, filepath.Join(home, "ca_kh"), caLine(addr, ca.PublicKey()))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("CA-trusted host (CA only in UserKnownHostsFile) refused: %v", err)
	}

	writeFile(t, filepath.Join(home, "ca_kh"), caLine(addr, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err == nil {
		t.Fatal("a certificate from an untrusted CA was accepted")
	}
}

// The probe looks up the dialled HostName:Port, not the alias typed.
func TestNewClient_OfferProbesTheDialledAddress(t *testing.T) {
	ed, ec := ed25519Signer(t), ecdsaSigner(t)
	home, addr := configServer(t, "", ed, ec)
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ec.PublicKey()))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("host recorded (ecdsa) under its dialled address refused through an alias: %v", err)
	}
}

// StrictHostKeyChecking yes wraps the raw answer: a known host presenting a
// key of a type it has no entry for is still refused by the verdict.
func TestHostKeyPolicy_StrictKeepsTheTypeMismatchRefusal(t *testing.T) {
	ec := ecdsaSigner(t)
	writeKnownHosts(t, knownhosts.Line([]string{"10.0.0.5"}, ec.PublicKey()))
	cb, _, err := hostKeyPolicyFor(&resolved{StrictYes: true}, "10.0.0.5:22")
	if err != nil {
		t.Fatal(err)
	}
	err = cb("10.0.0.5:22", &net.TCPAddr{IP: net.ParseIP("10.0.0.5"), Port: 22}, ed25519Signer(t).PublicKey())
	if err == nil || !strings.Contains(err.Error(), "cannot be verified") {
		t.Fatalf("err = %v, want the type-mismatch refusal", err)
	}
}

// What ~/.ssh/config can say about host keys never loosens litevirt's check:
// StrictHostKeyChecking no or accept-new, UserKnownHostsFile /dev/null or
// none -- a key pinned in ~/.ssh/known_hosts is still enforced.
func TestNewClient_ConfigCannotLoosenHostKeyChecking(t *testing.T) {
	for _, extra := range []string{
		"  StrictHostKeyChecking no\n",
		"  StrictHostKeyChecking accept-new\n",
		"  StrictHostKeyChecking off\n",
		"  UserKnownHostsFile /dev/null\n",
		"  UserKnownHostsFile none\n",
		"  UserKnownHostsFile /dev/null\n  StrictHostKeyChecking no\n",
		"  HostKeyAlgorithms ssh-rsa\n",
		"  CheckHostIP no\n  StrictHostKeyChecking no\n",
	} {
		t.Run(strings.TrimSpace(extra), func(t *testing.T) {
			home, addr := configServer(t, extra, ed25519Signer(t))
			writeFile(t, filepath.Join(home, ".ssh", "known_hosts"),
				knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
			if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") {
				t.Fatalf("err = %v, want a CHANGED refusal", err)
			}
		})
	}
}

// Reviewer probe (sshcfg M3): ssh -G prints known_hosts paths space-separated
// and unquoted, so a configured path with a space must be joined back, not
// split into two absent files and dropped with its pin.
func TestNewClient_KnownHostsPathWithSpace(t *testing.T) {
	for _, kind := range []string{"UserKnownHostsFile", "GlobalKnownHostsFile"} {
		t.Run(kind, func(t *testing.T) {
			home, addr := configServer(t, "  "+kind+" \"%H/my keys/kh\" %H/other_kh\n", ed25519Signer(t))
			os.Mkdir(filepath.Join(home, "my keys"), 0o700)
			pin := filepath.Join(home, "my keys", "kh")
			writeFile(t, pin, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
			if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), pin) {
				t.Fatalf("err = %v, want the pin in %q enforced", err, pin)
			}
		})
	}
}

// A configured known_hosts file that does not exist is skipped, as ssh skips
// it, but not silently: a pin the operator believes is there is not.
func TestResolveConfig_WarnsAboutAbsentKnownHostsFile(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	var warned []string
	old := warnf
	warnf = func(f string, a ...any) { warned = append(warned, fmt.Sprintf(f, a...)) }
	t.Cleanup(func() { warnf = old })
	missing := filepath.Join(home, "no_such_kh")
	writeSSHConfig(t, home, "Host h\n  UserKnownHostsFile "+missing+" /dev/null\n  GlobalKnownHostsFile "+missing+"2\n")
	if _, err := resolveConfig("h", "", "22", false, false, 0); err != nil {
		t.Fatal(err)
	}
	if len(warned) != 2 || !strings.Contains(warned[0], missing) || !strings.Contains(warned[1], missing+"2") {
		t.Fatalf("warnings %q, want one for each absent configured file", warned)
	}

	// The defaults are not warned about: they are usually absent.
	warned = nil
	writeSSHConfig(t, home, "Host h\n  Port 2200\n")
	if _, err := resolveConfig("h", "", "22", false, false, 0); err != nil || len(warned) != 0 {
		t.Fatalf("err %v, warnings %q, want none for the default files", err, warned)
	}
}

// A known_hosts path litevirt cannot expand refuses rather than being dropped.
// (OpenSSH 10's ssh -G expands these tokens itself; an ssh that does not must
// not turn the pin into nothing.)
func TestResolveConfig_UnexpandableKnownHostsRefused(t *testing.T) {
	home, _ := sshHome(t, "id_ed25519")
	writeSSHConfig(t, home, "Host h\n  Port 2200\n")
	old := sshG
	t.Cleanup(func() { sshG = old })
	for _, line := range []string{"userknownhostsfile /a/%C", "userknownhostsfile /x /a/%C"} {
		sshG = func(time.Duration, ...string) ([]byte, error) {
			return []byte("hostname h\nport 22\n" + line + "\n"), nil
		}
		if r, err := resolveConfig("h", "", "22", false, false, 0); err == nil {
			t.Fatalf("%q: resolved %+v, want a refusal", line, r)
		}
	}
}

// The offer reads every file, not just the first: with ~/.ssh/known_hosts
// present (holding other hosts) and this host recorded, as ecdsa, only in a
// configured or global file, the host is asked for ecdsa although it offers
// ed25519 first -- and a CA line there gets its certificate asked for.
func TestNewClient_OfferReadsEveryKnownHostsFile(t *testing.T) {
	for _, kind := range []string{"UserKnownHostsFile", "GlobalKnownHostsFile"} {
		t.Run(kind+"/plain", func(t *testing.T) {
			ed, ec := ed25519Signer(t), ecdsaSigner(t)
			home, addr := configServer(t, "  "+kind+" %H/pinned_kh\n", ed, ec)
			writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{"other.example"}, ed25519Signer(t).PublicKey()))
			writeFile(t, filepath.Join(home, "pinned_kh"), knownhosts.Line([]string{knownhosts.Normalize(addr)}, ec.PublicKey()))
			if err := dialLabnode(t); err != nil {
				t.Fatalf("host recorded (ecdsa) only in %s, with ~/.ssh/known_hosts present, was refused: %v", kind, err)
			}
		})
		t.Run(kind+"/cert-authority", func(t *testing.T) {
			ca, ed := ed25519Signer(t), ed25519Signer(t)
			home, addr := configServer(t, "  "+kind+" %H/pinned_kh\n", hostCert(t, ca, ed, "127.0.0.1"), ed)
			writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), knownhosts.Line([]string{"other.example"}, ed25519Signer(t).PublicKey()))
			writeFile(t, filepath.Join(home, "pinned_kh"), caLine(addr, ca.PublicKey()))
			if err := dialLabnode(t); err != nil {
				t.Fatalf("CA line only in %s, with ~/.ssh/known_hosts present: %v", kind, err)
			}
		})
	}
}
