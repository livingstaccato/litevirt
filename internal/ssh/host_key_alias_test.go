package ssh

import (
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh/knownhosts"
)

// HostKeyAlias: ssh looks host keys up under the alias, so `ssh node3` with
// `HostKeyAlias node3` records and checks "node3", not the address. litevirt
// must enforce a key pinned there, or an impostor answering the address is
// taken as first contact and handed the cluster CA-signed host key.

func aliasKnownHosts(t *testing.T, home string, lines ...string) {
	t.Helper()
	writeFile(t, filepath.Join(home, ".ssh", "known_hosts"), lines...)
}

// Reviewer probe (sshcfg I1): a key pinned under the alias, a different key
// presented. Refused, strict or not.
func TestNewClient_HostKeyAliasPinEnforced(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := map[bool]string{false: "accept-new", true: "strict"}[strict]
		t.Run(name, func(t *testing.T) {
			extra := "  HostKeyAlias pinned-alias\n"
			if strict {
				extra += "  StrictHostKeyChecking yes\n"
			}
			home, _ := configServer(t, extra, ed25519Signer(t))
			aliasKnownHosts(t, home, knownhosts.Line([]string{"pinned-alias"}, ed25519Signer(t).PublicKey()))
			err := dialLabnode(t)
			if err == nil {
				t.Fatal("a key differing from the one pinned under HostKeyAlias was accepted")
			}
			if !strings.Contains(err.Error(), "CHANGED") || !strings.Contains(err.Error(), "HostKeyAlias pinned-alias") {
				t.Fatalf("err = %v, want a CHANGED refusal naming the alias", err)
			}
		})
	}
}

// The genuine key under the alias is accepted, and the offer is narrowed by
// the alias's entry: recorded ecdsa, server offers ed25519 first.
func TestNewClient_HostKeyAliasGenuineKey(t *testing.T) {
	ed, ec := ed25519Signer(t), ecdsaSigner(t)
	home, addr := configServer(t, "  HostKeyAlias pinned-alias\n  StrictHostKeyChecking yes\n", ed, ec)
	aliasKnownHosts(t, home,
		knownhosts.Line([]string{"pinned-alias"}, ec.PublicKey()),
		// A stale entry under the address does not matter once the alias
		// knows the host: ssh does not look the address up either.
		knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("the key pinned under HostKeyAlias was refused: %v", err)
	}
}

// An alias known_hosts has no entry for does not make the address's pin
// unreachable: the address is checked instead of taking the host as new.
func TestNewClient_HostKeyAliasUnknownStillChecksTheAddress(t *testing.T) {
	home, addr := configServer(t, "  HostKeyAlias fresh-alias\n", ed25519Signer(t))
	aliasKnownHosts(t, home, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "CHANGED") {
		t.Fatalf("err = %v, want the address's pin enforced", err)
	}

	// Nothing recorded under either name: first contact, as before.
	aliasKnownHosts(t, home, knownhosts.Line([]string{"other.example"}, ed25519Signer(t).PublicKey()))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("an unknown host under accept-new was refused: %v", err)
	}
}

// Under StrictHostKeyChecking yes an alias known_hosts does not know is
// refused, as ssh refuses it, even when the address is recorded.
func TestNewClient_HostKeyAliasUnknownStrictRefused(t *testing.T) {
	ed := ed25519Signer(t)
	home, addr := configServer(t, "  HostKeyAlias fresh-alias\n  StrictHostKeyChecking yes\n", ed)
	aliasKnownHosts(t, home, knownhosts.Line([]string{knownhosts.Normalize(addr)}, ed.PublicKey()))
	if err := dialLabnode(t); err == nil || !strings.Contains(err.Error(), "StrictHostKeyChecking") {
		t.Fatalf("err = %v, want an unknown-alias refusal under StrictHostKeyChecking yes", err)
	}
}

// A @cert-authority line for the alias: the host is asked for its
// certificate, whose principal must be the alias.
func TestNewClient_HostKeyAliasCertAuthority(t *testing.T) {
	ca, ed := ed25519Signer(t), ed25519Signer(t)
	home, _ := configServer(t, "  HostKeyAlias pinned-alias\n", hostCert(t, ca, ed, "pinned-alias"), ed)
	aliasKnownHosts(t, home, "@cert-authority "+knownhosts.Line([]string{"pinned-alias"}, ca.PublicKey()))
	if err := dialLabnode(t); err != nil {
		t.Fatalf("a certificate for the alias from the alias's CA was refused: %v", err)
	}

	// A cert for another principal from the same CA is refused.
	home, _ = configServer(t, "  HostKeyAlias pinned-alias\n", hostCert(t, ca, ed, "127.0.0.1"), ed)
	aliasKnownHosts(t, home, "@cert-authority "+knownhosts.Line([]string{"pinned-alias"}, ca.PublicKey()))
	if err := dialLabnode(t); err == nil {
		t.Fatal("a certificate whose principal is not the alias was accepted")
	}
}
