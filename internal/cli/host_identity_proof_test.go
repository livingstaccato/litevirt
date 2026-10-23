package cli

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/pki"
)

// anotherClustersState gives the target another cluster's database and a
// running daemon.
func anotherClustersState(t *testing.T, f *addFixture) {
	t.Helper()
	writeOnTarget(t, f.target, "/var/lib/litevirt/state.db", "SQLite format 3\x00")
	f.target.DaemonState = "active"
}

// ourSigned mints a certificate of kind ("host", "client", "audit") with this
// cluster's CA and returns its PEM and its key's.
func ourSigned(t *testing.T, f *addFixture, kind string) (crt, key []byte) {
	t.Helper()
	tmp := t.TempDir()
	c, k := filepath.Join(tmp, "x.crt"), filepath.Join(tmp, "x.key")
	ca, cak := filepath.Join(f.opPKI, "ca.crt"), filepath.Join(f.opPKI, "ca.key")
	var err error
	switch kind {
	case "host":
		err = pki.GenerateHostCert(ca, cak, c, k, "node-1", net.IPv4(10, 0, 0, 1))
	case "client":
		err = pki.GenerateClientCert(ca, cak, c, k, "alice")
	case "audit":
		err = pki.GenerateAuditSigningCert(ca, cak, c, k, "node-1")
	}
	if err != nil {
		t.Fatal(err)
	}
	return mustRead(t, c), mustRead(t, k)
}

func writeFile(t *testing.T, p string, b []byte) {
	t.Helper()
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
}

// noOpenSSL makes the possession challenge find no openssl on the machine,
// so the key is compared in memory instead.
func noOpenSSL(t *testing.T) {
	t.Helper()
	old := openSSLBin
	openSSLBin = "/nonexistent/openssl-for-test"
	t.Cleanup(func() { openSSLBin = old })
}

// Re-review 1, finding 1: a certificate this cluster's CA signed is public
// (every member serves its host certificate in each handshake, lv-cli's
// client certificate is on every CLI machine, audit certificates are
// published), so one copied without its key, beside another cluster's
// database and daemon, passed as proof. The seven probes of the re-review,
// each now refused: a host, client or audit certificate of ours with no key,
// at /etc/litevirt/pki or in the config's pki_dir, and a ca.crt bundling a
// foreign CA with ours.
//
// Mutations: accept any certificate of ours without the key — the host
// probes go red; drop the ServerAuth check — client and audit go red (with a
// key); accept any bundle holding ours — the bundle probe goes red.
func TestHostAdd_RefusesACopiedCertificate(t *testing.T) {
	for _, kind := range []string{"host", "client", "audit"} {
		t.Run(kind+" certificate in the config's pki_dir, no key", func(t *testing.T) {
			f := newAddFixture(t)
			noIdentity(t, f)
			anotherClustersState(t, f)
			writeTargetConfig(t, f, "host_name: node-5\npki_dir: /srv/pki\n", 0o644)
			dir := mkdirOnTarget(t, f.target, "/srv/pki")
			writeFile(t, filepath.Join(dir, "ca.crt"), mustRead(t, filepath.Join(f.opPKI, "ca.crt")))
			crt, _ := ourSigned(t, f, kind)
			writeFile(t, filepath.Join(dir, "host.crt"), crt)
			refusedUntouched(t, f, f.add(t), "/srv/pki/host.crt")
		})
		t.Run(kind+" certificate in /etc/litevirt/pki, no key", func(t *testing.T) {
			f := newAddFixture(t)
			noIdentity(t, f)
			anotherClustersState(t, f)
			ourCAOnTarget(t, f)
			crt, _ := ourSigned(t, f, kind)
			writeFile(t, filepath.Join(f.targetPKI, "host.crt"), crt)
			refusedUntouched(t, f, f.add(t), "/etc/litevirt/pki/host.crt")
		})
	}
	t.Run("ca.crt bundling a foreign CA with ours, client certificate", func(t *testing.T) {
		f := newAddFixture(t)
		noIdentity(t, f)
		anotherClustersState(t, f)
		other := t.TempDir()
		if err := pki.GenerateCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(f.targetPKI, "ca.crt"),
			append(mustRead(t, filepath.Join(other, "ca.crt")), mustRead(t, filepath.Join(f.opPKI, "ca.crt"))...))
		crt, _ := ourSigned(t, f, "client")
		writeFile(t, filepath.Join(f.targetPKI, "host.crt"), crt)
		refusedUntouched(t, f, f.add(t), "/etc/litevirt/pki/ca.crt")
	})
}

// Rule 1 in full: chained to ours, a host certificate (ServerAuth), and the
// key on the machine pairs with it, proven by a signature openssl makes there
// or, with no openssl, by comparing public halves in memory. A client or
// audit certificate WITH its key is still not a host's; a host certificate
// with another key, or with none, is not proven.
//
// Mutations: make proveHostIdentity skip the possession step — "another
// key" goes red under both ways; drop the ServerAuth check — "client" and
// "audit" go red.
func TestHostAdd_ProofOfTheHostKey(t *testing.T) {
	for _, via := range []string{"openssl", "in memory"} {
		t.Run(via, func(t *testing.T) {
			if via == "in memory" {
				noOpenSSL(t)
			}
			for _, tc := range []struct {
				name   string
				kind   string
				key    string // "own", "other", "none"
				refuse string // "" accepted
			}{
				{"host certificate and its key", "host", "own", ""},
				{"host certificate, another key", "host", "other", "host.key"},
				{"host certificate, no key", "host", "none", "host.key"},
				{"client certificate and its key", "client", "own", "not a host certificate"},
				{"audit certificate and its key", "audit", "own", "not a host certificate"},
			} {
				t.Run(tc.name, func(t *testing.T) {
					f := newAddFixture(t)
					noIdentity(t, f)
					anotherClustersState(t, f)
					ourCAOnTarget(t, f)
					crt, key := ourSigned(t, f, tc.kind)
					writeFile(t, filepath.Join(f.targetPKI, "host.crt"), crt)
					switch tc.key {
					case "own":
						writeFile(t, filepath.Join(f.targetPKI, "host.key"), key)
					case "other":
						_, other := ourSigned(t, f, "host")
						writeFile(t, filepath.Join(f.targetPKI, "host.key"), other)
					}
					f.before = map[string][]byte{"host.crt": crt}
					err := f.add(t)
					if tc.refuse == "" {
						if err != nil {
							t.Fatalf("this cluster's host with its key was refused: %v", err)
						}
						return
					}
					refusedUntouched(t, f, err, tc.refuse)
				})
			}
		})
	}
}

// Re-review 1, finding 2 (TestRR1_AdmittedPairOverridesForeignHostCert): the
// staged pair of a stranded add was taken as proof even beside a host.crt
// that is present and foreign. It now counts only when host.crt is absent
// (the stranded add's own case: its rollback removed it); a present host.crt
// must prove itself.
//
// Mutation: take the admitted pair before the host.crt verdict — accepted.
func TestHostAdd_AStrandedPairDoesNotOverrideAForeignHostCert(t *testing.T) {
	f := newAddFixture(t)
	noIdentity(t, f)
	strandedAdd(t, f)
	writeTargetConfig(t, f, "host_name: node-9\npki_dir: /srv/pki\n", 0o644)
	dir := mkdirOnTarget(t, f.target, "/srv/pki")
	installPair(t, &addFixture{targetPKI: dir}, "", "other")
	anotherClustersState(t, f)
	f.target.Events = nil
	err := f.add(t)
	if err == nil || !strings.Contains(err.Error(), "/srv/pki/host.crt, a host certificate this cluster's CA did not issue") {
		t.Fatalf("rerun beside another cluster's host.crt = %v, want refused", err)
	}
	if reachedInstall(f.target.Events) {
		t.Errorf("the refused rerun installed: %v", f.target.Events)
	}
}

// Rule 3: ca.crt must hold this cluster's CA and nothing else. A bundle of
// ours and a foreign CA is refused even beside a host certificate of ours
// with its key, and with no state at all: a daemon loading it would trust
// the other CA.
//
// Mutation: accept a bundle that holds ours (the old sameCA) — red.
func TestHostAdd_RefusesACABundleWithAnotherCA(t *testing.T) {
	for _, state := range []bool{false, true} {
		f := newAddFixture(t)
		if state {
			anotherClustersState(t, f)
		}
		other := t.TempDir()
		if err := pki.GenerateCA(filepath.Join(other, "ca.crt"), filepath.Join(other, "ca.key")); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(f.targetPKI, "ca.crt"),
			append(mustRead(t, filepath.Join(f.opPKI, "ca.crt")), mustRead(t, filepath.Join(other, "ca.crt"))...))
		refusedUntouched(t, f, f.add(t), "/etc/litevirt/pki/ca.crt, which holds a CA that is not this cluster's")
	}
}

// The possession challenge as the machine runs it: openssl signs, the
// signature verifies; no key is NOKEY; no openssl is NOSIGN (the fallback).
func TestKeyProofCmd(t *testing.T) {
	f := newAddFixture(t)
	crt := parseCerts(f.before["host.crt"])[0]
	key := filepath.Join(f.targetPKI, "host.key")
	if proved, err := signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt); !proved || err != nil {
		t.Fatalf("own key: proved %v, %v", proved, err)
	}
	other := parseCerts(installPairCert(t))[0]
	if proved, err := signedChallenge(f.target, "/etc/litevirt/pki/host.key", other); proved || err == nil {
		t.Fatalf("another certificate's key: proved %v, %v", proved, err)
	}
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if proved, err := signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt); proved || err == nil {
		t.Fatalf("no key: proved %v, %v", proved, err)
	}
	writeFile(t, key, f.before["host.key"])
	noOpenSSL(t)
	if proved, err := signedChallenge(f.target, "/etc/litevirt/pki/host.key", crt); proved || err != nil {
		t.Fatalf("no openssl: proved %v, %v; want neither (fall back)", proved, err)
	}
}

// installPairCert mints a host certificate of a fresh CA and returns it.
func installPairCert(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := pki.GenerateCA(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if err := pki.GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(dir, "h.crt"), filepath.Join(dir, "h.key"), "x", net.IPv4(10, 0, 0, 2)); err != nil {
		t.Fatal(err)
	}
	return mustRead(t, filepath.Join(dir, "h.crt"))
}
