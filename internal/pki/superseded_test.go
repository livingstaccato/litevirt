package pki

import (
	"crypto/tls"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// observerPKI is another host's pki dir under dir's CA: what a peer holds.
func observerPKI(t *testing.T, dir, name string) string {
	t.Helper()
	obs := t.TempDir()
	b, err := os.ReadFile(filepath.Join(dir, "ca.crt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(obs, "ca.crt"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"),
		filepath.Join(obs, "host.crt"), filepath.Join(obs, "host.key"), name, net.ParseIP("127.0.0.1")); err != nil {
		t.Fatal(err)
	}
	return obs
}

// The proof that a certificate was replaced is the CA-signed successor and
// nothing else: it names one host's one serial, it survives a restart (the
// node-local file, re-verified on load), a successor from another CA proves
// nothing, and a successor the CA revoked unused hands the identity back,
// while one revoked because it was renewed in turn does not.
//
// Mutations: skip the CA verification in addLocked (another CA's successor
// counts); skip persistLocked (the proof is gone after a restart); treat any
// revoked successor as void (the chain prev -> next -> next2 loses prev);
// ignore revocation of the successor (the abandoned renewal keeps p2
// replaced).
func TestSupersession_OnlyTheCAsSuccessorProvesAReplacement(t *testing.T) {
	dir := setupPKI(t)
	ca, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	obs := observerPKI(t, dir, "obs-host")
	prev, next, err := RenewLocal(ca, caKey, dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	succ, err := ServedHostCertificate(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := SupersededBy(obs, "test-host", prev); ok {
		t.Fatal("superseded before any proof was seen")
	}
	if !NoteSuccessor(obs, succ) {
		t.Fatal("a CA-issued successor was not taken as proof")
	}
	if got, ok := SupersededBy(obs, "test-host", prev); !ok || got != next {
		t.Fatalf("SupersededBy(%s) = %s %v, want %s", prev, got, ok, next)
	}
	if _, ok := SupersededBy(obs, "other-host", prev); ok {
		t.Fatal("the proof for test-host applied to another host's name")
	}
	if _, ok := SupersededBy(obs, "test-host", next); ok {
		t.Fatal("the successor itself was judged replaced")
	}
	forgetSupersessionsForTests(obs)
	if _, ok := SupersededBy(obs, "test-host", prev); !ok {
		t.Fatal("the proof did not survive a restart")
	}

	// Another CA's successor proves nothing here.
	foreign := setupPKI(t)
	fprev, _, err := RenewLocal(filepath.Join(foreign, "ca.crt"), filepath.Join(foreign, "ca.key"), foreign, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	fsucc, _ := ServedHostCertificate(foreign)
	if NoteSuccessor(obs, fsucc) {
		t.Fatal("a successor from another CA was taken as proof")
	}
	if _, ok := SupersededBy(obs, "test-host", fprev); ok {
		t.Fatal("another CA's successor superseded a serial")
	}

	// A second renewal; then the CA revokes `next` as the renewal does.
	// prev stays replaced: its successor was itself replaced.
	if _, _, err := RenewLocal(ca, caKey, dir, "test-host"); err != nil {
		t.Fatal(err)
	}
	succ2, _ := ServedHostCertificate(dir)
	NoteSuccessor(obs, succ2)
	if err := GenerateCRL(ca, caKey, filepath.Join(obs, "crl.pem"), []string{next}); err != nil {
		t.Fatal(err)
	}
	if _, ok := SupersededBy(obs, "test-host", prev); !ok {
		t.Fatal("revoking a successor that was renewed in turn handed its predecessor back")
	}
	if _, ok := SupersededBy(obs, "test-host", next); !ok {
		t.Fatal("the revoked, renewed successor was not judged replaced")
	}

	// A renewal abandoned: the CA revokes the successor unused, and its
	// predecessor is the host's identity again.
	dir2 := setupPKI(t)
	ca2, caKey2 := filepath.Join(dir2, "ca.crt"), filepath.Join(dir2, "ca.key")
	obs2 := observerPKI(t, dir2, "obs-host")
	p2, s2, err := RenewLocal(ca2, caKey2, dir2, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	abandoned, _ := ServedHostCertificate(dir2)
	NoteSuccessor(obs2, abandoned)
	if _, ok := SupersededBy(obs2, "test-host", p2); !ok {
		t.Fatal("fixture: the successor was not taken as proof")
	}
	if err := GenerateCRL(ca2, caKey2, filepath.Join(obs2, "crl.pem"), []string{s2}); err != nil {
		t.Fatal(err)
	}
	if _, ok := SupersededBy(obs2, "test-host", p2); ok {
		t.Fatal("an abandoned successor kept its predecessor replaced")
	}
}

// Every handshake collects the proof: a peer that dials the renewed host
// learns from the certificate it is served that the previous one was
// replaced.
//
// Mutation: drop NoteSuccessor from revocationVerifier.
func TestSupersession_LearnedFromAHandshake(t *testing.T) {
	dir := setupPKI(t)
	prev, _, err := RenewLocal(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), dir, "test-host")
	if err != nil {
		t.Fatal(err)
	}
	obs := observerPKI(t, dir, "obs-host")
	srv, err := ServerTLSConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	lis, err := tls.Listen("tcp", "127.0.0.1:0", srv)
	if err != nil {
		t.Fatal(err)
	}
	defer lis.Close()
	go func() {
		c, err := lis.Accept()
		if err == nil {
			_ = c.(*tls.Conn).Handshake()
			_ = c.Close()
		}
	}()
	cli, err := PeerTLSConfig(obs)
	if err != nil {
		t.Fatal(err)
	}
	cli = cli.Clone()
	cli.ServerName = "test-host"
	conn, err := tls.Dial("tcp", lis.Addr().String(), cli)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if _, ok := SupersededBy(obs, "test-host", prev); !ok {
		t.Fatal("the peer did not learn from the handshake that the host's previous certificate was replaced")
	}
}

// The revocation check behind every handshake and RPC notices a new CRL even
// when it lands within the same mtime tick as the one before: CRLs are
// installed by rename, so the inode changes.
//
// Mutation: compare the mtime alone in crlChecker.refreshLocked — the second
// CRL is never read.
func TestCRLChecker_SeesAReplacementWithTheSameMtime(t *testing.T) {
	dir := setupPKI(t)
	ca, caKey := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	crl := filepath.Join(dir, "crl.pem")
	if err := GenerateCRL(ca, caKey, crl, []string{"aa01"}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(crl)
	if err != nil {
		t.Fatal(err)
	}
	chk := RevocationChecker(dir)
	n := func(h string) *big.Int { v, _ := new(big.Int).SetString(h, 16); return v }
	if !chk(n("aa01")) || chk(n("aa02")) {
		t.Fatal("fixture: first CRL not read")
	}
	if err := GenerateCRL(ca, caKey, crl, []string{"aa02"}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(crl, fi.ModTime(), fi.ModTime()); err != nil {
		t.Fatal(err)
	}
	if !chk(n("aa02")) {
		t.Fatal("a CRL installed within the previous one's mtime tick was not read")
	}
}
