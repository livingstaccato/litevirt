package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The assertion is deliberately dynamic: the first RED must compile and reach
// genuine native, signed evidence before reporting the absent capability.
type recordedCustodyVerifier interface {
	VerifyRecordedCustodyAt(chain [][]byte, host, serial string, at time.Time) error
}

type recordedCustodyFixture struct {
	original, successor, permissive, revoked, foreign *HostTrustEvidence
	chain                                             [][]byte
	leaf                                              *x509.Certificate
	at                                                time.Time
	originalBytes                                     []byte
}

func captureRecordedCustodyEvidence(t *testing.T, dir, host string) (*HostTrustEvidence, []byte) {
	t.Helper()
	v, err := CaptureHostTrust(context.Background(), dir, host)
	if err != nil {
		t.Fatal("historical fixture capture:", err)
	}
	raw, err := v.PublicEvidence()
	if err != nil {
		t.Fatal("historical fixture public evidence:", err)
	}
	e, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal("historical fixture decode:", err)
	}
	if e.RootDigest() != v.RootDigest() || e.Digest() != v.EvidenceDigest() {
		t.Fatal("historical fixture lost signed evidence identity")
	}
	return e, raw
}

func newRecordedCustodyFixture(t *testing.T) recordedCustodyFixture {
	t.Helper()
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal("historical fixture native initialization:", err)
	}
	ca, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := GenerateHostCert(ca, key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "custody-peer", nil); err != nil {
		t.Fatal("historical fixture served issuance:", err)
	}
	pair, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal("historical fixture served DER:", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	observer := observerPKI(t, dir, "custody-observer")
	// A genuine signed original CRL is present, without revoking our peer.
	if err := GenerateCRL(ca, key, filepath.Join(observer, "crl.pem"), []string{"ab01"}); err != nil {
		t.Fatal("historical fixture original CRL:", err)
	}
	f := recordedCustodyFixture{chain: pair.Certificate, leaf: leaf, at: time.Now().UTC()}
	f.original, f.originalBytes = captureRecordedCustodyEvidence(t, observer, "custody-observer")
	if len(f.original.crls) != 1 || f.original.crls[0].CheckSignatureFrom(f.original.root) != nil {
		t.Fatal("historical fixture lacks signed original CRL")
	}
	if err := f.original.VerifyRecordedPeer(f.chain, "custody-peer"); err != nil {
		t.Fatal("historical fixture original peer provenance:", err)
	}
	if err := f.original.VerifyRecordedHost(f.chain, "custody-peer"); err == nil {
		t.Fatal("historical fixture confused opposite peer and local served identity")
	}
	if _, _, err := RenewLocal(ca, key, dir, "custody-peer"); err != nil {
		t.Fatal("historical fixture actual renewal:", err)
	}
	next, err := ServedHostCertificate(dir)
	if err != nil || !NoteSuccessor(observer, next) {
		t.Fatal("historical fixture successor installation:", err)
	}
	f.successor, _ = captureRecordedCustodyEvidence(t, observer, "custody-observer")
	if len(f.successor.successors) == 0 {
		t.Fatal("historical fixture lost signed successor")
	}
	var policy atomic.Bool
	if err := PublishHostTrustPolicy(observer, &policy, true); err != nil {
		t.Fatal("historical fixture recorded peer policy:", err)
	}
	f.permissive, _ = captureRecordedCustodyEvidence(t, observer, "custody-observer")
	if err := GenerateCRL(ca, key, filepath.Join(observer, "crl.pem"), []string{leaf.SerialNumber.Text(16)}); err != nil {
		t.Fatal("historical fixture actual later revocation:", err)
	}
	f.revoked, _ = captureRecordedCustodyEvidence(t, observer, "custody-observer")
	foreign := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), foreign); err != nil {
		t.Fatal(err)
	}
	if err := GenerateHostCert(filepath.Join(foreign, "ca.crt"), filepath.Join(foreign, "ca.key"), filepath.Join(foreign, "host.crt"), filepath.Join(foreign, "host.key"), "foreign", nil); err != nil {
		t.Fatal(err)
	}
	f.foreign, _ = captureRecordedCustodyEvidence(t, foreign, "foreign")
	if f.foreign.RootDigest() == f.original.RootDigest() {
		t.Fatal("historical fixture foreign root is not distinct")
	}
	return f
}

func requireRecordedCustodyVerifier(t *testing.T, e *HostTrustEvidence) recordedCustodyVerifier {
	t.Helper()
	v, ok := any(e).(recordedCustodyVerifier)
	if !ok {
		t.Fatal("CUSTODY_RECORDED_CAPABILITY: signed original evidence cannot verify consumption time")
	}
	return v
}

func TestRecordedCustodyCapability(t *testing.T) {
	f := newRecordedCustodyFixture(t)
	v := requireRecordedCustodyVerifier(t, f.original)
	if err := v.VerifyRecordedCustodyAt(f.chain, "custody-peer", f.leaf.SerialNumber.Text(16), f.at); err != nil {
		t.Fatal("CUSTODY_RECORDED_VALID: genuine original consumption refused:", err)
	}
}

func TestRecordedCustodyExactIdentityTimeAndBounds(t *testing.T) {
	f := newRecordedCustodyFixture(t)
	serial := f.leaf.SerialNumber.Text(16)
	v := requireRecordedCustodyVerifier(t, f.original)
	for _, tc := range []struct {
		name, host, serial string
		chain              [][]byte
		at                 time.Time
	}{
		{"wrong-host", "other", serial, f.chain, f.at},
		{"empty-host", "", serial, f.chain, f.at},
		{"oversized-host", strings.Repeat("h", 254), serial, f.chain, f.at},
		{"wrong-serial", "custody-peer", serial + "0", f.chain, f.at},
		{"empty-serial", "custody-peer", "", f.chain, f.at},
		{"noncanonical-serial", "custody-peer", "0" + serial, f.chain, f.at},
		{"malformed-serial", "custody-peer", "not-hex", f.chain, f.at},
		{"oversized-serial", "custody-peer", strings.Repeat("a", maxServingChainBytes+1), f.chain, f.at},
		{"zero-time", "custody-peer", serial, f.chain, time.Time{}},
		{"before-leaf", "custody-peer", serial, f.chain, f.leaf.NotBefore.Add(-time.Nanosecond)},
		{"after-leaf", "custody-peer", serial, f.chain, f.leaf.NotAfter.Add(time.Nanosecond)},
		{"before-root", "custody-peer", serial, f.chain, f.original.root.NotBefore.Add(-time.Nanosecond)},
		{"after-root", "custody-peer", serial, f.chain, f.original.root.NotAfter.Add(time.Nanosecond)},
		{"empty-chain", "custody-peer", serial, nil, f.at},
		{"malformed-DER", "custody-peer", serial, [][]byte{{1, 2, 3}}, f.at},
		{"oversized-DER", "custody-peer", serial, [][]byte{make([]byte, maxServingChainBytes+1)}, f.at},
		{"too-many-certificates", "custody-peer", serial, make([][]byte, maxTrustCertificates+1), f.at},
		{"malformed-intermediate", "custody-peer", serial, append(append([][]byte{}, f.chain...), []byte{1}), f.at},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.VerifyRecordedCustodyAt(tc.chain, tc.host, tc.serial, tc.at); err == nil {
				t.Fatal("CUSTODY_RECORDED_INVALID: invalid original identity, time or bound accepted")
			}
		})
	}
	t.Run("foreign-root", func(t *testing.T) {
		if err := requireRecordedCustodyVerifier(t, f.foreign).VerifyRecordedCustodyAt(f.chain, "custody-peer", serial, f.at); err == nil {
			t.Fatal("CUSTODY_RECORDED_ROOT: foreign original root accepted")
		}
	})
	t.Run("nil-evidence", func(t *testing.T) {
		if err := requireRecordedCustodyVerifier(t, nil).VerifyRecordedCustodyAt(f.chain, "custody-peer", serial, f.at); err == nil {
			t.Fatal("CUSTODY_RECORDED_NIL: nil original evidence accepted")
		}
	})
	// X.509 validity endpoints are inclusive when the entire selected chain is valid.
	for _, at := range []time.Time{f.leaf.NotBefore, f.leaf.NotAfter} {
		if !at.Before(f.original.root.NotBefore) && !at.After(f.original.root.NotAfter) {
			if err := v.VerifyRecordedCustodyAt(f.chain, "custody-peer", serial, at); err != nil {
				t.Fatal("CUSTODY_RECORDED_BOUNDARY: valid original endpoint refused:", err)
			}
		}
	}
}

func TestRecordedCustodyOriginalPolicyAndLaterChanges(t *testing.T) {
	f := newRecordedCustodyFixture(t)
	serial := f.leaf.SerialNumber.Text(16)
	// The live files have already renewed and revoked the old leaf. An immutable
	// original observation remains valid, including after decoding it afresh.
	digest := f.original.Digest()
	redecoded, err := DecodeHostTrustEvidence(bytes.Clone(f.originalBytes))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range []*HostTrustEvidence{f.original, redecoded} {
		if err := requireRecordedCustodyVerifier(t, e).VerifyRecordedCustodyAt(f.chain, "custody-peer", serial, f.at); err != nil {
			t.Fatal("CUSTODY_RECORDED_HISTORY: later renewal/revocation rewrote original facts:", err)
		}
	}
	at := time.Now().UTC()
	if err := requireRecordedCustodyVerifier(t, f.successor).VerifyRecordedCustodyAt(f.chain, "custody-peer", serial, at); err == nil {
		t.Fatal("CUSTODY_RECORDED_SUCCESSOR: original strict policy accepted superseded peer")
	}
	if err := requireRecordedCustodyVerifier(t, f.permissive).VerifyRecordedCustodyAt(f.chain, "custody-peer", serial, at); err != nil {
		t.Fatal("CUSTODY_RECORDED_POLICY: original rotated-peer policy ignored:", err)
	}
	if err := requireRecordedCustodyVerifier(t, f.revoked).VerifyRecordedCustodyAt(f.chain, "custody-peer", serial, at); err == nil {
		t.Fatal("CUSTODY_RECORDED_REVOCATION: original signed revocation ignored")
	}
	// Existing provenance verification intentionally remains weaker: it is not
	// silently changed into consumption-time authorization by this new API.
	if err := f.revoked.VerifyRecordedPeer(f.chain, "custody-peer"); err != nil {
		t.Fatal("existing recorded-peer provenance semantics changed:", err)
	}
	if f.original.Digest() != digest {
		t.Fatal("historical verification mutated original public evidence")
	}
}

// Build public framing from an actual captured native observation and genuine
// signed objects, then enter through the production decoder. No parsed evidence
// fields or successful owner/capability are constructed by these fixtures.
func decodeRecordedCustodyObjects(t *testing.T, original, crls, successors []byte) (*HostTrustEvidence, []byte) {
	t.Helper()
	if !bytes.HasPrefix(original, []byte("LVTRUST1")) {
		t.Fatal("signed object fixture lacks actual public framing")
	}
	rest := original[8:]
	var parts [][]byte
	for i := 0; i < 5; i++ {
		if len(rest) < 4 {
			t.Fatal("signed object fixture truncated framing")
		}
		n := int(binary.BigEndian.Uint32(rest[:4]))
		rest = rest[4:]
		if n > len(rest) {
			t.Fatal("signed object fixture truncated field")
		}
		parts = append(parts, bytes.Clone(rest[:n]))
		rest = rest[n:]
	}
	if len(rest) != 0 {
		t.Fatal("signed object fixture trailing framing")
	}
	parts[1], parts[2] = crls, successors
	var out bytes.Buffer
	out.WriteString("LVTRUST1")
	for _, part := range parts {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(part)))
		out.Write(n[:])
		out.Write(part)
	}
	raw := bytes.Clone(out.Bytes())
	e, err := DecodeHostTrustEvidence(raw)
	if err != nil {
		t.Fatal("genuine signed object fixture failed production decode:", err)
	}
	return e, raw
}

func recordedCustodySigningRoot(t *testing.T, host string) (*x509.Certificate, *ecdsa.PrivateKey, [][]byte, []byte, time.Time) {
	t.Helper()
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	ca, key := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := GenerateHostCert(ca, key, filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), host, nil); err != nil {
		t.Fatal(err)
	}
	pair, err := ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	root, signer, err := loadCA(ca, key)
	if err != nil {
		t.Fatal(err)
	}
	_, raw := captureRecordedCustodyEvidence(t, dir, host)
	return root, signer, pair.Certificate, raw, time.Now().UTC()
}

func recordedCustodySignedCRL(t *testing.T, root *x509.Certificate, key *ecdsa.PrivateKey, at time.Time, serials []*big.Int) []byte {
	t.Helper()
	crl := &x509.RevocationList{Number: big.NewInt(9001), ThisUpdate: at.Add(-time.Minute), NextUpdate: at.Add(time.Hour)}
	for _, serial := range serials {
		crl.RevokedCertificateEntries = append(crl.RevokedCertificateEntries, x509.RevocationListEntry{SerialNumber: serial, RevocationTime: at.Add(-time.Second)})
	}
	der, err := x509.CreateRevocationList(rand.Reader, crl, root, key)
	if err != nil {
		t.Fatal("genuine original CRL signing:", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der})
}

func TestRecordedCustodySelectedChainRevocation(t *testing.T) {
	root, rootKey, _, original, at := recordedCustodySigningRoot(t, "custody-chain-observer")
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	interTemplate := &x509.Certificate{SerialNumber: big.NewInt(8001), Subject: pkix.Name{CommonName: "custody-intermediate"}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	interDER, err := x509.CreateCertificate(rand.Reader, interTemplate, root, &interKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, err := x509.ParseCertificate(interDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{SerialNumber: big.NewInt(8002), Subject: pkix.Name{CommonName: "custody-chain-peer"}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, inter, &leafKey.PublicKey, interKey)
	if err != nil {
		t.Fatal(err)
	}
	chain := [][]byte{leafDER, interDER}
	serial := leafTemplate.SerialNumber.Text(16)
	clean, _ := decodeRecordedCustodyObjects(t, original, recordedCustodySignedCRL(t, root, rootKey, at, nil), nil)
	if err := requireRecordedCustodyVerifier(t, clean).VerifyRecordedCustodyAt(chain, "custody-chain-peer", serial, at); err != nil {
		t.Fatal("CUSTODY_RECORDED_INTERMEDIATE_VALID: clean signed intermediate chain refused:", err)
	}
	for _, tc := range []struct {
		name   string
		serial *big.Int
	}{
		{"selected-intermediate", inter.SerialNumber},
		{"selected-root", root.SerialNumber},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, raw := decodeRecordedCustodyObjects(t, original, recordedCustodySignedCRL(t, root, rootKey, at, []*big.Int{tc.serial}), nil)
			before := e.Digest()
			if err := e.VerifyRecordedPeer(chain, "custody-chain-peer"); err != nil {
				t.Fatal("signed nonleaf fixture lost existing provenance:", err)
			}
			if err := requireRecordedCustodyVerifier(t, e).VerifyRecordedCustodyAt(chain, "custody-chain-peer", serial, at); err == nil {
				t.Fatal("CUSTODY_RECORDED_NONLEAF_REVOCATION: signed selected nonleaf revocation ignored")
			}
			decoded, err := DecodeHostTrustEvidence(raw)
			if err != nil || e.Digest() != before || decoded.Digest() != before {
				t.Fatal("nonleaf verification changed immutable original evidence:", err)
			}
		})
	}
}

type recordedCustodyEdge struct {
	from, to *big.Int
	host     string
}

func recordedCustodySignedEdges(t *testing.T, root *x509.Certificate, key *ecdsa.PrivateKey, at time.Time, edges []recordedCustodyEdge) []byte {
	t.Helper()
	var bundle []byte
	for _, edge := range edges {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		previous, err := asn1.Marshal(edge.from)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{SerialNumber: edge.to, Subject: pkix.Name{CommonName: edge.host}, NotBefore: at.Add(-time.Minute), NotAfter: at.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, ExtraExtensions: []pkix.Extension{{Id: hostCertRenewalOfOID, Value: previous}}}
		der, err := x509.CreateCertificate(rand.Reader, template, root, &leafKey.PublicKey, key)
		if err != nil {
			t.Fatal("genuine successor signing:", err)
		}
		bundle = append(bundle, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	return bundle
}

func TestRecordedCustodySuccessorGraph(t *testing.T) {
	const host = "custody-graph-peer"
	root, key, chain, original, at := recordedCustodySigningRoot(t, host)
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		t.Fatal(err)
	}
	clean, _ := decodeRecordedCustodyObjects(t, original, recordedCustodySignedCRL(t, root, key, at, nil), nil)
	if err := requireRecordedCustodyVerifier(t, clean).VerifyRecordedCustodyAt(chain, host, leaf.SerialNumber.Text(16), at); err != nil {
		t.Fatal("CUSTODY_RECORDED_GRAPH_VALID: clean original graph peer refused:", err)
	}
	a, b, c, d := big.NewInt(10001), big.NewInt(10002), big.NewInt(10003), big.NewInt(10004)
	cases := []struct {
		name    string
		edges   []recordedCustodyEdge
		revoked []*big.Int
		refuse  bool
	}{
		{"revoked-continuation", []recordedCustodyEdge{{leaf.SerialNumber, a, host}, {a, b, host}}, []*big.Int{a}, true},
		{"abandoned-revoked-successor", []recordedCustodyEdge{{leaf.SerialNumber, a, host}}, []*big.Int{a}, false},
		{"independent-same-host-branches", []recordedCustodyEdge{{leaf.SerialNumber, a, host}, {leaf.SerialNumber, d, host}}, []*big.Int{a}, true},
		{"wrong-host-first-edge", []recordedCustodyEdge{{leaf.SerialNumber, a, "other-host"}}, nil, false},
		{"wrong-host-continuation", []recordedCustodyEdge{{leaf.SerialNumber, a, host}, {a, b, "other-host"}}, []*big.Int{a}, false},
		{"revoked-cycle-and-convergence", []recordedCustodyEdge{{leaf.SerialNumber, a, host}, {leaf.SerialNumber, c, host}, {a, b, host}, {c, b, host}, {b, a, host}}, []*big.Int{a, b, c}, false},
		{"convergent-standing-exit", []recordedCustodyEdge{{leaf.SerialNumber, a, host}, {leaf.SerialNumber, c, host}, {a, b, host}, {c, b, host}, {b, a, host}, {b, d, host}}, []*big.Int{a, b, c}, true},
	}
	// Existing standing accepts outgoing edges at depths 0 through 16:
	// 17 edges to an unrevoked successor refuse; 18 edges are beyond its bound.
	for _, length := range []int{maxSupersessionChain + 1, maxSupersessionChain + 2} {
		var edges []recordedCustodyEdge
		var revoked []*big.Int
		previous := leaf.SerialNumber
		for i := 0; i < length; i++ {
			next := big.NewInt(int64(20000 + i))
			edges = append(edges, recordedCustodyEdge{previous, next, host})
			if i < length-1 {
				revoked = append(revoked, next)
			}
			previous = next
		}
		name := "inclusive-depth-boundary"
		if length > maxSupersessionChain+1 {
			name = "beyond-depth-boundary"
		}
		cases = append(cases, struct {
			name    string
			edges   []recordedCustodyEdge
			revoked []*big.Int
			refuse  bool
		}{name, edges, revoked, length == maxSupersessionChain+1})
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, raw := decodeRecordedCustodyObjects(t, original, recordedCustodySignedCRL(t, root, key, at, tc.revoked), recordedCustodySignedEdges(t, root, key, at, tc.edges))
			before := e.Digest()
			if err := e.VerifyRecordedPeer(chain, host); err != nil {
				t.Fatal("signed graph fixture lost original provenance:", err)
			}
			err := requireRecordedCustodyVerifier(t, e).VerifyRecordedCustodyAt(chain, host, leaf.SerialNumber.Text(16), at)
			if tc.refuse && err == nil {
				t.Fatal("CUSTODY_RECORDED_GRAPH_STANDING: standing original successor graph ignored")
			}
			if !tc.refuse && err != nil {
				t.Fatal("CUSTODY_RECORDED_GRAPH_ABANDONED: nonstanding original graph refused:", err)
			}
			decoded, decodeErr := DecodeHostTrustEvidence(raw)
			if decodeErr != nil || e.Digest() != before || decoded.Digest() != before {
				t.Fatal("graph verification changed immutable original evidence:", decodeErr)
			}
		})
	}
}
