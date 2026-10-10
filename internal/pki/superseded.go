package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/litevirt/litevirt/internal/secretfile"
)

// Supersession: which host certificates the CA has REPLACED.
//
// A renewal (`lv host renew-cert`) issues a successor that carries its
// predecessor's serial in a CA-signed extension (RenewedFromSerial). That
// certificate is proof, signed by the only key that can issue host identities,
// that the predecessor is no longer the host's identity — whatever any
// replicated row says. Nothing a peer can write (hosts.cert_serial, a health
// condition, a tombstone) can forge it or take it back.
//
// Every node collects that proof wherever it sees a successor: a TLS handshake
// in either direction (revocationVerifier), an accept carried in a claim or
// voter certificate (corrosion.ClaimVerifier), its own served identity. The
// proof is kept in pki_dir/superseded.pem — node-local, never replicated, and
// only ever added to — so a node that has seen it once keeps refusing the
// replaced certificate across restarts:
//
//   - the claim and voter-generation serial pin (corrosion.ClaimVerifier) does
//     not count an accept signed with a superseded certificate;
//   - the auth interceptor refuses every new RPC on a connection made with one
//     (grpcapi), and the connection tracker closes it.
//
// One thing takes the proof back: the CA revoking the SUCCESSOR before it was
// itself replaced. That is the abandoned-renewal path (the successor was never
// adopted, the host stays on its predecessor), and only the CA can sign it.
// A successor that was revoked because it was in turn renewed still counts:
// its own successor carries the chain on.

const supersededFile = "superseded.pem"

// maxSupersessionChain bounds how far a chain of renewals is followed when
// asking whether a revoked successor was itself replaced.
const maxSupersessionChain = 16

type supersession struct {
	cn        string
	successor *x509.Certificate
}

type supersessionStore struct {
	pkiDir string
	mu     sync.Mutex
	loaded bool
	ca     *x509.Certificate
	roots  *x509.CertPool
	byPrev map[string][]supersession // predecessor serial (lower-case hex) -> successors seen
	known  map[string]bool           // successor serials already judged
	crl    *crlChecker
}

var supersessionStores sync.Map // pkiDir -> *supersessionStore

func supersessionsFor(pkiDir string) *supersessionStore {
	if v, ok := supersessionStores.Load(pkiDir); ok {
		return v.(*supersessionStore)
	}
	v, _ := supersessionStores.LoadOrStore(pkiDir, &supersessionStore{pkiDir: pkiDir})
	return v.(*supersessionStore)
}

// loadLocked reads the CA and the evidence file once. A missing CA leaves the
// store empty and retried on the next call; nothing can be verified without it.
func (s *supersessionStore) loadLocked() bool {
	if s.loaded {
		return true
	}
	if s.pkiDir == "" {
		return false
	}
	caPEM, err := readBounded(filepath.Join(s.pkiDir, "ca.crt"))
	if err != nil {
		return false
	}
	ca := parseCACert(caPEM)
	if ca == nil {
		return false
	}
	s.ca, s.roots = ca, x509.NewCertPool()
	s.roots.AddCert(ca)
	s.byPrev, s.known = map[string][]supersession{}, map[string]bool{}
	s.crl = newCRLChecker(s.pkiDir, ca)
	s.loaded = true
	if b, err := readBounded(filepath.Join(s.pkiDir, supersededFile)); err == nil {
		for rest := b; ; {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			if block.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}
			s.addLocked(c) // re-verified: the file is evidence, not authority
		}
	}
	return true
}

// addLocked records c when it is a CA-issued host certificate naming a
// predecessor; it reports whether c was new.
func (s *supersessionStore) addLocked(c *x509.Certificate) bool {
	succ := strings.ToLower(c.SerialNumber.Text(16))
	if s.known[succ] {
		return false
	}
	prev, ok := RenewedFromSerial(c)
	if !ok || c.Subject.CommonName == "" || !hasUsage(c, x509.ExtKeyUsageServerAuth) {
		return false
	}
	// Verified at the moment it was issued: an expired successor still proves
	// that its predecessor was replaced.
	at := c.NotBefore.Add(time.Second)
	if _, err := c.Verify(x509.VerifyOptions{Roots: s.roots, CurrentTime: at,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		return false
	}
	s.known[succ] = true
	s.byPrev[prev] = append(s.byPrev[prev], supersession{cn: c.Subject.CommonName, successor: c})
	return true
}

// NoteSuccessor records cert as proof that the certificate it names as its
// predecessor has been replaced, when cert is a CA-issued host certificate
// carrying the renewal extension. It is cheap for anything else, and for a
// successor already known. New evidence is persisted before it returns; a
// failed write keeps it in memory and is retried with the next new one.
func NoteSuccessor(pkiDir string, cert *x509.Certificate) bool {
	if cert == nil || cert.SerialNumber == nil {
		return false
	}
	if _, ok := RenewedFromSerial(cert); !ok {
		return false
	}
	s := supersessionsFor(pkiDir)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loadLocked() || !s.addLocked(cert) {
		return false
	}
	if err := s.persistLocked(); err != nil {
		slog.Warn("could not persist the proof that a host certificate was replaced; it is kept in memory",
			"file", filepath.Join(pkiDir, supersededFile), "error", err)
	}
	prev, _ := RenewedFromSerial(cert)
	slog.Info("learned that a host certificate was replaced by a CA-issued renewal",
		"host", cert.Subject.CommonName, "replaced", prev, "successor", strings.ToLower(cert.SerialNumber.Text(16)))
	return true
}

func (s *supersessionStore) persistLocked() error {
	var buf bytes.Buffer
	for _, list := range s.byPrev {
		for _, e := range list {
			if err := pem.Encode(&buf, &pem.Block{Type: "CERTIFICATE", Bytes: e.successor.Raw}); err != nil {
				return err
			}
		}
	}
	return secretfile.Write(filepath.Join(s.pkiDir, supersededFile), buf.Bytes(), 0o644)
}

// SupersededBy reports the serial of a CA-issued successor of the certificate
// serial (lower-case hex) issued to cn, when this node holds proof of one that
// still stands (see the file comment). ok=false means no proof is held: not
// that the certificate is current.
func SupersededBy(pkiDir, cn, serial string) (successor string, ok bool) {
	s := supersessionsFor(pkiDir)
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.loadLocked() {
		return "", false
	}
	return s.standingLocked(cn, strings.ToLower(serial), 0)
}

func (s *supersessionStore) standingLocked(cn, serial string, depth int) (string, bool) {
	if depth > maxSupersessionChain {
		return "", false
	}
	for _, e := range s.byPrev[serial] {
		if e.cn != cn {
			continue
		}
		succ := strings.ToLower(e.successor.SerialNumber.Text(16))
		if !s.crl.isRevoked(e.successor.SerialNumber) {
			return succ, true
		}
		// A revoked successor stands only when it was itself replaced; one
		// revoked unused (an abandoned renewal) hands the identity back.
		if _, ok := s.standingLocked(cn, succ, depth+1); ok {
			return succ, true
		}
	}
	return "", false
}

// ErrSuperseded marks a refusal of a certificate the CA has replaced.
var ErrSuperseded = errors.New("certificate replaced by a CA-issued renewal")

// SupersededError returns an error wrapping ErrSuperseded when pkiDir holds
// standing proof that cert was replaced, else nil.
func SupersededError(pkiDir string, cert *x509.Certificate) error {
	if cert == nil || cert.SerialNumber == nil {
		return nil
	}
	serial := strings.ToLower(cert.SerialNumber.Text(16))
	if succ, ok := SupersededBy(pkiDir, cert.Subject.CommonName, serial); ok {
		return &supersededErr{cn: cert.Subject.CommonName, serial: serial, successor: succ}
	}
	return nil
}

type supersededErr struct{ cn, serial, successor string }

func (e *supersededErr) Error() string {
	return "certificate " + e.serial + " of " + e.cn + " was replaced by its CA-issued renewal " + e.successor
}

func (e *supersededErr) Unwrap() error { return ErrSuperseded }

// forgetSupersessionsForTests drops the in-memory store for pkiDir, so a test
// can show what survives a restart (the file).
func forgetSupersessionsForTests(pkiDir string) { supersessionStores.Delete(pkiDir) }
