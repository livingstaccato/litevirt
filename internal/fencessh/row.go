// Package fencessh is managed node-to-node fence SSH: each host publishes the
// public half of its own fence key and its sshd host keys in a row it signs
// with its CA-issued host key (corrosion host_fence_ssh), every daemon
// verifies every peer's row against the cluster CA and the CRL, and renders
// the verified ones into a restricted authorized_keys and a pinned
// known_hosts. A fence then dials the target with that key, against that pin,
// and the target's forced command powers it off only when the request names
// it.
//
// The private half of a fence key never leaves its host. A stolen key powers
// a peer off from its owner's certificate address and nothing else, and a
// machine answering at the wrong address fails the pin before it
// authenticates anything.
package fencessh

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/pki"
)

// sigDomain separates a fence SSH row's signature from every other use of a
// host key: the same key serves mTLS, libvirt TLS, audit rows and recovery
// claims.
const sigDomain = "litevirt-fence-ssh-v1\x00"

// maxKeys bounds how many keys one row may carry, of each kind.
const maxKeys = 8

// Publication is the signed content of a host's row.
type Publication struct {
	HostName      string
	Generation    int64
	FencePubkeys  string
	SSHDHostkeys  string
	Accepting     bool
	EverAccepting bool
	Detail        string
	CertPEM       string
}

// PublicationOf is the signed content of row.
func PublicationOf(r corrosion.HostFenceSSHRow) Publication {
	return Publication{
		HostName: r.HostName, Generation: r.Generation, FencePubkeys: r.FencePubkeys,
		SSHDHostkeys: r.SSHDHostkeys, Accepting: r.Accepting, EverAccepting: r.EverAccepting,
		Detail: r.Detail, CertPEM: r.CertPEM,
	}
}

// payload is the byte string a row's signature covers: the domain, then each
// field length-prefixed, so no field can be shifted into its neighbour.
func (p Publication) payload() []byte {
	var b bytes.Buffer
	b.WriteString(sigDomain)
	for _, f := range []string{
		p.HostName, strconv.FormatInt(p.Generation, 10), p.FencePubkeys, p.SSHDHostkeys,
		boolStr(p.Accepting), boolStr(p.EverAccepting), p.Detail, p.CertPEM,
	} {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		b.Write(n[:])
		b.WriteString(f)
	}
	return b.Bytes()
}

func boolStr(v bool) string {
	if v {
		return "1"
	}
	return "0"
}

// Sign signs p with the host key and returns the row to publish.
func Sign(p Publication, signer crypto.Signer) (corrosion.HostFenceSSHRow, error) {
	sum := sha256.Sum256(p.payload())
	sig, err := signer.Sign(rand.Reader, sum[:], crypto.SHA256)
	if err != nil {
		return corrosion.HostFenceSSHRow{}, fmt.Errorf("sign fence ssh row: %w", err)
	}
	return corrosion.HostFenceSSHRow{
		HostName: p.HostName, Generation: p.Generation, FencePubkeys: p.FencePubkeys,
		SSHDHostkeys: p.SSHDHostkeys, Accepting: p.Accepting, EverAccepting: p.EverAccepting,
		Detail: p.Detail, CertPEM: p.CertPEM, Signature: hex.EncodeToString(sig),
	}, nil
}

// Trust is what a row is verified against: the cluster CA and the CRL.
type Trust struct {
	Roots *x509.CertPool
	// Revoked reports whether a certificate serial is revoked. Nil revokes
	// nothing.
	Revoked func(serial *big.Int) bool
}

// TrustFromPKIDir is the trust a daemon holds: pkiDir/ca.crt, and the CRL
// installed in pkiDir.
func TrustFromPKIDir(pkiDir string) (Trust, error) {
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return Trust{}, fmt.Errorf("read the cluster CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return Trust{}, fmt.Errorf("no certificate in %s", filepath.Join(pkiDir, "ca.crt"))
	}
	return Trust{Roots: pool, Revoked: func(s *big.Int) bool { return pki.IsCertRevoked(pkiDir, s) }}, nil
}

// Verified is a row that passed Verify, with its keys parsed.
type Verified struct {
	Host          string
	Generation    int64
	FenceKeys     []ssh.PublicKey
	HostKeys      []ssh.PublicKey
	Accepting     bool
	EverAccepting bool
	Detail        string
	// Addr is the one IPv4 address the host's certificate names besides
	// 127.0.0.1: the only address its fence key is accepted from, and the
	// one a fence from it binds to.
	Addr   net.IP
	Serial string
	// Expired: the certificate that signed the row has expired (it is still
	// trusted for the keys it signed; renew it).
	Expired  bool
	NotAfter time.Time
}

// ErrNotPublished is a host that has no row.
var ErrNotPublished = errors.New("no fence ssh row published")

// Verify checks row against tr. A row is accepted only when:
//
//   - it is not a tombstone;
//   - its certificate chains to the cluster CA, is a host's (not a client's),
//     names the row's host as its Common Name, and is not revoked;
//   - its signature verifies under that certificate's key;
//   - the certificate names exactly one IPv4 address besides 127.0.0.1;
//   - every key parses, and none carries options.
//
// The address a peer's key is accepted from comes from the certificate the
// operator's CA minted, never from a field of the row.
func Verify(row corrosion.HostFenceSSHRow, tr Trust) (*Verified, error) {
	if row.Deleted {
		return nil, errors.New("the row is retired (the host was removed or re-admitted)")
	}
	if tr.Roots == nil {
		return nil, errors.New("no cluster CA loaded")
	}
	cert, err := pki.ParseCertPEM([]byte(row.CertPEM))
	if err != nil {
		return nil, fmt.Errorf("certificate: %w", err)
	}
	// A certificate that has merely expired still binds the keys it signed:
	// expiry is no evidence of compromise (revocation is), and refusing the
	// row would leave its host unfenceable in every mode, while a host whose
	// row disappeared would be fenced unpinned. So the chain is checked as of
	// the moment the certificate expired, and the row is marked Expired for
	// `lv doctor fence`.
	opts := x509.VerifyOptions{Roots: tr.Roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
	expired := time.Now().After(cert.NotAfter)
	if expired {
		opts.CurrentTime = cert.NotAfter
	}
	if _, err := cert.Verify(opts); err != nil {
		return nil, fmt.Errorf("certificate does not chain to the cluster CA: %w", err)
	}
	if pki.IsClientOnlyCert(cert) {
		return nil, errors.New("certificate is a client certificate, not a host's")
	}
	if cert.Subject.CommonName != row.HostName {
		return nil, fmt.Errorf("certificate is %q's, not %q's", cert.Subject.CommonName, row.HostName)
	}
	if tr.Revoked != nil && tr.Revoked(cert.SerialNumber) {
		return nil, fmt.Errorf("certificate %s is revoked", cert.SerialNumber.Text(16))
	}
	sig, err := hex.DecodeString(row.Signature)
	if err != nil || len(sig) == 0 {
		return nil, errors.New("signature is missing or not hex")
	}
	sum := sha256.Sum256(PublicationOf(row).payload())
	switch pub := cert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(pub, sum[:], sig) {
			return nil, errors.New("signature does not match")
		}
	default:
		return nil, fmt.Errorf("certificate key is %T, not ECDSA", cert.PublicKey)
	}
	addr, err := FenceAddress(cert)
	if err != nil {
		return nil, err
	}
	fk, err := parseKeys(row.FencePubkeys, "fence key")
	if err != nil {
		return nil, err
	}
	hk, err := parseKeys(row.SSHDHostkeys, "sshd host key")
	if err != nil {
		return nil, err
	}
	return &Verified{
		Host: row.HostName, Generation: row.Generation, FenceKeys: fk, HostKeys: hk,
		Accepting: row.Accepting, EverAccepting: row.EverAccepting, Detail: row.Detail,
		Addr: addr, Serial: strings.ToLower(cert.SerialNumber.Text(16)), Expired: expired, NotAfter: cert.NotAfter,
	}, nil
}

// FenceAddress is the address a host fences from and is fenced by: the one
// IPv4 address its certificate names besides the 127.0.0.1 every host
// certificate carries (pki.GenerateHostCert). A certificate naming only
// loopback was minted without an address, and its host cannot fence or be
// fenced over managed SSH.
func FenceAddress(cert *x509.Certificate) (net.IP, error) {
	var found []net.IP
	for _, ip := range cert.IPAddresses {
		v4 := ip.To4()
		if v4 == nil || v4.Equal(net.IPv4(127, 0, 0, 1)) {
			continue
		}
		found = append(found, v4)
	}
	switch len(found) {
	case 1:
		return found[0], nil
	case 0:
		return nil, fmt.Errorf("certificate of %q names no IPv4 address besides 127.0.0.1, so it cannot fence or be fenced "+
			"over managed SSH (it was minted without --address)", cert.Subject.CommonName)
	default:
		return nil, fmt.Errorf("certificate of %q names %d IPv4 addresses besides 127.0.0.1, so its fence address is ambiguous",
			cert.Subject.CommonName, len(found))
	}
}

// parseKeys parses one key per line ("type base64 [comment]"). Options are
// refused: a published line is never copied into an authorized_keys, it is
// re-rendered from the parsed key, and a line that carries options is not a
// key this code published.
func parseKeys(text, what string) ([]ssh.PublicKey, error) {
	var out []ssh.PublicKey
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		pub, _, opts, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("%s does not parse: %w", what, err)
		}
		if len(opts) > 0 || len(bytes.TrimSpace(rest)) > 0 {
			return nil, fmt.Errorf("%s carries options or trailing data", what)
		}
		out = append(out, pub)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s", what)
	}
	if len(out) > maxKeys {
		return nil, fmt.Errorf("%d %ss, more than %d", len(out), what, maxKeys)
	}
	return out, nil
}

// KeyLine is pub as "type base64", with no comment.
func KeyLine(pub ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub)))
}

// KeyLines is pubs as sorted "type base64" lines joined by "\n": the canonical
// text of a row's key columns.
func KeyLines(pubs []ssh.PublicKey) string {
	lines := make([]string, 0, len(pubs))
	for _, p := range pubs {
		lines = append(lines, KeyLine(p))
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

// HexName is a host name as the forced command and the pin alias carry it.
// Names admitted by older releases pass only pki.ValidateExistingHostName, so
// a name never reaches a shell or an ssh option unencoded.
func HexName(name string) string { return hex.EncodeToString([]byte(name)) }

// Alias is the HostKeyAlias a host's sshd keys are pinned under.
func Alias(name string) string { return "litevirt-fence." + HexName(name) }

// NewFenceKey generates a fence key pair: the private key in OpenSSH PEM form
// and the public key.
func NewFenceKey() (privPEM []byte, pub ssh.PublicKey, err error) {
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	blk, err := ssh.MarshalPrivateKey(edPriv, "litevirt-fence")
	if err != nil {
		return nil, nil, err
	}
	pub, err = ssh.NewPublicKey(edPub)
	if err != nil {
		return nil, nil, err
	}
	var b bytes.Buffer
	if err := pem.Encode(&b, blk); err != nil {
		return nil, nil, err
	}
	return b.Bytes(), pub, nil
}

// pemCert is cert in PEM form.
func pemCert(cert *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}
