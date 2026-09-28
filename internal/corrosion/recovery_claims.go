package corrosion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"

	"github.com/litevirt/litevirt/internal/pki"
)

// Single-decree claims: the types, the ballot order, the value digest, and
// the signed accept a certificate is made of (docs/design/recovery-claims.md
// §3.2–§3.4, §3.9–§3.10). The voter's rules live in recovery_claims_voter.go and
// the voter set in voter_config.go.

// ClaimKindVoterConfig is the target_kind of a voter-config change: the claim at
// key (voter_config, "", g, 0) decides generation g+1.
const ClaimKindVoterConfig = "voter_config"

// Claim target kinds a workload recovery is decided under. Nothing in this
// release MINTS a workload claim — recovery_claim_v1 (colonelpanik/litevirt#250)
// does — but voters already answer them, so promise history is unbroken when it
// lands (§5.1, "Voters answer regardless of the flag").
const (
	ClaimKindVM        = "vm"
	ClaimKindContainer = "container"
)

// ClaimKey is what one claim decides.
type ClaimKey struct {
	TargetKind string `json:"target_kind"`
	TargetName string `json:"target_name"`
	OwnerEpoch int64  `json:"owner_epoch"` // generation being left; config generation for voter_config
	Attempt    int64  `json:"attempt"`
}

// IsVoterConfig reports whether k decides a voter-config generation.
func (k ClaimKey) IsVoterConfig() bool { return k.TargetKind == ClaimKindVoterConfig }

// IsWorkload reports whether k decides the recovery of a workload.
func (k ClaimKey) IsWorkload() bool {
	return k.TargetKind == ClaimKindVM || k.TargetKind == ClaimKindContainer
}

// Validate refuses a key no voter should record state for.
func (k ClaimKey) Validate() error {
	switch {
	case k.IsVoterConfig():
		if k.TargetName != "" || k.Attempt != 0 || k.OwnerEpoch < 0 {
			return fmt.Errorf("a voter_config key is (voter_config, \"\", generation, 0), got %+v", k)
		}
	case k.IsWorkload():
		if k.TargetName == "" || k.OwnerEpoch < 0 || k.Attempt < 0 {
			return fmt.Errorf("a workload key needs a target name and non-negative epoch and attempt, got %+v", k)
		}
	default:
		return fmt.Errorf("unknown claim target kind %q", k.TargetKind)
	}
	return nil
}

func (k ClaimKey) String() string {
	return fmt.Sprintf("%s/%s@%d#%d", k.TargetKind, k.TargetName, k.OwnerEpoch, k.Attempt)
}

// Ballot orders proposals for one key (§3.2).
type Ballot struct {
	Round       uint64 `json:"round"`
	Coordinator string `json:"coordinator"`
	Nonce       []byte `json:"nonce"`
}

// IsZero reports whether b is the "nothing promised / nothing accepted" ballot.
func (b Ballot) IsZero() bool { return b.Round == 0 && b.Coordinator == "" && len(b.Nonce) == 0 }

// Equal reports whether a and b are the same ballot.
func (b Ballot) Equal(o Ballot) bool { return CompareBallots(b, o) == 0 }

func (b Ballot) String() string {
	if b.IsZero() {
		return "(none)"
	}
	return fmt.Sprintf("(%d, %s, %s)", b.Round, b.Coordinator, hex.EncodeToString(b.Nonce))
}

// CompareBallots returns 1 when a ranks above b, -1 when below, 0 when equal.
//
// A higher round ranks higher. At an equal round the lexicographically LOWER
// coordinator ranks higher — the lease-contest rule keeps the lowest-sorting
// claimant, so the node it keeps also wins an equal-round duel. The boot nonce
// breaks any remaining tie (higher nonce ranks higher; the direction is
// arbitrary, it only has to be total). The zero ballot ranks below every real
// one, because every real ballot has round >= 1.
func CompareBallots(a, b Ballot) int {
	switch {
	case a.Round > b.Round:
		return 1
	case a.Round < b.Round:
		return -1
	}
	switch {
	case a.Coordinator < b.Coordinator:
		return 1
	case a.Coordinator > b.Coordinator:
		return -1
	}
	return bytes.Compare(a.Nonce, b.Nonce)
}

// NewBootNonce draws the per-process ballot nonce (§3.2, "Why boot_nonce").
func NewBootNonce() []byte {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("claims: read random boot nonce: %v", err))
	}
	return b
}

// VoterMember is one member of a voter-config generation.
type VoterMember struct {
	Name        string `json:"name"`
	Incarnation string `json:"incarnation"`
}

// Voter-config change kinds (§4.1). force:<...> belongs to
// `lv cluster voter force-reconfigure`, which is not in this release.
const (
	VoterChangeGenesis = "genesis"
	VoterChangeReset   = "reset"
	voterChangeAddPfx  = "add:"
	voterChangeRmPfx   = "rm:"
)

// VoterChangeAdd and VoterChangeRm name a one-member change.
func VoterChangeAdd(host string) string { return voterChangeAddPfx + host }
func VoterChangeRm(host string) string  { return voterChangeRmPfx + host }

// VoterConfigValue is the value a voter_config claim decides: the complete
// voter_configs row except its certificate, so any node that learns the decided
// value writes the identical row (§4.1).
type VoterConfigValue struct {
	Generation int64         `json:"generation"`
	Members    []VoterMember `json:"members"` // sorted by name
	Change     string        `json:"change"`
	CreatedBy  string        `json:"created_by"`
	CreatedAt  string        `json:"created_at"`
}

// ClaimValue is what a claim decides. Exactly one of Proof (a workload
// recovery, §3.4) and Config (a voter-config change, §4.3) is set.
type ClaimValue struct {
	// Proof carries the ActionProof binding fields (ProofBindingEqual's set
	// plus the proof ID). The lease-holder and quorum fields are not part of
	// the decision and are not digested.
	Proof *ActionProof `json:"proof,omitempty"`
	// SourceHost is the recorded owner being left, the host every voter
	// probes before it accepts a workload value (§3.5.1). Digested, so a
	// certificate names the source its voters could not reach.
	SourceHost string            `json:"source_host,omitempty"`
	Config     *VoterConfigValue `json:"config,omitempty"`
}

const (
	claimValueDomain       = "litevirt-recovery-value-v1"
	claimConfigValueDomain = "litevirt-voter-config-value-v1"
	claimAcceptDomain      = "litevirt-recovery-accept-v1"
	voterMembersDomain     = "litevirt-voter-members-v1"
)

// claimField writes a length-prefixed field. Length-prefixed rather than
// separator-terminated: a value is operator- or peer-supplied text, and no
// choice of separator is safe against a value that contains it.
func claimField(h interface{ Write([]byte) (int, error) }, s string) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(s)))
	h.Write(n[:])
	h.Write([]byte(s))
}

func i64(v int64) string { return strconv.FormatInt(v, 10) }

// MembersHash is the digest of a sorted member list.
func MembersHash(members []VoterMember) string {
	h := sha256.New()
	claimField(h, voterMembersDomain)
	claimField(h, i64(int64(len(members))))
	for _, m := range members {
		claimField(h, m.Name)
		claimField(h, m.Incarnation)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// SortMembers orders members by name, the canonical order.
func SortMembers(members []VoterMember) []VoterMember {
	out := append([]VoterMember(nil), members...)
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Digest is the value_digest (§3.4). A workload value covers every binding
// field plus source_host; a config value covers the whole row but its
// certificate. The two domains keep a config value from ever colliding with a
// workload one.
func (v ClaimValue) Digest() (string, error) {
	h := sha256.New()
	switch {
	case v.Proof != nil && v.Config == nil:
		p := v.Proof
		claimField(h, claimValueDomain)
		for _, f := range []string{
			p.ID, p.Action, p.TargetKind, p.TargetName, p.DestHost, p.Coordinator,
			p.RelocationToken, p.FenceEpoch, p.OwnerEpoch, i64(p.LeaseTerm), p.LeaseKey,
			v.SourceHost,
		} {
			claimField(h, f)
		}
	case v.Config != nil && v.Proof == nil && v.SourceHost == "":
		cfg := v.Config
		claimField(h, claimConfigValueDomain)
		claimField(h, i64(cfg.Generation))
		claimField(h, MembersHash(cfg.Members))
		claimField(h, cfg.Change)
		claimField(h, cfg.CreatedBy)
		claimField(h, cfg.CreatedAt)
	default:
		return "", fmt.Errorf("a claim value carries exactly one of a proof or a voter config")
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// MustDigest is Digest for a value already known to be well-formed.
func (v ClaimValue) MustDigest() string {
	d, err := v.Digest()
	if err != nil {
		panic(err)
	}
	return d
}

// ClaimAccept is one voter's signed accept (§3.9).
type ClaimAccept struct {
	Voter            string   `json:"voter"`
	VoterIncarnation string   `json:"voter_incarnation"`
	ConfigGeneration int64    `json:"config_generation"`
	Key              ClaimKey `json:"key"`
	Ballot           Ballot   `json:"ballot"`
	ValueDigest      string   `json:"value_digest"`
	CertPEM          string   `json:"cert_pem"`
	Signature        []byte   `json:"signature"`
}

// ClaimCertificate is a quorum of signed accepts for one ballot and one value.
type ClaimCertificate struct {
	Key              ClaimKey      `json:"key"`
	ConfigGeneration int64         `json:"config_generation"`
	Ballot           Ballot        `json:"ballot"`
	ValueDigest      string        `json:"value_digest"`
	SourceHost       string        `json:"source_host,omitempty"`
	Accepts          []ClaimAccept `json:"accepts"`
}

// Encode is the certificate's stored form.
func (c ClaimCertificate) Encode() (string, error) {
	b, err := json.Marshal(c)
	return string(b), err
}

// DecodeClaimCertificate parses a stored certificate.
func DecodeClaimCertificate(s string) (ClaimCertificate, error) {
	var c ClaimCertificate
	if s == "" {
		return c, fmt.Errorf("no certificate")
	}
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return c, fmt.Errorf("certificate does not parse: %w", err)
	}
	return c, nil
}

// acceptPayload is exactly what a voter signs. The domain string keeps these
// bytes disjoint from every TLS handshake and every audit row the same key
// signs (§9 Q8).
func acceptPayload(key ClaimKey, gen int64, b Ballot, digest, voter, incarnation string) []byte {
	h := sha256.New()
	claimField(h, claimAcceptDomain)
	claimField(h, key.TargetKind)
	claimField(h, key.TargetName)
	claimField(h, i64(key.OwnerEpoch))
	claimField(h, i64(key.Attempt))
	claimField(h, i64(gen))
	claimField(h, strconv.FormatUint(b.Round, 10))
	claimField(h, b.Coordinator)
	claimField(h, string(b.Nonce))
	claimField(h, digest)
	claimField(h, voter)
	claimField(h, incarnation)
	return h.Sum(nil)
}

// ClaimSigner signs this voter's accepts with its cluster identity
// (pkiDir/host.key, CN = host name, signed by the cluster CA).
type ClaimSigner struct {
	name    string
	certPEM string
	key     *ecdsa.PrivateKey
}

// LoadClaimSigner loads host.crt/host.key from pkiDir. The certificate's CN
// must be hostName: an accept is only meaningful if the certificate that
// validates it names the voter it claims to come from.
func LoadClaimSigner(pkiDir, hostName string) (*ClaimSigner, error) {
	certPEM, err := os.ReadFile(filepath.Join(pkiDir, "host.crt"))
	if err != nil {
		return nil, fmt.Errorf("read host certificate: %w", err)
	}
	cert, err := parseCertPEM(certPEM)
	if err != nil {
		return nil, err
	}
	if cert.Subject.CommonName != hostName {
		return nil, fmt.Errorf("host certificate CN is %q but this host is %q", cert.Subject.CommonName, hostName)
	}
	keyPath := filepath.Join(pkiDir, "host.key")
	if err := pki.TightenKeyMode(keyPath); err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read host key: %w", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", keyPath)
	}
	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse host key: %w", err)
	}
	return &ClaimSigner{name: hostName, certPEM: string(certPEM), key: priv}, nil
}

// Name is the voter this signer signs as.
func (s *ClaimSigner) Name() string {
	if s == nil {
		return ""
	}
	return s.name
}

// Sign produces this voter's accept.
func (s *ClaimSigner) Sign(key ClaimKey, gen int64, b Ballot, digest, incarnation string) (ClaimAccept, error) {
	if s == nil || s.key == nil {
		return ClaimAccept{}, fmt.Errorf("no claim signing key loaded")
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.key, acceptPayload(key, gen, b, digest, s.name, incarnation))
	if err != nil {
		return ClaimAccept{}, fmt.Errorf("sign accept: %w", err)
	}
	return ClaimAccept{
		Voter: s.name, VoterIncarnation: incarnation, ConfigGeneration: gen,
		Key: key, Ballot: b, ValueDigest: digest, CertPEM: s.certPEM, Signature: sig,
	}, nil
}

// ClaimVerifier checks certificates offline against the cluster CA and CRL
// (§3.10 steps 4–5). It needs no private key and makes no RPC: a destination
// verifies without re-querying any voter.
type ClaimVerifier struct {
	roots  *x509.CertPool
	pkiDir string
}

// LoadClaimVerifier loads the cluster CA from pkiDir. Revocation is read from
// the CRL bundle installed in pkiDir (the CA-verified union of every published
// cluster_crl row, see SyncClusterCRL), checked on every call.
func LoadClaimVerifier(pkiDir string) (*ClaimVerifier, error) {
	caPEM, err := os.ReadFile(filepath.Join(pkiDir, "ca.crt"))
	if err != nil {
		return nil, fmt.Errorf("read cluster CA: %w", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("cluster CA at %s contains no usable certificate", pkiDir)
	}
	return &ClaimVerifier{roots: roots, pkiDir: pkiDir}, nil
}

// CertExpectation is what a certificate must certify, and who may certify it.
type CertExpectation struct {
	Key              ClaimKey
	ValueDigest      string
	ConfigGeneration int64
	// Electorate is the member list whose accepts count, with the incarnation
	// each was admitted with.
	Electorate []VoterMember
	// Quorum is how many DISTINCT electorate members must have signed.
	Quorum int
}

// MajorityOf is the quorum of a generation with n members.
func MajorityOf(n int) int { return n/2 + 1 }

// Verify checks cert against want. The accepts that count are the distinct
// electorate members, at the certificate's ballot, digest and generation,
// whose incarnation matches their entry and whose signature verifies with a
// CA-issued, unrevoked certificate naming them. Fewer than want.Quorum of those
// refuses.
func (v *ClaimVerifier) Verify(cert ClaimCertificate, want CertExpectation) error {
	if v == nil {
		return fmt.Errorf("no claim verifier loaded")
	}
	if cert.Key != want.Key {
		return fmt.Errorf("certificate decides %s, not %s", cert.Key, want.Key)
	}
	if cert.ValueDigest != want.ValueDigest {
		return fmt.Errorf("certificate certifies value %s, not %s", short(cert.ValueDigest), short(want.ValueDigest))
	}
	if cert.ConfigGeneration != want.ConfigGeneration {
		return fmt.Errorf("certificate is at generation %d, not %d", cert.ConfigGeneration, want.ConfigGeneration)
	}
	if want.Quorum < 1 {
		return fmt.Errorf("no quorum to verify against")
	}
	electorate := make(map[string]string, len(want.Electorate))
	for _, m := range want.Electorate {
		electorate[m.Name] = m.Incarnation
	}
	counted := map[string]bool{}
	var problems []string
	for _, a := range cert.Accepts {
		if err := v.verifyAccept(cert, a, electorate); err != nil {
			problems = append(problems, fmt.Sprintf("%s: %v", a.Voter, err))
			continue
		}
		counted[a.Voter] = true
	}
	if len(counted) < want.Quorum {
		return fmt.Errorf("certificate carries %d valid accept(s) from distinct members, needs %d (%v)",
			len(counted), want.Quorum, problems)
	}
	return nil
}

func (v *ClaimVerifier) verifyAccept(cert ClaimCertificate, a ClaimAccept, electorate map[string]string) error {
	inc, member := electorate[a.Voter]
	if !member {
		return fmt.Errorf("not a member of generation %d", cert.ConfigGeneration)
	}
	if a.VoterIncarnation != inc {
		return fmt.Errorf("incarnation %s does not match its member entry %s", short(a.VoterIncarnation), short(inc))
	}
	if a.Key != cert.Key || !a.Ballot.Equal(cert.Ballot) || a.ValueDigest != cert.ValueDigest ||
		a.ConfigGeneration != cert.ConfigGeneration {
		return fmt.Errorf("accept is for a different key, ballot, value or generation")
	}
	c, err := parseCertPEM([]byte(a.CertPEM))
	if err != nil {
		return err
	}
	if _, err := c.Verify(x509.VerifyOptions{Roots: v.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("certificate does not chain to the cluster CA: %w", err)
	}
	if c.Subject.CommonName != a.Voter {
		return fmt.Errorf("signed with %q's certificate", c.Subject.CommonName)
	}
	if pki.IsCertRevoked(v.pkiDir, c.SerialNumber) {
		return fmt.Errorf("certificate %s is revoked", c.SerialNumber.Text(16))
	}
	pub, ok := c.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("certificate key is not ECDSA")
	}
	if !ecdsa.VerifyASN1(pub, acceptPayload(a.Key, a.ConfigGeneration, a.Ballot, a.ValueDigest, a.Voter, a.VoterIncarnation), a.Signature) {
		return fmt.Errorf("signature does not verify")
	}
	return nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
