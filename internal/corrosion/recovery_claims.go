package corrosion

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
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
	"strings"
	"sync/atomic"

	"github.com/litevirt/litevirt/internal/pki"
)

// Single-decree claims: the types, the ballot order, the value digest, and
// the signed accept a certificate is made of (docs/design/recovery-claims.md
// §3.2–§3.4, §3.9–§3.10). The voter's rules live in recovery_claims_voter.go and
// the voter set in voter_config.go.

// ClaimKindVoterConfig is the target_kind of a voter-config change: the claim at
// key (voter_config, "", g, 0) decides generation g+1.
const ClaimKindVoterConfig = "voter_config"

// Claim target kinds a workload recovery is decided under. A coordinator
// claims one under recovery_claim_v1 before it mints the proof; voters answer
// them whatever the flag says, so promise history is unbroken across a staged
// rollout or a stand-down (§5.1, "Voters answer regardless of the flag").
const (
	ClaimKindVM        = "vm"
	ClaimKindContainer = "container"
)

// ClaimKindLUN is the target_kind of an iSCSI LUN allocation: the claim at
// key (lun, <LUN key>, g, 0) decides which disk the LUN's g-th allocation is
// (docs/storage.md, "iSCSI: one LUN, one disk"). It is decided under the voter
// generation like a workload key, and carried across a generation change.
const ClaimKindLUN = "lun"

// LUNClaimKey is the key of a LUN's gen-th allocation; lun is a
// storage.FixedDevice key.
func LUNClaimKey(lun string, gen int64) ClaimKey {
	return ClaimKey{TargetKind: ClaimKindLUN, TargetName: lun, OwnerEpoch: gen}
}

// ClaimKindLeaseTerm is the target_kind of a leader-lease term: the claim at
// key (lease_term, <lease key>, term, 0) decides which node holds that term
// of that lease (capabilities.LeaseTermClaimV1). It is decided under the voter
// generation like a workload key, and carried across a generation change.
const ClaimKindLeaseTerm = "lease_term"

// leaseKeyShaped reports whether name could be a lease key, of this build or a
// later one: 1–64 characters of a-z, 0-9 and '_'.
func leaseKeyShaped(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '_' {
			return false
		}
	}
	return true
}

// LeaseTermClaimKey is the key of term of the lease named key.
func LeaseTermClaimKey(key string, term int64) ClaimKey {
	return ClaimKey{TargetKind: ClaimKindLeaseTerm, TargetName: key, OwnerEpoch: term}
}

// ClaimKey is what one claim decides.
type ClaimKey struct {
	TargetKind string `json:"target_kind"`
	TargetName string `json:"target_name"`
	OwnerEpoch int64  `json:"owner_epoch"` // generation being left; config generation for voter_config
	Attempt    int64  `json:"attempt"`
	// Incarnation is which incarnation of the name the claim decides for: the
	// workload row's created_at, which every path that moves a row preserves
	// and every path that brings a name back to life stamps afresh (the
	// anti-entropy merge's incarnation identity). A workload deleted and
	// re-created under the same name starts again at the same owner epoch, so
	// without it the new incarnation met the old one's decided value at the
	// same key (docs/design/recovery-claims.md §10 item 37).
	//
	// "" is a LEGACY key: what a coordinator claims under until
	// claim_incarnation_v1 latches, and always for voter_config. Omitted from
	// the JSON when empty, so a legacy key's certificate encodes exactly as it
	// did before the field existed.
	Incarnation string `json:"incarnation,omitempty"`
}

// UnstampedIncarnation is the incarnation of a workload row whose created_at
// is empty (IncarnationOf). No writer leaves one empty — both columns are NOT
// NULL and every insert stamps them — but a claim's key format must not
// depend on a row's contents, so an unstamped row is scoped like any other
// rather than falling back to the legacy key (§10 item 37).
const UnstampedIncarnation = "unstamped"

// IncarnationOf is the claim incarnation of a workload row with created_at.
func IncarnationOf(createdAt string) string {
	if createdAt == "" {
		return UnstampedIncarnation
	}
	return createdAt
}

// Legacy is k without its incarnation: the key a coordinator claimed this
// decision under before claim_incarnation_v1 latched.
func (k ClaimKey) Legacy() ClaimKey {
	k.Incarnation = ""
	return k
}

// SameDecision reports whether a and b name the same (kind, name, epoch,
// attempt), whatever their incarnations.
func (k ClaimKey) SameDecision(o ClaimKey) bool { return k.Legacy() == o.Legacy() }

// WithIncarnation is k scoped to incarnation inc ("" leaves it legacy).
func (k ClaimKey) WithIncarnation(inc string) ClaimKey {
	k.Incarnation = inc
	return k
}

// IsVoterConfig reports whether k decides a voter-config generation.
func (k ClaimKey) IsVoterConfig() bool { return k.TargetKind == ClaimKindVoterConfig }

// IsWorkload reports whether k decides the recovery of a workload.
func (k ClaimKey) IsWorkload() bool {
	return k.TargetKind == ClaimKindVM || k.TargetKind == ClaimKindContainer
}

// IsLUN reports whether k decides an iSCSI LUN allocation.
func (k ClaimKey) IsLUN() bool { return k.TargetKind == ClaimKindLUN }

// IsLeaseTerm reports whether k decides the holder of a leader-lease term.
func (k ClaimKey) IsLeaseTerm() bool { return k.TargetKind == ClaimKindLeaseTerm }

// IsGenerationScoped reports whether k is decided by the members of the voter
// generation and carried into the next one: workload, LUN, automation or lease term.
// A voter_config key decides the generation itself.
func (k ClaimKey) IsGenerationScoped() bool {
	return k.IsWorkload() || k.IsLUN() || k.IsAutomation() || k.IsLeaseTerm()
}

// Validate refuses a key no voter should record state for.
func (k ClaimKey) Validate() error {
	switch {
	case k.IsAutomation():
		return validateAutomationKey(k)
	case k.IsLUN():
		if k.TargetName == "" || k.OwnerEpoch < 0 || k.Attempt != 0 || k.Incarnation != "" {
			return fmt.Errorf("a LUN key is (lun, <LUN>, generation, 0) with no incarnation, got %+v", k)
		}
	case k.IsLeaseTerm():
		// The SHAPE of a lease key only, not ValidLeaseKey: a later build adds
		// lease keys, and a voter or an importer on this build must keep a
		// decision for one it does not know — refusing it here failed a whole
		// voter-generation import mid-roll. The proposer (grpcapi
		// claimLeaseTerm) claims only keys this build acquires.
		if !leaseKeyShaped(k.TargetName) || k.OwnerEpoch < 1 || k.Attempt != 0 || k.Incarnation != "" {
			return fmt.Errorf("a lease_term key is (lease_term, <lease key>, term >= 1, 0) with no incarnation, got %+v", k)
		}
	case k.IsVoterConfig():
		if k.TargetName != "" || k.Attempt != 0 || k.OwnerEpoch < 0 || k.Incarnation != "" {
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
	if k.Incarnation != "" {
		return fmt.Sprintf("%s/%s(%s)@%d#%d", k.TargetKind, k.TargetName, k.Incarnation, k.OwnerEpoch, k.Attempt)
	}
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

// Voter-config change kinds (§4.1). force:<lost,...> is the forced
// reconfiguration of §4.6, decided by the survivors' unanimous signatures
// rather than by a majority of the generation it replaces.
const (
	VoterChangeGenesis  = "genesis"
	VoterChangeReset    = "reset"
	voterChangeAddPfx   = "add:"
	voterChangeRmPfx    = "rm:"
	voterChangeForcePfx = "force:"
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

// LUNAllocation is the value a LUN claim decides: which disk of which VM the
// LUN's Generation-th allocation is, made by which create on which host.
type LUNAllocation struct {
	LUN        string `json:"lun"`        // storage.FixedDevice key
	Generation int64  `json:"generation"` // the key's OwnerEpoch
	ClaimID    string `json:"claim_id"`   // the create that proposed it, unique
	VMID       string `json:"vm_id"`      // the VM's uuid (one incarnation)
	VMName     string `json:"vm_name"`
	Disk       string `json:"disk"`
	Host       string `json:"host"` // the host running the create
	// RunHost is set on a MOVED allocation — a rebuild or recreate deciding
	// its VM's next allocation before the teardown — when the re-created VM
	// runs on another host than Host: Host holds the claim until that VM's
	// rows reach it, RunHost runs the VM. The allocation is gone only once
	// both show nothing (or are recorded removed).
	RunHost string `json:"run_host,omitempty"`
	// Kept is set on a moved allocation whose disk keeps the LUN's contents
	// across the re-create: the LUN is that VM's own disk, as it was. A
	// create of the same VM name and disk that decides the allocation right
	// after it takes the LUN over as it is (the recovery of a re-create torn
	// down and failed), where any other create meets a LUN holding data.
	Kept bool `json:"kept,omitempty"`
	// Project and ReplacedCreatedAt bind a Kept allocation: only a create in
	// that (canonical) project takes the LUN over, and only while no plain
	// delete of the VM's incarnation ReplacedCreatedAt, or of a later one, is
	// recorded on the LUN (GetLUNPlainDelete). Set only with Kept.
	Project           string `json:"project,omitempty"`
	ReplacedCreatedAt string `json:"replaced_created_at,omitempty"`
}

// LeaseTermValue is the value a lease_term claim decides: which node holds
// term Term of the lease Key.
type LeaseTermValue struct {
	Key    string `json:"key"`
	Term   int64  `json:"term"`
	Holder string `json:"holder"`
}

// ClaimValue is what a claim decides. Exactly one of Proof (a workload
// recovery, §3.4), Config (a voter-config change, §4.3), LUN (an iSCSI LUN
// allocation) and LeaseTerm (a leader-lease term's holder) is set.
type ClaimValue struct {
	// Proof carries the ActionProof binding fields (ProofBindingEqual's set
	// plus the proof ID). The lease-holder and quorum fields are not part of
	// the decision and are not digested.
	Proof *ActionProof `json:"proof,omitempty"`
	// SourceHost is the recorded owner being left, the host every voter
	// probes before it accepts a workload value (§3.5.1). Digested, so a
	// certificate names the source its voters could not reach.
	SourceHost string                `json:"source_host,omitempty"`
	Config     *VoterConfigValue     `json:"config,omitempty"`
	LUN        *LUNAllocation        `json:"lun,omitempty"`
	Automation *AutomationClaimValue `json:"automation,omitempty"`
	LeaseTerm  *LeaseTermValue       `json:"lease_term,omitempty"`
}

const (
	claimValueDomain       = "litevirt-recovery-value-v1"
	claimConfigValueDomain = "litevirt-voter-config-value-v1"
	claimLUNValueDomain    = "litevirt-lun-allocation-v1"
	claimLeaseValueDomain  = "litevirt-lease-term-v1"
	claimAcceptDomain      = "litevirt-recovery-accept-v1"
	// claimAcceptDomainV2 signs an accept at an incarnation-scoped key. Its
	// own domain, so no v2 accept is ever the same bytes as a v1 one: a legacy
	// signature cannot be read as one for some incarnation, nor the reverse.
	claimAcceptDomainV2 = "litevirt-recovery-accept-v2"
	voterMembersDomain  = "litevirt-voter-members-v1"
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
	case v.Automation != nil:
		if _, err := automationDecision(v); err != nil {
			return "", err
		}
		claimField(h, "litevirt-automation-decision-v1")
		claimField(h, string(v.Automation.Envelope))
	case v.LeaseTerm != nil && v.Automation == nil && v.Proof == nil && v.Config == nil && v.LUN == nil && v.SourceHost == "":
		l := v.LeaseTerm
		claimField(h, claimLeaseValueDomain)
		claimField(h, l.Key)
		claimField(h, i64(l.Term))
		claimField(h, l.Holder)
	case v.LeaseTerm != nil:
		return "", fmt.Errorf("a lease-term claim value carries nothing but the lease term")
	case v.Proof != nil && v.Config == nil && v.LUN == nil:
		p := v.Proof
		claimField(h, claimValueDomain)
		for _, f := range []string{
			p.ID, p.Action, p.TargetKind, p.TargetName, p.DestHost, p.Coordinator,
			p.RelocationToken, p.FenceEpoch, p.OwnerEpoch, i64(p.LeaseTerm), p.LeaseKey,
			v.SourceHost,
		} {
			claimField(h, f)
		}
	case v.LUN != nil && v.Proof == nil && v.Config == nil && v.SourceHost == "":
		l := v.LUN
		claimField(h, claimLUNValueDomain)
		for _, f := range []string{l.LUN, i64(l.Generation), l.ClaimID, l.VMID, l.VMName, l.Disk, l.Host} {
			claimField(h, f)
		}
		if l.RunHost != "" {
			// Only a moved allocation has it, so every other value digests
			// as it always did.
			claimField(h, l.RunHost)
		}
		if l.Kept || l.Project != "" || l.ReplacedCreatedAt != "" {
			// Only a kept moved allocation has these, so every other value
			// digests as it always did. One block of four fields: with or
			// without RunHost (one field), the four field counts differ, so no
			// spelling of one digests as another.
			kept := "0"
			if l.Kept {
				kept = "1"
			}
			claimField(h, "kept-v1")
			claimField(h, kept)
			claimField(h, l.Project)
			claimField(h, l.ReplacedCreatedAt)
		}
	case v.Config != nil && v.Proof == nil && v.LUN == nil && v.SourceHost == "":
		cfg := v.Config
		claimField(h, claimConfigValueDomain)
		claimField(h, i64(cfg.Generation))
		claimField(h, MembersHash(cfg.Members))
		claimField(h, cfg.Change)
		claimField(h, cfg.CreatedBy)
		claimField(h, cfg.CreatedAt)
	default:
		return "", fmt.Errorf("a claim value carries exactly one of a proof, a voter config, a LUN allocation or a lease term")
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
	if key.Incarnation == "" {
		claimField(h, claimAcceptDomain)
		claimField(h, key.TargetKind)
		claimField(h, key.TargetName)
	} else {
		claimField(h, claimAcceptDomainV2)
		claimField(h, key.TargetKind)
		claimField(h, key.TargetName)
		claimField(h, key.Incarnation)
	}
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
	serial  string // lower-case hex, of the certificate in certPEM
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
	return &ClaimSigner{name: hostName, certPEM: string(certPEM),
		serial: strings.ToLower(cert.SerialNumber.Text(16)), key: priv}, nil
}

// ClaimSignerFromKeyPair builds the signer from the host identity this process
// is SERVING (pki.ServedHostKeyPair), for a signer that has to follow a renewal.
//
// The pair comes from the TLS identity source rather than two file reads
// because it is already known to match: certificate and key are separate files,
// and reading them one after the other mid-renewal can pair the new certificate
// with the old key — a signer whose every accept fails verification.
func ClaimSignerFromKeyPair(hostName string, pair *tls.Certificate) (*ClaimSigner, error) {
	if pair == nil || pair.Leaf == nil || len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("no host certificate loaded")
	}
	if pair.Leaf.Subject.CommonName != hostName {
		return nil, fmt.Errorf("host certificate CN is %q but this host is %q", pair.Leaf.Subject.CommonName, hostName)
	}
	priv, ok := pair.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("host key is %T, not an ECDSA key", pair.PrivateKey)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	return &ClaimSigner{name: hostName, certPEM: string(certPEM),
		serial: strings.ToLower(pair.Leaf.SerialNumber.Text(16)), key: priv}, nil
}

// Serial is the serial of the certificate this signer's accepts carry, as
// lower-case hex.
func (s *ClaimSigner) Serial() string {
	if s == nil {
		return ""
	}
	return s.serial
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
	sourceTrust               *pki.HostTrust
	ordinary                  *pki.OrdinaryClaimTrust
	policyCell                *atomic.Bool
	policyPinned, policyNoPin bool
	roots                     *x509.CertPool
	pkiDir                    string
	// historical is set on the copy Historical returns: a certificate
	// revoked since still counts. Nothing else is relaxed.
	historical bool
	// extraRevoked are serials (lower-case hex) treated as revoked in addition
	// to the installed CRL — the "what if" WithRevoked asks.
	extraRevoked map[string]bool
	// pinned (WithSerialPin): an accept signed with a certificate the CA has
	// replaced (pki.SupersededBy) does not count.
	pinned bool
	noPin  bool
	// renewalBlind (RenewalBlind): an accept signed with a certificate the CA
	// has replaced counts, revoked or not. Diagnosis only.
	renewalBlind bool
}

// WithHostTrustPolicy binds the server's actual effective policy cell. Proof
// preparation resamples it only while holding that directory's owner lease.
func (v *ClaimVerifier) WithHostTrustPolicy(cell *atomic.Bool) *ClaimVerifier {
	if v == nil {
		return nil
	}
	h := *v
	h.policyCell = cell
	if v.policyCell == nil {
		h.policyPinned, h.policyNoPin = v.pinned, v.noPin
	}
	// Rebinding must preserve the logical options, not a previously relaxed
	// effective value that would survive a later policy toggle back.
	h.pinned, h.noPin = h.policyPinned, h.policyNoPin
	if cell != nil && cell.Load() {
		h.pinned, h.noPin = false, true
	}
	return &h
}
func (v *ClaimVerifier) superseded(c *x509.Certificate) error {
	if v.ordinary != nil {
		return v.ordinary.Superseded(c)
	}
	return pki.SupersededError(v.pkiDir, c)
}

// WithRevoked returns a copy of v that also treats serials as revoked: the
// question "would this still verify if these were revoked?" asked before a
// revocation is published (a renewed voter's replaced certificate).
func (v *ClaimVerifier) WithRevoked(serials ...string) *ClaimVerifier {
	if v == nil {
		return nil
	}
	h := *v
	h.extraRevoked = map[string]bool{}
	for k := range v.extraRevoked {
		h.extraRevoked[k] = true
	}
	for _, s := range serials {
		h.extraRevoked[strings.ToLower(s)] = true
	}
	return &h
}

// WithSerialPin returns a copy of v that also refuses an accept signed with a
// certificate the CA has REPLACED: one this node holds a standing CA-issued
// successor of (pki.SupersededBy — the renewal extension, collected from
// handshakes, from accepts and from this node's own identity, and kept
// node-locally). Its authority is the CA's signature on the successor and
// nothing else: no replicated row, which any peer can write, can relax it.
//
// Without it, §3.10 step 5 asks only for a CA-issued, unrevoked certificate
// naming the voter, so the key of a certificate a renewal replaced — revocation
// of which may be held (§4.1) or skipped with --keep-old — could still sign
// accepts. A certificate this node holds no successor of is not refused by
// the pin; revocation (the CRL) is what ends it. Historical verification is
// never pinned: history was signed by whatever a voter held then.
func (v *ClaimVerifier) WithSerialPin() *ClaimVerifier {
	if v == nil {
		return nil
	}
	h := *v
	h.pinned, h.noPin = true, false
	h.policyPinned, h.policyNoPin = true, false
	return &h
}

// Pinned reports whether v refuses accepts signed with replaced certificates.
func (v *ClaimVerifier) Pinned() bool { return v != nil && v.pinned }

// WithoutSerialPin returns a copy of v that VerifyClaimCertificate does not
// pin: the auth.trust_rotated_peer_certs recovery mode, for a fleet whose
// recorded serials went stale and which peer trust already relaxes.
func (v *ClaimVerifier) WithoutSerialPin() *ClaimVerifier {
	if v == nil {
		return nil
	}
	h := *v
	h.pinned, h.noPin = false, true
	h.policyPinned, h.policyNoPin = false, true
	return &h
}

// RenewalBlind returns a copy of v that COUNTS an accept signed with a
// certificate the CA has replaced (a standing successor this node holds,
// pki.SupersededBy) — not pinned, and its revocation disregarded, since `lv
// host renew-cert` revokes the replaced certificate BECAUSE it was renewed.
// Everything else is checked as v does.
//
// It answers one question and must never decide anything: "does this
// certificate fail ONLY because one of its signers renewed since?" A
// generation that passes RenewalBlind but not v is one this node is stuck
// below by a renewal (voter_generation_stuck), and the signers whose accepts
// it cannot count are the ones asked to re-attest them.
func (v *ClaimVerifier) RenewalBlind() *ClaimVerifier {
	if v == nil {
		return nil
	}
	h := *v
	h.pinned, h.noPin, h.renewalBlind = false, true, true
	h.policyPinned, h.policyNoPin = false, true
	return &h
}

// SupersededAccepts lists the voters whose accepts in cert are signed with a
// certificate the CA has replaced, as far as this node knows (a standing
// successor it holds). They are the accepts a renewal took out of the count.
func (v *ClaimVerifier) SupersededAccepts(cert ClaimCertificate) []string {
	if v == nil {
		return nil
	}
	for _, a := range cert.Accepts {
		v.noteSuccessors(a.CertPEM)
	}
	var out []string
	seen := map[string]bool{}
	for _, a := range cert.Accepts {
		c, err := parseCertPEM([]byte(a.CertPEM))
		if err != nil || seen[a.Voter] {
			continue
		}
		if pki.SupersededError(v.pkiDir, c) != nil {
			seen[a.Voter] = true
			out = append(out, a.Voter)
		}
	}
	sort.Strings(out)
	return out
}

// SerialPinDisabled reports whether WithoutSerialPin made v.
func (v *ClaimVerifier) SerialPinDisabled() bool { return v != nil && v.noPin }

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

// Historical returns a verifier for a voter generation that a later
// generation, verified against today's CRL, already vouches for
// (docs/design/recovery-claims.md §4.1 "History and revocation"). It checks
// every signature exactly as v does — CA chain, name, incarnation, payload —
// except that a certificate revoked SINCE still counts: revocation is the end
// of a voter's life, not evidence against what it signed while it voted.
//
// Never use it for anything new: a workload certificate, a generation being
// decided, or the generation the history is judged from. Those are v's.
func (v *ClaimVerifier) Historical() *ClaimVerifier {
	if v == nil {
		return nil
	}
	h := *v
	h.historical = true
	return &h
}

// revoked reports whether c's certificate counts as revoked for this verifier.
func (v *ClaimVerifier) revoked(c *x509.Certificate) bool {
	if v.historical {
		return false
	}
	if v.renewalBlind && v.superseded(c) != nil {
		return false
	}
	if v.extraRevoked[strings.ToLower(c.SerialNumber.Text(16))] {
		return true
	}
	if v.ordinary != nil {
		return v.ordinary.Revoked(c)
	}
	return pki.IsCertRevoked(v.pkiDir, c.SerialNumber)
}

// pinRefuses reports why c may not sign as voter under v's serial pin, or nil.
func (v *ClaimVerifier) pinRefuses(c *x509.Certificate, voter string) error {
	if v.historical || !v.pinned {
		return nil
	}
	if err := v.superseded(c); err != nil {
		return fmt.Errorf("signed as %s with a replaced certificate: %w", voter, err)
	}
	return nil
}

// noteSuccessors collects, from every certificate an accept carries, the CA's
// proof that some other certificate was replaced (pki.NoteSuccessor). It runs
// before any accept is judged, so a renewed voter's own accept in a row proves
// its predecessor replaced for the rest of that row as well.
func (v *ClaimVerifier) noteSuccessors(certPEMs ...string) {
	if v.ordinary != nil || v.sourceTrust != nil {
		return
	}
	for _, p := range certPEMs {
		if c, err := parseCertPEM([]byte(p)); err == nil {
			pki.NoteSuccessor(v.pkiDir, c)
		}
	}
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
		v.noteSuccessors(a.CertPEM)
	}
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
	if v.ordinary != nil && !v.ordinary.Contains(c) {
		return fmt.Errorf("unprepared accept certificate")
	}
	if v.sourceTrust != nil {
		if v.renewalBlind {
			return fmt.Errorf("diagnostic renewal mode is not source authority")
		}
		if _, _, err := v.sourceTrust.VerifyOrdinaryCertificate(c.Raw, v.historical, v.pinned); err != nil {
			return err
		}
		if !v.historical && v.extraRevoked[strings.ToLower(c.SerialNumber.Text(16))] {
			return fmt.Errorf("certificate is revoked")
		}
	} else {
		if _, err := c.Verify(x509.VerifyOptions{Roots: v.roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			return fmt.Errorf("certificate does not chain to the cluster CA: %w", err)
		}
		if c.Subject.CommonName != a.Voter {
			return fmt.Errorf("signed with %q's certificate", c.Subject.CommonName)
		}
		if v.revoked(c) {
			return fmt.Errorf("certificate %s is revoked", c.SerialNumber.Text(16))
		}
		if err := v.pinRefuses(c, a.Voter); err != nil {
			return err
		}
	}
	if c.Subject.CommonName != a.Voter {
		return fmt.Errorf("signed with %q's certificate", c.Subject.CommonName)
	}
	// The Common Name alone does not make a host: a voter an older build
	// admitted as "lv-cli" would otherwise take the distributable client
	// certificate's signature as its own. Every host certificate names
	// ServerAuth (pki.IsClientOnlyCert).
	if pki.IsClientOnlyCert(c) {
		return fmt.Errorf("signed with a client certificate, not a host's")
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
