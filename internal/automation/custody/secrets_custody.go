package custody

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"sync"
	"time"
	"unicode/utf8"

	"filippo.io/age"
)

// CustodyScope contains supplied established host facts, not authentication or a
// newly allocated host incarnation. It is distinct from VM and voter counters.
type CustodyScope struct {
	ClusterUID, HostID string
	HostIncarnation    uint64
	AdmittedAt         string
}

// CustodyKeyRef identifies the original key context. Current activation and
// successor membership remain separate certified protocol facts.
type CustodyKeyRef struct {
	Epoch, KeyID string
	Generation   uint64
	ConfigDigest string
}
type custodyIO struct{ syncFile, syncDir func(*os.File) error }

// LocalCustody owns local immutable files only. Success is not a quorum custody
// receipt, enrollment, epoch activation or execution authorization.
type LocalCustody struct {
	mu           sync.Mutex
	root, parent *os.File
	path, name   string
	scope        CustodyScope
	ops          custodyIO
	closed       bool
}

// LocalVoterKey keeps the live private identity inside the custody package.
// There is deliberately no private serialization or generic export method.
type LocalVoterKey struct{ identity *age.X25519Identity }

func (key *LocalVoterKey) Recipient() string { return key.identity.Recipient().String() }
func (key *LocalVoterKey) String() string    { return "local voter custody" }
func (key *LocalVoterKey) GoString() string  { return key.String() }

var (
	ErrCustodyUnavailable      = errors.New("automation custody unavailable")
	ErrCustodyCorrupt          = errors.New("automation custody corrupt")
	ErrCustodyConflict         = errors.New("automation custody conflict")
	ErrCustodyRecoveryRequired = errors.New("automation custody recovery required")
)

const custodyRecordMax = 64 << 10
const custodyVoterPurpose = "voter-identity"
const custodyEqualityPurpose = "equality"

type custodyRecord struct {
	Version  uint32
	Purpose  string
	Scope    CustodyScope
	Ref      CustodyKeyRef
	Material []byte
}

func (scope CustodyScope) valid() bool {
	if !secretStringValid(scope.ClusterUID) || !secretStringValid(scope.HostID) || scope.HostIncarnation > math.MaxInt64 || !secretStringValid(scope.AdmittedAt) || !utf8.ValidString(scope.AdmittedAt) {
		return false
	}
	// Parsing validates the supplied spelling; the original bytes remain the
	// identity. Do not normalize it or compare its ordering to another lifetime.
	_, err := time.Parse(time.RFC3339Nano, scope.AdmittedAt)
	return err == nil
}
func (ref CustodyKeyRef) valid() bool {
	return secretStringValid(ref.Epoch) && secretStringValid(ref.KeyID) && secretStringValid(ref.ConfigDigest) && ref.Generation > 0
}
func (s *LocalCustody) record(purpose string, ref CustodyKeyRef, material []byte) custodyRecord {
	return custodyRecord{2, purpose, s.scope, ref, material}
}
func custodyEncode(r custodyRecord) ([]byte, error) {
	b, err := json.Marshal(r)
	if err != nil || len(b) > custodyRecordMax {
		return nil, ErrCustodyCorrupt
	}
	return b, nil
}
func custodyDecode(b []byte) (custodyRecord, error) {
	var r custodyRecord
	if len(b) > custodyRecordMax {
		return r, ErrCustodyCorrupt
	}
	var header struct{ Version uint32 }
	if json.Unmarshal(b, &header) != nil {
		return r, ErrCustodyCorrupt
	}
	if header.Version == 1 {
		return r, refuseLegacyCustody(b)
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil || r.Version != 2 || !r.Scope.valid() {
		return custodyRecord{}, ErrCustodyCorrupt
	}
	canonical, err := custodyEncode(r)
	if err != nil || !bytes.Equal(canonical, b) {
		return custodyRecord{}, ErrCustodyCorrupt
	}
	return r, nil
}
func custodyName(record custodyRecord) (string, error) {
	// Only nonsecret purpose/scope/reference metadata enters this path digest.
	record.Material = nil
	encoded, err := custodyEncode(record)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("litevirt/automation/local-custody-path/v2\x00"), encoded...))
	return "key-" + hex.EncodeToString(digest[:]), nil
}

// This frozen original shape is decoded only to refuse old artifacts. It never
// gains an AdmittedAt, returns private material or enters a current key lookup.
func refuseLegacyCustody(body []byte) error {
	var old struct {
		Version uint32
		Purpose string
		Scope   struct {
			ClusterUID, HostID string
			HostIncarnation    uint64
		}
		Ref      CustodyKeyRef
		Material []byte
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if dec.Decode(&old) != nil || old.Version != 1 || !secretStringValid(old.Scope.ClusterUID) || !secretStringValid(old.Scope.HostID) || old.Scope.HostIncarnation == 0 {
		return ErrCustodyCorrupt
	}
	canonical, err := json.Marshal(old)
	if err != nil || !bytes.Equal(canonical, body) {
		return ErrCustodyCorrupt
	}
	switch old.Purpose {
	case "scope":
		if old.Ref != (CustodyKeyRef{}) || old.Material != nil {
			return ErrCustodyCorrupt
		}
	case custodyEqualityPurpose:
		if !old.Ref.valid() || len(old.Material) != 32 {
			return ErrCustodyCorrupt
		}
	case custodyVoterPurpose:
		identity, err := age.ParseX25519Identity(string(old.Material))
		if !old.Ref.valid() || err != nil || identity.String() != string(old.Material) {
			return ErrCustodyCorrupt
		}
	default:
		return ErrCustodyCorrupt
	}
	return ErrCustodyRecoveryRequired
}

// CreateLocalCustody reserves a new root. An existing or incomplete root is
// never treated as fresh custody; recovery must explicitly open or replace it.
func CreateLocalCustody(path string, scope CustodyScope) (*LocalCustody, error) {
	return createLocalCustody(path, scope, custodyIO{})
}
func createLocalCustody(path string, scope CustodyScope, ops custodyIO) (*LocalCustody, error) {
	return openCustody(path, scope, ops, true)
}

// OpenLocalCustody never creates a missing root or missing key material.
func OpenLocalCustody(path string, scope CustodyScope) (*LocalCustody, error) {
	return openCustody(path, scope, custodyIO{}, false)
}
func (s *LocalCustody) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	e1, e2 := s.root.Close(), s.parent.Close()
	if e1 != nil || e2 != nil {
		return ErrCustodyUnavailable
	}
	return nil
}

// CreateVoterIdentity generates a fresh native identity only after an exclusive
// new key-directory reservation. Restart recovery uses OpenVoterIdentity instead.
func (s *LocalCustody) CreateVoterIdentity(ref CustodyKeyRef) (*LocalVoterKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, name, err := s.reserve(custodyVoterPurpose, ref)
	if errors.Is(err, ErrCustodyConflict) {
		if _, existingErr := s.load(custodyVoterPurpose, ref); existingErr != nil {
			err = existingErr
		}
	}
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, ErrCustodyUnavailable
	}
	record := s.record(custodyVoterPurpose, ref, []byte(identity.String()))
	if err = s.install(dir, name, record); err != nil {
		return nil, err
	}
	return &LocalVoterKey{identity: identity}, nil
}

// OpenVoterIdentity requires the original expected public recipient. It neither
// regenerates missing keys nor certifies that this recipient is enrolled.
func (s *LocalCustody) OpenVoterIdentity(ref CustodyKeyRef, expectedRecipient string) (*LocalVoterKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	expected, err := age.ParseX25519Recipient(expectedRecipient)
	if err != nil {
		return nil, ErrCustodyCorrupt
	}
	r, err := s.load(custodyVoterPurpose, ref)
	if err != nil {
		return nil, err
	}
	identity, err := age.ParseX25519Identity(string(r.Material))
	if err != nil || identity.String() != string(r.Material) {
		return nil, ErrCustodyCorrupt
	}
	if identity.Recipient().String() != expected.String() {
		return nil, ErrCustodyConflict
	}
	return &LocalVoterKey{identity: identity}, nil
}

// GenerateEqualityKey generates independent random material; no age file key or
// host signing key is reused. The epoch still needs actual protocol provenance.
func (s *LocalCustody) GenerateEqualityKey(ref CustodyKeyRef) (BootstrapEqualityKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	dir, name, err := s.reserve(custodyEqualityPurpose, ref)
	if errors.Is(err, ErrCustodyConflict) {
		if _, existingErr := s.load(custodyEqualityPurpose, ref); existingErr != nil {
			err = existingErr
		}
	}
	if err != nil {
		return BootstrapEqualityKey{}, err
	}
	defer dir.Close()
	material := make([]byte, 32)
	if _, err = rand.Read(material); err != nil {
		return BootstrapEqualityKey{}, ErrCustodyUnavailable
	}
	if err = s.install(dir, name, s.record(custodyEqualityPurpose, ref, material)); err != nil {
		return BootstrapEqualityKey{}, err
	}
	return NewBootstrapEqualityKey(ref.Epoch, material)
}

// ImportEqualityKey is immutable: only an exact existing private-material match
// may succeed on retry, after the same reopen and durability checks.
func (s *LocalCustody) ImportEqualityKey(ref CustodyKeyRef, material []byte) (BootstrapEqualityKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(material) != 32 {
		return BootstrapEqualityKey{}, ErrCustodyCorrupt
	}
	dir, name, err := s.reserve(custodyEqualityPurpose, ref)
	if errors.Is(err, ErrCustodyConflict) {
		old, err := s.load(custodyEqualityPurpose, ref)
		if err != nil {
			return BootstrapEqualityKey{}, err
		}
		if !hmac.Equal(old.Material, material) {
			return BootstrapEqualityKey{}, ErrCustodyConflict
		}
		return NewBootstrapEqualityKey(ref.Epoch, old.Material)
	}
	if err != nil {
		return BootstrapEqualityKey{}, err
	}
	defer dir.Close()
	if err = s.install(dir, name, s.record(custodyEqualityPurpose, ref, material)); err != nil {
		return BootstrapEqualityKey{}, err
	}
	return NewBootstrapEqualityKey(ref.Epoch, material)
}

// OpenEqualityKey selects only the exact historical reference. Local record
// binding and length do not authenticate epoch provenance or material against an
// external certificate; those remain obligations of the actual custody provider.
func (s *LocalCustody) OpenEqualityKey(ref CustodyKeyRef) (BootstrapEqualityKey, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.load(custodyEqualityPurpose, ref)
	if err != nil {
		return BootstrapEqualityKey{}, err
	}
	return NewBootstrapEqualityKey(ref.Epoch, r.Material)
}
