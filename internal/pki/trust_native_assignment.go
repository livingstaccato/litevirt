package pki

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	nativeDestinationName    = ".native-enrollment-destination"
	nativeAssignmentLimit    = (2 << 20) + (16 << 10)
	nativeBindingLimit       = 4096
	nativeAuthorizationLimit = 8192
	nativePEMLimit           = 1 << 20
)

var initialNativeMemberOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61117, 1, 3}

// Internal clock dependency only. Production uses the ordinary wall clock;
// tests date actual native creation/issuance without inventing evidence.
var nativeEnrollmentNow = time.Now

// NativeDestinationConfig names the actual effective destination. Route and
// SSH spelling are not destination identity. Only native preparation applies
// this path grammar; ordinary enrollment keeps its existing compatibility.
type NativeDestinationConfig struct {
	HostName, PKIDir, DataDir, ConfigPath string
}

// NativeFirstMemberMaterial is a disposable view of the durable assignment.
// It carries no root private key and establishes no DB or membership success.
type NativeFirstMemberMaterial struct {
	CA, Certificate, PrivateKey, DestinationBinding, AssignmentRef []byte
}

type nativeDestinationBinding struct {
	Version                 int
	Purpose                 string `asn1:"utf8"`
	Root, ID                []byte
	Host, PKI, Data, Config string `asn1:"utf8"`
}

type nativeDestinationReservation struct {
	Version            int
	Purpose            string `asn1:"utf8"`
	Operation, Binding []byte
}

type nativeMemberAuthorization struct {
	Version                   int
	Purpose                   string `asn1:"utf8"`
	Operation, Root           []byte
	Host                      string `asn1:"utf8"`
	Destination, Serial, SPKI []byte
}

type nativeAssignmentReference struct {
	Version                                          int
	Purpose                                          string `asn1:"utf8"`
	Operation, Root, Destination, Serial, SPKI, Leaf []byte
}

// Only assigned is implemented here. Future spent state must retain this
// complete payload; an unknown purpose/version is never an unassigned fallback.
type nativeAssignedOperation struct {
	Version                                                                                 int
	Purpose                                                                                 string `asn1:"utf8"`
	Original, OriginalHash, Operation, Root                                                 []byte
	Host                                                                                    string `asn1:"utf8"`
	Destination, Serial, SPKI, Certificate, PrivateKey, CertificateHash, KeyHash, Reference []byte
}

func nativeCanonicalDER(body []byte, limit int, value any) error {
	if len(body) == 0 || len(body) > limit {
		return errors.New("native DER exceeds bound")
	}
	rest, err := asn1.Unmarshal(body, value)
	if err != nil || len(rest) != 0 {
		return errors.New("invalid native DER")
	}
	canonical, err := asn1.Marshal(reflect.ValueOf(value).Elem().Interface())
	if err != nil || !bytes.Equal(canonical, body) {
		return errors.New("noncanonical native DER")
	}
	return nil
}

func nativeDigest(body []byte) []byte {
	h := sha256.Sum256(body)
	return h[:]
}

func nativeNonzero32(body []byte) bool {
	return len(body) == 32 && !bytes.Equal(body, make([]byte, 32))
}

func nativeHostValid(host string) bool {
	return len(host) > 0 && len(host) <= 253 && utf8.ValidString(host) && host != "." && host != ".." && !strings.ContainsAny(host, "/\\\r\n\x00")
}

// Resolve the nearest existing parent before appending validated components.
// Cleaning first would change the meaning of a symlink/../suffix input.
func canonicalNativePath(path string) (string, error) {
	if len(path) == 0 || len(path) > 1024 || !utf8.ValidString(path) || !filepath.IsAbs(path) || strings.ContainsAny(path, "\x00\r\n") {
		return "", errors.New("invalid native absolute path")
	}
	for _, part := range strings.Split(path, string(filepath.Separator)) {
		if part == "." || part == ".." {
			return "", errors.New("native path contains dot component")
		}
	}
	path = filepath.Clean(path)
	parent := path
	var suffix []string
	for {
		_, err := os.Lstat(parent)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		suffix = append(suffix, filepath.Base(parent))
		next := filepath.Dir(parent)
		if next == parent {
			return "", errors.New("native path has no existing parent")
		}
		parent = next
	}
	real, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return "", err
	}
	if len(suffix) > 0 {
		info, err := os.Stat(real)
		if err != nil {
			return "", err
		}
		if !info.IsDir() {
			return "", errors.New("native path parent is not a directory")
		}
	}
	for i := len(suffix) - 1; i >= 0; i-- {
		real = filepath.Join(real, suffix[i])
	}
	if len(real) > 1024 || !utf8.ValidString(real) || strings.ContainsAny(real, "\x00\r\n") {
		return "", errors.New("invalid canonical native path")
	}
	return real, nil
}

func canonicalNativeConfig(cfg NativeDestinationConfig) (NativeDestinationConfig, error) {
	if !nativeHostValid(cfg.HostName) {
		return cfg, errors.New("invalid native host name")
	}
	var err error
	if cfg.PKIDir, err = canonicalNativePath(cfg.PKIDir); err != nil {
		return cfg, err
	}
	if cfg.DataDir, err = canonicalNativePath(cfg.DataDir); err != nil {
		return cfg, err
	}
	if cfg.ConfigPath, err = canonicalNativePath(cfg.ConfigPath); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func decodeNativeBinding(body []byte) (*nativeDestinationBinding, error) {
	var b nativeDestinationBinding
	if err := nativeCanonicalDER(body, nativeBindingLimit, &b); err != nil {
		return nil, err
	}
	if b.Version != 1 || b.Purpose != "litevirt/native-enrollment-destination" || len(b.Root) != 32 || !nativeNonzero32(b.ID) || !nativeHostValid(b.Host) {
		return nil, errors.New("invalid native destination binding")
	}
	// These are already canonical destination paths. Do not resolve them on the
	// operator machine: its filesystem is not the destination filesystem.
	for _, path := range []string{b.PKI, b.Data, b.Config} {
		if len(path) == 0 || len(path) > 1024 || !utf8.ValidString(path) || !filepath.IsAbs(path) || filepath.Clean(path) != path || strings.ContainsAny(path, "\x00\r\n") {
			return nil, errors.New("invalid bound destination path")
		}
	}
	return &b, nil
}

func decodeNativeReservation(body []byte) (*nativeDestinationReservation, *nativeDestinationBinding, error) {
	var r nativeDestinationReservation
	if err := nativeCanonicalDER(body, nativeAuthorizationLimit, &r); err != nil {
		return nil, nil, err
	}
	if r.Version != 1 || r.Purpose != "litevirt/native-enrollment-reservation" || !nativeNonzero32(r.Operation) {
		return nil, nil, errors.New("invalid native destination reservation")
	}
	b, err := decodeNativeBinding(r.Binding)
	return &r, b, err
}

func nativeRootPEM(body []byte) (*x509.Certificate, error) {
	if len(body) == 0 || len(body) > nativePEMLimit {
		return nil, errors.New("native root exceeds bound")
	}
	roots, err := strictCertificateBundle(body, 1)
	if err != nil {
		return nil, err
	}
	root := roots[0]
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		return nil, errors.New("native root is not self-signed")
	}
	return root, nil
}

// NativeOperatorCAOperation reads public preparation metadata through the
// existing owner and full retained-state reader. An ordinary legacy CA has no
// native operation and cannot obtain one through this API.
func NativeOperatorCAOperation(ctx context.Context, dir string) ([]byte, []byte, error) {
	o, err := trustOwnerFor(dir)
	if err != nil {
		return nil, nil, err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer lock.release()
	n, err := o.readNativeOperatorCALocked()
	if err != nil {
		return nil, nil, err
	}
	if n == nil {
		return nil, nil, errors.New("operator has no native creation operation")
	}
	if pending, err := o.nativeOperatorCAPendingLocked(n); err != nil || pending {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, errors.New("native root publication is incomplete")
	}
	return bytes.Clone(n.original), bytes.Clone(n.cert), nil
}

// Preparation requires the actual caller-held exclusive lifetime admission.
// It is inert reservation, not signed permission or a DB constructor. Callers
// release this lease before invoking AssignNativeFirstMember on a local root.
func PrepareNativeEnrollmentDestination(ctx context.Context, cfg NativeDestinationConfig, ca, operation []byte, admission *HostDomainLease) ([]byte, error) {
	root, err := nativeRootPEM(ca)
	if err != nil {
		return nil, err
	}
	return nativeEnrollmentDestination(ctx, cfg, sha256.Sum256(root.Raw), operation, nil, admission, true)
}

// Assigned retry/apply must use this arm. Missing evidence cannot be repaired
// from a signed request or copied destination identifier.
func RequireNativeEnrollmentDestination(ctx context.Context, cfg NativeDestinationConfig, ca, operation, expected []byte, admission *HostDomainLease) error {
	if len(expected) == 0 {
		return errors.New("expected destination reservation required")
	}
	root, err := nativeRootPEM(ca)
	if err != nil {
		return err
	}
	_, err = nativeEnrollmentDestination(ctx, cfg, sha256.Sum256(root.Raw), operation, expected, admission, false)
	return err
}

// PrepareNativeEnrollmentDestinationDigest accepts the root correlation carried
// by native preparation. It reserves only the same inert destination tuple;
// assignment still requires the actual operator's retained root and private key.
func PrepareNativeEnrollmentDestinationDigest(ctx context.Context, cfg NativeDestinationConfig, rootDigest [sha256.Size]byte, operation []byte, admission *HostDomainLease) ([]byte, error) {
	return nativeEnrollmentDestination(ctx, cfg, rootDigest, operation, nil, admission, true)
}

// RequireNativeEnrollmentDestinationDigest never creates a missing reservation.
// The supplied digest and expected bytes are correlations, not use authority.
func RequireNativeEnrollmentDestinationDigest(ctx context.Context, cfg NativeDestinationConfig, rootDigest [sha256.Size]byte, operation, expected []byte, admission *HostDomainLease) error {
	if len(expected) == 0 {
		return errors.New("expected destination reservation required")
	}
	_, err := nativeEnrollmentDestination(ctx, cfg, rootDigest, operation, expected, admission, false)
	return err
}

func nativeEnrollmentDestination(ctx context.Context, cfg NativeDestinationConfig, rootDigest [sha256.Size]byte, operation, expected []byte, admission *HostDomainLease, create bool) ([]byte, error) {
	if rootDigest == [sha256.Size]byte{} {
		return nil, errors.New("invalid native root digest")
	}
	if admission == nil {
		return nil, errors.New("exclusive host domain admission required")
	}
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if err := admission.checkLocked(cfg.PKIDir); err != nil {
		return nil, err
	}
	canonical, err := canonicalNativeConfig(cfg)
	if err != nil {
		return nil, err
	}
	if !nativeNonzero32(operation) {
		return nil, errors.New("invalid native operation ID")
	}
	o, err := trustOwnerFor(canonical.PKIDir)
	if err != nil {
		return nil, err
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	if err := admission.checkLocked(cfg.PKIDir); err != nil {
		return nil, err
	}
	if rechecked, err := canonicalNativeConfig(cfg); err != nil || rechecked != canonical {
		return nil, errors.New("native destination paths changed")
	}
	if create {
		if err := o.nativeReservationEligibleLocked(canonical, rootDigest, operation); err != nil {
			return nil, err
		}
	}
	if !create {
		if n, err := o.readNativeOperatorCALocked(); err != nil {
			return nil, err
		} else if n != nil {
			if !bytes.Equal(n.original[8:40], operation) {
				return nil, errors.New("destination operator operation differs")
			}
			if pending, err := o.nativeOperatorCAPendingLocked(n); err != nil || pending {
				return nil, errors.New("destination operator root is incomplete")
			}
		}
		active, err := readNativeCAFile(filepath.Join(o.dir, "ca.crt"), nativePEMLimit)
		if err == nil {
			actual, err := nativeRootPEM(active)
			if err != nil || sha256.Sum256(actual.Raw) != rootDigest {
				return nil, errors.New("destination active root differs")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	path := filepath.Join(o.dir, nativeDestinationName)
	body, err := readNativeCAFile(path, nativeAuthorizationLimit)
	if errors.Is(err, os.ErrNotExist) {
		if !create || o.nativeReservationDigest != [32]byte{} {
			return nil, errors.New("native destination reservation is missing")
		}
		// Create directories only after eligibility, then resolve every actual
		// locator again before publishing the reservation.
		for _, dir := range []string{canonical.DataDir, filepath.Dir(canonical.ConfigPath)} {
			if err := os.MkdirAll(dir, 0700); err != nil {
				return nil, err
			}
		}
		if rechecked, err := canonicalNativeConfig(cfg); err != nil || rechecked != canonical {
			return nil, errors.New("native destination paths changed after creation")
		}
		id := make([]byte, 32)
		for !nativeNonzero32(id) {
			if _, err := rand.Read(id); err != nil {
				return nil, err
			}
		}
		binding, err := asn1.Marshal(nativeDestinationBinding{1, "litevirt/native-enrollment-destination", rootDigest[:], id, canonical.HostName, canonical.PKIDir, canonical.DataDir, canonical.ConfigPath})
		if err != nil {
			return nil, err
		}
		body, err = asn1.Marshal(nativeDestinationReservation{1, "litevirt/native-enrollment-reservation", bytes.Clone(operation), binding})
		if err != nil {
			return nil, err
		}
		if _, _, err := decodeNativeReservation(body); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := writeTrustFile(path, body, 0600); err != nil {
			return nil, err
		}
		if err := trustDurabilityPoint("native-destination:committed"); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	r, b, err := decodeNativeReservation(body)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.Operation, operation) || !bytes.Equal(b.Root, rootDigest[:]) || b.Host != canonical.HostName || b.PKI != canonical.PKIDir || b.Data != canonical.DataDir || b.Config != canonical.ConfigPath {
		return nil, errors.New("native destination reservation conflicts with effective context")
	}
	if !create && !bytes.Equal(body, expected) {
		return nil, errors.New("native destination reservation differs from assignment")
	}
	if o.nativeReservationDigest != [32]byte{} && o.nativeReservationDigest != sha256.Sum256(body) {
		return nil, errors.New("native destination reservation changed")
	}
	if err := durableTrustReopen(path, body); err != nil {
		return nil, err
	}
	o.nativeReservationDigest = sha256.Sum256(body)
	return bytes.Clone(body), nil
}

func (o *trustOwner) nativeReservationEligibleLocked(cfg NativeDestinationConfig, rootDigest [sha256.Size]byte, operation []byte) error {
	if len(o.root) != 0 || o.servedFingerprint != [32]byte{} || o.retired {
		return errors.New("established destination cannot create native reservation")
	}
	n, err := o.readNativeOperatorCALocked()
	if err != nil {
		return err
	}
	if n != nil {
		if n.assignment != nil || !bytes.Equal(n.original[8:40], operation) {
			return errors.New("operator operation is already assigned or different")
		}
		stagedRoot, err := nativeRootPEM(n.cert)
		if err != nil || sha256.Sum256(stagedRoot.Raw) != rootDigest {
			return errors.New("destination root differs from operator operation")
		}
		if pending, err := o.nativeOperatorCAPendingLocked(n); err != nil || pending {
			return errors.New("destination operator root publication incomplete")
		}
	} else {
		for _, name := range []string{"ca.crt", "ca.key"} {
			if _, err := os.Lstat(filepath.Join(o.dir, name)); !errors.Is(err, os.ErrNotExist) {
				return errors.New("ordinary existing root is not native reservation eligibility")
			}
		}
	}
	for _, name := range []string{"host.crt", "host.key", hostDirName, ".native-first-member-pending", ".native-first-member-spent", "crl.pem", supersededFile, GossipKeyName, GossipKeyringStateName, "audit-rejoin.json", AuditSigningCertName, AuditSigningKeyName, MigrationDirName} {
		if _, err := os.Lstat(filepath.Join(o.dir, name)); !errors.Is(err, os.ErrNotExist) {
			return errors.New("destination has existing native or identity evidence")
		}
	}
	if _, err := os.Lstat(cfg.ConfigPath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("destination has existing configuration")
	}
	entries, err := os.ReadDir(cfg.DataDir)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if len(entries) != 0 {
		return errors.New("destination has existing data")
	}
	return nil
}

// AssignNativeFirstMember consumes only the actual owner-created A operation.
// It owns lifetime EX before the owner lock, commits once, and returns bytes
// only after durable reopen. No temporary identity or caller flag is authority.
func AssignNativeFirstMember(ctx context.Context, dir string, reservation []byte, advertise net.IP) (*NativeFirstMemberMaterial, error) {
	r, b, err := decodeNativeReservation(reservation)
	if err != nil {
		return nil, err
	}
	if advertise != nil && advertise.To4() == nil {
		return nil, errors.New("native advertise address requires IPv4")
	}
	admission, err := AcquireHostReinitialization(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer admission.Release()
	admission.mu.Lock()
	defer admission.mu.Unlock()
	if err := admission.checkLocked(dir); err != nil {
		return nil, err
	}
	// Resolve the owner from the canonical directory actually excluded by this
	// lease, never from a second resolution of the caller's mutable locator.
	o, err := trustOwnerFor(admission.dir)
	if err != nil {
		return nil, err
	}
	checkAdmission := func() error {
		if o.dir != admission.dir {
			return errors.New("native assignment owner differs from lifetime admission")
		}
		if err := admission.checkLocked(o.dir); err != nil {
			return err
		}
		return admission.checkLocked(dir)
	}
	lock, err := o.lock(ctx)
	if err != nil {
		return nil, err
	}
	defer lock.release()
	if err := checkAdmission(); err != nil {
		return nil, err
	}
	n, err := o.readNativeOperatorCALocked()
	if err != nil {
		return nil, err
	}
	if n == nil {
		return nil, errors.New("owner-created native CA operation required")
	}
	if pending, err := o.nativeOperatorCAPendingLocked(n); err != nil || pending {
		if err != nil {
			return nil, err
		}
		return nil, errors.New("native root publication incomplete")
	}
	root, err := nativeRootPEM(n.cert)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(r.Operation, n.original[8:40]) || !bytes.Equal(b.Root, nativeDigest(root.Raw)) {
		return nil, errors.New("reservation belongs to another native operation")
	}
	if n.assignment != nil {
		if !bytes.Equal(n.assignment.Destination, r.Binding) {
			return nil, errors.New("native operation already assigned to another destination")
		}
		if advertise != nil {
			leaf, err := nativeAssignedLeaf(n.assignment.Certificate)
			if err != nil || leaf.VerifyHostname(advertise.To4().String()) != nil {
				return nil, errors.New("retained native assignment does not cover advertise address")
			}
		}
		if err := checkAdmission(); err != nil {
			return nil, err
		}
		if _, err := validateHostEnrollmentAt(b.Host, n.cert, n.assignment.Certificate, n.assignment.PrivateKey, nativeEnrollmentNow()); err != nil {
			return nil, err
		}
		return nativeMaterial(n), nil
	}
	if len(o.root) != 0 || o.servedFingerprint != [32]byte{} || o.retired {
		return nil, errors.New("established operator cannot assign first member")
	}
	for _, name := range []string{"host.crt", "host.key", hostDirName} {
		if _, err := os.Lstat(filepath.Join(o.dir, name)); !errors.Is(err, os.ErrNotExist) {
			return nil, errors.New("operator has existing host identity")
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	for serial.Sign() == 0 {
		serial, err = randomSerial()
		if err != nil {
			return nil, err
		}
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	auth := nativeMemberAuthorization{1, "litevirt/initial-native-member", bytes.Clone(r.Operation), nativeDigest(root.Raw), b.Host, bytes.Clone(r.Binding), serial.Bytes(), nativeDigest(spki)}
	authorization, err := asn1.Marshal(auth)
	if err != nil {
		return nil, err
	}
	at := nativeEnrollmentNow()
	template := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{Organization: []string{"litevirt"}, CommonName: b.Host}, DNSNames: []string{b.Host}, NotBefore: at.Add(-5 * time.Minute), NotAfter: at.Add(5 * 365 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtraExtensions: []pkix.Extension{{Id: initialNativeMemberOID, Value: authorization}}}
	if advertise != nil && !advertise.Equal(net.IPv4(127, 0, 0, 1)) {
		template.IPAddresses = append(template.IPAddresses, advertise.To4())
	}
	block, tail := pem.Decode(n.key)
	if block == nil || len(bytes.TrimSpace(tail)) != 0 {
		return nil, errors.New("invalid retained native root key")
	}
	rootKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		return nil, err
	}
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	reference, err := asn1.Marshal(nativeAssignmentReference{1, "litevirt/native-enrollment-assignment-ref", auth.Operation, auth.Root, auth.Destination, auth.Serial, auth.SPKI, nativeDigest(cert)})
	if err != nil {
		return nil, err
	}
	a := &nativeAssignedOperation{2, "litevirt/native-first-member-assignment", bytes.Clone(n.original), nativeDigest(n.original), auth.Operation, auth.Root, b.Host, auth.Destination, auth.Serial, auth.SPKI, cert, keyPEM, nativeDigest(cert), nativeDigest(keyPEM), reference}
	if err := validateNativeAssignment(a, n.cert, n.original); err != nil {
		return nil, err
	}
	body, err := asn1.Marshal(*a)
	if err != nil {
		return nil, err
	}
	record := append([]byte("LVNCA002"), body...)
	if len(record) > nativeAssignmentLimit {
		return nil, errors.New("native assignment exceeds bound")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := checkAdmission(); err != nil {
		return nil, err
	}
	if _, err := validateHostEnrollmentAt(b.Host, n.cert, cert, keyPEM, nativeEnrollmentNow()); err != nil {
		return nil, err
	}
	if err := writeTrustFile(filepath.Join(o.dir, nativeCARecordName), record, 0600); err != nil {
		return nil, err
	}
	if err := trustDurabilityPoint("native-assignment:committed"); err != nil {
		return nil, err
	}
	n.record, n.assignment = record, a
	if err := o.syncNativeOperatorCALocked(n); err != nil {
		return nil, err
	}
	if err := checkAdmission(); err != nil {
		return nil, err
	}
	if _, err := validateHostEnrollmentAt(b.Host, n.cert, cert, keyPEM, nativeEnrollmentNow()); err != nil {
		return nil, err
	}
	return nativeMaterial(n), nil
}

func nativeMaterial(n *nativeOperatorCA) *NativeFirstMemberMaterial {
	a := n.assignment
	return &NativeFirstMemberMaterial{bytes.Clone(n.cert), bytes.Clone(a.Certificate), bytes.Clone(a.PrivateKey), bytes.Clone(a.Destination), bytes.Clone(a.Reference)}
}

func nativeAssignedLeaf(body []byte) (*x509.Certificate, error) {
	if len(body) == 0 || len(body) > nativePEMLimit {
		return nil, errors.New("native leaf exceeds bound")
	}
	certs, err := strictCertificateBundle(body, 1)
	if err != nil {
		return nil, err
	}
	return certs[0], nil
}

func validateNativeAssignment(a *nativeAssignedOperation, ca, original []byte) error {
	if a.Version != 2 || a.Purpose != "litevirt/native-first-member-assignment" || !bytes.Equal(a.Original, original) || !bytes.Equal(a.OriginalHash, nativeDigest(original)) || !bytes.Equal(a.Operation, original[8:40]) || !nativeHostValid(a.Host) || len(a.PrivateKey) == 0 || len(a.PrivateKey) > nativePEMLimit || !bytes.Equal(a.CertificateHash, nativeDigest(a.Certificate)) || !bytes.Equal(a.KeyHash, nativeDigest(a.PrivateKey)) {
		return errors.New("invalid native assigned operation")
	}
	root, err := nativeRootPEM(ca)
	if err != nil {
		return err
	}
	b, err := decodeNativeBinding(a.Destination)
	if err != nil {
		return err
	}
	leaf, err := nativeAssignedLeaf(a.Certificate)
	if err != nil {
		return err
	}
	if leaf.SerialNumber.Sign() <= 0 || len(a.Serial) == 0 || len(a.Serial) > 20 || a.Serial[0] == 0 || !bytes.Equal(a.Serial, leaf.SerialNumber.Bytes()) || !bytes.Equal(a.SPKI, nativeDigest(leaf.RawSubjectPublicKeyInfo)) || !bytes.Equal(a.Root, nativeDigest(root.Raw)) || !bytes.Equal(b.Root, a.Root) || b.Host != a.Host {
		return errors.New("native assignment identity pins mismatch")
	}
	// Historical integrity and current credential authority are separate. The
	// existing root reader validates the original signature at original issuance;
	// a fresh assignment retry additionally requires current enrollment validity.
	if _, err := validateHostEnrollmentAt(a.Host, ca, a.Certificate, a.PrivateKey, leaf.NotBefore.Add(time.Second)); err != nil {
		return err
	}
	count := 0
	for _, ext := range leaf.Extensions {
		if !ext.Id.Equal(initialNativeMemberOID) {
			continue
		}
		count++
		if ext.Critical {
			return errors.New("critical native member extension")
		}
		var auth nativeMemberAuthorization
		if err := nativeCanonicalDER(ext.Value, nativeAuthorizationLimit, &auth); err != nil {
			return err
		}
		if auth.Version != 1 || auth.Purpose != "litevirt/initial-native-member" || !bytes.Equal(auth.Operation, a.Operation) || !bytes.Equal(auth.Root, a.Root) || auth.Host != a.Host || !bytes.Equal(auth.Destination, a.Destination) || !bytes.Equal(auth.Serial, a.Serial) || !bytes.Equal(auth.SPKI, a.SPKI) {
			return errors.New("native signed authorization mismatch")
		}
	}
	if count != 1 {
		return errors.New("native assignment requires exactly one authorization")
	}
	var ref nativeAssignmentReference
	if err := nativeCanonicalDER(a.Reference, nativeAuthorizationLimit, &ref); err != nil {
		return err
	}
	if ref.Version != 1 || ref.Purpose != "litevirt/native-enrollment-assignment-ref" || !bytes.Equal(ref.Operation, a.Operation) || !bytes.Equal(ref.Root, a.Root) || !bytes.Equal(ref.Destination, a.Destination) || !bytes.Equal(ref.Serial, a.Serial) || !bytes.Equal(ref.SPKI, a.SPKI) || !bytes.Equal(ref.Leaf, a.CertificateHash) {
		return errors.New("native assignment reference mismatch")
	}
	return nil
}
