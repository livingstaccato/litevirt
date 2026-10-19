package pki

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Removing owner retention or issuing an ordinary leaf must break this test.
// Expectations below decode the public bytes independently of the issuer.
func TestNativeFirstMemberCodecAndAssignment(t *testing.T) {
	dir, cfg, operation, root, reservation := nativeAssignmentFixture(t)
	original := bytes.Clone(operation)
	material, err := AssignNativeFirstMember(context.Background(), dir, reservation, net.ParseIP("192.0.2.17"))
	if err != nil {
		t.Fatal(err)
	}
	block, tail := pem.Decode(material.Certificate)
	if block == nil || len(tail) != 0 {
		t.Fatal("one retained leaf required")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	rootBlock, _ := pem.Decode(root)
	ca, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil || leaf.CheckSignatureFrom(ca) != nil {
		t.Fatal("assignment lacks actual root signature", err)
	}
	if _, err := tls.X509KeyPair(material.Certificate, material.PrivateKey); err != nil {
		t.Fatal(err)
	}
	if err := leaf.VerifyHostname("192.0.2.17"); err != nil {
		t.Fatal(err)
	}
	var auth struct {
		Version                   int
		Purpose                   string `asn1:"utf8"`
		Operation, Root           []byte
		Host                      string `asn1:"utf8"`
		Destination, Serial, SPKI []byte
	}
	count := 0
	for _, ext := range leaf.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61117, 1, 3}) {
			count++
			if ext.Critical {
				t.Fatal("native extension breaks ordinary TLS")
			}
			if rest, err := asn1.Unmarshal(ext.Value, &auth); err != nil || len(rest) != 0 {
				t.Fatal("invalid authorization", err)
			}
		}
	}
	rh, spki := sha256.Sum256(ca.Raw), sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
	if count != 1 || auth.Version != 1 || auth.Purpose != "litevirt/initial-native-member" || auth.Host != cfg.HostName || !bytes.Equal(auth.Operation, operation[8:40]) || !bytes.Equal(auth.Root, rh[:]) || !bytes.Equal(auth.Serial, leaf.SerialNumber.Bytes()) || !bytes.Equal(auth.SPKI, spki[:]) || !bytes.Equal(auth.Destination, material.DestinationBinding) {
		t.Fatal("signed authorization does not pin actual identity")
	}
	var binding struct {
		Version                 int
		Purpose                 string `asn1:"utf8"`
		Root, ID                []byte
		Host, PKI, Data, Config string `asn1:"utf8"`
	}
	if rest, err := asn1.Unmarshal(auth.Destination, &binding); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	if binding.Version != 1 || binding.Purpose != "litevirt/native-enrollment-destination" || !bytes.Equal(binding.Root, rh[:]) || len(binding.ID) != 32 || bytes.Equal(binding.ID, make([]byte, 32)) || binding.Host != cfg.HostName || binding.PKI != cfg.PKIDir || binding.Data != cfg.DataDir || binding.Config != cfg.ConfigPath {
		t.Fatal("destination context not bound")
	}
	var ref struct {
		Version                                          int
		Purpose                                          string `asn1:"utf8"`
		Operation, Root, Destination, Serial, SPKI, Leaf []byte
	}
	if rest, err := asn1.Unmarshal(material.AssignmentRef, &ref); err != nil || len(rest) != 0 {
		t.Fatal(err)
	}
	lh := sha256.Sum256(material.Certificate)
	if ref.Version != 1 || ref.Purpose != "litevirt/native-enrollment-assignment-ref" || !bytes.Equal(ref.Operation, auth.Operation) || !bytes.Equal(ref.Root, rh[:]) || !bytes.Equal(ref.Destination, auth.Destination) || !bytes.Equal(ref.Serial, auth.Serial) || !bytes.Equal(ref.SPKI, spki[:]) || !bytes.Equal(ref.Leaf, lh[:]) {
		t.Fatal("external assignment ref is not actual leaf projection")
	}
	checkpoint, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if err != nil || len(checkpoint) <= 104 || string(checkpoint[:8]) != "LVNCA002" || !bytes.Contains(checkpoint, original) || !bytes.Contains(checkpoint, material.Certificate) || !bytes.Contains(checkpoint, material.PrivateKey) {
		t.Fatal("assignment not retained in existing checkpoint", err)
	}
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal("actual existing-root consumer rejected valid v2", err)
	}
	again, err := AssignNativeFirstMember(context.Background(), dir, reservation, net.ParseIP("192.0.2.17"))
	if err != nil || !bytes.Equal(again.Certificate, material.Certificate) || !bytes.Equal(again.PrivateKey, material.PrivateKey) || !bytes.Equal(again.AssignmentRef, material.AssignmentRef) {
		t.Fatal("retry replaced exact assignment", err)
	}
	if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, net.ParseIP("192.0.2.18")); err == nil {
		t.Fatal("retry ignored retained SAN")
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if !bytes.Equal(checkpoint, after) {
		t.Fatal("retry rewrote checkpoint")
	}
}

func nativeAssignmentFixture(t *testing.T) (string, NativeDestinationConfig, []byte, []byte, []byte) {
	t.Helper()
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	op, root, _ := inspectNativeCA(t, dir)
	cfg, reservation := nativeDestinationFixture(t, root, op)
	return dir, cfg, op, root, reservation
}

func nativeDestinationFixture(t *testing.T, root, op []byte) (NativeDestinationConfig, []byte) {
	t.Helper()
	dest := t.TempDir()
	cfg := NativeDestinationConfig{HostName: "native-node", PKIDir: dest, DataDir: filepath.Join(dest, "data"), ConfigPath: filepath.Join(dest, "config.yaml")}
	lease, err := AcquireHostReinitialization(context.Background(), dest)
	if err != nil {
		t.Fatal(err)
	}
	reservation, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease)
	lease.Release()
	if err != nil {
		t.Fatal(err)
	}
	return cfg, reservation
}

// Missing/corrupt retained bytes must reach the existing InitializeOperatorCA
// reader, instead of being healed by a new assignment helper.
func TestNativeFirstMemberExistingReaderRefusesPartialLoss(t *testing.T) {
	for _, kind := range []string{"record-tail", "record-truncated", "record-oversize", "record-symlink", "stage-key", "active-root", "active-key", "leaf-corrupt", "key-corrupt", "record-missing"} {
		t.Run(kind, func(t *testing.T) {
			dir, _, _, _, reservation := nativeAssignmentFixture(t)
			material, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".operator-ca-operation")
			record, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "record-tail":
				err = os.WriteFile(path, append(record, 0), 0600)
			case "record-truncated":
				err = os.WriteFile(path, record[:len(record)-1], 0600)
			case "record-oversize":
				err = os.WriteFile(path, make([]byte, (2<<20)+16385), 0600)
			case "record-symlink":
				err = os.Rename(path, path+".saved")
				if err == nil {
					err = os.Symlink(path+".saved", path)
				}
			case "stage-key":
				err = os.Remove(filepath.Join(dir, ".operator-ca-native", "ca.key"))
			case "active-root":
				err = os.Remove(filepath.Join(dir, "ca.crt"))
			case "active-key":
				err = os.Remove(filepath.Join(dir, "ca.key"))
			case "leaf-corrupt":
				err = os.WriteFile(path, bytes.Replace(record, material.Certificate, bytes.Repeat([]byte("x"), len(material.Certificate)), 1), 0600)
			case "key-corrupt":
				err = os.WriteFile(path, bytes.Replace(record, material.PrivateKey, bytes.Repeat([]byte("x"), len(material.PrivateKey)), 1), 0600)
			case "record-missing":
				err = os.Remove(path)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, _ := os.ReadFile(path)
			if err := InitializeOperatorCA(context.Background(), dir); err == nil {
				t.Fatal("existing-root consumer accepted evidence loss")
			}
			after, _ := os.ReadFile(path)
			if !bytes.Equal(before, after) {
				t.Fatal("refusal rewrote native evidence")
			}
			if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err == nil {
				t.Fatal("assignment repaired missing or corrupt evidence")
			}
		})
	}
}

func TestNativeFirstMemberDestinationReservation(t *testing.T) {
	dir, cfg, op, root, reservation := nativeAssignmentFixture(t)
	lease, err := AcquireHostReinitialization(context.Background(), cfg.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(cfg.PKIDir, alias); err != nil {
		t.Fatal(err)
	}
	aliased := cfg
	aliased.PKIDir = alias
	aliased.DataDir = filepath.Join(alias, "data")
	aliased.ConfigPath = filepath.Join(alias, "config.yaml")
	again, err := PrepareNativeEnrollmentDestination(context.Background(), aliased, root, op[8:40], lease)
	if err != nil || !bytes.Equal(reservation, again) {
		t.Fatal("alias reminted destination", err)
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], reservation, lease); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"host", "data", "config", "operation", "root"} {
		changed := cfg
		changedOp := bytes.Clone(op[8:40])
		changedRoot := root
		switch field {
		case "host":
			changed.HostName = "Native-node"
		case "data":
			changed.DataDir += "-other"
		case "config":
			changed.ConfigPath += "-other"
		case "operation":
			changedOp[0] ^= 1
		case "root":
			changedRoot = []byte("not a root")
		}
		if err := RequireNativeEnrollmentDestination(context.Background(), changed, changedRoot, changedOp, reservation, lease); err == nil {
			t.Fatal("reservation ignored changed", field)
		}
	}
	// Same root/op/name/canonical paths: only the owner-created ID changes.
	var r struct {
		Version            int
		Purpose            string `asn1:"utf8"`
		Operation, Binding []byte
	}
	if _, err := asn1.Unmarshal(reservation, &r); err != nil {
		t.Fatal(err)
	}
	var b struct {
		Version                 int
		Purpose                 string `asn1:"utf8"`
		Root, ID                []byte
		Host, PKI, Data, Config string `asn1:"utf8"`
	}
	if _, err := asn1.Unmarshal(r.Binding, &b); err != nil {
		t.Fatal(err)
	}
	b.ID[0] ^= 1
	r.Binding, err = asn1.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := asn1.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], wrong, lease); err == nil {
		t.Fatal("another destination ID accepted with every other field identical")
	}
	if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(cfg.PKIDir, ".native-enrollment-destination")); err != nil {
		t.Fatal(err)
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], reservation, lease); err == nil {
		t.Fatal("assigned retry repaired missing destination reservation")
	}
}

func TestNativeFirstMemberConcurrentAssignment(t *testing.T) {
	dir, _, op, root, reservation := nativeAssignmentFixture(t)
	_, other := nativeDestinationFixture(t, root, op)
	alias := filepath.Join(t.TempDir(), "operator")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan []byte, 12)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			request := reservation
			path := dir
			if i%2 == 1 {
				request = other
				path = alias
			}
			m, err := AssignNativeFirstMember(context.Background(), path, request, nil)
			if err == nil {
				results <- m.Certificate
			} else {
				results <- nil
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(results)
	var winner []byte
	successes := 0
	for result := range results {
		if result != nil {
			successes++
			if winner == nil {
				winner = result
			}
			if !bytes.Equal(winner, result) {
				t.Fatal("two different leaves assigned")
			}
		}
	}
	if successes != 6 {
		t.Fatalf("expected one six-retry destination winner, got %d", successes)
	}
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
}

func TestNativeFirstMemberAssignmentCommitUncertainty(t *testing.T) {
	dir, _, _, _, reservation := nativeAssignmentFixture(t)
	injected := errors.New("assignment durable reopen uncertain")
	trustDurabilitySeam = func(at string) error {
		if at == "native-assignment:committed" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { trustDurabilitySeam = nil })
	if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); !errors.Is(err, injected) {
		t.Fatal("commit uncertainty was not returned", err)
	}
	trustDurabilitySeam = nil
	before, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if err != nil {
		t.Fatal(err)
	}
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if !bytes.Equal(before, after) {
		t.Fatal("uncertain committed assignment regenerated")
	}
}

// The test wire shape is deliberately independent of the production types.
// Updating external hashes must not let corrupted pins or authorizations pass.
type nativeAssignmentTestWire struct {
	Version                                                                                 int
	Purpose                                                                                 string `asn1:"utf8"`
	Original, OriginalHash, Operation, Root                                                 []byte
	Host                                                                                    string `asn1:"utf8"`
	Destination, Serial, SPKI, Certificate, PrivateKey, CertificateHash, KeyHash, Reference []byte
}

func TestNativeFirstMemberRejectsMalformedAssignedPins(t *testing.T) {
	for _, field := range []string{"version", "purpose", "original", "original-hash", "operation", "root", "host", "destination", "serial-zero", "serial-leading-zero", "serial-bound", "spki", "keypair", "leaf-hash", "key-hash", "reference", "reference-tail", "unknown-field"} {
		t.Run(field, func(t *testing.T) {
			dir, _, _, _, reservation := nativeAssignmentFixture(t)
			if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".operator-ca-operation")
			record, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var a nativeAssignmentTestWire
			if rest, err := asn1.Unmarshal(record[8:], &a); err != nil || len(rest) != 0 {
				t.Fatal(err)
			}
			switch field {
			case "version":
				a.Version = 3
			case "purpose":
				a.Purpose = "litevirt/native-first-member-operator-spent"
			case "original":
				a.Original[8] ^= 1
			case "original-hash":
				a.OriginalHash[0] ^= 1
			case "operation":
				a.Operation[0] ^= 1
			case "root":
				a.Root[0] ^= 1
			case "host":
				a.Host = "another-node"
			case "destination":
				a.Destination = append(a.Destination, 0)
			case "serial-zero":
				a.Serial = []byte{0}
			case "serial-leading-zero":
				a.Serial = append([]byte{0}, a.Serial...)
			case "serial-bound":
				a.Serial = bytes.Repeat([]byte{1}, 21)
			case "spki":
				a.SPKI[0] ^= 1
			case "keypair":
				a.PrivateKey = []byte("not a private key")
				h := sha256.Sum256(a.PrivateKey)
				a.KeyHash = h[:]
			case "leaf-hash":
				a.CertificateHash[0] ^= 1
			case "key-hash":
				a.KeyHash[0] ^= 1
			case "reference":
				a.Reference = []byte{0x30, 0}
			case "reference-tail":
				a.Reference = append(a.Reference, 0)
			}
			body, err := asn1.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			if field == "unknown-field" {
				var raw asn1.RawValue
				if _, err := asn1.Unmarshal(body, &raw); err != nil {
					t.Fatal(err)
				}
				raw.FullBytes = nil
				raw.Bytes = append(raw.Bytes, 0x05, 0)
				body, err = asn1.Marshal(raw)
				if err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(path, append([]byte("LVNCA002"), body...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := InitializeOperatorCA(context.Background(), dir); err == nil {
				t.Fatal("existing consumer accepted malformed", field)
			}
		})
	}
}

func TestNativeFirstMemberSignedAuthorizationValidation(t *testing.T) {
	for _, kind := range []string{"absent", "duplicate", "critical", "wrong-purpose", "wrong-version", "wrong-operation", "wrong-root", "wrong-host", "wrong-destination", "wrong-serial", "wrong-spki", "trailing", "oversize", "signature"} {
		t.Run(kind, func(t *testing.T) {
			dir, _, _, _, reservation := nativeAssignmentFixture(t)
			m, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, ".operator-ca-operation")
			record, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var a nativeAssignmentTestWire
			if _, err := asn1.Unmarshal(record[8:], &a); err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(m.Certificate)
			leaf, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			rootBlock, _ := pem.Decode(m.CA)
			root, err := x509.ParseCertificate(rootBlock.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			keyBody, err := os.ReadFile(filepath.Join(dir, "ca.key"))
			if err != nil {
				t.Fatal(err)
			}
			keyBlock, _ := pem.Decode(keyBody)
			key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			var auth struct {
				Version                   int
				Purpose                   string `asn1:"utf8"`
				Operation, Root           []byte
				Host                      string `asn1:"utf8"`
				Destination, Serial, SPKI []byte
			}
			var extIndex int
			leaf.ExtraExtensions = append(leaf.ExtraExtensions, leaf.Extensions...)
			for i, ext := range leaf.ExtraExtensions {
				if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61117, 1, 3}) {
					extIndex = i
					if _, err := asn1.Unmarshal(ext.Value, &auth); err != nil {
						t.Fatal(err)
					}
				}
			}
			switch kind {
			case "wrong-purpose":
				auth.Purpose = "ordinary"
			case "wrong-version":
				auth.Version = 2
			case "wrong-operation":
				auth.Operation[0] ^= 1
			case "wrong-root":
				auth.Root[0] ^= 1
			case "wrong-host":
				auth.Host = "other"
			case "wrong-destination":
				auth.Destination = append(auth.Destination, 0)
			case "wrong-serial":
				auth.Serial = []byte{1}
			case "wrong-spki":
				auth.SPKI[0] ^= 1
			}
			value, err := asn1.Marshal(auth)
			if err != nil {
				t.Fatal(err)
			}
			leaf.ExtraExtensions[extIndex].Value = value
			switch kind {
			case "absent":
				leaf.ExtraExtensions = append(leaf.ExtraExtensions[:extIndex], leaf.ExtraExtensions[extIndex+1:]...)
			case "duplicate":
				leaf.ExtraExtensions = append(leaf.ExtraExtensions, leaf.ExtraExtensions[extIndex])
			case "critical":
				leaf.ExtraExtensions[extIndex].Critical = true
			case "trailing":
				leaf.ExtraExtensions[extIndex].Value = append(value, 0)
			case "oversize":
				leaf.ExtraExtensions[extIndex].Value = bytes.Repeat([]byte{1}, 8193)
			}
			// Re-sign the negative fixture with the real A key, and update all
			// outer final-byte pins. The authorization itself must be checked.
			der, err := x509.CreateCertificate(rand.Reader, leaf, root, leaf.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "signature" {
				der[len(der)-1] ^= 1
			}
			a.Certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
			h := sha256.Sum256(a.Certificate)
			a.CertificateHash = h[:]
			var ref struct {
				Version                                          int
				Purpose                                          string `asn1:"utf8"`
				Operation, Root, Destination, Serial, SPKI, Leaf []byte
			}
			if _, err := asn1.Unmarshal(a.Reference, &ref); err != nil {
				t.Fatal(err)
			}
			ref.Leaf = h[:]
			a.Reference, err = asn1.Marshal(ref)
			if err != nil {
				t.Fatal(err)
			}
			body, err := asn1.Marshal(a)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append([]byte("LVNCA002"), body...), 0600); err != nil {
				t.Fatal(err)
			}
			if err := InitializeOperatorCA(context.Background(), dir); err == nil {
				t.Fatal("signed malformed authorization accepted", kind)
			}
		})
	}
}

func TestNativeFirstMemberReservationAdmissionAndGrammar(t *testing.T) {
	_, cfg, op, root, reservation := nativeAssignmentFixture(t)
	shared, err := AcquireHostDomain(context.Background(), cfg.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], shared); err == nil {
		t.Fatal("shared lifetime admitted reservation")
	}
	shared.Release()
	for _, lease := range []*HostDomainLease{nil, {}, shared} {
		if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], reservation, lease); err == nil {
			t.Fatal("invalid lifetime admitted reservation")
		}
	}
	wrong, err := AcquireHostReinitialization(context.Background(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], reservation, wrong); err == nil {
		t.Fatal("wrong-directory lifetime admitted reservation")
	}
	wrong.Release()
	lease, err := AcquireHostReinitialization(context.Background(), cfg.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	for _, path := range []string{"relative", "/tmp/./native", "/tmp/x/../native", "/tmp/native\n", string([]byte{'/', 0xff})} {
		changed := cfg
		changed.DataDir = path
		if _, err := PrepareNativeEnrollmentDestination(context.Background(), changed, root, op[8:40], lease); err == nil {
			t.Fatal("ambiguous native path accepted", path)
		}
	}
	for _, host := range []string{"", ".", "..", "a/b", "a\\b", "a\n", string([]byte{0xff})} {
		changed := cfg
		changed.HostName = host
		if _, err := PrepareNativeEnrollmentDestination(context.Background(), changed, root, op[8:40], lease); err == nil {
			t.Fatal("invalid host accepted")
		}
	}
	path := filepath.Join(cfg.PKIDir, ".native-enrollment-destination")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], reservation, lease); err == nil {
		t.Fatal("FIFO reservation accepted")
	}
}

func TestNativeFirstMemberLegacyAndOrdinaryIssuance(t *testing.T) {
	dir, cfg, op, root, reservation := nativeAssignmentFixture(t)
	readOp, readRoot, err := NativeOperatorCAOperation(context.Background(), dir)
	if err != nil || !bytes.Equal(readOp, op) || !bytes.Equal(readRoot, root) {
		t.Fatal("public metadata did not come from actual owner", err)
	}
	legacy := t.TempDir()
	if err := GenerateCA(filepath.Join(legacy, "ca.crt"), filepath.Join(legacy, "ca.key")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := NativeOperatorCAOperation(context.Background(), legacy); err == nil {
		t.Fatal("legacy root acquired native operation")
	}
	if _, err := AssignNativeFirstMember(context.Background(), legacy, reservation, nil); err == nil {
		t.Fatal("legacy root acquired assignment")
	}
	lease, err := AcquireHostReinitialization(context.Background(), legacy)
	if err != nil {
		t.Fatal(err)
	}
	cfg.PKIDir = legacy
	if _, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease); err == nil {
		t.Fatal("ordinary root became reservation eligibility")
	}
	lease.Release()
	for _, kind := range []string{"host", "client", "migration"} {
		certPath, keyPath := filepath.Join(t.TempDir(), "ordinary.crt"), filepath.Join(t.TempDir(), "ordinary.key")
		var err error
		switch kind {
		case "host":
			err = GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), certPath, keyPath, "ordinary", nil)
		case "client":
			err = GenerateClientCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), certPath, keyPath, "ordinary")
		case "migration":
			err = GenerateMigrationCA(certPath, keyPath)
		}
		if err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(certPath)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(body)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		for _, ext := range leaf.Extensions {
			if ext.Id.Equal(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 61117, 1, 3}) {
				t.Fatal("ordinary issuance acquired native permission", kind)
			}
		}
	}
}

func TestNativeFirstMemberLocalReservationCannotRearm(t *testing.T) {
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	op, root, err := NativeOperatorCAOperation(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg := NativeDestinationConfig{HostName: "local-native", PKIDir: dir, DataDir: filepath.Join(t.TempDir(), "data"), ConfigPath: filepath.Join(t.TempDir(), "config.yaml")}
	lease, err := AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	r, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease)
	lease.Release()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AssignNativeFirstMember(context.Background(), dir, r, nil); err != nil {
		t.Fatal(err)
	}
	lease, err = AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], r, lease); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease); err == nil {
		t.Fatal("assigned state accepted create arm")
	}
	if err := os.Remove(filepath.Join(dir, ".native-enrollment-destination")); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease); err == nil {
		t.Fatal("assigned local operation recreated missing reservation")
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], r, lease); err == nil {
		t.Fatal("assigned local retry repaired missing reservation")
	}
}

func TestNativeFirstMemberReservationRefusesEvidenceAndMalformedInput(t *testing.T) {
	for _, kind := range []string{"data", "config", "host", "pending", "spent", "crl", "superseded", "gossip", "admission", "record-symlink", "record-tail", "record-zero", "record-oversize"} {
		t.Run(kind, func(t *testing.T) {
			dir, cfg, op, root, reservation := nativeAssignmentFixture(t)
			path := filepath.Join(cfg.PKIDir, ".native-enrollment-destination")
			lease, err := AcquireHostReinitialization(context.Background(), cfg.PKIDir)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.Release()
			switch kind {
			case "data":
				err = os.WriteFile(filepath.Join(cfg.DataDir, "state.db"), []byte("preserved"), 0600)
			case "config":
				err = os.WriteFile(cfg.ConfigPath, []byte("host_name: existing\n"), 0600)
			case "host":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, "host.crt"), []byte("preserved"), 0600)
			case "pending":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, ".native-first-member-pending"), []byte("preserved"), 0600)
			case "spent":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, ".native-first-member-spent"), []byte("preserved"), 0600)
			case "crl":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, "crl.pem"), []byte("preserved"), 0600)
			case "superseded":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, supersededFile), []byte("preserved"), 0600)
			case "gossip":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, GossipKeyName), []byte("preserved"), 0600)
			case "admission":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, "audit-rejoin.json"), []byte("preserved"), 0600)
			case "record-symlink":
				err = os.Rename(path, path+".saved")
				if err == nil {
					err = os.Symlink(path+".saved", path)
				}
			case "record-tail":
				err = os.WriteFile(path, append(bytes.Clone(reservation), 0), 0600)
			case "record-zero":
				err = os.WriteFile(path, []byte{0x30, 0}, 0600)
			case "record-oversize":
				err = os.WriteFile(path, make([]byte, 8193), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease); err == nil {
				t.Fatal("evidence/malformed reservation reclassified as new", kind)
			}
			if kind == "record-tail" || kind == "record-zero" || kind == "record-oversize" {
				bad, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := AssignNativeFirstMember(context.Background(), dir, bad, nil); err == nil {
					t.Fatal("malformed reservation assigned")
				}
			}
		})
	}
}

func TestNativeFirstMemberReservationCommitUncertaintyAndPathAliases(t *testing.T) {
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	op, root, err := NativeOperatorCAOperation(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	target := t.TempDir()
	other := t.TempDir()
	alias := filepath.Join(t.TempDir(), "data-alias")
	if err := os.Symlink(target, alias); err != nil {
		t.Fatal(err)
	}
	cfg := NativeDestinationConfig{HostName: "node", PKIDir: destination, DataDir: filepath.Join(alias, "missing", "data"), ConfigPath: filepath.Join(t.TempDir(), "config.yaml")}
	lease, err := AcquireHostReinitialization(context.Background(), destination)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	injected := errors.New("reservation commit uncertain")
	trustDurabilitySeam = func(at string) error {
		if at == "native-destination:committed" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { trustDurabilitySeam = nil })
	if _, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease); !errors.Is(err, injected) {
		t.Fatal("reservation uncertainty not returned", err)
	}
	trustDurabilitySeam = nil
	before, err := os.ReadFile(filepath.Join(destination, ".native-enrollment-destination"))
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease)
	if err != nil || !bytes.Equal(before, again) {
		t.Fatal("uncertain reservation reminted", err)
	}
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(other, alias); err != nil {
		t.Fatal(err)
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], before, lease); err == nil {
		t.Fatal("changed alias target accepted")
	}
}

func TestNativeFirstMemberAssignmentCancellationPreservesOperation(t *testing.T) {
	dir, _, _, _, r := nativeAssignmentFixture(t)
	before, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := AcquireHostDomain(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Release()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := AssignNativeFirstMember(ctx, dir, r, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("assignment did not respect lifetime cancellation", err)
	}
	after, _ := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if !bytes.Equal(before, after) {
		t.Fatal("cancelled assignment changed operation")
	}
}

// A changed operator locator must never let EX(A) authorize mutation of B.
// The existing lifetime sync boundary makes this interleaving deterministic.
func TestNativeFirstMemberReviewAliasMustRetainLifetimeOwner(t *testing.T) {
	a := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	b, _, _, rootB, reservation := nativeAssignmentFixture(t)
	beforeA, _, _ := inspectNativeCA(t, a)
	beforeB, _, _ := inspectNativeCA(t, b)
	shared, err := AcquireHostDomain(context.Background(), b)
	if err != nil {
		t.Fatal(err)
	}
	defer shared.Release()
	alias := filepath.Join(t.TempDir(), "operator")
	if err := os.Symlink(a, alias); err != nil {
		t.Fatal(err)
	}
	switched := false
	var switchErr error
	trustDurabilitySeam = func(at string) error {
		if at != "directory-sync:"+a || switched {
			return nil
		}
		actual, err := os.Readlink(alias)
		if err != nil || actual != a {
			switchErr = errors.New("operator alias did not initially select A")
			return switchErr
		}
		if err := os.Remove(alias); err != nil {
			switchErr = err
			return err
		}
		if err := os.Symlink(b, alias); err != nil {
			switchErr = err
			return err
		}
		switched = true
		return nil
	}
	t.Cleanup(func() { trustDurabilitySeam = nil })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	material, assignmentErr := AssignNativeFirstMember(ctx, alias, reservation, nil)
	trustDurabilitySeam = nil
	if switchErr != nil || !switched {
		t.Fatal("alias interleaving setup failed", switchErr)
	}
	if errors.Is(assignmentErr, context.DeadlineExceeded) {
		t.Fatal("assignment waited for a different lifetime instead of refusing the changed locator")
	}
	shared.mu.Lock()
	leaseErr := shared.file.Sync()
	shared.mu.Unlock()
	if leaseErr != nil {
		t.Fatal("real B lifetime was not retained", leaseErr)
	}
	afterA, err := os.ReadFile(filepath.Join(a, ".operator-ca-operation"))
	if err != nil {
		t.Fatal(err)
	}
	afterB, err := os.ReadFile(filepath.Join(b, ".operator-ca-operation"))
	if err != nil {
		t.Fatal(err)
	}
	unchangedA, unchangedB := bytes.Equal(beforeA, afterA), bytes.Equal(beforeB, afterB)
	if assignmentErr == nil && material != nil && unchangedA && !unchangedB && len(afterB) > 104 && string(afterB[:8]) == "LVNCA002" {
		if !bytes.Equal(material.CA, rootB) {
			t.Fatal("unexpected successful assignment root")
		}
		if _, err := ValidateHostEnrollment("native-node", rootB, material.Certificate, material.PrivateKey); err != nil {
			t.Fatal("unexpected successful B material", err)
		}
		t.Log("CONTROL_NATIVE_ASSIGNMENT_ALIAS_SETUP_OK genuine_A_B=true switched_after_EX_A=true B_shared_held=true")
		t.Fatal("RED_NATIVE_ASSIGNMENT_ALIAS_ESCAPED_LIFETIME A_unchanged=true B_consumed=true B_shared_held=true material_returned=true")
	}
	if assignmentErr == nil || material != nil || !unchangedA || !unchangedB {
		t.Fatalf("changed alias must refuse without changing either operation: error=%v material=%t A_unchanged=%t B_unchanged=%t", assignmentErr, material != nil, unchangedA, unchangedB)
	}
}

func nativeDatedAssignmentFixture(t *testing.T, created time.Time) (string, []byte, []byte, []byte) {
	t.Helper()
	nativeEnrollmentNow = func() time.Time { return created }
	t.Cleanup(func() { nativeEnrollmentNow = time.Now })
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	op, root, _ := inspectNativeCA(t, dir)
	block, _ := pem.Decode(root)
	parsed, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.NotAfter.Equal(created.Add(10*365*24*time.Hour)) || parsed.CheckSignatureFrom(parsed) != nil {
		t.Fatal("actual native creation did not use controlled root dates")
	}
	_, reservation := nativeDestinationFixture(t, root, op)
	return dir, op, root, reservation
}

// Historical integrity cannot authorize first publication with an expired root.
func TestNativeFirstMemberReviewExpiredRootMustNotConsume(t *testing.T) {
	at := time.Now().UTC().Truncate(time.Second)
	created := at.Add(-10 * 365 * 24 * time.Hour).Add(-time.Minute)
	dir, before, root, reservation := nativeDatedAssignmentFixture(t, created)
	nativeEnrollmentNow = func() time.Time { return at }
	material, assignmentErr := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
	after, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if err != nil {
		t.Fatal(err)
	}
	rootBlock, _ := pem.Decode(root)
	ca, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.NotAfter.Equal(at.Add(-time.Minute)) {
		t.Fatal("expired-root setup is outside intended backdate window")
	}
	if assignmentErr == nil && material != nil && !bytes.Equal(before, after) && len(after) > 104 && string(after[:8]) == "LVNCA002" {
		block, _ := pem.Decode(material.Certificate)
		leaf, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		pool := x509.NewCertPool()
		pool.AddCert(ca)
		for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: at, KeyUsages: []x509.ExtKeyUsage{usage}}); err == nil {
				t.Fatal("unexpected current-valid expired-root material")
			}
			if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: leaf.NotBefore.Add(time.Second), KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
				t.Fatal("historical-only bug setup failed", err)
			}
		}
		if _, err := tls.X509KeyPair(material.Certificate, material.PrivateKey); err != nil {
			t.Fatal(err)
		}
		t.Log("CONTROL_NATIVE_ASSIGNMENT_EXPIRY_SETUP_OK genuine_owner_creation=true expired_within_backdate=true historical_valid=true current_invalid=true")
		t.Fatal("RED_NATIVE_ASSIGNMENT_EXPIRED_ROOT_CONSUMED root_expired=true A_consumed=true material_returned=true current_invalid=true")
	}
	if assignmentErr == nil || material != nil || !bytes.Equal(before, after) {
		t.Fatalf("expired root must refuse without consuming A104: error=%v material=%t unchanged=%t", assignmentErr, material != nil, bytes.Equal(before, after))
	}
}

func TestNativeFirstMemberReviewPositiveControls(t *testing.T) {
	t.Run("stable-alias", func(t *testing.T) {
		dir, _, _, _, reservation := nativeAssignmentFixture(t)
		alias := filepath.Join(t.TempDir(), "operator")
		if err := os.Symlink(dir, alias); err != nil {
			t.Fatal(err)
		}
		first, err := AssignNativeFirstMember(context.Background(), alias, reservation, nil)
		if err != nil {
			t.Fatal(err)
		}
		again, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
		if err != nil || !bytes.Equal(first.Certificate, again.Certificate) || !bytes.Equal(first.PrivateKey, again.PrivateKey) {
			t.Fatal("stable alias did not preserve assignment", err)
		}
	})
	t.Run("real-shared-exclusion-and-release", func(t *testing.T) {
		dir, _, _, _, reservation := nativeAssignmentFixture(t)
		before, _, _ := inspectNativeCA(t, dir)
		shared, err := AcquireHostDomain(context.Background(), dir)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		m, err := AssignNativeFirstMember(ctx, dir, reservation, nil)
		cancel()
		shared.Release()
		if !errors.Is(err, context.DeadlineExceeded) || m != nil {
			t.Fatal("real shared lifetime failed to exclude assignment", err)
		}
		after, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("excluded attempt changed operation", err)
		}
		if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err != nil {
			t.Fatal("released lifetime did not admit assignment", err)
		}
	})
	t.Run("current-dated-native-creation", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Second)
		dir, _, root, reservation := nativeDatedAssignmentFixture(t, at)
		nativeEnrollmentNow = func() time.Time { return at }
		m, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := validateHostEnrollmentAt("native-node", root, m.Certificate, m.PrivateKey, at); err != nil {
			t.Fatal("genuine current creation did not produce current enrollment", err)
		}
		if err := InitializeOperatorCA(context.Background(), dir); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("historical-reopen-expired-fresh-retry", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Second)
		dir, _, _, reservation := nativeDatedAssignmentFixture(t, at.Add(-10*365*24*time.Hour).Add(time.Minute))
		nativeEnrollmentNow = func() time.Time { return at }
		m, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
		if err != nil {
			t.Fatal("current initial assignment refused", err)
		}
		before, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
		if err != nil {
			t.Fatal(err)
		}
		nativeEnrollmentNow = func() time.Time { return at.Add(2 * time.Minute) }
		if err := InitializeOperatorCA(context.Background(), dir); err != nil {
			t.Fatal("historical reader demanded current validity", err)
		}
		if retry, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err == nil || retry != nil {
			t.Fatal("expired unfinished assignment granted fresh retry")
		}
		after, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
		if err != nil || !bytes.Equal(before, after) || !bytes.Contains(after, m.Certificate) || !bytes.Contains(after, m.PrivateKey) {
			t.Fatal("expiry renewed or discarded exact assignment", err)
		}
	})
	t.Run("expiry-during-final-durability", func(t *testing.T) {
		at := time.Now().UTC().Truncate(time.Second)
		dir, _, root, reservation := nativeDatedAssignmentFixture(t, at.Add(-10*365*24*time.Hour).Add(time.Minute))
		nativeEnrollmentNow = func() time.Time { return at }
		var committed []byte
		var seamErr error
		trustDurabilitySeam = func(stage string) error {
			if stage == "native-assignment:committed" {
				committed, seamErr = os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
				nativeEnrollmentNow = func() time.Time { return at.Add(2 * time.Minute) }
			}
			return seamErr
		}
		t.Cleanup(func() { trustDurabilitySeam = nil })
		m, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
		trustDurabilitySeam = nil
		if seamErr != nil || len(committed) <= 104 || string(committed[:8]) != "LVNCA002" {
			t.Fatal("final durability expiry boundary not reached", seamErr)
		}
		if err == nil || m != nil {
			t.Fatal("post-commit expiry returned fresh enrollment material")
		}
		if err := InitializeOperatorCA(context.Background(), dir); err != nil {
			t.Fatal("post-commit expiry blocked historical reopen", err)
		}
		if retry, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err == nil || retry != nil {
			t.Fatal("expired committed assignment was reminted")
		}
		after, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
		if err != nil || !bytes.Equal(committed, after) {
			t.Fatal("post-commit expiry changed assigned identity", err)
		}
		var a nativeAssignmentTestWire
		if _, err := asn1.Unmarshal(after[8:], &a); err != nil {
			t.Fatal(err)
		}
		if _, err := tls.X509KeyPair(a.Certificate, a.PrivateKey); err != nil {
			t.Fatal(err)
		}
		if _, err := validateHostEnrollmentAt("native-node", root, a.Certificate, a.PrivateKey, at); err != nil {
			t.Fatal("original issuance was not currently valid", err)
		}
		if _, err := validateHostEnrollmentAt("native-node", root, a.Certificate, a.PrivateKey, at.Add(2*time.Minute)); err == nil {
			t.Fatal("controlled final expiry is not genuine")
		}
	})
	t.Run("replaced-lifetime-inode-refuses", func(t *testing.T) {
		dir, _, _, _, reservation := nativeAssignmentFixture(t)
		before, _, _ := inspectNativeCA(t, dir)
		replaced := false
		var seamErr error
		trustDurabilitySeam = func(stage string) error {
			if stage != "directory-sync:"+dir || replaced {
				return nil
			}
			path := filepath.Join(dir, ".active-domain.lock")
			if err := os.Remove(path); err != nil {
				seamErr = err
				return err
			}
			seamErr = os.WriteFile(path, nil, 0600)
			replaced = seamErr == nil
			return seamErr
		}
		t.Cleanup(func() { trustDurabilitySeam = nil })
		m, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
		trustDurabilitySeam = nil
		if seamErr != nil || !replaced {
			t.Fatal("lifetime inode boundary not reached", seamErr)
		}
		if err == nil || m != nil {
			t.Fatal("assignment accepted a displaced lifetime inode")
		}
		after, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("displaced lifetime consumed operation", err)
		}
	})
}

// Each error is injected at the existing low-level boundary after the real
// assignment rename, before the record's durable reopen has completed.
func TestNativeFirstMemberRetryReconcilesLowLevelUncertainty(t *testing.T) {
	for _, stage := range []string{"reopen", "file-sync", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			dir, _, original, root, reservation := nativeAssignmentFixture(t)
			injected := errors.New("native assigned record durability uncertain")
			var landed []byte
			faults := 0
			trustDurabilitySeam = func(at string) error {
				record, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
				if err != nil {
					return err
				}
				if len(record) <= 104 || string(record[:8]) != "LVNCA002" {
					return nil
				}
				if landed == nil {
					landed = bytes.Clone(record)
				}
				want := stage
				if stage == "directory-sync" {
					want = "directory-sync:" + dir
				}
				if at == want {
					faults++
					return injected
				}
				return nil
			}
			t.Cleanup(func() { trustDurabilitySeam = nil })
			first, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
			if !errors.Is(err, injected) || first != nil || faults != 1 || len(landed) <= 104 {
				t.Fatalf("actual landed-v2 low-level fault not observed: stage=%s error=%v material=%t faults=%d landed=%d", stage, err, first != nil, faults, len(landed))
			}
			var retained nativeAssignmentTestWire
			if rest, err := asn1.Unmarshal(landed[8:], &retained); err != nil || len(rest) != 0 {
				t.Fatal("landed assignment is not a complete checkpoint", err)
			}
			if !bytes.Equal(retained.Original, original) || !bytes.Equal(retained.Operation, original[8:40]) {
				t.Fatal("landed assignment did not consume the actual creation operation")
			}
			if _, err := ValidateHostEnrollment("native-node", root, retained.Certificate, retained.PrivateKey); err != nil {
				t.Fatal("landed assignment is not genuine current signed material", err)
			}
			retry, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
			if !errors.Is(err, injected) || retry != nil || faults != 2 {
				t.Fatalf("retry must remain closed while the actual low-level fault persists: stage=%s error=%v material=%t faults=%d", stage, err, retry != nil, faults)
			}
			still, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
			if err != nil || !bytes.Equal(landed, still) {
				t.Fatal("uncertain retry changed retained identity", err)
			}
			trustDurabilitySeam = nil
			material, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil)
			if err != nil {
				t.Fatal("cleared low-level fault did not allow exact reconciliation", err)
			}
			if !bytes.Equal(material.CA, root) || !bytes.Equal(material.Certificate, retained.Certificate) || !bytes.Equal(material.PrivateKey, retained.PrivateKey) || !bytes.Equal(material.DestinationBinding, retained.Destination) || !bytes.Equal(material.AssignmentRef, retained.Reference) {
				t.Fatal("reconciliation regenerated assigned material")
			}
			if err := InitializeOperatorCA(context.Background(), dir); err != nil {
				t.Fatal("existing owner could not reopen reconciled assignment", err)
			}
			after, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
			if err != nil || !bytes.Equal(landed, after) {
				t.Fatal("successful reconciliation changed the operation", err)
			}
			t.Logf("CONTROL_NATIVE_ASSIGNMENT_LOWLEVEL_UNCERTAINTY_OK stage=%s faults=2 landed_v2=true retry_refused=true exact_retry=true", stage)
		})
	}
}
