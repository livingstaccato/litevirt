package pki

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func nativeDigestOperator(t *testing.T) (string, []byte, []byte, [sha256.Size]byte) {
	t.Helper()
	dir := t.TempDir()
	if err := InitializeOperatorCA(context.Background(), dir); err != nil {
		t.Fatal(err)
	}
	op, root, err := NativeOperatorCAOperation(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	block, tail := pem.Decode(root)
	if block == nil || len(tail) != 0 {
		t.Fatal("operator did not produce one actual root")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		t.Fatal("operator root is not valid", err)
	}
	return dir, op, root, sha256.Sum256(cert.Raw)
}

func nativeDigestDestination(t *testing.T) NativeDestinationConfig {
	t.Helper()
	dir := t.TempDir()
	return NativeDestinationConfig{HostName: "digest-node", PKIDir: dir, DataDir: filepath.Join(dir, "data"), ConfigPath: filepath.Join(dir, "config.yaml")}
}

func nativeDigestLease(t *testing.T, dir string) *HostDomainLease {
	t.Helper()
	lease, err := AcquireHostReinitialization(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(lease.Release)
	return lease
}

// A separate digest reservation store or a bridge that only refuses would
// break cross-form retry and the real operator's once-assignment.
func TestNativeDigestCrossFormAssignment(t *testing.T) {
	for _, first := range []string{"digest", "certificate"} {
		t.Run(first, func(t *testing.T) {
			operator, original, root, digest := nativeDigestOperator(t)
			cfg := nativeDigestDestination(t)
			lease := nativeDigestLease(t, cfg.PKIDir)
			var reservation []byte
			var err error
			if first == "digest" {
				reservation, err = PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, original[8:40], lease)
			} else {
				reservation, err = PrepareNativeEnrollmentDestination(context.Background(), cfg, root, original[8:40], lease)
			}
			if err != nil {
				t.Fatalf("DIGEST_CROSS_FORM_PREPARE first=%s: %v", first, err)
			}
			if err := RequireNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, original[8:40], reservation, lease); err != nil {
				t.Fatalf("DIGEST_CROSS_FORM_REQUIRE first=%s: %v", first, err)
			}
			if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, original[8:40], reservation, lease); err != nil {
				t.Fatal("full certificate cannot require digest reservation", err)
			}
			again, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, original[8:40], lease)
			if err != nil || !bytes.Equal(again, reservation) {
				t.Fatal("cross-form retry reminted the reservation", err)
			}
			path := filepath.Join(cfg.PKIDir, ".native-enrollment-destination")
			stored, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(stored, reservation) {
				t.Fatal("returned reservation is not retained", err)
			}
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
				t.Fatal("reservation is not a private regular file", err)
			}
			var record struct {
				Version            int
				Purpose            string `asn1:"utf8"`
				Operation, Binding []byte
			}
			if rest, err := asn1.Unmarshal(stored, &record); err != nil || len(rest) != 0 || record.Version != 1 || record.Purpose != "litevirt/native-enrollment-reservation" || !bytes.Equal(record.Operation, original[8:40]) {
				t.Fatal("reservation changed its existing format or operation", err)
			}
			var binding struct {
				Version                 int
				Purpose                 string `asn1:"utf8"`
				Root, ID                []byte
				Host, PKI, Data, Config string `asn1:"utf8"`
			}
			if rest, err := asn1.Unmarshal(record.Binding, &binding); err != nil || len(rest) != 0 || !bytes.Equal(binding.Root, digest[:]) || binding.Host != cfg.HostName || binding.PKI != cfg.PKIDir || binding.Data != cfg.DataDir || binding.Config != cfg.ConfigPath || len(binding.ID) != 32 || bytes.Equal(binding.ID, make([]byte, 32)) {
				t.Fatal("reservation does not bind actual destination and root", err)
			}
			lease.Release()
			material, err := AssignNativeFirstMember(context.Background(), operator, reservation, net.ParseIP("192.0.2.17"))
			if err != nil {
				t.Fatal("genuine operator cannot assign digest reservation", err)
			}
			if !bytes.Equal(material.CA, root) || !bytes.Equal(material.DestinationBinding, record.Binding) {
				t.Fatal("operator assignment changed original root or destination")
			}
			if _, err := tls.X509KeyPair(material.Certificate, material.PrivateKey); err != nil {
				t.Fatal("retained assignment is not an actual keypair", err)
			}
			checkpoint, err := os.ReadFile(filepath.Join(operator, ".operator-ca-operation"))
			if err != nil || len(checkpoint) <= 104 || string(checkpoint[:8]) != "LVNCA002" || !bytes.Contains(checkpoint, original) || !bytes.Contains(checkpoint, material.Certificate) || !bytes.Contains(checkpoint, material.PrivateKey) {
				t.Fatal("actual once-assignment lost retained original material", err)
			}
			for _, path := range []string{filepath.Join(cfg.PKIDir, "ca.crt"), filepath.Join(cfg.PKIDir, "host.crt"), filepath.Join(cfg.PKIDir, "host.key"), filepath.Join(cfg.DataDir, "state.db"), cfg.ConfigPath} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("inert reservation performed an install or DB effect", filepath.Base(path), err)
				}
			}
		})
	}
}

func nativeDigestTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	result := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		value := info.Mode().String()
		if info.Mode().IsRegular() {
			body, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			value += fmt.Sprintf(" %x", sha256.Sum256(body))
		} else if info.Mode()&os.ModeSymlink != 0 {
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			value += " " + target
		}
		result[rel] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// Omitting comparison with an actual parsed local operator root admits the
// independently created other valid CA. Malformed-only cases cannot catch it.
func TestNativeDigestLocalRootValidation(t *testing.T) {
	_, _, otherRoot, otherDigest := nativeDigestOperator(t)
	for _, state := range []string{"other-valid-root", "zero-digest", "missing-staged-key", "corrupt-staged-cert", "corrupt-operation", "missing-public-key", "other-valid-public-root"} {
		t.Run(state, func(t *testing.T) {
			dir, op, _, digest := nativeDigestOperator(t)
			cfg := NativeDestinationConfig{HostName: "local-digest", PKIDir: dir, DataDir: filepath.Join(t.TempDir(), "data"), ConfigPath: filepath.Join(t.TempDir(), "config.yaml")}
			lease := nativeDigestLease(t, dir)
			wantDigest := digest
			var err error
			switch state {
			case "other-valid-root":
				wantDigest = otherDigest
			case "zero-digest":
				wantDigest = [sha256.Size]byte{}
			case "missing-staged-key":
				err = os.Remove(filepath.Join(dir, ".operator-ca-native", "ca.key"))
			case "corrupt-staged-cert":
				err = os.WriteFile(filepath.Join(dir, ".operator-ca-native", "ca.crt"), []byte("not a certificate"), 0600)
			case "corrupt-operation":
				err = os.WriteFile(filepath.Join(dir, ".operator-ca-operation"), make([]byte, 104), 0600)
			case "missing-public-key":
				err = os.Remove(filepath.Join(dir, "ca.key"))
			case "other-valid-public-root":
				err = os.WriteFile(filepath.Join(dir, "ca.crt"), otherRoot, 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			before := nativeDigestTree(t, dir)
			if _, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, wantDigest, op[8:40], lease); err == nil {
				if state == "other-valid-root" {
					t.Fatal("DIGEST_WRONG_VALID_OPERATOR_ROOT_ACCEPTED")
				}
				t.Fatal("digest preparation admitted invalid local root state", state)
			}
			if !reflect.DeepEqual(before, nativeDigestTree(t, dir)) {
				t.Fatal("refusal changed actual retained local evidence", state)
			}
			if state == "other-valid-root" || state == "zero-digest" {
				if _, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], lease); err != nil {
					t.Fatal("matching genuine root positive control cannot reserve", err)
				}
			}
		})
	}
}

// A matching hash cannot turn an ordinary root or existing current evidence
// into eligibility. This exercises the digest arm through actual file owners.
func TestNativeDigestEligibilityAndAdmission(t *testing.T) {
	_, op, _, rootDigest := nativeDigestOperator(t)
	for _, state := range []string{"ordinary-root", "host-key", "pending", "spent", "gossip", "migration", "config", "data", "nil-admission", "shared-admission", "released-admission", "copied-admission"} {
		t.Run(state, func(t *testing.T) {
			cfg := nativeDigestDestination(t)
			lease := nativeDigestLease(t, cfg.PKIDir)
			// The real owner creates its stable lock on first acquisition.
			// Establish that lock under EX before the protected-file snapshot;
			// refusal must still leave every retained byte and mode unchanged.
			owner, err := trustOwnerFor(cfg.PKIDir)
			if err != nil {
				t.Fatal(err)
			}
			guard, err := owner.lock(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			guard.release()
			admission := lease
			digest := rootDigest
			switch state {
			case "ordinary-root":
				certPath := filepath.Join(cfg.PKIDir, "ca.crt")
				err = GenerateCA(certPath, filepath.Join(cfg.PKIDir, "ca.key"))
				if err == nil {
					body, readErr := os.ReadFile(certPath)
					if readErr != nil {
						t.Fatal(readErr)
					}
					block, _ := pem.Decode(body)
					if block == nil {
						t.Fatal("ordinary root fixture missing PEM")
					}
					cert, parseErr := x509.ParseCertificate(block.Bytes)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					digest = sha256.Sum256(cert.Raw)
				}
			case "host-key":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, "host.key"), []byte("preserved"), 0600)
			case "pending":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, ".native-first-member-pending"), []byte("preserved"), 0600)
			case "spent":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, ".native-first-member-spent"), []byte("preserved"), 0600)
			case "gossip":
				err = os.WriteFile(filepath.Join(cfg.PKIDir, GossipKeyName), []byte("preserved"), 0600)
			case "migration":
				err = os.Mkdir(filepath.Join(cfg.PKIDir, MigrationDirName), 0700)
			case "config":
				err = os.WriteFile(cfg.ConfigPath, []byte("host_name: existing\n"), 0600)
			case "data":
				err = os.MkdirAll(cfg.DataDir, 0700)
				if err == nil {
					err = os.WriteFile(filepath.Join(cfg.DataDir, "state.db"), []byte("preserved"), 0600)
				}
			case "nil-admission":
				admission = nil
			case "shared-admission":
				lease.Release()
				admission, err = AcquireHostDomain(context.Background(), cfg.PKIDir)
				if err == nil {
					t.Cleanup(admission.Release)
				}
			case "released-admission":
				lease.Release()
			case "copied-admission":
				admission = &HostDomainLease{self: lease, dir: lease.dir, file: lease.file, exclusive: true}
			}
			if err != nil {
				t.Fatal(err)
			}
			before := nativeDigestTree(t, cfg.PKIDir)
			if _, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], admission); err == nil {
				t.Fatal("digest bypassed current eligibility or actual EX", state)
			}
			if !reflect.DeepEqual(before, nativeDigestTree(t, cfg.PKIDir)) {
				t.Fatal("refused digest operation changed files", state)
			}
		})
	}
}

// Removing one request/binding comparison must not make require an alternate
// creator or allow a caller to change the actual retained destination tuple.
func TestNativeDigestRequireBindsRetainedContext(t *testing.T) {
	_, cfg, op, root, reservation := nativeAssignmentFixture(t)
	block, _ := pem.Decode(root)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cert.Raw)
	lease := nativeDigestLease(t, cfg.PKIDir)
	if err := RequireNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], reservation, lease); err != nil {
		t.Fatal("valid digest require positive control", err)
	}
	for _, state := range []string{"operation", "root", "host", "pki", "data", "config", "expected", "missing-expected"} {
		t.Run(state, func(t *testing.T) {
			changed := cfg
			candidateDigest := digest
			operation := bytes.Clone(op[8:40])
			expected := bytes.Clone(reservation)
			switch state {
			case "operation":
				operation[0] ^= 1
			case "root":
				candidateDigest[0] ^= 1
			case "host":
				changed.HostName = "other-host"
			case "pki":
				changed.PKIDir = t.TempDir()
			case "data":
				changed.DataDir = filepath.Join(t.TempDir(), "data")
			case "config":
				changed.ConfigPath = filepath.Join(t.TempDir(), "other.yaml")
			case "expected":
				expected[len(expected)-1] ^= 1
			case "missing-expected":
				expected = nil
			}
			before := nativeDigestTree(t, cfg.PKIDir)
			if err := RequireNativeEnrollmentDestinationDigest(context.Background(), changed, candidateDigest, operation, expected, lease); err == nil {
				t.Fatal("changed retained-context pin accepted", state)
			}
			if !reflect.DeepEqual(before, nativeDigestTree(t, cfg.PKIDir)) {
				t.Fatal("require refusal changed retained reservation", state)
			}
		})
	}
}

func TestNativeDigestMissingAssignedReservationRefuses(t *testing.T) {
	dir, op, _, digest := nativeDigestOperator(t)
	cfg := NativeDestinationConfig{HostName: "local-digest", PKIDir: dir, DataDir: filepath.Join(t.TempDir(), "data"), ConfigPath: filepath.Join(t.TempDir(), "config.yaml")}
	lease := nativeDigestLease(t, dir)
	reservation, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], lease)
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err != nil {
		t.Fatal(err)
	}
	lease = nativeDigestLease(t, dir)
	if err := RequireNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], reservation, lease); err != nil {
		t.Fatal("same assigned retry did not require original", err)
	}
	path := filepath.Join(dir, ".native-enrollment-destination")
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := nativeDigestTree(t, dir)
	if err := RequireNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], reservation, lease); err == nil {
		t.Fatal("assigned require recreated missing reservation")
	}
	if _, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], lease); err == nil {
		t.Fatal("assigned create rearmed missing reservation")
	}
	if !reflect.DeepEqual(before, nativeDigestTree(t, dir)) {
		t.Fatal("assigned evidence loss was repaired")
	}
}

type nativeDigestReopenRequest struct {
	Config              NativeDestinationConfig
	Root                [sha256.Size]byte
	Operation, Expected []byte
}

func TestNativeDigestReopenProcess(t *testing.T) {
	path := os.Getenv("LITEVIRT_DIGEST_REOPEN_REQUEST")
	if path == "" {
		t.Skip("owned subprocess only")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var request nativeDigestReopenRequest
	if err := json.Unmarshal(body, &request); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	lease, err := AcquireHostReinitialization(ctx, request.Config.PKIDir)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err := RequireNativeEnrollmentDestinationDigest(ctx, request.Config, request.Root, request.Operation, request.Expected, lease); err != nil {
		t.Fatal("fresh process cannot require retained digest reservation", err)
	}
	fmt.Println("NATIVE_DIGEST_REOPEN_OK")
}

func TestNativeDigestUncertaintyAndFreshProcessReopen(t *testing.T) {
	_, op, root, digest := nativeDigestOperator(t)
	cfg := nativeDigestDestination(t)
	lease := nativeDigestLease(t, cfg.PKIDir)
	injected := errors.New("digest reservation commit uncertain")
	trustDurabilitySeam = func(at string) error {
		if at == "native-destination:committed" {
			return injected
		}
		return nil
	}
	t.Cleanup(func() { trustDurabilitySeam = nil })
	_, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], lease)
	trustDurabilitySeam = nil
	if !errors.Is(err, injected) {
		t.Fatal("actual post-commit uncertainty boundary not reached", err)
	}
	path := filepath.Join(cfg.PKIDir, ".native-enrollment-destination")
	retained, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	again, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], lease)
	if err != nil || !bytes.Equal(again, retained) {
		t.Fatal("uncertain digest commit reminted on certificate retry", err)
	}
	if err := RequireNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], retained, lease); err != nil {
		t.Fatal(err)
	}
	lease.Release()
	body, err := json.Marshal(nativeDigestReopenRequest{cfg, digest, op[8:40], retained})
	if err != nil {
		t.Fatal(err)
	}
	request := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(request, body, 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, executable, "-test.run=^TestNativeDigestReopenProcess$", "-test.count=1", "-test.timeout=10s")
	child.Env = append(os.Environ(), "LITEVIRT_DIGEST_REOPEN_REQUEST="+request)
	output, err := child.CombinedOutput()
	t.Logf("actual fresh digest child pid=%d Wait=%v", child.Process.Pid, err)
	if err != nil || !bytes.Contains(output, []byte("NATIVE_DIGEST_REOPEN_OK")) {
		t.Fatal("fresh actual process failed retained reservation", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, retained) {
		t.Fatal("fresh process changed retained reservation", err)
	}
}

// Correlation can reserve an inert tuple, but cannot replace the genuine root
// and native creation operation required by the real assignment consumer.
func TestNativeDigestArbitraryCorrelationIsNotAssignment(t *testing.T) {
	dir, op, root, _ := nativeDigestOperator(t)
	cfg := nativeDigestDestination(t)
	lease := nativeDigestLease(t, cfg.PKIDir)
	digest := sha256.Sum256([]byte("independent arbitrary root correlation"))
	reservation, err := PrepareNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], lease)
	if err != nil {
		t.Fatal("inert reservation could not record correlation", err)
	}
	if err := RequireNativeEnrollmentDestination(context.Background(), cfg, root, op[8:40], reservation, lease); err == nil {
		t.Fatal("actual root accepted unrelated digest reservation")
	}
	lease.Release()
	if _, err := AssignNativeFirstMember(context.Background(), dir, reservation, nil); err == nil {
		t.Fatal("arbitrary correlation granted a signed assignment")
	}
	after, err := os.ReadFile(filepath.Join(dir, ".operator-ca-operation"))
	if err != nil || !bytes.Equal(after, op) {
		t.Fatal("refused assignment changed actual root operation", err)
	}
	for _, path := range []string{filepath.Join(cfg.PKIDir, "ca.crt"), filepath.Join(cfg.PKIDir, "ca.key"), filepath.Join(cfg.PKIDir, "host.crt"), filepath.Join(cfg.PKIDir, "host.key"), filepath.Join(cfg.DataDir, "state.db"), cfg.ConfigPath} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("correlation caused an active identity or DB effect", filepath.Base(path), err)
		}
	}
}

func TestNativeDigestFullCertificateAndActiveRootValidation(t *testing.T) {
	_, cfg, op, root, reservation := nativeAssignmentFixture(t)
	block, _ := pem.Decode(root)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(cert.Raw)
	lease := nativeDigestLease(t, cfg.PKIDir)
	badSelfSignature := bytes.Clone(block.Bytes)
	badSelfSignature[len(badSelfSignature)-1] ^= 1
	for _, bad := range [][]byte{nil, digest[:], []byte("not PEM"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: badSelfSignature})} {
		before := nativeDigestTree(t, cfg.PKIDir)
		if _, err := PrepareNativeEnrollmentDestination(context.Background(), cfg, bad, op[8:40], lease); err == nil {
			t.Fatal("full-certificate prepare reinterpreted malformed CA as digest")
		}
		if err := RequireNativeEnrollmentDestination(context.Background(), cfg, bad, op[8:40], reservation, lease); err == nil {
			t.Fatal("full-certificate require accepted malformed CA")
		}
		if !reflect.DeepEqual(before, nativeDigestTree(t, cfg.PKIDir)) {
			t.Fatal("malformed full-CA refusal changed retained evidence")
		}
	}
	_, _, otherRoot, _ := nativeDigestOperator(t)
	active := filepath.Join(cfg.PKIDir, "ca.crt")
	if err := os.WriteFile(active, otherRoot, 0644); err != nil {
		t.Fatal(err)
	}
	before := nativeDigestTree(t, cfg.PKIDir)
	if err := RequireNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], reservation, lease); err == nil {
		t.Fatal("DIGEST_WRONG_VALID_ACTIVE_ROOT_ACCEPTED")
	}
	if !reflect.DeepEqual(before, nativeDigestTree(t, cfg.PKIDir)) {
		t.Fatal("wrong valid active root refusal rewrote evidence")
	}
	if err := os.WriteFile(active, root, 0644); err != nil {
		t.Fatal(err)
	}
	if err := RequireNativeEnrollmentDestinationDigest(context.Background(), cfg, digest, op[8:40], reservation, lease); err != nil {
		t.Fatal("valid active root positive control refused", err)
	}
}
