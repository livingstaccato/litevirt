package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pki"
	"github.com/litevirt/litevirt/internal/ssh"
)

// These controls distinguish a missing retained assignment from a caller,
// genuine operator-CA creation, certificate, or request-capture setup failure.
// Global enrollment seams are restored by cleanup; none of these tests run in
// parallel. The sentinel stops before any destination enrollment is executed.
func TestNativeFirstMemberActualHostInitCaptureControls(t *testing.T) {
	for _, mode := range []string{"remote", "local"} {
		t.Run(mode, func(t *testing.T) {
			captureNativeFirstMemberInit(t, mode)
		})
	}
}

// A first-init caller that issues a disposable ordinary leaf, without retaining
// that exact identity in its operator checkpoint, loses its once-assignment on
// an unknown destination reply. Both real callers currently leave A unassigned.
// No destination success, future extension OID, or new codec is assumed here.
func TestNativeFirstMemberActualHostInitRetainsIssuedIdentity(t *testing.T) {
	for _, mode := range []string{"remote", "local"} {
		t.Run(mode, func(t *testing.T) {
			capture := captureNativeFirstMemberInit(t, mode)
			if bytes.Equal(capture.after, capture.before) {
				t.Fatalf("RED_NATIVE_INIT_ASSIGNMENT_UNRETAINED mode=%s checkpoint_bytes=104 unchanged=true magic=LVNCA001 issued_leaf=true issued_key=true", mode)
			}
			// These are only retention observations. Strict assigned-state decoding,
			// authorization and destination consumption need their own real tests.
			if !bytes.Contains(capture.after, capture.before) {
				t.Fatal("native init checkpoint lost the original operator operation")
			}
			if !bytes.Contains(capture.after, capture.request.Certificate) {
				t.Fatal("native init checkpoint did not retain the exact issued certificate")
			}
			if !bytes.Contains(capture.after, capture.request.Key) {
				t.Fatal("native init checkpoint did not retain the exact issued private key")
			}
		})
	}
}

type nativeFirstMemberInitCapture struct {
	before, after []byte
	request       HostEnrollmentRequest
}

func captureNativeFirstMemberInit(t *testing.T, mode string) nativeFirstMemberInitCapture {
	t.Helper()
	t.Setenv("LV_CONFIG_DIR", t.TempDir())
	t.Setenv("SUDO_USER", "")
	useConfig(t, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	dir := PKIDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatalf("create private operator directory: %v", err)
	}
	if err := pki.InitializeOperatorCA(ctx, dir); err != nil {
		t.Fatalf("create genuine fresh operator CA: %v", err)
	}
	read := func(name string) []byte {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read operator evidence %s: %v", name, err)
		}
		return body
	}
	capture := nativeFirstMemberInitCapture{before: read(".operator-ca-operation")}
	if len(capture.before) != 104 || string(capture.before[:8]) != "LVNCA001" || bytes.Equal(capture.before[8:40], make([]byte, 32)) {
		t.Fatal("fresh operator CA did not publish the real unassigned A104 operation")
	}
	rootPEM, rootKey := read("ca.crt"), read("ca.key")
	rootHash, keyHash := sha256.Sum256(rootPEM), sha256.Sum256(rootKey)
	if !bytes.Equal(capture.before[40:72], rootHash[:]) || !bytes.Equal(capture.before[72:104], keyHash[:]) {
		t.Fatal("fresh A104 does not commit the exact real operator root and key")
	}
	if !bytes.Equal(read(".operator-ca-native/ca.crt"), rootPEM) || !bytes.Equal(read(".operator-ca-native/ca.key"), rootKey) {
		t.Fatal("fresh A104 retained root material differs from the active operator pair")
	}
	root := parseNativeInitCertificate(t, rootPEM)
	if !root.IsCA || root.CheckSignatureFrom(root) != nil {
		t.Fatal("fresh operator root is not a real self-signed CA")
	}
	if _, err := tls.X509KeyPair(rootPEM, rootKey); err != nil {
		t.Fatalf("fresh operator root keypair: %v", err)
	}

	stop := errors.New("native init request captured before destination effects")
	remote := &nativeInitCaptureRemote{probe: remoteConfigProbe(daemonConfigPath), stop: stop}
	oldConnect, oldLocal := connectEnrollmentRemote, enrollLocalHost
	t.Cleanup(func() {
		connectEnrollmentRemote, enrollLocalHost = oldConnect, oldLocal
	})
	connectEnrollmentRemote = func(target *ssh.Target) (enrollmentConnection, error) {
		if mode != "remote" || target.Host() != "127.0.0.1" {
			return nil, errors.New("unexpected native init remote connection")
		}
		return remote, nil
	}
	localCalls := 0
	enrollLocalHost = func(_ context.Context, request HostEnrollmentRequest) error {
		if mode != "local" {
			return errors.New("unexpected native init local enrollment")
		}
		localCalls++
		capture.request = request
		return stop
	}
	var err error
	switch mode {
	case "remote":
		err = HostInit(ctx, "root@127.0.0.1", "native-first", false)
		capture.request = remote.request
		if strings.Join(remote.events, ",") != "probe,stage,copy,capture,cleanup,close" || localCalls != 0 {
			t.Fatal("actual remote init did not reach only the bounded capture boundary")
		}
	case "local":
		err = HostInitLocal(ctx, "native-first", "127.0.0.1", false)
		if localCalls != 1 || len(remote.events) != 0 {
			t.Fatal("actual local init did not reach only the bounded capture boundary")
		}
	default:
		t.Fatal("unknown native init capture mode")
	}
	if !errors.Is(err, stop) {
		t.Fatalf("actual init failed before its sentinel capture: %v", err)
	}
	request := capture.request
	if request.Host != "native-first" || !request.Founding || request.Force {
		t.Fatal("actual init request lost its host or first-init intent")
	}
	if !bytes.Equal(request.CA, rootPEM) || !bytes.Equal(read("ca.crt"), rootPEM) || !bytes.Equal(read("ca.key"), rootKey) {
		t.Fatal("actual init changed or did not capture the exact genuine operator CA")
	}
	leaf := parseNativeInitCertificate(t, request.Certificate)
	if leaf.IsCA || leaf.Subject.CommonName != "native-first" || leaf.CheckSignatureFrom(root) != nil {
		t.Fatal("actual init did not issue the requested real host leaf under the operator root")
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "127.0.0.1", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("actual init leaf does not cover the requested peer address: %v", err)
	}
	pair, err := tls.X509KeyPair(request.Certificate, request.Key)
	if err != nil || len(pair.Certificate) != 1 || !bytes.Equal(pair.Certificate[0], leaf.Raw) {
		t.Fatal("captured real leaf and private key do not form the exact issued identity")
	}
	capture.after = read(".operator-ca-operation")
	t.Logf("CONTROL_NATIVE_INIT_CAPTURE_OK mode=%s initial_checkpoint_bytes=104 root_pins=true leaf_pair=true sentinel=true", mode)
	return capture
}

func parseNativeInitCertificate(t *testing.T, raw []byte) *x509.Certificate {
	t.Helper()
	block, rest := pem.Decode(raw)
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		t.Fatal("captured material is not exactly one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse real captured X509 certificate: %v", err)
	}
	return certificate
}

// This transport only observes the real caller's serialized request. It never
// executes the copied helper, installs identity, or returns enrollment success.
type nativeInitCaptureRemote struct {
	probe   string
	stop    error
	events  []string
	request HostEnrollmentRequest
}

func (r *nativeInitCaptureRemote) Close() error {
	r.events = append(r.events, "close")
	return nil
}

func (r *nativeInitCaptureRemote) RunOutput(command string) ([]byte, error) {
	switch command {
	case r.probe:
		r.events = append(r.events, "probe")
		return []byte(noConfigSentinel), nil
	case "mktemp -d /var/tmp/litevirt-enrollment.XXXXXXXXXX":
		r.events = append(r.events, "stage")
		return []byte("/var/tmp/litevirt-enrollment.native-init-capture\n"), nil
	default:
		return nil, errors.New("native init attempted an effect outside request staging")
	}
}

func (r *nativeInitCaptureRemote) CopyFileMode(local, remote string, mode os.FileMode) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	if local != self || remote != "/var/tmp/litevirt-enrollment.native-init-capture/litevirt" || mode != 0700 {
		return errors.New("native init did not stage only the current private helper")
	}
	r.events = append(r.events, "copy")
	return nil
}

func (r *nativeInitCaptureRemote) RunWithInput(command string, body []byte) error {
	if command != "exec '/var/tmp/litevirt-enrollment.native-init-capture/litevirt' host-enroll" {
		return errors.New("native init did not use the bounded enrollment request")
	}
	if err := json.Unmarshal(body, &r.request); err != nil {
		return errors.New("native init did not serialize a valid enrollment request")
	}
	r.events = append(r.events, "capture")
	return r.stop
}

func (r *nativeInitCaptureRemote) Run(command string) error {
	if command != "rm -rf -- '/var/tmp/litevirt-enrollment.native-init-capture'" {
		return errors.New("native init cleanup escaped inert staging")
	}
	r.events = append(r.events, "cleanup")
	return nil
}
