package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/pki"
	"google.golang.org/grpc"
)

func TestEnrollmentServiceStopRequiresVerifiedState(t *testing.T) {
	for _, mode := range []string{"normal", "absent", "stop-error", "ambiguous", "still-active"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
			t.Setenv("ENROLL_TEST_MODE", mode)
			t.Setenv("ENROLL_TEST_STOP", filepath.Join(dir, "stopped"))
			script := `#!/bin/sh
if [ "$1" = stop ]; then
 [ "$ENROLL_TEST_MODE" != stop-error ] || exit 1
 touch "$ENROLL_TEST_STOP"
 exit 0
fi
if [ "$ENROLL_TEST_MODE" = ambiguous ]; then exit 1; fi
if [ "$ENROLL_TEST_MODE" = absent ]; then
 printf 'LoadState=not-found\nActiveState=inactive\nSubState=dead\n'
 exit 1
fi
if [ -e "$ENROLL_TEST_STOP" ] && [ "$ENROLL_TEST_MODE" != still-active ]; then
 printf 'LoadState=loaded\nActiveState=inactive\nSubState=dead\n'
else
 printf 'LoadState=loaded\nActiveState=active\nSubState=running\n'
fi
`
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			err := stopEnrollmentService(context.Background())
			want := mode == "normal" || mode == "absent"
			if (err == nil) != want {
				t.Fatalf("service stop mode %s: %v", mode, err)
			}
		})
	}
}

func TestEnrollmentActualSetupScriptDefersRestart(t *testing.T) {
	// Execute the exact production script tail that enables/restarts litevirt.
	// Earlier setup is privileged host configuration and is deliberately not run.
	at := strings.LastIndex(setupScriptContent, "systemctl daemon-reload")
	if at < 0 {
		t.Fatal("setup service tail missing")
	}
	dir := t.TempDir()
	calls := filepath.Join(dir, "calls")
	t.Setenv("ENROLL_TEST_CALLS", calls)
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte("#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$ENROLL_TEST_CALLS\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, deferStart := range []bool{true, false} {
		_ = os.Remove(calls)
		cmd := exec.Command("bash", "-s")
		cmd.Stdin = strings.NewReader(setupScriptContent[at:])
		cmd.Env = os.Environ()
		if deferStart {
			cmd.Env = append(cmd.Env, "LITEVIRT_DEFER_START=1")
		}
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("setup tail: %v %s", err, out)
		}
		b, err := os.ReadFile(calls)
		if err != nil {
			t.Fatal(err)
		}
		restarted := strings.Contains(string(b), "restart litevirt.service")
		if restarted == deferStart {
			t.Fatalf("actual setup tail restart=%v with defer=%v", restarted, deferStart)
		}
	}
}

type enrollmentRemoteFixture struct {
	events  []string
	copied  string
	request HostEnrollmentRequest
}

func (f *enrollmentRemoteFixture) Close() error { f.events = append(f.events, "close"); return nil }

func (f *enrollmentRemoteFixture) Run(command string) error {
	f.events = append(f.events, "cleanup")
	if !strings.HasPrefix(command, "rm -rf -- '/var/tmp/litevirt-enrollment.") {
		return errors.New("cleanup escaped owned staging")
	}
	return nil
}
func (f *enrollmentRemoteFixture) RunOutput(command string) ([]byte, error) {
	if strings.HasPrefix(command, "if [ -e ") {
		f.events = append(f.events, "probe")
		return []byte(noConfigSentinel), nil
	}
	f.events = append(f.events, "stage")
	if !strings.HasPrefix(command, "mktemp -d /var/tmp/litevirt-enrollment.") {
		return nil, errors.New("active remote effect before helper")
	}
	return []byte("/var/tmp/litevirt-enrollment.1234567890\n"), nil
}

type enrollmentAdmissionClient struct {
	pb.LiteVirtClient
	remote *enrollmentRemoteFixture
}

func (c *enrollmentAdmissionClient) AdmitHost(context.Context, *pb.AdmitHostRequest, ...grpc.CallOption) (*pb.AdmitHostResponse, error) {
	c.remote.events = append(c.remote.events, "admit")
	return &pb.AdmitHostResponse{AuditPositionProven: true}, nil
}

func TestAllEnrollmentEntryPathsUseStagedWorkflow(t *testing.T) {
	for _, path := range []string{"remote-init", "remote-add", "local-init"} {
		t.Run(path, func(t *testing.T) {
			source := addOperatorPKI(t)
			useConfig(t, "")
			t.Setenv("SUDO_USER", "")
			if err := pki.GenerateHostCert(filepath.Join(source, "ca.crt"), filepath.Join(source, "ca.key"), filepath.Join(source, "host.crt"), filepath.Join(source, "host.key"), "existing-host", nil); err != nil {
				t.Fatal(err)
			}
			originalKey, err := os.ReadFile(filepath.Join(source, "host.key"))
			if err != nil {
				t.Fatal(err)
			}
			remote := &enrollmentRemoteFixture{}
			oldConnect := connectEnrollmentRemote
			connectEnrollmentRemote = func(string) (enrollmentConnection, error) { return remote, nil }
			defer func() { connectEnrollmentRemote = oldConnect }()
			oldLocal := enrollLocalHost
			enrollLocalHost = func(_ context.Context, r HostEnrollmentRequest) error {
				remote.events = append(remote.events, "local-invoke")
				remote.request = r
				return nil
			}
			defer func() { enrollLocalHost = oldLocal }()
			stubPeerConfig(t, func(string) (string, bool, error) { return "enforcement:\n  gossip_encryption: enforce\n", true, nil })
			stubMigrationProbe(t, func(string) (bool, error) { return false, nil })
			switch path {
			case "remote-init":
				err = HostInit(context.Background(), "root@127.0.0.1", "host", false)
			case "remote-add":
				err = HostAdd(context.Background(), &enrollmentAdmissionClient{remote: remote}, "root@127.0.0.1", "host", []string{"127.0.0.2:7946"})
			case "local-init":
				err = HostInitLocal(context.Background(), "host", "127.0.0.1", false)
			}
			if err != nil {
				t.Fatal(err)
			}
			if remote.request.Host != "host" || remote.request.Founding != (path != "remote-add") || remote.request.Force {
				t.Fatal("entry path did not preserve enrollment intent")
			}
			if _, err := pki.ValidateHostEnrollment("host", remote.request.CA, remote.request.Certificate, remote.request.Key); err != nil {
				t.Fatal("entry staged invalid identity", err)
			}
			after, err := os.ReadFile(filepath.Join(source, "host.key"))
			if err != nil || string(after) != string(originalKey) {
				t.Fatal("entry minted into active operator identity")
			}
			events := strings.Join(remote.events, ",")
			switch path {
			case "remote-init":
				if events != "probe,stage,current-helper,invoke,cleanup,close" {
					t.Fatal(events)
				}
			case "remote-add":
				if events != "admit,stage,current-helper,invoke,cleanup,close" {
					t.Fatal(events)
				}
			case "local-init":
				if events != "local-invoke" {
					t.Fatal(events)
				}
			}
		})
	}
}
func (f *enrollmentRemoteFixture) CopyFileMode(local, remote string, mode os.FileMode) error {
	f.events = append(f.events, "current-helper")
	f.copied = local
	if remote != "/var/tmp/litevirt-enrollment.1234567890/litevirt" || mode != 0700 {
		return errors.New("helper was copied into an active path or with unsafe mode")
	}
	return nil
}
func (f *enrollmentRemoteFixture) RunWithInput(command string, body []byte) error {
	f.events = append(f.events, "invoke")
	if command != "exec '/var/tmp/litevirt-enrollment.1234567890/litevirt' host-enroll" {
		return errors.New("did not invoke staged current helper")
	}
	return json.Unmarshal(body, &f.request)
}

func TestRemoteEnrollmentStagesCurrentHelperBeforeActiveEffects(t *testing.T) {
	request, _, _ := enrollmentFixture(t)
	remote := &enrollmentRemoteFixture{}
	if err := runRemoteEnrollment(remote, request); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if remote.copied != self {
		t.Fatal("enrollment selected an old installed or sibling binary")
	}
	if strings.Join(remote.events, ",") != "stage,current-helper,invoke,cleanup" {
		t.Fatal(remote.events)
	}
	if string(remote.request.Key) != string(request.Key) || remote.request.Host != request.Host {
		t.Fatal("staged request changed")
	}
}

func enrollmentFixture(t *testing.T) (HostEnrollmentRequest, hostEnrollmentOps, *[]string) {
	t.Helper()
	source := t.TempDir()
	mustCA(t, source)
	if err := pki.GenerateHostCert(filepath.Join(source, "ca.crt"), filepath.Join(source, "ca.key"), filepath.Join(source, "host.crt"), filepath.Join(source, "host.key"), "test-host", nil); err != nil {
		t.Fatal(err)
	}
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	request := HostEnrollmentRequest{Host: "test-host", CA: read("ca.crt"), Certificate: read("host.crt"), Key: read("host.key"), Founding: true}
	root := t.TempDir()
	events := []string{}
	op := func(name string) func(context.Context, HostEnrollmentRequest) error {
		return func(context.Context, HostEnrollmentRequest) error { events = append(events, name); return nil }
	}
	ops := hostEnrollmentOps{pkiDir: filepath.Join(root, "pki"), migrationDir: filepath.Join(root, "migration"), configPath: filepath.Join(root, "config.yaml"), prepare: op("prepare"), stop: op("stop"), installBinary: op("binary"), configure: op("configure"), start: op("start")}
	return request, ops, &events
}

func TestEnrollmentQuiescenceAndStartOrdering(t *testing.T) {
	request, ops, events := enrollmentFixture(t)
	ops.configure = func(ctx context.Context, _ HostEnrollmentRequest) error {
		*events = append(*events, "configure")
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		if _, err := pki.CaptureHostTrust(ctx, ops.pkiDir, "test-host"); err != nil {
			return errors.New("configure ran under owner lease")
		}
		if lease, err := pki.AcquireHostDomain(ctx, ops.pkiDir); !errors.Is(err, context.DeadlineExceeded) {
			if lease != nil {
				lease.Release()
			}
			return errors.New("configuration lost exclusive lifetime admission")
		}
		return nil
	}
	ops.start = func(ctx context.Context, _ HostEnrollmentRequest) error {
		*events = append(*events, "start")
		ctx, cancel := context.WithTimeout(ctx, 100*time.Millisecond)
		defer cancel()
		lease, err := pki.AcquireHostDomain(ctx, ops.pkiDir)
		if err != nil {
			return errors.New("start waited for helper's unreleased exclusive admission")
		}
		lease.Release()
		return nil
	}
	if err := runHostEnrollment(context.Background(), request, ops); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(*events, ","); got != "prepare,stop,binary,configure,start" {
		t.Fatal(got)
	}
	for _, name := range []string{"host.key", "ca.crt", "host.crt"} {
		if _, err := os.Stat(filepath.Join(ops.pkiDir, name)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnrollmentFailuresDoNotStartOrBypassAdmission(t *testing.T) {
	for _, failure := range []string{"stop", "manual-daemon", "configure", "invalid-key"} {
		t.Run(failure, func(t *testing.T) {
			request, ops, events := enrollmentFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			switch failure {
			case "stop":
				ops.stop = func(context.Context, HostEnrollmentRequest) error {
					*events = append(*events, "stop")
					return errors.New("stop refused")
				}
			case "manual-daemon":
				if err := os.MkdirAll(ops.pkiDir, 0700); err != nil {
					t.Fatal(err)
				}
				lease, err := pki.AcquireHostDomain(context.Background(), ops.pkiDir)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Release()
			case "configure":
				ops.configure = func(context.Context, HostEnrollmentRequest) error { return errors.New("partial setup failure") }
			case "invalid-key":
				request.Key = []byte("private-invalid-marker")
			}
			err := runHostEnrollment(ctx, request, ops)
			if err == nil {
				t.Fatal("failed enrollment reported success")
			}
			if strings.Contains(err.Error(), "private-invalid-marker") {
				t.Fatal("enrollment error disclosed key")
			}
			for _, event := range *events {
				if event == "start" {
					t.Fatal("failed enrollment started daemon")
				}
			}
			if failure != "configure" {
				if _, err := os.Stat(filepath.Join(ops.pkiDir, "ca.crt")); !os.IsNotExist(err) {
					t.Fatal("refused quiescence/input changed active root")
				}
			}
		})
	}
}

func TestPublishedCLIRevocationWaitsForTrustLease(t *testing.T) {
	fixture := newRenewFixture(t)
	dir := fixture.op
	if err := pki.GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "operator-host", nil); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	view, err := pki.CaptureHostTrust(ctx, dir, "operator-host")
	if err != nil {
		t.Fatal(err)
	}
	pair, err := pki.ServedHostKeyPair(dir)
	if err != nil {
		t.Fatal(err)
	}
	cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, "operator-host")
	if err != nil {
		t.Fatal(err)
	}
	lease, err := pki.AcquireHostCertificateLease(ctx, dir, cap)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	done := make(chan error, 1)
	go func() { done <- revokeReplaced(ctx, fixture.client, "node-r", "abc123") }()
	select {
	case err := <-done:
		t.Fatalf("CLI published CRL through active trust lease: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	lease.Release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CLI CRL writer did not resume")
	}
}

func TestLegacyHostCacheCleanupCannotRemoveActiveOrAliasedIdentity(t *testing.T) {
	for _, kind := range []string{"host", "ca", "traversal", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			active := filepath.Join(root, "active")
			if err := os.Mkdir(active, 0700); err != nil {
				t.Fatal(err)
			}
			mustCA(t, active)
			if err := pki.GenerateHostCert(filepath.Join(active, "ca.crt"), filepath.Join(active, "ca.key"), filepath.Join(active, "host.crt"), filepath.Join(active, "host.key"), "host", nil); err != nil {
				t.Fatal(err)
			}
			cache, name, stem := active, "host", "host"
			if kind == "ca" {
				name, stem = "ca", "ca"
			}
			if kind == "traversal" {
				cache = filepath.Join(root, "operator")
				if err := os.Mkdir(cache, 0700); err != nil {
					t.Fatal(err)
				}
				name = "../active/host"
			}
			if kind == "symlink" || kind == "hardlink" {
				name = "alias"
				for _, suffix := range []string{".crt", ".key"} {
					src, dst := filepath.Join(active, "host"+suffix), filepath.Join(active, "alias"+suffix)
					var err error
					if kind == "symlink" {
						err = os.Symlink(src, dst)
					} else {
						err = os.Link(src, dst)
					}
					if err != nil {
						t.Fatal(err)
					}
				}
			}
			certBytes, err := os.ReadFile(filepath.Join(active, stem+".crt"))
			if err != nil {
				t.Fatal(err)
			}
			cert, err := pki.ParseCertPEM(certBytes)
			if err != nil {
				t.Fatal(err)
			}
			keyBefore, err := os.ReadFile(filepath.Join(cache, name+".key"))
			if err != nil {
				t.Fatal(err)
			}
			removeCAMachineCopy(cache, name, cert)
			keyAfter, err := os.ReadFile(filepath.Join(cache, name+".key"))
			if err != nil || string(keyAfter) != string(keyBefore) {
				t.Fatalf("legacy cache cleanup removed active or aliased identity (%s): %v", kind, err)
			}
		})
	}
}

func TestEnrollmentStagingNeverUsesHostNameAsActivePath(t *testing.T) {
	source := t.TempDir()
	mustCA(t, source)
	if err := pki.GenerateHostCert(filepath.Join(source, "ca.crt"), filepath.Join(source, "ca.key"), filepath.Join(source, "host.crt"), filepath.Join(source, "host.key"), "original-host", nil); err != nil {
		t.Fatal(err)
	}
	before := map[string]string{}
	for _, name := range []string{"ca.crt", "ca.key", "host.crt", "host.key"} {
		b, err := os.ReadFile(filepath.Join(source, name))
		if err != nil {
			t.Fatal(err)
		}
		before[name] = string(b)
	}
	for _, host := range []string{"host", "ca", "../host", "client"} {
		staged, err := stageHostEnrollmentIdentity(source, host, "127.0.0.1")
		if host == "../host" {
			if err == nil {
				staged.remove()
				t.Fatal("traversal host accepted")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if filepath.Dir(staged.dir) == source {
			t.Fatal("staged host private key remained in active directory")
		}
		cert, err := os.ReadFile(staged.cert)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := pki.ParseCertPEM(cert)
		if err != nil || leaf.Subject.CommonName != host {
			t.Fatal("staging changed requested identity", err)
		}
		keyInfo, err := os.Stat(staged.key)
		if err != nil || keyInfo.Mode().Perm() != 0600 {
			t.Fatal("staged private key was not private", err)
		}
		staged.remove()
		for name, want := range before {
			got, err := os.ReadFile(filepath.Join(source, name))
			if err != nil || string(got) != want {
				t.Fatalf("staging host %q changed active %s", host, name)
			}
		}
	}
}

func TestCLIClientBundlePreservesActiveTrustDomain(t *testing.T) {
	for _, kind := range []string{"same-ca-inode", "foreign-ca-alias", "held-lease", "missing-hosts"} {
		t.Run(kind, func(t *testing.T) {
			fixture := newRenewFixture(t)
			active := fixture.op
			if err := pki.GenerateHostCert(filepath.Join(active, "ca.crt"), filepath.Join(active, "ca.key"), filepath.Join(active, "host.crt"), filepath.Join(active, "host.key"), "operator-host", nil); err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			view, err := pki.CaptureHostTrust(ctx, active, "operator-host")
			if err != nil {
				t.Fatal(err)
			}
			source := t.TempDir()
			for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
				b, err := os.ReadFile(filepath.Join(active, name))
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(source, name), b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			alias := filepath.Join(t.TempDir(), "alias")
			if err := os.Symlink(active, alias); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(filepath.Join(active, "ca.crt"))
			if err != nil {
				t.Fatal(err)
			}
			rootBefore, err := os.ReadFile(filepath.Join(active, "ca.crt"))
			if err != nil {
				t.Fatal(err)
			}
			if kind == "foreign-ca-alias" || kind == "missing-hosts" {
				mustCA(t, source)
			}
			if kind == "missing-hosts" {
				for _, name := range []string{"host.crt", "host.key"} {
					if err := os.Remove(filepath.Join(active, name)); err != nil {
						t.Fatal(err)
					}
				}
			}
			if kind == "held-lease" {
				pair, err := pki.ServedHostKeyPair(active)
				if err != nil {
					t.Fatal(err)
				}
				cap, err := view.ValidateHostCertificate(ctx, pair.Certificate, "operator-host")
				if err != nil {
					t.Fatal(err)
				}
				lease, err := pki.AcquireHostCertificateLease(ctx, active, cap)
				if err != nil {
					t.Fatal(err)
				}
				defer lease.Release()
				done := make(chan error, 1)
				go func() { done <- installCLIClientBundle(source, cliPKITarget{dir: alias}) }()
				select {
				case err := <-done:
					t.Fatalf("CLI CA classification/write crossed trust lease: %v", err)
				case <-time.After(100 * time.Millisecond):
				}
				lease.Release()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			} else {
				err := installCLIClientBundle(source, cliPKITarget{dir: alias})
				if kind == "same-ca-inode" {
					if err != nil {
						t.Fatal(err)
					}
				} else if err == nil {
					t.Fatal("CLI bundle replaced an established active root")
				}
			}
			after, err := os.Stat(filepath.Join(active, "ca.crt"))
			if err != nil {
				t.Fatal(err)
			}
			rootAfter, err := os.ReadFile(filepath.Join(active, "ca.crt"))
			if err != nil {
				t.Fatal(err)
			}
			if !os.SameFile(before, after) || string(rootAfter) != string(rootBefore) {
				t.Fatal("CLI bundle rewrote active CA inode")
			}
		})
	}
}

func TestHostInitDoesNotRegenerateMissingEstablishedOperatorCA(t *testing.T) {
	for _, local := range []bool{false, true} {
		for _, kind := range []string{"active-files", "pinned-missing-files", "orphan-key"} {
			t.Run(fmt.Sprintf("local=%v/%s", local, kind), func(t *testing.T) {
				dir := addOperatorPKI(t)
				useConfig(t, "")
				t.Setenv("SUDO_USER", "")
				oldKey, err := os.ReadFile(filepath.Join(dir, "ca.key"))
				if err != nil {
					t.Fatal(err)
				}
				if kind != "orphan-key" {
					if err := pki.GenerateHostCert(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), filepath.Join(dir, "host.crt"), filepath.Join(dir, "host.key"), "operator", nil); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "pinned-missing-files" {
					if _, err := pki.CaptureHostTrust(context.Background(), dir, "operator"); err != nil {
						t.Fatal(err)
					}
					for _, name := range []string{"host.crt", "host.key", "ca.key"} {
						if err := os.Remove(filepath.Join(dir, name)); err != nil {
							t.Fatal(err)
						}
					}
				}
				if err := os.Remove(filepath.Join(dir, "ca.crt")); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(t.TempDir(), "operator-alias")
				if err := os.Symlink(dir, alias); err != nil {
					t.Fatal(err)
				}
				t.Setenv("LITEVIRT_PKI_DIR", alias)
				remote := &enrollmentRemoteFixture{}
				oldConnect := connectEnrollmentRemote
				connectEnrollmentRemote = func(string) (enrollmentConnection, error) { return remote, nil }
				defer func() { connectEnrollmentRemote = oldConnect }()
				oldLocal := enrollLocalHost
				enrollLocalHost = func(context.Context, HostEnrollmentRequest) error { return nil }
				defer func() { enrollLocalHost = oldLocal }()
				if local {
					err = HostInitLocal(context.Background(), "new-host", "127.0.0.1", false)
				} else {
					err = HostInit(context.Background(), "root@127.0.0.1", "new-host", false)
				}
				if err == nil {
					t.Error("host init treated missing established CA as fresh workstation authority")
				}
				if _, err := os.Lstat(filepath.Join(dir, "ca.crt")); !os.IsNotExist(err) {
					t.Error("host init regenerated active or unknown operator root before quiescence")
				}
				if kind != "pinned-missing-files" {
					got, err := os.ReadFile(filepath.Join(dir, "ca.key"))
					if err != nil || !bytes.Equal(got, oldKey) {
						t.Error("refused initialization replaced existing CA key")
					}
				}
			})
		}
	}
}
