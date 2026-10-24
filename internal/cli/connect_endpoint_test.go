package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/endpointfile"
)

// TestMain keeps every test off this machine's real /run/litevirt/endpoint
// (a test run on a node would otherwise dial its daemon's values) and out of
// the fallback notices; a test that needs either sets its own.
func TestMain(m *testing.M) {
	dispatchEnrollmentC1Role()
	endpointPath = filepath.Join(os.TempDir(), "litevirt-cli-test-no-endpoint", "endpoint")
	cliNotice = io.Discard
	// A test cannot create root's files: the endpoint files these tests
	// write are this user's (endpointfile tests the owner check itself).
	endpointfile.SetReaderOwnerForTest(os.Getuid())
	os.Exit(m.Run())
}

func useEndpointFile(t *testing.T, body string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "run")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil { // not the umask's: a group-writable dir is refused
		t.Fatal(err)
	}
	p := filepath.Join(dir, "endpoint")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0o644); err != nil {
		t.Fatal(err)
	}
	old := endpointPath
	endpointPath = p
	t.Cleanup(func() { endpointPath = old })
	return p
}

func captureNotices(t *testing.T) *bytes.Buffer {
	t.Helper()
	var b bytes.Buffer
	old := cliNotice
	cliNotice = &b
	t.Cleanup(func() { cliNotice = old })
	return &b
}

func readableDaemonConfig(t *testing.T, body string) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	old := daemonConfigPath
	daemonConfigPath = p
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")
	t.Setenv("LV_CONFIG_DIR", filepath.Join(t.TempDir(), "user-config"))
}

// lv reads the daemon's endpoint file before config.yaml.
//
// Mutation: skip the endpoint file: red (config.yaml's port).
func TestLoadClusterConfig_PrefersTheDaemonsEndpointFile(t *testing.T) {
	readableDaemonConfig(t, "grpc_port: 9443\npki_dir: /cfg/pki\n")
	useEndpointFile(t, "grpc_port: 9555\npki_dir: /ep/pki\n")
	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Local || cfg.GRPCPort != 9555 || cfg.PKIDir != "/ep/pki" {
		t.Fatalf("cfg = %+v, want local mode on the endpoint file's 9555 and /ep/pki", cfg)
	}
}

// With config.yaml unreadable, the endpoint file is all a non-root lv needs:
// its port, and the user's own bundle in place of the daemon's PKI dir.
func TestLoadClusterConfig_UnreadableConfigUsesTheEndpointFile(t *testing.T) {
	unreadableDaemonConfig(t)
	userConfig := filepath.Join(t.TempDir(), "user-config")
	t.Setenv("LV_CONFIG_DIR", userConfig)
	writeUserBundle(t, filepath.Join(userConfig, "pki"))
	useEndpointFile(t, "grpc_port: 9555\npki_dir: /etc/litevirt/pki\n")
	notices := captureNotices(t)

	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Local || cfg.GRPCPort != 9555 || cfg.PKIDir != filepath.Join(userConfig, "pki") {
		t.Fatalf("cfg = %+v, want local mode on 9555 with the user's bundle", cfg)
	}
	if notices.Len() != 0 {
		t.Errorf("a usable endpoint file still printed a fallback notice: %q", notices)
	}
}

// A malformed endpoint file is not trusted in any part: lv says it ignores
// it and goes on to config.yaml.
//
// Mutations: use a file Read refused (its partly decoded values): red.
// Ignore it without a word: red.
func TestLoadClusterConfig_AMalformedEndpointFileIsIgnored(t *testing.T) {
	for name, body := range map[string]string{
		"unknown key":   "grpc_port: 9555\npki_dir: /ep/pki\nbind_password: x\n",
		"relative pki":  "grpc_port: 9555\npki_dir: ep/pki\n",
		"not yaml":      "grpc_port: [\n",
		"port too high": "grpc_port: 95550\npki_dir: /ep/pki\n",
	} {
		t.Run(name, func(t *testing.T) {
			readableDaemonConfig(t, "grpc_port: 9443\npki_dir: /cfg/pki\n")
			p := useEndpointFile(t, body)
			notices := captureNotices(t)
			cfg, err := LoadClusterConfig()
			if err != nil {
				t.Fatal(err)
			}
			if cfg.GRPCPort != 9443 || cfg.PKIDir != "/cfg/pki" {
				t.Fatalf("cfg = %+v, want config.yaml's 9443 and /cfg/pki", cfg)
			}
			if !strings.Contains(notices.String(), "ignoring") || !strings.Contains(notices.String(), p) {
				t.Errorf("notice = %q, want it to say it ignores %s", notices, p)
			}
		})
	}
}

func writeUserBundle(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// An endpoint file someone other than its owner could have written is a
// trust anchor nobody vouches for: lv ignores it, says so, and goes on.
//
// Mutation: drop the mode check in endpointfile.Read: red.
func TestLoadClusterConfig_AnEndpointFileOthersCanWriteIsIgnored(t *testing.T) {
	readableDaemonConfig(t, "grpc_port: 9443\npki_dir: /cfg/pki\n")
	p := useEndpointFile(t, "grpc_port: 9555\npki_dir: /attacker/pki\n")
	if err := os.Chmod(p, 0o666); err != nil {
		t.Fatal(err)
	}
	notices := captureNotices(t)
	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PKIDir != "/cfg/pki" || cfg.GRPCPort != 9443 {
		t.Fatalf("cfg = %+v: an endpoint file others can write was trusted", cfg)
	}
	if !strings.Contains(notices.String(), "ignoring") || !strings.Contains(notices.String(), "writable") {
		t.Errorf("notice = %q, want it to say the file is ignored as writable by others", notices)
	}
}
