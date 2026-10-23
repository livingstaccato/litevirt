package cli

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Lab 2 drill F3: a non-root `lv` with no CLI client bundle fell back to the
// daemon's PKI directory, loaded the node's own host.key, and logged
// "host.key is owned by uid 0: chown 1001 /etc/litevirt/pki/host.key":
// advice to give the user the node's private key. A non-root lv uses its own
// CLI bundle and never the node identity.

func asUID(t *testing.T, uid int) {
	t.Helper()
	old := geteuid
	geteuid = func() int { return uid }
	t.Cleanup(func() { geteuid = old })
}

// captureSlog sends the default logger to a buffer for the test.
func captureSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// localNodeConfig points daemonConfigPath at a config naming pkiDir.
func localNodeConfig(t *testing.T, pkiDir string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("grpc_port: 7443\npki_dir: "+pkiDir+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := daemonConfigPath
	daemonConfigPath = path
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")
}

func TestConnect_ANonRootUserIsNeverGivenTheNodeIdentity(t *testing.T) {
	nodePKI := setupTestPKI(t)
	// As on a node: the user cannot read host.key. The refusal must come
	// before anything is read from the daemon's PKI directory, or this
	// user is back to a load error and the chown advice.
	hostKey := filepath.Join(nodePKI, "host.key")
	if err := os.Chmod(hostKey, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hostKey, 0o600) })
	localNodeConfig(t, nodePKI)
	t.Setenv("LV_CONFIG_DIR", t.TempDir()) // no CLI bundle
	asUID(t, 1001)
	logs := captureSlog(t)

	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	_, closer, err := connectLocal(cfg)
	if err == nil {
		closer()
		t.Fatalf("a non-root lv connected with the node identity in %s", nodePKI)
	}
	msg := err.Error()
	if strings.Contains(msg, "load local TLS config") || strings.Contains(msg, "permission denied") {
		t.Errorf("the daemon's PKI directory was read before the refusal: %s", msg)
	}
	if fi, serr := os.Stat(hostKey); serr != nil || fi.Mode().Perm() != 0 {
		t.Errorf("host.key was changed: %v %v", fi, serr)
	}
	for _, want := range []string{"sudo", PKIDir(), "lv host init", "SUDO_USER"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "chown") || strings.Contains(logs.String(), "chown") {
		t.Errorf("a non-root lv was told to chown something: %s | %s", msg, logs.String())
	}
	if strings.Contains(logs.String(), "host.key") {
		t.Errorf("a non-root lv touched the node's host.key: %s", logs.String())
	}
}

// The user's own bundle is what a non-root lv uses.
func TestConnect_ANonRootUserUsesItsCLIBundle(t *testing.T) {
	nodePKI := setupTestPKI(t)
	localNodeConfig(t, nodePKI)
	cfgDir := t.TempDir()
	t.Setenv("LV_CONFIG_DIR", cfgDir)
	bundle := filepath.Join(cfgDir, "pki")
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"ca.crt", "client.crt", "client.key"} {
		data, err := os.ReadFile(filepath.Join(nodePKI, f))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(bundle, f), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	asUID(t, 1001)
	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	if cfg.PKIDir != bundle {
		t.Fatalf("PKIDir = %s, want the CLI bundle %s", cfg.PKIDir, bundle)
	}
	_, closer, err := connectLocal(cfg)
	if err != nil {
		t.Fatalf("connectLocal with the CLI bundle: %v", err)
	}
	closer()
}

// Root on the node uses the daemon's PKI directory, as before.
func TestConnect_RootUsesTheDaemonPKI(t *testing.T) {
	nodePKI := setupTestPKI(t)
	localNodeConfig(t, nodePKI)
	t.Setenv("LV_CONFIG_DIR", t.TempDir())
	asUID(t, 0)
	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	_, closer, err := connectLocal(cfg)
	if err != nil {
		t.Fatalf("root connectLocal: %v", err)
	}
	closer()
}

// The local root channel presents the host certificate, which only root may
// use: a non-root caller is refused before host.key is read.
func TestConnectLocalRoot_RefusesANonRootUser(t *testing.T) {
	nodePKI := setupTestPKI(t)
	hostKey := filepath.Join(nodePKI, "host.key")
	if err := os.Chmod(hostKey, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(hostKey, 0o600) })
	asUID(t, 1001)
	logs := captureSlog(t)
	_, closer, err := ConnectLocalRoot(nodePKI, 7443)
	if err == nil {
		closer()
		t.Fatal("a non-root caller got the local root channel")
	}
	if !strings.Contains(err.Error(), "sudo") || strings.Contains(err.Error(), "chown") ||
		strings.Contains(err.Error(), "load this host's certificate") {
		t.Errorf("refusal = %v, want it to say sudo and never chown", err)
	}
	if strings.Contains(logs.String(), "host.key") {
		t.Errorf("a non-root caller touched host.key: %s", logs.String())
	}
}
