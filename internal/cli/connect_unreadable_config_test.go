package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unreadableDaemonConfig points daemonConfigPath at a config.yaml this user
// cannot read, as a non-root user meets the 0600 root-owned file on a node.
func unreadableDaemonConfig(t *testing.T) string {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file: the permission error cannot be produced")
	}
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte("host_name: node1\ngrpc_port: 7443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	old := daemonConfigPath
	daemonConfigPath = p
	t.Cleanup(func() { daemonConfigPath = old })
	t.Setenv("LV_HOST", "")
	return p
}

// A non-root user on a node, given a CLI bundle by `sudo lv host init
// --local`, keeps working once config.yaml is 0600: local mode, over that
// bundle (verified mTLS, as with a readable config), on the port init writes.
//
// Mutation: drop the permission branch in LoadClusterConfig: red ("LV_HOST
// not set").
func TestLoadClusterConfig_UnreadableConfigUsesTheUsersCLIBundle(t *testing.T) {
	unreadableDaemonConfig(t)
	userConfig := filepath.Join(t.TempDir(), "user-config")
	t.Setenv("LV_CONFIG_DIR", userConfig)
	userPKI := filepath.Join(userConfig, "pki")
	if err := os.MkdirAll(userPKI, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.crt", "client.crt", "client.key"} {
		if err := os.WriteFile(filepath.Join(userPKI, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	cfg, err := LoadClusterConfig()
	if err != nil {
		t.Fatalf("LoadClusterConfig: %v", err)
	}
	if !cfg.Local || cfg.DefaultHost != "" {
		t.Errorf("cfg = %+v, want local mode", cfg)
	}
	if cfg.PKIDir != userPKI {
		t.Errorf("PKIDir = %q, want the user's CLI bundle %q", cfg.PKIDir, userPKI)
	}
	if cfg.GRPCPort != 7443 {
		t.Errorf("GRPCPort = %d, want 7443", cfg.GRPCPort)
	}
}

// With no endpoint file either, the defaults are taken and the output says
// so, naming the file it could not read and what it used.
//
// Mutation: take the defaults without the notice: red.
func TestLoadClusterConfig_UnreadableConfigSaysItTookTheDefaults(t *testing.T) {
	p := unreadableDaemonConfig(t)
	userConfig := filepath.Join(t.TempDir(), "user-config")
	t.Setenv("LV_CONFIG_DIR", userConfig)
	writeUserBundle(t, filepath.Join(userConfig, "pki"))
	notices := captureNotices(t)

	if _, err := LoadClusterConfig(); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{p, "defaults", "127.0.0.1:7443", filepath.Join(userConfig, "pki")} {
		if !strings.Contains(notices.String(), want) {
			t.Errorf("notice %q does not name %q", notices, want)
		}
	}
	if strings.Contains(notices.String(), "LV_HOST not set") {
		t.Errorf("notice still says LV_HOST not set: %q", notices)
	}
}

// With no bundle, the error names the file that cannot be read and both ways
// out, instead of claiming there is no config at all.
//
// Mutation: return the generic "LV_HOST not set" error on a permission
// error: red.
func TestLoadClusterConfig_UnreadableConfigWithoutABundleNamesTheFile(t *testing.T) {
	p := unreadableDaemonConfig(t)
	t.Setenv("LV_CONFIG_DIR", filepath.Join(t.TempDir(), "user-config"))

	cfg, err := LoadClusterConfig()
	if err == nil {
		t.Fatalf("LoadClusterConfig = %+v, want an error", cfg)
	}
	for _, want := range []string{p, "LV_HOST", "sudo"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name %q", err, want)
		}
	}
}
