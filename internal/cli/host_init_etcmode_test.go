package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func modeOf(t *testing.T, p string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

// The fence ssh AuthorizedKeysCommand runs as nobody and must traverse
// /etc/litevirt. `lv host init --local` made it 0700 as a side effect of
// MkdirAll(pki, 0700); the remote form leaves it 0755.
func TestEnsureEtcLitevirtDir_Modes(t *testing.T) {
	for _, tc := range []struct {
		name        string
		start, want os.FileMode
	}{
		{"0700 gains search only", 0o700, 0o701},
		{"0750 gains search only", 0o750, 0o751},
		{"0755 untouched", 0o755, 0o755},
		{"0711 untouched", 0o711, 0o711},
		{"0500 gains search only", 0o500, 0o501},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "litevirt")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			secret := filepath.Join(dir, "admin-password")
			if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(dir, tc.start); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
			for i := 0; i < 2; i++ { // idempotent
				if err := ensureEtcLitevirtDir(dir); err != nil {
					t.Fatal(err)
				}
				if got := modeOf(t, dir); got != tc.want {
					t.Fatalf("pass %d: dir mode %o, want %o", i, got, tc.want)
				}
			}
			_ = os.Chmod(dir, 0o700)
			if got := modeOf(t, secret); got != 0o600 {
				t.Fatalf("secret file mode %o, want 600", got)
			}
		})
	}
}

func TestEnsureEtcLitevirtDir_CreatesSearchableNotListable(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	dir := filepath.Join(t.TempDir(), "a", "litevirt")
	if err := ensureEtcLitevirtDir(dir); err != nil {
		t.Fatal(err)
	}
	if got := modeOf(t, dir); got != 0o711 {
		t.Fatalf("created mode %o, want 711", got)
	}
}

// HostInitLocal must open the directory before any MkdirAll creates it 0700.
// The run fails later (it cannot write the real /etc/litevirt/pki unprivileged),
// which is fine: the directory is fixed before that point.
func TestHostInitLocal_OpensEtcLitevirtBeforeCreatingChildren(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("would write the real /etc/litevirt")
	}
	etc := filepath.Join(t.TempDir(), "litevirt")
	if err := os.Mkdir(etc, 0o700); err != nil {
		t.Fatal(err)
	}
	oldCfg := daemonConfigPath
	daemonConfigPath = filepath.Join(etc, "absent.yaml")
	old := etcLitevirtDir
	etcLitevirtDir = etc
	t.Cleanup(func() { daemonConfigPath = oldCfg; etcLitevirtDir = old; _ = os.Chmod(etc, 0o700) })
	t.Setenv("LV_CONFIG_DIR", filepath.Join(etc, "cfg"))

	_ = HostInitLocal(context.Background(), "node-1", "10.77.0.11", true)
	if got := modeOf(t, etc); got&0o001 == 0 {
		t.Fatalf("the config dir is %o after init --local; nobody cannot traverse it", got)
	}
}

// The remote form's setup script covers the same two cases: a directory it
// creates, and one an earlier init left 0700.
func TestSetupScript_EtcLitevirtIsSearchable(t *testing.T) {
	s, err := getSetupScript()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"mkdir -p -m 0711 /etc/litevirt\nchmod o+x /etc/litevirt\n",
		"install -d -m 0755 /etc/litevirt/ssh\n    chmod o+x /etc/litevirt\n",
	} {
		if !strings.Contains(s, want) {
			t.Fatalf("setup script lacks %q", want)
		}
	}
}
