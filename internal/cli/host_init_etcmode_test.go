package cli

import (
	"context"
	"os"
	"os/exec"
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

// setupEtcLines is what the setup script runs on /etc/litevirt, with the
// directory renamed to etc.
func setupEtcLines(t *testing.T, etc string) string {
	t.Helper()
	const lines = "mkdir -p -m 0711 /etc/litevirt\nchmod o+x /etc/litevirt\n"
	s, err := getSetupScript()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(s, lines) {
		t.Fatalf("setup script lacks %q", lines)
	}
	return strings.ReplaceAll(lines, "/etc/litevirt", etc)
}

// Lab 4 finding 3: a remote-added host's /etc/litevirt came out 0755, so any
// user could list it, where `lv host init --local` gives 0711. The add (and
// the remote init) ran a plain `mkdir -p /etc/litevirt/pki` under umask 022
// first, and the setup script's `mkdir -p -m 0711 /etc/litevirt` then
// changed nothing. Run as the host runs them, under umask 022: the add's own
// command, then the setup script's lines. A directory they create is 0711;
// one the operator made keeps its mode, gaining only the search bit.
//
// Mutation: back to `mkdir -p <pki>` alone — "created by the add" is 0755.
func TestHostAdd_EtcLitevirtIsCreated0711(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	for _, tc := range []struct {
		name        string
		start, want os.FileMode // start 0: the machine has no /etc/litevirt
	}{
		{"created by the add", 0, 0o711},
		{"the operator's 0750", 0o750, 0o751},
		{"the operator's 0755", 0o755, 0o755},
		{"the operator's 0700", 0o700, 0o701},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAddFixture(t)
			etc := filepath.Join(f.target.Root, "etc", "litevirt")
			if err := os.RemoveAll(etc); err != nil {
				t.Fatal(err)
			}
			if tc.start != 0 {
				if err := os.Mkdir(etc, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Chmod(etc, tc.start); err != nil {
					t.Fatal(err)
				}
			}
			if err := f.add(t); err != nil {
				t.Fatal(err)
			}
			if tc.start != 0 && modeOf(t, etc) != tc.start {
				t.Fatalf("the add changed the operator's %o to %o", tc.start, modeOf(t, etc))
			}
			if out, err := exec.Command("sh", "-c", setupEtcLines(t, etc)).CombinedOutput(); err != nil {
				t.Fatalf("setup lines: %v: %s", err, out)
			}
			if got := modeOf(t, etc); got != tc.want {
				t.Fatalf("/etc/litevirt is %o after add and setup, want %o", got, tc.want)
			}
		})
	}
}

// The remote init runs the same command before it pushes anything.
func TestRemotePKIDirsCmd_Init(t *testing.T) {
	old := syscall.Umask(0o022)
	defer syscall.Umask(old)
	etc := filepath.Join(t.TempDir(), "litevirt")
	cmd := remotePKIDirsCmd(etc, filepath.Join(etc, "pki")) + "\n" + setupEtcLines(t, etc)
	if out, err := exec.Command("sh", "-c", cmd).CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if got := modeOf(t, etc); got != 0o711 {
		t.Fatalf("/etc/litevirt is %o after init, want 711", got)
	}
}
