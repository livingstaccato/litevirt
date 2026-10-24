package daemon

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Lab 2 drill F4: a node upgraded in place kept config.yaml 0644; only an add
// tightened it. The daemon tightens its own config to owner-only at start.

func writeMode(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte("grpc_port: 7443\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func modeOf(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func captureDaemonSlog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

func TestTightenConfigFile_RemovesGroupAndOtherBitsOnly(t *testing.T) {
	me := os.Getuid()
	for _, tc := range []struct{ from, want os.FileMode }{
		{0o644, 0o600},
		{0o640, 0o600},
		{0o666, 0o600},
		{0o604, 0o600},
		{0o755, 0o700}, // the owner's own bits are kept, never widened or narrowed
		{0o400, 0o400}, // narrower than 0600: kept
		{0o600, 0o600},
	} {
		path := filepath.Join(t.TempDir(), "config.yaml")
		writeMode(t, path, tc.from)
		logs := captureDaemonSlog(t)
		tightenConfigFileAs(path, me)
		if got := modeOf(t, path); got != tc.want {
			t.Errorf("%#o: mode after = %#o, want %#o", tc.from, got, tc.want)
		}
		logged := strings.Contains(logs.String(), "tightened")
		if changed := tc.from != tc.want; logged != changed {
			t.Errorf("%#o: logged = %v, want %v: %s", tc.from, logged, changed, logs.String())
		}
		// Once: a second start finds nothing to do and says nothing.
		logs.Reset()
		tightenConfigFileAs(path, me)
		if logs.Len() != 0 {
			t.Errorf("%#o: the second start logged: %s", tc.from, logs.String())
		}
	}
}

// A symlinked config.yaml is tightened at its target, and the link is kept.
func TestTightenConfigFile_ActsOnASymlinksTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.yaml")
	writeMode(t, target, 0o644)
	link := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	tightenConfigFileAs(link, os.Getuid())
	if got := modeOf(t, target); got != 0o600 {
		t.Errorf("target mode = %#o, want 0600", got)
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Errorf("the symlink was replaced: %v %v", fi, err)
	}
}

// A config (or a symlink's target) owned by anyone but root is left alone.
func TestTightenConfigFile_LeavesAFileRootDoesNotOwn(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	writeMode(t, path, 0o644)
	logs := captureDaemonSlog(t)
	tightenConfigFileAs(path, os.Getuid()+1)
	if got := modeOf(t, path); got != 0o644 {
		t.Errorf("mode = %#o, want 0644 kept", got)
	}
	if !strings.Contains(logs.String(), "owned by uid") {
		t.Errorf("leaving it said nothing: %s", logs.String())
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	tightenConfigFileAs(link, os.Getuid()+1)
	if got := modeOf(t, path); got != 0o644 {
		t.Errorf("target mode via a symlink = %#o, want 0644 kept", got)
	}
}

// Not a regular file, or missing: nothing is changed, and the daemon starts.
func TestTightenConfigFile_IgnoresAMissingOrIrregularFile(t *testing.T) {
	dir := t.TempDir()
	tightenConfigFileAs(filepath.Join(dir, "absent.yaml"), os.Getuid())
	sub := filepath.Join(dir, "adir")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	tightenConfigFileAs(sub, os.Getuid())
	if got := modeOf(t, sub); got != 0o755 {
		t.Errorf("a directory was changed to %#o", got)
	}
}

// LoadConfig records the path it read, which the start-up tightening acts on.
func TestLoadConfig_RecordsItsPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("host_name: h\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("LITEVIRT_CONFIG", path)
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConfigPath != path {
		t.Errorf("ConfigPath = %q, want %q", cfg.ConfigPath, path)
	}
}

// Run makes the config owner-only at start.
func TestRunTightensItsOwnConfig(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "daemon.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		fd, ok := n.(*ast.FuncDecl)
		if !ok || fd.Name.Name != "Run" || fd.Recv == nil {
			return true
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "tightenOwnConfig" {
					found = true
				}
			}
			return true
		})
		return false
	})
	if !found {
		t.Error("Daemon.Run does not call tightenOwnConfig")
	}
}
