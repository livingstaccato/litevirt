package filerestoretest

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// m-6: this package and the agent parse guest data on the host; only tests
// (and, for the agent, the binary's main, to become the agent inside a
// restore VM) may import them.
func TestNoProductionImport(t *testing.T) {
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..", "..")
	allowedAgent := map[string]bool{filepath.Join("cmd", "litevirt", "main.go"): true}
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (d.Name() == ".git" || d.Name() == "node_modules" || d.Name() == "gen") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if strings.HasPrefix(rel, filepath.Join("internal", "filerestore", "agent")) ||
			strings.HasPrefix(rel, filepath.Join("internal", "filerestore", "filerestoretest")) {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		src := string(b)
		if strings.Contains(src, `"github.com/litevirt/litevirt/internal/filerestore/filerestoretest"`) {
			t.Errorf("%s imports filerestoretest (tests only)", rel)
		}
		if strings.Contains(src, `"github.com/litevirt/litevirt/internal/filerestore/agent"`) && !allowedAgent[rel] {
			t.Errorf("%s imports the restore agent; only cmd/litevirt/main.go may", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
