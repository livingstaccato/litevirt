package pbsstore

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// InitUngated and SetCompressionUngated write the release feature backup_zstd's
// data with no gate and no recorded use. Their one legitimate caller is the
// operator's --force override in cmd/litevirt/pbsrepo.go; any other non-test
// caller is a path around the gate.
func TestUngatedWriters_OnlyTheForceOverrideCallsThem(t *testing.T) {
	root := filepath.Join("..", "..")
	allowed := filepath.Join("cmd", "litevirt", "pbsrepo.go")
	var bad []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", ".claude", ".superpowers", "node_modules", "gen":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		if rel == allowed || strings.HasPrefix(rel, filepath.Join("internal", "pbsstore")+string(filepath.Separator)) {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if s := string(b); strings.Contains(s, "InitUngated(") || strings.Contains(s, "SetCompressionUngated(") {
			bad = append(bad, rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range bad {
		t.Errorf("%s calls an ungated zstd writer; only %s (--force) may", f, allowed)
	}
}
