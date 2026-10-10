package capabilities

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The release-feature guard. A release feature's data may be written only
// through health.Checker.WithFeature, which records the feature's use — the
// bit a rolled-back node decides its quarantine on — before it hands the write
// a FeatureGrant. Two shortcuts compile, pass a branch's own tests, and leave
// no used bit:
//
//   - gating on the release token's latch directly (Latched, Enforced,
//     DurablyLatched, CapabilityActive… with the release token), the way every
//     per-feature token was gated before;
//   - minting a FeatureGrant anywhere but the gate.
//
// This test fails the build on either, in non-test code outside the files that
// implement the gate and the status report.

var releaseLatchReaders = map[string]bool{
	"Latched": true, "Enforced": true, "DurablyLatched": true, "CapabilityActive": true,
	"CapabilityActiveForHealth": true, "PeerSupports": true, "PeerSupportsFresh": true,
}

// releaseGuardAllowed are the files that may read the release token's latch.
var releaseGuardAllowed = map[string]bool{
	"internal/health/release_feature.go": true, // the gate itself
	"internal/grpcapi/upgrade_status.go": true, // the status report and the peer-refusal check
}

// mintAllowed are the files that may mint a grant: the gate, and the definition.
var mintAllowed = map[string]bool{
	"internal/health/release_feature.go":        true,
	"internal/capabilities/release_features.go": true,
}

func isReleaseTokenExpr(e ast.Expr) bool {
	switch v := e.(type) {
	case *ast.SelectorExpr:
		return v.Sel.Name == "ReleaseToken" || strings.HasPrefix(v.Sel.Name, "Release20")
	case *ast.Ident:
		return v.Name == "ReleaseToken" || strings.HasPrefix(v.Name, "Release20")
	case *ast.BasicLit:
		if v.Kind == token.STRING {
			s, err := strconv.Unquote(v.Value)
			return err == nil && strings.HasPrefix(s, "release_")
		}
	}
	return false
}

func calleeName(call *ast.CallExpr) string {
	switch f := call.Fun.(type) {
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.Ident:
		return f.Name
	}
	return ""
}

// releaseGuardViolations lists the guard's findings in one parsed file.
func releaseGuardViolations(fset *token.FileSet, f *ast.File, rel string) []string {
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := calleeName(call)
		if name == "MintFeatureGrant" && !mintAllowed[rel] {
			out = append(out, fset.Position(call.Pos()).String()+": MintFeatureGrant outside the release-feature gate")
		}
		if releaseLatchReaders[name] && !releaseGuardAllowed[rel] {
			for _, a := range call.Args {
				if isReleaseTokenExpr(a) {
					out = append(out, fset.Position(call.Pos()).String()+": "+name+
						" on a release token; gate the write with health.Checker.WithFeature")
				}
			}
		}
		return true
	})
	return out
}

func TestReleaseFeatureGuard_NoLatchShortcutsInTheTree(t *testing.T) {
	root := filepath.Join("..", "..")
	fset := token.NewFileSet()
	var violations []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			if rel == "gen" || rel == ".git" || strings.HasPrefix(rel, ".claude") || rel == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		violations = append(violations, releaseGuardViolations(fset, f, rel)...)
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	for _, v := range violations {
		t.Error(v)
	}
}

// The guard has teeth: each shortcut in a file outside the allowlist is found.
func TestReleaseFeatureGuard_FindsEachShortcut(t *testing.T) {
	src := `package x
func f() {
	_ = gate.Enforced(ctx, capabilities.ReleaseToken)
	_ = gate.DurablyLatched(capabilities.Release202611V1)
	_ = gate.Latched("release_2026_11_v1")
	_ = capabilities.MintFeatureGrant("widgets")
	_ = gate.Latched(capabilities.SplitBrainGateV1)
}`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got := releaseGuardViolations(fset, f, "internal/grpcapi/vm.go"); len(got) != 4 {
		t.Fatalf("violations = %v, want the four shortcuts and not the split-brain read", got)
	}
	if got := releaseGuardViolations(fset, f, "internal/health/release_feature.go"); len(got) != 0 {
		t.Fatalf("the gate's own file was flagged: %v", got)
	}
}
