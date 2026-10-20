package corrosion

import (
	"context"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// D2 merge with cand31, review I-1: the firmware return publishes each disk
// row's placement (host, path, driver, pool) as it read them, never
// host_name alone — the same statement as every other disk-row mover
// (TestDiskPlacementMove_PublishesThePlacementItRead).
//
// Mutation: emit the host-only UPDATE (vm_disk_host_move_v130) from
// ReturnMigratedVM — red.
func TestReturnMigratedVM_PublishesThePlacement(t *testing.T) {
	ctx := context.Background()
	c, vm, disks := returnRig(t)
	var before int64
	if err := c.DB().QueryRow(`SELECT COALESCE(MAX(seq), 0) FROM mutation_log`).Scan(&before); err != nil {
		t.Fatal(err)
	}
	if ok, err := ReturnMigratedVM(ctx, c, "fw", "host-b", "host-a", returnUUID, vm.CreatedAt, "stopped", disks); err != nil || !ok {
		t.Fatalf("ReturnMigratedVM: ok=%v err=%v", ok, err)
	}
	rows, err := c.Query(ctx, `SELECT stmts FROM mutation_log WHERE seq > ? ORDER BY seq`, before)
	if err != nil {
		t.Fatal(err)
	}
	placement := mustStatementFingerprint(vmDiskPlacementSQL)
	byDisk := map[string]DiskRecord{}
	for _, d := range disks {
		byDisk[d.DiskName] = d
	}
	found := 0
	for _, r := range rows {
		var stmts []Statement
		if err := json.Unmarshal([]byte(r.String("stmts")), &stmts); err != nil {
			t.Fatal(err)
		}
		for _, s := range stmts {
			sh, _, err := parseResolved(s.SQL)
			if err != nil {
				t.Fatal(err)
			}
			if sh.Table != "vm_disks" {
				continue
			}
			found++
			if fp := stmtFingerprint(sh); fp != placement {
				t.Fatalf("the return published a vm_disks statement of shape %s, want the placement (vmDiskPlacementSQL):\n%s", fp, s.SQL)
			}
			if len(s.Params) != 7 {
				t.Fatalf("params %v", s.Params)
			}
			d, ok := byDisk[coerceString(s.Params[6])]
			if !ok || coerceString(s.Params[5]) != "fw" {
				t.Fatalf("the statement names %v/%v, not one of fw's disks", s.Params[5], s.Params[6])
			}
			want := []string{"host-a", d.Path, d.StorageType, d.StorageVolume}
			for i, w := range want {
				if got := coerceString(s.Params[i]); got != w {
					t.Errorf("disk %s: param %d = %q, want %q", d.DiskName, i, got, w)
				}
			}
		}
	}
	if found != len(disks) {
		t.Fatalf("the return published %d vm_disks statements, want %d", found, len(disks))
	}
}

// D2 merge with cand31, review I-1 (hardening): this build never emits the
// host-only disk move. Its shape stays in the historical ledger so an older
// peer's write is still accepted, and stmtshapecheck accepts a historical
// shape from a current builder, so this test reads every SQL string literal
// of the build's non-test Go source and refuses that shape. The historical
// ledger's own declaration (stmthistorical.go) is the one exception.
//
// Mutation: put the host-only UPDATE back in ReturnMigratedVM — red.
func TestNoCurrentEmitterOfTheHostOnlyDiskMove(t *testing.T) {
	var hostOnly string
	for _, hs := range HistoricalShapes() {
		if hs.Family == "vm_disk_host_move_v130" {
			hostOnly = mustStatementFingerprint(hs.SQL)
		}
	}
	if hostOnly == "" {
		t.Fatal("no historical shape vm_disk_host_move_v130")
	}
	root := filepath.Join("..", "..")
	checked := 0
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, e fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if e.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") ||
				(filepath.Base(p) == "stmthistorical.go" && filepath.Base(filepath.Dir(p)) == "corrosion") {
				return nil
			}
			f, err := parser.ParseFile(token.NewFileSet(), p, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(f, func(n ast.Node) bool {
				expr, ok := n.(ast.Expr)
				if !ok {
					return true
				}
				sql, ok := stringConstant(expr)
				if !ok || !strings.Contains(strings.ToUpper(sql), "VM_DISKS") || !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "UPDATE") {
					return true
				}
				checked++
				sh, _, err := parseResolved(sql)
				if err != nil {
					return false
				}
				if stmtFingerprint(sh) == hostOnly {
					t.Errorf("%s emits the host-only disk move (vm_disk_host_move_v130), which this build only accepts from older peers:\n%s", p, sql)
				}
				return false
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked == 0 {
		t.Fatal("no UPDATE vm_disks literal found: the scan reads nothing")
	}
}

// stringConstant is the value of a string literal, or of a + of string
// literals.
func stringConstant(e ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		l, ok := stringConstant(v.X)
		if !ok {
			return "", false
		}
		r, ok := stringConstant(v.Y)
		return l + r, ok
	case *ast.ParenExpr:
		return stringConstant(v.X)
	}
	return "", false
}
