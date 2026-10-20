package main

import (
	"go/ast"
	"go/constant"
	"go/types"
	"path/filepath"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
	"golang.org/x/tools/go/packages"
)

func TestSnapshotClaimCallbackScanner(t *testing.T) {
	path, err := filepath.Abs("../../../internal/corrosion/snapshot_callback_scanner_fixture.go")
	if err != nil {
		t.Fatal(err)
	}
	source := []byte(`package corrosion
import ("context"; "database/sql")
func SnapshotScanStatic(ctx context.Context,c *Client,op OperationRecord)(bool,error){return c.executeSnapshotClaim(ctx,func(*sql.Tx)([]Statement,error){return snapshotClaimStatements(op,"{}","{}",snapshotClaimFacts{}),nil})}
func SnapshotScanDynamic(ctx context.Context,c *Client,text string)(bool,error){return c.executeSnapshotClaim(ctx,func(*sql.Tx)([]Statement,error){return []Statement{{SQL:text}},nil})}
func SnapshotScanOpaqueCallback(ctx context.Context,c *Client,prepare func(*sql.Tx)([]Statement,error))(bool,error){return c.executeSnapshotClaim(ctx,prepare)}
func SnapshotScanOpaqueBatch(ctx context.Context,c *Client,stmts []Statement)(bool,error){return c.executeSnapshotClaim(ctx,func(*sql.Tx)([]Statement,error){return stmts,nil})}
func SnapshotScanMethodValue(c *Client){_ = c.executeSnapshotClaim}
type snapshotScannerForeign struct{}
func (*snapshotScannerForeign) executeSnapshotClaim(context.Context,func(*sql.Tx)([]Statement,error))(bool,error){return false,nil}
func SnapshotScanForeign(ctx context.Context,c *snapshotScannerForeign,text string)(bool,error){return c.executeSnapshotClaim(ctx,func(*sql.Tx)([]Statement,error){return []Statement{{SQL:text}},nil})}
func SnapshotScanDirect(ctx context.Context,c *Client,op OperationRecord)error{return c.ExecuteBatch(ctx,[]Statement{operationInsertStatement(op,"wall","now",nil),operationStepInsertStatement(op.ID,0,OpStepPlanned,"{}","wall","now",nil)})}
func SnapshotScanCapturedConditional(ctx context.Context, c *Client, stmts []Statement, choose bool) (bool, error) {
    return c.executeSnapshotClaim(ctx, func(*sql.Tx) ([]Statement, error) {
        if choose {
            stmts = []Statement{{SQL: usersInsertSQL}}
        }
        return stmts, nil
    })
}
func SnapshotScanCapturedNestedOnly(ctx context.Context, c *Client, stmts []Statement) (bool, error) {
    return c.executeSnapshotClaim(ctx, func(*sql.Tx) ([]Statement, error) {
        _ = func() { stmts = []Statement{{SQL: usersInsertSQL}} }
        return stmts, nil
    })
}
`)
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps, Tests: false, Overlay: map[string][]byte{path: source}}
	pkgs, err := packages.Load(cfg, "../../../internal/corrosion")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) != 0 || len(pkgs) != 1 {
		t.Fatal("snapshot callback typed fixture failed to load")
	}
	pkg := pkgs[0]
	constantSQL := func(name string) string {
		t.Helper()
		obj, ok := pkg.Types.Scope().Lookup(name).(*types.Const)
		if !ok || obj.Val().Kind() != constant.String {
			t.Fatalf("missing real constant %s", name)
		}
		return constant.StringVal(obj.Val())
	}
	fingerprint := func(sql string) string {
		t.Helper()
		fp, err := corrosion.FingerprintSQL(sql)
		if err != nil {
			t.Fatalf("expected real SQL must parse: %v", err)
		}
		return fp
	}
	update := fingerprint(constantSQL("vmSnapshotClaimSQL"))
	header := fingerprint("INSERT INTO operations (" + constantSQL("operationCols") + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)")
	planned := fingerprint("INSERT INTO operation_steps (operation_id, owner_epoch, step_name, facts, created_at, updated_at, deleted_at) VALUES (?, ?, ?, ?, ?, ?, NULL)")
	for _, fp := range []string{header, planned} {
		if _, ok := corrosion.LedgerLookup(fp); !ok {
			t.Fatal("existing journal INSERT control is unregistered")
		}
	}
	found := map[string][]finding{}
	for _, f := range scanPkg(pkg) {
		found[f.fn] = append(found[f.fn], f)
	}
	for _, role := range []struct{ name, fp string }{{"ActualUpdate", update}, {"ActualHeader", header}, {"ActualPlanned", planned}} {
		t.Run(role.name, func(t *testing.T) {
			got := found["BeginVMOperationAtSnapshot"]
			n := 0
			for _, f := range got {
				if f.dynamic || f.unresolvedBatch || f.methodValue || f.parseErr != "" {
					t.Fatalf("real callback has unresolved finding: %+v", f)
				}
				if f.fp == role.fp {
					n++
				}
			}
			// Both retry and first-claim returns reach the real three-role helper.
			if len(got) != 6 || n != 2 {
				t.Fatalf("snapshot callback actual %s: findings=%d matching=%d, want 6/2", role.name, len(got), n)
			}
		})
	}
	t.Run("StaticHelper", func(t *testing.T) {
		got := found["SnapshotScanStatic"]
		counts := map[string]int{}
		for _, f := range got {
			if f.dynamic || f.unresolvedBatch || f.methodValue || f.parseErr != "" {
				t.Fatalf("static callback unresolved: %+v", f)
			}
			counts[f.fp]++
		}
		if len(got) != 3 || counts[update] != 1 || counts[header] != 1 || counts[planned] != 1 {
			t.Fatalf("snapshot callback static roles: got %d findings, want three exact roles", len(got))
		}
		// The new UPDATE need not be registered until the separate generator step.
	})
	for _, tc := range []struct{ name, fn, flag string }{
		{"DynamicSQL", "SnapshotScanDynamic", "dynamic"},
		{"OpaqueCallback", "SnapshotScanOpaqueCallback", "unresolved"},
		{"OpaqueBatch", "SnapshotScanOpaqueBatch", "unresolved"},
		{"MethodValue", "SnapshotScanMethodValue", "method"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := found[tc.fn]
			if len(got) != 1 {
				t.Fatalf("snapshot callback %s: findings=%d, want one refusing finding", tc.name, len(got))
			}
			f := got[0]
			valid := tc.flag == "dynamic" && f.dynamic || tc.flag == "unresolved" && f.unresolvedBatch || tc.flag == "method" && f.methodValue
			if !valid || len(computeGaps(got)) != 1 {
				t.Fatalf("snapshot callback %s did not fail closed: %+v", tc.name, got)
			}
		})
	}
	for _, tc := range []struct{ name, fn string }{
		{"CapturedConditional", "SnapshotScanCapturedConditional"},
		{"CapturedNestedOnly", "SnapshotScanCapturedNestedOnly"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := found[tc.fn]
			if len(got) != 1 || !got[0].unresolvedBatch || len(computeGaps(got)) != 1 {
				t.Fatalf("captured callback batch must remain unresolved: %+v", got)
			}
		})
	}
	t.Run("ForeignReceiver", func(t *testing.T) {
		if len(found["SnapshotScanForeign"]) != 0 {
			t.Fatal("foreign receiver was treated as a corrosion sink")
		}
	})
	t.Run("ExistingDirectControl", func(t *testing.T) {
		got := found["SnapshotScanDirect"]
		if len(got) != 2 || got[0].fp != header || got[1].fp != planned || len(computeGaps(got)) != 0 {
			t.Fatalf("existing direct journal control failed: %+v", got)
		}
	})
	t.Run("PlumbingRegistered", func(t *testing.T) {
		seen := false
		for _, file := range pkg.Syntax {
			for _, decl := range file.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if ok && fd.Recv != nil && fd.Name.Name == "executeSnapshotClaim" && isCorrosionClient(pkg.TypesInfo.TypeOf(fd.Recv.List[0].Type)) {
					seen = true
					if !isPlumbingMethod(pkg, fd) {
						t.Fatal("snapshot callback sink is not registered as Client plumbing")
					}
				}
			}
		}
		if !seen || len(found["executeSnapshotClaim"]) != 0 {
			t.Fatal("snapshot callback real plumbing missing or scanned as a builder")
		}
	})
}
