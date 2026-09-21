package grpcapi

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/qcow2"
)

// A VM row inserted at "running" lands at the vm_owner_epoch column default of
// 0, and nothing routine graduates it: convergeOwnerEpochMarker returns early on
// a zero epoch, and the backfill sweep that would fix it is gated behind
// enforcement.owner_epoch, which is OFF by default. Such a VM is running and
// unprovable, permanently, on a default cluster.
//
// assignOwnerEpochAtCreate is the one thing that closes that window, and it was
// wired into CreateVM only. Three other producers — promote, clone and
// live-restore autostart — insert a running VM and were missed, which is the
// shape this scan exists to stop recurring: the invariant lives at the INSERT,
// so it has to be checked at every insert rather than remembered at one.
//
// A site that genuinely must not graduate opts out with a trailing
// `//ownerepoch:allow <reason>` comment inside the enclosing function.
func TestEveryVMBornRunningIsGraduatedOffEpochZero(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}

	var violations []string
	scanned, found := 0, 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		scanned++
		f, perr := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if perr != nil {
			t.Fatalf("parse %s: %v", name, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if funcHasAllowComment(f, fn) {
				continue
			}
			lits := bornRunningVMRecords(fn)
			if len(lits) == 0 {
				continue
			}
			found += len(lits)
			if callsAssignOwnerEpoch(fn) {
				continue
			}
			for _, pos := range lits {
				violations = append(violations, filepath.Base(name)+":"+
					itoa(fset.Position(pos).Line)+" in "+fn.Name.Name)
			}
		}
	}

	if scanned == 0 {
		t.Fatal("scanned no production files; the scan is not looking at anything")
	}
	if found == 0 {
		t.Fatal("found no corrosion.VMRecord inserted at a running or runtime-determined " +
			"state anywhere; the matcher is broken, not the code")
	}
	for _, v := range violations {
		t.Errorf("%s: a corrosion.VMRecord is built at a running (or runtime-determined) "+
			"state with no assignOwnerEpochAtCreate call in the same function. It would be "+
			"born at vm_owner_epoch 0, which convergence never repairs and the default-off "+
			"backfill never graduates — a running VM nobody can prove.", v)
	}
}

// bornRunningVMRecords returns the positions of corrosion.VMRecord literals in
// fn whose State is the literal "running", or an expression whose value is only
// known at runtime. A literal state that is anything else cannot publish a
// running VM and is exempt.
func bornRunningVMRecords(fn *ast.FuncDecl) []token.Pos {
	var out []token.Pos
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "VMRecord" {
			return true
		}
		pkg, ok := sel.X.(*ast.Ident)
		if !ok || pkg.Name != "corrosion" {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := kv.Key.(*ast.Ident)
			if !ok || key.Name != "State" {
				continue
			}
			if bl, ok := kv.Value.(*ast.BasicLit); ok {
				if bl.Kind == token.STRING && strings.Trim(bl.Value, `"`) == "running" {
					out = append(out, lit.Pos())
				}
				return true // a literal that is not "running" cannot publish one
			}
			// Not a literal: only known at runtime, so it may be "running".
			out = append(out, lit.Pos())
		}
		return true
	})
	return out
}

func callsAssignOwnerEpoch(fn *ast.FuncDecl) bool {
	found := false
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "assignOwnerEpochAtCreate" {
			found = true
			return false
		}
		return true
	})
	return found
}

func funcHasAllowComment(f *ast.File, fn *ast.FuncDecl) bool {
	for _, cg := range f.Comments {
		if cg.Pos() < fn.Pos() || cg.End() > fn.End() {
			continue
		}
		if strings.Contains(cg.Text(), "ownerepoch:allow") {
			return true
		}
	}
	return false
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// The scan above proves the call SITE exists; it cannot prove the call is
// reached. A clone started at creation must come out at a positive owner epoch,
// through the real CloneVM.
func TestCloneVM_AStartedCloneIsProvable(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	srcDisk := s.images.DiskPath("src", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 64*1024*1024, nil); err != nil {
		t.Fatalf("create source qcow2: %v", err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "src", Cpu: 1, MemoryMib: 512})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "src", HostName: "test-host", State: "stopped", Spec: string(specJSON)},
		nil,
		[]corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "test-host",
			Path: srcDisk, SizeBytes: 64 * 1024 * 1024, StorageType: "local"}},
	); err != nil {
		t.Fatalf("InsertVM src: %v", err)
	}

	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{
		Source: "src", Target: "clone1", Mode: "full", Start: true,
	}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}

	rows, err := s.db.Query(ctx, `SELECT vm_owner_epoch FROM vms WHERE name = ?`, "clone1")
	if err != nil {
		t.Fatalf("read clone epoch: %v", err)
	}
	if len(rows) == 0 {
		t.Fatal("no row for the clone")
	}
	if got := rows[0].Int64("vm_owner_epoch"); got == 0 {
		t.Fatal("the started clone is at vm_owner_epoch 0 — convergence returns early on a " +
			"zero epoch and the default-off backfill never graduates it, so this running VM " +
			"is permanently unprovable")
	}
}
