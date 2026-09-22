package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/corrosion"
)

// `lv rm base --keep-disks` exists so linked clones stay valid: it
// tombstones the base's rows and leaves base-root.qcow2 on disk, still named by
// every overlay's backing_disk. Creating a NEW VM that reuses the name then runs
// the debris glob for "base-*.qcow2" — and the keep set it is given is derived
// from the named VM's LIVE rows, of which a freshly-created name has none by
// construction (createVM refuses a duplicate live name before reaching here).
//
// So the guard cannot protect anything on that path, the base file is removed,
// and every clone's backing chain is destroyed with no recovery.
func TestProtectedDiskPaths_ProtectsABaseStillBackingALiveClone(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	basePath := s.images.DiskPath("base", "root")
	if err := os.MkdirAll(filepath.Dir(basePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, []byte("base image"), 0o644); err != nil {
		t.Fatal(err)
	}

	// A live linked clone whose overlay still names the base as its backing file.
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "clone1", HostName: "test-host", State: "stopped"},
		nil,
		[]corrosion.DiskRecord{{
			VMName: "clone1", DiskName: "root", HostName: "test-host",
			Path: s.images.DiskPath("clone1", "root"), StorageType: "local",
			BackingDisk: basePath,
		}},
	); err != nil {
		t.Fatalf("InsertVM clone1: %v", err)
	}

	// The base itself has NO live rows — it was deleted with --keep-disks, and a
	// new VM is about to be created under the same name.
	keep := s.protectedDiskPaths(ctx, "base")
	if err := s.images.DeleteVMDisks("base", keep); err != nil {
		t.Fatalf("DeleteVMDisks: %v", err)
	}

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		t.Fatal("the debris glob deleted a base image that a live linked clone still names as " +
			"its backing file — every overlay's chain is destroyed, unrecoverably, and " +
			"--keep-disks exists precisely to prevent this")
	}
}

// protectedDiskPaths' own comment claims it "Fails CLOSED in both directions".
// Returning nil on a read error protects nothing, so the glob then deletes every
// <vm>-*.qcow2 including a live clone base — a transient SQLITE_BUSY is enough.
func TestProtectedDiskPaths_FailsClosedWhenItCannotRead(t *testing.T) {
	s, _ := provableCreateServer(t)
	ctx := adminCtx()

	basePath := s.images.DiskPath("base", "root")
	if err := os.MkdirAll(filepath.Dir(basePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(basePath, []byte("base image"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Make every disk read fail.
	s.db.Close()

	keep := s.protectedDiskPaths(ctx, "base")
	if err := s.images.DeleteVMDisks("base", keep); err != nil {
		t.Fatalf("DeleteVMDisks: %v", err)
	}

	if _, err := os.Stat(basePath); os.IsNotExist(err) {
		t.Fatal("a failed disk read let the glob delete everything — the read that decides " +
			"whether a file is still referenced cannot fail OPEN, which is what the function's " +
			"own comment already claims it does not do")
	}
}

// No caller may pass protectedDiskPaths straight into DeleteVMDisks.
//
// That pairing is the fail-open: on a listing failure protectedDiskPaths returns
// an EMPTY keep set, which protects nothing, while its log line claimed the
// opposite. It survived only because DeleteVMDisks re-lists and bails on the
// same error — so the safety rested on two independent calls failing
// identically, and no behavioural test can tell the two apart precisely BECAUSE
// the coincidence holds. (Verified: removing the guard leaves every test green.)
//
// What is checkable is the shape. sweepVMDiskDebris owns the pairing and refuses
// to glob when the candidate list is unreadable, so the guarantee is stated in
// one place instead of emerging from a coincidence.
func TestNoCallerPairsProtectedPathsWithTheGlobDirectly(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var bad []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, perr := parser.ParseFile(fset, n, nil, 0)
		if perr != nil {
			t.Fatalf("parse %s: %v", n, perr)
		}
		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			// sweepVMDiskDebris OWNS the pairing — that is the point of it. It
			// guards the listing first, so the empty-keep-set case never reaches
			// the glob. Everything else must go through it.
			if fn.Name.Name == "sweepVMDiskDebris" {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "DeleteVMDisks" {
					return true
				}
				for _, a := range call.Args {
					inner, ok := a.(*ast.CallExpr)
					if !ok {
						continue
					}
					if isel, ok := inner.Fun.(*ast.SelectorExpr); ok && isel.Sel.Name == "protectedDiskPaths" {
						bad = append(bad, n+":"+itoa(fset.Position(call.Pos()).Line))
					}
				}
				return true
			})
		}
	}
	for _, b := range bad {
		t.Errorf("%s: DeleteVMDisks is called with protectedDiskPaths inline. On a listing "+
			"failure that pair deletes with an empty keep set; route it through "+
			"sweepVMDiskDebris, which refuses to glob when it cannot build the list.", b)
	}
}
