package main

import (
	"golang.org/x/tools/go/packages"
	"path/filepath"
	"testing"
)

func TestLifecycleWrappersTraceAndRefuseUnknownSQL(t *testing.T) {
	path, err := filepath.Abs("../../../internal/corrosion/automation_scanner_fixture.go")
	if err != nil {
		t.Fatal(err)
	}
	source := []byte(`package corrosion
 import "context"
 func LifecycleStatic(ctx context.Context,c *Client)error{return c.executeLifecycleBatch(ctx,[]Statement{{SQL:usersInsertSQL}},"principal","name","birth")}
 func LifecycleDynamic(ctx context.Context,c *Client,text string)error{return c.executeLifecycleBatch(ctx,[]Statement{{SQL:text}},"principal","name","birth")}
 func CredentialUnregistered(ctx context.Context,c *Client)error{return c.executeCredentialBatch(ctx,nil,"token","id","name",[]Statement{{SQL:"INSERT INTO tokens (id, bogus_extra) VALUES (?, ?)"}})}
 func CredentialCallerBatch(ctx context.Context,c *Client,stmts []Statement)error{return c.executeCredentialBatch(ctx,nil,"token","id","name",stmts)}
 `)
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps, Overlay: map[string][]byte{path: source}}
	pkgs, err := packages.Load(cfg, "../../../internal/corrosion")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 || len(pkgs) != 1 {
		t.Fatal("scanner fixture failed to load")
	}
	found := map[string][]finding{}
	for _, f := range scanPkg(pkgs[0]) {
		found[f.fn] = append(found[f.fn], f)
	}
	for _, name := range []string{"LifecycleStatic", "LifecycleDynamic", "CredentialUnregistered", "CredentialCallerBatch"} {
		if len(found[name]) != 1 {
			t.Fatalf("%s: expected one actual emitted statement, got %+v", name, found[name])
		}
		gaps := computeGaps(found[name])
		if name == "LifecycleStatic" {
			if len(gaps) != 0 {
				t.Fatalf("registered literal rejected: %v", gaps)
			}
		} else if len(gaps) == 0 {
			t.Fatalf("%s: unsafe SQL hidden by wrapper", name)
		}
	}
	for _, name := range []string{"InsertUser", "InsertToken", "InsertSessionWithLoginData"} {
		if len(found[name]) == 0 {
			t.Fatalf("real emitting builder %s lost statement coverage", name)
		}
	}
}

// TestGuardedLifecycleWrappersTraceAndRefuseUnknownSQL binds scanner coverage to
// both guarded lifecycle sinks, including the real project builder's provenance.
func TestGuardedLifecycleWrappersTraceAndRefuseUnknownSQL(t *testing.T) {
	path, err := filepath.Abs("../../../internal/corrosion/automation_guarded_scanner_fixture.go")
	if err != nil {
		t.Fatal(err)
	}
	source := []byte(`package corrosion
 import "context"
 func GuardedBatchStatic(ctx context.Context,c *Client)(bool,error){return c.executeGuardedLifecycleBatch(ctx,nil,[]Statement{{SQL:"UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?"},{SQL:usersInsertSQL}},"project","name","birth")}
 func GuardedBatchDynamic(ctx context.Context,c *Client,text string)(bool,error){return c.executeGuardedLifecycleBatch(ctx,nil,[]Statement{{SQL:text}},"project","name","birth")}
 func GuardedBatchUnregistered(ctx context.Context,c *Client)(bool,error){return c.executeGuardedLifecycleBatch(ctx,nil,[]Statement{{SQL:"INSERT INTO tokens (id, bogus_extra) VALUES (?, ?)"}},"project","name","birth")}
 func GuardedBatchCaller(ctx context.Context,c *Client,stmts []Statement)(bool,error){return c.executeGuardedLifecycleBatch(ctx,nil,stmts,"project","name","birth")}
 func GuardedBatchMethodValue(c *Client){_ = c.executeGuardedLifecycleBatch}
 func GuardedEntriesStatic(ctx context.Context,c *Client)(bool,error){return c.executeEntriesGuardedWithLifecycle(ctx,nil,[][]Statement{{{SQL:"UPDATE projects SET deleted_at = ?, updated_at = ? WHERE name = ?"}},{{SQL:usersInsertSQL}}},nil)}
 func GuardedEntriesDynamic(ctx context.Context,c *Client,text string)(bool,error){return c.executeEntriesGuardedWithLifecycle(ctx,nil,[][]Statement{{{SQL:text}}},nil)}
 func GuardedEntriesUnregistered(ctx context.Context,c *Client)(bool,error){return c.executeEntriesGuardedWithLifecycle(ctx,nil,[][]Statement{{{SQL:"INSERT INTO tokens (id, bogus_extra) VALUES (?, ?)"}}},nil)}
 func GuardedEntriesCaller(ctx context.Context,c *Client,entries [][]Statement)(bool,error){return c.executeEntriesGuardedWithLifecycle(ctx,nil,entries,nil)}
 func GuardedEntriesMethodValue(c *Client){_ = c.executeEntriesGuardedWithLifecycle}
 type guardedScannerForeign struct{}
 func (*guardedScannerForeign) executeGuardedLifecycleBatch(context.Context,interface{},[]Statement,string,string,string)(bool,error){return true,nil}
 func (*guardedScannerForeign) executeEntriesGuardedWithLifecycle(context.Context,interface{},[][]Statement,interface{})(bool,error){return true,nil}
 func GuardedBatchForeign(ctx context.Context,c *guardedScannerForeign,text string)(bool,error){return c.executeGuardedLifecycleBatch(ctx,nil,[]Statement{{SQL:text}},"project","name","birth")}
 func GuardedEntriesForeign(ctx context.Context,c *guardedScannerForeign,text string)(bool,error){return c.executeEntriesGuardedWithLifecycle(ctx,nil,[][]Statement{{{SQL:text}}},nil)}
 `)
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedImports | packages.NeedDeps, Tests: false, Overlay: map[string][]byte{path: source}}
	pkgs, err := packages.Load(cfg, "../../../internal/corrosion")
	if err != nil {
		t.Fatal(err)
	}
	if packages.PrintErrors(pkgs) > 0 || len(pkgs) != 1 {
		t.Fatal("guarded scanner fixture failed to load")
	}
	found := map[string][]finding{}
	for _, f := range scanPkg(pkgs[0]) {
		found[f.fn] = append(found[f.fn], f)
	}
	const projectUpdate = "stmtshape/v1:e604ad221360f11ea0365f523a7b1fd3c3ab1aad24f148d5cdcb66db305ed725"
	for _, prefix := range []string{"GuardedBatch", "GuardedEntries"} {
		for _, kind := range []string{"Static", "Dynamic", "Unregistered", "Caller", "MethodValue", "Foreign"} {
			name := prefix + kind
			t.Run(name, func(t *testing.T) {
				got := found[name]
				want := 1
				if kind == "Static" {
					want = 2
				} else if kind == "Foreign" {
					want = 0
				}
				if len(got) != want {
					t.Fatalf("%s: got %d findings, want %d: %+v", name, len(got), want, got)
				}
				if kind == "Foreign" {
					return
				}
				gaps := computeGaps(got)
				if kind == "Static" {
					if len(gaps) != 0 {
						t.Fatalf("registered literals rejected: %v", gaps)
					}
					n := 0
					for _, f := range got {
						if f.fp == projectUpdate {
							n++
						}
					}
					if n != 1 {
						t.Fatalf("project UPDATE fingerprint occurrences = %d, want 1: %+v", n, got)
					}
					return
				}
				if len(gaps) == 0 {
					t.Fatalf("%s: unsafe SQL hidden by wrapper", name)
				}
				switch kind {
				case "Dynamic":
					if !got[0].dynamic {
						t.Fatal("dynamic SQL misclassified")
					}
				case "Unregistered":
					if got[0].fp == "" || got[0].dynamic || got[0].unresolvedBatch || got[0].parseErr != "" {
						t.Fatal("unregistered literal must resolve before ledger refusal")
					}
				case "Caller":
					if !got[0].unresolvedBatch {
						t.Fatal("caller input must fail as unresolved batch")
					}
				case "MethodValue":
					if !got[0].methodValue {
						t.Fatal("method value must fail closed")
					}
				}
			})
		}
	}
	t.Run("ProjectBuilderProvenance", func(t *testing.T) {
		n := 0
		for _, f := range found["commitProjectLifecycle"] {
			if f.fp == projectUpdate {
				n++
			}
		}
		// Revive and delete are separate literal sites with this exact shape.
		if n != 2 {
			t.Fatalf("commitProjectLifecycle UPDATE findings = %d, want 2", n)
		}
	})
	t.Run("PlumbingExcluded", func(t *testing.T) {
		for _, name := range []string{"executeGuardedLifecycleBatch", "executeEntriesGuardedWithLifecycle"} {
			if len(found[name]) != 0 {
				t.Errorf("plumbing %s misclassified as builder: %+v", name, found[name])
			}
		}
	})
}
