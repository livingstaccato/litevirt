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
