package corrosion

import (
	"go/ast"
	"go/token"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The firewall-tags key guard (spec §4.3, m-1). Only the store's own files
// write a cluster_policies key under firewall_tags/ or firewall_tag_group/:
// any other non-test function that both names such a key (a literal, a
// constant folding to one, or the exported prefix constants) and writes (a
// SetClusterPolicy or Execute* call, or the table's upsert statement) is
// flagged. A reader that only queries a key is not a writer. The writers
// that take an arbitrary key (SetClusterPolicy, SetPoolRecord,
// WriteNetworkVLANsCAS) count as writes too, and each must refuse the
// reserved prefixes at runtime through refuseReservedPolicyKey: the
// arbitrary-key guard finds every corrosion function that hands the upsert a
// key that is not a fixed prefix, and fails on one not listed or not
// refusing.
//
// The authority guard: the FWTagAuthority minter is claimed once, by
// internal/grpcapi, and handed only to Server.fwTagAuthority, which checks
// sg.write, and returns on its error, before it mints; no package-level value
// mints; only newFWTagAuthority builds a non-zero FWTagAuthority; and
// FWTagAuthorityForTest has no non-test caller.

// firewallTagsKeyWriterFiles may write the reserved keys.
var firewallTagsKeyWriterFiles = map[string]bool{
	"internal/corrosion/firewall_tags.go":      true,
	"internal/corrosion/firewall_tag_group.go": true,
}

// arbitraryKeyPolicyWriters are the corrosion functions that write a
// cluster_policies key their caller chooses. Each refuses the reserved
// prefixes (refuseReservedPolicyKey), and a write through one counts as a
// write in the key rule.
var arbitraryKeyPolicyWriters = []string{"SetClusterPolicy", "SetPoolRecord", "WriteNetworkVLANsCAS"}

var reservedTagKeyPrefixes = []string{FirewallTagsKeyPrefix, FirewallTagGroupKeyPrefix}

var reservedTagKeyConsts = map[string]bool{"FirewallTagsKeyPrefix": true, "FirewallTagGroupKeyPrefix": true}

// namesReservedTagKey reports whether body names a reserved key.
func namesReservedTagKey(body ast.Node, scopes []map[string]ast.Expr) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *ast.BasicLit:
			if v.Kind == token.STRING {
				if s, err := strconv.Unquote(v.Value); err == nil {
					for _, p := range reservedTagKeyPrefixes {
						found = found || strings.Contains(s, p)
					}
				}
			}
		case *ast.SelectorExpr:
			found = found || reservedTagKeyConsts[v.Sel.Name]
		case *ast.Ident:
			if reservedTagKeyConsts[v.Name] {
				found = true
			} else if s, ok := constString(v, scopes, 0); ok {
				for _, p := range reservedTagKeyPrefixes {
					found = found || strings.Contains(s, p)
				}
			}
		}
		return !found
	})
	return found
}

// writesClusterPolicy reports whether body makes a write a key could reach.
func writesClusterPolicy(body ast.Node) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if found {
			return false
		}
		switch v := n.(type) {
		case *ast.Ident:
			found = v.Name == "clusterPolicyUpsertSQL"
		case *ast.CallExpr:
			var name string
			switch f := v.Fun.(type) {
			case *ast.Ident:
				name = f.Name
			case *ast.SelectorExpr:
				name = f.Sel.Name
			}
			found = slices.Contains(arbitraryKeyPolicyWriters, name) || strings.HasPrefix(name, "Execute")
		}
		return !found
	})
	return found
}

// firewallTagsKeyViolations applies the key rule.
func firewallTagsKeyViolations(pkgs []goPackage) []string {
	var bad []string
	for _, p := range pkgs {
		scope := map[string]ast.Expr{}
		for _, f := range p.files {
			stringConsts(f.Decls, scope)
		}
		for i, f := range p.files {
			if firewallTagsKeyWriterFiles[p.paths[i]] {
				continue
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				local := map[string]ast.Expr{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if gen, ok := n.(*ast.GenDecl); ok {
						collectValueSpecs(gen, local)
					}
					return true
				})
				scopes := []map[string]ast.Expr{local, scope}
				if namesReservedTagKey(fd.Body, scopes) && writesClusterPolicy(fd.Body) {
					bad = append(bad, p.paths[i]+": "+funcKey(fd)+" writes a firewall_tags/ or firewall_tag_group/ key outside the store")
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
}

func TestFirewallTagsKeyGuard(t *testing.T) {
	if bad := firewallTagsKeyViolations(repoPackages(t)); len(bad) > 0 {
		t.Fatalf("firewall tags key guard:\n  %s", strings.Join(bad, "\n  "))
	}
}

// The guard flags a fixture SetClusterPolicy(…, "firewall_tags/x"), a write
// through the upsert with the exported prefix, a key folded from a constant,
// and a reserved key handed to SetPoolRecord or WriteNetworkVLANsCAS; a reader
// is not flagged.
//
// Mutations: skip the literal check — red; count only SetClusterPolicy as an
// arbitrary-key write (D2c review I-1) — pool and vlans pass: red.
func TestFirewallTagsKeyGuard_FlagsAFixture(t *testing.T) {
	src := `package grpcapi

const groupKey = "firewall_tag_group/"

func literal() { corrosion.SetClusterPolicy(ctx, db, "firewall_tags/x", "", "me") }
func prefix(id string) { c.Execute(ctx, clusterPolicyUpsertSQL, corrosion.FirewallTagsKeyPrefix+"vm/"+id, "", "me", ts) }
func folded() { corrosion.SetClusterPolicy(ctx, db, groupKey+"web", "{}", "me") }
func reader(id string) { c.Query(ctx, "SELECT value FROM cluster_policies WHERE key = ?", corrosion.FirewallTagsKeyPrefix+id) }
func other() { corrosion.SetClusterPolicy(ctx, db, "firewall_trunk_vlans_recorded", "{}", "me") }
func pool(id string) { corrosion.SetPoolRecord(ctx, db, corrosion.FirewallTagsKeyPrefix+"vm/"+id, "", "me") }
func vlans() { corrosion.WriteNetworkVLANsCAS(ctx, db, snap, nil, map[string]string{"firewall_tag_group/x": "{}"}, "me") }
`
	got := firewallTagsKeyViolations([]goPackage{fixturePackage(t, "internal/grpcapi", src)})
	want := []string{"folded", "literal", "pool", "prefix", "vlans"}
	if len(got) != len(want) {
		t.Fatalf("flagged %v, want exactly %v", got, want)
	}
	for i, w := range want {
		if !strings.Contains(got[i], " "+w+" writes") {
			t.Errorf("flag %d = %q, want %s", i, got[i], w)
		}
	}
}

// policyUpsertKeys returns the key expressions body hands
// clusterPolicyUpsertSQL: the argument after it in a call, and the first
// element of a Statement literal's Params beside it.
func policyUpsertKeys(body ast.Node) []ast.Expr {
	var out []ast.Expr
	isUpsert := func(e ast.Expr) bool { id, ok := e.(*ast.Ident); return ok && id.Name == "clusterPolicyUpsertSQL" }
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.CallExpr:
			for i, a := range v.Args {
				if isUpsert(a) && i+1 < len(v.Args) {
					out = append(out, v.Args[i+1])
				}
			}
		case *ast.CompositeLit:
			var sqlIsUpsert bool
			var params ast.Expr
			for _, el := range v.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if k, ok := kv.Key.(*ast.Ident); ok {
					switch k.Name {
					case "SQL":
						sqlIsUpsert = isUpsert(kv.Value)
					case "Params":
						params = kv.Value
					}
				}
			}
			if pl, ok := params.(*ast.CompositeLit); ok && sqlIsUpsert && len(pl.Elts) > 0 {
				out = append(out, pl.Elts[0])
			}
		}
		return true
	})
	return out
}

// fixedPrefixKey reports whether key starts with a constant string (a literal,
// a constant, or a concatenation led by one), or is built by a call (a key
// builder with its own prefix). A bare variable, a parameter, an index or a
// field is a key the caller chose.
func fixedPrefixKey(key ast.Expr, scopes []map[string]ast.Expr) bool {
	for {
		switch v := key.(type) {
		case *ast.ParenExpr:
			key = v.X
			continue
		case *ast.BinaryExpr:
			key = v.X
			continue
		case *ast.CallExpr:
			return true
		}
		break
	}
	s, ok := constString(key, scopes, 0)
	return ok && s != ""
}

// arbitraryKeyWriterViolations: in internal/corrosion, every function that
// hands the cluster_policies upsert a key it did not fix is listed in
// arbitraryKeyPolicyWriters and calls refuseReservedPolicyKey; every listed
// one exists.
func arbitraryKeyWriterViolations(pkgs []goPackage) []string {
	var bad []string
	found := map[string]bool{}
	for _, p := range pkgs {
		if p.dir != "internal/corrosion" {
			continue
		}
		scope := map[string]ast.Expr{}
		for _, f := range p.files {
			stringConsts(f.Decls, scope)
		}
		for i, f := range p.files {
			if firewallTagsKeyWriterFiles[p.paths[i]] {
				continue // the store builds its keys with firewallTagsKey
			}
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				local := map[string]ast.Expr{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if gen, ok := n.(*ast.GenDecl); ok {
						collectValueSpecs(gen, local)
					}
					return true
				})
				arbitrary := false
				for _, k := range policyUpsertKeys(fd.Body) {
					if !fixedPrefixKey(k, []map[string]ast.Expr{local, scope}) {
						arbitrary = true
					}
				}
				if !arbitrary {
					continue
				}
				name := funcKey(fd)
				found[name] = true
				switch {
				case !slices.Contains(arbitraryKeyPolicyWriters, name):
					bad = append(bad, p.paths[i]+": "+name+" writes a cluster_policies key its caller chooses; "+
						"list it in arbitraryKeyPolicyWriters and refuse the reserved prefixes (refuseReservedPolicyKey)")
				case !callsFunc(fd.Body, "refuseReservedPolicyKey"):
					bad = append(bad, p.paths[i]+": "+name+" does not refuse the reserved prefixes (refuseReservedPolicyKey)")
				}
			}
		}
	}
	for _, w := range arbitraryKeyPolicyWriters {
		if !found[w] {
			bad = append(bad, w+": listed in arbitraryKeyPolicyWriters but writes no caller-chosen key; remove it")
		}
	}
	sort.Strings(bad)
	return bad
}

func TestArbitraryKeyPolicyWritersRefuseTheReservedPrefixes(t *testing.T) {
	if bad := arbitraryKeyWriterViolations(repoPackages(t)); len(bad) > 0 {
		t.Fatalf("arbitrary-key cluster_policies writers:\n  %s", strings.Join(bad, "\n  "))
	}
}

// The arbitrary-key guard flags an unlisted writer of a caller-chosen key, and
// a listed one that does not refuse; a fixed-prefix key, a folded constant and
// a key builder are not caller-chosen.
//
// Mutation: treat every key as fixed — red.
func TestArbitraryKeyPolicyWriters_FlagsAFixture(t *testing.T) {
	src := `package corrosion

const prefix = "iso_catalog/"

func SetClusterPolicy(key string) { refuseReservedPolicyKey(key); c.Execute(ctx, clusterPolicyUpsertSQL, key, "", "", ts) }
func SetPoolRecord(key string) { c.Execute(ctx, clusterPolicyUpsertSQL, key, "", "", ts) }
func WriteNetworkVLANsCAS(keys map[string]string) {
	for k := range keys { refuseReservedPolicyKey(k) }
	for k := range keys { stmts = append(stmts, Statement{SQL: clusterPolicyUpsertSQL, Params: []interface{}{k, keys[k]}}) }
}
func sneaky(key string) { c.Execute(ctx, clusterPolicyUpsertSQL, key, "", "", ts) }
func fixed(name string) { c.Execute(ctx, clusterPolicyUpsertSQL, prefix+name, "", "", ts) }
func built(vm, mac string) { c.Execute(ctx, clusterPolicyUpsertSQL, NICGuardKey(vm, mac), "", "", ts) }
`
	got := arbitraryKeyWriterViolations([]goPackage{fixturePackage(t, "internal/corrosion", src)})
	if len(got) != 2 || !strings.Contains(got[0], "SetPoolRecord does not refuse") || !strings.Contains(got[1], "sneaky writes a cluster_policies key its caller chooses") {
		t.Fatalf("flagged %v, want SetPoolRecord (no refusal) and sneaky (unlisted)", got)
	}
}

// fwTagAuthorityViolations: ClaimFWTagAuthorityMinter is called only in a
// package-level value of internal/grpcapi; the minted function's variable is
// referenced only by Server.fwTagAuthority, which checks sg.write
// (requireSGWrite); FWTagAuthorityForTest has no non-test caller.
func fwTagAuthorityViolations(pkgs []goPackage) []string {
	const home = "internal/grpcapi"
	var bad []string
	minterVars := map[string]bool{}
	for _, p := range pkgs {
		for i, f := range p.files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for j, v := range vs.Values {
							if callsFunc(v, "ClaimFWTagAuthorityMinter") {
								if p.dir != home || j >= len(vs.Names) {
									bad = append(bad, p.paths[i]+": claims the firewall-tags authority minter outside "+home)
									continue
								}
								minterVars[vs.Names[j].Name] = true
							}
						}
					}
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					if callsFunc(d.Body, "ClaimFWTagAuthorityMinter") {
						bad = append(bad, p.paths[i]+": "+funcKey(d)+" claims the firewall-tags authority minter")
					}
					if callsFunc(d.Body, "FWTagAuthorityForTest") {
						bad = append(bad, p.paths[i]+": "+funcKey(d)+" calls FWTagAuthorityForTest outside a test")
					}
				}
			}
		}
	}
	var mintVar []string
	for v := range minterVars {
		mintVar = append(mintVar, v)
	}
	for _, p := range pkgs {
		for i, f := range p.files {
			for _, decl := range f.Decls {
				switch d := decl.(type) {
				case *ast.GenDecl:
					// A package-level value (or a func literal in one)
					// that calls the minter hands out an authority no
					// sg.write check stands behind.
					for _, spec := range d.Specs {
						vs, ok := spec.(*ast.ValueSpec)
						if !ok {
							continue
						}
						for _, v := range vs.Values {
							if usesAny(v, mintVar) {
								bad = append(bad, p.paths[i]+": a package-level value mints a firewall-tags authority")
							}
						}
					}
				case *ast.FuncDecl:
					if d.Body == nil {
						continue
					}
					forgesFWTagAuthority(d, p, i, &bad)
					if !usesAny(d.Body, mintVar) {
						continue
					}
					switch {
					case p.dir != home || funcKey(d) != "Server.fwTagAuthority":
						bad = append(bad, p.paths[i]+": "+funcKey(d)+" mints a firewall-tags authority; only Server.fwTagAuthority may")
					case !checksSGWriteBeforeMinting(d.Body, mintVar):
						bad = append(bad, p.paths[i]+": Server.fwTagAuthority mints without first returning on requireSGWrite's error")
					}
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
}

// checksSGWriteBeforeMinting reports whether, before the first statement
// that uses the minter, body has `if err := …requireSGWrite(…); err != nil {
// … return … }`.
func checksSGWriteBeforeMinting(body *ast.BlockStmt, mintVar []string) bool {
	for _, st := range body.List {
		if usesAny(st, mintVar) {
			return false
		}
		ifs, ok := st.(*ast.IfStmt)
		if !ok || ifs.Init == nil {
			continue
		}
		as, ok := ifs.Init.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || !callsFunc(as.Rhs[0], "requireSGWrite") {
			continue
		}
		errName, ok := as.Lhs[0].(*ast.Ident)
		cond, cok := ifs.Cond.(*ast.BinaryExpr)
		if !ok || !cok || cond.Op != token.NEQ {
			continue
		}
		x, xok := cond.X.(*ast.Ident)
		y, yok := cond.Y.(*ast.Ident)
		if !xok || !yok || x.Name != errName.Name || y.Name != "nil" {
			continue
		}
		returns := false
		ast.Inspect(ifs.Body, func(n ast.Node) bool {
			if _, ok := n.(*ast.ReturnStmt); ok {
				returns = true
			}
			return !returns
		})
		if returns {
			return true
		}
	}
	return false
}

// forgesFWTagAuthority flags a non-zero FWTagAuthority literal outside
// newFWTagAuthority: only that constructor builds one.
func forgesFWTagAuthority(fd *ast.FuncDecl, p goPackage, i int, bad *[]string) {
	if p.dir == "internal/corrosion" && funcKey(fd) == "newFWTagAuthority" {
		return
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		cl, ok := n.(*ast.CompositeLit)
		if !ok || len(cl.Elts) == 0 {
			return true
		}
		named := false
		switch t := cl.Type.(type) {
		case *ast.Ident:
			named = t.Name == "FWTagAuthority"
		case *ast.SelectorExpr:
			named = t.Sel.Name == "FWTagAuthority"
		}
		if named {
			*bad = append(*bad, p.paths[i]+": "+funcKey(fd)+" builds a non-zero FWTagAuthority; only newFWTagAuthority may")
		}
		return true
	})
}

func TestFWTagAuthorityGuard(t *testing.T) {
	pkgs := repoPackages(t)
	if bad := fwTagAuthorityViolations(pkgs); len(bad) > 0 {
		t.Fatalf("firewall-tags authority guard:\n  %s", strings.Join(bad, "\n  "))
	}
	// Guard the guard: the one claim exists.
	claimed := false
	for _, p := range pkgs {
		for _, f := range p.files {
			if p.dir == "internal/grpcapi" && callsFunc(f, "ClaimFWTagAuthorityMinter") {
				claimed = true
			}
		}
	}
	if !claimed {
		t.Fatal("internal/grpcapi does not claim the firewall-tags authority minter")
	}
}

// Mutations: drop the requireSGWrite requirement — the fixture's unchecked
// mint passes: red; skip package-level values — red; accept any call to
// requireSGWrite (D2c review M-2) — the ignored-error fixture passes: red;
// skip the composite-literal check (M-3) — red.
func TestFWTagAuthorityGuard_FlagsAFixture(t *testing.T) {
	src := `package grpcapi

var mint = corrosion.ClaimFWTagAuthorityMinter()

var cached = mint()
var hook = func() corrosion.FWTagAuthority { return mint() }

func (s *Server) fwTagAuthority(ctx context.Context) (corrosion.FWTagAuthority, error) { return mint(), nil }
func (s *Server) sneaky() corrosion.FWTagAuthority { return mint() }
func shortcut(t testing.TB) { _ = corrosion.FWTagAuthorityForTest(t) }
`
	got := fwTagAuthorityViolations([]goPackage{fixturePackage(t, "internal/grpcapi", src)})
	n := 0
	for _, g := range got {
		if strings.Contains(g, "a package-level value mints") {
			n++
		}
	}
	if n != 2 {
		t.Errorf("package-level mints flagged %d times, want 2 (cached, hook): %v", n, got)
	}
	for _, want := range []string{"Server.fwTagAuthority mints without first returning", "Server.sneaky mints", "shortcut calls FWTagAuthorityForTest"} {
		found := false
		for _, g := range got {
			found = found || strings.Contains(g, want)
		}
		if !found {
			t.Errorf("not flagged: %q (got %v)", want, got)
		}
	}
	// The check must precede the mint and its error must be returned.
	for name, body := range map[string]string{
		"ignored error":  `_ = s.requireSGWrite(ctx); return mint(), nil`,
		"after the mint": `a := mint(); if err := s.requireSGWrite(ctx); err != nil { return corrosion.FWTagAuthority{}, err }; return a, nil`,
		"not returned":   `if err := s.requireSGWrite(ctx); err != nil { log(err) }; return mint(), nil`,
	} {
		fx := fixturePackage(t, "internal/grpcapi", "package grpcapi\n\nvar mint = corrosion.ClaimFWTagAuthorityMinter()\n\n"+
			"func (s *Server) fwTagAuthority(ctx context.Context) (corrosion.FWTagAuthority, error) { "+body+" }\n")
		if got := fwTagAuthorityViolations([]goPackage{fx}); len(got) != 1 || !strings.Contains(got[0], "without first returning") {
			t.Errorf("%s: %v", name, got)
		}
	}
	good := fixturePackage(t, "internal/grpcapi", "package grpcapi\n\nvar mint = corrosion.ClaimFWTagAuthorityMinter()\n\n"+
		"func (s *Server) fwTagAuthority(ctx context.Context) (corrosion.FWTagAuthority, error) { if err := s.requireSGWrite(ctx); err != nil { return corrosion.FWTagAuthority{}, err }; return mint(), nil }\n")
	if got := fwTagAuthorityViolations([]goPackage{good}); len(got) != 0 {
		t.Errorf("the checked shape is flagged: %v", got)
	}
	forge := fixturePackage(t, "internal/corrosion", "package corrosion\n\nfunc newFWTagAuthority() FWTagAuthority { return FWTagAuthority{minted: true} }\n"+
		"func forge() FWTagAuthority { return FWTagAuthority{minted: true} }\nfunc zero() FWTagAuthority { return FWTagAuthority{} }\n")
	if got := fwTagAuthorityViolations([]goPackage{forge}); len(got) != 1 || !strings.Contains(got[0], "forge builds a non-zero FWTagAuthority") {
		t.Errorf("a forged authority: %v", got)
	}
	other := fixturePackage(t, "internal/ui", `package ui

var mint = corrosion.ClaimFWTagAuthorityMinter()
`)
	if got := fwTagAuthorityViolations([]goPackage{other}); len(got) != 1 || !strings.Contains(got[0], "outside internal/grpcapi") {
		t.Errorf("a claim outside internal/grpcapi: %v", got)
	}
}
