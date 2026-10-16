package corrosion

import (
	"go/ast"
	"go/token"
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
// flagged. A reader that only queries a key is not a writer.
//
// The authority guard: the FWTagAuthority minter is claimed once, by
// internal/grpcapi, and handed only to Server.fwTagAuthority, which checks
// sg.write before it mints; FWTagAuthorityForTest has no non-test caller.

// firewallTagsKeyWriterFiles may write the reserved keys.
var firewallTagsKeyWriterFiles = map[string]bool{
	"internal/corrosion/firewall_tags.go":      true,
	"internal/corrosion/firewall_tag_group.go": true,
}

// firewallTagsKeyRefusers name a reserved key only to refuse it: each must
// use ErrReservedClusterPolicyKey.
var firewallTagsKeyRefusers = map[string]bool{"internal/corrosion.SetClusterPolicy": true}

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
			found = name == "SetClusterPolicy" || strings.HasPrefix(name, "Execute")
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
				if firewallTagsKeyRefusers[p.dir+"."+funcKey(fd)] && usesAny(fd.Body, []string{"ErrReservedClusterPolicyKey"}) {
					continue
				}
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
// through the upsert with the exported prefix, and a key folded from a
// constant; a reader is not flagged.
//
// Mutation: skip the literal check — the first fixture passes: red.
func TestFirewallTagsKeyGuard_FlagsAFixture(t *testing.T) {
	src := `package grpcapi

const groupKey = "firewall_tag_group/"

func literal() { corrosion.SetClusterPolicy(ctx, db, "firewall_tags/x", "", "me") }
func prefix(id string) { c.Execute(ctx, clusterPolicyUpsertSQL, corrosion.FirewallTagsKeyPrefix+"vm/"+id, "", "me", ts) }
func folded() { corrosion.SetClusterPolicy(ctx, db, groupKey+"web", "{}", "me") }
func reader(id string) { c.Query(ctx, "SELECT value FROM cluster_policies WHERE key = ?", corrosion.FirewallTagsKeyPrefix+id) }
func other() { corrosion.SetClusterPolicy(ctx, db, "firewall_trunk_vlans_recorded", "{}", "me") }
func SetClusterPolicy(key string) { if strings.HasPrefix(key, FirewallTagsKeyPrefix) { return }; c.Execute(ctx, q, key) }
`
	got := firewallTagsKeyViolations([]goPackage{fixturePackage(t, "internal/corrosion", src)})
	// SetClusterPolicy is listed as a refuser, but this one does not refuse
	// with ErrReservedClusterPolicyKey: flagged.
	want := []string{"SetClusterPolicy", "folded", "literal", "prefix"}
	if len(got) != len(want) {
		t.Fatalf("flagged %v, want exactly %v", got, want)
	}
	for i, w := range want {
		if !strings.Contains(got[i], " "+w+" writes") {
			t.Errorf("flag %d = %q, want %s", i, got[i], w)
		}
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
	for _, p := range pkgs {
		for i, f := range p.files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				var mintVar []string
				for v := range minterVars {
					mintVar = append(mintVar, v)
				}
				if !usesAny(fd.Body, mintVar) {
					continue
				}
				switch {
				case p.dir != home || funcKey(fd) != "Server.fwTagAuthority":
					bad = append(bad, p.paths[i]+": "+funcKey(fd)+" mints a firewall-tags authority; only Server.fwTagAuthority may")
				case !callsFunc(fd.Body, "requireSGWrite"):
					bad = append(bad, p.paths[i]+": Server.fwTagAuthority mints without requireSGWrite")
				}
			}
		}
	}
	sort.Strings(bad)
	return bad
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

// Mutation: drop the requireSGWrite requirement — the fixture's unchecked
// mint passes: red.
func TestFWTagAuthorityGuard_FlagsAFixture(t *testing.T) {
	src := `package grpcapi

var mint = corrosion.ClaimFWTagAuthorityMinter()

func (s *Server) fwTagAuthority(ctx context.Context) (corrosion.FWTagAuthority, error) { return mint(), nil }
func (s *Server) sneaky() corrosion.FWTagAuthority { return mint() }
func shortcut(t testing.TB) { _ = corrosion.FWTagAuthorityForTest(t) }
`
	got := fwTagAuthorityViolations([]goPackage{fixturePackage(t, "internal/grpcapi", src)})
	for _, want := range []string{"Server.fwTagAuthority mints without requireSGWrite", "Server.sneaky mints", "shortcut calls FWTagAuthorityForTest"} {
		found := false
		for _, g := range got {
			found = found || strings.Contains(g, want)
		}
		if !found {
			t.Errorf("not flagged: %q (got %v)", want, got)
		}
	}
	other := fixturePackage(t, "internal/ui", `package ui

var mint = corrosion.ClaimFWTagAuthorityMinter()
`)
	if got := fwTagAuthorityViolations([]goPackage{other}); len(got) != 1 || !strings.Contains(got[0], "outside internal/grpcapi") {
		t.Errorf("a claim outside internal/grpcapi: %v", got)
	}
}
