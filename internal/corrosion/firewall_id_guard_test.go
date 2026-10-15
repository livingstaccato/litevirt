package corrosion

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	_ "github.com/litevirt/litevirt/gen/litevirt/v1"
)

// The guards of the firewall identity (spec §4.3, m-1, m-5, R4-I1):
//
//   - the writer guard: every function that writes vms.spec or
//     containers.create_spec — found by the PARSED statement's columns, not by
//     an SQL prefix — calls keepFirewallID, or hands the write to one that does.
//     It checks the call, not that its result is the value bound to the
//     column; TestFirewallIDWriters_* pin that for every writer;
//   - the carry guard: CarryFirewallID is called only from the listed paths,
//     each of which obtains its source through withReplacedVM, the container
//     re-key's own batch or the relocation proof, and no code builds a token
//     any other way;
//   - the request guard: no request message carries an identity field other
//     than VMSpec.firewall_id, which every insert strips.

// firewallIDNonWriters reference a statement that writes an identity column
// without executing it.
var firewallIDNonWriters = map[string]string{
	"validateGuardedCreateBeginEntry":      "fingerprints a received create-begin envelope",
	"validateGuardedVMReplaceEntry":        "fingerprints a received guarded-replace envelope",
	"validateLegacyContainerRekeyEnvelope": "fingerprints a received legacy re-key envelope",
	"legacyAtomicRelocationEntry":          "fingerprints a received single-entry relocation",
	"HistoricalShapes":                     "enumerates retained SQL for the compatibility ledger",
}

// firewallIDDelegates execute an identity-column statement whose parameters a
// named builder produced; the builder calls keepFirewallID.
var firewallIDDelegates = map[string]string{
	"RekeyContainerOwnerGuarded": "rekeyContainerStmt",
}

// firewallIDCarrySource is where a carry token's source row comes from.
type firewallIDCarrySource string

const (
	carryFromReplacedVM      firewallIDCarrySource = "replacedVM"
	carryFromRekeyBatch      firewallIDCarrySource = "rekey batch"
	carryFromRelocationProof firewallIDCarrySource = "relocation proof"
)

// carrySourceEvidence names, per source, the identifiers a carrying function
// must use: the snapshot of the VM its own delete tombstoned (withReplacedVM,
// or acceptReplacedVMMD's metadata from a peer); the container re-key's own
// insert; the fenced-host relocation proof.
var carrySourceEvidence = map[firewallIDCarrySource][]string{
	carryFromReplacedVM:      {"replacedVM", "replacedVMFrom"},
	carryFromRekeyBatch:      {"containerRekeyInsertSQL", "legacyContainerRekeySQL"},
	carryFromRelocationProof: {"ActionProof"},
}

// firewallIDCarriers is the closed list of functions allowed to mint a
// FirewallIDCarry ("<package dir>.<Recv.>Func"). D2a wires none; the
// same-workload paths of spec §4.3 add themselves here.
var firewallIDCarriers = map[string]firewallIDCarrySource{}

// allowedRequestIdentityFields are the identity fields a request message may
// reach: VMSpec.firewall_id, which every insert strips and every update keeps
// (TestFirewallIDWriters_*).
var allowedRequestIdentityFields = []string{"litevirt.v1.VMSpec.firewall_id"}

// goPackage is one directory's parsed non-test Go files.
type goPackage struct {
	dir   string // relative to the repo root, slash-separated
	files []*ast.File
}

// repoPackages parses every non-test Go package under the repo's internal/
// and cmd/ trees.
func repoPackages(t *testing.T) []goPackage {
	t.Helper()
	root := filepath.Join("..", "..")
	byDir := map[string]*goPackage{}
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				return perr
			}
			rel, _ := filepath.Rel(root, filepath.Dir(path))
			rel = filepath.ToSlash(rel)
			if byDir[rel] == nil {
				byDir[rel] = &goPackage{dir: rel}
			}
			byDir[rel].files = append(byDir[rel].files, f)
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", top, err)
		}
	}
	var out []goPackage
	for _, p := range byDir {
		out = append(out, *p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dir < out[j].dir })
	if len(out) < 20 {
		t.Fatalf("parsed only %d packages; the walk is broken", len(out))
	}
	return out
}

// funcKey names a declared function: "Recv.Name" for a method, else "Name".
func funcKey(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	typ := fd.Recv.List[0].Type
	if st, ok := typ.(*ast.StarExpr); ok {
		typ = st.X
	}
	if ix, ok := typ.(*ast.IndexExpr); ok {
		typ = ix.X
	}
	if id, ok := typ.(*ast.Ident); ok {
		return id.Name + "." + fd.Name.Name
	}
	return fd.Name.Name
}

// stringConsts collects the string constants and initialised vars a scope
// declares, by name, as unevaluated expressions.
func stringConsts(decls []ast.Decl, into map[string]ast.Expr) {
	for _, decl := range decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || (gen.Tok != token.CONST && gen.Tok != token.VAR) {
			continue
		}
		collectValueSpecs(gen, into)
	}
}

func collectValueSpecs(gen *ast.GenDecl, into map[string]ast.Expr) {
	for _, spec := range gen.Specs {
		vs, ok := spec.(*ast.ValueSpec)
		if !ok || len(vs.Names) != len(vs.Values) {
			continue
		}
		for i, n := range vs.Names {
			into[n.Name] = vs.Values[i]
		}
	}
}

// constString folds e to a constant string: literals, named constants and
// their concatenation.
func constString(e ast.Expr, scopes []map[string]ast.Expr, depth int) (string, bool) {
	if depth > 20 {
		return "", false
	}
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		return s, err == nil
	case *ast.ParenExpr:
		return constString(v.X, scopes, depth+1)
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		a, ok := constString(v.X, scopes, depth+1)
		if !ok {
			return "", false
		}
		b, ok := constString(v.Y, scopes, depth+1)
		return a + b, ok
	case *ast.Ident:
		for _, sc := range scopes {
			if def, ok := sc[v.Name]; ok {
				return constString(def, scopes, depth+1)
			}
		}
	}
	return "", false
}

// writesIdentityColumn reports whether sqlText, PARSED, writes vms.spec or
// containers.create_spec: an INSERT naming the column (or setting it in its
// conflict arm) or an UPDATE setting it.
func writesIdentityColumn(sqlText string) bool {
	sh, _, err := parseResolved(sqlText)
	if err != nil {
		return false
	}
	var col string
	switch strings.ToLower(sh.Table) {
	case "vms":
		col = "spec"
	case "containers":
		col = "create_spec"
	default:
		return false
	}
	var assigns []AssignmentShape
	switch sh.Kind {
	case KindInsert:
		for _, c := range sh.InsertCols {
			if strings.EqualFold(c, col) {
				return true
			}
		}
		if sh.OnConflict != nil {
			assigns = sh.OnConflict.Assignments
		}
	case KindUpdate:
		assigns = sh.SetAssigns
	}
	for _, a := range assigns {
		if strings.EqualFold(a.Column, col) {
			return true
		}
	}
	return false
}

// identityWriters returns, per package dir, the functions whose body holds a
// constant statement that writes an identity column.
func identityWriters(pkgs []goPackage) map[string]map[string]*ast.FuncDecl {
	out := map[string]map[string]*ast.FuncDecl{}
	for _, p := range pkgs {
		pkgScope := map[string]ast.Expr{}
		for _, f := range p.files {
			stringConsts(f.Decls, pkgScope)
		}
		for _, f := range p.files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				local := map[string]ast.Expr{}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if ds, ok := n.(*ast.DeclStmt); ok {
						if gen, ok := ds.Decl.(*ast.GenDecl); ok && gen.Tok == token.CONST {
							collectValueSpecs(gen, local)
						}
					}
					return true
				})
				scopes := []map[string]ast.Expr{local, pkgScope}
				hit := false
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if hit {
						return false
					}
					e, ok := n.(ast.Expr)
					if !ok {
						return true
					}
					if s, ok := constString(e, scopes, 0); ok && writesIdentityColumn(s) {
						hit = true
						return false
					}
					return true
				})
				if hit {
					if out[p.dir] == nil {
						out[p.dir] = map[string]*ast.FuncDecl{}
					}
					out[p.dir][funcKey(fd)] = fd
				}
			}
		}
	}
	return out
}

// callsFunc reports whether body calls a function named name (a plain call or
// a selector call).
func callsFunc(body ast.Node, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return !found
		}
		switch f := call.Fun.(type) {
		case *ast.Ident:
			found = found || f.Name == name
		case *ast.SelectorExpr:
			found = found || f.Sel.Name == name
		}
		return !found
	})
	return found
}

// firewallIDWriterViolations applies the writer rules.
func firewallIDWriterViolations(pkgs []goPackage, nonWriters, delegates map[string]string) []string {
	const home = "internal/corrosion"
	writers := identityWriters(pkgs)
	var bad []string
	for dir, fns := range writers {
		for name, fd := range fns {
			switch {
			case dir != home:
				bad = append(bad, dir+"."+name+": writes vms.spec / containers.create_spec outside internal/corrosion")
			case nonWriters[name] != "":
			case delegates[name] != "":
				builder, ok := fns[delegates[name]]
				if !ok || !callsFunc(fd.Body, delegates[name]) || !callsFunc(builder.Body, "keepFirewallID") {
					bad = append(bad, name+": delegates to "+delegates[name]+", which it does not call or which does not call keepFirewallID")
				}
			case !callsFunc(fd.Body, "keepFirewallID"):
				bad = append(bad, name+": writes vms.spec / containers.create_spec without keepFirewallID")
			}
		}
	}
	for name := range nonWriters {
		if writers[home][name] == nil {
			bad = append(bad, name+": listed in firewallIDNonWriters but references no identity-column write; remove it")
		}
	}
	for name := range delegates {
		if writers[home][name] == nil {
			bad = append(bad, name+": listed in firewallIDDelegates but references no identity-column write; remove it")
		}
	}
	sort.Strings(bad)
	return bad
}

func TestFirewallIDWriterGuard(t *testing.T) {
	pkgs := repoPackages(t)
	if bad := firewallIDWriterViolations(pkgs, firewallIDNonWriters, firewallIDDelegates); len(bad) > 0 {
		t.Fatalf("firewall identity writer guard:\n  %s", strings.Join(bad, "\n  "))
	}
	// Guard the guard: the enumeration finds the writers spec §4.3 lists.
	found := identityWriters(pkgs)["internal/corrosion"]
	for _, want := range []string{
		"InsertVMWithHardware", "Client.BeginVMCreateOperation", "Client.BeginContainerCreateOperation",
		"mutateDesiredSpec", "Client.BeginVMOperation", "migrateVMSpecNetworkNames", "execVMRekey",
		"vmReplaceStatements", "upsertContainerStmt", "rekeyContainerStmt", "legacyRekeyContainerStmt",
		"RelocateContainerWithToken", "MintContainerPlacementSpec", "mintContainerFirewallID",
	} {
		if found[want] == nil {
			t.Errorf("the writer enumeration misses %s", want)
		}
	}
}

// fixturePackage parses src as one file of package dir.
func fixturePackage(t *testing.T, dir, src string) goPackage {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "fixture.go", src, 0)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}
	return goPackage{dir: dir, files: []*ast.File{f}}
}

// TestFirewallIDWriterGuard_FlagsAFixture: the guard finds a writer by the
// parsed columns — whitespace, case and constant concatenation do not hide
// one — and flags it without keepFirewallID; a statement that does not write
// the column is not a writer.
//
// Mutation: drop the keepFirewallID requirement (or match an SQL prefix) — the
// fixture writers pass.
func TestFirewallIDWriterGuard_FlagsAFixture(t *testing.T) {
	src := `package corrosion

const base = "UPDATE vms SET name = ?, "

func rename() { exec("UPDATE vms SET name = ?, spec = ? WHERE name = ?") }
func renameKept() { keepFirewallID(); exec("UPDATE vms SET name = ?, spec = ? WHERE name = ?") }
func spaced() { exec("update   VMS\n\tset spec=?, updated_at = ? where name = ?") }
func joined() { exec(base + "spec = ?, updated_at = ? WHERE name = ?") }
func ctInsert() { exec(` + "`" + `INSERT INTO containers (host_name, name, create_spec, updated_at) VALUES (?, ?, ?, ?)` + "`" + `) }
func ctConflict() {
	exec(` + "`" + `INSERT INTO containers (host_name, name, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(host_name, name) DO UPDATE SET create_spec = excluded.updated_at` + "`" + `)
}
func state() { exec("UPDATE vms SET state = ?, updated_at = ? WHERE name = ?") }
func read() { query("SELECT spec FROM vms WHERE name = ?") }
const specSQL = "UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?"

func delegator() { b := builder(); exec(specSQL, b) }
func builder() []any { keepFirewallID(); _ = specSQL; return nil }
func lazy() { b := builder(); exec(specSQL, b) }
`
	pkgs := []goPackage{
		fixturePackage(t, "internal/corrosion", src),
		fixturePackage(t, "internal/grpcapi", `package grpcapi
func sneaky() { keepFirewallID(); exec("UPDATE containers SET create_spec = ?, updated_at = ? WHERE host_name = ? AND name = ?") }
`),
	}
	got := firewallIDWriterViolations(pkgs, map[string]string{}, map[string]string{"delegator": "builder"})
	want := []string{
		"ctConflict: writes vms.spec / containers.create_spec without keepFirewallID",
		"ctInsert: writes vms.spec / containers.create_spec without keepFirewallID",
		"internal/grpcapi.sneaky: writes vms.spec / containers.create_spec outside internal/corrosion",
		"joined: writes vms.spec / containers.create_spec without keepFirewallID",
		"lazy: writes vms.spec / containers.create_spec without keepFirewallID",
		"rename: writes vms.spec / containers.create_spec without keepFirewallID",
		"spaced: writes vms.spec / containers.create_spec without keepFirewallID",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("violations:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
	// A delegate that does not call keepFirewallID is flagged.
	bad := fixturePackage(t, "internal/corrosion", `package corrosion
const specSQL = "UPDATE vms SET spec = ?, updated_at = ? WHERE name = ?"
func delegator() { b := builder(); exec(specSQL, b) }
func builder() []any { _ = specSQL; return nil }
`)
	got = firewallIDWriterViolations([]goPackage{bad}, map[string]string{}, map[string]string{"delegator": "builder"})
	if len(got) != 2 {
		t.Fatalf("an unkept delegate: %v, want both the delegator and the builder flagged", got)
	}
}

// carryViolations applies the carry rules: every CarryFirewallID call is in a
// listed function that uses its source's evidence, and no code outside
// CarryFirewallID builds a non-zero token.
func carryViolations(pkgs []goPackage, carriers map[string]firewallIDCarrySource) []string {
	var bad []string
	seen := map[string]bool{}
	for _, p := range pkgs {
		for _, f := range p.files {
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				key := p.dir + "." + funcKey(fd)
				if p.dir == "internal/corrosion" && funcKey(fd) == "CarryFirewallID" {
					continue
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					if lit, ok := n.(*ast.CompositeLit); ok && len(lit.Elts) > 0 && typeNamed(lit.Type, "FirewallIDCarry") {
						bad = append(bad, key+": builds a FirewallIDCarry; only CarryFirewallID may")
					}
					return true
				})
				if !callsFunc(fd.Body, "CarryFirewallID") {
					continue
				}
				seen[key] = true
				src, listed := carriers[key]
				if !listed {
					bad = append(bad, key+": calls CarryFirewallID but is not a listed carry path")
					continue
				}
				if !usesAny(fd.Body, carrySourceEvidence[src]) {
					bad = append(bad, key+": carries from "+string(src)+" but obtains its source through none of "+
						strings.Join(carrySourceEvidence[src], ", "))
				}
			}
		}
	}
	for key := range carriers {
		if !seen[key] {
			bad = append(bad, key+": listed as a carry path but calls no CarryFirewallID; remove it")
		}
	}
	sort.Strings(bad)
	return bad
}

func typeNamed(e ast.Expr, name string) bool {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name == name
	case *ast.SelectorExpr:
		return v.Sel.Name == name
	}
	return false
}

// usesAny reports whether body names any of idents.
func usesAny(body ast.Node, idents []string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && slices.Contains(idents, id.Name) {
			found = true
		}
		return !found
	})
	return found
}

func TestFirewallIDCarryGuard(t *testing.T) {
	if bad := carryViolations(repoPackages(t), firewallIDCarriers); len(bad) > 0 {
		t.Fatalf("firewall identity carry guard:\n  %s", strings.Join(bad, "\n  "))
	}
}

// TestFirewallIDCarryGuard_FlagsAFixture: a token minted outside the listed
// paths, or by a listed path that obtains its source other than through its
// evidence, or built as a literal, is flagged.
//
// Mutation: drop the source assertion (usesAny) — "noEvidence" passes.
func TestFirewallIDCarryGuard_FlagsAFixture(t *testing.T) {
	pkg := fixturePackage(t, "internal/grpcapi", `package grpcapi
func rebuild(ctx context.Context) { r := replacedVMFrom(ctx); _ = corrosion.CarryFirewallID("vm", r.snap.Spec) }
func clone(src string) { _ = corrosion.CarryFirewallID("vm", src) }
func noEvidence(src string) { _ = corrosion.CarryFirewallID("vm", src) }
func forge() { _ = corrosion.FirewallIDCarry{} ; _ = corrosion.FirewallIDCarry{kind: "vm", id: "x"} }
`)
	got := carryViolations([]goPackage{pkg}, map[string]firewallIDCarrySource{
		"internal/grpcapi.rebuild":    carryFromReplacedVM,
		"internal/grpcapi.noEvidence": carryFromReplacedVM,
		"internal/grpcapi.gone":       carryFromRekeyBatch,
	})
	want := []string{
		"internal/grpcapi.clone: calls CarryFirewallID but is not a listed carry path",
		"internal/grpcapi.forge: builds a FirewallIDCarry; only CarryFirewallID may",
		"internal/grpcapi.gone: listed as a carry path but calls no CarryFirewallID; remove it",
		"internal/grpcapi.noEvidence: carries from replacedVM but obtains its source through none of replacedVM, replacedVMFrom",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("violations:\n  %s\nwant:\n  %s", strings.Join(got, "\n  "), strings.Join(want, "\n  "))
	}
}

// requestIdentityFields returns every identity field (fw_id, firewall_id, in
// any spelling) reachable from a message of files whose name ends in Request.
func requestIdentityFields(files []protoreflect.FileDescriptor) []string {
	var out []string
	visited := map[protoreflect.FullName]bool{}
	var walk func(md protoreflect.MessageDescriptor)
	walk = func(md protoreflect.MessageDescriptor) {
		if visited[md.FullName()] {
			return
		}
		visited[md.FullName()] = true
		fields := md.Fields()
		for i := 0; i < fields.Len(); i++ {
			fd := fields.Get(i)
			norm := strings.ReplaceAll(strings.ToLower(string(fd.Name())), "_", "")
			if norm == "fwid" || norm == "firewallid" {
				out = append(out, string(fd.FullName()))
			}
			if fd.IsMap() {
				fd = fd.MapValue()
			}
			if fd.Message() != nil {
				walk(fd.Message())
			}
		}
	}
	for _, f := range files {
		msgs := f.Messages()
		for i := 0; i < msgs.Len(); i++ {
			if strings.HasSuffix(string(msgs.Get(i).Name()), "Request") {
				walk(msgs.Get(i))
			}
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
}

func TestFirewallIDRequestGuard(t *testing.T) {
	var files []protoreflect.FileDescriptor
	protoregistry.GlobalFiles.RangeFilesByPackage("litevirt.v1", func(fd protoreflect.FileDescriptor) bool {
		files = append(files, fd)
		return true
	})
	if len(files) == 0 {
		t.Fatal("no litevirt.v1 descriptors registered")
	}
	if got := requestIdentityFields(files); !slices.Equal(got, allowedRequestIdentityFields) {
		t.Fatalf("request messages reach identity fields %v, want only %v: a client could set an identity",
			got, allowedRequestIdentityFields)
	}
}

// TestFirewallIDRequestGuard_FlagsAFixture: a request message reaching an
// identity field, directly, nested, or through a map value, is found.
func TestFirewallIDRequestGuard_FlagsAFixture(t *testing.T) {
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum()
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	field := func(name string, n int32, typ *descriptorpb.FieldDescriptorProto_Type, label *descriptorpb.FieldDescriptorProto_Label, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(n), Type: typ, Label: label}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	fdp := &descriptorpb.FileDescriptorProto{
		Name: proto.String("fixture.proto"), Package: proto.String("fixture"), Syntax: proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("DirectRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("FW_ID", 1, str, opt, "")}},
			{Name: proto.String("NestedRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("inner", 1, msg, opt, ".fixture.Inner")}},
			{Name: proto.String("MapRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("by_name", 1, msg, rep, ".fixture.MapRequest.ByNameEntry")},
				NestedType: []*descriptorpb.DescriptorProto{{
					Name:    proto.String("ByNameEntry"),
					Field:   []*descriptorpb.FieldDescriptorProto{field("key", 1, str, opt, ""), field("value", 2, msg, opt, ".fixture.Other")},
					Options: &descriptorpb.MessageOptions{MapEntry: proto.Bool(true)},
				}}},
			{Name: proto.String("Inner"), Field: []*descriptorpb.FieldDescriptorProto{field("firewall_id", 1, str, opt, "")}},
			{Name: proto.String("Other"), Field: []*descriptorpb.FieldDescriptorProto{field("fwId", 1, str, opt, "")}},
			{Name: proto.String("Reply"), Field: []*descriptorpb.FieldDescriptorProto{field("fw_id", 1, str, opt, "")}},
		},
	}
	fd, err := protodesc.NewFile(fdp, nil)
	if err != nil {
		t.Fatalf("build fixture descriptor: %v", err)
	}
	got := requestIdentityFields([]protoreflect.FileDescriptor{fd})
	want := []string{"fixture.DirectRequest.FW_ID", "fixture.Inner.firewall_id", "fixture.Other.fwId"}
	if !slices.Equal(got, want) {
		t.Fatalf("identity fields = %v, want %v", got, want)
	}
}
