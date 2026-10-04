package ui

import (
	"go/types"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// TestNoUIHandlerRunsAStoreOperationInProcess is the type-aware half of the
// source guard TestNoUIHandlerWritesReplicatedStateInProcess.
//
// That guard matches `corrosion.X(` by text, so it only ever saw one package.
// The /backups page's verify, GC, prune and sync called internal/pbsstore —
// pbsstore.GC, pbsstore.ApplyPrune, pbsstore.SyncRepo — in-process, and sailed
// past it: no corrosion call, so nothing to match. A Viewer could prune and
// garbage-collect backups, and none of it was audited. Those actions now go
// through the daemon's backup-repo RPCs.
//
// This guard resolves every function and method the UI's production code
// refers to, in any internal/ package, and requires each to be classified
// here. A store package (one whose calls can change state the daemon owns) has
// an allowlist of reads; anything else from it fails. A package not listed at
// all fails too, so a new import has to be classified rather than slipping by
// the way pbsstore did. Method calls count — `repo.PutManifest(...)` or
// `s.db.Exec(...)` is as much a write as a package-level function.
func TestNoUIHandlerRunsAStoreOperationInProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("loads and type-checks the package")
	}
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo,
		Dir:   ".",
		Tests: false,
	}
	pkgs, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if n := packages.PrintErrors(pkgs); n > 0 {
		t.Fatalf("%d package load error(s)", n)
	}
	var bad []string
	for _, pkg := range pkgs {
		bad = append(bad, unclassifiedStoreCalls(pkg)...)
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
}

const uiModuleInternal = "github.com/litevirt/litevirt/internal/"

// uiInternalCallPolicy classifies every internal/ package the UI's
// production code calls into. allow reports whether a callee (a package
// function "Name" or a method "Type.Name") may be called in-process.
var uiInternalCallPolicy = map[string]func(callee string) bool{
	// Replicated state. Reads only (the same List/Get rule as the textual
	// guard); no method on the client, so no s.db.Exec.
	"corrosion": func(c string) bool {
		return !strings.Contains(c, ".") && (strings.HasPrefix(c, "List") || strings.HasPrefix(c, "Get"))
	},
	// The backup chunk store. Opening a repo and reading its manifests serves
	// the inventory page; everything that writes — PutChunk, PutManifest,
	// DeleteChunk, GC, ApplyPrune, SyncRepo, Push*, SetKey, Init — and Verify,
	// which reads every chunk at will, goes through an RPC.
	"pbsstore": allowOnly("Open", "Repo.ListManifests", "Repo.Meta", "Repo.Root",
		"Repo.IsEncrypted", "Repo.GetManifest", "Repo.LatestManifestFor", "Repo.HasChunk"),
	// The Ceph dashboard reads status; Bootstrap / Add* deploy daemons.
	"cephdeploy": allowOnly("NewCephadmRunner", "CephadmRunner.Status", "CephadmRunner.OSDTree"),
	// NewTarget parses and validates a target's config; it sends nothing.
	// Target.Send would fire at the endpoint (see TestNotificationTarget).
	"notify": allowOnly("NewTarget"),
	// Pure helpers with no state of their own.
	"randid":      func(string) bool { return true },
	"auditexport": func(string) bool { return true },
}

func allowOnly(names ...string) func(string) bool {
	set := make(map[string]bool, len(names))
	for _, n := range names {
		set[n] = true
	}
	return func(c string) bool { return set[c] }
}

// unclassifiedStoreCalls returns one message per reference, in pkg's own
// files, to an internal/ function or method its policy does not allow.
func unclassifiedStoreCalls(pkg *packages.Package) []string {
	var out []string
	for id, obj := range pkg.TypesInfo.Uses {
		fn, ok := obj.(*types.Func)
		if !ok || fn.Pkg() == nil || fn.Pkg() == pkg.Types {
			continue
		}
		path := fn.Pkg().Path()
		if !strings.HasPrefix(path, uiModuleInternal) {
			continue
		}
		rel := strings.TrimPrefix(path, uiModuleInternal)
		callee := fn.Name()
		if recv := fn.Type().(*types.Signature).Recv(); recv != nil {
			callee = recvTypeName(recv.Type()) + "." + callee
		}
		pos := pkg.Fset.Position(id.Pos())
		where := pos.Filename
		if i := strings.LastIndex(where, "/"); i >= 0 {
			where = where[i+1:]
		}
		allow, known := uiInternalCallPolicy[rel]
		switch {
		case !known:
			out = append(out, where+":"+strconv.Itoa(pos.Line)+": "+rel+"."+callee+
				": the UI calls into internal/"+rel+", which this guard has not classified. "+
				"If the call can change state, route it through its gRPC twin with s.uiBearerCtx(r); "+
				"if the package is read-only or pure, add it to uiInternalCallPolicy with an allowlist")
		case !allow(callee):
			out = append(out, where+":"+strconv.Itoa(pos.Line)+": "+rel+"."+callee+
				" is not an allowed in-process read. The UI must not run a store or backup operation "+
				"itself: call its gRPC twin with s.uiBearerCtx(r), so the daemon authorizes it against "+
				"the session and audits it, as it does for the CLI. In-process, any session with a role "+
				"can run it and the audit log never hears of it")
		}
	}
	return out
}

func recvTypeName(t types.Type) string {
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return t.String()
}
