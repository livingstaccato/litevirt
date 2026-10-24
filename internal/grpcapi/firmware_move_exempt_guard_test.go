package grpcapi

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// T-5 (spec §2 I5, §9): only the move's own steps undefine a moved VM's
// source definition, wipe its source state, stop or resume a held guest, or
// resume a marked source. Each exempt entry point of the firmware move guard
// is called only from its owner, and each owner only from the step it
// belongs to; the raw libvirt calls that undefine, resume, destroy or define a
// domain appear only in the guarded internal/libvirt functions listed here.
//
// The D-5 operator entry points (`lv doctor firmware-move`, task D2-18) each
// have one owner too, and that owner is reached only from the doctor.
//
// Mutation: call an exempt entry point from deleteVM — red; call
// DomainUndefineFlags from a new function in internal/libvirt — red.

// fwExemptOwners: the exempt entry point (or the owner helper that calls one)
// → the functions allowed to call it, as "pkgdir.Recv.Func" or "pkgdir.Func".
var fwExemptOwners = map[string][]string{
	// Bound starts retain one looked-up UUID handle and the entry's firmware/NIC
	// guard. The semantic boundary is checked by fwBoundStartProblems below.
	"startDomainBound":              {"internal/libvirt.Client.StartDomainBound"},
	"startBoundWithConsoleBackstop": {"internal/libvirt.startDomainBound"},
	"startBoundHandle":              {"internal/libvirt.startBoundWithConsoleBackstop"},
	// §7 M1p, and its recovery retry, which goes through the same handler.
	"ResumeFirmwareMoveSource":  {"internal/grpcapi.Server.liveFirmwareSourcePaused"},
	"liveFirmwareSourcePaused":  {"internal/grpcapi.Server.liveFirmwareMigrateFailed"},
	"liveFirmwareMigrateFailed": {"internal/grpcapi.Server.migrateOwnedVM", "internal/grpcapi.Server.adoptAbandonedMigration", "internal/grpcapi.Server.recoverFirmwareMigrationFailed"},
	// The partition pauser resuming a guest it paused.
	"ResumePartitionPaused": {"internal/health.PartitionPauser.resume"},
	// Release, the one resume of a held target guest, and its H1 NVRAM push.
	// The doctor's adopt on a target whose source host is lost releases the
	// adopted guest through the same resume (D-5).
	"ResumeFirmwareMoveTarget": {"internal/grpcapi.Server.resumeReleased", "internal/grpcapi.Server.releaseAdoptedHold"},
	"resumeReleased":           {"internal/grpcapi.Server.ReleaseLiveFirmwareTarget"},
	"releaseAdoptedHold":       {"internal/grpcapi.Server.doctorTargetLocalAdopt"},
	// H1's push, and the D-5 push of held_domain_absent (H1's checks without
	// "domain defined", D2-6 m-10).
	"PushFirmwareMoveNvram": {"internal/grpcapi.Server.releaseH1", "internal/grpcapi.Server.pushSourceNvramForOperator"},
	"releaseH1":             {"internal/grpcapi.Server.ReleaseLiveFirmwareTarget"},
	// Abort, the one removal of a held target domain, and the D-5
	// --discard-target on a target whose source holds no marker.
	"DiscardFirmwareMoveTarget": {"internal/grpcapi.Server.AbortLiveFirmwareTarget", "internal/grpcapi.Server.doctorTargetLocalDiscard"},
	// Cleanup, the one undefine of a moved VM's source definition and the
	// one wipe of its source state; the D-5 --accept-target on a stopped
	// cleanup undefines the same way and quarantines instead of wiping.
	"UndefineFirmwareMoveLeftover": {"internal/grpcapi.Server.undefineLiveFirmwareLeftover"},
	"undefineLiveFirmwareLeftover": {"internal/grpcapi.Server.fwmigCleanupSourceAs", "internal/grpcapi.Server.quarantineFirmwareMoveSource"},
	"WipeFirmwareMoveSource":       {"internal/grpcapi.Server.fwmigCleanupSourceAs"},
	// Prepare's materialisation; rule D and rule Q of the hold's disposal.
	"MaterialiseFirmwareMoveNvram":      {"internal/grpcapi.Server.PrepareLiveFirmwareTarget"},
	"RemoveFirmwareMoveTargetState":     {"internal/grpcapi.Server.deleteHoldState"},
	"deleteHoldState":                   {"internal/grpcapi.Server.disposePreparedHold", "internal/grpcapi.Server.AbortLiveFirmwareTarget"},
	"QuarantineFirmwareMoveTargetState": {"internal/grpcapi.Server.quarantineHold"},
	"quarantineHold": {"internal/grpcapi.Server.disposePreparedHold", "internal/grpcapi.Server.AbortLiveFirmwareTarget", "internal/grpcapi.Server.sweepFirmwareHold",
		"internal/grpcapi.Server.doctorTargetLocalDiscard"},
	// D-5 (`lv doctor firmware-move`, D2-18): each operator entry point from
	// its one action, and each action only from the doctor.
	"ResumeFirmwareMoveSourceForOperator":     {"internal/grpcapi.Server.doctorAcceptSourcePaused"},
	"doctorAcceptSourcePaused":                {"internal/grpcapi.Server.doctorAcceptSource"},
	"StopFirmwareMoveTargetForOperator":       {"internal/grpcapi.Server.stopHeldGuestForOperator"},
	"stopHeldGuestForOperator":                {"internal/grpcapi.Server.FirmwareMoveDoctorTarget", "internal/grpcapi.Server.doctorTargetLocalDiscard"},
	"PushSourceNvramForOperator":              {"internal/grpcapi.Server.pushSourceNvramForOperator"},
	"pushSourceNvramForOperator":              {"internal/grpcapi.Server.FirmwareMoveDoctorTarget"},
	"QuarantineFirmwareMoveSourceForOperator": {"internal/grpcapi.Server.quarantineFirmwareMoveSource"},
	"quarantineFirmwareMoveSource":            {"internal/grpcapi.Server.doctorAcceptTarget", "internal/grpcapi.Server.doctorAdopt"},
	"doctorTargetLocalDiscard":                {"internal/grpcapi.Server.doctorTargetLocalAct"},
	"doctorTargetLocalAdopt":                  {"internal/grpcapi.Server.doctorTargetLocalAct"},
	"adoptHold":                               {"internal/grpcapi.Server.FirmwareMoveDoctorTarget", "internal/grpcapi.Server.doctorTargetLocalAdopt"},
	"doctorTargetLocalAct":                    {"internal/grpcapi.Server.firmwareMoveDoctorAct"},
	"doctorSourceAct":                         {"internal/grpcapi.Server.firmwareMoveDoctorAct"},
	"firmwareMoveDoctorAct":                   {"internal/grpcapi.Server.FirmwareMoveDoctor"},
	// The D-5 --discard-target of a leftover an owed DISCARD names.
	"StopOwedFirmwareLeftover":       {"internal/grpcapi.Server.doctorDiscardOwedLeftover"},
	"QuarantineOwedFirmwareLeftover": {"internal/grpcapi.Server.doctorDiscardOwedLeftover"},
	"UndefineOwedFirmwareLeftover":   {"internal/grpcapi.Server.doctorDiscardOwedLeftover"},
	"doctorDiscardOwedLeftover":      {"internal/grpcapi.Server.firmwareMoveDoctorAct"},
}

// fwRawLibvirt: the raw libvirt calls that undefine, resume, destroy or
// define a domain → the internal/libvirt functions allowed to make them, each
// guarded (spec §5.1) or a wrapper of the client's own connection.
var fwRawLibvirt = map[string][]string{
	"DomainUndefineFlags": {
		"internal/libvirt.discardFirmwareMoveTarget", "internal/libvirt.undefineDomain",
		"internal/libvirt.undefineDomainPreservingState", "internal/libvirt.undefineKeepingState",
		"internal/libvirt.forceRemoveDomain", "internal/libvirt.revertToLiveSnapshot", "internal/libvirt.revertToSnapshot",
	},
	"DomainResume": {
		"internal/libvirt.startDomainGuarded", "internal/libvirt.startBoundHandle", "internal/libvirt.resumeDomain",
		"internal/libvirt.capture.settle", "internal/libvirt.restoreWithRetry",
	},
	"DomainDestroy": {
		"internal/libvirt.startDomainGuarded", "internal/libvirt.startBoundHandle", "internal/libvirt.destroyDomain", "internal/libvirt.discardFirmwareMoveTarget",
		"internal/libvirt.stopForOperator", "internal/libvirt.forceRemoveDomain",
		"internal/libvirt.restoreWithRetry", "internal/libvirt.revertToLiveSnapshot", "internal/libvirt.revertToSnapshot",
	},
	"DomainDefineXML": {
		"internal/libvirt.keepConsolePITAPI.DomainDefineXML", "internal/libvirt.keepConsoleSnapshotAPI.DomainDefineXML",
		"internal/libvirt.startWithConsoleBackstop", "internal/libvirt.startBoundWithConsoleBackstop", "internal/libvirt.Client.SetBootOrder", "internal/libvirt.defineDomain",
		"internal/libvirt.repairPersistentDisk", "internal/libvirt.revertToLiveSnapshot", "internal/libvirt.revertToSnapshot",
	},
}

type fwCallSite struct {
	sel, caller string
	pos         token.Position
}

// fwCallSites parses every non-test Go file under internal/ and cmd/ and
// returns each call X.Sel(...) whose Sel is in names, with the function it
// is made in (a function literal counts as the function that holds it).
func fwCallSites(t *testing.T, names map[string]bool) []fwCallSite {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var out []fwCallSite
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, p, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, filepath.Dir(p))
			out = append(out, fwCallsInSyntax(fset, f, filepath.ToSlash(rel), names)...)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestFirmwareMoveExemptCallers(t *testing.T) {
	for _, problem := range fwBoundStartProblems(fwBoundStartSources(t)) {
		t.Error(problem)
	}
	names := map[string]bool{}
	for n := range fwExemptOwners {
		names[n] = true
	}
	for n := range fwRawLibvirt {
		names[n] = true
	}
	seen := map[string]bool{}
	var bad []string
	for _, c := range fwCallSites(t, names) {
		ok := fwAllowedCall(c)
		if !ok {
			bad = append(bad, c.sel+" called from "+c.caller+" at "+c.pos.String())
			continue
		}
		seen[c.sel+"<-"+c.caller] = true
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Errorf("%s: not one of its owners", b)
	}
	// Every listed owner still makes the call: an owner renamed or moved
	// leaves a stale entry that would allow a newcomer of that name.
	for sel, owners := range fwExemptOwners {
		for _, o := range owners {
			if !seen[sel+"<-"+o] {
				t.Errorf("%s: listed owner %s no longer calls it; update the list", sel, o)
			}
		}
	}
	for sel, owners := range fwRawLibvirt {
		for _, o := range owners {
			if !seen[sel+"<-"+o] {
				t.Errorf("%s: listed function %s no longer calls it; update the list", sel, o)
			}
		}
	}
}

// D2-14 review I-1: the marker refusal at migrateOwnedVM's entry stops only a
// new migration. migrateOwnedVM is entered only by MigrateVM and drainMove
// (drain's cold moves, and a running Secure Boot / vTPM VM's live firmware
// move, D2-17: each a new migration the entry refusal stops); a live move
// writes its marker after the entry, and the adopter and restart recovery
// carry the move on without re-entering it, so a marker of
// a move in progress never refuses that move's own steps. (The live happy
// path, TestMigrateVM_FirmwareLive_HappyPathOrder, and the adopter,
// TestAdoptedFirmwareMigration_VerifiesBeforeCommit, run through it.)
//
// Mutation: call migrateOwnedVM from the adopter or the recovery — red.
func TestMigrateOwnedVM_EnteredOnlyByMigrateAndDrain(t *testing.T) {
	allowed := map[string]bool{
		"internal/grpcapi.Server.MigrateVM": true,
		"internal/grpcapi.Server.drainMove": true,
	}
	n := 0
	for _, c := range fwCallSites(t, map[string]bool{"migrateOwnedVM": true}) {
		n++
		if !allowed[c.caller] {
			t.Errorf("migrateOwnedVM called from %s at %s", c.caller, c.pos)
		}
	}
	if n != len(allowed) {
		t.Fatalf("%d calls of migrateOwnedVM, want one from each of %v", n, allowed)
	}
}

// drainMove is migrateOwnedVM's drain entry: a cold move (drainColdMove) or a
// running Secure Boot / vTPM VM's live firmware move (drainRunningFirmwareVM),
// each under drain's lock discipline. A third caller would reach
// migrateOwnedVM past the guard above.
//
// Mutation: call drainMove from drainOneVM directly — red.
func TestDrainMove_EnteredOnlyByDrainsMoves(t *testing.T) {
	allowed := map[string]bool{
		"internal/grpcapi.Server.drainColdMove":          true,
		"internal/grpcapi.Server.drainRunningFirmwareVM": true,
	}
	n := 0
	for _, c := range fwCallSites(t, map[string]bool{"drainMove": true}) {
		n++
		if !allowed[c.caller] {
			t.Errorf("drainMove called from %s at %s", c.caller, c.pos)
		}
	}
	if n != len(allowed) {
		t.Fatalf("%d calls of drainMove, want one from each of %v", n, allowed)
	}
}

// Bound owners earn their narrow raw-call entries only while their current
// firmware gate, exact UUID identity, and guarded same-handle effects remain.
func fwBoundStartSources(t *testing.T) map[string][]byte {
	t.Helper()
	out := map[string][]byte{}
	for _, file := range []string{"domain.go", "console_password.go", "start_guard.go"} {
		raw, err := os.ReadFile(filepath.Join("..", "libvirt", file))
		if err != nil {
			t.Fatal(err)
		}
		out[file] = raw
	}
	return out
}
func fwBoundStartProblems(sources map[string][]byte) []string {
	funcs := map[string]*ast.FuncDecl{}
	for file, raw := range sources {
		f, err := parser.ParseFile(token.NewFileSet(), file, raw, parser.SkipObjectResolution)
		if err != nil {
			return []string{fmt.Sprintf("parse %s: %v", file, err)}
		}
		for _, d := range f.Decls {
			if f, ok := d.(*ast.FuncDecl); ok {
				funcs[f.Name.Name] = f
			}
		}
	}
	text := func(n ast.Node) string {
		var b bytes.Buffer
		_ = printer.Fprint(&b, token.NewFileSet(), n)
		return b.String()
	}
	var problems []string
	check := func(ok bool, boundary string) {
		if !ok {
			problems = append(problems, boundary)
		}
	}
	callInAssignment := func(s ast.Stmt) string {
		if a, ok := s.(*ast.AssignStmt); ok && len(a.Rhs) == 1 {
			return text(a.Rhs[0])
		}
		return ""
	}
	tail := func(f *ast.FuncDecl) string {
		if f == nil || f.Body == nil || len(f.Body.List) == 0 {
			return ""
		}
		if r, ok := f.Body.List[len(f.Body.List)-1].(*ast.ReturnStmt); ok && len(r.Results) == 1 {
			return text(r.Results[0])
		}
		return ""
	}
	returningIf := func(f *ast.FuncDecl, cond string) token.Pos {
		if f == nil || f.Body == nil {
			return token.NoPos
		}
		for _, statement := range f.Body.List {
			if branch, ok := statement.(*ast.IfStmt); ok && text(branch.Cond) == cond && len(branch.Body.List) == 1 {
				if _, ok := branch.Body.List[0].(*ast.ReturnStmt); ok {
					return branch.Pos()
				}
			}
		}
		return token.NoPos
	}
	entry := funcs["StartDomainBound"]
	entryOK := entry != nil && entry.Body != nil && len(entry.Body.List) == 3
	if entryOK {
		entryOK = callInAssignment(entry.Body.List[0]) == "c.guard(name)" && returningIf(entry, "err != nil") != token.NoPos && tail(entry) == "startDomainBound(c.virt, g, name, expectedUUID, c.consoleDecision(), c.SetVNCPasswordUnavailable)"
	}
	check(entryOK, "bound entry lost its firmware/start guard")
	guard := funcs["guard"]
	guardOK := false
	if guard != nil && guard.Body != nil && len(guard.Body.List) > 0 {
		if branch, ok := guard.Body.List[0].(*ast.IfStmt); ok && branch.Init != nil {
			guardOK = callInAssignment(branch.Init) == "c.firmwareGuard().check(FirmwareCall{Op: OpStart, Name: name})" && text(branch.Cond) == "err != nil" && len(branch.Body.List) == 1
			if guardOK {
				_, guardOK = branch.Body.List[0].(*ast.ReturnStmt)
			}
		}
	}
	check(guardOK, "bound entry lost firmware OpStart refusal before readiness")
	bound := funcs["startDomainBound"]
	boundOK := bound != nil && bound.Body != nil && len(bound.Body.List) == 6
	if boundOK {
		boundOK = callInAssignment(bound.Body.List[0]) == "boundDomainUUID(expectedUUID)" && callInAssignment(bound.Body.List[2]) == "v.DomainLookupByName(name)" && returningIf(bound, "dom.Name != name || dom.UUID != uuid") != token.NoPos && tail(bound) == "startBoundWithConsoleBackstop(v, g, dom, policy, unavailable)"
	}
	check(boundOK, "bound helper lost UUID/name gate or guard forwarding")
	handle := funcs["startBoundHandle"]
	handleOK := handle != nil && handle.Body != nil && len(handle.Body.List) == 1
	if handleOK {
		ret, ok := handle.Body.List[0].(*ast.ReturnStmt)
		handleOK = ok && len(ret.Results) == 1
		if handleOK {
			call, ok := ret.Results[0].(*ast.CallExpr)
			handleOK = ok && text(call.Fun) == "guardedStart" && len(call.Args) == 5 && text(call.Args[0]) == "g" && text(call.Args[1]) == "dom.Name"
			if handleOK {
				seen := map[string]int{}
				ast.Inspect(call, func(n ast.Node) bool {
					if c, ok := n.(*ast.CallExpr); ok {
						if sel, ok := c.Fun.(*ast.SelectorExpr); ok && (sel.Sel.Name == "DomainResume" || sel.Sel.Name == "DomainDestroy") {
							seen[sel.Sel.Name]++
							if len(c.Args) != 1 || text(c.Args[0]) != "dom" {
								handleOK = false
							}
						}
					}
					return true
				})
				handleOK = handleOK && seen["DomainResume"] == 1 && seen["DomainDestroy"] == 1
			}
		}
	}
	check(handleOK, "bound effects lost guarded same-handle resume/destroy ownership")
	console := funcs["startBoundWithConsoleBackstop"]
	consoleOK := console != nil && console.Body != nil && len(console.Body.List) > 0
	if consoleOK {
		consoleOK = callInAssignment(console.Body.List[0]) == "startBoundHandle(v, g, dom)" && tail(console) == "startBoundHandle(v, g, dom)"
		before := returningIf(console, "xerr != nil || !boundConsoleXML(x, dom) || !HasConsolePassword(x)")
		after := returningIf(console, "redefined.Name != dom.Name || redefined.UUID != dom.UUID")
		defines := 0
		ast.Inspect(console.Body, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok && text(call.Fun) == "v.DomainDefineXML" {
				defines++
				if before == token.NoPos || after == token.NoPos || before >= call.Pos() || after <= call.End() || len(call.Args) != 1 || text(call.Args[0]) != "stripped" {
					consoleOK = false
				}
			}
			return true
		})
		consoleOK = consoleOK && defines == 1
	}
	check(consoleOK, "bound console redefine lost exact identity or guarded retry boundary")
	return problems
}

func TestFirmwareMoveBoundOwnersRejectUnsafeCurrentPaths(t *testing.T) {
	sources := fwBoundStartSources(t)
	for _, tc := range []struct{ name, file, before, after, want string }{
		{"entry-guard", "domain.go", "g, err := c.guard(name)", "g, err := c.uncheckedGuard(name)", "bound entry lost its firmware/start guard"},
		{"firmware-gate", "start_guard.go", "c.firmwareGuard().check(FirmwareCall{Op: OpStart, Name: name})", "c.firmwareGuard().check(FirmwareCall{Op: OpResume, Name: name})", "lost firmware OpStart refusal"},
		{"uuid-gate", "domain.go", "dom.Name != name || dom.UUID != uuid", "dom.Name != name", "lost UUID/name gate"},
		{"guard-forwarding", "domain.go", "return guardedStart(g, dom.Name", "return guardedStart(StartGuard{}, dom.Name", "lost guarded same-handle"},
		{"foreign-cleanup", "domain.go", "return v.DomainResume(dom)", "return v.DomainResume(golibvirt.Domain{Name: dom.Name})", "lost guarded same-handle"},
		{"console-original", "console_password.go", "!boundConsoleXML(x, dom)", "false", "lost exact identity"},
		{"console-successor", "console_password.go", "redefined.Name != dom.Name || redefined.UUID != dom.UUID", "redefined.Name != dom.Name", "lost exact identity"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := map[string][]byte{}
			for name, raw := range sources {
				changed[name] = raw
			}
			// The entry guard spelling also exists in ordinary StartDomain. Select
			// the bound method's actual AST span, never an unrelated first match.
			raw := string(sources[tc.file])
			start := 0
			if tc.name == "entry-guard" {
				start = strings.Index(raw, "func (c *Client) StartDomainBound(")
			}
			if start < 0 {
				t.Fatal("bound entry disappeared")
			}
			at := strings.Index(raw[start:], tc.before)
			if at < 0 {
				t.Fatal("mutation did not reach bound owner")
			}
			at += start
			changed[tc.file] = []byte(raw[:at] + tc.after + raw[at+len(tc.before):])
			got := strings.Join(fwBoundStartProblems(changed), "\n")
			if strings.Contains(got, "parse ") || !strings.Contains(got, tc.want) {
				t.Fatalf("wrong boundary refusal: %s, want %q", got, tc.want)
			}
		})
	}
}

func fwCallsInSyntax(fset *token.FileSet, f *ast.File, pkg string, names map[string]bool) []fwCallSite {
	var out []fwCallSite
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		caller := pkg + "." + fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			rt := fd.Recv.List[0].Type
			if st, ok := rt.(*ast.StarExpr); ok {
				rt = st.X
			}
			if id, ok := rt.(*ast.Ident); ok {
				caller = pkg + "." + id.Name + "." + fd.Name.Name
			}
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch fn := call.Fun.(type) {
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			case *ast.Ident:
				name = fn.Name
			}
			if names[name] {
				out = append(out, fwCallSite{sel: name, caller: caller, pos: fset.Position(call.Pos())})
			}
			return true
		})
	}
	return out
}

func fwAllowedCall(c fwCallSite) bool {
	allowed, exempt := fwExemptOwners[c.sel]
	if !exempt {
		allowed = fwRawLibvirt[c.sel]
	}
	for _, owner := range allowed {
		if owner == c.caller {
			return true
		}
	}
	return false
}
func TestFirmwareMoveGuardRejectsUnownedRawAndBoundCalls(t *testing.T) {
	raw := string(fwBoundStartSources(t)["domain.go"])
	raw += `
func unsafeBoundStart(v snapshotAPI, dom golibvirt.Domain) {
 _ = v.DomainDestroy(dom)
 _ = startBoundHandle(v, StartGuard{}, dom)
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "domain.go", raw, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{"DomainDestroy": true, "startBoundHandle": true}
	found := map[string]bool{}
	for _, call := range fwCallsInSyntax(fset, f, "internal/libvirt", names) {
		if call.caller == "internal/libvirt.unsafeBoundStart" {
			if fwAllowedCall(call) {
				t.Fatalf("unowned current call accepted: %s", call.sel)
			}
			found[call.sel] = true
		}
	}
	if !found["DomainDestroy"] || !found["startBoundHandle"] {
		t.Fatalf("bad current paths were not inspected: %v", found)
	}
}
