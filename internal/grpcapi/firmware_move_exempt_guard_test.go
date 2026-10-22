package grpcapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
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
		"internal/libvirt.undefineDomainPreservingState", "internal/libvirt.undefineDeletedDomainKeepingState", "internal/libvirt.undefineKeepingState",
		"internal/libvirt.forceRemoveDomain", "internal/libvirt.revertToLiveSnapshot", "internal/libvirt.revertToSnapshot",
	},
	"DomainResume": {
		"internal/libvirt.startDomainGuarded", "internal/libvirt.resumeDomain",
		"internal/libvirt.capture.settle", "internal/libvirt.restoreWithRetry",
	},
	"DomainDestroy": {
		"internal/libvirt.startDomainGuarded", "internal/libvirt.destroyDomain", "internal/libvirt.discardFirmwareMoveTarget",
		"internal/libvirt.stopForOperator", "internal/libvirt.forceRemoveDomain",
		"internal/libvirt.restoreWithRetry", "internal/libvirt.revertToLiveSnapshot", "internal/libvirt.revertToSnapshot",
	},
	"DomainDefineXML": {
		"internal/libvirt.keepConsolePITAPI.DomainDefineXML", "internal/libvirt.keepConsoleSnapshotAPI.DomainDefineXML",
		"internal/libvirt.startWithConsoleBackstop", "internal/libvirt.Client.SetBootOrder", "internal/libvirt.defineDomain",
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
			for _, decl := range f.Decls {
				fd, ok := decl.(*ast.FuncDecl)
				if !ok || fd.Body == nil {
					continue
				}
				caller := filepath.ToSlash(rel) + "." + fd.Name.Name
				if fd.Recv != nil && len(fd.Recv.List) == 1 {
					rt := fd.Recv.List[0].Type
					if st, ok := rt.(*ast.StarExpr); ok {
						rt = st.X
					}
					if id, ok := rt.(*ast.Ident); ok {
						caller = filepath.ToSlash(rel) + "." + id.Name + "." + fd.Name.Name
					}
				}
				ast.Inspect(fd.Body, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					if se, ok := call.Fun.(*ast.SelectorExpr); ok && names[se.Sel.Name] {
						out = append(out, fwCallSite{sel: se.Sel.Name, caller: caller, pos: fset.Position(call.Pos())})
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func TestFirmwareMoveExemptCallers(t *testing.T) {
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
		allowed, exempt := fwExemptOwners[c.sel]
		if !exempt {
			allowed = fwRawLibvirt[c.sel]
		}
		ok := false
		for _, a := range allowed {
			if a == c.caller {
				ok = true
			}
		}
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
