package daemon

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// Codex I4: the first pass over the swtpm tree (vtpm_state_sync) completes,
// or runs past its wait and raises vtpm_state_not_durable, before anything
// on this host can start a VM. The vTPM capability label orders placement
// only; an onboot start, a restart policy, a cutover or operation recovery,
// a drain recovery or an API start on this host does not ask it, so Run
// waits for the pass before it launches any of them.
//
// Asserted against the source, as TestRunLaunchesDrainRecoveryAfterTheStartupBarrier
// is: Run opens libvirt, binds sockets and joins gossip.
//
// Mutation: move awaitFirstVTPMPass back to the capability labels, after
// the runtime loops start, and this goes red.
func TestRunAwaitsTheFirstVTPMPassBeforeAnyVMStart(t *testing.T) {
	daemon, workers, registration := readFirmwareWiring(t)
	if err := vtpmStartupOrderError(daemon, workers, registration); err != nil {
		t.Fatal(err)
	}
}

func vtpmStartupOrderError(source, workers, registration string) error {
	// A helper name is a VM starter only if its real body and owned context
	// remain bound to the service. Do not silently drop firmware coverage.
	if err := firmwareWiringError(source, workers, registration); err != nil {
		return err
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon.go", source, 0)
	if err != nil {
		return fmt.Errorf("parse daemon.go: %w", err)
	}
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Run" && fn.Recv != nil {
			run = fn
		}
	}
	if run == nil {
		return fmt.Errorf("no (*Daemon).Run in daemon.go")
	}
	first := map[string]int{}
	ast.Inspect(run, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		var name string
		switch fn := call.Fun.(type) {
		case *ast.Ident:
			name = fn.Name
		case *ast.SelectorExpr:
			name = fn.Sel.Name
			if x, ok := fn.X.(*ast.Ident); ok && name == "Start" {
				name = x.Name + ".Start"
			}
		default:
			return true
		}
		if _, seen := first[name]; !seen {
			first[name] = int(call.Pos())
		}
		return true
	})
	at, ok := first["awaitFirstVTPMPass"]
	if !ok {
		return fmt.Errorf("(*Daemon).Run never awaits the first vTPM pass")
	}
	for _, starter := range []string{
		"resumeVMReplaceCleanups", "runOperationRecovery", "SetStartGuard",
		"vmChecker.Start", "reconciler.Start", "StartOnbootVMs", "RunDrainColdMoveRecovery",
		"RunHeldGuestResumer", "fc.Start", "Serve",
		// D2: the live firmware move recovery can resume a guest.
		"recoverFirmwareMoves", "startFirmwareMoveRecovery",
	} {
		pos, ok := first[starter]
		if !ok {
			return fmt.Errorf("(*Daemon).Run no longer calls %s; update this test's list of VM starters", starter)
		}
		if pos < at {
			return fmt.Errorf("%s (%s) runs before the first vTPM pass is awaited (%s)",
				starter, fset.Position(token.Pos(pos)), fset.Position(token.Pos(at)))
		}
	}
	return nil
}

func TestVTPMStartupOrderRejectsMovedBarrier(t *testing.T) {
	daemon, workers, registration := readFirmwareWiring(t)
	if err := vtpmStartupOrderError(daemon, workers, registration); err != nil {
		t.Fatal(err)
	}
	const wait = "awaitFirstVTPMPass(tpmCapable)"
	for _, starter := range []string{"dbWorkers.recoverFirmwareMoves(ctx)", "dbWorkers.startFirmwareMoveRecovery(ctx)", "go vmChecker.Start(ctx)"} {
		t.Run(starter, func(t *testing.T) {
			if strings.Count(daemon, wait) != 1 || strings.Count(daemon, starter) != 1 {
				t.Fatal("mutation must identify exact source sites")
			}
			moved := strings.Replace(daemon, wait, "", 1)
			moved = strings.Replace(moved, starter, starter+"\n\t"+wait, 1)
			if err := vtpmStartupOrderError(moved, workers, registration); err == nil {
				t.Fatal("VM starter before the vTPM barrier escaped the guard")
			}
		})
	}
}
