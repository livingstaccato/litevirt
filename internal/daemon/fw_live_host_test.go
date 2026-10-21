package daemon

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// The Prepare check of a live firmware move's target (spec §6.2 item 1): the
// label's conditions, read now, with the first that fails named, and the
// installed runtime when every one holds.
//
// Mutations: drop any one condition — its row passes, red; return a zero
// runtime — the all-true row goes red.
func TestFwLiveHostCheck_Reasons(t *testing.T) {
	off := false
	cases := []struct {
		name string
		cfg  MigrationConfig
		set  func(*fwLiveHost)
		want string // "" = passes
	}{
		{"all preconditions", MigrationConfig{}, func(*fwLiveHost) {}, ""},
		{"config off", MigrationConfig{LiveFirmware: &off}, func(*fwLiveHost) {}, "migration.live_firmware is off"},
		{"tpm missing", MigrationConfig{}, func(h *fwLiveHost) { h.tpm = func() bool { return false } }, "vTPM"},
		{"secure boot missing", MigrationConfig{}, func(h *fwLiveHost) { h.secureBoot = func() bool { return false } }, "Secure Boot"},
		{"installed unreadable", MigrationConfig{}, func(h *fwLiveHost) {
			h.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
				return libvirt.InstalledFirmwareCode{}, errors.New("swtpm: not found")
			}
		}, "swtpm: not found"},
		{"below a floor", MigrationConfig{}, func(h *fwLiveHost) {
			h.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
				v, _ := okInstalled()
				v.Runtime.Libtpms = "0.9.2"
				return v, nil
			}
		}, "libtpms 0.9.2 is below the live firmware migration floor 0.9.3"},
		{"libvirt-guests", MigrationConfig{}, func(h *fwLiveHost) {
			h.guests = func(context.Context) error { return errors.New("ON_SHUTDOWN=suspend") }
		}, "libvirt-guests: ON_SHUTDOWN=suspend"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := okHost()
			c.set(&h)
			code, err := fwLiveHostCheck{cfg: c.cfg, h: h}.Check(context.Background())
			rt := code.Runtime
			if c.want == "" {
				want, _ := okInstalled()
				if err != nil || rt != want.Runtime {
					t.Fatalf("check = %+v, %v", rt, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || rt != (libvirt.FirmwareRuntime{}) {
				t.Fatalf("check = %+v, %v; want an error naming %q", rt, err, c.want)
			}
		})
	}
}

// D-9 is read live on every Prepare, never from a cached answer or the label.
//
// Mutation: read libvirt-guests once and reuse it — red.
func TestFwLiveHostCheck_LibvirtGuestsReadEachTime(t *testing.T) {
	h := okHost()
	calls := 0
	h.guests = func(context.Context) error { calls++; return nil }
	check := fwLiveHostCheck{cfg: MigrationConfig{}, h: h}
	for i := 0; i < 3; i++ {
		if _, err := check.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Fatalf("libvirt-guests read %d times in 3 checks", calls)
	}
}

// The production probes behind the label and the host check read
// libvirt-guests with CheckLibvirtGuests, and the installed and running code
// from one probe.
//
// Mutations: hand newFwLiveHost another guests check, or leave running unset
// — red.
func TestNewFwLiveHost_ReadsLibvirtGuests(t *testing.T) {
	h := newFwLiveHost(libvirt.NewFirmwareStore(t.TempDir()), libvirt.FirmwarePaths{},
		func() (uint64, error) { return 10000000, nil }, func() bool { return true })
	if reflect.ValueOf(h.guests).Pointer() != reflect.ValueOf(CheckLibvirtGuests).Pointer() {
		t.Fatal("newFwLiveHost does not read libvirt-guests with CheckLibvirtGuests")
	}
	if h.installed == nil || h.running == nil {
		t.Fatal("newFwLiveHost has no installed or running code probe")
	}
}

// RunningFirmwareCode is the probe's, given the live XML, under a deadline
// of fwLiveProbeTimeout; its error is passed on.
//
// Mutations: call it without the deadline, or drop the XML — red.
func TestFwLiveHostCheck_RunningFirmwareCodeBounded(t *testing.T) {
	h := okHost()
	var gotXML string
	var deadline time.Time
	var hasDeadline bool
	h.running = func(ctx context.Context, x string) (libvirt.FirmwareRuntime, error) {
		gotXML = x
		deadline, hasDeadline = ctx.Deadline()
		return libvirt.FirmwareRuntime{QEMU: "8.2.2"}, nil
	}
	start := time.Now()
	rt, err := fwLiveHostCheck{h: h}.RunningFirmwareCode(context.Background(), "<domain/>")
	if err != nil || rt.QEMU != "8.2.2" || gotXML != "<domain/>" {
		t.Fatalf("running = %+v, %v (xml %q)", rt, err, gotXML)
	}
	if !hasDeadline || deadline.Sub(start) > fwLiveProbeTimeout+time.Second {
		t.Fatalf("running code read without the %s bound (deadline %v, set %v)", fwLiveProbeTimeout, deadline.Sub(start), hasDeadline)
	}
	h.running = func(context.Context, string) (libvirt.FirmwareRuntime, error) {
		return libvirt.FirmwareRuntime{}, errors.New("qemu exe (deleted)")
	}
	if _, err := (fwLiveHostCheck{h: h}).RunningFirmwareCode(context.Background(), "<domain/>"); err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("running error = %v", err)
	}
}

// Check runs under a deadline of fwLiveProbeTimeout.
//
// Mutation: drop the deadline from Check — red.
func TestFwLiveHostCheck_CheckBounded(t *testing.T) {
	h := okHost()
	var hasDeadline bool
	h.installed = func(ctx context.Context) (libvirt.InstalledFirmwareCode, error) {
		_, hasDeadline = ctx.Deadline()
		return okInstalled()
	}
	if _, err := (fwLiveHostCheck{h: h}).Check(context.Background()); err != nil || !hasDeadline {
		t.Fatalf("check = %v, deadline set %v", err, hasDeadline)
	}
}

// Firmware startup is delegated to the DB worker owner. Pin both the Run
// wiring and the helper implementations; a renamed or empty helper is not
// evidence that recovery runs or that shutdown joins its producers.
func firmwareWiringError(daemonSource, workerSource, registrationSource string) error {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "daemon.go", daemonSource, 0)
	if err != nil {
		return err
	}
	var run *ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "Run" && fn.Recv != nil {
			run = fn
		}
	}
	if run == nil {
		return fmt.Errorf("missing daemon Run")
	}
	run, err = executionOwnedRun(run)
	if err != nil {
		return err
	}
	if len(run.Type.Params.List) == 0 || len(run.Type.Params.List[0].Names) != 1 {
		return fmt.Errorf("missing Run context")
	}
	parent := runVar(run.Type.Params.List[0].Names[0])
	var worker, service *ast.Object
	for _, statement := range run.Body.List {
		a, ok := statement.(*ast.AssignStmt)
		if !ok || a.Tok != token.DEFINE || len(a.Lhs) != 1 || len(a.Rhs) != 1 {
			continue
		}
		call, ok := a.Rhs[0].(*ast.CallExpr)
		if !ok || !isFuncCall(call, "newDBWorkerCoordinator") {
			continue
		}
		if worker != nil || len(call.Args) != 2 || parent == nil || runVar(call.Args[0]) != parent {
			return fmt.Errorf("wrong coordinator parent or duplicate coordinator")
		}
		worker, service = runVar(a.Lhs[0]), runVar(call.Args[1])
	}
	if worker == nil || service == nil {
		return fmt.Errorf("missing coordinator/service binding")
	}
	wanted := map[string]bool{
		"recoverFirmwareMoves": true, "startFirmwareSweeps": true, "startFirmwareMoveRecovery": true,
		"RecoverDeviceLeases": false, "RecoverResourceOperationsAtStart": false,
		"RecoverHardwareOperationsAtStart": false, "RunDrainColdMoveRecovery": false,
		"MarkStartupWired": false, "RegisterServices": false, "SetLiveFirmwareHost": false,
	}
	positions := map[string]token.Pos{}
	var invalid error
	ast.Inspect(run.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		owned, selected := wanted[sel.Sel.Name]
		if !selected {
			return true
		}
		name := sel.Sel.Name
		receiver := service
		if owned {
			receiver = worker
		}
		if runVar(sel.X) != receiver || positions[name] != token.NoPos {
			invalid = fmt.Errorf("wrong receiver or duplicate %s", name)
			return true
		}
		positions[name] = call.Pos()
		if name != "SetLiveFirmwareHost" && name != "RegisterServices" && name != "MarkStartupWired" {
			if len(call.Args) != 1 || runVar(call.Args[0]) != parent {
				invalid = fmt.Errorf("wrong context for %s", name)
			}
		}
		return true
	})
	if invalid != nil {
		return invalid
	}
	for name := range wanted {
		if positions[name] == token.NoPos {
			return fmt.Errorf("missing %s", name)
		}
	}
	// Other than device recovery, every site must be a direct owned-startup
	// statement. In particular initial recovery must not become asynchronous.
	direct := map[string]bool{}
	for _, statement := range run.Body.List {
		var call *ast.CallExpr
		switch s := statement.(type) {
		case *ast.ExprStmt:
			call, _ = s.X.(*ast.CallExpr)
		case *ast.GoStmt:
			if isMethodCall(s.Call, "RunDrainColdMoveRecovery") {
				call = s.Call
			}
		}
		if call != nil {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok && positions[sel.Sel.Name] == call.Pos() {
				direct[sel.Sel.Name] = true
			}
		}
	}
	for name := range wanted {
		if name != "RecoverDeviceLeases" && !direct[name] {
			return fmt.Errorf("%s must remain direct owned-startup wiring", name)
		}
	}
	order := []string{"RecoverDeviceLeases", "recoverFirmwareMoves", "RecoverResourceOperationsAtStart", "RecoverHardwareOperationsAtStart", "RunDrainColdMoveRecovery", "startFirmwareSweeps", "MarkStartupWired", "startFirmwareMoveRecovery", "RegisterServices"}
	for i := 1; i < len(order); i++ {
		if positions[order[i-1]] >= positions[order[i]] {
			return fmt.Errorf("%s must precede %s", order[i-1], order[i])
		}
	}
	// Bind the host check constructor and the registered gRPC server to this
	// daemon rather than accepting a same-named call on a different object.
	var hostOK, registerOK bool
	ast.Inspect(run.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if call.Pos() == positions["SetLiveFirmwareHost"] && len(call.Args) == 1 {
			constructor, ok := call.Args[0].(*ast.CallExpr)
			if ok && isFuncCall(constructor, "newFwLiveHostCheck") && len(constructor.Args) > 0 {
				migration, ok := constructor.Args[0].(*ast.SelectorExpr)
				if ok && migration.Sel.Name == "Migration" {
					cfg, ok := migration.X.(*ast.SelectorExpr)
					hostOK = ok && cfg.Sel.Name == "cfg" && len(run.Recv.List[0].Names) == 1 && runVar(cfg.X) == runVar(run.Recv.List[0].Names[0])
				}
			}
		}
		if call.Pos() == positions["RegisterServices"] && len(call.Args) == 1 {
			srv, ok := call.Args[0].(*ast.SelectorExpr)
			registerOK = ok && srv.Sel.Name == "grpcSrv" && len(run.Recv.List[0].Names) == 1 && runVar(srv.X) == runVar(run.Recv.List[0].Names[0])
		}
		return true
	})
	if !hostOK || !registerOK {
		return fmt.Errorf("host check or service registration is not bound to the actual daemon")
	}
	if err := exactFirmwareHelpers(workerSource, firmwareOwnerContract); err != nil {
		return err
	}
	return exactFirmwareHelpers(registrationSource, firmwareRegistrationContract)
}

// Compare parsed declarations, not text fragments: comments and formatting do
// not matter, but empty bodies, wrong contexts, detached/unjoined goroutines,
// substituted services and changed registration arguments all fail. These small
// boundary helpers intentionally require review when their contract changes.
func exactFirmwareHelpers(source, contract string) error {
	parse := func(src string) (map[string]string, error) {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "wiring.go", src, 0)
		if err != nil {
			return nil, err
		}
		functions := map[string]string{}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			if _, exists := functions[fn.Name.Name]; exists {
				return nil, fmt.Errorf("duplicate helper %s", fn.Name.Name)
			}
			// Tokenize only this parsed declaration. Normalize semicolon spelling
			// so line layout and comments cannot affect the comparison.
			fragment := src[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset]
			var scan scanner.Scanner
			scan.Init(token.NewFileSet().AddFile("helper", -1, len(fragment)), []byte(fragment), nil, 0)
			var b strings.Builder
			for {
				_, kind, literal := scan.Scan()
				if kind == token.EOF {
					break
				}
				if kind == token.SEMICOLON {
					literal = ";"
				}
				fmt.Fprintf(&b, "%s:%q\n", kind, literal)
			}
			functions[fn.Name.Name] = b.String()
		}
		return functions, nil
	}
	actual, err := parse(source)
	if err != nil {
		return err
	}
	expected, err := parse(contract)
	if err != nil {
		return err
	}
	for name, want := range expected {
		if actual[name] != want {
			return fmt.Errorf("%s no longer implements the reviewed ownership/registration contract", name)
		}
	}
	return nil
}

const firmwareOwnerContract = `package daemon
func (c *dbWorkerCoordinator) shutdown(ctx context.Context, reexec, shutdown <-chan struct{}, prepare func(daemonStopReason), stopServing, cleanup func()) {
	var reason daemonStopReason
	select {
	case <-ctx.Done():
		reason = daemonContextStop
	case <-reexec:
		reason = daemonReExecStop
	case <-shutdown:
		reason = daemonUninstallStop
	}
	c.svc.StopDeleteVMAdmission()
	c.svc.StopFirewallTagAdmission()
	c.svc.StopMigrationAdmission()
	prepare(reason)
	c.cancel()
	stopServing()
	c.wait()
	cleanup()
}
func newDBWorkerCoordinator(ctx context.Context, svc *grpcapi.Server) *dbWorkerCoordinator {
 ctx, cancel := context.WithCancel(ctx)
 return &dbWorkerCoordinator{ctx: ctx, cancel: cancel, svc: svc}
}
func (c *dbWorkerCoordinator) recoverFirmwareMoves(_ context.Context) {
 c.svc.RecoverFirmwareMoves(c.ctx)
}
func (c *dbWorkerCoordinator) startFirmwareSweeps(_ context.Context) {
 c.wg.Add(2)
 go func() { defer c.wg.Done(); c.svc.RunFirmwareHoldSweep(c.ctx) }()
 go func() { defer c.wg.Done(); c.svc.RunFirmwareRetainedSweep(c.ctx) }()
}
func (c *dbWorkerCoordinator) startFirmwareMoveRecovery(_ context.Context) {
 c.wg.Add(1)
 go func() { defer c.wg.Done(); c.svc.RunFirmwareMoveRecovery(c.ctx) }()
}
func (c *dbWorkerCoordinator) wait() {
 c.wg.Wait()
 c.svc.WaitFirmwareMoveRecovery()
 c.svc.WaitFirewallTagWork()
 c.svc.WaitDeleteVMWork()
 c.svc.WaitGatewayAnnouncements()
}
`

const firmwareRegistrationContract = `package grpcapi
func (s *Server) RegisterServices(registrar grpc.ServiceRegistrar) {
 pb.RegisterLiteVirtServer(registrar, s)
 automationv1.RegisterAutomationServer(registrar, s)
}
`

func readFirmwareWiring(t *testing.T) (string, string, string) {
	t.Helper()
	read := func(path string) string {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	return read("daemon.go"), read("db_workers.go"), read("../grpcapi/automation_public.go")
}

func TestFwLiveTarget_WiredInDaemon(t *testing.T) {
	if err := firmwareWiringError(readFirmwareWiring(t)); err != nil {
		t.Fatal(err)
	}
}

func TestFwLiveRecovery_StartupOrder(t *testing.T) {
	if err := firmwareWiringError(readFirmwareWiring(t)); err != nil {
		t.Fatal(err)
	}
}

func TestFirmwareWiringRejectsUnsafeDelegation(t *testing.T) {
	daemon, workers, registration := readFirmwareWiring(t)
	for _, tc := range []struct{ name, target, old, replacement string }{
		{"control", "", "", ""},
		{"empty_initial_helper", "workers", "c.svc.RecoverFirmwareMoves(c.ctx)", ""},
		{"wrong_helper_context", "workers", "c.svc.RecoverFirmwareMoves(c.ctx)", "c.svc.RecoverFirmwareMoves(context.Background())"},
		{"missing_producer_join", "workers", "c.wg.Wait()", ""},
		{"missing_shutdown_join", "workers", "\n\tc.wait()\n\tcleanup()", "\n\tcleanup()"},
		{"missing_recovery_done", "workers", "go func() { defer c.wg.Done(); c.svc.RunFirmwareMoveRecovery(c.ctx) }()", "go c.svc.RunFirmwareMoveRecovery(c.ctx)"},
		{"missing_producer_add", "workers", "c.wg.Add(2)", ""},
		{"wrong_worker", "daemon", "dbWorkers.recoverFirmwareMoves(ctx)", "other.recoverFirmwareMoves(ctx)"},
		{"wrong_context", "daemon", "dbWorkers.recoverFirmwareMoves(ctx)", "dbWorkers.recoverFirmwareMoves(other)"},
		{"async_initial_recovery", "daemon", "dbWorkers.recoverFirmwareMoves(ctx)", "go dbWorkers.recoverFirmwareMoves(ctx)"},
		{"late_initial_recovery", "daemon", "dbWorkers.recoverFirmwareMoves(ctx)", ""},
		{"early_periodic_recovery", "daemon", "svc.MarkStartupWired()\n\t\tdbWorkers.startFirmwareMoveRecovery(ctx)", "dbWorkers.startFirmwareMoveRecovery(ctx)\n\t\tsvc.MarkStartupWired()"},
		{"wrong_registration_service", "registration", "pb.RegisterLiteVirtServer(registrar, s)", "pb.RegisterLiteVirtServer(registrar, other)"},
		{"missing_registration", "registration", "pb.RegisterLiteVirtServer(registrar, s)", ""},
		{"wrong_registration_server", "daemon", "svc.RegisterServices(d.grpcSrv)", "svc.RegisterServices(other.grpcSrv)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, w, r := daemon, workers, registration
			var target *string
			switch tc.target {
			case "daemon":
				target = &d
			case "workers":
				target = &w
			case "registration":
				target = &r
			}
			if target != nil {
				if strings.Count(*target, tc.old) != 1 {
					t.Fatal("mutation must identify exactly one source site")
				}
				*target = strings.Replace(*target, tc.old, tc.replacement, 1)
				if tc.name == "late_initial_recovery" {
					d = strings.Replace(d, "svc.MarkStartupWired()", "dbWorkers.recoverFirmwareMoves(ctx)\n\t\tsvc.MarkStartupWired()", 1)
				}
			}
			err := firmwareWiringError(d, w, r)
			if tc.name == "control" && err != nil {
				t.Fatal(err)
			}
			if tc.name != "control" && err == nil {
				t.Fatal("unsafe firmware delegation escaped the guard")
			}
		})
	}
}
