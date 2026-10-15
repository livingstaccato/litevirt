package fwmig

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

const (
	wireVM      = "vm1"
	wireUUID    = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	wireAttempt = "6f1c0c5e-0a43-4c55-9b5e-2b2b1f4d0e11"
)

func wireMarker(vm string, phase Phase) Marker {
	return Marker{
		VM: vm, Binding: Binding{UUID: wireUUID, CreatedAt: "2026-10-15T00:00:00Z", Attempt: wireAttempt},
		Target: "node-2", Route: RouteTunnelled, Phase: phase, TPM: true, UEFI: true,
		Since: time.Unix(1, 0).UTC(),
	}
}

func wireHold(vm string, s HoldState) Hold {
	return Hold{
		VM: vm, Binding: Binding{UUID: wireUUID, CreatedAt: "2026-10-15T00:00:00Z", Attempt: wireAttempt},
		Source: "node-1", Since: time.Unix(1, 0).UTC(), State: s, TPM: true, UEFI: true,
		NvramMaterialised: NvramDone,
	}
}

// The guard's rules (internal/libvirt) name record states by value; they
// must be fwmig's, and every hold state fwmig can write must be one the
// rules know.
//
// Mutation: rename a hold state or PhaseCleaning on either side — red.
func TestFwmigWire_StateNamesAgree(t *testing.T) {
	pairs := map[string]string{
		string(PhaseCleaning):           lv.FirmwarePhaseCleaning,
		string(HoldPrepared):            lv.FirmwareHoldPrepared,
		string(HoldVerified):            lv.FirmwareHoldVerified,
		string(HoldResuming):            lv.FirmwareHoldResuming,
		string(HoldMismatch):            lv.FirmwareHoldMismatch,
		string(HoldReleasedUnconfirmed): lv.FirmwareHoldReleasedUnconfirmed,
	}
	for f, l := range pairs {
		if f != l {
			t.Errorf("fwmig %q, libvirt %q", f, l)
		}
	}
	if n := len(AllHoldStates()); n != 5 {
		t.Errorf("fwmig has %d hold states; the guard's rules know 5", n)
	}
}

type recordingVirt struct{ g *lv.FirmwareMoveGuard }

func (v *recordingVirt) SetFirmwareMoveGuard(g lv.FirmwareMoveGuard) { v.g = &g }

// Wire installs one guard, over the records under the store's data dir, on
// the libvirt side and on the store.
//
// Mutations: Wire without the store install — the store keeps writing under
// a marker, red; records under another directory — nothing is refused, red.
func TestFwmigWire_InstallsOnVirtAndStore(t *testing.T) {
	store := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	virt := &recordingVirt{}
	Wire(virt, store)
	if virt.g == nil || virt.g.Check == nil {
		t.Fatal("no guard on the libvirt side")
	}
	start := lv.FirmwareCall{Op: lv.OpStart, Name: wireVM}
	if err := virt.g.Check(start); err != nil {
		t.Fatalf("no record: %v", err)
	}
	nvram := store.NvramPath(wireVM)
	if err := os.MkdirAll(filepath.Dir(nvram), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nvram, []byte("T0"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := New(store.DataDir).PutMarker(wireMarker(wireVM, PhaseMigrating)); err != nil {
		t.Fatal(err)
	}
	if err := virt.g.Check(start); !errors.Is(err, lv.ErrFirmwareMoveInFlight) {
		t.Fatalf("libvirt side under a marker: %v", err)
	}
	if err := store.RemoveNvram(wireVM); !errors.Is(err, lv.ErrFirmwareMoveInFlight) {
		t.Fatalf("store under a marker: %v", err)
	}
	if _, err := os.Stat(nvram); err != nil {
		t.Fatalf("the NVRAM went: %v", err)
	}
}

func TestFwmigWire_PanicsWithoutStore(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Wire took a nil store")
		}
	}()
	Wire(&recordingVirt{}, nil)
}

// Lookup finds the record under the name and any record of the uuid under
// another name; a record of another incarnation is still a record; a record
// that cannot be read is an error; an owed discard is not a record; a name
// that cannot be a VM name names nothing.
func TestFwmigWire_Lookup(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	if recs, err := r.Lookup(wireVM, wireUUID); err != nil || len(recs) != 0 {
		t.Fatalf("empty: %v %v", recs, err)
	}
	if err := r.PutOwedDiscard(OwedDiscard{VM: wireVM, Binding: wireMarker(wireVM, PhaseCutover).Binding, Target: "node-2", Since: time.Unix(1, 0)}); err != nil {
		t.Fatal(err)
	}
	if recs, err := r.Lookup(wireVM, wireUUID); err != nil || len(recs) != 0 {
		t.Fatalf("owed discard read as a record: %v %v", recs, err)
	}

	m := wireMarker("renamed", PhaseCleaning)
	m.CreatedAt = "1999-01-01T00:00:00Z" // another incarnation: still a veto
	if err := r.PutMarker(m); err != nil {
		t.Fatal(err)
	}
	if err := r.PutHold(wireHold(wireVM, HoldVerified)); err != nil {
		t.Fatal(err)
	}
	recs, err := r.Lookup(wireVM, "")
	if err != nil || len(recs) != 1 || recs[0].Kind != lv.FirmwareHold || recs[0].State != "verified" || recs[0].Peer != "node-1" || recs[0].Attempt != wireAttempt {
		t.Fatalf("by name: %+v %v", recs, err)
	}
	recs, err = r.Lookup("", strings.ToUpper(wireUUID))
	if err != nil || len(recs) != 2 {
		t.Fatalf("by uuid: %+v %v", recs, err)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Kind > recs[j].Kind })
	if recs[0].Kind != lv.FirmwareMarker || recs[0].VM != "renamed" || recs[0].RetainedBundle {
		t.Fatalf("marker by uuid: %+v", recs[0])
	}
	if recs, err := r.Lookup(wireVM, wireUUID); err != nil || len(recs) != 2 {
		t.Fatalf("by name and uuid: no duplicates, both records: %+v %v", recs, err)
	}

	// The retained bundle of a cleaning marker.
	p, err := r.RetainedPath("renamed", wireAttempt)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("tar"), 0o600); err != nil {
		t.Fatal(err)
	}
	if recs, err := r.Lookup("renamed", ""); err != nil || len(recs) != 1 || !recs[0].RetainedBundle {
		t.Fatalf("retained bundle not seen: %+v %v", recs, err)
	}

	// A name no VM can have names no record, and is not an error.
	if recs, err := r.Lookup("vm1.replace/old", ""); err != nil || len(recs) != 0 {
		t.Fatalf("invalid name: %v %v", recs, err)
	}

	// A record that cannot be read refuses, by name and by uuid.
	bad := filepath.Join(dir, InflightDir, "vm9.json")
	if err := os.WriteFile(bad, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Lookup("vm9", ""); err == nil {
		t.Fatal("corrupt marker read by name without an error")
	}
	if _, err := r.Lookup("", "0b5c44a3-6f7e-4a55-8a09-3c8d8f0f6a21"); err == nil {
		t.Fatal("corrupt marker skipped by a uuid scan")
	}
}

// A corrupt record is a record present: through Wire every op on the VM is
// refused, the exempt entry points included.
func TestFwmigWire_UnreadableRecordRefuses(t *testing.T) {
	store := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	virt := &recordingVirt{}
	Wire(virt, store)
	if err := os.MkdirAll(filepath.Join(store.DataDir, HoldDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(store.DataDir, HoldDir, wireVM+".json"), []byte(`{"vm":"vm1"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []lv.FirmwareCall{
		{Op: lv.OpStart, Name: wireVM},
		{Op: lv.OpResume, Name: wireVM},
		{Op: lv.OpResume, Name: wireVM, UUID: wireUUID, Attempt: wireAttempt, Via: lv.ViaResumeFirmwareMoveTarget},
		{Op: lv.OpStop, Name: wireVM, UUID: wireUUID, Attempt: wireAttempt, Via: lv.ViaDiscardFirmwareMoveTarget},
	} {
		if err := virt.g.Check(c); !errors.Is(err, lv.ErrFirmwareMoveInFlight) {
			t.Errorf("%+v: %v, want refused", c, err)
		}
	}
}

// T-34 (fwmig half): through Wire and the real records, the partition
// pauser's resume goes ahead under a marker exactly while the phase is
// preparing, prepared or migrating, or parked from one of those other than
// source_paused.
//
// Mutations: Marker.BeforeCutover true at cutover — red; ResumePartitionPaused
// refused under every marker — red.
func TestFwmigWire_PartitionPauseResume(t *testing.T) {
	pre := map[Phase]bool{PhasePreparing: true, PhasePrepared: true, PhaseMigrating: true}
	type tc struct {
		m    Marker
		want bool
	}
	var cases []tc
	for _, p := range AllPhases() {
		if !p.Parked() {
			cases = append(cases, tc{wireMarker(wireVM, p), pre[p]})
			continue
		}
		for _, from := range AllPhases() {
			if from.Parked() {
				continue
			}
			m := wireMarker(wireVM, from)
			pm, err := m.Park(p)
			if err != nil {
				t.Fatal(err)
			}
			cases = append(cases, tc{pm, p != PhaseSourcePaused && pre[from]})
		}
	}
	for _, c := range cases {
		name := string(c.m.Phase)
		if c.m.ParkedFrom != "" {
			name += "_from_" + string(c.m.ParkedFrom)
		}
		t.Run(name, func(t *testing.T) {
			store := &lv.FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
			virt := &recordingVirt{}
			Wire(virt, store)
			if err := New(store.DataDir).PutMarker(c.m); err != nil {
				t.Fatal(err)
			}
			err := virt.g.Check(lv.FirmwareCall{Op: lv.OpResume, Name: wireVM, UUID: wireUUID, Via: lv.ViaResumePartitionPaused})
			if got := err == nil; got != c.want {
				t.Fatalf("allowed = %v, want %v (%v)", got, c.want, err)
			}
			if err := virt.g.Check(lv.FirmwareCall{Op: lv.OpResume, Name: wireVM}); !errors.Is(err, lv.ErrFirmwareMoveInFlight) {
				t.Fatalf("an ordinary resume under the marker: %v", err)
			}
		})
	}
}

// ── AST: who installs the guard ──

type astCall struct {
	fn   string // enclosing function
	recv string // X of X.Sel
	sel  string
	args []string
	pos  token.Pos
}

func parseCalls(t *testing.T, paths ...string) ([]astCall, []*ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	var calls []astCall
	var files []*ast.File
	for _, p := range paths {
		f, err := parser.ParseFile(fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, f)
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				ce, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				se, ok := ce.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				c := astCall{fn: fd.Name.Name, recv: types.ExprString(se.X), sel: se.Sel.Name, pos: ce.Pos()}
				for _, a := range ce.Args {
					c.args = append(c.args, types.ExprString(a))
				}
				calls = append(calls, c)
				return true
			})
		}
	}
	return calls, files
}

func goFiles(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		if n := e.Name(); strings.HasSuffix(n, ".go") && !strings.HasSuffix(n, "_test.go") {
			out = append(out, filepath.Join(dir, n))
		}
	}
	return out
}

func findCalls(calls []astCall, recv, sel string) []astCall {
	var out []astCall
	for _, c := range calls {
		if (recv == "" || c.recv == recv) && c.sel == sel {
			out = append(out, c)
		}
	}
	return out
}

// The daemon installs the guard through Wire, once, in New, right after
// connecting to libvirt and before RequireStartGuard, on the store it keeps;
// nothing in the daemon installs a guard any other way.
//
// Mutations: move Wire after RequireStartGuard — red; Wire a second
// NewFirmwareStore — red; call SetFirmwareMoveGuard directly — red.
func TestFwmigWire_DaemonWiresGuardFirst(t *testing.T) {
	calls, files := parseCalls(t, goFiles(t, "../daemon")...)
	wires := findCalls(calls, "fwmig", "Wire")
	if len(wires) != 1 {
		t.Fatalf("daemon calls fwmig.Wire %d times, want once", len(wires))
	}
	w := wires[0]
	if w.fn != "New" || strings.Join(w.args, ",") != "virt,fwStore" {
		t.Fatalf("fwmig.Wire(%s) in %s, want fwmig.Wire(virt, fwStore) in New", strings.Join(w.args, ", "), w.fn)
	}
	nc := findCalls(calls, "libvirt", "NewClient")
	rq := findCalls(calls, "virt", "RequireStartGuard")
	if len(nc) != 1 || len(rq) != 1 || nc[0].fn != "New" || rq[0].fn != "New" {
		t.Fatalf("NewClient %d, RequireStartGuard %d calls in New", len(nc), len(rq))
	}
	if !(nc[0].pos < w.pos && w.pos < rq[0].pos) {
		t.Fatal("fwmig.Wire is not between libvirt.NewClient and RequireStartGuard")
	}
	stores := findCalls(calls, "libvirt", "NewFirmwareStore")
	if len(stores) != 1 || stores[0].fn != "New" || !(stores[0].pos < w.pos) {
		t.Fatalf("daemon builds %d firmware stores, want one, in New before Wire", len(stores))
	}
	if sg := findCalls(calls, "", "SetFirmwareMoveGuard"); len(sg) != 0 {
		t.Fatalf("daemon installs a firmware move guard outside fwmig.Wire: %+v", sg)
	}
	// The wired store is the one the Daemon keeps.
	kept := false
	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			cl, ok := n.(*ast.CompositeLit)
			if !ok || types.ExprString(cl.Type) != "Daemon" {
				return true
			}
			for _, e := range cl.Elts {
				if kv, ok := e.(*ast.KeyValueExpr); ok && types.ExprString(kv.Key) == "fwStore" && types.ExprString(kv.Value) == "fwStore" {
					kept = true
				}
			}
			return true
		})
	}
	if !kept {
		t.Fatal("the Daemon does not keep the wired store (Daemon{fwStore: fwStore})")
	}
}

// The daemon hands the server and the reconciler the SAME store, the guarded
// one it keeps (D2-1 review m-4).
//
// Mutations: drop reconciler.SetFirmwareStore — red; hand either a fresh
// NewFirmwareStore — red.
func TestFwmigWire_DaemonSharesOneStore(t *testing.T) {
	calls, _ := parseCalls(t, goFiles(t, "../daemon")...)
	got := map[string]string{}
	for _, c := range findCalls(calls, "", "SetFirmwareStore") {
		got[c.recv] = strings.Join(c.args, ",")
	}
	want := map[string]string{"svc": "d.fwStore", "reconciler": "d.fwStore"}
	if len(got) != len(want) || got["svc"] != want["svc"] || got["reconciler"] != want["reconciler"] {
		t.Fatalf("SetFirmwareStore calls = %v, want %v", got, want)
	}
}
