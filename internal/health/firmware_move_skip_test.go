package health

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/fwmig"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// The health paths a live firmware move's record stops (spec §6.9, §9, §10,
// §11; T-17, T-18, T-19, T-25, T-34), on the D2-7 fake: each with the record
// leaves the VM's definition, both copies of its firmware state and its row
// as they were, and each without one acts as before (the control that keeps
// the record cases from passing vacuously).

const (
	fsVM      = "fw1"
	fsUUID    = "5e1c2b3a-1111-4222-8333-444455556666"
	fsAttempt = "a1a1a1a1-0000-4000-8000-0000000000f1"
)

var fsXML = `<domain type='kvm'><name>` + fsVM + `</name><uuid>` + fsUUID + `</uuid></domain>`

// fsStore is a firmware store under temp dirs holding fw1's NVRAM ("NV0")
// and swtpm permall ("P0"), with the guard wired over it and over fake.
func fsStore(t *testing.T, dataDir string, fake *libvirtfake.Fake) *lv.FirmwareStore {
	t.Helper()
	store := &lv.FirmwareStore{DataDir: dataDir, SwtpmBase: t.TempDir()}
	fsWrite(t, store.NvramPath(fsVM), "NV0")
	fsWrite(t, filepath.Join(store.SwtpmDir(fsUUID), "tpm2", "tpm2-00.permall"), "P0")
	fake.SetFirmwareStore(store)
	fwmig.Wire(fake, store)
	return store
}

func fsWrite(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// fsDefine defines fw1 in state st (before any record exists).
func fsDefine(t *testing.T, fake *libvirtfake.Fake, st libvirtfake.State) {
	t.Helper()
	if err := fake.DefineDomain(fsXML); err != nil {
		t.Fatal(err)
	}
	fake.SetState(fsVM, st)
}

// fsRecord writes a marker in phase (parked ones from migrating) or a hold
// in state for fw1.
func fsRecord(t *testing.T, dataDir, kind, state string) {
	t.Helper()
	recs := fwmig.New(dataDir)
	b := fwmig.Binding{UUID: fsUUID, CreatedAt: "2026-10-17T00:00:00Z", Attempt: fsAttempt}
	switch kind {
	case "marker":
		m := fwmig.Marker{VM: fsVM, Binding: b, Target: "node-b", Route: fwmig.RouteTunnelled,
			Phase: fwmig.PhaseMigrating, TPM: true, UEFI: true, Since: time.Now().UTC()}
		if p := fwmig.Phase(state); p.Parked() {
			var err error
			if m, err = m.Park(p); err != nil {
				t.Fatal(err)
			}
		} else {
			m.Phase = p
		}
		if err := recs.PutMarker(m); err != nil {
			t.Fatal(err)
		}
	case "hold":
		h := fwmig.Hold{VM: fsVM, Binding: b, Source: "node-b", Since: time.Now().UTC(), State: fwmig.HoldState(state),
			TPM: true, UEFI: true, NvramMaterialised: fwmig.NvramDone}
		if err := recs.PutHold(h); err != nil {
			t.Fatal(err)
		}
	case "":
	default:
		t.Fatalf("record kind %q", kind)
	}
}

// fsRequireKept: fw1 is still defined in state st, and its NVRAM and
// permall are byte-unchanged.
func fsRequireKept(t *testing.T, fake *libvirtfake.Fake, store *lv.FirmwareStore, st libvirtfake.State) {
	t.Helper()
	if got, ok := fake.RawState(fsVM); !ok || got != st {
		t.Fatalf("fw1 is %q (defined %v), want %q kept", got, ok, st)
	}
	if b, err := os.ReadFile(store.NvramPath(fsVM)); err != nil || string(b) != "NV0" {
		t.Fatalf("NVRAM = %q, %v; want NV0 kept", b, err)
	}
	if b, err := os.ReadFile(filepath.Join(store.SwtpmDir(fsUUID), "tpm2", "tpm2-00.permall")); err != nil || string(b) != "P0" {
		t.Fatalf("permall = %q, %v; want P0 kept", b, err)
	}
}

// fsActed reports whether fake logged one of ops on fw1 after its first
// since events (the setup's own).
func fsActed(fake *libvirtfake.Fake, since int, ops ...string) bool {
	for _, e := range fake.EventLog()[since:] {
		if e.Domain != fsVM {
			continue
		}
		for _, op := range ops {
			if e.Op == op {
				return true
			}
		}
	}
	return false
}

type fsReconciler struct {
	base  int // events logged by the setup
	db    *corrosion.Client
	fake  *libvirtfake.Fake
	r     *Reconciler
	store *lv.FirmwareStore
}

// newFSReconciler is node-a's reconciler with fw1's row (on host, in state,
// with detail) and fw1 defined in domain state st.
func newFSReconciler(t *testing.T, host, state, detail string, st libvirtfake.State) *fsReconciler {
	t.Helper()
	db := testReconcilerDB(t)
	ctx := context.Background()
	for _, h := range []string{"node-a", "node-b"} {
		if err := corrosion.InsertHost(ctx, db, corrosion.HostRecord{Name: h, Address: "10.0.0.1", State: "active"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, db, corrosion.VMRecord{Name: fsVM, HostName: host, State: state, StateDetail: detail,
		CPUActual: 1, MemActual: 256, Spec: `{"name":"fw1","cpu":1,"memory_mib":256,"uuid":"` + fsUUID + `"}`}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fsDefine(t, fake, st)
	dataDir := t.TempDir()
	r := NewReconciler("node-a", dataDir, db, fake)
	store := fsStore(t, dataDir, fake)
	r.SetFirmwareStore(store)
	return &fsReconciler{base: len(fake.EventLog()), db: db, fake: fake, r: r, store: store}
}

func (f *fsReconciler) row(t *testing.T) corrosion.VMRecord {
	t.Helper()
	vm, err := corrosion.GetVM(context.Background(), f.db, fsVM)
	if err != nil || vm == nil {
		t.Fatalf("GetVM: %v %v", vm, err)
	}
	return *vm
}

// T-19 (health), F-8's unit half: the reconciler's leftover cleanup leaves a
// moved VM's source definition, NVRAM and permall alone while the marker
// names it — the leftover shut off with reason migrated (which the cleanup
// does not take today either), with reason unknown and an owner proven to
// run it (a source reboot after cutover), and with reason destroyed. Without
// a marker the last two are undefined (and probe (g) deletes the NVRAM),
// which is what the skip prevents.
//
// Mutation: remove the reconciler's marker skip AND the guard — red.
func TestFirmwareMarker_LeftoverCleanupLeavesState(t *testing.T) {
	for _, reason := range []string{"migrated", "unknown", "destroyed"} {
		for _, kind := range []string{"marker", ""} {
			if reason == "migrated" && kind == "" {
				continue // not cleaned up with or without a marker: no control
			}
			name := reason + "/" + map[string]string{"marker": "marked", "": "unmarked_control"}[kind]
			t.Run(name, func(t *testing.T) {
				f := newFSReconciler(t, "node-b", "running", "", libvirtfake.StateShutdown)
				f.fake.SetStateReason(fsVM, reason)
				f.r.checkPeerRuntime = func(context.Context, string, string) (string, error) { return RuntimeRunning, nil }
				fsRecord(t, f.store.DataDir, kind, string(fwmig.PhaseCommitted))
				f.r.selfFence(context.Background())
				if kind == "" {
					if f.fake.DomainExists(fsVM) {
						t.Fatal("control: an unmarked leftover was not cleaned up; the marked case proves nothing")
					}
					return
				}
				fsRequireKept(t, f.fake, f.store, libvirtfake.StateShutdown)
				if fsActed(f.fake, f.base, "undefine", "destroy") {
					t.Fatalf("the leftover cleanup acted on a marked VM: %+v", f.fake.EventLog())
				}
			})
		}
	}
}

// T-18 / T-19 (health): the reconciler does not start a VM a marker names
// here — the row says it should run, the domain is defined and shut off.
//
// Mutation: remove startPendingVM's skip AND the guard — red.
func TestFirmwareMarker_StartPendingVMLeavesIt(t *testing.T) {
	for _, kind := range []string{"marker", "hold", ""} {
		t.Run(map[string]string{"marker": "marker", "hold": "hold", "": "unmarked_control"}[kind], func(t *testing.T) {
			f := newFSReconciler(t, "node-a", "pending", "", libvirtfake.StateShutdown)
			state := string(fwmig.PhaseTargetUnreachable)
			if kind == "hold" {
				state = string(fwmig.HoldVerified)
			}
			fsRecord(t, f.store.DataDir, kind, state)
			f.r.startPendingVM(context.Background(), f.row(t))
			if kind == "" {
				if !fsActed(f.fake, f.base, "start") {
					t.Fatalf("control: an unmarked pending VM was not started (%+v); the marked case proves nothing", f.fake.EventLog())
				}
				return
			}
			if fsActed(f.fake, f.base, "start", "define", "undefine") {
				t.Fatalf("the reconciler acted on a marked VM: %+v", f.fake.EventLog())
			}
			fsRequireKept(t, f.fake, f.store, libvirtfake.StateShutdown)
			if row := f.row(t); row.State != "pending" {
				t.Fatalf("row %s/%q, want pending left as it was", row.State, row.StateDetail)
			}
		})
	}
}

// T-19 (health): a stopped VM failover re-keyed here is not (re)defined, and
// a re-key leftover whose row names another host is not undefined, while a
// marker names it here.
//
// Mutations: remove the re-key define skip AND the guard — red; remove the
// re-key leftover skip AND the guard — red.
func TestFirmwareMarker_RekeyLeavesState(t *testing.T) {
	t.Run("define", func(t *testing.T) {
		for _, kind := range []string{"marker", ""} {
			t.Run(map[string]string{"marker": "marker", "": "unmarked_control"}[kind], func(t *testing.T) {
				f := newFSReconciler(t, "node-a", "stopped", corrosion.StoppedRekeyDetail("node-b"), libvirtfake.StateShutdown)
				fsRecord(t, f.store.DataDir, kind, string(fwmig.PhaseSourceStateSuspect))
				f.r.defineRekeyedStoppedVM(context.Background(), f.row(t))
				if kind == "" {
					if !fsActed(f.fake, f.base, "define") {
						t.Fatalf("control: an unmarked re-keyed VM was not defined (%+v); the marked case proves nothing", f.fake.EventLog())
					}
					return
				}
				if fsActed(f.fake, f.base, "define", "undefine") {
					t.Fatalf("the re-key define acted on a marked VM: %+v", f.fake.EventLog())
				}
				if f.fake.DefinedXML(fsVM) != fsXML {
					t.Fatalf("the definition changed:\n%s", f.fake.DefinedXML(fsVM))
				}
				fsRequireKept(t, f.fake, f.store, libvirtfake.StateShutdown)
			})
		}
	})
	t.Run("leftover", func(t *testing.T) {
		for _, kind := range []string{"marker", ""} {
			t.Run(map[string]string{"marker": "marker", "": "unmarked_control"}[kind], func(t *testing.T) {
				f := newFSReconciler(t, "node-b", "stopped", corrosion.StoppedRekeyDetail("node-c"), libvirtfake.StateShutdown)
				f.r.rekeyDefined = map[string]string{fsVM: "earlier"}
				fsRecord(t, f.store.DataDir, kind, string(fwmig.PhaseCommitted))
				f.r.cleanupRekeyLeftovers(context.Background())
				if kind == "" {
					if f.fake.DomainExists(fsVM) {
						t.Fatal("control: an unmarked re-key leftover was not undefined; the marked case proves nothing")
					}
					return
				}
				fsRequireKept(t, f.fake, f.store, libvirtfake.StateShutdown)
				if _, still := f.r.rekeyDefined[fsVM]; !still {
					t.Fatal("the leftover was forgotten; it must be asked again once the move ends")
				}
			})
		}
	})
}

// T-19 (health), start_row_gone: a guest a start booted for a row that went
// meanwhile is not stopped, undefined or stripped of its NVRAM while a marker
// names it.
//
// Mutation: remove the guard (libvirt and store) — red.
func TestFirmwareMarker_StartRowGoneKeepsNvram(t *testing.T) {
	f := newFSReconciler(t, "node-a", "running", "", libvirtfake.StateRunning)
	vm := f.row(t)
	if err := corrosion.DeleteVM(context.Background(), f.db, fsVM); err != nil {
		t.Fatal(err)
	}
	fsRecord(t, f.store.DataDir, "marker", string(fwmig.PhasePreparing))
	f.r.startedForGoneRow(context.Background(), vm, 0, nil, false)
	fsRequireKept(t, f.fake, f.store, libvirtfake.StateRunning)
}

// fsChecker is node-a's VM checker over fw1, running, whose probe failed.
func fsChecker(t *testing.T, spec string) (*VMChecker, *libvirtfake.Fake, *lv.FirmwareStore, *corrosion.Client, int) {
	t.Helper()
	db := testCheckVMDB(t)
	if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{Name: fsVM, HostName: "node-a",
		Spec: spec, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fake := libvirtfake.New()
	fsDefine(t, fake, libvirtfake.StateRunning)
	dataDir := t.TempDir()
	v := NewVMChecker("node-a", dataDir, db, nil)
	v.SetBackend(fake)
	store := fsStore(t, dataDir, fake)
	return v, fake, store, db, len(fake.EventLog())
}

// T-17 / T-18 (health): the health-check restart of a VM a record names here
// is skipped at its entry: no destroy, no start, and no row write (a refused
// destroy used to be followed by a refused start and a row `error`).
//
// Mutation: remove the vmcheck entry skip — red (the row turns error).
func TestVMCheck_RestartSkipsFirmwareMove(t *testing.T) {
	for _, c := range []struct{ kind, state string }{
		{"marker", string(fwmig.PhaseTargetUnreachable)}, {"marker", string(fwmig.PhaseCleaning)},
		{"hold", string(fwmig.HoldVerified)}, {"hold", string(fwmig.HoldResuming)}, {"hold", string(fwmig.HoldReleasedUnconfirmed)},
		{"", ""},
	} {
		t.Run(c.kind+"/"+c.state, func(t *testing.T) {
			v, fake, store, db, base := fsChecker(t, `{"name":"fw1","uuid":"`+fsUUID+`"}`)
			fsRecord(t, store.DataDir, c.kind, c.state)
			v.takeAction(context.Background(), corrosion.VMRecord{Name: fsVM, HostName: "node-a"}, &pb.HealthCheckSpec{Action: "restart"})
			row, _ := corrosion.GetVM(context.Background(), db, fsVM)
			if c.kind == "" {
				if !fsActed(fake, base, "destroy") {
					t.Fatalf("control: the restart did not act on an unmarked VM (%+v); the marked cases prove nothing", fake.EventLog())
				}
				return
			}
			if fsActed(fake, base, "destroy", "shutdown", "start") {
				t.Fatalf("the health check acted on a VM in a firmware move: %+v", fake.EventLog())
			}
			if row == nil || row.State != "running" || row.StateDetail != "" {
				t.Fatalf("row %+v, want running with nothing written", row)
			}
			fsRequireKept(t, fake, store, libvirtfake.StateRunning)
		})
	}
}

// T-25 (health): the health-check migrate action's direct-libvirt fallback
// (no RPC callback wired) never moves a Secure Boot / vTPM VM, and writes no
// `migrating` row for it; a plain VM still takes it.
//
// Mutation: remove the fallback's refusal — red.
func TestVMCheck_FallbackRefusesFirmwareVM(t *testing.T) {
	for _, c := range []struct {
		name, spec string
		refused    bool
	}{
		{"secure_boot", `{"name":"fw1","secure_boot":true,"firmware":"uefi"}`, true},
		{"tpm", `{"name":"fw1","tpm":true}`, true},
		{"plain_control", `{"name":"fw1"}`, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			v, fake, _, db, base := fsChecker(t, c.spec)
			if err := corrosion.InsertHost(context.Background(), db, corrosion.HostRecord{Name: "node-b", Address: "10.0.0.2",
				State: "active", MemTotal: 65536, CPUTotal: 16}); err != nil {
				t.Fatal(err)
			}
			row, _ := corrosion.GetVM(context.Background(), db, fsVM)
			v.migrateVM(context.Background(), *row)
			row, _ = corrosion.GetVM(context.Background(), db, fsVM)
			migrated := fsActed(fake, base, "migrate")
			if !c.refused {
				if !migrated && row.State != "migrating" && row.HostName == "node-a" && row.StateDetail == "" {
					t.Fatalf("control: the fallback did not act on a plain VM (%+v, row %+v)", fake.EventLog(), row)
				}
				return
			}
			if migrated || row.State != "running" || row.HostName != "node-a" || row.StateDetail != "" {
				t.Fatalf("the fallback acted on a firmware VM: events %+v, row %+v", fake.EventLog(), row)
			}
		})
	}
}

// fsPauser is node-a's partition pauser over fw1 (restart-any, running),
// with the firmware move guard wired; fw1 has been paused by it.
func fsPauser(t *testing.T) (*pauseFixture, *lv.FirmwareStore) {
	t.Helper()
	f := newPauseFixture(t)
	if err := corrosion.InsertVM(context.Background(), f.db, corrosion.VMRecord{Name: fsVM, HostName: "node-a",
		Spec: `{"on_host_failure":"restart-any","uuid":"` + fsUUID + `"}`, State: "running"}, nil, nil); err != nil {
		t.Fatal(err)
	}
	fsDefine(t, f.virt, libvirtfake.StateRunning)
	f.virt.SetActiveXML(fsVM, fsXML)
	store := fsStore(t, t.TempDir(), f.virt)
	f.loseFor(QuorumNo, PartitionPauseAfter+time.Second)
	if st := f.raw(fsVM); st != libvirtfake.StatePaused {
		t.Fatalf("setup: fw1 is %s after T_pause, want paused by the pauser", st)
	}
	return f, store
}

func (f *pauseFixture) pausedRecord(name string) bool {
	for _, r := range f.records() {
		if r.Kind == PauseKindVM && r.Name == name {
			return true
		}
	}
	return false
}

// T-34 (partition pauser half). The pauser resumes a guest it paused while a
// marker names it only while the move is in progress before cutover
// (preparing, prepared, migrating): the source's copy is the live one.
//
// Mutation: refuse ResumePartitionPaused under every marker — red; resume
// through the plain ResumeDomain — red (a marker refuses an ordinary resume).
func TestPartitionPauseResume_PreCutoverMarkerAllowed(t *testing.T) {
	for _, p := range []fwmig.Phase{fwmig.PhasePreparing, fwmig.PhasePrepared, fwmig.PhaseMigrating} {
		t.Run(string(p), func(t *testing.T) {
			f, store := fsPauser(t)
			fsRecord(t, store.DataDir, "marker", string(p))
			f.regain()
			if st := f.raw(fsVM); st != libvirtfake.StateRunning {
				t.Fatalf("fw1 is %s after the heal, want resumed (marker %s)", st, p)
			}
			if f.pausedRecord(fsVM) {
				t.Fatal("the pause record was kept after the resume")
			}
		})
	}
}

// T-34 (partition pauser half), with D2-13 re-review 3 m-C: from cutover on,
// and under every parked marker whatever it was parked from, the pauser
// leaves the guest paused and keeps its record: a parked move resumes its
// source through its own steps (the M1p handler, which asks the target
// first), since a parked target may hold a copy it cannot report.
//
// Mutations: allow ResumePartitionPaused at cutover — red; allow it under a
// parked marker reached before cutover — red.
func TestPartitionPauseResume_CutoverMarkerRefused(t *testing.T) {
	var phases []string
	for _, p := range fwmig.AllPhases() {
		if p == fwmig.PhasePreparing || p == fwmig.PhasePrepared || p == fwmig.PhaseMigrating {
			continue
		}
		phases = append(phases, string(p))
	}
	for _, p := range phases {
		t.Run(p, func(t *testing.T) {
			f, store := fsPauser(t)
			fsRecord(t, store.DataDir, "marker", p)
			f.regain()
			if st := f.raw(fsVM); st != libvirtfake.StatePaused {
				t.Fatalf("fw1 is %s after the heal under marker %s, want left paused", st, p)
			}
			if !f.pausedRecord(fsVM) {
				t.Fatal("the pause record was dropped although the guest stays paused")
			}
		})
	}
}

// T-17 (partition pauser half): a hold whose guest is held (verified,
// resuming) refuses the pauser's resume; a released_unconfirmed hold — the
// guest runs, only its NVRAM is unconfirmed — lets it resume (spec §5.1).
//
// Mutation: allow the pauser's resume under any hold — red.
func TestHeldFirmwareGuest_PartitionPauseResume(t *testing.T) {
	for _, c := range []struct {
		state fwmig.HoldState
		want  libvirtfake.State
	}{
		{fwmig.HoldVerified, libvirtfake.StatePaused},
		{fwmig.HoldResuming, libvirtfake.StatePaused},
		{fwmig.HoldReleasedUnconfirmed, libvirtfake.StateRunning},
	} {
		t.Run(string(c.state), func(t *testing.T) {
			f, store := fsPauser(t)
			fsRecord(t, store.DataDir, "hold", string(c.state))
			f.regain()
			if st := f.raw(fsVM); st != c.want {
				t.Fatalf("fw1 is %s after the heal under hold %s, want %s", st, c.state, c.want)
			}
		})
	}
}

// T-18 (health): the restart policy does not start a crashed VM a record
// names here: no restart counted, no destroy, no start.
//
// Mutation: remove the restart policy's skip AND the guard — red.
func TestMaybeRestartVM_SkipsFirmwareMove(t *testing.T) {
	for _, kind := range []string{"marker", "hold", ""} {
		t.Run(map[string]string{"marker": "marker", "hold": "hold", "": "unmarked_control"}[kind], func(t *testing.T) {
			db := testStartDB(t)
			spec, err := json.Marshal(&pb.VMSpec{Name: fsVM, Uuid: fsUUID,
				Restart: &pb.RestartPolicy{Condition: "always", MaxAttempts: 10, Window: "1h", Delay: "0s"}})
			if err != nil {
				t.Fatal(err)
			}
			if err := corrosion.InsertVM(context.Background(), db, corrosion.VMRecord{Name: fsVM, HostName: "node1",
				State: "stopped", StateDetail: "crashed", Spec: string(spec)}, nil, nil); err != nil {
				t.Fatal(err)
			}
			fake := libvirtfake.New()
			fsDefine(t, fake, libvirtfake.StateShutdown)
			fake.SetStateReason(fsVM, "crashed")
			dataDir := t.TempDir()
			v := NewVMChecker("node1", dataDir, db, nil)
			v.SetBackend(fake)
			store := fsStore(t, dataDir, fake)
			base := len(fake.EventLog())
			state := string(fwmig.PhaseSourceStateMissing)
			if kind == "hold" {
				state = string(fwmig.HoldReleasedUnconfirmed)
			}
			fsRecord(t, store.DataDir, kind, state)
			vm, _ := corrosion.GetVM(context.Background(), db, fsVM)
			v.maybeRestartVM(context.Background(), *vm, time.Now())
			if kind == "" {
				if !fsActed(fake, base, "start") {
					t.Fatalf("control: the restart policy did not start an unmarked crashed VM (%+v); the marked cases prove nothing", fake.EventLog())
				}
				return
			}
			if got := restartAttempts(t, db, fsVM); got != 0 {
				t.Fatalf("restart attempts = %d, want 0", got)
			}
			if fsActed(fake, base, "destroy", "start") {
				t.Fatalf("the restart policy acted on a VM in a firmware move: %+v", fake.EventLog())
			}
			fsRequireKept(t, fake, store, libvirtfake.StateShutdown)
		})
	}
}
