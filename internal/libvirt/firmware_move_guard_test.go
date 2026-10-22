package libvirt

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"
	"github.com/google/uuid"
)

// The firmware move guard, spec §5.1 and T-6/T-7/T-21a/T-34 (libvirt half).
//
// Every cell of the §5.1 table is a sub-test, TestFirmwareMoveGuard/<op>/<state>,
// run through each primitive of the op against a fake snapshotAPI (domain
// operations) or a store under temp dirs (state writes and wipes). The
// expected answer is written out here from the spec table, not taken from
// the code under test.

const (
	fwTestVM      = "vm1"
	fwTestUUID    = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	fwTestAttempt = "6f1c0c5e-0a43-4c55-9b5e-2b2b1f4d0e11"
	fwOtherUUID   = "0b5c44a3-6f7e-4a55-8a09-3c8d8f0f6a21"
	fwOtherAtt    = "1d2e3f40-5a6b-4c7d-8e9f-0a1b2c3d4e5f"
)

var (
	fwProgressPhases = []string{"preparing", "prepared", "migrating", "cutover", "verified", "committed", "released", "cleaning"}
	fwParkedPhases   = []string{"target_unreachable", "source_state_missing", "source_state_suspect", "target_ran", "nvram_unconfirmed", "discard_pending", "source_paused"}
	fwHoldStates     = []string{"prepared", "verified", "resuming", "released_unconfirmed", "mismatch"}
)

// fwUnreadable is another VM's record that does not read: the guard cannot
// tell whether it binds this VM.
var fwUnreadable = &FirmwareRecordUnreadableError{Path: "/var/lib/litevirt/fwmig-hold/vm9.json", Err: errors.New("unexpected end of JSON input")}

func fwPrePhase(p string) bool { return p == "preparing" || p == "prepared" || p == "migrating" }

// fwState is one column cell: the records the lookup returns, or its error.
type fwState struct {
	name string
	recs []FirmwareMoveRecord
	err  error
}

func fwMarker(name, phase string, pre, bundle bool) fwState {
	return fwState{name: name, recs: []FirmwareMoveRecord{{
		Kind: FirmwareMarker, VM: fwTestVM, UUID: fwTestUUID, Attempt: fwTestAttempt,
		Peer: "node-2", State: phase, PreCutover: pre, RetainedBundle: bundle,
	}}}
}

func fwHold(state string) fwState {
	return fwState{name: "hold/" + state, recs: []FirmwareMoveRecord{{
		Kind: FirmwareHold, VM: fwTestVM, UUID: fwTestUUID, Attempt: fwTestAttempt,
		Peer: "node-1", State: state,
	}}}
}

func fwLeftover() fwState {
	return fwState{name: "leftover", recs: []FirmwareMoveRecord{{
		Kind: FirmwareLeftover, VM: fwTestVM, UUID: fwTestUUID, Attempt: fwTestAttempt,
		Peer: "node-1", State: "leftover",
	}}}
}

// fwStates: no record; a record that cannot be read; a marker in every phase
// (a parked one from a pre-cutover and from a post-cutover phase; a cleaning
// one with and without its retained bundle); a hold in every state.
func fwStates() []fwState {
	out := []fwState{{name: "none"}, {name: "unreadable", err: fwUnreadable}}
	for _, p := range fwProgressPhases {
		out = append(out, fwMarker("marker/"+p, p, fwPrePhase(p), p == "cleaning"))
	}
	out = append(out, fwMarker("marker/cleaning_no_bundle", "cleaning", false, false))
	for _, p := range fwParkedPhases {
		for _, from := range []string{"migrating", "cutover"} {
			st := fwMarker("marker/"+p+"_from_"+from, p, p != "source_paused" && fwPrePhase(from), false)
			st.recs[0].ParkedPreCutover = fwPrePhase(from)
			st.recs[0].Parked = true
			out = append(out, st)
		}
	}
	for _, h := range fwHoldStates {
		out = append(out, fwHold(h))
	}
	return append(out, fwLeftover())
}

// fwLookup answers from st: the records that carry the name or the uuid.
func fwLookup(st fwState) FirmwareMoveLookup {
	return func(name, id string) ([]FirmwareMoveRecord, error) {
		if st.err != nil {
			return nil, st.err
		}
		var out []FirmwareMoveRecord
		for _, r := range st.recs {
			if (name != "" && r.VM == name) || (id != "" && strings.EqualFold(r.UUID, id)) {
				out = append(out, r)
			}
		}
		return out, nil
	}
}

// ── fake snapshotAPI ──

type fwFakeDom struct {
	state golibvirt.DomainState
	uuid  golibvirt.UUID
}

type fwFakeAPI struct {
	snapshotAPI // nil: a call this fake does not model panics
	doms        map[string]*fwFakeDom
	calls       []string
	undefFlags  []golibvirt.DomainUndefineFlagsValues
}

func newFWFakeAPI(state golibvirt.DomainState) *fwFakeAPI {
	return &fwFakeAPI{doms: map[string]*fwFakeDom{fwTestVM: {state: state, uuid: golibvirt.UUID(uuid.MustParse(fwTestUUID))}}}
}

func (f *fwFakeAPI) DomainLookupByName(name string) (golibvirt.Domain, error) {
	d, ok := f.doms[name]
	if !ok {
		return golibvirt.Domain{}, errors.New("Domain not found")
	}
	return golibvirt.Domain{Name: name, UUID: d.uuid}, nil
}

func (f *fwFakeAPI) DomainGetState(dom golibvirt.Domain, _ uint32) (int32, int32, error) {
	d, ok := f.doms[dom.Name]
	if !ok {
		return 0, 0, errors.New("Domain not found")
	}
	return int32(d.state), 0, nil
}

func (f *fwFakeAPI) DomainDestroy(dom golibvirt.Domain) error {
	f.calls = append(f.calls, "destroy")
	f.doms[dom.Name].state = golibvirt.DomainShutoff
	return nil
}

func (f *fwFakeAPI) DomainShutdown(dom golibvirt.Domain) error {
	f.calls = append(f.calls, "shutdown")
	f.doms[dom.Name].state = golibvirt.DomainShutoff
	return nil
}

func (f *fwFakeAPI) DomainUndefineFlags(dom golibvirt.Domain, flags golibvirt.DomainUndefineFlagsValues) error {
	f.calls = append(f.calls, "undefine")
	f.undefFlags = append(f.undefFlags, flags)
	delete(f.doms, dom.Name)
	return nil
}

func (f *fwFakeAPI) DomainDefineXML(x string) (golibvirt.Domain, error) {
	f.calls = append(f.calls, "define")
	return golibvirt.Domain{Name: DomainNameFromXML(x)}, nil
}

func (f *fwFakeAPI) DomainResume(dom golibvirt.Domain) error {
	d := f.doms[dom.Name]
	if d.state != golibvirt.DomainPaused {
		return errors.New("domain is not paused")
	}
	f.calls = append(f.calls, "resume")
	d.state = golibvirt.DomainRunning
	return nil
}

func (f *fwFakeAPI) called(op string) bool {
	for _, c := range f.calls {
		if c == op {
			return true
		}
	}
	return false
}

// ── environment ──

type fwEnv struct {
	t      *testing.T
	api    *fwFakeAPI
	store  *FirmwareStore
	guard  FirmwareMoveGuard
	client *Client
}

func newFWEnv(t *testing.T, st fwState, domState golibvirt.DomainState) *fwEnv {
	t.Helper()
	g := NewFirmwareMoveGuard(fwLookup(st))
	store := &FirmwareStore{DataDir: t.TempDir(), SwtpmBase: t.TempDir()}
	store.SetFirmwareMoveGuard(g)
	fwWriteFile(t, store.NvramPath(fwTestVM), "T0")
	fwWriteFile(t, filepath.Join(store.SwtpmDir(fwTestUUID), "tpm2", "tpm2-00.permall"), "P0")
	c := &Client{}
	c.SetFirmwareMoveGuard(g)
	return &fwEnv{t: t, api: newFWFakeAPI(domState), store: store, guard: g, client: c}
}

func fwWriteFile(t *testing.T, p, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func (e *fwEnv) nvram(vm string) (string, bool) {
	b, err := os.ReadFile(e.store.NvramPath(vm))
	return string(b), err == nil
}

func (e *fwEnv) hasSwtpm() bool {
	_, err := os.Stat(filepath.Join(e.store.SwtpmDir(fwTestUUID), "tpm2", "tpm2-00.permall"))
	return err == nil
}

// bundle is a firmware bundle whose NVRAM is "NEW".
func (e *fwEnv) bundle() *bytes.Buffer {
	src := &FirmwareStore{DataDir: e.t.TempDir(), SwtpmBase: e.t.TempDir()}
	fwWriteFile(e.t, src.NvramPath(fwTestVM), "NEW")
	var buf bytes.Buffer
	if _, err := src.WriteFirmwareBundle(fwTestVM, "", &buf); err != nil {
		e.t.Fatal(err)
	}
	return &buf
}

// fwPrim is one primitive of an op.
type fwPrim struct {
	name string
	// refuseOnly: a Client method on a client with no libvirt connection,
	// which can show a refusal (it returns before libvirt) but not a pass.
	refuseOnly bool
	// bestEffort: returns no error; a refusal is a no-op.
	bestEffort bool
	dom        golibvirt.DomainState
	run        func(e *fwEnv) error
	acted      func(e *fwEnv) bool // nil: the run's own nil error is the act
}

var fwTestDomXML = "<domain><name>" + fwTestVM + "</name><uuid>" + fwTestUUID + "</uuid></domain>"

func fwPrims() map[FirmwareOp][]fwPrim {
	running, paused := golibvirt.DomainRunning, golibvirt.DomainPaused
	return map[FirmwareOp][]fwPrim{
		OpStart: {
			{name: "guard", run: func(e *fwEnv) error { _, err := e.client.guard(fwTestVM); return err }},
			{name: "StartDomain", refuseOnly: true, run: func(e *fwEnv) error { return e.client.StartDomain(fwTestVM) }},
			{name: "RevertToSnapshot", refuseOnly: true, run: func(e *fwEnv) error { return e.client.RevertToSnapshot(fwTestVM, "s1", nil) }},
			{name: "RevertToLiveSnapshot", refuseOnly: true, run: func(e *fwEnv) error {
				return e.client.RevertToLiveSnapshot(fwTestVM, "s1", "/nonexistent", nil, nil)
			}},
			{name: "restore", refuseOnly: true, run: func(e *fwEnv) error { return e.client.restoreWithRetry(fwTestVM, "/nonexistent", "") }},
			// The point a memory snapshot records is one a revert starts the
			// guest from: asked before the suspend.
			{name: "Client.CreateLiveSnapshot", refuseOnly: true, run: func(e *fwEnv) error {
				_, _, err := e.client.CreateLiveSnapshot(fwTestVM, "s1", "/nonexistent", CaptureOptions{})
				return err
			}},
		},
		OpResume: {
			{name: "ResumeDomain", dom: paused, run: func(e *fwEnv) error {
				return resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM})
			}, acted: func(e *fwEnv) bool { return e.api.called("resume") }},
			{name: "Client.ResumeDomain", refuseOnly: true, run: func(e *fwEnv) error { return e.client.ResumeDomain(fwTestVM) }},
			// The memory snapshot pauses and resumes the guest: asked before
			// the suspend, so a refusal never leaves it paused.
			{name: "Client.CreateLiveSnapshot", refuseOnly: true, run: func(e *fwEnv) error {
				_, _, err := e.client.CreateLiveSnapshot(fwTestVM, "s1", "/nonexistent", CaptureOptions{})
				return err
			}},
		},
		OpStop: {
			{name: "DestroyDomain", dom: running, run: func(e *fwEnv) error { return destroyDomain(e.api, e.guard, fwTestVM) },
				acted: func(e *fwEnv) bool { return e.api.called("destroy") }},
			{name: "ShutdownDomain", dom: running, run: func(e *fwEnv) error { return shutdownDomain(e.api, e.guard, fwTestVM) },
				acted: func(e *fwEnv) bool { return e.api.called("shutdown") }},
			{name: "forceRemoveDomain", bestEffort: true, dom: running, run: func(e *fwEnv) error { forceRemoveDomain(e.api, e.guard, fwTestVM); return nil },
				acted: func(e *fwEnv) bool { return e.api.called("destroy") }},
			{name: "Client.DestroyDomain", refuseOnly: true, run: func(e *fwEnv) error { return e.client.DestroyDomain(fwTestVM) }},
			{name: "Client.ShutdownDomain", refuseOnly: true, run: func(e *fwEnv) error { return e.client.ShutdownDomain(fwTestVM) }},
		},
		OpDefine: {
			{name: "DefineDomain", run: func(e *fwEnv) error {
				return defineDomain(e.api, e.guard, fwTestDomXML, func(x string) (string, error) { return x, nil })
			}, acted: func(e *fwEnv) bool { return e.api.called("define") }},
			{name: "Client.DefineDomain", refuseOnly: true, run: func(e *fwEnv) error { return e.client.DefineDomain(fwTestDomXML) }},
			{name: "Client.SetBootOrder", refuseOnly: true, run: func(e *fwEnv) error { return e.client.SetBootOrder(fwTestVM, "disk") }},
			// The point-in-time commit ends in a redefine: asked before it
			// commits anything.
			{name: "Client.CommitDiskOverlay", refuseOnly: true, run: func(e *fwEnv) error {
				return e.client.CommitDiskOverlay(fwTestVM, "/pool/d.qcow2", "/pool/ov", "qcow2", nil)
			}},
		},
		OpUndefine: {
			{name: "UndefineDomain", run: func(e *fwEnv) error { return undefineDomain(e.api, e.guard, fwTestVM, false) },
				acted: func(e *fwEnv) bool { return e.api.called("undefine") }},
			{name: "UndefineDomainPreservingState", run: func(e *fwEnv) error { return undefineDomainPreservingState(e.api, e.guard, fwTestVM) },
				acted: func(e *fwEnv) bool { return e.api.called("undefine") }},
			{name: "forceRemoveDomain", bestEffort: true, run: func(e *fwEnv) error { forceRemoveDomain(e.api, e.guard, fwTestVM); return nil },
				acted: func(e *fwEnv) bool { return e.api.called("undefine") }},
			{name: "Client.UndefineDomain", refuseOnly: true, run: func(e *fwEnv) error { return e.client.UndefineDomain(fwTestVM, false) }},
			{name: "Client.UndefineDomainPreservingState", refuseOnly: true, run: func(e *fwEnv) error { return e.client.UndefineDomainPreservingState(fwTestVM) }},
		},
		OpWriteState: {
			{name: "ReadFirmwareBundle", run: func(e *fwEnv) error { return e.store.ReadFirmwareBundle(e.bundle(), fwTestVM, fwTestUUID) },
				acted: func(e *fwEnv) bool { b, _ := e.nvram(fwTestVM); return b == "NEW" }},
			{name: "RemoveNvram", run: func(e *fwEnv) error { return e.store.RemoveNvram(fwTestVM) },
				acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok }},
			{name: "RenameNvramFrom", run: func(e *fwEnv) error { return e.store.RenameNvram(fwTestVM, "vm2") },
				acted: func(e *fwEnv) bool { _, ok := e.nvram("vm2"); return ok }},
			{name: "RenameNvramOnto", run: func(e *fwEnv) error {
				fwWriteFile(e.t, e.store.NvramPath("vm0"), "OTHER")
				return e.store.RenameNvram("vm0", fwTestVM)
			}, acted: func(e *fwEnv) bool { b, _ := e.nvram(fwTestVM); return b == "OTHER" }},
		},
		OpWipe: {
			{name: "WipeFirmwareState", bestEffort: true, run: func(e *fwEnv) error { e.store.WipeFirmwareState(fwTestVM, fwTestUUID); return nil },
				acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok || !e.hasSwtpm() }},
			{name: "WipeNameKeyedFirmwareState", bestEffort: true, run: func(e *fwEnv) error { e.store.WipeNameKeyedFirmwareState(fwTestVM); return nil },
				acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok }},
			// uuid-only: the record is found by its uuid (spec §5.1, the
			// vm_replace_cleanup.go:348 case).
			{name: "WipeFirmwareStateByUUID", bestEffort: true, run: func(e *fwEnv) error { e.store.WipeFirmwareStateByUUID(fwTestUUID); return nil },
				acted: func(e *fwEnv) bool { return !e.hasSwtpm() }},
		},
	}
}

// fwOrdinaryAllowed is the §5.1 table for an ordinary call: no record →
// allow; a marker → refuse; a hold → refuse, except OpResume under
// released_unconfirmed; an unreadable record → refuse.
func fwOrdinaryAllowed(st fwState, op FirmwareOp) bool {
	if st.err != nil {
		return false
	}
	for _, r := range st.recs {
		if !(r.Kind == FirmwareHold && r.State == "released_unconfirmed" && op == OpResume) {
			return false
		}
	}
	return true
}

func TestFirmwareMoveGuard(t *testing.T) {
	ops := []FirmwareOp{OpStart, OpResume, OpStop, OpDefine, OpUndefine, OpWriteState, OpWipe}
	prims := fwPrims()
	for _, op := range ops {
		t.Run(string(op), func(t *testing.T) {
			for _, st := range fwStates() {
				t.Run(st.name, func(t *testing.T) {
					want := fwOrdinaryAllowed(st, op)
					for _, p := range prims[op] {
						if want && p.refuseOnly {
							continue
						}
						t.Run(p.name, func(t *testing.T) {
							e := newFWEnv(t, st, p.dom)
							err := p.run(e)
							acted := err == nil
							if p.acted != nil {
								acted = p.acted(e)
							}
							switch {
							case want && (err != nil || !acted):
								t.Fatalf("refused, want allowed: err=%v acted=%v calls=%v", err, acted, e.api.calls)
							case !want && acted && (p.acted != nil || p.bestEffort):
								t.Fatalf("acted, want refused: err=%v calls=%v", err, e.api.calls)
							case !want && !p.bestEffort && st.err == nil && !errors.Is(err, ErrFirmwareMoveInFlight):
								t.Fatalf("err = %v, want ErrFirmwareMoveInFlight", err)
							case !want && !p.bestEffort && st.err != nil && (!errors.Is(err, ErrFirmwareMoveRecordUnreadable) || errors.Is(err, ErrFirmwareMoveInFlight)):
								t.Fatalf("err = %v, want ErrFirmwareMoveRecordUnreadable and not in flight", err)
							case !want && len(e.api.calls) > 0:
								t.Fatalf("refused, but libvirt was called: %v", e.api.calls)
							}
						})
					}
				})
			}
		})
	}
}

// fwExempt is one exempt entry point: the op row it is exempt in and the
// spec's condition on the record.
type fwExempt struct {
	via   FirmwareExemption
	op    FirmwareOp
	dom   golibvirt.DomainState
	allow func(r FirmwareMoveRecord) bool
	run   func(e *fwEnv, id, attempt string) error
	acted func(e *fwEnv) bool
}

func fwExempts() []fwExempt {
	marker := func(r FirmwareMoveRecord) bool { return r.Kind == FirmwareMarker }
	hold := func(states ...string) func(FirmwareMoveRecord) bool {
		return func(r FirmwareMoveRecord) bool {
			if r.Kind != FirmwareHold {
				return false
			}
			for _, s := range states {
				if r.State == s {
					return true
				}
			}
			return false
		}
	}
	held := hold("prepared", "verified", "resuming", "mismatch")
	leftover := func(r FirmwareMoveRecord) bool { return r.Kind == FirmwareLeftover }
	nvram := []byte("PUSHED")
	return []fwExempt{
		// §7 M1p and its retry: before cutover only, never source_paused.
		{via: ViaResumeFirmwareMoveSource, op: OpResume, dom: golibvirt.DomainPaused,
			allow: func(r FirmwareMoveRecord) bool { return marker(r) && r.PreCutover },
			run: func(e *fwEnv, id, a string) error {
				return resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: id, Attempt: a, Via: ViaResumeFirmwareMoveSource})
			}, acted: func(e *fwEnv) bool { return e.api.called("resume") }},
		// D-5 --accept-source: source_paused, parked before cutover only
		// (spec §5.y); source_paused_from_cutover is refused.
		{via: ViaResumeFirmwareMoveSourceOperator, op: OpResume, dom: golibvirt.DomainPaused,
			allow: func(r FirmwareMoveRecord) bool {
				return marker(r) && r.State == "source_paused" && r.ParkedPreCutover
			},
			run: func(e *fwEnv, id, a string) error {
				return resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: id, Attempt: a, Via: ViaResumeFirmwareMoveSourceOperator})
			}, acted: func(e *fwEnv) bool { return e.api.called("resume") }},
		// The partition pauser: a move in progress before cutover only, never
		// a parked one (D2-13 re-review 3, m-C).
		{via: ViaResumePartitionPaused, op: OpResume, dom: golibvirt.DomainPaused,
			allow: func(r FirmwareMoveRecord) bool { return marker(r) && r.PreCutover && !r.Parked },
			run: func(e *fwEnv, id, _ string) error {
				return resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: id, Via: ViaResumePartitionPaused})
			}, acted: func(e *fwEnv) bool { return e.api.called("resume") }},
		{via: ViaResumeFirmwareMoveTarget, op: OpResume, dom: golibvirt.DomainPaused, allow: hold("resuming"),
			run: func(e *fwEnv, id, a string) error {
				return resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: id, Attempt: a, Via: ViaResumeFirmwareMoveTarget})
			}, acted: func(e *fwEnv) bool { return e.api.called("resume") }},
		{via: ViaDiscardFirmwareMoveTarget, op: OpStop, dom: golibvirt.DomainPaused, allow: held,
			run:   func(e *fwEnv, id, a string) error { return discardFirmwareMoveTarget(e.api, e.guard, fwTestVM, id, a) },
			acted: func(e *fwEnv) bool { return e.api.called("destroy") && e.api.called("undefine") }},
		// D-5 --stop-target (spec §5.y), and the stop of a
		// released_unconfirmed guest.
		{via: ViaStopFirmwareMoveTargetForOperator, op: OpStop, dom: golibvirt.DomainRunning,
			allow: hold("prepared", "verified", "resuming", "released_unconfirmed"),
			run: func(e *fwEnv, id, a string) error {
				return stopFirmwareMoveTargetForOperator(e.api, e.guard, fwTestVM, id, a, true)
			}, acted: func(e *fwEnv) bool { return e.api.called("destroy") }},
		{via: ViaUndefineFirmwareMoveLeftover, op: OpUndefine, dom: golibvirt.DomainShutoff,
			allow: func(r FirmwareMoveRecord) bool { return marker(r) && r.State == "cleaning" },
			run: func(e *fwEnv, id, a string) error {
				return undefineFirmwareMoveLeftover(e.api, e.guard, fwTestVM, id, a)
			},
			acted: func(e *fwEnv) bool { return e.api.called("undefine") }},
		{via: ViaMaterialiseFirmwareMoveNvram, op: OpWriteState, allow: hold("prepared"),
			run: func(e *fwEnv, id, a string) error {
				return e.store.MaterialiseFirmwareMoveNvram(fwTestVM, id, a, nvram)
			},
			acted: func(e *fwEnv) bool { b, _ := e.nvram(fwTestVM); return b == "PUSHED" }},
		{via: ViaPushFirmwareMoveNvram, op: OpWriteState, allow: hold("verified", "resuming"),
			run:   func(e *fwEnv, id, a string) error { return e.store.PushFirmwareMoveNvram(fwTestVM, id, a, nvram) },
			acted: func(e *fwEnv) bool { b, _ := e.nvram(fwTestVM); return b == "PUSHED" }},
		// D-5 --push-source-nvram (spec §5.y).
		{via: ViaPushSourceNvramForOperator, op: OpWriteState, allow: hold("released_unconfirmed"),
			run:   func(e *fwEnv, id, a string) error { return e.store.PushSourceNvramForOperator(fwTestVM, id, a, nvram) },
			acted: func(e *fwEnv) bool { b, _ := e.nvram(fwTestVM); return b == "PUSHED" }},
		{via: ViaWipeFirmwareMoveSource, op: OpWipe,
			allow: func(r FirmwareMoveRecord) bool { return marker(r) && r.State == "cleaning" && r.RetainedBundle },
			run:   func(e *fwEnv, id, a string) error { return e.store.WipeFirmwareMoveSource(fwTestVM, id, a) },
			acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok && !e.hasSwtpm() }},
		{via: ViaRemoveFirmwareMoveTargetState, op: OpWipe, allow: hold("prepared"),
			run: func(e *fwEnv, id, a string) error {
				return e.store.RemoveFirmwareMoveTargetState(fwTestVM, id, a, true, true)
			},
			acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok && !e.hasSwtpm() }},
		{via: ViaQuarantineFirmwareMoveTargetState, op: OpWipe, allow: held,
			run: func(e *fwEnv, id, a string) error {
				return e.store.QuarantineFirmwareMoveTargetState(fwTestVM, id, a, filepath.Join(e.store.DataDir, "q"))
			}, acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok && !e.hasSwtpm() }},
		// D-5 --discard-target of a leftover an owed DISCARD names: under
		// its leftover record only.
		{via: ViaStopOwedFirmwareLeftover, op: OpStop, dom: golibvirt.DomainRunning, allow: leftover,
			run: func(e *fwEnv, id, a string) error {
				return stopForOperator(e.api, e.guard, fwTestVM, id, a, true, ViaStopOwedFirmwareLeftover)
			}, acted: func(e *fwEnv) bool { return e.api.called("destroy") }},
		{via: ViaUndefineOwedFirmwareLeftover, op: OpUndefine, dom: golibvirt.DomainShutoff, allow: leftover,
			run: func(e *fwEnv, id, a string) error {
				return undefineKeepingState(e.api, e.guard, fwTestVM, id, a, ViaUndefineOwedFirmwareLeftover)
			}, acted: func(e *fwEnv) bool { return e.api.called("undefine") }},
		{via: ViaQuarantineOwedFirmwareLeftover, op: OpWipe, allow: leftover,
			run: func(e *fwEnv, id, a string) error {
				return e.store.QuarantineOwedFirmwareLeftover(fwTestVM, id, a, filepath.Join(e.store.DataDir, "q"))
			}, acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok && !e.hasSwtpm() }},
		// D-5 --accept-target on a stopped source cleanup: a cleaning marker,
		// bundle or not; never a hold, never another phase.
		{via: ViaQuarantineFirmwareMoveSourceForOperator, op: OpWipe,
			allow: func(r FirmwareMoveRecord) bool { return marker(r) && r.State == "cleaning" },
			run: func(e *fwEnv, id, a string) error {
				return e.store.QuarantineFirmwareMoveSourceForOperator(fwTestVM, id, a, filepath.Join(e.store.DataDir, "q"))
			}, acted: func(e *fwEnv) bool { _, ok := e.nvram(fwTestVM); return !ok && !e.hasSwtpm() }},
	}
}

// TestFirmwareMoveGuard_Exempt covers the exempt column of every row: each
// exempt entry point, for its own uuid and attempt, in every record state,
// TestFirmwareMoveGuard_Exempt/<op>/<entry point>/<state>. It is allowed
// where the ordinary call is, and where the spec exempts it; refused
// everywhere else. With no record only ResumePartitionPaused (the pauser's
// own resume, firmware VM or not) goes ahead; the others act only for a move.
func TestFirmwareMoveGuard_Exempt(t *testing.T) {
	for _, x := range fwExempts() {
		t.Run(string(x.op)+"/"+string(x.via), func(t *testing.T) {
			for _, st := range fwStates() {
				t.Run(st.name, func(t *testing.T) {
					want := fwOrdinaryAllowed(st, x.op)
					if len(st.recs) == 0 && st.err == nil {
						want = x.via == ViaResumePartitionPaused
					}
					for _, r := range st.recs {
						if x.allow(r) {
							want = true
						}
					}
					e := newFWEnv(t, st, x.dom)
					err := x.run(e, fwTestUUID, fwTestAttempt)
					acted := x.acted(e)
					switch {
					case want && (err != nil || !acted):
						t.Fatalf("refused, want allowed: err=%v acted=%v calls=%v", err, acted, e.api.calls)
					case !want && (err == nil || acted):
						t.Fatalf("allowed, want refused: err=%v acted=%v calls=%v", err, acted, e.api.calls)
					case !want && len(e.api.calls) > 0:
						t.Fatalf("refused, but libvirt was called: %v", e.api.calls)
					}
				})
			}
		})
	}
}

// An exempt entry point acts only for its own record: another attempt or
// another uuid is refused, in a state where the right binding is allowed.
// ResumePartitionPaused knows no attempt and is bound by the uuid alone.
func TestFirmwareMoveGuard_ExemptBinding(t *testing.T) {
	allowing := map[FirmwareExemption]fwState{
		ViaResumeFirmwareMoveSource:                fwMarker("m", "migrating", true, false),
		ViaResumeFirmwareMoveSourceOperator:        fwSourcePausedPre(),
		ViaResumePartitionPaused:                   fwMarker("m", "migrating", true, false),
		ViaResumeFirmwareMoveTarget:                fwHold("resuming"),
		ViaDiscardFirmwareMoveTarget:               fwHold("verified"),
		ViaStopFirmwareMoveTargetForOperator:       fwHold("released_unconfirmed"),
		ViaUndefineFirmwareMoveLeftover:            fwMarker("m", "cleaning", false, true),
		ViaMaterialiseFirmwareMoveNvram:            fwHold("prepared"),
		ViaPushFirmwareMoveNvram:                   fwHold("verified"),
		ViaPushSourceNvramForOperator:              fwHold("released_unconfirmed"),
		ViaWipeFirmwareMoveSource:                  fwMarker("m", "cleaning", false, true),
		ViaRemoveFirmwareMoveTargetState:           fwHold("prepared"),
		ViaQuarantineFirmwareMoveTargetState:       fwHold("mismatch"),
		ViaQuarantineFirmwareMoveSourceForOperator: fwMarker("m", "cleaning", false, false),
		ViaStopOwedFirmwareLeftover:                fwLeftover(),
		ViaUndefineOwedFirmwareLeftover:            fwLeftover(),
		ViaQuarantineOwedFirmwareLeftover:          fwLeftover(),
	}
	for _, x := range fwExempts() {
		st, ok := allowing[x.via]
		if !ok {
			t.Fatalf("%s: no allowing state", x.via)
		}
		t.Run(string(x.via), func(t *testing.T) {
			cases := map[string][2]string{
				"right":         {fwTestUUID, fwTestAttempt},
				"other_uuid":    {fwOtherUUID, fwTestAttempt},
				"no_uuid":       {"", fwTestAttempt},
				"other_attempt": {fwTestUUID, fwOtherAtt},
				"no_attempt":    {fwTestUUID, ""},
			}
			for name, b := range cases {
				t.Run(name, func(t *testing.T) {
					e := newFWEnv(t, st, x.dom)
					err := x.run(e, b[0], b[1])
					want := name == "right" || (x.via == ViaResumePartitionPaused && (name == "other_attempt" || name == "no_attempt"))
					if got := err == nil && x.acted(e); got != want {
						t.Fatalf("allowed=%v, want %v (err=%v, calls=%v)", got, want, err, e.api.calls)
					}
				})
			}
		})
	}
}

// T-34 (libvirt half). The partition pauser's resume of a source guest it
// paused goes ahead while the move is in progress before cutover (preparing,
// prepared, migrating); from cutover on it is refused, and so is every parked
// marker, whatever it was parked from: a parked move resumes its source
// through its own steps, which ask the target first (D2-13 re-review 3, m-C).
// fwmig's TestFwmigWire_PartitionPauseResume runs the same through every real
// phase.
//
// Mutation: refuse ResumePartitionPaused under every marker — red.
func TestPartitionPauseResume_PreCutoverMarkerAllowed(t *testing.T) {
	for _, st := range fwStates() {
		if !strings.HasPrefix(st.name, "marker/") || !st.recs[0].PreCutover || st.recs[0].Parked {
			continue
		}
		t.Run(st.name, func(t *testing.T) {
			e := newFWEnv(t, st, golibvirt.DomainPaused)
			if err := resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: fwTestUUID, Via: ViaResumePartitionPaused}); err != nil {
				t.Fatalf("refused: %v", err)
			}
			if !e.api.called("resume") {
				t.Fatal("not resumed")
			}
		})
	}
}

// Mutations: allow ResumePartitionPaused whatever the phase — red; allow it
// under a parked marker reached before cutover — red.
func TestPartitionPauseResume_CutoverMarkerRefused(t *testing.T) {
	n, parkedPre := 0, 0
	for _, st := range fwStates() {
		if !strings.HasPrefix(st.name, "marker/") || (st.recs[0].PreCutover && !st.recs[0].Parked) {
			continue
		}
		if st.recs[0].PreCutover {
			parkedPre++
		}
		n++
		t.Run(st.name, func(t *testing.T) {
			e := newFWEnv(t, st, golibvirt.DomainPaused)
			err := resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: fwTestUUID, Via: ViaResumePartitionPaused})
			if !errors.Is(err, ErrFirmwareMoveInFlight) || e.api.called("resume") {
				t.Fatalf("err=%v calls=%v, want refused and not resumed", err, e.api.calls)
			}
		})
	}
	if n < 10 || parkedPre < 6 {
		t.Fatalf("only %d refused marker states, %d of them parked before cutover", n, parkedPre)
	}
}

// T-7. The firmware move guard is asked before the start guard's readiness:
// a domain RequireStartGuard lets start without waiting (no NIC guard) is
// still refused, and one that would wait is refused at once rather than
// after the wait.
//
// Mutation: ask the firmware guard after the needs short-circuit — red.
func TestFirmwareMoveGuard_StartRefusedBeforeNICGuardSet(t *testing.T) {
	refuse := NewFirmwareMoveGuard(fwLookup(fwMarker("m", "migrating", true, false)))

	c := &Client{}
	c.RequireStartGuard(time.Hour, func(string) bool { return false })
	c.SetFirmwareMoveGuard(refuse)
	if _, err := c.guard(fwTestVM); !errors.Is(err, ErrFirmwareMoveInFlight) {
		t.Fatalf("unguarded start: err = %v, want ErrFirmwareMoveInFlight", err)
	}

	c = &Client{}
	c.RequireStartGuard(time.Hour, nil)
	c.SetFirmwareMoveGuard(refuse)
	done := make(chan error, 1)
	go func() { _, err := c.guard(fwTestVM); done <- err }()
	select {
	case err := <-done:
		if !errors.Is(err, ErrFirmwareMoveInFlight) {
			t.Fatalf("waiting start: err = %v, want ErrFirmwareMoveInFlight", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the start waited for the NIC guard before asking the firmware move guard")
	}

	// No record: the start guard decides, as before the firmware guard.
	c = &Client{}
	c.RequireStartGuard(time.Hour, func(string) bool { return false })
	c.SetFirmwareMoveGuard(NewFirmwareMoveGuard(fwLookup(fwState{})))
	if _, err := c.guard(fwTestVM); err != nil {
		t.Fatalf("no record: err = %v", err)
	}
}

// T-21a. DiscardFirmwareMoveTarget destroys a paused held domain and then
// undefines it with KEEP_NVRAM|KEEP_TPM (flags 72), keeping its state for the
// quarantine; a shut-off one is only undefined; a running one is refused
// with nothing done; a domain of the name with another uuid is refused; no
// domain is nothing to discard.
//
// Mutation: undefine with UndefineDomain(false)'s flags — red.
func TestDiscardFirmwareMoveTarget_DestroyThenKeepFlags(t *testing.T) {
	st := fwHold("verified")
	const keep = golibvirt.DomainUndefineKeepNvram | golibvirt.DomainUndefineKeepTpm
	if keep != 72 {
		t.Fatalf("KEEP_NVRAM|KEEP_TPM = %d, want 72 (probe (b))", keep)
	}

	e := newFWEnv(t, st, golibvirt.DomainPaused)
	if err := discardFirmwareMoveTarget(e.api, e.guard, fwTestVM, fwTestUUID, fwTestAttempt); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.api.calls, ","); got != "destroy,undefine" {
		t.Fatalf("calls = %s, want destroy,undefine", got)
	}
	if e.api.undefFlags[0] != keep {
		t.Fatalf("undefine flags = %d, want %d", e.api.undefFlags[0], keep)
	}
	if b, ok := e.nvram(fwTestVM); !ok || b != "T0" || !e.hasSwtpm() {
		t.Fatal("the discard touched the state files")
	}

	e = newFWEnv(t, st, golibvirt.DomainShutoff)
	if err := discardFirmwareMoveTarget(e.api, e.guard, fwTestVM, fwTestUUID, fwTestAttempt); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(e.api.calls, ","); got != "undefine" || e.api.undefFlags[0] != keep {
		t.Fatalf("shut off: calls = %s flags %v, want undefine with %d", got, e.api.undefFlags, keep)
	}

	e = newFWEnv(t, st, golibvirt.DomainRunning)
	if err := discardFirmwareMoveTarget(e.api, e.guard, fwTestVM, fwTestUUID, fwTestAttempt); err == nil || len(e.api.calls) > 0 {
		t.Fatalf("running: err=%v calls=%v, want refused with nothing done", err, e.api.calls)
	}

	e = newFWEnv(t, st, golibvirt.DomainPaused)
	e.api.doms[fwTestVM].uuid = golibvirt.UUID(uuid.MustParse(fwOtherUUID))
	if err := discardFirmwareMoveTarget(e.api, e.guard, fwTestVM, fwTestUUID, fwTestAttempt); err == nil || len(e.api.calls) > 0 {
		t.Fatalf("other uuid: err=%v calls=%v, want refused with nothing done", err, e.api.calls)
	}

	e = newFWEnv(t, st, golibvirt.DomainPaused)
	delete(e.api.doms, fwTestVM)
	if err := discardFirmwareMoveTarget(e.api, e.guard, fwTestVM, fwTestUUID, fwTestAttempt); err != nil || len(e.api.calls) > 0 {
		t.Fatalf("no domain: err=%v calls=%v, want nothing done", err, e.api.calls)
	}
}

// A refusal names the VM, the attempt, the peer and the phase or state, and
// is ErrFirmwareMoveInFlight; an unreadable record says so.
func TestFirmwareMoveGuard_RefusalText(t *testing.T) {
	g := NewFirmwareMoveGuard(fwLookup(fwMarker("m", "target_ran", false, false)))
	err := g.check(FirmwareCall{Op: OpStop, Name: fwTestVM})
	for _, want := range []string{fwTestVM, fwTestAttempt, "to node-2", "phase target_ran", "stop refused"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("marker refusal %q lacks %q", err, want)
		}
	}
	g = NewFirmwareMoveGuard(fwLookup(fwHold("verified")))
	err = g.check(FirmwareCall{Op: OpStart, Name: fwTestVM})
	for _, want := range []string{"from node-1", "state verified"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("hold refusal %q lacks %q", err, want)
		}
	}
	// Another VM's unreadable record: the refusal names the file, the
	// remedy and the condition, and does not call anything in flight.
	//
	// Mutation: refuse an unreadable record with the in-flight text — red.
	g = NewFirmwareMoveGuard(fwLookup(fwState{err: fwUnreadable}))
	err = g.check(FirmwareCall{Op: OpDefine, Name: "web", UUID: fwTestUUID})
	var ue *FirmwareRecordUnreadableError
	if !errors.Is(err, ErrFirmwareMoveRecordUnreadable) || errors.Is(err, ErrFirmwareMoveInFlight) || !errors.As(err, &ue) || ue.Path != fwUnreadable.Path {
		t.Errorf("unreadable: %v, want ErrFirmwareMoveRecordUnreadable carrying the file, not in flight", err)
	}
	for _, want := range []string{"define of web refused", fwUnreadable.Path, "cannot be read", "repaired", "firmware_migration_record_unreadable"} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("unreadable refusal %q lacks %q", err, want)
		}
	}
	if err != nil && strings.Contains(err.Error(), "in flight") {
		t.Errorf("unreadable refusal %q says a move is in flight", err)
	}
	if !IsFirmwareMoveRefusal(err) {
		t.Errorf("IsFirmwareMoveRefusal(%v) = false", err)
	}
	if err := NewFirmwareMoveGuard(nil).check(FirmwareCall{Op: OpStart, Name: fwTestVM}); !IsFirmwareMoveRefusal(err) {
		t.Errorf("nil lookup: %v, want refused", err)
	}
	if err := (FirmwareMoveGuard{}).check(FirmwareCall{Op: OpStart, Name: fwTestVM}); err != nil {
		t.Errorf("zero guard: %v, want allowed", err)
	}
}

func TestDomainNameFromXML(t *testing.T) {
	if got := DomainNameFromXML(fwTestDomXML); got != fwTestVM {
		t.Fatalf("got %q", got)
	}
	if got := DomainNameFromXML("<domain/>"); got != "" {
		t.Fatalf("got %q", got)
	}
}

// A best-effort wipe refused because a record cannot be read is kept for
// TakeRefusedWipes, so the daemon reports it (the state is still on disk); one
// refused because a record names the VM is the guard doing its job and is not.
//
// Mutation: record no refused wipe — red.
func TestFirmwareStore_RefusedWipesForUnreadableRecord(t *testing.T) {
	e := newFWEnv(t, fwState{err: fwUnreadable}, golibvirt.DomainShutoff)
	e.store.WipeFirmwareState(fwTestVM, fwTestUUID)
	e.store.WipeFirmwareStateByUUID(fwTestUUID)
	got, dropped := e.store.TakeRefusedWipes()
	if len(got) != 2 || dropped != 0 || got[0].VM != fwTestVM || got[1].UUID != fwTestUUID || !errors.Is(got[0].Err, ErrFirmwareMoveRecordUnreadable) {
		t.Fatalf("refused wipes = %+v", got)
	}
	if again, _ := e.store.TakeRefusedWipes(); len(again) != 0 {
		t.Fatalf("taken twice: %+v", again)
	}
	e = newFWEnv(t, fwMarker("m", "migrating", true, false), golibvirt.DomainShutoff)
	e.store.WipeFirmwareState(fwTestVM, fwTestUUID)
	if got, _ := e.store.TakeRefusedWipes(); len(got) != 0 {
		t.Fatalf("a marker's refusal reported as a leak: %+v", got)
	}
}

// Past maxRefusedWipes between two collections the store keeps the newest
// and counts the ones it drops, so the report's total still counts every
// refusal (D2-6 re-review 2, m-13).
//
// Mutation: do not count the dropped refusals; keep the count after a
// collection — red.
func TestFirmwareStore_RefusedWipesDroppedAreCounted(t *testing.T) {
	e := newFWEnv(t, fwState{err: fwUnreadable}, golibvirt.DomainShutoff)
	for i := 0; i < maxRefusedWipes+6; i++ {
		e.store.WipeFirmwareStateByUUID(fmt.Sprintf("aad2e0bb-3311-42a9-92f9-%012d", i))
	}
	got, dropped := e.store.TakeRefusedWipes()
	if len(got) != maxRefusedWipes || dropped != 6 {
		t.Fatalf("took %d wipes, %d dropped; want %d and 6", len(got), dropped, maxRefusedWipes)
	}
	if got[len(got)-1].UUID != fmt.Sprintf("aad2e0bb-3311-42a9-92f9-%012d", maxRefusedWipes+5) {
		t.Fatalf("the newest refusal was not kept: %+v", got[len(got)-1])
	}
	if again, d := e.store.TakeRefusedWipes(); len(again) != 0 || d != 0 {
		t.Fatalf("a second collection took %d wipes, %d dropped", len(again), d)
	}
}

// WipeFirmwareMoveSource reports a removal that failed, so cleanup keeps its
// marker over state still on disk (review m-5).
//
// Mutation: ignore the removal errors — red.
func TestWipeFirmwareMoveSource_ReportsFailure(t *testing.T) {
	e := newFWEnv(t, fwMarker("m", "cleaning", false, true), golibvirt.DomainShutoff)
	p := e.store.NvramPath(fwTestVM)
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	fwWriteFile(t, filepath.Join(p, "x"), "a directory where the NVRAM was")
	if err := e.store.WipeFirmwareMoveSource(fwTestVM, fwTestUUID, fwTestAttempt); err == nil {
		t.Fatal("a failed removal reported success")
	}
}

// I-2: a memory snapshot asks the guard for the resume that ends it AND the
// start a revert makes from it before it suspends anything; either refusal
// alone refuses it (together: every record that names the VM, as the old
// save+restore capture's stop+start did). The client here has no libvirt connection: a call that got past
// the guard would panic on it.
//
// Mutation: drop either op from CreateLiveSnapshot's check — red.
func TestCreateLiveSnapshot_AsksResumeAndStart(t *testing.T) {
	for _, only := range []FirmwareOp{OpResume, OpStart} {
		t.Run(string(only), func(t *testing.T) {
			refused := errors.New("refused")
			c := &Client{}
			c.SetFirmwareMoveGuard(FirmwareMoveGuard{Check: func(fc FirmwareCall) error {
				if fc.Op == only {
					return refused
				}
				return nil
			}})
			var err error
			func() {
				defer func() {
					if r := recover(); r != nil {
						err = fmt.Errorf("reached libvirt: %v", r)
					}
				}()
				_, _, err = c.CreateLiveSnapshot(fwTestVM, "s1", "/nonexistent", CaptureOptions{})
			}()
			if !errors.Is(err, refused) {
				t.Fatalf("err = %v, want the %s refusal before any libvirt call", err, only)
			}
		})
	}
}

func fwSourcePausedPre() fwState {
	st := fwMarker("m", "source_paused", false, false)
	st.recs[0].ParkedPreCutover = true
	return st
}

// N-1: the D-5 resume of a source_paused source goes ahead only when the
// marker was parked before cutover; parked from cutover or later the target's
// copy is current, and resuming the source would run a second copy. The
// automatic M1p entry point never resumes a source_paused source.
//
// Mutations: drop ParkedPreCutover from the operator cell — red; let the M1p
// entry point resume source_paused — red.
func TestFirmwareMoveGuard_SourcePausedResumeOnlyBeforeCutover(t *testing.T) {
	post := fwMarker("m", "source_paused", false, false) // parked from cutover
	for name, c := range map[string]struct {
		st   fwState
		via  FirmwareExemption
		want bool
	}{
		"operator/parked_pre_cutover":  {fwSourcePausedPre(), ViaResumeFirmwareMoveSourceOperator, true},
		"operator/parked_post_cutover": {post, ViaResumeFirmwareMoveSourceOperator, false},
		"m1p/parked_pre_cutover":       {fwSourcePausedPre(), ViaResumeFirmwareMoveSource, false},
		"m1p/parked_post_cutover":      {post, ViaResumeFirmwareMoveSource, false},
	} {
		t.Run(name, func(t *testing.T) {
			e := newFWEnv(t, c.st, golibvirt.DomainPaused)
			err := resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: fwTestUUID, Attempt: fwTestAttempt, Via: c.via})
			if got := err == nil && e.api.called("resume"); got != c.want {
				t.Fatalf("resumed = %v, want %v (%v)", got, c.want, err)
			}
		})
	}
}

// N-2: across filesystems the quarantine copies, makes the copy durable, and
// only then removes the source. Every fsync of the copy happens while the
// source is still whole; a failed fsync keeps the source and drops the copy.
//
// Mutation: remove the source before the copy's fsyncs — red.
func TestQuarantine_CrossFilesystemKeepsSourceUntilCopyDurable(t *testing.T) {
	exdev := func(o, n string) error { return &os.LinkError{Op: "rename", Old: o, New: n, Err: syscall.EXDEV} }
	defer func(r func(string, string) error, s func(string) error) { quarantineRename, quarantineSync = r, s }(quarantineRename, quarantineSync)
	quarantineRename = exdev

	t.Run("ok", func(t *testing.T) {
		e := newFWEnv(t, fwHold("mismatch"), golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine", "vm1-x")
		var synced []string
		syncedWhileSource := map[string]bool{}
		entryDurable := false // q fsynced with the swtpm copy in it and the source still whole
		quarantineSync = func(p string) error {
			synced = append(synced, p)
			if _, seen := syncedWhileSource[p]; !seen { // the first fsync of each
				syncedWhileSource[p] = e.hasSwtpm()
			}
			if _, err := os.Stat(filepath.Join(q, "swtpm")); err == nil && p == q && e.hasSwtpm() {
				entryDurable = true
			}
			return fsyncPath(p)
		}
		if err := e.store.QuarantineFirmwareMoveTargetState(fwTestVM, fwTestUUID, fwTestAttempt, q); err != nil {
			t.Fatal(err)
		}
		if b, err := os.ReadFile(filepath.Join(q, "nvram")); err != nil || string(b) != "T0" {
			t.Fatalf("quarantined nvram = %q, %v", b, err)
		}
		if b, err := os.ReadFile(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall")); err != nil || string(b) != "P0" {
			t.Fatalf("quarantined permall = %q, %v", b, err)
		}
		if _, ok := e.nvram(fwTestVM); ok || e.hasSwtpm() {
			t.Fatal("the sources are still there after a completed move")
		}
		if !entryDurable {
			t.Error("the quarantine dir holding the swtpm copy was not fsynced before the source was removed")
		}
		// The swtpm copy is made, and fsynced, under its temporary name, and
		// renamed into place only once durable.
		cp := filepath.Join(q, "swtpm"+quarantineCopySuffix)
		for _, d := range []string{cp, filepath.Join(cp, "tpm2"), q, filepath.Dir(q)} {
			was, ok := syncedWhileSource[d]
			if !ok {
				t.Errorf("%s never fsynced (synced %v)", d, synced)
			} else if !was {
				t.Errorf("%s fsynced after the swtpm source was removed", d)
			}
		}
	})

	t.Run("fsync_fails", func(t *testing.T) {
		e := newFWEnv(t, fwHold("mismatch"), golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine", "vm1-x")
		if err := os.MkdirAll(q, 0o700); err != nil {
			t.Fatal(err)
		}
		quarantineSync = func(p string) error {
			if p == q {
				return errors.New("injected fsync failure")
			}
			return fsyncPath(p)
		}
		if err := e.store.QuarantineFirmwareMoveTargetState(fwTestVM, fwTestUUID, fwTestAttempt, q); err == nil {
			t.Fatal("a failed fsync of the copy reported success")
		}
		if b, ok := e.nvram(fwTestVM); !ok || b != "T0" {
			t.Fatal("the NVRAM source is gone although its copy was not durable")
		}
		if !e.hasSwtpm() {
			t.Fatal("the swtpm source is gone although its copy was not durable")
		}
	})

	// The swtpm tree's own copy fails to become durable, after the NVRAM has
	// moved: the tree's source is kept, whole (D2-6 re-review 2, m-14 test
	// nit: the failure above stops at the NVRAM, before the tree).
	t.Run("fsync_fails_swtpm", func(t *testing.T) {
		e := newFWEnv(t, fwHold("mismatch"), golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine", "vm1-x")
		cp := filepath.Join(q, "swtpm"+quarantineCopySuffix)
		hit := false
		quarantineSync = func(p string) error {
			if p == cp {
				hit = true
				return errors.New("injected fsync failure")
			}
			return fsyncPath(p)
		}
		if err := e.store.QuarantineFirmwareMoveTargetState(fwTestVM, fwTestUUID, fwTestAttempt, q); err == nil {
			t.Fatal("a failed fsync of the swtpm copy reported success")
		}
		if !hit {
			t.Fatal("the swtpm copy was never fsynced")
		}
		if !e.hasSwtpm() {
			t.Fatal("the swtpm source is gone although its copy was not durable")
		}
		if b, err := os.ReadFile(filepath.Join(q, "nvram")); err != nil || string(b) != "T0" {
			t.Fatalf("the NVRAM was not quarantined before the tree: %q, %v", b, err)
		}
		for _, p := range []string{cp, filepath.Join(q, "swtpm")} {
			if _, err := os.Lstat(p); !os.IsNotExist(err) {
				t.Fatalf("%s left behind by a copy that was not durable (%v)", p, err)
			}
		}
	})
}

// m-14 (D2-6 re-review 2): a cross-filesystem quarantine a crash interrupted
// completes on the retry, and never removes a source the quarantine does not
// hold, byte for byte.
//
// Mutations: refuse an existing destination as before ("already exists") —
// red (placed_source_not_removed, source_partly_removed); remove the source
// without comparing — red (differs_keeps_both); copy straight to the final
// name — red (partial_copy_leftover).
func TestQuarantine_CrossFilesystemRetryAfterCrash(t *testing.T) {
	exdev := func(o, n string) error { return &os.LinkError{Op: "rename", Old: o, New: n, Err: syscall.EXDEV} }
	defer func(r, pl func(string, string) error) { quarantineRename, quarantinePlace = r, pl }(quarantineRename, quarantinePlace)
	quarantineRename = exdev
	crash := errors.New("injected crash")

	quarantine := func(e *fwEnv, q string) error {
		return e.store.QuarantineFirmwareMoveTargetState(fwTestVM, fwTestUUID, fwTestAttempt, q)
	}
	requireMoved := func(t *testing.T, e *fwEnv, q string) {
		t.Helper()
		if b, err := os.ReadFile(filepath.Join(q, "nvram")); err != nil || string(b) != "T0" {
			t.Fatalf("quarantined nvram = %q, %v", b, err)
		}
		if b, err := os.ReadFile(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall")); err != nil || string(b) != "P0" {
			t.Fatalf("quarantined permall = %q, %v", b, err)
		}
		if _, ok := e.nvram(fwTestVM); ok || e.hasSwtpm() {
			t.Fatal("a source is still there after the retry")
		}
		if _, err := os.Lstat(filepath.Join(q, "swtpm"+quarantineCopySuffix)); !os.IsNotExist(err) {
			t.Fatalf("the temporary copy is left (%v)", err)
		}
	}

	// A crash mid-copy: a partial copy under the temporary name, the source
	// whole. The retry replaces the partial copy and completes.
	t.Run("partial_copy_leftover", func(t *testing.T) {
		quarantinePlace = os.Rename
		e := newFWEnv(t, fwHold("mismatch"), golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine", "vm1-x")
		fwWriteFile(t, filepath.Join(q, "swtpm"+quarantineCopySuffix, "tpm2", "tpm2-00.permall"), "P")
		if err := quarantine(e, q); err != nil {
			t.Fatalf("retry after a crash mid-copy: %v", err)
		}
		requireMoved(t, e, q)
	})

	// A crash after the copy took its name, before (or during) the removal of
	// the source: the retry finds a whole copy and removes what is left of
	// the source.
	t.Run("placed_source_not_removed", func(t *testing.T) {
		e := newFWEnv(t, fwHold("mismatch"), golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine", "vm1-x")
		quarantinePlace = func(o, n string) error {
			if err := os.Rename(o, n); err != nil {
				return err
			}
			if filepath.Base(n) == "swtpm" {
				return crash // placed; the process dies before removing the source
			}
			return nil
		}
		if err := quarantine(e, q); err == nil {
			t.Fatal("the injected crash did not stop the move")
		}
		if _, err := os.Lstat(filepath.Join(q, "swtpm")); err != nil {
			t.Fatalf("the crash did not leave the placed copy: %v", err)
		}
		if !e.hasSwtpm() {
			t.Fatal("the source went before the copy was durable")
		}
		quarantinePlace = os.Rename
		if err := quarantine(e, q); err != nil {
			t.Fatalf("retry after a crash before the source's removal: %v", err)
		}
		requireMoved(t, e, q)
	})

	// The removal of the source was cut short: a part of it is left. The
	// quarantine holds that part, so the retry removes it.
	t.Run("source_partly_removed", func(t *testing.T) {
		quarantinePlace = os.Rename
		e := newFWEnv(t, fwHold("mismatch"), golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine", "vm1-x")
		fwWriteFile(t, filepath.Join(q, "nvram"), "T0")
		fwWriteFile(t, filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall"), "P0")
		fwWriteFile(t, filepath.Join(q, "swtpm", "tpm2", "other"), "O")
		if err := os.Remove(e.store.NvramPath(fwTestVM)); err != nil {
			t.Fatal(err)
		}
		if err := quarantine(e, q); err != nil {
			t.Fatalf("retry after a partial removal: %v", err)
		}
		requireMoved(t, e, q)
	})

	// The destination holds something else: both are kept and the retry
	// refuses, naming them.
	t.Run("differs_keeps_both", func(t *testing.T) {
		quarantinePlace = os.Rename
		e := newFWEnv(t, fwHold("mismatch"), golibvirt.DomainShutoff)
		q := filepath.Join(e.store.DataDir, "fwmig-quarantine", "vm1-x")
		fwWriteFile(t, filepath.Join(q, "nvram"), "T0")
		fwWriteFile(t, filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall"), "P-OTHER")
		err := quarantine(e, q)
		if err == nil || !strings.Contains(err.Error(), "both are kept") {
			t.Fatalf("err = %v, want a refusal keeping both", err)
		}
		if !e.hasSwtpm() {
			t.Fatal("a source the quarantine does not hold was removed")
		}
		if b, _ := os.ReadFile(filepath.Join(q, "swtpm", "tpm2", "tpm2-00.permall")); string(b) != "P-OTHER" {
			t.Fatalf("the quarantined copy was overwritten: %q", b)
		}
	})
}
