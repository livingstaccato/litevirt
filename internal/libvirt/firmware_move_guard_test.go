package libvirt

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
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

// fwStates: no record; a record that cannot be read; a marker in every phase
// (a parked one from a pre-cutover and from a post-cutover phase; a cleaning
// one with and without its retained bundle); a hold in every state.
func fwStates() []fwState {
	out := []fwState{{name: "none"}, {name: "unreadable", err: errors.New("fwmig: corrupt record")}}
	for _, p := range fwProgressPhases {
		out = append(out, fwMarker("marker/"+p, p, fwPrePhase(p), p == "cleaning"))
	}
	out = append(out, fwMarker("marker/cleaning_no_bundle", "cleaning", false, false))
	for _, p := range fwParkedPhases {
		for _, from := range []string{"migrating", "cutover"} {
			out = append(out, fwMarker("marker/"+p+"_from_"+from, p, p != "source_paused" && fwPrePhase(from), false))
		}
	}
	for _, h := range fwHoldStates {
		out = append(out, fwHold(h))
	}
	return out
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
		},
		OpResume: {
			{name: "ResumeDomain", dom: paused, run: func(e *fwEnv) error {
				return resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM})
			}, acted: func(e *fwEnv) bool { return e.api.called("resume") }},
			{name: "Client.ResumeDomain", refuseOnly: true, run: func(e *fwEnv) error { return e.client.ResumeDomain(fwTestVM) }},
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
							case !want && !p.bestEffort && !errors.Is(err, ErrFirmwareMoveInFlight):
								t.Fatalf("err = %v, want ErrFirmwareMoveInFlight", err)
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
	nvram := []byte("PUSHED")
	return []fwExempt{
		{via: ViaResumeFirmwareMoveSource, op: OpResume, dom: golibvirt.DomainPaused,
			allow: func(r FirmwareMoveRecord) bool { return marker(r) && r.PreCutover },
			run: func(e *fwEnv, id, a string) error {
				return resumeDomain(e.api, e.guard, FirmwareCall{Op: OpResume, Name: fwTestVM, UUID: id, Attempt: a, Via: ViaResumeFirmwareMoveSource})
			}, acted: func(e *fwEnv) bool { return e.api.called("resume") }},
		{via: ViaResumePartitionPaused, op: OpResume, dom: golibvirt.DomainPaused,
			allow: func(r FirmwareMoveRecord) bool { return marker(r) && r.PreCutover },
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
		{via: ViaStopFirmwareMoveTargetForOperator, op: OpStop, dom: golibvirt.DomainRunning, allow: hold("released_unconfirmed"),
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
		ViaResumeFirmwareMoveSource:          fwMarker("m", "migrating", true, false),
		ViaResumePartitionPaused:             fwMarker("m", "migrating", true, false),
		ViaResumeFirmwareMoveTarget:          fwHold("resuming"),
		ViaDiscardFirmwareMoveTarget:         fwHold("verified"),
		ViaStopFirmwareMoveTargetForOperator: fwHold("released_unconfirmed"),
		ViaUndefineFirmwareMoveLeftover:      fwMarker("m", "cleaning", false, true),
		ViaMaterialiseFirmwareMoveNvram:      fwHold("prepared"),
		ViaPushFirmwareMoveNvram:             fwHold("verified"),
		ViaWipeFirmwareMoveSource:            fwMarker("m", "cleaning", false, true),
		ViaRemoveFirmwareMoveTargetState:     fwHold("prepared"),
		ViaQuarantineFirmwareMoveTargetState: fwHold("mismatch"),
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
// paused goes ahead while the marker is before cutover (preparing, prepared,
// migrating, or parked from those other than source_paused), so a running
// source left by a failed move is not kept paused; from cutover on, or in
// source_paused, it is refused. fwmig's TestFwmigWire_PartitionPauseResume
// runs the same through every real phase.
//
// Mutation: refuse ResumePartitionPaused under every marker — red.
func TestPartitionPauseResume_PreCutoverMarkerAllowed(t *testing.T) {
	for _, st := range fwStates() {
		if !strings.HasPrefix(st.name, "marker/") || !st.recs[0].PreCutover {
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

// Mutation: allow ResumePartitionPaused whatever the phase — red.
func TestPartitionPauseResume_CutoverMarkerRefused(t *testing.T) {
	n := 0
	for _, st := range fwStates() {
		if !strings.HasPrefix(st.name, "marker/") || st.recs[0].PreCutover {
			continue
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
	if n < 10 {
		t.Fatalf("only %d post-cutover marker states", n)
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
	g = NewFirmwareMoveGuard(fwLookup(fwState{err: errors.New("corrupt")}))
	if err = g.check(FirmwareCall{Op: OpWipe, UUID: fwTestUUID}); !errors.Is(err, ErrFirmwareMoveInFlight) || !strings.Contains(err.Error(), "cannot be read") {
		t.Errorf("unreadable: %v", err)
	}
	if err := NewFirmwareMoveGuard(nil).check(FirmwareCall{Op: OpStart, Name: fwTestVM}); !errors.Is(err, ErrFirmwareMoveInFlight) {
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
