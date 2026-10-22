package libvirtfake

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// The fake mirrors libvirt.Client's firmware move guard (spec §5.1): the same
// primitives ask it, with the same op, name, uuid, attempt and exempt entry
// point, before they change anything, so a fleet scenario on the fake sees
// the refusals a host would.

// firmwareMoveVirt is what both libvirt.Client and the fake offer the
// firmware move protocol.
type firmwareMoveVirt interface {
	SetFirmwareMoveGuard(libvirt.FirmwareMoveGuard)
	ResumeFirmwareMoveSource(name, uuid, attempt string) error
	ResumeFirmwareMoveSourceForOperator(name, uuid, attempt string) error
	ResumePartitionPaused(name, uuid string) error
	ResumeFirmwareMoveTarget(name, uuid, attempt string) error
	DiscardFirmwareMoveTarget(name, uuid, attempt string) error
	UndefineFirmwareMoveLeftover(name, uuid, attempt string) error
	StopFirmwareMoveTargetForOperator(name, uuid, attempt string, force bool) error
}

var (
	_ firmwareMoveVirt = (*Fake)(nil)
	_ firmwareMoveVirt = (*libvirt.Client)(nil)
)

const (
	fgVM      = "vm1"
	fgUUID    = "aad2e0bb-3311-42a9-92f9-4062205a4dc1"
	fgAttempt = "6f1c0c5e-0a43-4c55-9b5e-2b2b1f4d0e11"
	fgXML     = "<domain><name>" + fgVM + "</name><uuid>" + fgUUID + "</uuid></domain>"
)

func fgFake(t *testing.T, st State) *Fake {
	t.Helper()
	f := New()
	if err := f.DefineDomain(fgXML); err != nil {
		t.Fatal(err)
	}
	f.SetState(fgVM, st)
	return f
}

// Each guarded primitive asks the guard with the call libvirt.Client makes,
// and a refusal changes nothing.
//
// Mutation: drop the guard call from any one primitive — red.
func TestFake_FirmwareMoveGuardAskedFirst(t *testing.T) {
	type prim struct {
		name string
		st   State
		want libvirt.FirmwareCall
		run  func(f *Fake) error
	}
	exempt := func(op libvirt.FirmwareOp, via libvirt.FirmwareExemption) libvirt.FirmwareCall {
		return libvirt.FirmwareCall{Op: op, Name: fgVM, UUID: fgUUID, Attempt: fgAttempt, Via: via}
	}
	prims := []prim{
		{"StartDomain", StateDefined, libvirt.FirmwareCall{Op: libvirt.OpStart, Name: fgVM}, func(f *Fake) error { return f.StartDomain(fgVM) }},
		{"RevertToSnapshot", StateRunning, libvirt.FirmwareCall{Op: libvirt.OpStart, Name: fgVM}, func(f *Fake) error { return f.RevertToSnapshot(fgVM, "s1", nil) }},
		{"RevertToLiveSnapshot", StateRunning, libvirt.FirmwareCall{Op: libvirt.OpStart, Name: fgVM}, func(f *Fake) error {
			return f.RevertToLiveSnapshot(fgVM, "s1", "/nonexistent", nil, nil)
		}},
		{"ResumeDomain", StatePaused, libvirt.FirmwareCall{Op: libvirt.OpResume, Name: fgVM}, func(f *Fake) error { return f.ResumeDomain(fgVM) }},
		{"ShutdownDomain", StateRunning, libvirt.FirmwareCall{Op: libvirt.OpStop, Name: fgVM}, func(f *Fake) error { return f.ShutdownDomain(fgVM) }},
		{"DestroyDomain", StateRunning, libvirt.FirmwareCall{Op: libvirt.OpStop, Name: fgVM}, func(f *Fake) error { return f.DestroyDomain(fgVM) }},
		{"DefineDomain", StateDefined, libvirt.FirmwareCall{Op: libvirt.OpDefine, Name: fgVM, UUID: fgUUID}, func(f *Fake) error { return f.DefineDomain(fgXML) }},
		{"SetBootOrder", StateDefined, libvirt.FirmwareCall{Op: libvirt.OpDefine, Name: fgVM}, func(f *Fake) error { return f.SetBootOrder(fgVM, "disk") }},
		{"UndefineDomain", StateDefined, libvirt.FirmwareCall{Op: libvirt.OpUndefine, Name: fgVM}, func(f *Fake) error { return f.UndefineDomain(fgVM, false) }},
		{"UndefineDomainPreservingState", StateDefined, libvirt.FirmwareCall{Op: libvirt.OpUndefine, Name: fgVM}, func(f *Fake) error { return f.UndefineDomainPreservingState(fgVM) }},
		{"UndefineDeletedDomainKeepingState", StateDefined, libvirt.FirmwareCall{Op: libvirt.OpUndefine, Name: fgVM}, func(f *Fake) error { return f.UndefineDeletedDomainKeepingState(fgVM) }},
		{"CreateLiveSnapshot", StateRunning, libvirt.FirmwareCall{Op: libvirt.OpStart, Name: fgVM}, func(f *Fake) error {
			_, _, err := f.CreateLiveSnapshot(fgVM, "s1", "/nonexistent", libvirt.CaptureOptions{})
			return err
		}},
		{"CommitDiskOverlay", StateRunning, libvirt.FirmwareCall{Op: libvirt.OpDefine, Name: fgVM}, func(f *Fake) error {
			return f.CommitDiskOverlay(fgVM, "/pool/d.qcow2", "/pool/ov", "qcow2", nil)
		}},
		{"ResumeFirmwareMoveSource", StatePaused, exempt(libvirt.OpResume, libvirt.ViaResumeFirmwareMoveSource), func(f *Fake) error {
			return f.ResumeFirmwareMoveSource(fgVM, fgUUID, fgAttempt)
		}},
		{"ResumeFirmwareMoveSourceForOperator", StatePaused, exempt(libvirt.OpResume, libvirt.ViaResumeFirmwareMoveSourceOperator), func(f *Fake) error {
			return f.ResumeFirmwareMoveSourceForOperator(fgVM, fgUUID, fgAttempt)
		}},
		{"ResumePartitionPaused", StatePaused, libvirt.FirmwareCall{Op: libvirt.OpResume, Name: fgVM, UUID: fgUUID, Via: libvirt.ViaResumePartitionPaused}, func(f *Fake) error {
			return f.ResumePartitionPaused(fgVM, fgUUID)
		}},
		{"ResumeFirmwareMoveTarget", StatePaused, exempt(libvirt.OpResume, libvirt.ViaResumeFirmwareMoveTarget), func(f *Fake) error {
			return f.ResumeFirmwareMoveTarget(fgVM, fgUUID, fgAttempt)
		}},
		{"DiscardFirmwareMoveTarget", StatePaused, exempt(libvirt.OpStop, libvirt.ViaDiscardFirmwareMoveTarget), func(f *Fake) error {
			return f.DiscardFirmwareMoveTarget(fgVM, fgUUID, fgAttempt)
		}},
		{"UndefineFirmwareMoveLeftover", StateShutdown, exempt(libvirt.OpUndefine, libvirt.ViaUndefineFirmwareMoveLeftover), func(f *Fake) error {
			return f.UndefineFirmwareMoveLeftover(fgVM, fgUUID, fgAttempt)
		}},
		{"StopFirmwareMoveTargetForOperator", StateRunning, exempt(libvirt.OpStop, libvirt.ViaStopFirmwareMoveTargetForOperator), func(f *Fake) error {
			return f.StopFirmwareMoveTargetForOperator(fgVM, fgUUID, fgAttempt, true)
		}},
	}
	refused := errors.New("refused by the test guard")
	for _, p := range prims {
		t.Run(p.name, func(t *testing.T) {
			f := fgFake(t, p.st)
			before := len(f.EventLog())
			var got []libvirt.FirmwareCall
			f.SetFirmwareMoveGuard(libvirt.FirmwareMoveGuard{Check: func(c libvirt.FirmwareCall) error {
				got = append(got, c)
				return refused
			}})
			if err := p.run(f); !errors.Is(err, refused) {
				t.Fatalf("err = %v, want the guard's refusal", err)
			}
			if len(got) == 0 || got[0] != p.want {
				t.Fatalf("guard asked %+v, want first %+v", got, p.want)
			}
			if st, _ := f.RawState(fgVM); st != p.st {
				t.Fatalf("state %s after a refusal, want %s", st, p.st)
			}
			if ev := f.EventLog()[before:]; len(ev) != 0 {
				t.Fatalf("a refused call acted: %+v", ev)
			}
		})
	}
}

func fgGuard(recs ...libvirt.FirmwareMoveRecord) libvirt.FirmwareMoveGuard {
	return libvirt.NewFirmwareMoveGuard(func(name, uuid string) ([]libvirt.FirmwareMoveRecord, error) {
		var out []libvirt.FirmwareMoveRecord
		for _, r := range recs {
			if r.VM == name || (uuid != "" && strings.EqualFold(r.UUID, uuid)) {
				out = append(out, r)
			}
		}
		return out, nil
	})
}

func fgHold(state string) libvirt.FirmwareMoveRecord {
	return libvirt.FirmwareMoveRecord{Kind: libvirt.FirmwareHold, VM: fgVM, UUID: fgUUID, Attempt: fgAttempt, Peer: "node-1", State: state}
}

// The spec table through the fake, with the real rules: no record allows; a
// held target refuses start, stop and resume but takes its exempt resume and
// discard; released_unconfirmed lets a resume through and refuses a stop.
func TestFake_FirmwareMoveGuardTable(t *testing.T) {
	f := fgFake(t, StateDefined)
	f.SetFirmwareMoveGuard(fgGuard())
	if err := f.StartDomain(fgVM); err != nil {
		t.Fatalf("no record: %v", err)
	}

	f = fgFake(t, StatePaused)
	f.SetFirmwareMoveGuard(fgGuard(fgHold("resuming")))
	for name, run := range map[string]func() error{
		"start":   func() error { return f.StartDomain(fgVM) },
		"resume":  func() error { return f.ResumeDomain(fgVM) },
		"destroy": func() error { return f.DestroyDomain(fgVM) },
		"define":  func() error { return f.DefineDomain(fgXML) },
	} {
		if err := run(); !errors.Is(err, libvirt.ErrFirmwareMoveInFlight) {
			t.Errorf("%s under a resuming hold: %v", name, err)
		}
	}
	if st, _ := f.RawState(fgVM); st != StatePaused {
		t.Fatalf("held guest is %s", st)
	}
	if err := f.ResumeFirmwareMoveTarget(fgVM, fgUUID, "1d2e3f40-5a6b-4c7d-8e9f-0a1b2c3d4e5f"); err == nil {
		t.Fatal("another attempt's exempt resume went ahead")
	}
	if err := f.ResumeFirmwareMoveTarget(fgVM, fgUUID, fgAttempt); err != nil {
		t.Fatalf("exempt resume: %v", err)
	}
	if st, _ := f.RawState(fgVM); st != StateRunning {
		t.Fatalf("after the exempt resume: %s", st)
	}

	f = fgFake(t, StateRunning)
	f.SetFirmwareMoveGuard(fgGuard(fgHold("released_unconfirmed")))
	if err := f.ShutdownDomain(fgVM); !errors.Is(err, libvirt.ErrFirmwareMoveInFlight) {
		t.Fatalf("stop under released_unconfirmed: %v", err)
	}
	if err := f.SuspendDomain(fgVM); err != nil {
		t.Fatal(err)
	}
	if err := f.ResumeDomain(fgVM); err != nil {
		t.Fatalf("resume under released_unconfirmed: %v", err)
	}

	// Discard: a running held domain is refused, a paused one destroyed and
	// undefined keeping its state.
	f = fgFake(t, StateRunning)
	f.SetFirmwareMoveGuard(fgGuard(fgHold("verified")))
	if err := f.DiscardFirmwareMoveTarget(fgVM, fgUUID, fgAttempt); err == nil {
		t.Fatal("discard of a running domain went ahead")
	}
	f.SetState(fgVM, StatePaused)
	if err := f.DiscardFirmwareMoveTarget(fgVM, fgUUID, fgAttempt); err != nil {
		t.Fatal(err)
	}
	var ops []string
	for _, e := range f.EventLog() {
		ops = append(ops, e.Op+":"+e.Note)
	}
	if got := strings.Join(ops, ","); !strings.HasSuffix(got, "destroy:,undefine:keep_state=true") {
		t.Fatalf("events %s, want destroy then a state-keeping undefine", got)
	}
	if _, ok := f.RawState(fgVM); ok {
		t.Fatal("the discarded domain is still defined")
	}
}

// T-7 on the fake: the firmware move guard refuses a start before the NIC
// guard's readiness is consulted, with no wait.
//
// Mutation: ask the firmware guard after the readiness wait — red.
func TestFake_FirmwareMoveGuardBeforeNICGuardReadiness(t *testing.T) {
	f := fgFake(t, StateDefined)
	f.RequireStartGuard(time.Hour, nil)
	f.SetFirmwareMoveGuard(fgGuard(libvirt.FirmwareMoveRecord{Kind: libvirt.FirmwareMarker, VM: fgVM, UUID: fgUUID, Attempt: fgAttempt, Peer: "node-2", State: "migrating", PreCutover: true}))
	done := make(chan error, 1)
	go func() { done <- f.StartDomain(fgVM) }()
	select {
	case err := <-done:
		if !errors.Is(err, libvirt.ErrFirmwareMoveInFlight) {
			t.Fatalf("err = %v, want ErrFirmwareMoveInFlight", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the start waited for the NIC guard before asking the firmware move guard")
	}
}

// I-2 on the fake: the memory snapshot asks for the start AND the resume
// before it does anything; either refusal alone refuses it.
//
// Mutation: drop either op from the fake's check — red.
func TestFake_CreateLiveSnapshotAsksStartAndResume(t *testing.T) {
	for _, only := range []libvirt.FirmwareOp{libvirt.OpStart, libvirt.OpResume} {
		f := fgFake(t, StateRunning)
		before := len(f.EventLog())
		refused := errors.New("refused")
		f.SetFirmwareMoveGuard(libvirt.FirmwareMoveGuard{Check: func(c libvirt.FirmwareCall) error {
			if c.Op == only {
				return refused
			}
			return nil
		}})
		if _, _, err := f.CreateLiveSnapshot(fgVM, "s1", "/nonexistent", libvirt.CaptureOptions{}); !errors.Is(err, refused) {
			t.Fatalf("%s refused: err = %v", only, err)
		}
		if ev := f.EventLog()[before:]; len(ev) != 0 {
			t.Fatalf("%s refused, yet the snapshot acted: %+v", only, ev)
		}
	}
}
