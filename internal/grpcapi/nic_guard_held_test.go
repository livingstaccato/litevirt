package grpcapi

import (
	"context"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// TestResumeHeldGuests_OnlyWhatThisHostHoldsForItsGuards (re-review R3-I2):
// the target lets a guest run only when it holds it paused for its guards —
// owned here, paused here, its record on this host's disk — and leaves a guest
// partition pause also holds to its pauser. A record for a guest that never
// arrived is kept while a move may still be running, and dropped after.
func TestResumeHeldGuests_OnlyWhatThisHostHoldsForItsGuards(t *testing.T) {
	ctx := context.Background()
	s := guardServer(t, true)
	s.dataDir = t.TempDir()
	virt := libvirtfake.New()
	s.virt = virt
	for _, vm := range []struct{ name, host string }{{"held", s.hostName}, {"split", s.hostName}, {"elsewhere", "other"}, {"gone", "other"}} {
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: vm.name, HostName: vm.host, State: "running",
			Spec: `{"name":"` + vm.name + `","uuid":"u-` + vm.name + `"}`}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"held", "split"} {
		virt.SetInactiveXML(name, `<domain type='kvm'><name>`+name+`</name></domain>`)
		virt.SetState(name, libvirtfake.StatePaused)
	}
	old := time.Now().Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	now := time.Now().UTC().Format(time.RFC3339)
	for _, g := range []heldGuest{
		{VM: "held", UUID: "u-held", Since: now},
		{VM: "split", UUID: "u-split", Since: now},
		{VM: "elsewhere", UUID: "u-elsewhere", Since: now},
		{VM: "gone", UUID: "u-gone", Since: old},
	} {
		if err := s.putHeld(g); err != nil {
			t.Fatal(err)
		}
	}
	if err := health.WritePauseRecordForTests(s.dataDir, health.PauseRecord{Kind: health.PauseKindVM, Name: "split",
		Host: s.hostName, Reason: "partition"}); err != nil {
		t.Fatal(err)
	}

	s.ResumeHeldGuestsOnce(ctx)

	if st, _ := virt.RawState("held"); st != libvirtfake.StateRunning {
		t.Errorf("the guest held for its guards is %s, want running", st)
	}
	if st, _ := virt.RawState("split"); st != libvirtfake.StatePaused {
		t.Errorf("a guest partition pause also holds was resumed: %s", st)
	}
	got := map[string]bool{}
	for _, vm := range s.HeldGuestsForTests() {
		got[vm] = true
	}
	if got["held"] {
		t.Error("the resumed guest's record outlived it")
	}
	if !got["elsewhere"] {
		t.Error("the record of a guest whose move may still run was dropped")
	}
	if got["gone"] {
		t.Error("the record of a guest that never arrived outlived heldStaleAfter")
	}
}
