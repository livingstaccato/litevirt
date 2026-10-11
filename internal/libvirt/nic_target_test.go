package libvirt

import (
	"errors"
	"strings"
	"testing"
	"time"

	golibvirt "github.com/digitalocean/go-libvirt"

	"github.com/litevirt/litevirt/internal/nictap"
)

// TestGenerateDomainXML_NICTapNamedByMAC (re-review I-10): a bridged NIC's
// tap is named in the domain XML after its MAC, so the per-NIC firewall —
// guard included — can be in force for it before the domain first runs, on
// this host and on any host it migrates to. A macvtap NIC has no tap.
func TestGenerateDomainXML_NICTapNamedByMAC(t *testing.T) {
	x, err := GenerateDomainXML(VMConfig{Name: "web", CPU: 1, MemoryMiB: 256, Networks: []NetworkConfig{
		{Bridge: "br0", MAC: "52:54:00:aa:bb:cc"},
		{Direct: "eno1", MAC: "52:54:00:aa:bb:cd"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(x, `<target dev="`+nictap.Name("52:54:00:aa:bb:cc")+`"></target>`) {
		t.Errorf("the bridged NIC's tap is not named by its MAC:\n%s", x)
	}
	if strings.Contains(x, nictap.Name("52:54:00:aa:bb:cd")) {
		t.Errorf("a macvtap NIC was given a tap name:\n%s", x)
	}
	frag, err := marshalNewNIC("", WantNIC{Bridge: "br0", MAC: "52:54:00:aa:bb:ce"})
	if err != nil || !strings.Contains(frag, nictap.Name("52:54:00:aa:bb:ce")) {
		t.Errorf("a NIC added to a stopped domain's definition is not named by its MAC: %q, %v", frag, err)
	}
	if f := bridgeInterface("br0", "", "52:54:00:aa:bb:cf"); f.Target == nil || f.Target.Dev != nictap.Name("52:54:00:aa:bb:cf") {
		t.Errorf("a hot-attached NIC is not named by its MAC: %+v", f)
	}
}

// TestStartDomain_GuardRefuses: a domain whose NIC firewall cannot be put in
// force first is not started (the guard fails closed for guarded VMs).
func TestStartDomain_GuardRefuses(t *testing.T) {
	c := &Client{}
	called := ""
	c.SetStartGuard(StartGuard{Before: func(name string) (bool, error) { called = name; return false, errors.New("guards not applied") }})
	if err := c.StartDomain("web"); err == nil || called != "web" || !strings.Contains(err.Error(), "guards not applied") {
		t.Fatalf("StartDomain = %v (guard saw %q); want the guard's refusal before libvirt is asked", err, called)
	}
}

// TestStartDomain_WaitsForARequiredGuard (re-review R2-I2): after a host
// boots, the daemon's onboot, self-heal and restart-policy starts may run
// before the firewall is wired. A client that requires a guard holds every
// start until one is set — and refuses, rather than starting unguarded, if
// none is set in time.
func TestStartDomain_WaitsForARequiredGuard(t *testing.T) {
	c := &Client{}
	c.RequireStartGuard(5*time.Second, nil)
	done := make(chan error, 1)
	go func() { done <- c.StartDomain("web") }()
	select {
	case err := <-done:
		t.Fatalf("a start ran before any guard was set: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	seen := make(chan string, 1)
	c.SetStartGuard(StartGuard{Before: func(name string) (bool, error) { seen <- name; return false, errors.New("stop here") }})
	select {
	case err := <-done:
		if !strings.Contains(err.Error(), "stop here") || <-seen != "web" {
			t.Fatalf("the held start did not go through the guard: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the held start never resumed once the guard was set")
	}

	late := &Client{}
	late.RequireStartGuard(50*time.Millisecond, nil)
	if err := late.StartDomain("web"); err == nil || !strings.Contains(err.Error(), "not ready") {
		t.Fatalf("a start with no guard set in time = %v; want a refusal", err)
	}
}

// TestSnapshotRevert_GoesThroughTheGuard (re-review m5): a snapshot revert
// starts the domain, and a live-snapshot restore resumes it: both put its NIC
// firewall in force first — a restore while it is paused, under the taps it
// actually has — and neither runs a guarded domain the guard refused.
func TestSnapshotRevert_GoesThroughTheGuard(t *testing.T) {
	refuse := StartGuard{Before: func(string) (bool, error) { return false, errors.New("guards not in force") }}
	t.Run("disk", func(t *testing.T) {
		m := newLibvirt10(t)
		m.write(markA, 1)
		m.snapshot("m1")
		if err := revertToSnapshot(m, "vm", "m1", nil, refuse); err == nil || !strings.Contains(err.Error(), "guards not in force") {
			t.Fatalf("revert with a refusing guard = %v", err)
		}
		if m.state() == golibvirt.DomainRunning {
			t.Fatal("the domain runs although its guard refused")
		}
	})
	t.Run("memory", func(t *testing.T) {
		m := newLibvirt10(t)
		m.write(markA, 1)
		save := m.memorySnapshot("m1")
		var stateWhileArmed golibvirt.DomainState
		g := StartGuard{
			Before:      func(string) (bool, error) { return true, nil },
			AfterPaused: func(string) error { stateWhileArmed = m.state(); return nil },
		}
		if err := revertToLiveSnapshot(m, "vm", "m1", save, nil, nil, g); err != nil {
			t.Fatalf("revert with an arming guard: %v", err)
		}
		if stateWhileArmed != golibvirt.DomainPaused || m.state() != golibvirt.DomainRunning {
			t.Fatalf("armed in state %v, now %v; want armed while paused, then running", stateWhileArmed, m.state())
		}
		bad := StartGuard{Before: func(string) (bool, error) { return true, nil }, AfterPaused: func(string) error { return errors.New("no") }}
		if err := revertToLiveSnapshot(m, "vm", "m1", save, nil, nil, bad); err == nil {
			t.Fatal("a restore whose guard failed while paused succeeded")
		}
		if m.state() == golibvirt.DomainRunning {
			t.Fatal("the restored domain runs although its guard failed")
		}
	})
}
