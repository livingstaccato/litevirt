package libvirtfake

import (
	"testing"

	"github.com/litevirt/litevirt/internal/libvirt"
)

const flagsNIC = "52:54:00:aa:bb:cc"

const flagsDomainXML = `<domain type='kvm'><name>vm1</name><devices>` +
	`<interface type='bridge'><source bridge='br0'/><mac address='52:54:00:aa:bb:cc'/></interface>` +
	`</devices></domain>`

func nicIn(t *testing.T, f *Fake) (live, config bool) {
	t.Helper()
	lx, err := f.DumpXML("vm1")
	if err != nil {
		t.Fatal(err)
	}
	cx, err := f.DumpXMLInactive("vm1")
	if err != nil {
		t.Fatal(err)
	}
	return nicMacInDomainXML(lx, flagsNIC), nicMacInDomainXML(cx, flagsNIC)
}

// One virDomainDetachDeviceFlags call with LIVE|CONFIG is all-or-nothing: a copy
// that lacks the device fails it with VIR_ERR_DEVICE_MISSING and the other copy
// is left as it was. The fake used to succeed on every detach, which hid lab
// finding N1 from every in-process test.
func TestDetachFlags_LiveAndConfigIsAllOrNothing(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	f.SetInactiveXML("vm1", `<domain type='kvm'><name>vm1</name><devices></devices></domain>`)
	f.SetActiveXML("vm1", flagsDomainXML)

	f.mu.Lock()
	err := f.detachFlagsLocked("vm1", libvirt.ModifyLive|libvirt.ModifyConfig, false,
		true, false, "live", "config",
		func() { f.activeXML["vm1"] = removeNICFromDomainXML(f.activeBaseline("vm1"), flagsNIC) },
		func() { f.xml["vm1"] = removeNICFromDomainXML(f.xml["vm1"], flagsNIC) })
	f.mu.Unlock()
	if !libvirt.IsDeviceMissing(err) {
		t.Fatalf("LIVE|CONFIG with the persistent copy gone: err = %v, want VIR_ERR_DEVICE_MISSING", err)
	}
	if live, _ := nicIn(t, f); !live {
		t.Fatal("a failed LIVE|CONFIG call must not apply its live half")
	}

	// The public DetachNIC goes through libvirt.DetachLiveAndConfig and so
	// reaches the live copy anyway.
	if err := f.DetachNIC("vm1", flagsNIC); err != nil {
		t.Fatalf("DetachNIC with only the live copy left: %v", err)
	}
	if live, config := nicIn(t, f); live || config {
		t.Fatalf("after DetachNIC: live=%v config=%v, want neither", live, config)
	}
}

// A deferred (unacknowledged) unplug on a domain whose live view the fake was
// still reading from the persistent one: the config half removes the NIC from
// the persistent copy at once, and the live copy must keep it until the guest
// answers. Without pinning the live view first, the persistent change leaked
// into it and the unplug looked instant.
func TestDetachFlags_DeferredUnplugKeepsTheLiveCopy(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	f.SetInactiveXML("vm1", flagsDomainXML) // no live override: live mirrors it
	f.DeferLiveUnplug = true

	if err := f.DetachNIC("vm1", flagsNIC); err != nil {
		t.Fatalf("DetachNIC: %v", err)
	}
	live, config := nicIn(t, f)
	if config {
		t.Fatal("the persistent copy must go at once")
	}
	if !live {
		t.Fatal("the live copy must stay until the guest acknowledges the unplug")
	}
	f.AckLiveUnplug("vm1")
	if live, _ := nicIn(t, f); live {
		t.Fatal("the acknowledged unplug must remove the live copy")
	}
}

// Absent from both copies reads as detached, as it did before the fake modeled
// the flags (and as libvirt.DetachLiveAndConfig reports it).
func TestDetachFlags_AbsentFromBothIsNotAnError(t *testing.T) {
	f := New()
	f.SetState("vm1", StateRunning)
	if err := f.DetachNIC("vm1", flagsNIC); err != nil {
		t.Fatalf("NIC: %v", err)
	}
	if err := f.DetachDisk("vm1", "vdz"); err != nil {
		t.Fatalf("disk: %v", err)
	}
	if err := f.DetachHostdev("vm1", "0000:99:00.0"); err != nil {
		t.Fatalf("hostdev: %v", err)
	}
}
