package libvirt

import (
	"errors"
	"fmt"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

// detachModel is one device in one running domain, as virDomainDetachDeviceFlags
// sees it: present or not in the live instance and in the persistent definition.
//
// It models the libvirt semantics the lab finding (N1) turned on, from
// qemuDomainDetachDeviceLiveAndConfig:
//
//   - with VIR_DOMAIN_AFFECT_CONFIG the device must be in the persistent
//     definition, else VIR_ERR_DEVICE_MISSING;
//   - with VIR_DOMAIN_AFFECT_LIVE it must be in the live instance, else
//     VIR_ERR_DEVICE_MISSING;
//   - the call is all-or-nothing: a missing half fails the whole call and the
//     other half is not applied, so a LIVE|CONFIG retry against a device whose
//     persistent copy is already gone never re-issues the live unplug;
//   - the live half only REQUESTS the unplug; the guest decides when (or whether)
//     it leaves. guestHonors models a guest that has booted far enough to answer.
type detachModel struct {
	live, config bool
	guestHonors  bool
	calls        []uint32
	failWith     error // a non-DEVICE_MISSING failure for every call, when set
}

func deviceMissing(what string) error {
	return golibvirt.Error{Code: uint32(golibvirt.ErrDeviceMissing), Message: "device not found: " + what}
}

func (m *detachModel) detach(flags uint32) error {
	m.calls = append(m.calls, flags)
	if m.failWith != nil {
		return m.failWith
	}
	if flags&ModifyConfig != 0 && !m.config {
		return deviceMissing("not present in domain configuration")
	}
	if flags&ModifyLive != 0 && !m.live {
		return deviceMissing("not present in live domain")
	}
	if flags&ModifyConfig != 0 {
		m.config = false
	}
	if flags&ModifyLive != 0 && m.guestHonors {
		m.live = false
	}
	return nil
}

func flagName(f uint32) string {
	switch f {
	case ModifyLive | ModifyConfig:
		return "LIVE|CONFIG"
	case ModifyLive:
		return "LIVE"
	case ModifyConfig:
		return "CONFIG"
	}
	return fmt.Sprintf("0x%x", f)
}

// TestDetachLiveAndConfig_PersistentCopyAlreadyGone is N1 from the lab: the first
// LIVE|CONFIG detach removed the NIC from the persistent definition, but the guest
// was still booting and dropped the eject, so the live copy stayed. Every retry
// with LIVE|CONFIG then failed on the config half and never re-requested the live
// unplug, holding the VM's operation barrier for as long as anyone watched (>9
// minutes). A manual `virsh detach-interface --live` cleared it at once.
//
// A retry must re-issue the LIVE unplug.
func TestDetachLiveAndConfig_PersistentCopyAlreadyGone(t *testing.T) {
	m := &detachModel{live: true, config: false, guestHonors: true}
	if err := DetachLiveAndConfig(m.detach); err != nil {
		t.Fatalf("detach with only the live copy left: %v (calls %v)", err, names(m.calls))
	}
	if m.live {
		t.Fatalf("the live unplug was never re-requested (calls %v)", names(m.calls))
	}
}

// The mirror image: the live copy is gone (the guest answered) but the persistent
// definition still holds the device, which would come back on the next cold boot.
func TestDetachLiveAndConfig_LiveCopyAlreadyGone(t *testing.T) {
	m := &detachModel{live: false, config: true}
	if err := DetachLiveAndConfig(m.detach); err != nil {
		t.Fatalf("detach with only the persistent copy left: %v (calls %v)", err, names(m.calls))
	}
	if m.config {
		t.Fatalf("the persistent copy was never removed (calls %v)", names(m.calls))
	}
}

// A device in neither copy is a detach that is already done.
func TestDetachLiveAndConfig_AbsentFromBothIsDone(t *testing.T) {
	m := &detachModel{}
	if err := DetachLiveAndConfig(m.detach); err != nil {
		t.Fatalf("a device absent from both copies must read as detached: %v (calls %v)", err, names(m.calls))
	}
}

// The common case costs exactly one call, with both flags, as it always did.
func TestDetachLiveAndConfig_BothPresentIsOneCall(t *testing.T) {
	m := &detachModel{live: true, config: true, guestHonors: true}
	if err := DetachLiveAndConfig(m.detach); err != nil {
		t.Fatalf("detach: %v", err)
	}
	if len(m.calls) != 1 || m.calls[0] != ModifyLive|ModifyConfig {
		t.Fatalf("both copies present must be one LIVE|CONFIG call, got %v", names(m.calls))
	}
}

// Any failure that is not VIR_ERR_DEVICE_MISSING is a real fault, never a "done":
// the device may well still be in both copies.
func TestDetachLiveAndConfig_OtherErrorsAreNeverSuccess(t *testing.T) {
	for _, failWith := range []error{
		golibvirt.Error{Code: uint32(golibvirt.ErrOperationFailed), Message: "operation failed"},
		golibvirt.Error{Code: uint32(golibvirt.ErrOperationInvalid), Message: "domain is not running"},
		golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "Domain not found"},
		// The text of a DEVICE_MISSING without its code: untyped, so not trusted.
		errors.New("device not found: no target device vdb"),
	} {
		m := &detachModel{live: true, config: true, failWith: failWith}
		if err := DetachLiveAndConfig(m.detach); err == nil {
			t.Fatalf("%q reported as a successful detach (calls %v)", failWith, names(m.calls))
		}
	}
}

// The live half is retried, but only once the combined call has said a copy is
// missing; a different failure on that retry is still a failure.
func TestDetachLiveAndConfig_LiveRetryFailureIsReported(t *testing.T) {
	calls := 0
	err := DetachLiveAndConfig(func(flags uint32) error {
		calls++
		if flags == ModifyLive|ModifyConfig {
			return deviceMissing("not present in domain configuration")
		}
		if flags == ModifyLive {
			return golibvirt.Error{Code: uint32(golibvirt.ErrOperationFailed), Message: "unplug rejected"}
		}
		return deviceMissing("not present in domain configuration")
	})
	if err == nil {
		t.Fatalf("a live unplug libvirt rejected must not read as done (%d calls)", calls)
	}
}

// IsDeviceMissing is typed only, and survives the wrapping detachDeviceXML adds.
func TestIsDeviceMissing(t *testing.T) {
	wrapped := fmt.Errorf("detach device from vm1: %w", deviceMissing("x"))
	if !IsDeviceMissing(wrapped) {
		t.Fatal("a wrapped VIR_ERR_DEVICE_MISSING must classify")
	}
	if IsDeviceMissing(errors.New("device not found: x")) {
		t.Fatal("an untyped message must not classify")
	}
	if IsDeviceMissing(golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "device not found"}) {
		t.Fatal("another code must not classify")
	}
}

// The detach element is described from whichever copy still holds the device. A
// retry that finds the NIC only in the persistent definition must still send a
// valid element: the MAC-only shape has an empty <source> that libvirt rejects
// as XML before it ever matches the device, so the persistent copy would never
// be cleared.
func TestInterfaceForDetach_ReadsThePersistentCopyWhenLiveLacksIt(t *testing.T) {
	const mac = "52:54:00:aa:bb:cc"
	live := `<domain><devices></devices></domain>`
	persistent := `<domain><devices><interface type='bridge'><mac address='52:54:00:aa:bb:cc'/><source bridge='br7'/></interface></devices></domain>`
	got := interfaceForDetach(mac,
		func() (string, error) { return live, nil },
		func() (string, error) { return persistent, nil })
	if got.Type != "bridge" || got.Source.Bridge != "br7" {
		t.Fatalf("element = type %q source %+v, want the persistent copy's bridge br7", got.Type, got.Source)
	}

	// An unreadable live copy is skipped, not fatal.
	got = interfaceForDetach(mac,
		func() (string, error) { return "", errors.New("unreadable") },
		func() (string, error) { return persistent, nil })
	if got.Source.Bridge != "br7" {
		t.Fatalf("an unreadable live copy hid the persistent one: %+v", got.Source)
	}

	// The live copy wins when it holds the NIC.
	liveHas := `<domain><devices><interface type='direct'><mac address='52:54:00:aa:bb:cc'/><source dev='eth9' mode='bridge'/></interface></devices></domain>`
	got = interfaceForDetach(mac,
		func() (string, error) { return liveHas, nil },
		func() (string, error) { return persistent, nil })
	if got.Type != "direct" || got.Source.Dev != "eth9" {
		t.Fatalf("element = type %q source %+v, want the live copy's", got.Type, got.Source)
	}
}

func TestDiskForDetach_ReadsThePersistentCopyWhenLiveLacksIt(t *testing.T) {
	live := `<domain><devices></devices></domain>`
	persistent := `<domain><devices><disk type='block' device='disk'><source dev='/dev/vg/data'/><target dev='vdb' bus='virtio'/></disk></devices></domain>`
	got := diskForDetach("vdb",
		func() (string, error) { return live, nil },
		func() (string, error) { return persistent, nil })
	if got.Type != "block" || got.Source.Dev != "/dev/vg/data" {
		t.Fatalf("element = type %q source %+v, want the persistent copy's block source", got.Type, got.Source)
	}
}

func names(fs []uint32) []string {
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = flagName(f)
	}
	return out
}
