package libvirt

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	golibvirt "github.com/digitalocean/go-libvirt"
)

func domWithDevices(devices string) string {
	return `<domain type='kvm'><name>vm</name><devices>` + devices + `</devices></domain>`
}

const pciHostdev = `<hostdev mode='subsystem' type='pci' managed='yes'><source><address domain='0x0000' bus='0x41' slot='0x00' function='0x0'/></source></hostdev>`

func TestMemorySnapshotBlockers(t *testing.T) {
	for _, tc := range []struct {
		name    string
		devices string
		want    []string
	}{
		{"none", `<disk type='file' device='disk'><target dev='vda'/></disk>`, nil},
		{"pci", pciHostdev, []string{"pci 0000:41:00.0"}},
		// libvirt saves a domain with a USB hostdev (qemuMigrationSrcIsAllowedHostdev).
		{"usb", `<hostdev mode='subsystem' type='usb'><source><vendor id='0x1234'/><product id='0x5678'/></source></hostdev>`, nil},
		{"mdev", `<hostdev mode='subsystem' type='mdev' model='vfio-pci'><source><address uuid='c2177883-f1bb-47f0-914d-32a22e3a8804'/></source></hostdev>`, []string{"mdev"}},
		{"interface", `<interface type='hostdev' managed='yes'><mac address='52:54:00:6d:90:02'/><source><address type='pci' domain='0x0000' bus='0x03' slot='0x10' function='0x1'/></source></interface>`, []string{"interface hostdev 52:54:00:6d:90:02"}},
		{"bridge", `<interface type='bridge'><mac address='52:54:00:6d:90:03'/></interface>`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := MemorySnapshotBlockers(domWithDevices(tc.devices))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("MemorySnapshotBlockers = %q, want %q", got, tc.want)
			}
		})
	}
	if _, err := MemorySnapshotBlockers("<domain"); err == nil {
		t.Fatal("an unparseable definition was read as one with no passthrough devices")
	}
}

// preflightAPI answers the three calls the preflight makes; any other call
// panics on the nil embedded interface, so a preflight that suspended or
// snapshotted anything would fail this test.
type preflightAPI struct {
	snapshotAPI
	state  golibvirt.DomainState
	xml    string
	xmlErr error
}

func (p *preflightAPI) DomainLookupByName(string) (golibvirt.Domain, error) {
	return golibvirt.Domain{Name: "vm"}, nil
}
func (p *preflightAPI) DomainGetState(golibvirt.Domain, uint32) (int32, int32, error) {
	return int32(p.state), 0, nil
}
func (p *preflightAPI) DomainGetXMLDesc(golibvirt.Domain, golibvirt.DomainXMLFlags) (string, error) {
	return p.xml, p.xmlErr
}

// The memory snapshot's checks run before the freeze: a domain holding a
// device whose state cannot be saved is refused with a PassthroughSnapshotError,
// and one whose live definition cannot be read is refused too (it cannot be
// judged). A running domain with no such device passes.
//
// Mutation: drop the blocker check from liveSnapshotPreflight — red.
func TestLiveSnapshotPreflight_RefusesPassthrough(t *testing.T) {
	api := &preflightAPI{state: golibvirt.DomainRunning, xml: domWithDevices(pciHostdev)}
	_, err := liveSnapshotPreflight(api, "vm")
	var pe *PassthroughSnapshotError
	if !errors.As(err, &pe) {
		t.Fatalf("preflight of a PCI passthrough domain = %v, want a PassthroughSnapshotError", err)
	}
	if !reflect.DeepEqual(pe.Devices, []string{"pci 0000:41:00.0"}) || !strings.Contains(err.Error(), "0000:41:00.0") {
		t.Errorf("refusal %v does not name the device", err)
	}

	api.xml, api.xmlErr = "", errors.New("connection reset")
	if _, err := liveSnapshotPreflight(api, "vm"); err == nil || errors.As(err, &pe) {
		t.Errorf("preflight with an unreadable definition = %v, want a refusal that is not the passthrough one", err)
	}

	api.xml, api.xmlErr = domWithDevices(""), nil
	if _, err := liveSnapshotPreflight(api, "vm"); err != nil {
		t.Errorf("preflight of a device-less running domain: %v", err)
	}
	api.state = golibvirt.DomainPaused
	if _, err := liveSnapshotPreflight(api, "vm"); err == nil {
		t.Error("preflight of a paused domain passed")
	}
}
