package libvirt

import (
	"strings"
	"testing"
)

// TestFirmwareFloorsMet pins the installed-version floors of a live firmware
// move (spec §3.1): each floor itself passes, one release below it refuses
// naming the component, and a version that is not X.Y.Z refuses. The daemon's
// label and grpcapi's stage A both read these floors.
//
// Mutation: lower any one floor, compare the versions as strings, or treat an
// unparsable version as met — red.
func TestFirmwareFloorsMet(t *testing.T) {
	floor := FirmwareRuntime{Libvirt: "10.0.0", QEMU: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3"}
	if LiveFirmwareFloors != floor {
		t.Fatalf("LiveFirmwareFloors = %+v, want %+v", LiveFirmwareFloors, floor)
	}
	if err := FirmwareFloorsMet(floor); err != nil {
		t.Fatalf("the floors themselves: %v", err)
	}
	newer := FirmwareRuntime{Libvirt: "10.10.0", QEMU: "9.0.0", Swtpm: "0.10.0", Libtpms: "0.10.1"}
	if err := FirmwareFloorsMet(newer); err != nil {
		t.Fatalf("newer releases (numeric, not string, order): %v", err)
	}
	for _, c := range []struct {
		name string
		mut  func(*FirmwareRuntime)
		want string
	}{
		{"libvirt", func(r *FirmwareRuntime) { r.Libvirt = "9.10.0" }, "libvirt 9.10.0"},
		{"qemu", func(r *FirmwareRuntime) { r.QEMU = "8.2.1" }, "qemu 8.2.1"},
		{"swtpm", func(r *FirmwareRuntime) { r.Swtpm = "0.7.2" }, "swtpm 0.7.2"},
		{"libtpms", func(r *FirmwareRuntime) { r.Libtpms = "0.9.2" }, "libtpms 0.9.2"},
		{"empty", func(r *FirmwareRuntime) { r.QEMU = "" }, `qemu "" is not an X.Y.Z release`},
		{"not_xyz", func(r *FirmwareRuntime) { r.Swtpm = "0.7" }, `swtpm "0.7" is not an X.Y.Z release`},
		{"garbage", func(r *FirmwareRuntime) { r.Libtpms = "0.9.x" }, `libtpms "0.9.x" is not an X.Y.Z release`},
	} {
		t.Run(c.name, func(t *testing.T) {
			rt := floor
			c.mut(&rt)
			err := FirmwareFloorsMet(rt)
			if err == nil {
				t.Fatalf("%+v met the floors", rt)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error %q does not name %q", err, c.want)
			}
		})
	}
}
