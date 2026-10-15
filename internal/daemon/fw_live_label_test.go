package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/libvirt"
)

func okInstalled() (libvirt.InstalledFirmwareCode, error) {
	return libvirt.InstalledFirmwareCode{Runtime: libvirt.FirmwareRuntime{
		Libvirt: "10.0.0", QEMU: "8.2.2", Swtpm: "0.7.3", Libtpms: "0.9.3",
	}}, nil
}

func okInputs() fwLiveInputs {
	return fwLiveInputs{
		enabled:    true,
		tpm:        func() bool { return true },
		secureBoot: func() bool { return true },
		installed:  func(context.Context) (libvirt.InstalledFirmwareCode, error) { return okInstalled() },
		guests:     func(context.Context) error { return nil },
	}
}

// Mutation: lower any one floor in fwLiveFloors (or compare the versions as
// strings) and the matching row goes red.
func TestFwLiveMigrateLabel_Floors(t *testing.T) {
	if !fwLiveMigrateCapable(context.Background(), okInputs()) {
		t.Fatal("a host exactly at every floor is not capable")
	}
	cases := []struct {
		name string
		set  func(r *libvirt.FirmwareRuntime)
		want bool
	}{
		{"libvirt 9.10.0 (below, numeric)", func(r *libvirt.FirmwareRuntime) { r.Libvirt = "9.10.0" }, false},
		{"libvirt 9.99.99", func(r *libvirt.FirmwareRuntime) { r.Libvirt = "9.99.99" }, false},
		{"libvirt 10.0.1", func(r *libvirt.FirmwareRuntime) { r.Libvirt = "10.0.1" }, true},
		{"libvirt 10.10.0 (numeric above a string)", func(r *libvirt.FirmwareRuntime) { r.Libvirt = "10.10.0" }, true},
		{"qemu 8.2.1", func(r *libvirt.FirmwareRuntime) { r.QEMU = "8.2.1" }, false},
		{"qemu 8.1.9", func(r *libvirt.FirmwareRuntime) { r.QEMU = "8.1.9" }, false},
		{"qemu 8.2.10", func(r *libvirt.FirmwareRuntime) { r.QEMU = "8.2.10" }, true},
		{"qemu 9.0.0", func(r *libvirt.FirmwareRuntime) { r.QEMU = "9.0.0" }, true},
		{"swtpm 0.7.2", func(r *libvirt.FirmwareRuntime) { r.Swtpm = "0.7.2" }, false},
		{"swtpm 0.6.9", func(r *libvirt.FirmwareRuntime) { r.Swtpm = "0.6.9" }, false},
		{"swtpm 0.10.0", func(r *libvirt.FirmwareRuntime) { r.Swtpm = "0.10.0" }, true},
		{"libtpms 0.9.2", func(r *libvirt.FirmwareRuntime) { r.Libtpms = "0.9.2" }, false},
		{"libtpms 0.8.9", func(r *libvirt.FirmwareRuntime) { r.Libtpms = "0.8.9" }, false},
		{"libtpms 0.10.0", func(r *libvirt.FirmwareRuntime) { r.Libtpms = "0.10.0" }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			in := okInputs()
			in.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
				v, _ := okInstalled()
				c.set(&v.Runtime)
				return v, nil
			}
			if got := fwLiveMigrateCapable(context.Background(), in); got != c.want {
				t.Fatalf("capable = %v, want %v", got, c.want)
			}
		})
	}

	// The probes each count: a host without vTPM or Secure Boot is not capable.
	for name, set := range map[string]func(*fwLiveInputs){
		"tpm probe false":        func(i *fwLiveInputs) { i.tpm = func() bool { return false } },
		"secureboot probe false": func(i *fwLiveInputs) { i.secureBoot = func() bool { return false } },
	} {
		in := okInputs()
		set(&in)
		if fwLiveMigrateCapable(context.Background(), in) {
			t.Errorf("%s: capable", name)
		}
	}
}

// Mutation: drop the enabled test and the off row goes red.
func TestFwLiveMigrateLabel_ConfigOff(t *testing.T) {
	in := okInputs()
	in.enabled = false
	if fwLiveMigrateCapable(context.Background(), in) {
		t.Fatal("capable with migration.live_firmware off")
	}
}

// Mutation: treat an installed-code error as a pass (or fill zero versions)
// and every row goes red.
func TestFwLiveMigrateLabel_UnreadableVersion(t *testing.T) {
	in := okInputs()
	in.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
		v, _ := okInstalled() // good versions beside the error: the error alone refuses
		return v, errors.New("swtpm: not found")
	}
	if fwLiveMigrateCapable(context.Background(), in) {
		t.Fatal("capable although a version cannot be read")
	}
	for _, bad := range []string{"", "garbage", "10.0", "10.0.x"} {
		in := okInputs()
		in.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
			v, _ := okInstalled()
			v.Runtime.QEMU = bad
			return v, nil
		}
		if fwLiveMigrateCapable(context.Background(), in) {
			t.Errorf("capable with qemu version %q", bad)
		}
	}
}

// Mutation: ignore the libvirt-guests check in fwLiveMigrateCapable and the
// refusal row goes red; make the D-9 check itself pass on an error and the
// TestLibvirtGuests rows go red.
func TestFwLiveMigrateLabel_LibvirtGuests(t *testing.T) {
	in := okInputs()
	in.guests = func(context.Context) error { return errors.New("libvirt-guests saves guests") }
	if fwLiveMigrateCapable(context.Background(), in) {
		t.Fatal("capable although libvirt-guests saves or restores guests")
	}
}

// The label rides the capability list the daemon publishes.
//
// Mutation: remove the fw_live_migrate entry from daemon.go's list — red.
func TestFwLiveMigrateLabel_InDaemonList(t *testing.T) {
	src, err := os.ReadFile("daemon.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "key: corrosion.LabelFwLiveMigrate") {
		t.Fatal("daemon.go's capability label list has no litevirt.fw_live_migrate entry")
	}
}

func TestFwLiveMigrateLabel_ConfigDefaultsOn(t *testing.T) {
	var m MigrationConfig
	if !m.LiveFirmwareEnabled() {
		t.Error("migration.live_firmware is off by default")
	}
	f := false
	m.LiveFirmware = &f
	if m.LiveFirmwareEnabled() {
		t.Error("an explicit false is ignored")
	}
}
