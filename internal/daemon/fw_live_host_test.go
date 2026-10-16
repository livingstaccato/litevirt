package daemon

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/litevirt/litevirt/internal/libvirt"
)

// The Prepare check of a live firmware move's target (spec §6.2 item 1): the
// label's conditions, read now, with the first that fails named, and the
// installed runtime when every one holds.
//
// Mutations: drop any one condition — its row passes, red; return a zero
// runtime — the all-true row goes red.
func TestFwLiveHostCheck_Reasons(t *testing.T) {
	off := false
	cases := []struct {
		name string
		cfg  MigrationConfig
		set  func(*fwLiveHost)
		want string // "" = passes
	}{
		{"all preconditions", MigrationConfig{}, func(*fwLiveHost) {}, ""},
		{"config off", MigrationConfig{LiveFirmware: &off}, func(*fwLiveHost) {}, "migration.live_firmware is off"},
		{"tpm missing", MigrationConfig{}, func(h *fwLiveHost) { h.tpm = func() bool { return false } }, "vTPM"},
		{"secure boot missing", MigrationConfig{}, func(h *fwLiveHost) { h.secureBoot = func() bool { return false } }, "Secure Boot"},
		{"installed unreadable", MigrationConfig{}, func(h *fwLiveHost) {
			h.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
				return libvirt.InstalledFirmwareCode{}, errors.New("swtpm: not found")
			}
		}, "swtpm: not found"},
		{"below a floor", MigrationConfig{}, func(h *fwLiveHost) {
			h.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
				v, _ := okInstalled()
				v.Runtime.Libtpms = "0.9.2"
				return v, nil
			}
		}, `libtpms "0.9.2" is below the floor 0.9.3`},
		{"libvirt-guests", MigrationConfig{}, func(h *fwLiveHost) {
			h.guests = func(context.Context) error { return errors.New("ON_SHUTDOWN=suspend") }
		}, "libvirt-guests: ON_SHUTDOWN=suspend"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := okHost()
			c.set(&h)
			rt, err := fwLiveHostCheck(c.cfg, h)(context.Background())
			if c.want == "" {
				want, _ := okInstalled()
				if err != nil || rt != want.Runtime {
					t.Fatalf("check = %+v, %v", rt, err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || rt != (libvirt.FirmwareRuntime{}) {
				t.Fatalf("check = %+v, %v; want an error naming %q", rt, err, c.want)
			}
		})
	}
}

// D-9 is read live on every Prepare, never from a cached answer or the label.
//
// Mutation: read libvirt-guests once and reuse it — red.
func TestFwLiveHostCheck_LibvirtGuestsReadEachTime(t *testing.T) {
	h := okHost()
	calls := 0
	h.guests = func(context.Context) error { calls++; return nil }
	check := fwLiveHostCheck(MigrationConfig{}, h)
	for i := 0; i < 3; i++ {
		if _, err := check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Fatalf("libvirt-guests read %d times in 3 checks", calls)
	}
}

// The production probes behind the label and the Prepare check read
// libvirt-guests with CheckLibvirtGuests.
//
// Mutation: hand newFwLiveHost another guests check — red.
func TestNewFwLiveHost_ReadsLibvirtGuests(t *testing.T) {
	h := newFwLiveHost(libvirt.NewFirmwareStore(t.TempDir()), libvirt.FirmwarePaths{},
		func() (uint64, error) { return 10000000, nil }, func() bool { return true })
	if reflect.ValueOf(h.guests).Pointer() != reflect.ValueOf(CheckLibvirtGuests).Pointer() {
		t.Fatal("newFwLiveHost does not read libvirt-guests with CheckLibvirtGuests")
	}
}

// The daemon installs the Prepare check, from its own config, and starts the
// hold sweep (comments do not count).
//
// Mutation: remove or comment out either line in daemon.go — red.
func TestFwLiveTarget_WiredInDaemon(t *testing.T) {
	src, err := os.ReadFile("daemon.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"svc.SetLiveFirmwareHost(newFwLiveHostCheck(d.cfg.Migration,",
		"go svc.RunFirmwareHoldSweep(ctx)",
	} {
		found := false
		for _, l := range strings.Split(string(src), "\n") {
			if t := strings.TrimSpace(l); !strings.HasPrefix(t, "//") && strings.Contains(t, want) {
				found = true
			}
		}
		if !found {
			t.Errorf("daemon.go does not call %s", want)
		}
	}
}
