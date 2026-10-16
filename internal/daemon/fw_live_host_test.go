package daemon

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

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
		}, "libtpms 0.9.2 is below the live firmware migration floor 0.9.3"},
		{"libvirt-guests", MigrationConfig{}, func(h *fwLiveHost) {
			h.guests = func(context.Context) error { return errors.New("ON_SHUTDOWN=suspend") }
		}, "libvirt-guests: ON_SHUTDOWN=suspend"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := okHost()
			c.set(&h)
			code, err := fwLiveHostCheck{cfg: c.cfg, h: h}.Check(context.Background())
			rt := code.Runtime
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
	check := fwLiveHostCheck{cfg: MigrationConfig{}, h: h}
	for i := 0; i < 3; i++ {
		if _, err := check.Check(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if calls != 3 {
		t.Fatalf("libvirt-guests read %d times in 3 checks", calls)
	}
}

// The production probes behind the label and the host check read
// libvirt-guests with CheckLibvirtGuests, and the installed and running code
// from one probe.
//
// Mutations: hand newFwLiveHost another guests check, or leave running unset
// — red.
func TestNewFwLiveHost_ReadsLibvirtGuests(t *testing.T) {
	h := newFwLiveHost(libvirt.NewFirmwareStore(t.TempDir()), libvirt.FirmwarePaths{},
		func() (uint64, error) { return 10000000, nil }, func() bool { return true })
	if reflect.ValueOf(h.guests).Pointer() != reflect.ValueOf(CheckLibvirtGuests).Pointer() {
		t.Fatal("newFwLiveHost does not read libvirt-guests with CheckLibvirtGuests")
	}
	if h.installed == nil || h.running == nil {
		t.Fatal("newFwLiveHost has no installed or running code probe")
	}
}

// RunningFirmwareCode is the probe's, given the live XML, under a deadline
// of fwLiveProbeTimeout; its error is passed on.
//
// Mutations: call it without the deadline, or drop the XML — red.
func TestFwLiveHostCheck_RunningFirmwareCodeBounded(t *testing.T) {
	h := okHost()
	var gotXML string
	var deadline time.Time
	var hasDeadline bool
	h.running = func(ctx context.Context, x string) (libvirt.FirmwareRuntime, error) {
		gotXML = x
		deadline, hasDeadline = ctx.Deadline()
		return libvirt.FirmwareRuntime{QEMU: "8.2.2"}, nil
	}
	start := time.Now()
	rt, err := fwLiveHostCheck{h: h}.RunningFirmwareCode(context.Background(), "<domain/>")
	if err != nil || rt.QEMU != "8.2.2" || gotXML != "<domain/>" {
		t.Fatalf("running = %+v, %v (xml %q)", rt, err, gotXML)
	}
	if !hasDeadline || deadline.Sub(start) > fwLiveProbeTimeout+time.Second {
		t.Fatalf("running code read without the %s bound (deadline %v, set %v)", fwLiveProbeTimeout, deadline.Sub(start), hasDeadline)
	}
	h.running = func(context.Context, string) (libvirt.FirmwareRuntime, error) {
		return libvirt.FirmwareRuntime{}, errors.New("qemu exe (deleted)")
	}
	if _, err := (fwLiveHostCheck{h: h}).RunningFirmwareCode(context.Background(), "<domain/>"); err == nil || !strings.Contains(err.Error(), "deleted") {
		t.Fatalf("running error = %v", err)
	}
}

// Check runs under a deadline of fwLiveProbeTimeout.
//
// Mutation: drop the deadline from Check — red.
func TestFwLiveHostCheck_CheckBounded(t *testing.T) {
	h := okHost()
	var hasDeadline bool
	h.installed = func(ctx context.Context) (libvirt.InstalledFirmwareCode, error) {
		_, hasDeadline = ctx.Deadline()
		return okInstalled()
	}
	if _, err := (fwLiveHostCheck{h: h}).Check(context.Background()); err != nil || !hasDeadline {
		t.Fatalf("check = %v, deadline set %v", err, hasDeadline)
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
