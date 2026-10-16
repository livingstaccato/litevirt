package daemon

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

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

// Mutation: lower any one floor in libvirt.LiveFirmwareFloors (or compare the versions as
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

// The label rides the capability list the daemon publishes, built by
// newFwLiveLabel from the daemon's own config (comments do not count).
//
// Mutation: remove or comment out the entry in daemon.go's list, or hand it
// another config - red.
func TestFwLiveMigrateLabel_InDaemonList(t *testing.T) {
	src, err := os.ReadFile("daemon.go")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, l := range strings.Split(string(src), "\n") {
		if t := strings.TrimSpace(l); !strings.HasPrefix(t, "//") &&
			strings.Contains(t, "key: corrosion.LabelFwLiveMigrate, capable: newFwLiveLabel(d.cfg.Migration,") {
			found = true
		}
	}
	if !found {
		t.Fatal("daemon.go's capability label list has no litevirt.fw_live_migrate entry built by newFwLiveLabel(d.cfg.Migration, ...)")
	}
}

func okHost() fwLiveHost {
	return fwLiveHost{
		tpm:        func() bool { return true },
		secureBoot: func() bool { return true },
		installed:  func(context.Context) (libvirt.InstalledFirmwareCode, error) { return okInstalled() },
		guests:     func(context.Context) error { return nil },
	}
}

// The label probe as the daemon builds it: each precondition alone makes it
// false, and all of them make it true.
//
// Mutations: hardcode enabled true - the config-off row goes red; hardcode the
// probe's result true - every false row goes red; hardcode it false - the
// all-true row goes red; swap tpm and secureBoot - the two missing rows go red.
func TestFwLiveLabelProbe(t *testing.T) {
	off := false
	cases := []struct {
		name string
		cfg  MigrationConfig
		set  func(*fwLiveHost)
		want bool
	}{
		{"all preconditions", MigrationConfig{}, func(*fwLiveHost) {}, true},
		{"config on explicitly", MigrationConfig{LiveFirmware: func() *bool { b := true; return &b }()}, func(*fwLiveHost) {}, true},
		{"config off", MigrationConfig{LiveFirmware: &off}, func(*fwLiveHost) {}, false},
		{"guests not safe", MigrationConfig{}, func(h *fwLiveHost) { h.guests = func(context.Context) error { return errors.New("saves guests") } }, false},
		{"tpm missing", MigrationConfig{}, func(h *fwLiveHost) { h.tpm = func() bool { return false } }, false},
		{"secure boot missing", MigrationConfig{}, func(h *fwLiveHost) { h.secureBoot = func() bool { return false } }, false},
		{"installed unreadable", MigrationConfig{}, func(h *fwLiveHost) {
			h.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
				return libvirt.InstalledFirmwareCode{}, errors.New("x")
			}
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h := okHost()
			c.set(&h)
			if got := fwLiveLabelProbe(c.cfg, h)(); got != c.want {
				t.Fatalf("probe = %v, want %v", got, c.want)
			}
		})
	}
}

// A wedged libvirtd (its version call never returns) makes the host not
// capable, within the bound, and the next probe does not pile up behind it:
// it waits on the same call, within its own bound.
//
// Mutations: call fn directly in boundedVersion - the test hangs and goes red;
// start a new call for every caller - the calls row goes red; return a stale
// success on timeout - the first row goes red.
func TestBoundedVersion_WedgedLibvirtIsNotCapable(t *testing.T) {
	release := make(chan struct{})
	calls := 0
	var mu sync.Mutex
	wedged := func() (uint64, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return 10000000, nil
	}
	bv := boundedVersion(50*time.Millisecond, wedged)
	start := time.Now()
	if _, err := bv(); err == nil {
		t.Fatal("a wedged version call returned no error")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the wedged call was not bounded: %v", time.Since(start))
	}
	start = time.Now()
	if _, err := bv(); err == nil || time.Since(start) > 5*time.Second {
		t.Fatalf("second call while the first is blocked: err %v after %v, want an error within the bound", err, time.Since(start))
	}
	mu.Lock()
	if calls != 1 {
		t.Errorf("fn called %d times while wedged, want 1", calls)
	}
	mu.Unlock()
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for {
		if v, err := bv(); err == nil && v == 10000000 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("bounded version never recovered after libvirtd answered")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Two live firmware moves on one host (or one host the source of one and the
// target of another) read the version at once: both get the answer of one
// call, and neither is refused because the other's call is in flight (merge
// review m-1).
//
// Mutation: refuse a caller while a call is in flight (the old in-flight
// flag) - red.
func TestBoundedVersion_ConcurrentCallersShareOneCall(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	calls := 0
	bv := boundedVersion(5*time.Second, func() (uint64, error) {
		mu.Lock()
		calls++
		mu.Unlock()
		<-release
		return 10000000, nil
	})
	type res struct {
		v   uint64
		err error
	}
	out := make(chan res, 2)
	for i := 0; i < 2; i++ {
		go func() {
			v, err := bv()
			out <- res{v, err}
		}()
	}
	// Both callers are in before the call returns.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		c := calls
		mu.Unlock()
		if c >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no version call started")
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	for i := 0; i < 2; i++ {
		r := <-out
		if r.err != nil || r.v != 10000000 {
			t.Fatalf("caller %d: %v, %v; want the shared answer", i, r.v, r.err)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if calls != 1 {
		t.Fatalf("fn called %d times for two concurrent callers, want 1", calls)
	}
}

// Through the label: a wedged version call is "not capable", and the probe
// returns (the loop continues).
//
// Mutation: pass the raw version func (unbounded) to the probe - it hangs.
func TestFwLiveLabel_WedgedVersionIsFalse(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	bv := boundedVersion(50*time.Millisecond, func() (uint64, error) { <-release; return 10000000, nil })
	h := okHost()
	h.installed = func(context.Context) (libvirt.InstalledFirmwareCode, error) {
		_, err := bv()
		return libvirt.InstalledFirmwareCode{}, err
	}
	done := make(chan bool, 1)
	go func() { done <- fwLiveLabelProbe(MigrationConfig{}, h)() }()
	select {
	case got := <-done:
		if got {
			t.Fatal("capable with libvirt wedged")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the probe did not return")
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
