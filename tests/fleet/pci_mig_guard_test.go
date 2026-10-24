package fleet

// A GPU split into MIG instances is still a free `type: gpu` device in the
// replicated inventory, so a failover can place a VM on a host whose only
// matching GPU MIG holds. The host the VM lands on refuses to bind that GPU to
// vfio-pci at start: the VM does not start, the GPU stays on the NVIDIA driver
// and unowned. Once the operator turns MIG off there, the next start takes it.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/litevirt/litevirt/internal/pci"
	"github.com/litevirt/litevirt/internal/vfio"
)

// migSysfs is a sysfs in which the devices listed in drv are on the driver
// named there (every other on vfio-pci), and a bind moves one to vfio-pci.
type migSysfs struct {
	mu    sync.Mutex
	drv   map[string]string
	binds int
}

func (f *migSysfs) addr(p, suffix string) string {
	return strings.TrimSuffix(strings.TrimPrefix(p, "/sys/bus/pci/devices/"), suffix)
}

func (f *migSysfs) ReadFile(p string) ([]byte, error) {
	switch {
	case strings.HasSuffix(p, "/driver_override"):
		return []byte("(null)\n"), nil
	case strings.HasSuffix(p, "/vendor"):
		return []byte("0x10de\n"), nil
	case strings.HasSuffix(p, "/device"):
		return []byte("0x2330\n"), nil
	}
	return nil, os.ErrNotExist
}

func (f *migSysfs) WriteFile(p string, data []byte, _ os.FileMode) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	a := strings.TrimSpace(string(data))
	switch {
	case strings.HasSuffix(p, "/driver/unbind"):
		f.drv[a] = ""
	case p == "/sys/bus/pci/drivers/vfio-pci/bind":
		f.drv[a] = "vfio-pci"
		f.binds++
	}
	return nil
}

func (f *migSysfs) ReadDir(string) ([]os.DirEntry, error) { return nil, os.ErrNotExist }

func (f *migSysfs) Readlink(p string) (string, error) {
	if !strings.HasSuffix(p, "/driver") {
		return "", os.ErrNotExist
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.drv[f.addr(p, "/driver")]
	if !ok {
		d = "vfio-pci"
	}
	if d == "" {
		return "", os.ErrNotExist
	}
	return "../../../bus/pci/drivers/" + d, nil
}

// fleetFakeSMI makes nvidia-smi report the GPU at pciFoThere with MIG mode
// mode and no GPU instance.
func fleetFakeSMI(t *testing.T, mode string) {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "nvidia-smi")
	script := "#!/bin/sh\ncase \"$1\" in\n" +
		"--query-gpu*) echo '0, 00000000:81:00.0, " + mode + ", " + mode + ", NVIDIA H100';;\n" +
		"mig) echo 'No GPU instances found: Not Found'; exit 6;;\n" +
		"*) exit 1;;\nesac\n"
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pci.SetNvidiaSMI(bin))
}

func TestFleet_PCIFailover_MIGGPUIsNotBoundUntilMIGIsOff(t *testing.T) {
	pciFoRegimes(t, func(t *testing.T, latched bool) {
		fs := &migSysfs{drv: map[string]string{}}
		defer vfio.SetFS(fs)()
		ctx := context.Background()
		clock := NewVirtualClock(time.Now().UTC())
		c, a, b, _ := pciFoFleet(t, clock, latched, nil, nil, []pciFoDevice{h100.at(pciFoThere)})
		// b's H100 is on the NVIDIA driver, split into MIG instances.
		fs.mu.Lock()
		fs.drv[pciFoThere] = "nvidia"
		fs.mu.Unlock()
		fleetFakeSMI(t, "Enabled")

		pciFoFailOver(t, ctx, c, clock, a, b)
		if vm := vmOn(t, a, pciFoVM); vm == nil || vm.HostName != b.Name {
			t.Fatalf("%s on %+v; want it placed on %s, whose H100 the inventory lists free", pciFoVM, vm, b.Name)
		}
		pciFoStart(t, ctx, b)
		if v := vmOn(t, b, pciFoVM); v != nil && v.State == "running" {
			t.Fatalf("%s started on %s with a GPU MIG holds: %+v", pciFoVM, b.Name, v)
		}
		fs.mu.Lock()
		drv, binds := fs.drv[pciFoThere], fs.binds
		fs.mu.Unlock()
		if drv != "nvidia" || binds != 0 {
			t.Fatalf("the MIG GPU on %s is on %q after %d vfio binds; want it left on nvidia", b.Name, drv, binds)
		}
		if o := pciFoOwner(t, ctx, b, b.Name, pciFoThere); o != "" {
			t.Fatalf("the MIG GPU on %s is owned by %q", b.Name, o)
		}
		if buses := pciFoHostdevBuses(b.Virt.DefinedXML(pciFoVM)); len(buses) != 0 {
			t.Fatalf("%s's domain on %s passes through %v", pciFoVM, b.Name, buses)
		}
		if st, _ := b.Virt.DomainState(pciFoVM); st == "running" {
			t.Fatalf("%s's domain runs on %s", pciFoVM, b.Name)
		}

		// `lv host mig disable` on b: MIG off, no instance. The next start binds it.
		fleetFakeSMI(t, "Disabled")
		if v := pciFoRestart(t, ctx, c, a, b); v == nil || v.State != "running" {
			t.Fatalf("%s did not start on %s once MIG was off: %+v", pciFoVM, b.Name, v)
		}
		if o := pciFoOwner(t, ctx, b, b.Name, pciFoThere); o != pciFoVM {
			t.Fatalf("the H100 on %s is owned by %q, want %s", b.Name, o, pciFoVM)
		}
		fs.mu.Lock()
		drv = fs.drv[pciFoThere]
		fs.mu.Unlock()
		if drv != "vfio-pci" {
			t.Fatalf("the H100 on %s is on %q once MIG was off, want vfio-pci", b.Name, drv)
		}
	})
}
