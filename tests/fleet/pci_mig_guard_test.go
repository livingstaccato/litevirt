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

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
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

// A passthrough VM crashes; managed='yes' put its GPU back on the nvidia
// driver, and the operator split the GPU into MIG instances meanwhile. The
// restart policy's restart (health.VMChecker, wired with the daemon's
// hardware pre-start) is refused: the domain stays down and the GPU stays on
// nvidia, before the hardware_v2 latch and after it.
func TestFleet_HealthRestartDoesNotRebindAMIGGPU(t *testing.T) {
	const addr = "0000:81:00.0"
	for _, latched := range []bool{false, true} {
		t.Run(map[bool]string{false: "pre-latch", true: "post-latch"}[latched], func(t *testing.T) {
			fs := &migSysfs{drv: map[string]string{addr: "nvidia"}}
			defer vfio.SetFS(fs)()
			fleetFakeSMI(t, "Disabled")
			c := New(t, Options{Nodes: 1})
			n := c.Nodes[0]
			ctx := context.Background()
			if latched {
				latchHardwareV2(t, c, gateAll(t, c))
			}
			if err := corrosion.UpsertPCIDevice(ctx, n.DB, corrosion.PCIDeviceRecord{
				HostName: n.Name, Address: addr, VendorID: h100.vendor, DeviceID: h100.device,
				DeviceName: h100.name, Type: h100.typ, Driver: "nvidia", IOMMUGroup: 80,
			}); err != nil {
				t.Fatal(err)
			}
			if _, err := c.SelfClient(n).CreateVM(ctx, &pb.CreateVMRequest{Spec: &pb.VMSpec{
				Name: "web", Cpu: 1, MemoryMib: 512,
				Placement: &pb.PlacementSpec{Host: n.Name},
				Restart:   &pb.RestartPolicy{Condition: "always", Delay: "1ms"},
				Devices:   []*pb.DeviceSpec{{Address: addr}},
			}}); err != nil {
				t.Fatalf("CreateVM: %v", err)
			}
			if st, _ := n.Virt.RawState("web"); st != libvirtfake.StateRunning {
				t.Fatalf("setup: web is %q, want running", st)
			}

			// The crash: the domain is gone, libvirt gave the GPU back to
			// nvidia, and MIG is on now.
			if err := n.Virt.DestroyDomain("web"); err != nil {
				t.Fatal(err)
			}
			n.Virt.SetStateReason("web", "crashed")
			if err := localExec(ctx, n.DB, `UPDATE vms SET state = 'stopped' WHERE name = 'web'`); err != nil {
				t.Fatal(err)
			}
			fs.mu.Lock()
			fs.drv[addr] = "nvidia"
			binds := fs.binds
			fs.mu.Unlock()
			fleetFakeSMI(t, "Enabled")

			checker := newRestartChecker(t, n)
			checker.SetHardwareStartPreparer(n.Server.PrepareHardwareForStart)
			before := len(n.Virt.EventLog())
			checker.SweepOnce(ctx)

			for _, e := range n.Virt.EventLog()[before:] {
				if e.Domain == "web" && e.Op == "start" {
					t.Fatal("the restart policy started web on a GPU MIG holds")
				}
			}
			if st, _ := n.Virt.RawState("web"); st == libvirtfake.StateRunning {
				t.Fatal("web runs on a GPU MIG holds")
			}
			// The restart went ahead (its attempt is counted before the
			// destroy), so the refusal is what kept web down.
			if rs, err := corrosion.GetRestartState(ctx, n.DB, "web"); err != nil || rs == nil || rs.AttemptCount < 1 {
				t.Fatalf("the restart policy never tried to restart web (%+v, %v); the scenario did not run", rs, err)
			}
			fs.mu.Lock()
			drv, after := fs.drv[addr], fs.binds
			fs.mu.Unlock()
			if drv != "nvidia" || after != binds {
				t.Fatalf("the MIG GPU is on %q after %d more vfio binds; want it left on nvidia", drv, after-binds)
			}
		})
	}
}
