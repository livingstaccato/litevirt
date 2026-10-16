package fleet

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

var domainCPURE = regexp.MustCompile(`(?s)<cpu\b[^>]*?(?:/>|>.*?</cpu>)`)

// domainCPU is a domain definition's top-level <cpu> element, "" for none.
func domainCPU(domXML string) string { return domainCPURE.FindString(domXML) }

// A VM failed over to another host boots there on the CPU it was created
// with, and a cold migration afterwards keeps it. The failover start once
// defined the domain with no <cpu> element at all, so libvirt gave the guest
// qemu64: a Rocky 9 guest (x86-64-v2) spun at 100% CPU in early boot with no
// console output, and a cold migration carried the broken domain on (lab 2,
// F3). A VM whose stored spec names no cpu_mode (created before the
// create-time default) renders as every other path renders it, with no <cpu>:
// a failover never changes the CPU a guest sees.
//
// Multi-node by construction: CreateVM renders the domain on one host, a
// second host's coordinator fails it over, a third host's reconciler defines
// it from replicated state, and the cold migration defines it on a fourth
// libvirt from the third's definition.
//
// Mutation: domainXMLFor builds its VMConfig by hand again, without
// CPUMode/CPUModel — every VM's <cpu> is gone on the survivor and after the
// cold migration; fill a default in for a spec with no cpu_mode — the legacy
// VM gains one.
func TestFleet_FailoverAndColdMigrationKeepTheCPU(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	coord, home, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]

	want := map[string]string{}
	for name, spec := range map[string]*pb.VMSpec{
		"cpu-default": {},
		"cpu-pass":    {CpuMode: lv.CPUModeHostPassthrough},
		"cpu-custom":  {CpuMode: lv.CPUModeCustom, CpuModel: "x86-64-v2"},
	} {
		spec.Name, spec.Cpu, spec.MemoryMib, spec.OnHostFailure = name, 1, 256, "restart-any"
		spec.Placement = &pb.PlacementSpec{Host: home.Name}
		if _, err := c.SelfClient(home).CreateVM(ctx, &pb.CreateVMRequest{Spec: spec}); err != nil {
			t.Fatalf("CreateVM %s: %v", name, err)
		}
		want[name] = domainCPU(home.Virt.DefinedXML(name))
		if want[name] == "" {
			t.Fatalf("fixture: %s was created with no <cpu> element:\n%s", name, home.Virt.DefinedXML(name))
		}
	}
	// A VM stored before the create-time default: its spec names no cpu_mode.
	if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
		Name: "cpu-legacy", HostName: home.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"cpu-legacy","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
	}, nil, nil); err != nil {
		t.Fatalf("InsertVM cpu-legacy: %v", err)
	}
	// The create and redefine paths render it with no <cpu> element.
	want["cpu-legacy"] = ""

	for name := range want {
		pinTo(t, coord, name, other.Name)
	}
	if got := fenceVictim(t, c, coord, home, other, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	rec := health.NewReconciler(other.Name, t.TempDir(), other.DB, other.Virt)
	rec.SetNetworkProvision(other.Net.Provision)
	rec.ReconcileOnce(ctx)

	for name, w := range want {
		if vm, _ := corrosion.GetVM(ctx, coord.DB, name); vm == nil || vm.HostName != other.Name || vm.State != "running" {
			t.Fatalf("%s after the failover = %+v, want it running on %s", name, vm, other.Name)
		}
		if got := domainCPU(other.Virt.DefinedXML(name)); got != w {
			t.Errorf("%s failed over to %s with <cpu> %q, want %q", name, other.Name, got, w)
		}
	}

	// Stopped, then moved cold to a third host: the domain defined there is
	// the survivor's.
	for name, w := range want {
		if _, err := c.SelfClient(other).StopVM(ctx, &pb.StopVMRequest{Name: name, Force: true}); err != nil {
			t.Fatalf("StopVM %s: %v", name, err)
		}
		if err := migrateColdTo(ctx, c, other, name, coord.Name); err != nil {
			t.Fatalf("migrate --cold %s %s → %s: %v", name, other.Name, coord.Name, err)
		}
		if got := domainCPU(coord.Virt.DefinedXML(name)); got != w {
			t.Errorf("%s cold-migrated to %s with <cpu> %q, want %q", name, coord.Name, got, w)
		}
	}
}

// migrateColdTo moves vm cold from at to target and waits for the stream.
func migrateColdTo(ctx context.Context, c *Cluster, at *Node, vm, target string) error {
	st, err := c.SelfClient(at).MigrateVM(ctx, &pb.MigrateVMRequest{
		VmName: vm, TargetHost: target, Strategy: pb.MigrateStrategy_MIGRATE_COLD,
	})
	if err != nil {
		return err
	}
	for {
		if _, rerr := st.Recv(); errors.Is(rerr, io.EOF) {
			return nil
		} else if rerr != nil {
			return rerr
		}
	}
}

// A VM whose spec lists no disks (created before the disk-tuning latch) fails
// over with a sata data disk hot-plugged on sda beside its root on vda, and
// the survivor boots the root: boot order 1 is on it, not on the data disk
// that sorts first by target.
//
// Mutation: sort every disk row of such a spec by target alone — boot order 1
// lands on the data disk and the test goes red.
func TestFleet_FailoverBootsTheRootOfASpecWithNoDisks(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	coord, home, other := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	dir := t.TempDir()
	root, data := filepath.Join(dir, "nd-root.qcow2"), filepath.Join(dir, "nd-data.qcow2")
	for _, p := range []string{root, data} {
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := corrosion.InsertVM(ctx, coord.DB, corrosion.VMRecord{
		Name: "nd", HostName: home.Name, State: "running", CPUActual: 1, MemActual: 256,
		Spec: `{"name":"nd","cpu":1,"memory_mib":256,"on_host_failure":"restart-any"}`,
	}, nil, []corrosion.DiskRecord{
		{VMName: "nd", DiskName: "root", HostName: home.Name, Path: root, StorageType: "nfs", StorageVolume: "shared", SizeBytes: 1 << 30, TargetDev: "vda"},
		{VMName: "nd", DiskName: "data", HostName: home.Name, Path: data, StorageType: "nfs", StorageVolume: "shared", SizeBytes: 1 << 30, TargetDev: "sda", Bus: "sata"},
	}); err != nil {
		t.Fatalf("InsertVM nd: %v", err)
	}
	pinTo(t, coord, "nd", other.Name)
	if got := fenceVictim(t, c, coord, home, other, coord); got != 1 {
		t.Fatalf("fencer fired %d times, want 1", got)
	}
	rec := health.NewReconciler(other.Name, t.TempDir(), other.DB, other.Virt)
	rec.SetNetworkProvision(other.Net.Provision)
	rec.ReconcileOnce(ctx)
	if vm, _ := corrosion.GetVM(ctx, coord.DB, "nd"); vm == nil || vm.HostName != other.Name || vm.State != "running" {
		t.Fatalf("nd after the failover = %+v, want it running on %s", vm, other.Name)
	}
	var d struct {
		Disks []struct {
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
			Boot *struct {
				Order string `xml:"order,attr"`
			} `xml:"boot"`
		} `xml:"devices>disk"`
	}
	x := other.Virt.DefinedXML("nd")
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		t.Fatalf("parse nd's domain: %v\n%s", err, x)
	}
	boot := ""
	for _, dk := range d.Disks {
		if dk.Boot != nil && dk.Boot.Order == "1" {
			boot = dk.Source.File
		}
	}
	if boot != root {
		t.Fatalf("nd on %s boots %q, want its root %q\n%s", other.Name, boot, root, x)
	}
}
