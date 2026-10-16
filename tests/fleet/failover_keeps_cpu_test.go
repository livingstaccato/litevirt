package fleet

import (
	"context"
	"errors"
	"io"
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
// create-time default) gets that default, not qemu64.
//
// Multi-node by construction: CreateVM renders the domain on one host, a
// second host's coordinator fails it over, a third host's reconciler defines
// it from replicated state, and the cold migration defines it on a fourth
// libvirt from the third's definition.
//
// Mutation: domainXMLFor builds its VMConfig by hand again, without
// CPUMode/CPUModel — every VM's <cpu> is gone on the survivor and after the
// cold migration; drop the default for a spec with no cpu_mode — the legacy
// VM's is.
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
	want["cpu-legacy"] = `<cpu mode="` + lv.DefaultCPUMode + `"></cpu>`

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
