package health

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
	"github.com/litevirt/litevirt/internal/libvirtfake"
)

// A domain the reconciler defines on this host (a failover start, a stopped VM
// a failover moved here, an autostart) is rendered from the stored spec by the
// same builder CreateVM uses, so the guest boots with the hardware it was
// created with. The failover start once set no CPU mode at all: libvirt gave
// the guest qemu64, and a Rocky 9 guest (x86-64-v2) spun at 100% CPU in early
// boot with no console output (lab 2, F3).
//
// Mutations, each turning the named test red:
//   - domainXMLFor builds its VMConfig by hand again, without CPUMode/CPUModel
//     (RendersTheSpecsCPU, MatchesTheCreateBuilder);
//   - the vCPU ceiling, balloon ceiling and VNC console cleared after the
//     builder (MatchesTheCreateBuilder);
//   - a default filled in for a spec with no cpu_mode
//     (NoCPUModeRendersAsTheCreatePath);
//   - the reconciler's NICs take no model (KeepsTheNICModel);
//   - failoverDiskConfigs takes the bus from the spec only and drops the
//     controller model, cache and stored target (KeepsDiskBusControllerAndOrder).

var cpuElementRE = regexp.MustCompile(`(?s)<cpu\b[^>]*?(?:/>|>.*?</cpu>)`)

// cpuElement is the domain's top-level <cpu> element, "" when it has none.
func cpuElement(domXML string) string { return cpuElementRE.FindString(domXML) }

// createRender is the domain CreateVM renders for spec, with no devices.
func createRender(t *testing.T, spec *pb.VMSpec) string {
	t.Helper()
	x, err := lv.GenerateDomainXML(compose.DomainConfig(spec, nil, nil, nil))
	if err != nil {
		t.Fatalf("create render: %v", err)
	}
	return x
}

func TestDomainXMLFor_RendersTheSpecsCPU(t *testing.T) {
	for _, tc := range []struct{ mode, model string }{
		{lv.CPUModeHostPassthrough, ""},
		{lv.CPUModeHostModel, ""},
		{lv.CPUModeCustom, "x86-64-v2"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			r := NewReconciler("node-a", t.TempDir(), testLogicDB(t), libvirtfake.New())
			spec := &pb.VMSpec{Name: "vm1", Cpu: 2, MemoryMib: 1024, CpuMode: tc.mode, CpuModel: tc.model}
			x, _, failure := r.domainXMLFor(context.Background(),
				corrosion.VMRecord{Name: "vm1", CPUActual: 2, MemActual: 1024}, spec, nil)
			if failure != "" {
				t.Fatalf("domainXMLFor: %s", failure)
			}
			got, want := cpuElement(x), cpuElement(createRender(t, spec))
			if want == "" {
				t.Fatalf("fixture: the create render has no <cpu> element for mode %q", tc.mode)
			}
			if got != want {
				t.Fatalf("failover <cpu> = %q, want the create path's %q\n%s", got, want, x)
			}
		})
	}
}

// A spec with no cpu_mode (one stored before the create-time default existed)
// renders exactly as the create and redefine paths render it: with no <cpu>
// element. A boot on this host never changes the CPU the guest sees.
func TestDomainXMLFor_NoCPUModeRendersAsTheCreatePath(t *testing.T) {
	r := NewReconciler("node-a", t.TempDir(), testLogicDB(t), libvirtfake.New())
	spec := &pb.VMSpec{Name: "old", Cpu: 1, MemoryMib: 512}
	x, _, failure := r.domainXMLFor(context.Background(),
		corrosion.VMRecord{Name: "old", CPUActual: 1, MemActual: 512}, spec, nil)
	if failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	if got, want := cpuElement(x), cpuElement(createRender(t, spec)); got != want || got != "" {
		t.Fatalf("no cpu_mode: failover <cpu> = %q, want the create path's %q (none)", got, want)
	}
}

// Every element the spec decides comes out as the create path renders it: the
// vCPU ceiling, the balloon, the consoles, the machine and the CPU.
func TestDomainXMLFor_MatchesTheCreateBuilder(t *testing.T) {
	r := NewReconciler("node-a", t.TempDir(), testLogicDB(t), libvirtfake.New())
	spec := &pb.VMSpec{
		Name: "full", Uuid: "11111111-2222-4333-8444-555555555555",
		Cpu: 2, MaxCpu: 4, MemoryMib: 1024, MinMemoryMib: 512, MaxMemoryMib: 2048,
		Machine: "pc", Firmware: "bios", EnableSpice: true, GuestAgent: true,
		CpuMode: lv.CPUModeHostPassthrough,
	}
	x, _, failure := r.domainXMLFor(context.Background(),
		corrosion.VMRecord{Name: "full", CPUActual: 2, MemActual: 1024}, spec, nil)
	if failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	want := createRender(t, spec)
	for _, el := range []string{
		`<vcpu\b[^>]*>[^<]*</vcpu>`,
		`<memory\b[^>]*>[^<]*</memory>`,
		`<currentMemory\b[^>]*>[^<]*</currentMemory>`,
		`<type\b[^>]*>hvm</type>`,
		`(?s)<cpu\b[^>]*?(?:/>|>.*?</cpu>)`,
		`<graphics type="vnc"`,
		`<graphics type="spice"`,
		`<channel type="unix"`,
	} {
		re := regexp.MustCompile(el)
		w := re.FindString(want)
		if w == "" {
			t.Fatalf("fixture: the create render has no %s:\n%s", el, want)
		}
		if g := re.FindString(x); g != w {
			t.Errorf("failover %s = %q, want the create path's %q", el, g, w)
		}
	}
}

// A NIC attached with a model other than virtio keeps it: the guest's driver
// for it is bound to that model.
func TestDomainXMLFor_KeepsTheNICModel(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, _, _ := sharedDiskReconciler(t, db)
	vm := corrosion.VMRecord{Name: "nm", HostName: "node-a", Spec: "{}", State: "running", CPUActual: 1, MemActual: 512}
	if err := corrosion.InsertVM(ctx, db, vm, nil, nil); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	const mac = "52:54:00:aa:bb:e1"
	if err := corrosion.UpsertNIC(ctx, db, corrosion.NICRecord{VMName: "nm", ID: corrosion.DeterministicNICID("nm", mac),
		NetworkName: "br0", Model: "e1000", MAC: mac}); err != nil {
		t.Fatalf("UpsertNIC: %v", err)
	}
	x, _, failure := r.domainXMLFor(ctx, vm, &pb.VMSpec{Name: "nm", Cpu: 1, MemoryMib: 512}, nil)
	if failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	var d struct {
		Interfaces []struct {
			MAC struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Model struct {
				Type string `xml:"type,attr"`
			} `xml:"model"`
		} `xml:"devices>interface"`
	}
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(d.Interfaces) != 1 || d.Interfaces[0].Model.Type != "e1000" {
		t.Fatalf("failover NICs = %+v, want the one e1000 NIC\n%s", d.Interfaces, x)
	}
}

// A failover start renders the disks as the create and a redefine do: in the
// spec's order (the boot disk first, whatever order the rows come back in),
// with the spec's bus, cache and SCSI controller model, and a disk hot-plugged
// since the create on its recorded bus and target.
func TestStartPendingVM_KeepsDiskBusControllerAndOrder(t *testing.T) {
	db := testReconcilerDB(t)
	ctx := context.Background()
	dir := t.TempDir()
	root, extra, hot := filepath.Join(dir, "root.img"), filepath.Join(dir, "aextra.img"), filepath.Join(dir, "hot.img")
	for _, p := range []string{root, extra, hot} {
		if err := os.WriteFile(p, []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	spec, _ := json.Marshal(&pb.VMSpec{Name: "win", Cpu: 1, MemoryMib: 512, CpuMode: lv.CPUModeHostModel,
		Disks: []*pb.DiskSpec{
			{Name: "root", Bus: "scsi", Cache: "none", ControllerModel: "lsilogic"},
			{Name: "aextra", Bus: "scsi"},
		}})
	if err := corrosion.InsertVM(ctx, db,
		corrosion.VMRecord{Name: "win", HostName: "node-a", Spec: string(spec), State: "running", CPUActual: 1, MemActual: 512},
		nil,
		[]corrosion.DiskRecord{
			// "aextra" and "a-hot" sort before "root": a render in row order
			// would boot the wrong disk.
			{VMName: "win", DiskName: "aextra", HostName: "node-a", Path: extra, StorageType: "local", SizeBytes: 1 << 30, TargetDev: "sdb"},
			{VMName: "win", DiskName: "a-hot", HostName: "node-a", Path: hot, StorageType: "local", SizeBytes: 1 << 30, TargetDev: "sdd", Bus: "sata"},
			{VMName: "win", DiskName: "root", HostName: "node-a", Path: root, StorageType: "local", SizeBytes: 1 << 30, TargetDev: "sda"},
		},
	); err != nil {
		t.Fatalf("InsertVM: %v", err)
	}
	r, fake, _ := sharedDiskReconciler(t, db)
	fresh, _ := corrosion.GetVM(ctx, db, "win")
	r.startPendingVM(ctx, *fresh)

	x := fake.DefinedXML("win")
	if x == "" {
		t.Fatal("the VM was not defined")
	}
	var d struct {
		Disks []struct {
			Device string `xml:"device,attr"`
			Driver struct {
				Cache string `xml:"cache,attr"`
			} `xml:"driver"`
			Source struct {
				File string `xml:"file,attr"`
			} `xml:"source"`
			Target struct {
				Dev string `xml:"dev,attr"`
				Bus string `xml:"bus,attr"`
			} `xml:"target"`
		} `xml:"devices>disk"`
		Controllers []struct {
			Type  string `xml:"type,attr"`
			Model string `xml:"model,attr"`
		} `xml:"devices>controller"`
	}
	if err := xml.Unmarshal([]byte(x), &d); err != nil {
		t.Fatalf("parse: %v", err)
	}
	type disk struct{ file, dev, bus, cache string }
	var got []disk
	for _, dk := range d.Disks {
		if dk.Device == "disk" {
			got = append(got, disk{dk.Source.File, dk.Target.Dev, dk.Target.Bus, dk.Driver.Cache})
		}
	}
	want := []disk{
		{root, "sda", "scsi", "none"},
		{extra, "sdb", "scsi", "writeback"},
		{hot, "sdd", "sata", "writeback"},
	}
	if len(got) != len(want) {
		t.Fatalf("failover disks = %+v, want %+v\n%s", got, want, x)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("failover disk %d = %+v, want %+v", i, got[i], want[i])
		}
	}
	scsi := ""
	for _, c := range d.Controllers {
		if c.Type == "scsi" {
			scsi = c.Model
		}
	}
	if scsi != "lsilogic" {
		t.Errorf("failover SCSI controller model = %q, want lsilogic\n%s", scsi, x)
	}
}
