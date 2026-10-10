// Fleet scenarios for USB passthrough, memory hot-add and container host
// mounts on INDEPENDENT replicas: each node decides from its own database, and
// rows (mappings, VMs, containers, users) reach it only through the
// production push loop. A shared database would hide exactly what these pin:
// a check made on one node from a row another node wrote, and a forwarded
// call that the owner runs as the peer.
package fleet

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/health"
	"github.com/litevirt/litevirt/internal/lxc"
)

// operatorOn creates an operator user and token on n and returns a client
// carrying that token; the rows replicate before it returns.
func operatorOn(t *testing.T, c *Cluster, n *Node) pb.LiteVirtClient {
	t.Helper()
	ctx := context.Background()
	admin := c.SelfClient(n)
	if _, err := admin.CreateUser(ctx, &pb.CreateUserRequest{Username: "op", Password: "p4ssw0rd", Role: "operator"}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	tok, err := admin.CreateToken(ctx, &pb.CreateTokenRequest{Username: "op", Name: "op"})
	if err != nil {
		t.Fatalf("CreateToken: %v", err)
	}
	c.WaitConverged(t, convergeTimeout)
	return c.bearerClient(n, tok.Token)
}

// mountedContainer seeds a stopped container on n whose authorized create
// spec carries a host mount of hostPath, and lets it replicate.
func mountedContainer(t *testing.T, c *Cluster, n *Node, name, hostPath string) {
	t.Helper()
	n.CT.Seed(name, "payload-"+name)
	if err := corrosion.UpsertContainer(context.Background(), n.DB, corrosion.ContainerRecord{
		HostName: n.Name, Name: name, State: "stopped", Image: "docker.io/library/alpine:3.19",
		CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine",
			Mounts: []corrosion.ContainerHostMount{{HostPath: hostPath, ContainerPath: "/data", ReadWrite: true}}}),
	}); err != nil {
		t.Fatalf("seed %s on %s: %v", name, n.Name, err)
	}
	c.WaitConverged(t, convergeTimeout)
}

// C1. An operator's clone of a container with a host mount, sent to a node
// that is NOT the container's host, is refused there. The source's host runs
// a forwarded call as the peer — an admin, with auth.forwarded_identity off,
// the default — so a check made only after the forward passes and hands a
// non-admin the mount.
func TestFleet_ForwardedCloneOfAMountedContainerNeedsAdmin(t *testing.T) {
	c := New(t, Options{Nodes: 2, IndependentReplicas: true})
	ctx := context.Background()
	entry, owner := c.Nodes[0], c.Nodes[1]
	allowed, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.MkdirAll(filepath.Join(allowed, "data"), 0o755)
	owner.CT.SetHostAccessPolicy(lxc.HostAccess{MountPaths: []string{allowed}, HookBinary: "/opt/litevirt"})
	mountedContainer(t, c, owner, "m", filepath.Join(allowed, "data"))
	op := operatorOn(t, c, entry)

	_, err := op.CloneContainer(ctx, &pb.CloneContainerRequest{Source: "m", Target: "x", HostName: owner.Name})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("operator clone of a mounted container through %s = %v; want PermissionDenied", entry.Name, err)
	}
	if owner.CT.Exists("x") {
		t.Fatalf("%s cloned the container for an operator", owner.Name)
	}
	c.WaitConverged(t, convergeTimeout)
	if rec, _ := corrosion.GetContainer(ctx, entry.DB, owner.Name, "x"); rec != nil {
		t.Fatalf("a clone row replicated back: %+v", rec)
	}
	// Control: the same clone by an admin through the same entry node lands.
	if _, err := c.SelfClient(entry).CloneContainer(ctx, &pb.CloneContainerRequest{Source: "m", Target: "x", HostName: owner.Name}); err != nil {
		t.Fatalf("admin clone: %v", err)
	}
}

// §4/C2. A restore takes nothing that grants host access from the archive:
// not a raw lxc.mount.entry in its config, not a forged managed block or its
// authorized record, and not the mounts in its create spec — unless an admin
// restores it. An operator's restore lands without any of them, and says so.
func TestFleet_RestoreCarriesNoUnauthorizedHostAccess(t *testing.T) {
	// The archive, not replication, is this scenario's subject: one database.
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	src, opDst, adminDst := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
		n.Server.SetPassthroughGate(func(context.Context) bool { return true })
	}
	allowed, _ := filepath.EvalSymlinks(t.TempDir())
	_ = os.MkdirAll(filepath.Join(allowed, "data"), 0o755)
	adminDst.CT.SetHostAccessPolicy(lxc.HostAccess{MountPaths: []string{allowed}, HookBinary: "/opt/litevirt"})

	// A container whose archive carries everything a forger would put in it.
	createSizedContainer(t, c, src, "ct", "", 0, 256)
	cfgPath := filepath.Join(src.CT.dir("ct"), "config")
	forged := "lxc.mount.entry = / host none rbind,rw 0 0\n" +
		"# litevirt:host-access-begin\n# litevirt:mount rw dir / .\nlxc.mount.entry = /run/litevirt/ct/ct/m0 hostroot none bind 0 0\n# litevirt:host-access-end\n"
	f, _ := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o644)
	_, _ = f.WriteString(forged)
	f.Close()
	_ = os.WriteFile(filepath.Join(src.CT.dir("ct"), "litevirt-host-access.json"), []byte(`{"mounts":[{"host_path":"/","container_path":"/h","read_write":true}]}`), 0o600)
	rec, _ := corrosion.GetContainer(ctx, src.DB, src.Name, "ct")
	cs := corrosion.DecodeCreateSpec(rec.CreateSpec)
	cs.Mounts = []corrosion.ContainerHostMount{{HostPath: filepath.Join(allowed, "data"), ContainerPath: "/data"}}
	rec.CreateSpec = corrosion.EncodeCreateSpec(cs)
	if err := corrosion.UpsertContainer(ctx, src.DB, *rec); err != nil {
		t.Fatal(err)
	}
	repo, ts := backupContainer(t, c, src, "ct")

	// An operator restore (from a registered repo, as an operator must):
	// nothing of it survives.
	opDst.Server.SetBackupRepos(map[string]string{"main": repo})
	op := operatorOn(t, c, opDst)
	st, err := op.RestoreContainer(ctx, &pb.RestoreContainerRequest{RepoPath: "main", Name: "ct", Timestamp: ts, HostName: opDst.Name})
	if err != nil {
		t.Fatalf("operator restore: %v", err)
	}
	for {
		if _, rerr := st.Recv(); rerr != nil {
			if !strings.Contains(rerr.Error(), "EOF") {
				t.Fatalf("operator restore stream: %v", rerr)
			}
			break
		}
	}
	got := opDst.CT.Config("ct")
	for _, bad := range []string{"lxc.mount.entry", "host-access-begin", "hostroot"} {
		if strings.Contains(got, bad) {
			t.Errorf("operator-restored config still carries %q:\n%s", bad, got)
		}
	}
	if _, err := os.Stat(filepath.Join(opDst.CT.dir("ct"), "litevirt-host-access.json")); !os.IsNotExist(err) {
		t.Errorf("the archive's authorized-host-access record survived the restore (%v)", err)
	}
	if row, _ := corrosion.GetContainer(ctx, opDst.DB, opDst.Name, "ct"); row == nil || len(corrosion.DecodeCreateSpec(row.CreateSpec).Mounts) != 0 {
		t.Errorf("operator-restored row carries the archived mounts: %+v", row)
	}

	// An admin restore keeps the spec's mount, rendered by the host from it —
	// still never the forged lines.
	if err := restoreContainerAt(t, c, adminDst, repo, "ct", ts); err != nil {
		t.Fatalf("admin restore: %v", err)
	}
	got = adminDst.CT.Config("ct")
	if !strings.Contains(got, "lxc.mount.entry = /run/litevirt/ct/ct/m0 data none bind,ro,nosuid,nodev,create=dir 0 0") {
		t.Errorf("admin-restored config lacks the authorized, staged mount:\n%s", got)
	}
	if strings.Contains(got, "hostroot") || strings.Contains(got, "rbind,rw") {
		t.Errorf("admin-restored config carries a forged line:\n%s", got)
	}
	if row, _ := corrosion.GetContainer(ctx, adminDst.DB, adminDst.Name, "ct"); row == nil || len(corrosion.DecodeCreateSpec(row.CreateSpec).Mounts) != 1 {
		t.Errorf("admin-restored row lost the mount: %+v", row)
	}
}

// victimFleet is three independent replicas — two survivors and a victim —
// with the given rows seeded on the victim's side by a survivor's write and
// replicated, then the victim cut off and probed failed by both survivors.
func victimFleet(t *testing.T, clock *VirtualClock, seed func(c *Cluster, a, b, victim *Node)) (c *Cluster, a, b, victim *Node) {
	t.Helper()
	c = New(t, Options{Nodes: 3, IndependentReplicas: true, FaultSeed: 266})
	a, b, victim = c.Nodes[0], c.Nodes[1], c.Nodes[2]
	seed(c, a, b, victim)
	c.WaitConverged(t, convergeTimeout)
	c.Isolate(victim)
	PublishHealth(t, a, victim.Name, 5, clock.Now())
	PublishHealth(t, b, victim.Name, 5, clock.Now())
	c.WaitConverged(t, convergeTimeout, a, b)
	return c, a, b, victim
}

func vmSpecJSON(t *testing.T, spec *pb.VMSpec) string {
	t.Helper()
	spec.OnHostFailure = "restart-any"
	b, err := json.Marshal(spec)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// I9. USB failover: a VM whose device comes through a mapping is recovered
// only onto a host the mapping lists — learned from a replicated mapping row —
// and a VM with a raw device, plugged into the failed host, is not started
// anywhere without it.
func TestFleet_USBFailoverFollowsTheMapping(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, victim := victimFleet(t, clock, func(c *Cluster, a, b, victim *Node) {
		if err := corrosion.CreateResourceMapping(ctx, a.DB, "dongle", ""); err != nil {
			t.Fatal(err)
		}
		for _, h := range []*Node{b, victim} {
			if err := corrosion.AddMappingDevice(ctx, a.DB, "dongle", h.Name, "usb:096e:0006", "", ""); err != nil {
				t.Fatal(err)
			}
		}
		for name, usb := range map[string]*pb.USBDeviceSpec{
			"vm-mapped": {Mapping: "dongle"},
			"vm-raw":    {Vendor: "046d", Product: "c52b"},
		} {
			if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: name, HostName: victim.Name, State: "running",
				CPUActual: 1, MemActual: 256,
				Spec: vmSpecJSON(t, &pb.VMSpec{Name: name, Cpu: 1, MemoryMib: 256, UsbDevices: []*pb.USBDeviceSpec{usb}})}, nil, nil); err != nil {
				t.Fatal(err)
			}
		}
	})
	cs := c.NewCoordinators(clock)
	for i := 0; i < 3; i++ {
		cs.Tick(ctx, a)
		c.WaitConverged(t, convergeTimeout, a, b)
		clock.Advance(contentionPoll)
	}
	if f := cs.Fences(); len(f) != 1 {
		t.Fatalf("fences = %+v; want the victim fenced once", f)
	}
	for _, n := range []*Node{a, b} {
		if vm := vmOn(t, n, "vm-mapped"); vm == nil || vm.HostName != b.Name {
			t.Errorf("%s: vm-mapped on %+v; want it recovered onto %s, the only survivor its mapping lists", n.Name, vm, b.Name)
		}
		if vm := vmOn(t, n, "vm-raw"); vm == nil || vm.HostName != victim.Name {
			t.Errorf("%s: vm-raw on %+v; a raw USB device is the failed host's, so it must stay there", n.Name, vm)
		}
	}
}

// I4/I9. A hot-add VM recovered onto a survivor is defined there with its
// virtio-mem region, so a set-memory after the failover plugs memory and
// its operation ends — it never holds the VM's barrier waiting on a region
// the definition does not have.
func TestFleet_HotplugFailoverThenSetMemoryCompletes(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	disk := filepath.Join(t.TempDir(), "hv-root.qcow2")
	if err := os.WriteFile(disk, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	c, a, b, victim := victimFleet(t, clock, func(c *Cluster, a, b, victim *Node) {
		if err := corrosion.InsertVM(ctx, a.DB, corrosion.VMRecord{Name: "hv", HostName: victim.Name, State: "running",
			CPUActual: 1, MemActual: 1024,
			Spec: vmSpecJSON(t, &pb.VMSpec{Name: "hv", Cpu: 1, MemoryMib: 1024, MemoryHotplugBaseMib: 1024, MemoryHotplugMaxMib: 4096})},
			nil, []corrosion.DiskRecord{{VMName: "hv", DiskName: "root", HostName: victim.Name, Path: disk, StorageType: "nfs"}}); err != nil {
			t.Fatal(err)
		}
	})
	cs := c.NewCoordinators(clock)
	cs.Tick(ctx, a)
	c.WaitConverged(t, convergeTimeout, a, b)
	vm := vmOn(t, a, "hv")
	if vm == nil || vm.HostName == victim.Name {
		t.Fatalf("hv was not recovered off the victim: %+v", vm)
	}
	survivor := c.Node(vm.HostName)
	c.WaitConverged(t, convergeTimeout, a, b)

	rec := health.NewReconciler(survivor.Name, t.TempDir(), survivor.DB, survivor.Virt)
	rec.SetHardwareStartPreparer(survivor.Server.PrepareHardwareForStart)
	rec.ReconcileOnce(ctx)
	if x := survivor.Virt.DefinedXML("hv"); !strings.Contains(x, `model="virtio-mem"`) {
		t.Fatalf("the failover definition on %s has no virtio-mem region:\n%s", survivor.Name, x)
	}
	if v := vmOn(t, survivor, "hv"); v == nil || v.State != "running" {
		t.Fatalf("hv did not start on %s: %+v", survivor.Name, v)
	}

	if _, err := c.SelfClient(survivor).SetVMMemory(ctx, &pb.SetVMMemoryRequest{Name: "hv", TargetMib: 3072}); err != nil {
		t.Fatalf("set-memory after the failover: %v", err)
	}
	if v := vmOn(t, survivor, "hv"); v.ActiveOperationID != "" {
		t.Fatalf("the resize left the barrier held by %q", v.ActiveOperationID)
	}
	if !strings.Contains(survivor.Virt.DefinedXML("hv"), `<requested unit="KiB">2097152</requested>`) {
		t.Fatalf("2048 MiB not plugged:\n%s", survivor.Virt.DefinedXML("hv"))
	}
}

// I9. A container relocated off a failed host is recreated with the host
// mounts its (admin-authorized) row records, judged by the recreating host.
func TestFleet_ContainerRelocationCarriesItsAuthorizedMounts(t *testing.T) {
	ctx := context.Background()
	clock := NewVirtualClock(time.Now().UTC())
	c, a, b, _ := victimFleet(t, clock, func(c *Cluster, a, b, victim *Node) {
		for _, n := range []*Node{a, b} {
			if err := corrosion.SetHostLabel(ctx, a.DB, n.Name, corrosion.LabelLXCCapable, "true"); err != nil {
				t.Fatal(err)
			}
		}
		if err := corrosion.UpsertContainer(ctx, a.DB, corrosion.ContainerRecord{
			HostName: victim.Name, Name: "ctm", State: "running", Image: "docker.io/library/alpine:3.19",
			OnHostFailure: "image-recreate",
			CreateSpec: corrosion.EncodeCreateSpec(corrosion.ContainerCreateSpec{Template: "download", Distro: "alpine",
				Mounts: []corrosion.ContainerHostMount{{HostPath: "/srv/data", ContainerPath: "/data"}}}),
		}); err != nil {
			t.Fatal(err)
		}
	})
	cs := c.NewCoordinators(clock)
	cs.Tick(ctx, a)
	c.WaitConverged(t, convergeTimeout, a, b)
	var dest *Node
	for _, n := range []*Node{a, b} {
		if rec, _ := corrosion.GetContainer(ctx, a.DB, n.Name, "ctm"); rec != nil {
			dest = n
		}
	}
	if dest == nil {
		t.Fatal("ctm was not relocated to a survivor")
	}
	c.WaitConverged(t, convergeTimeout, a, b)
	cc := health.NewContainerChecker(dest.Name, dest.DB, dest.CT.LXC())
	cc.SweepOnce(ctx)
	calls := dest.CT.CreateCalls()
	if len(calls) == 0 {
		t.Fatalf("%s never recreated ctm", dest.Name)
	}
	last := calls[len(calls)-1]
	if last.Name != "ctm" || len(last.Mounts) != 1 || last.Mounts[0].HostPath != "/srv/data" || last.Mounts[0].ReadWrite {
		t.Fatalf("recreate on %s asked for %+v; want ctm with its one read-only /srv/data mount", dest.Name, last)
	}
}

// §4.3: a restore takes privileged mode and legacy confinement from a backup
// only for an admin. An operator's restore of a privileged, legacy container
// lands unprivileged, in a range of its own, with default confinement — and
// says so; an admin's restore keeps the backup's mode.
func TestFleet_RestoreCarriesNoUnauthorizedPrivilege(t *testing.T) {
	c := New(t, Options{Nodes: 3, SharedCRDT: true})
	ctx := context.Background()
	src, opDst, adminDst := c.Nodes[0], c.Nodes[1], c.Nodes[2]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
		n.Server.SetPassthroughGate(func(context.Context) bool { return true })
	}
	if _, err := c.SelfClient(src).CreateContainer(ctx, &pb.CreateContainerRequest{
		HostName: src.Name, Name: "pv", Template: "download", Distro: "debian", Release: "bookworm", Arch: "amd64",
		Privileged: true, Confinement: "legacy",
	}); err != nil {
		t.Fatalf("admin create of a privileged container: %v", err)
	}
	repo, ts := backupContainer(t, c, src, "pv")

	opDst.Server.SetBackupRepos(map[string]string{"main": repo})
	op := operatorOn(t, c, opDst)
	st, err := op.RestoreContainer(ctx, &pb.RestoreContainerRequest{RepoPath: "main", Name: "pv", Timestamp: ts, HostName: opDst.Name})
	if err != nil {
		t.Fatalf("operator restore: %v", err)
	}
	for {
		if _, rerr := st.Recv(); rerr != nil {
			if !strings.Contains(rerr.Error(), "EOF") {
				t.Fatalf("operator restore stream: %v", rerr)
			}
			break
		}
	}
	row, _ := corrosion.GetContainer(ctx, opDst.DB, opDst.Name, "pv")
	if row == nil {
		t.Fatal("no restored row")
	}
	if cs := corrosion.DecodeCreateSpec(row.CreateSpec); cs.IDMapBase == 0 || cs.Confinement != "default" {
		t.Errorf("operator-restored row idmap_base=%d confinement=%q; want unprivileged with default confinement", cs.IDMapBase, cs.Confinement)
	}
	sec := lxc.ParseSecurity(opDst.CT.Config("pv"))
	if sec.IDMap == nil || sec.Confinement != "default" {
		t.Errorf("operator-restored config is privileged=%v confinement=%q:\n%s", sec.IDMap == nil, sec.Confinement, opDst.CT.Config("pv"))
	}

	// An admin's restore keeps the backup's privileged, legacy mode.
	if err := restoreContainerAt(t, c, adminDst, repo, "pv", ts); err != nil {
		t.Fatalf("admin restore: %v", err)
	}
	arow, _ := corrosion.GetContainer(ctx, adminDst.DB, adminDst.Name, "pv")
	if cs := corrosion.DecodeCreateSpec(arow.CreateSpec); cs.IDMapBase != 0 || cs.Confinement != "legacy" {
		t.Errorf("admin-restored row idmap_base=%d confinement=%q; want privileged legacy kept", cs.IDMapBase, cs.Confinement)
	}
}

// A drain moves a running VM with a mapped USB device COLD — libvirt is
// never asked to migrate it live — onto a host its mapping lists, which
// defines it with that host's device.
func TestFleet_DrainMovesAUSBVMCold(t *testing.T) {
	c := New(t, Options{Nodes: 2, SharedCRDT: true})
	ctx := context.Background()
	src, dst := c.Nodes[0], c.Nodes[1]
	for _, n := range c.Nodes {
		setHostCapacity(t, c, n.Name, 64, 65536, nil)
	}
	if err := corrosion.CreateResourceMapping(ctx, src.DB, "dongle", ""); err != nil {
		t.Fatal(err)
	}
	for h, addr := range map[string]string{src.Name: "usb:046d:c52b", dst.Name: "usb:1a86:7523"} {
		if err := corrosion.AddMappingDevice(ctx, src.DB, "dongle", h, addr, "", ""); err != nil {
			t.Fatal(err)
		}
	}
	shared := filepath.Join(c.tmpRoot, "nfs", "u1-root.qcow2")
	_ = os.MkdirAll(filepath.Dir(shared), 0o755)
	_ = os.WriteFile(shared, nil, 0o600)
	spec, _ := json.Marshal(&pb.VMSpec{Name: "u1", Cpu: 1, MemoryMib: 256, UsbDevices: []*pb.USBDeviceSpec{{Mapping: "dongle"}}})
	if err := corrosion.InsertVM(ctx, src.DB, corrosion.VMRecord{Name: "u1", HostName: src.Name, State: "running", Spec: string(spec), CPUActual: 1, MemActual: 256},
		nil, []corrosion.DiskRecord{{VMName: "u1", DiskName: "root", HostName: src.Name, Path: shared, StorageType: "nfs", TargetDev: "vda"}}); err != nil {
		t.Fatal(err)
	}
	if err := src.Virt.DefineDomain(`<domain type='kvm'><name>u1</name><uuid>11111111-2222-4333-8444-777777777777</uuid><devices>` +
		`<disk type='file' device='disk'><driver name='qemu' type='qcow2'/><source file='` + shared + `'/><target dev='vda'/></disk>` +
		`<hostdev mode='subsystem' type='usb' managed='yes'><source><vendor id='0x046d'/><product id='0xc52b'/></source></hostdev>` +
		`</devices></domain>`); err != nil {
		t.Fatal(err)
	}
	if err := src.Virt.StartDomain("u1"); err != nil {
		t.Fatal(err)
	}
	st, err := c.SelfClient(src).DrainHost(ctx, &pb.DrainHostRequest{Name: src.Name})
	if err != nil {
		t.Fatalf("drain: %v", err)
	}
	for {
		if _, rerr := st.Recv(); rerr != nil {
			break
		}
	}
	for _, e := range src.Virt.EventLog() {
		if e.Op == "migrate" && e.Domain == "u1" {
			t.Fatalf("drain asked libvirt to migrate a USB VM live: %+v", e)
		}
	}
	vm := vmOn(t, src, "u1")
	if vm == nil || vm.HostName != dst.Name {
		t.Fatalf("u1 after the drain: %+v; want it moved to %s", vm, dst.Name)
	}
	if x := dst.Virt.DefinedXML("u1"); !strings.Contains(x, "0x1a86") {
		t.Fatalf("u1 on %s does not name that host's mapped device:\n%s", dst.Name, x)
	}
}
