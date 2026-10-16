package health

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// stageSeedGenisoimage stages a genisoimage whose "ISO" is the seed's
// network-config verbatim, or "<no network-config>".
func stageSeedGenisoimage(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	script := `#!/bin/sh
out=""; src=""
while [ $# -gt 0 ]; do
  case "$1" in
    -output) out="$2"; shift ;;
    -volid) shift ;;
    -*) ;;
    *) src="$1" ;;
  esac
  shift
done
if [ -f "$src/network-config" ]; then cat "$src/network-config" > "$out"; else printf '<no network-config>' > "$out"; fi
`
	if err := os.WriteFile(filepath.Join(dir, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

// Review I-3: a VM the reconciler defines on a host that has no copy of its
// seed (a failover) gets the seed it was created with, network-config
// included: derived from its spec, NIC rows and networks
// (cloudinit.SeedNetworkConfig, which internal/grpcapi's
// TestCreateVM_SeedIsRebuiltAlike holds equal to what CreateVM wrote). That
// covers a cloud image created with no cloud-init in its spec too, which
// CreateVM gave a seed and the reconciler used to rebuild without one.
//
// Here: NIC 0 on a DHCP bridge (the IP scanner has recorded its lease), NIC 1
// on a host-isolated network with its picked address. Before, the rebuilt
// seed was none at all — the guest would come up on NIC 0's fallback DHCP
// with NIC 1 unaddressed.
//
// Mutation: rebuild only from spec.CloudInit.Networkconfig — red; regenerate
// only when spec.CloudInit is set — red (no seed).
func TestDomainXMLFor_RebuildsTheCreatedSeed(t *testing.T) {
	stageSeedGenisoimage(t)
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, _, _ := sharedDiskReconciler(t, db)
	r.SetNetworkProvision(func(context.Context, *corrosion.Client, string, compose.NetworkDef, string, string) (string, error) {
		return "", nil
	})
	for name, def := range map[string]compose.NetworkDef{
		"brnet": {Type: "bridge", Subnet: "172.40.0.0/24", DHCP: true},
		"hinet": {Type: "vxlan", VNI: 7, Subnet: "10.212.0.0/24", HostIsolation: true},
	} {
		cfg, _ := json.Marshal(def)
		if err := corrosion.UpsertNetwork(ctx, db, corrosion.NetworkRecord{Name: name, Type: def.Type, Config: string(cfg)}); err != nil {
			t.Fatal(err)
		}
	}
	spec := &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512, Image: "ubuntu",
		Network: []*pb.NetworkAttachment{{Name: "brnet", Mac: "52:54:00:aa:00:01"}, {Name: "hinet", Mac: "52:54:00:aa:00:02"}}}
	specJSON, _ := json.Marshal(spec)
	vm := corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: string(specJSON), State: "running", CPUActual: 1, MemActual: 512}
	if err := corrosion.InsertVM(ctx, db, vm, []corrosion.InterfaceRecord{
		{VMName: "vm1", NetworkName: "brnet", MAC: "52:54:00:aa:00:01", IP: "172.40.0.99"},
		{VMName: "vm1", NetworkName: "hinet", MAC: "52:54:00:aa:00:02", Ordinal: 1, IP: "10.212.0.7"},
	}, nil); err != nil {
		t.Fatal(err)
	}
	if _, _, failure := r.domainXMLFor(ctx, vm, spec, nil); failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	iso, _ := lv.SafeCloudInitISOPath(r.dataDir, "vm1")
	b, err := os.ReadFile(iso)
	if err != nil {
		t.Fatalf("no seed rebuilt: %v", err)
	}
	want, err := cloudinit.SeedNetworkConfig(ctx, db, "vm1", spec, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if got != want || !strings.Contains(got, "address") || !strings.Contains(got, "10.212.0.7/24") ||
		strings.Contains(got, "172.40.0.99") {
		t.Errorf("rebuilt seed network-config:\n%s\nwant:\n%s", got, want)
	}
}

// Re-review R1-m1: a read that fails while deriving the network-config
// writes no seed — a seed written without it would be kept by every later
// pass — and the start is retried.
//
// Mutation: log the error and write the seed anyway — a seed exists and the
// failure is not retryable.
func TestDomainXMLFor_UnreadableNetworkConfigIsRetried(t *testing.T) {
	stageSeedGenisoimage(t)
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, _, _ := sharedDiskReconciler(t, db)
	spec := &pb.VMSpec{Name: "vm1", Cpu: 1, MemoryMib: 512, Image: "ubuntu",
		Network: []*pb.NetworkAttachment{{Name: "brnet", Mac: "52:54:00:aa:00:01"}}}
	specJSON, _ := json.Marshal(spec)
	vm := corrosion.VMRecord{Name: "vm1", HostName: "node-a", Spec: string(specJSON), State: "running", CPUActual: 1, MemActual: 512}
	if err := corrosion.InsertVM(ctx, db, vm, []corrosion.InterfaceRecord{
		{VMName: "vm1", NetworkName: "brnet", MAC: "52:54:00:aa:00:01"}}, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Execute(ctx, `DROP TABLE networks`); err != nil {
		t.Fatal(err)
	}
	_, retryable, failure := r.domainXMLFor(ctx, vm, spec, nil)
	if !retryable || !strings.Contains(failure, "network-config") {
		t.Errorf("retryable=%v failure=%q, want a retryable failure naming the network-config", retryable, failure)
	}
	iso, _ := lv.SafeCloudInitISOPath(r.dataDir, "vm1")
	if _, err := os.Stat(iso); err == nil {
		t.Errorf("a seed was written without its network-config")
	}
}

// Round 1: a failover's rebuilt seed carries the vendor-data that has
// cloud-init apply the network-config again on boot, as the created seed
// does, unless the spec names its own network-config. Two NICs, so litevirt
// writes a network-config (a VM it writes none for gets no vendor-data).
//
// Mutation: drop VendorData from the reconciler's GenerateISO — red; write it
// for a spec network-config too — the override case goes red.
func TestDomainXMLFor_RebuiltSeedCarriesTheVendorData(t *testing.T) {
	dir := t.TempDir()
	script := `#!/bin/sh
out=""; src=""
while [ $# -gt 0 ]; do
  case "$1" in
    -output) out="$2"; shift ;;
    -volid) shift ;;
    -*) ;;
    *) src="$1" ;;
  esac
  shift
done
if [ -f "$src/vendor-data" ]; then cat "$src/vendor-data" > "$out"; else printf '<no vendor-data>' > "$out"; fi
`
	if err := os.WriteFile(filepath.Join(dir, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, _, _ := sharedDiskReconciler(t, db)
	r.SetNetworkProvision(func(context.Context, *corrosion.Client, string, compose.NetworkDef, string, string) (string, error) {
		return "", nil
	})
	for vm, override := range map[string]string{"vm1": "", "vm2": "version: 1\nconfig: []\n"} {
		macs := map[string][2]string{"vm1": {"52:54:00:ab:00:01", "52:54:00:ab:00:02"}, "vm2": {"52:54:00:ab:00:03", "52:54:00:ab:00:04"}}[vm]
		spec := &pb.VMSpec{Name: vm, Cpu: 1, MemoryMib: 512, Image: "ubuntu",
			CloudInit: &pb.CloudInitSpec{Networkconfig: override},
			Network:   []*pb.NetworkAttachment{{Name: "na", Mac: macs[0]}, {Name: "nb", Mac: macs[1]}}}
		specJSON, _ := json.Marshal(spec)
		rec := corrosion.VMRecord{Name: vm, HostName: "node-a", Spec: string(specJSON), State: "running", CPUActual: 1, MemActual: 512}
		if err := corrosion.InsertVM(ctx, db, rec, []corrosion.InterfaceRecord{
			{VMName: vm, NetworkName: "na", MAC: macs[0]}, {VMName: vm, NetworkName: "nb", Ordinal: 1, MAC: macs[1]}}, nil); err != nil {
			t.Fatal(err)
		}
		if _, _, failure := r.domainXMLFor(ctx, rec, spec, nil); failure != "" {
			t.Fatalf("domainXMLFor %s: %s", vm, failure)
		}
		iso, _ := lv.SafeCloudInitISOPath(r.dataDir, vm)
		b, err := os.ReadFile(iso)
		if err != nil {
			t.Fatalf("no seed rebuilt for %s: %v", vm, err)
		}
		want := cloudinit.NetworkUpdatesVendorData
		if override != "" {
			want = "<no vendor-data>"
		}
		if string(b) != want {
			t.Errorf("%s: vendor-data = %q, want %q", vm, b, want)
		}
	}
}

// Re-review N1, the lab-shaped sequence: a legacy VM (MAC-less spec) got a
// clean rebuild with the network update vendor-data on its old host, and its
// guest recorded it; `lv config --ip` then made X's entry undecidable; the host
// fails. The failover host has no seed of the VM's, so it cannot keep one: it
// writes a network-config cloud-init reads as disabled — it renders nothing,
// on this boot too, whatever update events the guest recorded — and the
// vendor-data that turns the per-boot re-render off. A seed with no
// network-config would have the guest render cloud-init's fallback (DHCP on
// one NIC) at its next boot and lose X's static address. The start is not
// retried for it, and an event says why.
//
// Where the failover host does hold the VM's own seed (one it wrote before,
// unstamped, of the VM's instance-id, that the VM's domain there attaches),
// that seed's network-config and vendor-data are kept. An unstamped seed of
// the VM's name that no domain of the VM's attaches (re-review 2 N4: a
// deleted VM of the name may have left it) is not kept.
//
// Mutation: write no network-config (the round-2 behaviour) — the first case
// goes red; write no vendor-data — red; ignore the VM's own seed — the second
// case goes red; OwnSeed without the cdrom check — the third case goes red.
func TestDomainXMLFor_AmbiguousNICsDisableNetworkRendering(t *testing.T) {
	if _, err := exec.LookPath("genisoimage"); err != nil {
		t.Skip("genisoimage not installed")
	}
	db := testReconcilerDB(t)
	ctx := context.Background()
	r, fake, _ := sharedDiskReconciler(t, db)
	r.SetNetworkProvision(func(context.Context, *corrosion.Client, string, compose.NetworkDef, string, string) (string, error) {
		return "", nil
	})
	const macX, macY = "52:54:00:aa:00:01", "52:54:00:aa:00:02"
	insert := func(vm string) (corrosion.VMRecord, *pb.VMSpec) {
		spec := &pb.VMSpec{Name: vm, Cpu: 1, MemoryMib: 512, Image: "ubuntu",
			Network: []*pb.NetworkAttachment{{Name: "n0", Ip: "10.0.0.10"}, {Name: "n1", Ip: "10.1.0.50"}}}
		specJSON, _ := json.Marshal(spec)
		rec := corrosion.VMRecord{Name: vm, HostName: "node-a", Spec: string(specJSON), State: "running", CPUActual: 1, MemActual: 512}
		if err := corrosion.InsertVM(ctx, db, rec, []corrosion.InterfaceRecord{
			{VMName: vm, NetworkName: "n0", MAC: macX, IP: "10.0.0.99"}, // `lv config --ip`: not the spec's .10
			{VMName: vm, NetworkName: "n1", Ordinal: 1, MAC: macY, IP: "10.1.0.50"},
		}, nil); err != nil {
			t.Fatal(err)
		}
		return rec, spec
	}

	rec, spec := insert("vm1")
	if _, _, failure := r.domainXMLFor(ctx, rec, spec, nil); failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	iso, _ := lv.SafeCloudInitISOPath(r.dataDir, "vm1")
	sd, err := cloudinit.ReadSeed(iso)
	if err != nil {
		t.Fatalf("no seed written: %v", err)
	}
	if sd.NetworkConfig != cloudinit.NetworkConfigDisabled || sd.VendorData != cloudinit.NetworkUpdatesOffVendorData {
		t.Errorf("failover seed: network-config %q vendor-data %q, want rendering disabled and the update events off", sd.NetworkConfig, sd.VendorData)
	}
	evs, err := corrosion.ListVMEvents(ctx, db, "vm1", 50, "")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range evs {
		if e.Type == "seed.not_rebuilt" && strings.Contains(e.Detail, "MAC") {
			found = true
		}
	}
	if !found {
		t.Errorf("no seed.not_rebuilt event: %+v", evs)
	}

	// The VM's own (unstamped) seed is here: its network-config and
	// vendor-data are kept.
	rec2, spec2 := insert("vm2")
	iso2, _ := lv.SafeCloudInitISOPath(r.dataDir, "vm2")
	ownNC := cloudinit.BuildV1([]cloudinit.StaticIface{{MAC: macX, Address: "10.0.0.10/24"}, {MAC: macY, Address: "10.1.0.50/24"}})
	if err := cloudinit.GenerateISO(cloudinit.Config{InstanceID: "vm2", LocalHostname: "vm2", NetworkConfig: ownNC,
		VendorData: cloudinit.NetworkUpdatesVendorData}, iso2); err != nil {
		t.Fatal(err)
	}
	if err := fake.DefineDomain(seedCDROMDomain("vm2", iso2)); err != nil {
		t.Fatal(err)
	}
	if _, _, failure := r.domainXMLFor(ctx, rec2, spec2, nil); failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	sd2, err := cloudinit.ReadSeed(iso2)
	if err != nil {
		t.Fatal(err)
	}
	if sd2.NetworkConfig != ownNC || sd2.VendorData != cloudinit.NetworkUpdatesVendorData {
		t.Errorf("the VM's own seed's network-config was not kept: %q %q", sd2.NetworkConfig, sd2.VendorData)
	}

	// An unstamped seed of the VM's name, which no domain here attaches: not
	// proven the VM's, so its network-config is not kept.
	rec3, spec3 := insert("vm3")
	iso3, _ := lv.SafeCloudInitISOPath(r.dataDir, "vm3")
	if err := cloudinit.GenerateISO(cloudinit.Config{InstanceID: "vm3", LocalHostname: "vm3", NetworkConfig: ownNC,
		VendorData: cloudinit.NetworkUpdatesVendorData}, iso3); err != nil {
		t.Fatal(err)
	}
	if _, _, failure := r.domainXMLFor(ctx, rec3, spec3, nil); failure != "" {
		t.Fatalf("domainXMLFor: %s", failure)
	}
	sd3, err := cloudinit.ReadSeed(iso3)
	if err != nil {
		t.Fatal(err)
	}
	if sd3.NetworkConfig != cloudinit.NetworkConfigDisabled || sd3.VendorData != cloudinit.NetworkUpdatesOffVendorData {
		t.Errorf("an unattached unstamped seed's network-config was kept: %q %q", sd3.NetworkConfig, sd3.VendorData)
	}
}

// seedCDROMDomain is a definition of domain vm whose cdrom is iso, as a start
// that attached the seed leaves it.
func seedCDROMDomain(vm, iso string) string {
	return "<domain type='kvm'><name>" + vm + "</name><memory unit='MiB'>512</memory><vcpu>1</vcpu><devices>" +
		"<disk type='file' device='cdrom'><driver name='qemu' type='raw'/><source file='" + iso + "'/><target dev='sdb' bus='sata'/><readonly/></disk>" +
		"</devices></domain>"
}

// Re-review 2 N4: a VM whose spec has no cloud-init is started with no seed,
// whatever file is at its path: one stamped for it (a migration target writes
// one when the source had a file there) or unstamped (a deleted VM of the
// name left it, user-data and all), even one its domain here attaches (an
// earlier release's start attached any file at the path). No create or clone
// writes a seed for such a VM, so none of these is one it was created with.
//
// Mutation: attach a seed stamped for the VM whatever its spec (the round-3
// rule) — "stamped" goes red.
func TestDomainXMLFor_ANoCloudInitVMGetsNoSeed(t *testing.T) {
	for _, tc := range []struct {
		name            string
		stamp, attached bool
	}{
		{"stamped", true, false},
		{"stamped, attached by its domain", true, true},
		{"unstamped", false, false},
		{"unstamped, attached by its domain", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testReconcilerDB(t)
			ctx := context.Background()
			r, fake, _ := sharedDiskReconciler(t, db)
			spec := &pb.VMSpec{Name: "x", Uuid: "uuid-new", Cpu: 1, MemoryMib: 512}
			specJSON, _ := json.Marshal(spec)
			rec := corrosion.VMRecord{Name: "x", HostName: "node-a", Spec: string(specJSON), State: "running", CPUActual: 1, MemActual: 512}
			if err := corrosion.InsertVM(ctx, db, rec, nil, nil); err != nil {
				t.Fatal(err)
			}
			iso, _ := lv.SafeCloudInitISOPath(r.dataDir, "x")
			if err := os.MkdirAll(filepath.Dir(iso), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(iso, []byte("#cloud-config\npassword: theirs\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.stamp {
				if err := cloudinit.StampSeed(iso, "uuid-new"); err != nil {
					t.Fatal(err)
				}
			}
			if tc.attached {
				if err := fake.DefineDomain(seedCDROMDomain("x", iso)); err != nil {
					t.Fatal(err)
				}
			}
			domXML, _, failure := r.domainXMLFor(ctx, rec, spec, nil)
			if failure != "" {
				t.Fatalf("domainXMLFor: %s", failure)
			}
			if strings.Contains(domXML, iso) {
				t.Errorf("a VM without cloud-init was given the seed at its path:\n%s", domXML)
			}
		})
	}
}
