package health

import (
	"context"
	"encoding/json"
	"os"
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
	want, err := cloudinit.SeedNetworkConfig(ctx, db, "vm1", spec)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	if got != want || !strings.Contains(got, "address") || !strings.Contains(got, "10.212.0.7/24") ||
		strings.Contains(got, "172.40.0.99") {
		t.Errorf("rebuilt seed network-config:\n%s\nwant:\n%s", got, want)
	}
}
