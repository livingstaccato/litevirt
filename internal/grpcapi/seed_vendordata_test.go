package grpcapi

import (
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
	"github.com/litevirt/litevirt/internal/qcow2"
)

const noVendorData = "<no vendor-data>"

// stageVendorDataGenisoimage stages a genisoimage whose "ISO" is the seed's
// vendor-data file verbatim, or noVendorData.
func stageVendorDataGenisoimage(t *testing.T) {
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
if [ -f "$src/vendor-data" ]; then cat "$src/vendor-data" > "$out"; else printf '` + noVendorData + `' > "$out"; fi
`
	if err := os.WriteFile(filepath.Join(dir, "genisoimage"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func seedVendorData(t *testing.T, s *Server, vm string) string {
	t.Helper()
	b, err := os.ReadFile(lv.CloudInitISOPath(s.dataDir, vm))
	if err != nil {
		t.Fatalf("read seed of %s: %v", vm, err)
	}
	return string(b)
}

// Round 1: every seed whose network-config litevirt writes carries the
// vendor-data that has cloud-init apply it again on boot and on hot-plug —
// at create (a cloud image with or without cloud-init in its spec), clone,
// and a migration target's rebuild. A spec that names its own network-config
// gets none: the guest's network is the operator's.
//
// Mutation: drop VendorData from either CreateVM seed — that case goes red;
// from CloneVM — the clone goes red; from EnsureCloudInit — the migration
// case goes red; write it for a spec network-config too — the override cases
// go red; write it with no network-config — the one-NIC case goes red.
func TestSeeds_CarryTheNetworkUpdatesVendorData(t *testing.T) {
	s := netcfgServer(t, map[string]compose.NetworkDef{"brnet": defBridgeDHCP, "brnet2": {Type: "bridge", Subnet: "172.41.0.0/24", DHCP: true}})
	stageVendorDataGenisoimage(t)
	ctx := adminCtx()
	// Two NICs: litevirt writes a network-config for them (one DHCP NIC gets
	// none, and no vendor-data either: review m1).
	nic := func(mac string) []*pb.NetworkAttachment {
		return []*pb.NetworkAttachment{{Name: "brnet", Model: "virtio", Mac: mac}, {Name: "brnet2", Model: "virtio", Mac: strings.Replace(mac, ":21:", ":2f:", 1)}}
	}

	auto := seedCreateRequest(t, s, "auto", "")
	auto.Spec.Network = nic("52:54:00:00:21:01")
	ud := seedCreateRequest(t, s, "ud", "#cloud-config\n{}\n")
	ud.Spec.Network = nic("52:54:00:00:21:02")
	own := seedCreateRequest(t, s, "own", "#cloud-config\n{}\n")
	own.Spec.Network = nic("52:54:00:00:21:03")
	own.Spec.CloudInit.Networkconfig = "version: 1\nconfig: []\n"
	one := seedCreateRequest(t, s, "one", "")
	one.Spec.Network = []*pb.NetworkAttachment{{Name: "brnet", Model: "virtio", Mac: "52:54:00:00:21:05"}}
	for _, tc := range []struct {
		req  *pb.CreateVMRequest
		want string
	}{
		{auto, cloudinit.NetworkUpdatesVendorData},
		{ud, cloudinit.NetworkUpdatesVendorData},
		{own, noVendorData},
		{one, noVendorData},
	} {
		if _, err := s.CreateVM(ctx, tc.req); err != nil {
			t.Fatalf("CreateVM %s: %v", tc.req.Spec.Name, err)
		}
		if got := seedVendorData(t, s, tc.req.Spec.Name); got != tc.want {
			t.Errorf("create %s: vendor-data = %q, want %q", tc.req.Spec.Name, got, tc.want)
		}
	}

	// Clone.
	srcDisk := s.images.DiskPath("src", "root")
	if err := os.MkdirAll(filepath.Dir(srcDisk), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := qcow2.Create(srcDisk, 1<<20, nil); err != nil {
		t.Fatal(err)
	}
	specJSON, _ := json.Marshal(&pb.VMSpec{Name: "src", Cpu: 1, MemoryMib: 512, Image: "ubuntu",
		CloudInit: &pb.CloudInitSpec{Userdata: "#cloud-config\n{}\n"},
		Network:   nic("52:54:00:00:21:04")})
	if err := corrosion.InsertVM(ctx, s.db,
		corrosion.VMRecord{Name: "src", HostName: "test-host", State: "stopped", Spec: string(specJSON)},
		[]corrosion.InterfaceRecord{{VMName: "src", NetworkName: "brnet", MAC: "52:54:00:00:21:04"},
			{VMName: "src", NetworkName: "brnet2", Ordinal: 1, MAC: "52:54:00:00:2f:04"}},
		[]corrosion.DiskRecord{{VMName: "src", DiskName: "root", HostName: "test-host", Path: srcDisk, SizeBytes: 1 << 20, StorageType: "local"}},
	); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CloneVM(ctx, &pb.CloneVMRequest{Source: "src", Target: "c1", Mode: "full"}); err != nil {
		t.Fatalf("CloneVM: %v", err)
	}
	if got := seedVendorData(t, s, "c1"); got != cloudinit.NetworkUpdatesVendorData {
		t.Errorf("clone: vendor-data = %q", got)
	}

	// A migration target's rebuild, for a VM whose seed it does not hold.
	peer := diskPeerCtx(t, s)
	for vm, override := range map[string]string{"mig": "", "migown": "version: 1\nconfig: []\n"} {
		spec, _ := json.Marshal(&pb.VMSpec{Name: vm, CloudInit: &pb.CloudInitSpec{Networkconfig: override}})
		if err := corrosion.InsertVM(ctx, s.db, corrosion.VMRecord{Name: vm, HostName: "other-host", State: "running", Spec: string(spec)}, nil, nil); err != nil {
			t.Fatal(err)
		}
		if _, err := s.EnsureCloudInit(peer, &pb.EnsureCloudInitRequest{VmName: vm, Networkconfig: "version: 2\n"}); err != nil {
			t.Fatalf("EnsureCloudInit %s: %v", vm, err)
		}
		want := cloudinit.NetworkUpdatesVendorData
		if override != "" {
			want = noVendorData
		}
		if got := seedVendorData(t, s, vm); got != want {
			t.Errorf("migration target %s: vendor-data = %q, want %q", vm, got, want)
		}
	}
}
