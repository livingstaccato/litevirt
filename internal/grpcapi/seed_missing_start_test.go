package grpcapi

import (
	"fmt"
	"os"
	"strings"
	"testing"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/cloudinit"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// lab2-D2-proof F2: a live move's commit removes the source's seed
// (cleanupPostMigration), and a VM returned to the source after the commit
// (`lv doctor firmware-move --accept-source`), or cold-moved from it, has a
// domain there that boots from the missing file: libvirt refused the start
// with "Cannot access storage file". A start writes it again first, from the
// VM's spec and NIC rows (its user-data, its NIC's static address in the network-config),
// stamped for the VM, with the instance-id the guest booted with, so the
// guest is not a new instance: the VM's name, or the <name>-next a cutover
// created it under (review m3). A domain with no seed CD-ROM, or a VM whose
// spec has no cloud-init (review m2), gets none.
//
// Mutations: drop writeMissingSeedForStart from PrepareHardwareForStart — the
// seed is still missing after the start (cdrom); drop the spec check — a seed
// is written for the VM without cloud-init (no_cloud_init); always use the
// VM's name — instance-id x, not x-next (cutover_renamed).
func TestStart_WritesAMissingSeedTheDomainBootsFrom(t *testing.T) {
	for _, tc := range []struct {
		name       string
		cdrom      bool
		cloudInit  bool
		instanceID string // the guest's, before the commit removed the seed
		want       string // the instance-id written; "" for no seed
	}{
		{"cdrom", true, true, "x", "x"},
		{"cutover_renamed", true, true, "x-next", "x-next"},
		{"no_cdrom", false, true, "x", ""},
		{"no_cloud_init", true, false, "x", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := hotplugDiskServer(t)
			enableHardwareV2(t, s)
			useSeedISOWriter(t)
			spec := &pb.VMSpec{Name: "x", Uuid: "uuid-x", Cpu: 2, MemoryMib: 4096,
				Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:77:00:01", Ip: "10.0.0.10/24", Gateway: "10.0.0.1"}}}
			if tc.cloudInit {
				spec.Image = "ubuntu"
				spec.CloudInit = &pb.CloudInitSpec{Userdata: "#cloud-config\nhostname: x\n"}
			}
			iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{{VMName: "x", NetworkName: "lan", MAC: "52:54:00:77:00:01", IP: "10.0.0.10"}}, "stopped",
				cloudinit.Config{InstanceID: tc.instanceID, LocalHostname: "x", UserData: cloudinit.SpecUserData(spec)}, "uuid-x")
			cdrom := ""
			if tc.cdrom {
				cdrom = fmt.Sprintf(`<disk type="file" device="cdrom"><source file=%q/><target dev="sdz" bus="sata"/></disk>`, iso)
			}
			if err := s.virt.DefineDomain(fmt.Sprintf(`<domain type="kvm"><name>x</name><uuid>uuid-x</uuid><devices>%s</devices></domain>`, cdrom)); err != nil {
				t.Fatal(err)
			}
			// The commit of a live move away from here took it.
			s.cleanupPostMigration("x")
			if _, err := os.Stat(iso); err == nil {
				t.Fatal("fixture: the commit's cleanup left the seed")
			}
			if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "x"}); err != nil {
				t.Fatalf("start: %v", err)
			}
			_, statErr := os.Stat(iso)
			if tc.want == "" {
				if statErr == nil {
					t.Fatal("a seed was written for a VM that boots from none, or has no cloud-init")
				}
				return
			}
			if statErr != nil {
				t.Fatalf("the start did not write the missing seed the domain boots from: %v", statErr)
			}
			if !cloudinit.SeedIsFor(iso, "uuid-x") {
				t.Error("the written seed is not stamped for the VM")
			}
			sd := mustReadSeed(t, iso)
			if id := sd.InstanceID(); id != tc.want {
				t.Errorf("instance-id = %q, want %q (not a new instance)", id, tc.want)
			}
			if sd.UserData != spec.CloudInit.Userdata {
				t.Errorf("user-data = %q, want the spec's %q", sd.UserData, spec.CloudInit.Userdata)
			}
			if !strings.Contains(sd.NetworkConfig, "10.0.0.10") {
				t.Errorf("network-config does not give the VM's NIC its static address:\n%s", sd.NetworkConfig)
			}
		})
	}
}
