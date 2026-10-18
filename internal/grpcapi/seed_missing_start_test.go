package grpcapi

import (
	"fmt"
	"os"
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
// VM's spec, stamped for the VM, with the VM's name as its instance-id so the
// guest is not a new instance. A domain with no seed CD-ROM gets none.
//
// Mutation: drop writeMissingSeedForStart from PrepareHardwareForStart — the
// seed is still missing after the start.
func TestStart_WritesAMissingSeedTheDomainBootsFrom(t *testing.T) {
	for _, withCDROM := range []bool{true, false} {
		t.Run(fmt.Sprintf("cdrom=%v", withCDROM), func(t *testing.T) {
			s := hotplugDiskServer(t)
			useSeedISOWriter(t)
			spec := &pb.VMSpec{Name: "x", Uuid: "uuid-x", Image: "ubuntu", Cpu: 2, MemoryMib: 4096,
				Network: []*pb.NetworkAttachment{{Name: "lan", Mac: "52:54:00:77:00:01"}}}
			iso := r2VM(t, s, spec, []corrosion.InterfaceRecord{{VMName: "x", NetworkName: "lan", MAC: "52:54:00:77:00:01"}}, "stopped",
				cloudinit.Config{InstanceID: "x", LocalHostname: "x", UserData: cloudinit.SpecUserData(spec)}, "uuid-x")
			cdrom := ""
			if withCDROM {
				cdrom = fmt.Sprintf(`<disk type="file" device="cdrom"><source file=%q/><target dev="sdz" bus="sata"/></disk>`, iso)
			}
			if err := s.virt.DefineDomain(fmt.Sprintf(`<domain type="kvm"><name>x</name><uuid>uuid-x</uuid><devices>%s</devices></domain>`, cdrom)); err != nil {
				t.Fatal(err)
			}
			// The commit of a live move away from here took it.
			if err := cloudinit.RemoveSeed(iso); err != nil {
				t.Fatal(err)
			}
			if _, err := s.StartVM(adminCtx(), &pb.StartVMRequest{Name: "x"}); err != nil {
				t.Fatalf("start: %v", err)
			}
			_, statErr := os.Stat(iso)
			if !withCDROM {
				if statErr == nil {
					t.Fatal("a seed was written for a domain that does not boot from one")
				}
				return
			}
			if statErr != nil {
				t.Fatalf("the start did not write the missing seed the domain boots from: %v", statErr)
			}
			if !cloudinit.SeedIsFor(iso, "uuid-x") {
				t.Error("the written seed is not stamped for the VM")
			}
			if id := mustReadSeed(t, iso).InstanceID(); id != "x" {
				t.Errorf("instance-id = %q, want the VM's name (not a new instance)", id)
			}
		})
	}
}
