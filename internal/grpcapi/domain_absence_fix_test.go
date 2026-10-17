package grpcapi

import (
	"errors"
	"fmt"
	golibvirt "github.com/digitalocean/go-libvirt"
	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/libvirtfake"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"testing"
)

func TestAttachDevice_TypedReadFailureNeverMeansDomainAbsent(t *testing.T) {
	for _, view := range []string{"live", "persistent"} {
		for _, tc := range []struct {
			name string
			err  error
		}{
			{"auth", golibvirt.Error{Code: uint32(golibvirt.ErrAuthFailed), Message: "certificate not found"}},
			{"system", fmt.Errorf("dump: %w", golibvirt.Error{Code: uint32(golibvirt.ErrSystemError), Message: "cannot find socket"})},
			{"snapshot", golibvirt.Error{Code: uint32(golibvirt.ErrNoDomainSnapshot), Message: "snapshot not found"}},
			{"checkpoint", golibvirt.Error{Code: uint32(golibvirt.ErrNoDomainCheckpoint), Message: "cannot find checkpoint"}},
		} {
			t.Run(view+"/"+tc.name, func(t *testing.T) {
				s := hotplugDiskServer(t)
				enableHardwareV2(t, s)
				ctx := adminCtx()
				seedDiskVM(t, s, "vm1", "running")
				f := s.virt.(*libvirtfake.Fake)
				f.SetInactiveXML("vm1", seedCDROMDomain)
				if view == "live" {
					f.FailDumpXML = func(string) error { return tc.err }
				} else {
					f.FailDumpXMLInactive = func(string) error { return tc.err }
				}
				_, err := s.AttachDevice(ctx, &pb.AttachDeviceRequest{VmName: "vm1", Disk: &pb.DiskSpec{Name: "data", Size: "1G", Bus: "sata"}})
				if status.Code(err) != codes.Unavailable {
					t.Errorf("unread %s definition must refuse Unavailable, got %v", view, err)
				}
				disks, err := corrosion.GetVMDisks(ctx, s.db, "vm1")
				if err != nil {
					t.Fatal(err)
				}
				if hasDiskName(disks, "data") {
					t.Errorf("unread definition allocated a durable disk: %+v", disks)
				}
				if vm := mustGetVM(t, s, "vm1"); vm.ActiveOperationID != "" {
					t.Errorf("unread definition admitted operation %q", vm.ActiveOperationID)
				}
			})
		}
	}
}

func TestDomainAbsence_PreservesDomainSpecificCompatibility(t *testing.T) {
	for _, err := range []error{
		fmt.Errorf("dump: %w", golibvirt.Error{Code: uint32(golibvirt.ErrNoDomain), Message: "missing"}),
		errors.New(`libvirtfake: domain "vm1" not found`),
		errors.New("Domain not found: no domain with matching name 'vm1'"),
		errors.New("no such domain: vm1"),
	} {
		if !domainAbsent(err) {
			t.Errorf("genuine domain absence refused: %v", err)
		}
	}
	for _, err := range []error{nil, errors.New("certificate not found"), errors.New("cannot find socket"), errors.New("snapshot not found in domain vm1")} {
		if domainAbsent(err) {
			t.Errorf("unproven domain absence accepted: %v", err)
		}
	}
}
