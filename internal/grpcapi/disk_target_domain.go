package grpcapi

import (
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// domainDiskTargets is every <target dev> vmName's domain holds, live and
// persistent: the disks vm_disks records, and the CD-ROMs it does not (the
// cloud-init seed, an installer). A hot-plug allocating from vm_disks alone
// handed a sata/scsi disk the seed's target. A domain that does not exist
// holds none. Any other read failure is returned: allocating without it could
// give the new disk a target the domain already uses.
func (s *Server) domainDiskTargets(vmName string) (map[string]bool, error) {
	out := map[string]bool{}
	if s.virt == nil {
		return out, nil
	}
	for _, view := range []struct {
		name string
		dump func(string) (string, error)
	}{
		{"live", s.virt.DumpXML},
		{"persistent", s.virt.DumpXMLInactive},
	} {
		x, err := view.dump(vmName)
		if err != nil {
			if lv.IsNoDomain(err) || lv.IsNotFound(err) {
				continue
			}
			return nil, status.Errorf(codes.Unavailable, "read the %s definition of %q to allocate a disk target: %v", view.name, vmName, err)
		}
		targets, err := lv.DomainDiskTargets(x)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "parse the %s definition of %q to allocate a disk target: %v", view.name, vmName, err)
		}
		for _, t := range targets {
			out[t] = true
		}
	}
	return out, nil
}
