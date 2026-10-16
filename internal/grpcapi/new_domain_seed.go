package grpcapi

import (
	"github.com/litevirt/litevirt/internal/cloudinit"
	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// stampedSeedFor is the cloud-init seed on this host written for the VM
// named name whose spec uuid is uuid, or "" when this host has none. A
// builder of a new domain attaches it as CreateVM does. A seed stamped for
// another VM of the name, or unstamped, is never attached: it would boot that
// VM's user-data (cloudinit/seed_owner.go).
func (s *Server) stampedSeedFor(name, uuid string) string {
	iso, err := lv.SafeCloudInitISOPath(s.dataDir, name)
	if err != nil || !cloudinit.SeedIsFor(iso, uuid) {
		return ""
	}
	return iso
}
