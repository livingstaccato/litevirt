package grpcapi

// A dedicated migration network (migration.network in the daemon config), the
// counterpart of Proxmox's `migration: network=<CIDR>`.
//
// WHICH ADDRESS. A migration's data (guest memory, and for a storage migration
// the disk blocks) goes to an address on the destination. By default that is
// the host's cluster address. With migration.network set on the SOURCE, the
// source asks the target, in the EnsureDisks it already sends, for the address
// of its own inside that network (EnsureDisksRequest.migration_network, answered
// in EnsureDisksResponse.migration_address), so nothing about a host's address
// in that network is replicated or configured twice, and a target on an older
// build simply does not answer.
//
// WHAT STAYS ON THE CLUSTER ADDRESS. libvirt's control connection
// (qemu+tls://<cluster address>:16514) and the certificate name the QEMU
// stream is checked against. Both certificates, libvirt's server certificate and
// the migration certificate QEMU presents (internal/pki/migration.go), carry the
// host's cluster address as their IP SAN and nothing else, so a migration
// address in another network is in neither. The data channel is therefore
// pointed at the migration address (migrate_uri) while tls.destination keeps
// naming the cluster address: the certificate is verified exactly as it was, and
// no certificate has to be reissued or learn a second address.
//
// WHAT A MEMORY-ONLY MIGRATION NEEDS. Without a disk copy the guest's memory
// rides inside libvirt's own tunnel on the cluster address. Moving it onto the
// migration network means leaving the tunnel for QEMU's own stream, which is
// encrypted only when both hosts hold migration-TLS credentials. When one does
// not, the migration stays in the tunnel on the cluster address and says so,
// because the alternative is sending guest memory in plaintext over a network
// the operator may well consider trusted but never told the daemon so.
//
// FALLBACK. A host with no address in the network, a target that cannot answer,
// or an answer outside the network falls back to the cluster address, with a
// warning in the log and on the VM's event stream. A migration is never refused
// for want of the network.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
)

// ParseMigrationNetwork validates migration.network: an IPv4 CIDR that is not
// the whole address space. Cluster transport is IPv4-only, so an IPv6 network
// is refused here rather than failing every migration later.
func ParseMigrationNetwork(cidr string) (*net.IPNet, error) {
	ip, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("migration.network %q is not a CIDR (for example 10.20.0.0/24): %w", cidr, err)
	}
	if ip.To4() == nil {
		return nil, fmt.Errorf("migration.network %q is not IPv4: cluster transport is IPv4-only", cidr)
	}
	if ones, _ := n.Mask.Size(); ones == 0 {
		return nil, fmt.Errorf("migration.network %q matches every address, so it names no network", cidr)
	}
	return n, nil
}

// SetMigrationNetwork sets migration.network. Empty disables it. The daemon
// validates the value at start (ParseMigrationNetwork); a bad one here is
// ignored rather than half-applied.
func (s *Server) SetMigrationNetwork(cidr string) {
	if cidr == "" {
		s.migrationNetwork = ""
		return
	}
	if _, err := ParseMigrationNetwork(cidr); err != nil {
		slog.Error("migration network ignored", "error", err)
		return
	}
	s.migrationNetwork = cidr
}

// SetLocalIPsForTest replaces how this host lists its own addresses.
func (s *Server) SetLocalIPsForTest(fn func() ([]net.IP, error)) { s.localIPs = fn }

func (s *Server) listLocalIPs() ([]net.IP, error) {
	if s.localIPs != nil {
		return s.localIPs()
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	var out []net.IP
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out = append(out, n.IP)
		}
	}
	return out, nil
}

// localAddressIn returns this host's IPv4 address inside cidr, "" when it has
// none or cidr is not a valid migration network. With several the lowest is
// answered, so the same host always answers the same.
func (s *Server) localAddressIn(cidr string) string {
	n, err := ParseMigrationNetwork(cidr)
	if err != nil {
		return ""
	}
	ips, err := s.listLocalIPs()
	if err != nil {
		return ""
	}
	var in []string
	for _, ip := range ips {
		if v4 := ip.To4(); v4 != nil && !v4.IsLoopback() && !v4.IsUnspecified() && n.Contains(v4) {
			in = append(in, v4.String())
		}
	}
	if len(in) == 0 {
		return ""
	}
	sort.Strings(in)
	return in[0]
}

// migrationRoute is where a migration's data goes.
type migrationRoute struct {
	// addr is the destination of the data channel, unbracketed: the target's
	// cluster address, or its address in the migration network.
	addr string
	// direct moves a memory-only migration out of libvirt's tunnel onto QEMU's
	// own TLS stream to addr. Always false for a storage migration, which is
	// direct whatever the address.
	direct bool
	// onNetwork: addr is in the migration network.
	onNetwork bool
}

// chooseMigrationRoute decides, on the source, where vm's data goes, given the
// target's answer to EnsureDisks (migAddr, "" when it gave none) and whether
// both hosts hold migration-TLS credentials (bothTLS). It warns, in the log and
// on the VM's events, whenever a configured network is not used.
func (s *Server) chooseMigrationRoute(ctx context.Context, vmName string, target corrosion.HostRecord, migAddr string, withStorage, bothTLS bool) migrationRoute {
	fallback := migrationRoute{addr: target.Address}
	if s.migrationNetwork == "" {
		return fallback
	}
	warn := func(why string) migrationRoute {
		msg := fmt.Sprintf("migration.network %s is not used for the move of %s to %s: %s; "+
			"its data goes to %s, the address the host is dialed on",
			s.migrationNetwork, vmName, target.Name, why, target.Address)
		slog.Warn("migration: " + msg)
		s.recordVMEvent(ctx, vmName, "vm.migrate.network_fallback", "warn", msg)
		return fallback
	}
	if migAddr == "" {
		return warn(target.Name + " reported no address in that network (it has none there, or runs a build that predates the setting)")
	}
	// Defence in depth: the answer comes from a peer, and it is about to become
	// the address this host sends a guest's memory to.
	n, err := ParseMigrationNetwork(s.migrationNetwork)
	ip := net.ParseIP(migAddr)
	if err != nil || ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() || !n.Contains(ip) {
		return warn(fmt.Sprintf("%s answered %q, which is not an address in it", target.Name, migAddr))
	}
	if withStorage {
		return migrationRoute{addr: migAddr, onNetwork: true}
	}
	if !bothTLS {
		return warn("a memory-only migration leaves libvirt's tunnel to use it, and that stream is encrypted only when both hosts " +
			"hold migration-TLS credentials (`lv host install-migration-tls`); this one would otherwise be sent in plaintext")
	}
	return migrationRoute{addr: migAddr, direct: true, onNetwork: true}
}

// answerMigrationNetwork is the target's half, run in EnsureDisks.
func (s *Server) answerMigrationNetwork(req *pb.EnsureDisksRequest, resp *pb.EnsureDisksResponse) {
	if req.GetMigrationNetwork() == "" {
		return
	}
	resp.MigrationAddress = s.localAddressIn(req.GetMigrationNetwork())
}
