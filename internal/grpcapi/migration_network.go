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
// WHAT IT CARRIES. Live moves (memory, and the disk blocks of a storage copy)
// and the disk stream of a cold move, which a stopped-VM migration, a drain's
// cold move and a cross-host clone all use. The cold stream is the peer
// connection's mTLS gRPC, so it is always encrypted; it is dialed at the
// migration address while the certificate is still checked against the cluster
// address (the same trick, grpc.WithAuthority), and the VM's ownership commit
// and every other call stay on the cluster address.
//
// ENCRYPTION. Nothing travels the migration network in the clear that a main
// build kept off it: a storage copy goes there only when it is encrypted
// (migration TLS on both hosts); an unencrypted copy, which the operator has
// allowed with migration.allow_unencrypted_storage, stays on the cluster
// address as it always was.
//
// BOTH ENDS. The source must hold an address in the network too: a source with
// none (the NIC is down or missing) would send to the target's migration
// address by the default route, out of whatever interface the kernel picks, so
// it falls back to the cluster address. The same goes for a host with no
// address there, a target that cannot answer, or an answer outside the network.
// The fallback is a warning in the log and on the VM's event stream, never a
// refusal.
//
// WHICH ADDRESS A TARGET ANSWERS. migration.address if the operator set one
// (inside the network), else the lowest address inside it that is not loopback,
// link-local, a load-balancer VIP, or on a bridge or virtual interface litevirt
// or libvirt owns: a floating address would send one host's data to another.
//
// WHICH NETWORKS ARE ACCEPTED. A private (RFC 1918) range that does not contain
// the host's cluster address or its default-route source address. Anything else
// would route migration data out the uplink or the cluster interface, and is
// refused at start unless migration.allow_any_network is set.

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sort"
	"strings"
	"time"

	"google.golang.org/grpc"

	pb "github.com/litevirt/litevirt/gen/litevirt/v1"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
	"github.com/litevirt/litevirt/internal/pki"
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

// privateIPv4 are the RFC 1918 ranges.
var privateIPv4 = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"} {
		_, n, _ := net.ParseCIDR(c)
		out = append(out, n)
	}
	return out
}()

// CheckMigrationNetwork refuses a migration network that would send migration
// data somewhere an operator did not mean: one that is not inside an RFC 1918
// range, or that contains one of hostAddrs (the host's cluster address and its
// default-route source address). allowAny is migration.allow_any_network, the
// explicit override of both rules.
func CheckMigrationNetwork(n *net.IPNet, allowAny bool, hostAddrs ...net.IP) error {
	if allowAny {
		return nil
	}
	inside := false
	for _, p := range privateIPv4 {
		po, _ := p.Mask.Size()
		no, _ := n.Mask.Size()
		if p.Contains(n.IP) && no >= po {
			inside = true
		}
	}
	if !inside {
		return fmt.Errorf("migration.network %s is not inside a private range (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16): "+
			"migration data would cross a public or unclassified network. If that is intended, set migration.allow_any_network: true", n)
	}
	for _, a := range hostAddrs {
		if a != nil && n.Contains(a) {
			return fmt.Errorf("migration.network %s contains this host's cluster or default-route address %s, so it is not a separate network "+
				"and its traffic could leave on the interface the cluster uses. Name the dedicated network, "+
				"or set migration.allow_any_network: true to use it anyway", n, a)
		}
	}
	return nil
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

// SetMigrationAddress sets migration.address: the address this host answers
// with, instead of choosing one, when a source asks for its address in the
// migration network. Empty chooses.
func (s *Server) SetMigrationAddress(addr string) { s.migrationAddress = addr }

// SetLocalIPsForTest replaces how this host lists its own addresses.
func (s *Server) SetLocalIPsForTest(fn func() ([]net.IP, error)) {
	s.localIPs = func() ([]localAddr, error) {
		ips, err := fn()
		out := make([]localAddr, 0, len(ips))
		for _, ip := range ips {
			out = append(out, localAddr{IP: ip})
		}
		return out, err
	}
}

// SetLocalAddrsForTest replaces how this host lists its own addresses, with the
// interface each is on.
func (s *Server) SetLocalAddrsForTest(fn func() ([]localAddr, error)) { s.localIPs = fn }

// localAddr is one of this host's addresses and the interface it is on.
type localAddr struct {
	IP    net.IP
	Iface string
}

func (s *Server) listLocalAddrs() ([]localAddr, error) {
	if s.localIPs != nil {
		return s.localIPs()
	}
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []localAddr
	for _, ifc := range ifs {
		addrs, aerr := ifc.Addrs()
		if aerr != nil {
			continue
		}
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				out = append(out, localAddr{IP: n.IP, Iface: ifc.Name})
			}
		}
	}
	return out, nil
}

// virtualIfacePrefixes are interfaces that are never a migration NIC: libvirt's
// and the container runtimes' bridges and the per-guest devices.
var virtualIfacePrefixes = []string{"lo", "virbr", "docker", "veth", "tap", "vnet", "vxlan", "lxc", "cni", "flannel"}

// floatingAddrs is what this host must not answer as its migration address: the
// load-balancer VIPs the cluster knows, and the bridges litevirt's own networks
// created, whose gateway addresses are the same on every host that has the
// network. A floating address moves; an answer that names it sends the data to
// whichever host holds it.
func (s *Server) floatingAddrs(ctx context.Context) (vips map[string]bool, bridges map[string]bool) {
	vips, bridges = map[string]bool{}, map[string]bool{}
	if rows, err := s.db.Query(ctx, `SELECT vip FROM lb_configs WHERE deleted_at IS NULL`); err == nil {
		for _, r := range rows {
			v := r.String("vip")
			if i := strings.IndexByte(v, '/'); i >= 0 {
				v = v[:i]
			}
			if v != "" {
				vips[v] = true
			}
		}
	}
	if nets, err := corrosion.ListNetworks(ctx, s.db); err == nil {
		for _, n := range nets {
			bridges[network.FlatBridgeName(n.Name)] = true
			bridges[network.IsolatedBridgeName(n.Name)] = true
		}
	}
	return vips, bridges
}

// localAddressIn returns this host's IPv4 address inside cidr, "" when it has
// none or cidr is not a valid migration network. migration.address, when set
// and inside the network, is the answer. Otherwise the lowest address that is a
// plain unicast address of a physical-looking interface (see floatingAddrs), so
// the same host always answers the same.
func (s *Server) localAddressIn(ctx context.Context, cidr string) string {
	n, err := ParseMigrationNetwork(cidr)
	if err != nil {
		return ""
	}
	if a := net.ParseIP(s.migrationAddress); a != nil && a.To4() != nil && n.Contains(a) {
		return a.To4().String()
	}
	addrs, err := s.listLocalAddrs()
	if err != nil {
		return ""
	}
	vips, bridges := s.floatingAddrs(ctx)
	var in []string
	for _, a := range addrs {
		v4 := a.IP.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsUnspecified() || v4.IsLinkLocalUnicast() || !n.Contains(v4) {
			continue
		}
		if vips[v4.String()] || bridges[a.Iface] {
			continue
		}
		virtual := false
		for _, p := range virtualIfacePrefixes {
			if a.Iface != "" && strings.HasPrefix(a.Iface, p) {
				virtual = true
			}
		}
		if !virtual {
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

// What a migration moves, which decides what the migration network needs.
type routeKind int

const (
	// routeMemory is a live move with no disk to copy: it leaves libvirt's
	// tunnel for QEMU's own stream, which must be TLS.
	routeMemory routeKind = iota
	// routeStorage is a live move that copies disks: QEMU's stream, which must
	// be TLS to use the network.
	routeStorage
	// routeCold is a stopped VM's move: the disk stream is mTLS gRPC already.
	routeCold
)

// chooseMigrationRoute decides, on the source, where vm's data goes, given the
// target's answer to EnsureDisks (migAddr, "" when it gave none) and whether
// both hosts hold migration-TLS credentials (bothTLS). It warns, in the log and
// on the VM's events, whenever a configured network is not used.
func (s *Server) chooseMigrationRoute(ctx context.Context, vmName string, target corrosion.HostRecord, migAddr string, kind routeKind, bothTLS bool) migrationRoute {
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
	// This host must hold an address in the network too: without one the kernel
	// would send the data to the target's migration address by the default route,
	// out of whatever interface that is.
	if s.localAddressIn(ctx, s.migrationNetwork) == "" {
		return warn("this host (" + s.hostName + ") has no address in that network, so the data would leave by the default route")
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
	switch kind {
	case routeCold:
		return migrationRoute{addr: migAddr, onNetwork: true}
	case routeStorage:
		if !bothTLS {
			return warn("the storage copy is not encrypted (a host has no migration-TLS credentials, `lv host install-migration-tls`), " +
				"and an unencrypted copy stays on the cluster address")
		}
		return migrationRoute{addr: migAddr, onNetwork: true}
	}
	if !bothTLS {
		return warn("a memory-only migration leaves libvirt's tunnel to use it, and that stream is encrypted only when both hosts " +
			"hold migration-TLS credentials (`lv host install-migration-tls`); this one would otherwise be sent in plaintext")
	}
	return migrationRoute{addr: migAddr, direct: true, onNetwork: true}
}

// answerMigrationNetwork is the target's half, run in EnsureDisks.
func (s *Server) answerMigrationNetwork(ctx context.Context, req *pb.EnsureDisksRequest, resp *pb.EnsureDisksResponse) {
	if req.GetMigrationNetwork() == "" {
		return
	}
	resp.MigrationAddress = s.localAddressIn(ctx, req.GetMigrationNetwork())
}

// SetMigrationDialForTest replaces the dial of a peer at its migration address.
func (s *Server) SetMigrationDialForTest(fn func(ctx context.Context, host, addr string) (pb.LiteVirtClient, func(), error)) {
	s.migrationDial = fn
}

// dialColdPeer dials targetHost for a cold move's disk stream: at its address in
// the migration network when diskAddr names one and that connection answers,
// else at its cluster address. Either way the certificate is checked against the
// cluster address (grpc.WithAuthority), which the host certificate carries.
// A connection that does not answer falls back, with the warning of every other
// fallback: the network being down is not a reason to refuse a move.
func (s *Server) dialColdPeer(ctx context.Context, targetHost, vmName, diskAddr string) (pb.LiteVirtClient, func(), error) {
	if diskAddr == "" {
		return s.dialPeer(ctx, targetHost)
	}
	fallback := func(why error) (pb.LiteVirtClient, func(), error) {
		msg := fmt.Sprintf("migration.network %s is not used for the disk copy of %s to %s: %v; it goes to the address the host is dialed on",
			s.migrationNetwork, vmName, targetHost, why)
		slog.Warn("migration: " + msg)
		s.recordVMEvent(ctx, vmName, "vm.migrate.network_fallback", "warn", msg)
		return s.dialPeer(ctx, targetHost)
	}
	var client pb.LiteVirtClient
	var closer func()
	if s.migrationDial != nil {
		c, cl, err := s.migrationDial(ctx, targetHost, diskAddr)
		if err != nil {
			return fallback(err)
		}
		client, closer = c, cl
	} else {
		h, err := corrosion.GetHost(ctx, s.db, targetHost)
		if err != nil || h == nil {
			return fallback(fmt.Errorf("target host record: %v", err))
		}
		conn, err := pki.PeerDial(s.pkiDir, corrosion.PeerTarget(diskAddr, h.GRPCPort), grpc.WithAuthority(h.Address))
		if err != nil {
			return fallback(err)
		}
		client, closer = pb.NewLiteVirtClient(conn), func() { _ = conn.Close() }
	}
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if _, err := client.Ping(pctx, &pb.PingRequest{}); err != nil {
		closer()
		return fallback(fmt.Errorf("it does not answer: %v", err))
	}
	return client, closer, nil
}
