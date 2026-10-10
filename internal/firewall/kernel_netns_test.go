//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The kernel tests load the rendered ruleset into a real nf_tables and push
// real frames through a real Linux bridge. They run in a private user and
// network and mount namespace (unshare -rnm), so they need no root and touch nothing on
// the host — but they need a kernel with nf_tables bridge support, the bridge
// and veth drivers, and nft and ip on PATH. Opt in with
// LITEVIRT_NFT_NETNS=1; the test re-executes itself inside the namespace.
const (
	netnsOptIn = "LITEVIRT_NFT_NETNS"
	netnsChild = "LITEVIRT_NFT_NETNS_CHILD"
)

// TestKernel_NICGuard is the parent: it re-runs the child tests under
// unshare and reports their output.
func TestKernel_NICGuard(t *testing.T) {
	if os.Getenv(netnsChild) == "1" {
		t.Skip("parent only")
	}
	if os.Getenv(netnsOptIn) != "1" {
		t.Skipf("set %s=1 to run the nf_tables kernel tests in a private namespace", netnsOptIn)
	}
	if _, err := exec.LookPath("unshare"); err != nil {
		t.Fatalf("%s=1 but unshare is not on PATH", netnsOptIn)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "unshare", "-rnm", os.Args[0], "-test.run", "^TestKernelChild_", "-test.v", "-test.count=1")
	cmd.Env = append(os.Environ(), netnsChild+"=1")
	out, err := cmd.CombinedOutput()
	t.Logf("namespace run:\n%s", out)
	if err != nil {
		t.Fatalf("kernel tests failed in the namespace: %v", err)
	}
	for _, child := range []string{"TestKernelChild_GuardDropsSpoofs", "TestKernelChild_RulesetLoads", "TestKernelChild_RulesHoldOnEveryPath"} {
		if !strings.Contains(string(out), "--- PASS: "+child) {
			t.Errorf("%s did not pass in the namespace", child)
		}
	}
}

func inNetns(t *testing.T) {
	t.Helper()
	if os.Getenv(netnsChild) != "1" {
		t.Skip("runs only inside the namespace TestKernel_NICGuard creates")
	}
}

func sh(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// bridgeLab is a bridge with two veth ports. A "guest" sends from gN, the
// bridge sees the frame arrive on hN (the port a VM's tap would be), and gM
// receives whatever the bridge forwards out hM.
type bridgeLab struct {
	guestMAC net.HardwareAddr
}

func newBridgeLab(t *testing.T) *bridgeLab {
	t.Helper()
	sh(t, "ip", "link", "add", "lvbr0", "type", "bridge", "stp_state", "0", "forward_delay", "0")
	for _, i := range []string{"0", "1"} {
		sh(t, "ip", "link", "add", "lvg"+i, "type", "veth", "peer", "name", "lvh"+i)
		sh(t, "ip", "link", "set", "lvh"+i, "master", "lvbr0")
		sh(t, "ip", "link", "set", "lvh"+i, "up")
		sh(t, "ip", "link", "set", "lvg"+i, "up")
	}
	sh(t, "ip", "link", "set", "lvbr0", "up")
	ifc, err := net.InterfaceByName("lvg0")
	if err != nil {
		t.Fatal(err)
	}
	return &bridgeLab{guestMAC: ifc.HardwareAddr}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func packetSocket(t *testing.T, dev string) int {
	t.Helper()
	ifc, err := net.InterfaceByName(dev)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		t.Fatalf("packet socket: %v", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrLinklayer{Protocol: htons(syscall.ETH_P_ALL), Ifindex: ifc.Index}); err != nil {
		t.Fatalf("bind %s: %v", dev, err)
	}
	tv := syscall.NsecToTimeval(int64(50 * time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd
}

// delivered sends frame from the guest end of port 0 and reports whether it
// came out of port 1. Each frame carries a unique marker, so the kernel's own
// traffic on the link can never be mistaken for it.
func (l *bridgeLab) delivered(t *testing.T, frame []byte) bool {
	t.Helper()
	tx := packetSocket(t, "lvg0")
	rx := packetSocket(t, "lvg1")
	// Exactly 32 bytes: the IPv4 and IPv6 headers built below count 32 bytes
	// of payload for it, and a length field longer than the frame makes the
	// kernel treat the packet as malformed rather than parse it.
	marker := []byte(fmt.Sprintf("LVMARK%026d", time.Now().UnixNano()))
	frame = append(append([]byte(nil), frame...), marker...)
	ifc, _ := net.InterfaceByName("lvg0")
	if err := syscall.Sendto(tx, frame, 0, &syscall.SockaddrLinklayer{Ifindex: ifc.Index, Halen: 6}); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 4096)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		n, _, err := syscall.Recvfrom(rx, buf, 0)
		if err != nil {
			continue
		}
		if bytes.Contains(buf[:n], marker) {
			return true
		}
	}
	return false
}

var bcast = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

func ether(src net.HardwareAddr, etype uint16, payload []byte) []byte {
	f := append(append([]byte(nil), bcast...), src...)
	f = binary.BigEndian.AppendUint16(f, etype)
	return append(f, payload...)
}

func ipv4UDP(src, dst string, sport, dport uint16) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], 8+32) // room for the marker
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], uint16(20+8+32))
	h[8] = 64
	h[9] = 17
	copy(h[12:], net.ParseIP(src).To4())
	copy(h[16:], net.ParseIP(dst).To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
	return append(h, udp...)
}

func arpRequest(sha net.HardwareAddr, spa, tpa string) []byte {
	a := []byte{0, 1, 8, 0, 6, 4, 0, 1}
	a = append(a, sha...)
	a = append(a, net.ParseIP(spa).To4()...)
	a = append(a, make([]byte, 6)...)
	return append(a, net.ParseIP(tpa).To4()...)
}

func ipv6(src, dst string, next byte, payload []byte) []byte {
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], uint16(len(payload)+32))
	h[6] = next
	h[7] = 255
	copy(h[8:], net.ParseIP(src).To16())
	copy(h[24:], net.ParseIP(dst).To16())
	return append(h, payload...)
}

func icmpv6(typ byte, body []byte) []byte { return append([]byte{typ, 0, 0, 0}, body...) }

func neighborAdvert(target string) []byte {
	return icmpv6(136, append([]byte{0x20, 0, 0, 0}, net.ParseIP(target).To16()...))
}

func udp6(sport, dport uint16) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], 8+32)
	return u
}

// TestKernelChild_GuardDropsSpoofs pushes forged and honest frames through a
// guarded bridge port and checks what the kernel forwards. It then removes the
// guard and checks the applier deleted the table and the forgeries pass, which
// proves the guard — and nothing else in the namespace — was dropping them.
func TestKernelChild_GuardDropsSpoofs(t *testing.T) {
	inNetns(t)
	l := newBridgeLab(t)
	mac := l.guestMAC
	foreign := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}

	plan := Plan{NICs: []NICBinding{{
		NICDev: "lvh0", VMName: "guest",
		Guard: &NICGuard{MAC: mac.String(), V4: []string{"10.0.0.5"}, V6: []string{"2001:db8::5"}},
	}}}
	a := NewApplier(NftBinary{})
	if _, err := a.Apply(context.Background(), plan); err != nil {
		t.Fatalf("apply guarded plan: %v", err)
	}
	t.Logf("loaded:\n%s", sh(t, "nft", "list", "table", "bridge", NICTableName))

	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"own IPv4 address", ether(mac, 0x0800, ipv4UDP("10.0.0.5", "10.0.0.9", 4000, 5000)), true},
		{"spoofed IPv4 source", ether(mac, 0x0800, ipv4UDP("10.0.0.99", "10.0.0.9", 4000, 5000)), false},
		{"foreign source MAC", ether(foreign, 0x0800, ipv4UDP("10.0.0.5", "10.0.0.9", 4000, 5000)), false},
		{"DHCP discover from 0.0.0.0", ether(mac, 0x0800, ipv4UDP("0.0.0.0", "255.255.255.255", 68, 67)), true},
		{"DHCP server reply", ether(mac, 0x0800, ipv4UDP("10.0.0.5", "255.255.255.255", 67, 68)), false},
		{"honest ARP", ether(mac, 0x0806, arpRequest(mac, "10.0.0.5", "10.0.0.9")), true},
		{"ARP claiming another IP", ether(mac, 0x0806, arpRequest(mac, "10.0.0.99", "10.0.0.9")), false},
		{"ARP claiming another MAC", ether(mac, 0x0806, arpRequest(foreign, "10.0.0.5", "10.0.0.9")), false},
		{"VLAN-tagged frame", ether(mac, 0x8100, append([]byte{0, 10, 8, 0}, ipv4UDP("10.0.0.99", "10.0.0.9", 1, 2)...)), false},
		{"own IPv6 address", ether(mac, 0x86dd, ipv6("2001:db8::5", "2001:db8::9", 17, udp6(4000, 5000))), true},
		{"link-local IPv6", ether(mac, 0x86dd, ipv6("fe80::5", "ff02::1", 17, udp6(4000, 5000))), true},
		{"spoofed IPv6 source", ether(mac, 0x86dd, ipv6("2001:db8::99", "2001:db8::9", 17, udp6(4000, 5000))), false},
		{"router advertisement", ether(mac, 0x86dd, ipv6("fe80::5", "ff02::1", 58, icmpv6(134, make([]byte, 12)))), false},
		{"DHCPv6 server reply", ether(mac, 0x86dd, ipv6("fe80::5", "fe80::9", 17, udp6(547, 546))), false},
		{"honest neighbour advert", ether(mac, 0x86dd, ipv6("fe80::5", "ff02::1", 58, neighborAdvert("2001:db8::5"))), true},
		{"neighbour advert for another address", ether(mac, 0x86dd, ipv6("fe80::5", "ff02::1", 58, neighborAdvert("2001:db8::99"))), false},
	}
	for _, c := range cases {
		if got := l.delivered(t, c.frame); got != c.want {
			t.Errorf("%s: delivered=%v, want %v", c.name, got, c.want)
		}
	}

	// Unguard: the table must go, and the forgeries must now pass.
	if _, err := a.Apply(context.Background(), Plan{NICs: []NICBinding{{NICDev: "lvh0", VMName: "guest"}}}); err != nil {
		t.Fatalf("apply unguarded plan: %v", err)
	}
	if err := exec.Command("nft", "list", "table", "bridge", NICTableName).Run(); err == nil {
		t.Fatal("the guard table outlived the last guarded NIC")
	}
	for _, c := range cases {
		if !c.want && !l.delivered(t, c.frame) {
			t.Errorf("%s: still dropped with no guard loaded — the drop above was not the guard's", c.name)
		}
	}
}

// TestKernelChild_RulesetLoads: the IPv6 rule forms and the ICMPv6 essentials
// are accepted by a real nft, so none of them can poison the atomic replace.
func TestKernelChild_RulesetLoads(t *testing.T) {
	inNetns(t)
	plan := Plan{
		DefaultDeny: true,
		IPSets:      []IPSet{{Name: "admins", CIDRs: []string{"10.0.0.0/8", "2001:db8::/32", "2001:db8:1::/48"}}},
		ClusterRules: []Rule{
			{Direction: Ingress, Proto: "icmpv6", Action: Accept},
			{Direction: Ingress, Proto: "icmpv6", CIDR: "fd00::/8", Action: Accept},
			{Direction: Egress, Proto: "gre", CIDR: "2001:db8::/32", Action: Drop},
			{Direction: Ingress, Proto: "icmp", CIDR: "@admins", Action: Accept},
			{Direction: Ingress, Proto: "gre", CIDR: "@admins", Action: Accept},
		},
		SecurityGroups: []SecurityGroup{{Name: "ssh", Rules: []Rule{
			{Direction: Ingress, Proto: "tcp", PortRange: "22", CIDR: "@admins", Action: Accept},
			{Direction: Egress, Proto: "udp", PortRange: "53", CIDR: "2001:db8:53::1", Action: Accept},
		}}},
		NICs: []NICBinding{{NICDev: "vnet9", VMName: "vm", SecurityGroups: []string{"ssh"},
			Guard: &NICGuard{MAC: "52:54:00:aa:bb:cc", V4: []string{"10.0.0.0/24", "10.0.0.5"}, V6: []string{"2001:db8::/64"}}}},
	}
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), plan); err != nil {
		t.Fatalf("a real nft refused the ruleset: %v", err)
	}
	// Applying twice must replace, not merge.
	a := NewApplier(NftBinary{})
	for i := 0; i < 2; i++ {
		a.Reset()
		if _, err := a.Apply(context.Background(), plan); err != nil {
			t.Fatalf("re-apply %d: %v", i, err)
		}
	}
	if n := strings.Count(sh(t, "nft", "list", "table", "bridge", NICTableName), "jump guard_vnet9"); n != 1 {
		t.Errorf("guard dispatch rule appears %d times after re-apply, want 1", n)
	}
}

// guestLab is a host network namespace with real guest network stacks behind
// two bridges: gwbr0 (10.20.0.0/24) and gwbr1 (10.21.0.0/24), the host the
// gateway (.254) of both and routing between them. Guest g's bridge port is
// p<g>, the device a VM's tap would be.
type guestLab struct{}

func newGuestLab(t *testing.T, guests map[string]string) *guestLab {
	t.Helper()
	sh(t, "mount", "-t", "tmpfs", "tmpfs", "/run")
	sh(t, "mkdir", "-p", "/run/netns")
	sh(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	for i, br := range []string{"gwbr0", "gwbr1"} {
		sh(t, "ip", "link", "add", br, "type", "bridge", "stp_state", "0", "forward_delay", "0")
		sh(t, "ip", "addr", "add", fmt.Sprintf("10.2%d.0.254/24", i), "dev", br)
		sh(t, "ip", "link", "set", br, "up")
	}
	for g, addr := range guests {
		br := "gwbr0"
		gw := "10.20.0.254"
		if strings.HasPrefix(addr, "10.21.") {
			br, gw = "gwbr1", "10.21.0.254"
		}
		sh(t, "ip", "netns", "add", g)
		sh(t, "ip", "link", "add", "p"+g, "type", "veth", "peer", "name", "eth0", "netns", g)
		sh(t, "ip", "link", "set", "p"+g, "master", br)
		sh(t, "ip", "link", "set", "p"+g, "up")
		sh(t, "ip", "-n", g, "addr", "add", addr+"/24", "dev", "eth0")
		sh(t, "ip", "-n", g, "link", "set", "eth0", "up")
		sh(t, "ip", "-n", g, "link", "set", "lo", "up")
		sh(t, "ip", "-n", g, "route", "add", "default", "via", gw)
	}
	return &guestLab{}
}

// ping reports whether from ("" = the host) gets an echo reply from to.
func (*guestLab) ping(from, to string) bool {
	args := []string{"ping", "-c", "1", "-W", "1", to}
	if from != "" {
		args = append([]string{"ip", "netns", "exec", from}, args...)
	}
	return exec.Command(args[0], args[1:]...).Run() == nil
}

// TestKernelChild_RulesHoldOnEveryPath pushes real traffic between real guest
// network stacks and checks every path a per-NIC rule must hold on: guest to
// guest on one bridge, host to guest, routed into a guest, guest to host and
// routed out of a guest — then that the allowed paths still work.
//
// This namespace cannot load nf_conntrack_bridge, so replies are not tracked
// here: every case is built so no reply crosses a rule (the stateful half is
// the e2e case, tests/e2e TestFirewall_TrafficBetweenVMs).
func TestKernelChild_RulesHoldOnEveryPath(t *testing.T) {
	inNetns(t)
	l := newGuestLab(t, map[string]string{
		"ga": "10.20.0.1", // may send icmp (an explicit egress accept)
		"gb": "10.20.0.2", // may not RECEIVE icmp
		"ge": "10.20.0.5", // no rules
		"gc": "10.21.0.3", // may not SEND icmp
		"gd": "10.21.0.4", // no rules
	})
	nic := func(g string, sgs ...string) NICBinding {
		br := "gwbr0"
		if g == "gc" || g == "gd" {
			br = "gwbr1"
		}
		return NICBinding{NICDev: "p" + g, VMName: g, Bridge: br, SecurityGroups: sgs}
	}
	plan := Plan{
		SecurityGroups: []SecurityGroup{
			{Name: "no-icmp-in", Rules: []Rule{{Direction: Ingress, Proto: "icmp", Action: Drop}}},
			{Name: "no-icmp-out", Rules: []Rule{{Direction: Egress, Proto: "icmp", Action: Drop}}},
			// The sender explicitly allowing icmp out must not let it past
			// the receiver's ingress drop.
			{Name: "icmp-out-ok", Rules: []Rule{{Direction: Egress, Proto: "icmp", Action: Accept}}},
		},
		NICs: []NICBinding{nic("ga", "icmp-out-ok"), nic("gb", "no-icmp-in"), nic("ge"), nic("gc", "no-icmp-out"), nic("gd")},
	}
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), plan); err != nil {
		t.Fatalf("apply: %v", err)
	}
	for _, c := range []struct {
		name     string
		from, to string
		want     bool
	}{
		{"guest to guest, same bridge, into a NIC that refuses icmp", "ga", "10.20.0.2", false},
		{"host to a NIC that refuses icmp", "", "10.20.0.2", false},
		{"routed into a NIC that refuses icmp", "gd", "10.20.0.2", false},
		{"a NIC that may not send icmp, to the host", "gc", "10.21.0.254", false},
		{"a NIC that may not send icmp, same bridge", "gc", "10.21.0.4", false},
		{"a NIC that may not send icmp, routed out", "gc", "10.20.0.1", false},
		{"allowed: guest to guest, same bridge", "ga", "10.20.0.5", true},
		{"allowed: guest to host", "ga", "10.20.0.254", true},
		{"allowed: host to guest", "", "10.20.0.5", true},
		{"allowed: routed between bridges", "ga", "10.21.0.4", true},
	} {
		if got := l.ping(c.from, c.to); got != c.want {
			t.Errorf("%s (%s -> %s): reached=%v, want %v", c.name, c.from, c.to, got, c.want)
		}
	}
	if t.Failed() {
		t.Logf("ruleset:\n%s", sh(t, "nft", "list", "ruleset"))
	}

	// Remove the rules: everything must pass, so the drops above were the
	// rules' and not the lab's.
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), Plan{}); err != nil {
		t.Fatalf("apply empty: %v", err)
	}
	for _, c := range [][2]string{{"ga", "10.20.0.2"}, {"", "10.20.0.2"}, {"gc", "10.21.0.254"}, {"gc", "10.20.0.1"}} {
		if !l.ping(c[0], c[1]) {
			t.Errorf("%s -> %s still fails with no rules loaded", c[0], c[1])
		}
	}
}
