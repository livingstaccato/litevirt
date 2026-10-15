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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
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
	// Loading a module changes the host, which a test must never do: the
	// kernel autoloads one the moment a ruleset uses it. Every module the
	// rulesets below need must already be loaded (or built in), or the tests
	// skip, saying which.
	if missing := missingModules(kernelTestModules...); len(missing) > 0 {
		t.Skipf("not running the kernel tests: they would make the kernel load %v, which is not loaded on this host; "+
			"prove these properties on a lab VM instead", missing)
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
	for _, child := range []string{"TestKernelChild_GuardDropsSpoofs", "TestKernelChild_RulesetLoads",
		"TestKernelChild_RulesHoldOnEveryPath", "TestKernelChild_DefaultDenyAndBypasses",
		"TestKernelChild_VLANToNICAndTrunk"} {
		if !strings.Contains(string(out), "--- PASS: "+child) {
			t.Errorf("%s did not pass in the namespace", child)
		}
	}
	// Children with their own module list skip on their own when one is
	// missing (saying which); they must not fail or vanish.
	for _, child := range []string{"TestKernelChild_CompatCorpusLoads"} {
		if !strings.Contains(string(out), "--- PASS: "+child) && !strings.Contains(string(out), "--- SKIP: "+child) {
			t.Errorf("%s neither passed nor skipped in the namespace", child)
		}
	}
}

// kernelTestModules are the modules the rulesets these tests load make the
// kernel use. The rulesets avoid every other one (no inet reject, no log, no
// limit), so nothing else can be autoloaded.
var kernelTestModules = []string{"nf_tables", "nf_conntrack", "nft_ct", "nf_conntrack_bridge", "nft_meta_bridge", "bridge", "veth"}

// missingModules lists the named modules that are neither loaded nor built in.
func missingModules(names ...string) []string {
	loaded, _ := os.ReadFile("/proc/modules")
	var uts syscall.Utsname
	_ = syscall.Uname(&uts)
	var rel []byte
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		rel = append(rel, byte(c))
	}
	builtin, _ := os.ReadFile("/lib/modules/" + string(rel) + "/modules.builtin")
	var out []string
	for _, n := range names {
		if bytes.Contains(loaded, []byte("\n"+n+" ")) || bytes.HasPrefix(loaded, []byte(n+" ")) ||
			bytes.Contains(builtin, []byte("/"+n+".ko")) {
			continue
		}
		out = append(out, n)
	}
	return out
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
	otherMAC net.HardwareAddr
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
	ifc1, err := net.InterfaceByName("lvg1")
	if err != nil {
		t.Fatal(err)
	}
	return &bridgeLab{guestMAC: ifc.HardwareAddr, otherMAC: ifc1.HardwareAddr}
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
	return l.deliveredFrom(t, "lvg0", "lvg1", frame)
}

func (l *bridgeLab) deliveredFrom(t *testing.T, from, to string, frame []byte) bool {
	t.Helper()
	tx := packetSocket(t, from)
	rx := packetSocket(t, to)
	// Exactly 32 bytes: the IPv4 and IPv6 headers built below count 32 bytes
	// of payload for it, and a length field longer than the frame makes the
	// kernel treat the packet as malformed rather than parse it.
	marker := []byte(fmt.Sprintf("LVMARK%026d", time.Now().UnixNano()))
	frame = append(append([]byte(nil), frame...), marker...)
	ifc, _ := net.InterfaceByName(from)
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

// deliveredWhole is deliveredFrom for a frame that must go out at its exact
// length (no marker appended): it reports whether a frame byte-identical to
// it came out of to. The frames sent this way carry a zero checksum, which
// the kernel never sends, so its own traffic cannot match.
func (l *bridgeLab) deliveredWhole(t *testing.T, from, to string, frame []byte) bool {
	t.Helper()
	tx := packetSocket(t, from)
	rx := packetSocket(t, to)
	ifc, _ := net.InterfaceByName(from)
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
		if n >= len(frame) && bytes.Equal(buf[:len(frame)], frame) {
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

// ipv6Exact is ipv6 with a payload length that counts the payload alone, for
// frames sent without the marker (deliveredWhole).
func ipv6Exact(src, dst string, next byte, payload []byte) []byte {
	f := ipv6(src, dst, next, payload)
	binary.BigEndian.PutUint16(f[4:], uint16(len(payload)))
	return f
}

func icmpv6(typ byte, body []byte) []byte { return append([]byte{typ, 0, 0, 0}, body...) }

func neighborAdvert(target string) []byte {
	return icmpv6(136, append([]byte{0x20, 0, 0, 0}, net.ParseIP(target).To16()...))
}

// neighborSolicit is an NS for target carrying a source link-layer address
// option for sll.
func neighborSolicit(target string, sll net.HardwareAddr) []byte {
	body := append([]byte{0, 0, 0, 0}, net.ParseIP(target).To16()...)
	body = append(body, 1, 1)
	return icmpv6(135, append(body, sll...))
}

func udp6(sport, dport uint16) []byte {
	u := make([]byte, 8)
	binary.BigEndian.PutUint16(u[0:], sport)
	binary.BigEndian.PutUint16(u[2:], dport)
	binary.BigEndian.PutUint16(u[4:], 8+32)
	return u
}

// icmpv6Packet is an exact-length IPv6 packet (hop limit 255) carrying msg as
// ICMPv6, with a valid checksum: a frame conntrack would call invalid is
// dropped by the forward chain in enforce mode whatever the guard does, which
// would make a "dropped" row pass for the wrong reason (lab 1 C).
func icmpv6Packet(src, dst string, msg []byte) []byte {
	p := ipv6Exact(src, dst, 58, msg)
	body := p[40:]
	body[2], body[3] = 0, 0
	var sum uint32
	add := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	add(p[8:40]) // source and destination
	add([]byte{0, 0, byte(len(body) >> 8), byte(len(body)), 0, 0, 0, 58})
	add(body)
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(body[2:], ^uint16(sum))
	return p
}

// routerAdvert is a router advertisement with no options.
func routerAdvert() []byte {
	return icmpv6(134, []byte{64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0})
}

// neighborAdvertTLL is a neighbour advertisement for target carrying a target
// link-layer address option for tll.
func neighborAdvertTLL(target string, tll net.HardwareAddr) []byte {
	body := append([]byte{0x20, 0, 0, 0}, net.ParseIP(target).To16()...)
	body = append(body, 2, 1)
	return icmpv6(136, append(body, tll...))
}

var flowNonce atomic.Uint32

// deliveredV6 sends the IPv6 packet pkt from src's port, untagged (vid < 0)
// or in one 802.1Q tag (VID 0 is a priority tag), and reports whether it came
// out of to. The packet goes at its exact length (the marker the other cases
// append would be trimmed, or would count against the guard's ND length cap),
// so it is told apart by a fresh flow label, which the checksum does not
// cover, and found by the whole IPv6 packet: a receiving packet socket sees
// the frame with its tag held outside the data.
func (l *bridgeLab) deliveredV6(t *testing.T, from, to string, src net.HardwareAddr, vid int, pkt []byte) bool {
	t.Helper()
	p := append([]byte(nil), pkt...)
	n := flowNonce.Add(1)&0xfffff | 0x80000
	p[1] = p[1]&0xf0 | byte(n>>16)
	p[2], p[3] = byte(n>>8), byte(n)
	frame := ether(src, 0x86dd, p)
	if vid >= 0 {
		frame = taggedType(src, 0x8100, 0x86dd, p, uint16(vid))
	}
	tx := packetSocket(t, from)
	rx := packetSocket(t, to)
	ifc, _ := net.InterfaceByName(from)
	if err := syscall.Sendto(tx, frame, 0, &syscall.SockaddrLinklayer{Ifindex: ifc.Index, Halen: 6}); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 4096)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		k, _, err := syscall.Recvfrom(rx, buf, 0)
		if err != nil {
			continue
		}
		if bytes.Contains(buf[:k], p) {
			return true
		}
	}
	return false
}

// TestKernelChild_GuardDropsSpoofs pushes forged and honest frames through a
// guarded bridge port and checks what the kernel forwards: first with the
// guest's exact address, then confined to its subnet with the gateway and a
// neighbour's address excluded. It then checks tagged frames from an
// UNGUARDED NIC are dropped, and finally removes every NIC and checks the
// table is gone and the forgeries pass — so the guard, and nothing else in the
// namespace, was dropping them.
//
// The guard phases run in observe mode: guards are enforced in every mode,
// and observe keeps the table's conntrack-invalid rule from dropping the
// hand-built frames (whose UDP checksums are not filled in) for a reason that
// is not the guard's.
func TestKernelChild_GuardDropsSpoofs(t *testing.T) {
	inNetns(t)
	l := newBridgeLab(t)
	mac := l.guestMAC
	ll, _ := eui64LinkLocal(mac.String())
	foreign := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}

	apply := func(p Plan) *Applier {
		a := NewApplier(NftBinary{})
		if _, err := a.Apply(context.Background(), p); err != nil {
			t.Fatalf("apply: %v", err)
		}
		return a
	}
	other := NICBinding{NICDev: "lvh1", VMName: "other"}
	apply(Plan{NICMode: NICModeObserve, NICs: []NICBinding{{
		NICDev: "lvh0", VMName: "guest",
		Guard: &NICGuard{MAC: mac.String(), V4: []string{"10.0.0.5"}, V6: []string{"2001:db8::5"}},
	}, other}})
	t.Logf("loaded:\n%s", sh(t, "nft", "list", "table", "bridge", NICTableName))

	type tc struct {
		name  string
		frame []byte
		want  bool
	}
	run := func(cases []tc) {
		for _, c := range cases {
			if got := l.delivered(t, c.frame); got != c.want {
				t.Errorf("%s: delivered=%v, want %v", c.name, got, c.want)
			}
		}
	}
	exact := []tc{
		{"own IPv4 address", ether(mac, 0x0800, ipv4UDP("10.0.0.5", "10.0.0.9", 4000, 5000)), true},
		{"spoofed IPv4 source", ether(mac, 0x0800, ipv4UDP("10.0.0.99", "10.0.0.9", 4000, 5000)), false},
		{"foreign source MAC", ether(foreign, 0x0800, ipv4UDP("10.0.0.5", "10.0.0.9", 4000, 5000)), false},
		{"DHCP discover from 0.0.0.0", ether(mac, 0x0800, ipv4UDP("0.0.0.0", "255.255.255.255", 68, 67)), true},
		{"DHCP server reply", ether(mac, 0x0800, ipv4UDP("10.0.0.5", "255.255.255.255", 67, 68)), false},
		{"DHCP reply from another source port", ether(mac, 0x0800, ipv4UDP("10.0.0.5", "255.255.255.255", 9999, 68)), false},
		{"honest ARP", ether(mac, 0x0806, arpRequest(mac, "10.0.0.5", "10.0.0.9")), true},
		{"ARP claiming another IP", ether(mac, 0x0806, arpRequest(mac, "10.0.0.99", "10.0.0.9")), false},
		{"ARP claiming another MAC", ether(mac, 0x0806, arpRequest(foreign, "10.0.0.5", "10.0.0.9")), false},
		{"VLAN-tagged frame", ether(mac, 0x8100, append([]byte{0, 10, 8, 0}, ipv4UDP("10.0.0.99", "10.0.0.9", 1, 2)...)), false},
		{"own IPv6 address", ether(mac, 0x86dd, ipv6("2001:db8::5", "2001:db8::9", 17, udp6(4000, 5000))), true},
		{"own (EUI-64) link-local", ether(mac, 0x86dd, ipv6(ll, "ff02::1", 17, udp6(4000, 5000))), true},
		{"the router's link-local as source", ether(mac, 0x86dd, ipv6("fe80::1", "ff02::1", 17, udp6(4000, 5000))), false},
		{"spoofed IPv6 source", ether(mac, 0x86dd, ipv6("2001:db8::99", "2001:db8::9", 17, udp6(4000, 5000))), false},
		{"router advertisement", ether(mac, 0x86dd, ipv6(ll, "ff02::1", 58, icmpv6(134, make([]byte, 12)))), false},
		{"DHCPv6 server reply", ether(mac, 0x86dd, ipv6(ll, "fe80::9", 17, udp6(547, 546))), false},
		{"DHCPv6 reply from another source port", ether(mac, 0x86dd, ipv6(ll, "fe80::9", 17, udp6(9999, 546))), false},
		{"neighbour advert for another address", ether(mac, 0x86dd, ipv6(ll, "ff02::1", 58, neighborAdvert("2001:db8::99"))), false},
		{"neighbour advert for the router's link-local", ether(mac, 0x86dd, ipv6(ll, "ff02::1", 58, neighborAdvert("fe80::1"))), false},
		{"solicitation naming another MAC", ether(mac, 0x86dd, ipv6(ll, "ff02::1:ff00:9", 58, neighborSolicit("2001:db8::9", foreign))), false},
	}
	run(exact)

	// Neighbour discovery at its real length: the guard caps it at the header
	// plus one option (re-review m-a), and the marker the other cases append
	// would count against that, so these frames are matched whole instead.
	nonce := []byte{14, 1, 1, 2, 3, 4, 5, 6} // a Nonce option (RFC 3971), ahead of the SLLA
	smuggled := icmpv6(135, append(append(append([]byte{0, 0, 0, 0}, net.ParseIP("2001:db8::9").To16()...), nonce...), append([]byte{1, 1}, foreign...)...))
	for _, c := range []tc{
		{"honest neighbour advert", ether(mac, 0x86dd, ipv6Exact(ll, "ff02::1", 58, neighborAdvert("2001:db8::5"))), true},
		{"honest neighbour solicitation", ether(mac, 0x86dd, ipv6Exact(ll, "ff02::1:ff00:9", 58, neighborSolicit("2001:db8::9", mac))), true},
		{"solicitation smuggling a foreign MAC in a second option", ether(mac, 0x86dd, ipv6Exact(ll, "ff02::1:ff00:9", 58, smuggled)), false},
	} {
		if got := l.deliveredWhole(t, "lvg0", "lvg1", c.frame); got != c.want {
			t.Errorf("%s: delivered=%v, want %v", c.name, got, c.want)
		}
	}

	// Confined to the subnet: anything in it, except the network's own
	// addresses and another NIC's.
	apply(Plan{NICMode: NICModeObserve, NICs: []NICBinding{{
		NICDev: "lvh0", VMName: "guest",
		Guard: &NICGuard{MAC: mac.String(), V4: []string{"10.0.0.0/24"}, ExcludeV4: []string{"10.0.0.0", "10.0.0.1", "10.0.0.255", "10.0.0.7"}},
	}, other}})
	subnet := []tc{
		{"an address in the subnet", ether(mac, 0x0800, ipv4UDP("10.0.0.99", "10.0.0.9", 4000, 5000)), true},
		{"the gateway's address", ether(mac, 0x0800, ipv4UDP("10.0.0.1", "10.0.0.9", 4000, 5000)), false},
		{"ARP claiming the gateway", ether(mac, 0x0806, arpRequest(mac, "10.0.0.1", "10.0.0.9")), false},
		{"a neighbour's address", ether(mac, 0x0800, ipv4UDP("10.0.0.7", "10.0.0.9", 4000, 5000)), false},
		{"outside the subnet", ether(mac, 0x0800, ipv4UDP("192.168.0.1", "10.0.0.9", 4000, 5000)), false},
	}
	run(subnet)

	// An UNGUARDED NIC, enforce mode: tagged frames are dropped (they would
	// carry their payload past every per-NIC rule), untagged ones pass.
	om := l.otherMAC
	apply(Plan{NICs: []NICBinding{{NICDev: "lvh0", VMName: "guest"}, other}})
	tagged := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"untagged from an unguarded NIC", ether(om, 0x0800, ipv4UDP("10.0.0.8", "10.0.0.9", 4000, 5000)), true},
		{"802.1Q from an unguarded NIC", ether(om, 0x8100, append([]byte{0, 10, 8, 0}, ipv4UDP("10.0.0.8", "10.0.0.9", 1, 2)...)), false},
		{"QinQ from an unguarded NIC", ether(om, 0x88a8, append([]byte{0, 20, 0x81, 0, 0, 10, 8, 0}, ipv4UDP("10.0.0.8", "10.0.0.9", 1, 2)...)), false},
	}
	for _, c := range tagged {
		if got := l.deliveredFrom(t, "lvg1", "lvg0", c.frame); got != c.want {
			t.Errorf("%s: delivered=%v, want %v", c.name, got, c.want)
		}
	}

	// No NIC at all: the table must go, and every forgery must now pass.
	apply(Plan{})
	if err := exec.Command("nft", "list", "table", "bridge", NICTableName).Run(); err == nil {
		t.Fatal("the per-NIC table outlived the last NIC")
	}
	for _, c := range append(exact, subnet...) {
		if !c.want && !l.delivered(t, c.frame) {
			t.Errorf("%s: still dropped with no table loaded — the drop above was not the guard's", c.name)
		}
	}
	for _, c := range tagged {
		if !c.want && !l.deliveredFrom(t, "lvg1", "lvg0", c.frame) {
			t.Errorf("%s: still dropped with no table loaded", c.name)
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
			// Main's shapes, rendered as main rendered them (switch review m3).
			{Direction: Ingress, Proto: "ipv6-icmp", Action: Accept},
			{Direction: Ingress, Proto: "icmpv6", CIDR: "10.0.0.0/8", Action: Drop},
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

var mountRun sync.Once

func newGuestLab(t *testing.T, guests map[string]string) *guestLab {
	t.Helper()
	mountRun.Do(func() {
		sh(t, "mount", "-t", "tmpfs", "tmpfs", "/run")
		sh(t, "mkdir", "-p", "/run/netns")
	})
	t.Cleanup(func() {
		_, _ = NewApplier(NftBinary{}).Apply(context.Background(), Plan{})
		for g := range guests {
			_ = exec.Command("ip", "netns", "del", g).Run()
			_ = exec.Command("ip", "link", "del", "p"+g).Run()
		}
		_ = exec.Command("ip", "link", "del", "gwbr0").Run()
		_ = exec.Command("ip", "link", "del", "gwbr1").Run()
	})
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
// No case here depends on replies being tracked (the stateful cases are in
// TestKernelChild_DefaultDenyAndBypasses).
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

// TestKernelHelper_SendUDP is not a test: a kernel test runs it inside a guest
// namespace to send one UDP datagram from a chosen source port
// (LV_UDP_SEND="<sport> <daddr> <dport>").
func TestKernelHelper_SendUDP(t *testing.T) {
	spec := os.Getenv("LV_UDP_SEND")
	if spec == "" {
		t.Skip("helper")
	}
	f := strings.Fields(spec)
	sport, _ := strconv.Atoi(f[0])
	dport, _ := strconv.Atoi(f[2])
	c, err := net.DialUDP("udp4", &net.UDPAddr{Port: sport}, &net.UDPAddr{IP: net.ParseIP(f[1]), Port: dport})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		_, _ = c.Write([]byte("litevirt-probe"))
	}
}

// sendUDP sends from guest g with the given ports.
func sendUDP(t *testing.T, g string, sport int, daddr string, dport int) {
	t.Helper()
	cmd := exec.Command("ip", "netns", "exec", g, os.Args[0], "-test.run", "^TestKernelHelper_SendUDP$", "-test.count=1")
	cmd.Env = append(os.Environ(), fmt.Sprintf("LV_UDP_SEND=%d %s %d", sport, daddr, dport))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("send udp from %s: %v\n%s", g, err, out)
	}
}

var packetsRE = regexp.MustCompile(`packets (\d+)`)

// probeCount reads a counter the test put on the host's IP prerouting hook,
// ahead of litevirt's: what got past the bridge into the host's stack.
func probeCount(t *testing.T) int {
	t.Helper()
	m := packetsRE.FindStringSubmatch(sh(t, "nft", "list", "chain", "inet", "lvprobe", "pre"))
	if m == nil {
		t.Fatal("no probe counter")
	}
	n, _ := strconv.Atoi(m[1])
	return n
}

// TestKernelChild_DefaultDenyAndBypasses runs real traffic under default-deny
// with replies tracked by bridge conntrack, and the bypasses the review found:
//
//   - a guest that may not send UDP must not reach a routed UDP/67 listener
//     by using DHCP's ports (review C2);
//   - a reject rule loads (the kernel would refuse it on the forward and
//     output hooks; it is rendered as drop) and holds (C1);
//   - routed traffic between ports that are not guest NICs is still judged by
//     the default policy, not let through because its bridge carries guests
//     (ruling 5, I1);
//   - observe mode drops nothing per NIC, counts what it would have dropped,
//     and loosens nothing routed.
func TestKernelChild_DefaultDenyAndBypasses(t *testing.T) {
	inNetns(t)
	if missing := missingModules("nf_conntrack_bridge"); len(missing) > 0 {
		t.Skip("nf_conntrack_bridge is not loaded; a test must not load it")
	}
	l := newGuestLab(t, map[string]string{
		"ga": "10.20.0.1", // may send icmp and udp/67
		"gb": "10.20.0.2", // may receive icmp; sends nothing
		"gc": "10.20.0.3", // no rules, plus a reject: default-deny both ways
		"gd": "10.21.0.4", // the routed target
		"gx": "10.20.0.9", // a port that is no guest NIC
		"gu": "10.21.0.9", // another
	})
	nic := func(g, br string, sgs ...string) NICBinding {
		return NICBinding{NICDev: "p" + g, VMName: g, Bridge: br, SecurityGroups: sgs}
	}
	plan := Plan{
		DefaultDeny: true,
		SecurityGroups: []SecurityGroup{
			{Name: "sender", Rules: []Rule{
				{Direction: Egress, Proto: "icmp", Action: Accept},
				{Direction: Egress, Proto: "udp", PortRange: "67", Action: Accept},
			}},
			{Name: "receiver", Rules: []Rule{{Direction: Ingress, Proto: "icmp", Action: Accept}}},
			{Name: "rejecting", Rules: []Rule{{Direction: Ingress, Proto: "icmp", Action: Reject}}},
			{Name: "target", Rules: []Rule{{Direction: Ingress, Proto: "udp", PortRange: "67", Action: Accept}}},
		},
		NICs: []NICBinding{nic("ga", "gwbr0", "sender"), nic("gb", "gwbr0", "receiver"),
			nic("gc", "gwbr0", "rejecting"), nic("gd", "gwbr1", "target")},
	}
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), plan); err != nil {
		t.Fatalf("apply (a reject rule in a security group must load): %v", err)
	}
	sh(t, "sh", "-c", `nft add table inet lvprobe && nft add chain inet lvprobe pre '{ type filter hook prerouting priority -400; policy accept; }' && nft add rule inet lvprobe pre ip daddr 10.21.0.4 udp dport 67 counter`)

	check := func(name, from, to string, want bool) {
		if got := l.ping(from, to); got != want {
			t.Errorf("%s (%s -> %s): reached=%v, want %v", name, from, to, got, want)
		}
	}
	check("allowed both ways, replies tracked", "ga", "10.20.0.2", true)
	check("a sender with no egress rule", "gb", "10.20.0.1", false)
	check("into a NIC that rejects icmp", "ga", "10.20.0.3", false)
	check("routed between two ports that are no guest NIC", "gx", "10.21.0.9", false)

	sendUDP(t, "gc", 68, "10.21.0.4", 67)
	if n := probeCount(t); n != 0 {
		t.Errorf("%d datagrams from a guest that may not send UDP reached a routed UDP/67 listener using DHCP's ports", n)
	}
	sendUDP(t, "ga", 68, "10.21.0.4", 67)
	if n := probeCount(t); n == 0 {
		t.Error("the allowed sender's datagram never reached the probe either; the zero above proves nothing")
	}

	// Observe: the per-NIC drops above become counters, nothing routed
	// loosens.
	plan.NICMode = NICModeObserve
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), plan); err != nil {
		t.Fatalf("apply observe: %v", err)
	}
	check("observe: a sender with no egress rule", "gb", "10.20.0.1", true)
	check("observe: routed between ports that are no guest NIC", "gx", "10.21.0.9", false)
	wd, err := WouldDrops(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range wd {
		if w.Device == "pgb" && w.Side == "out" && w.Rule == "default" && w.Packets > 0 {
			found = true
		}
	}
	if !found {
		t.Errorf("observe mode counted no would-drop for gb's egress default: %+v", wd)
	}

	// No rules: everything passes, so the drops above were the rules'.
	if _, err := NewApplier(NftBinary{}).Apply(context.Background(), Plan{}); err != nil {
		t.Fatal(err)
	}
	check("no rules: gb", "gb", "10.20.0.1", true)
	check("no rules: routed", "gx", "10.21.0.9", true)
}

// vport adds a veth pair to bridge br: the bridge port is host, the far end
// (where a frame is sent from or seen arriving) is far.
func vport(t *testing.T, br, host, far string) net.HardwareAddr {
	t.Helper()
	sh(t, "ip", "link", "add", far, "type", "veth", "peer", "name", host)
	sh(t, "ip", "link", "set", host, "master", br)
	sh(t, "ip", "link", "set", host, "up")
	sh(t, "ip", "link", "set", far, "up")
	ifc, err := net.InterfaceByName(far)
	if err != nil {
		t.Fatal(err)
	}
	return ifc.HardwareAddr
}

// tagged wraps an IPv4 payload in one 802.1Q tag per VID, outermost first;
// tpid sets the outer tag's type (0x8100 or 0x88a8).
func tagged(src net.HardwareAddr, tpid uint16, payload []byte, vids ...uint16) []byte {
	return taggedType(src, tpid, 0x0800, payload, vids...)
}

// taggedType is tagged with the innermost ethertype given (0x0806 for ARP).
func taggedType(src net.HardwareAddr, tpid, etype uint16, payload []byte, vids ...uint16) []byte {
	inner := []byte{byte(etype >> 8), byte(etype)}
	for i := len(vids) - 1; i >= 0; i-- {
		tci := []byte{byte(vids[i] >> 8), byte(vids[i])}
		tag := append(tci, inner...)
		inner = append([]byte{0x81, 0}, tag...)
	}
	// inner now begins with the outer TPID; replace it with tpid.
	inner[0], inner[1] = byte(tpid>>8), byte(tpid)
	return ether(src, binary.BigEndian.Uint16(inner[:2]), append(inner[2:], payload...))
}

// TestKernelChild_VLANToNICAndTrunk pushes tagged frames through real
// bridges:
//
//   - re-review I-1: a tagged frame sent TO a guest NIC from a port that is
//     not one (the uplink) is dropped, so it cannot carry its payload past
//     the receiver's rules — and observe mode only counts it;
//   - re-review I-2: a NIC on the `trunk:` feature, on a vlan_filtering
//     bridge as litevirt configures it, carries its VLANs, is still judged
//     by its rules (which see the inner packet), and cannot send a doubled or
//     802.1ad tag in enforce mode; in observe mode nothing it could send on
//     main is dropped.
//
// Each drop is then shown to pass with no table loaded.
func TestKernelChild_VLANToNICAndTrunk(t *testing.T) {
	inNetns(t)
	if missing := missingModules("nf_conntrack_bridge"); len(missing) > 0 {
		t.Skip("nf_conntrack_bridge is not loaded; a test must not load it")
	}
	apply := func(p Plan) {
		t.Helper()
		if _, err := NewApplier(NftBinary{}).Apply(context.Background(), p); err != nil {
			t.Fatalf("apply: %v", err)
		}
	}
	l := &bridgeLab{}
	udp := func(dport uint16) []byte { return ipv4UDP("10.0.0.8", "10.0.0.9", 4000, dport) }

	// I-1: a plain bridge, two guest NICs and an uplink.
	sh(t, "ip", "link", "add", "lvvb0", "type", "bridge", "stp_state", "0", "forward_delay", "0")
	sh(t, "ip", "link", "set", "lvvb0", "up")
	ga := vport(t, "lvvb0", "lvvh0", "lvvg0")
	vport(t, "lvvb0", "lvvh1", "lvvg1")
	up := vport(t, "lvvb0", "lvvh2", "lvvg2")
	nics := []NICBinding{{NICDev: "lvvh0", VMName: "a", Bridge: "lvvb0"}, {NICDev: "lvvh1", VMName: "b", Bridge: "lvvb0"}}
	toNIC := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"untagged from the uplink", ether(up, 0x0800, udp(5000)), true},
		{"priority-tagged (VID 0) from the uplink", tagged(up, 0x8100, udp(5000), 0), false},
		{"802.1Q from the uplink", tagged(up, 0x8100, udp(5000), 10), false},
		{"802.1ad over 802.1Q from the uplink", tagged(up, 0x88a8, udp(5000), 0, 10), false},
	}
	apply(Plan{NICs: nics})
	for _, c := range toNIC {
		if got := l.deliveredFrom(t, "lvvg2", "lvvg0", c.frame); got != c.want {
			t.Errorf("enforce: %s: delivered=%v, want %v", c.name, got, c.want)
		}
	}
	apply(Plan{NICMode: NICModeObserve, NICs: nics})
	for _, c := range toNIC {
		if !l.deliveredFrom(t, "lvvg2", "lvvg0", c.frame) {
			t.Errorf("observe: %s was dropped", c.name)
		}
	}
	counted := false
	wd, _ := WouldDrops(context.Background())
	for _, w := range wd {
		if w.Rule == "tagged-to-nic" && w.Packets > 0 {
			counted = true
		}
	}
	if !counted {
		t.Errorf("observe mode counted no tagged frame sent to a NIC: %+v", wd)
	}

	// I-2: a vlan_filtering bridge; the trunk NIC carries VLANs 100 and 101,
	// the uplink 100-102.
	sh(t, "ip", "link", "add", "lvtb0", "type", "bridge", "stp_state", "0", "forward_delay", "0", "vlan_filtering", "1")
	sh(t, "ip", "link", "set", "lvtb0", "up")
	tr := vport(t, "lvtb0", "lvth0", "lvtg0")
	vport(t, "lvtb0", "lvth1", "lvtg1")
	for _, v := range []string{"100", "101"} {
		sh(t, "bridge", "vlan", "add", "dev", "lvth0", "vid", v)
	}
	for _, v := range []string{"100", "101", "102"} {
		sh(t, "bridge", "vlan", "add", "dev", "lvth1", "vid", v)
	}
	// The trunk NIC is guarded (re-review R2-I1: a trunk keeps the default
	// guard) on every frame, tagged or not.
	trunkPlan := Plan{
		SecurityGroups: []SecurityGroup{{Name: "no25", Rules: []Rule{{Direction: Egress, Proto: "udp", PortRange: "25", Action: Drop}}}},
		NICs: []NICBinding{{NICDev: "lvth0", VMName: "router", Bridge: "lvtb0", TrunkVIDs: []int{100, 101}, SecurityGroups: []string{"no25"},
			Guard: &NICGuard{MAC: tr.String(), V4: []string{"10.0.0.8"}}}},
	}
	foreign := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}
	trunk := []struct {
		name                    string
		frame                   []byte
		enforce, observe, empty bool
	}{
		{"VLAN 100", tagged(tr, 0x8100, udp(5000), 100), true, true, true},
		{"VLAN 101", tagged(tr, 0x8100, udp(5000), 101), true, true, true},
		{"untagged (native VLAN)", ether(tr, 0x0800, udp(5000)), true, true, true},
		{"VLAN 100, to a port its rules refuse", tagged(tr, 0x8100, udp(25), 100), false, true, true},
		{"a doubled tag inside VLAN 100", tagged(tr, 0x8100, udp(5000), 100, 7), false, true, true},
		{"802.1ad outer tag", tagged(tr, 0x88a8, udp(5000), 100, 7), false, true, true},
		{"a DHCP server reply on VLAN 100", tagged(tr, 0x8100, ipv4UDP("10.0.0.8", "255.255.255.255", 67, 68), 100), false, false, true},
		{"ARP naming another MAC on VLAN 100", taggedType(tr, 0x8100, 0x0806, arpRequest(foreign, "10.9.0.5", "10.9.0.1"), 100), false, false, true},
	}
	apply(trunkPlan)
	for _, c := range trunk {
		if got := l.deliveredFrom(t, "lvtg0", "lvtg1", c.frame); got != c.enforce {
			t.Errorf("trunk, enforce: %s: delivered=%v, want %v", c.name, got, c.enforce)
		}
	}
	trunkPlan.NICMode = NICModeObserve
	apply(trunkPlan)
	for _, c := range trunk {
		if got := l.deliveredFrom(t, "lvtg0", "lvtg1", c.frame); got != c.observe {
			t.Errorf("trunk, observe: %s: delivered=%v, want %v", c.name, got, c.observe)
		}
	}

	// The trunk's router advertisements and neighbour discovery on VLAN 100
	// (lab 1 F3): held to its MAC and to no router role exactly as untagged,
	// in either mode (a guard drops in observe mode too). VID 0 is no VLAN the
	// trunk carries, so its confinement drops it before the guard.
	trLL, _ := eui64LinkLocal(tr.String())
	trunkV6 := []struct {
		name           string
		pkt            []byte
		untagged, vlan bool
	}{
		{"RA", icmpv6Packet(trLL, "ff02::1", routerAdvert()), false, false},
		{"NS with its own MAC", icmpv6Packet(trLL, "ff02::1:ff00:9", neighborSolicit("2001:db8::9", tr)), true, true},
		{"NS naming another MAC", icmpv6Packet(trLL, "ff02::1:ff00:9", neighborSolicit("2001:db8::9", foreign)), false, false},
		{"NA with its own MAC", icmpv6Packet(trLL, "ff02::1", neighborAdvertTLL(trLL, tr)), true, true},
		{"NA naming another MAC", icmpv6Packet(trLL, "ff02::1", neighborAdvertTLL(trLL, foreign)), false, false},
	}
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		trunkPlan.NICMode = mode
		apply(trunkPlan)
		for _, c := range trunkV6 {
			if got := l.deliveredV6(t, "lvtg0", "lvtg1", tr, -1, c.pkt); got != c.untagged {
				t.Errorf("trunk, %s: untagged %s: delivered=%v, want %v", mode, c.name, got, c.untagged)
			}
			if got := l.deliveredV6(t, "lvtg0", "lvtg1", tr, 100, c.pkt); got != c.vlan {
				t.Errorf("trunk, %s: VLAN 100 %s: delivered=%v, want %v", mode, c.name, got, c.vlan)
			}
		}
	}

	// A guarded NIC allowed tags with --allow-vlan-tags (not a trunk), on a
	// plain bridge, receiving port allowed tags too. Its tagged frames are
	// held to its MAC, ARP sender MAC and ND link-layer option, and not to its
	// native addresses; a priority tag (VID 0) is native traffic and is held
	// to them; a doubled tag is dropped.
	sh(t, "ip", "link", "add", "lvab0", "type", "bridge", "stp_state", "0", "forward_delay", "0")
	sh(t, "ip", "link", "set", "lvab0", "up")
	am := vport(t, "lvab0", "lvah0", "lvag0")
	vport(t, "lvab0", "lvah1", "lvag1")
	allowTags := Plan{NICs: []NICBinding{
		{NICDev: "lvah0", VMName: "vlanaware", Bridge: "lvab0", AllowVLANTags: true,
			// The usual guard of a NIC on a DHCP network with no static IP: the
			// whole subnet, less the addresses litevirt keeps (the gateway). That
			// renders the raw ARP range set and exclusion rule for VID 0.
			Guard: &NICGuard{MAC: am.String(), V4: []string{"10.0.0.0/24"}, ExcludeV4: []string{"10.0.0.1"}}},
		{NICDev: "lvah1", VMName: "peer", Bridge: "lvab0", AllowVLANTags: true},
	}}
	euiLL, _ := eui64LinkLocal(am.String())
	allow := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"untagged, its own address", ether(am, 0x0800, udp(5000)), true},
		{"untagged, a foreign address", ether(am, 0x0800, ipv4UDP("10.9.9.9", "10.0.0.9", 4000, 5000)), false},
		{"VLAN 10, IPv4 on another subnet", tagged(am, 0x8100, ipv4UDP("10.215.0.1", "10.215.0.2", 4000, 5000), 10), true},
		{"VLAN 10, ARP with its own MAC on another subnet", taggedType(am, 0x8100, 0x0806, arpRequest(am, "10.215.0.1", "10.215.0.2"), 10), true},
		{"VLAN 10, ARP naming another MAC", taggedType(am, 0x8100, 0x0806, arpRequest(foreign, "10.215.0.1", "10.215.0.2"), 10), false},
		{"VLAN 10, a DHCP server reply", tagged(am, 0x8100, ipv4UDP("10.215.0.1", "255.255.255.255", 67, 68), 10), false},
		{"untagged, an excluded address", ether(am, 0x0800, ipv4UDP("10.0.0.1", "10.0.0.9", 4000, 5000)), false},
		{"untagged ARP, its own address", ether(am, 0x0806, arpRequest(am, "10.0.0.8", "10.0.0.9")), true},
		{"untagged ARP, an excluded address", ether(am, 0x0806, arpRequest(am, "10.0.0.1", "10.0.0.9")), false},
		{"VID 0, its own address", tagged(am, 0x8100, udp(5000), 0), true},
		{"VID 0, a foreign address", tagged(am, 0x8100, ipv4UDP("10.9.9.9", "10.0.0.9", 4000, 5000), 0), false},
		{"VID 0, ARP with its own address", taggedType(am, 0x8100, 0x0806, arpRequest(am, "10.0.0.8", "10.0.0.9"), 0), true},
		{"VID 0, ARP claiming a foreign address", taggedType(am, 0x8100, 0x0806, arpRequest(am, "10.9.9.9", "10.0.0.9"), 0), false},
		{"VID 0, an excluded address", tagged(am, 0x8100, ipv4UDP("10.0.0.1", "10.0.0.9", 4000, 5000), 0), false},
		{"VID 0, ARP from an address in the subnet", taggedType(am, 0x8100, 0x0806, arpRequest(am, "10.0.0.200", "10.0.0.9"), 0), true},
		{"VID 0, ARP probe from 0.0.0.0", taggedType(am, 0x8100, 0x0806, arpRequest(am, "0.0.0.0", "10.0.0.9"), 0), true},
		{"VID 0, ARP from an excluded address", taggedType(am, 0x8100, 0x0806, arpRequest(am, "10.0.0.1", "10.0.0.9"), 0), false},
		{"VID 0, ARP from an address outside the subnet", taggedType(am, 0x8100, 0x0806, arpRequest(am, "10.0.1.5", "10.0.0.9"), 0), false},
		// A UDP header with a real length: an all-zero one is conntrack-invalid,
		// and the forward chain drops it in enforce mode whatever the guard says.
		{"VID 0, IPv6 from its own link-local", taggedType(am, 0x8100, 0x86dd, ipv6(euiLL, "ff02::1", 17, udp6(4000, 5000)), 0), true},
		{"VID 0, IPv6 from a foreign link-local", taggedType(am, 0x8100, 0x86dd, ipv6("fe80::dead:1", "ff02::1", 17, udp6(4000, 5000)), 0), false},
		{"VLAN 10, IPv6 from a foreign link-local (unchecked inside a VLAN)", taggedType(am, 0x8100, 0x86dd, ipv6("fe80::dead:1", "ff02::1", 17, udp6(4000, 5000)), 10), true},
		{"a lone 802.1ad tag", tagged(am, 0x88a8, udp(5000), 10), false},
		{"802.1Q inside 802.1Q", tagged(am, 0x8100, udp(5000), 10, 20), false},
		{"802.1ad outer tag", tagged(am, 0x88a8, udp(5000), 10, 20), false},
		{"802.1ad outer tag, ARP naming another MAC", taggedType(am, 0x88a8, 0x0806, arpRequest(foreign, "10.215.0.1", "10.215.0.2"), 10, 20), false},
	}
	apply(allowTags)
	for _, c := range allow {
		if got := l.deliveredFrom(t, "lvag0", "lvag1", c.frame); got != c.want {
			t.Errorf("allow-vlan-tags guard: %s: delivered=%v, want %v", c.name, got, c.want)
		}
	}

	// Router advertisements and neighbour discovery (lab 1 F3), each sent
	// untagged, in VLAN 10 and with a priority tag (VID 0), at its exact length
	// with a valid checksum. The RA and redirect drop, the ND length cap and
	// the link-layer option checks hold all three; the NA target check holds
	// untagged and VID 0, and not inside a VLAN, where the addresses are no one's
	// to know. nft compiles a bare `icmpv6 type` in the bridge family with an
	// `ether type ip6` check, which a tagged frame (VID 0 included) never
	// passes: these rows are what catches a rule written that way.
	ns := func(sll net.HardwareAddr) []byte {
		return icmpv6Packet(euiLL, "ff02::1:ff00:9", neighborSolicit("2001:db8::9", sll))
	}
	na := func(target string, tll net.HardwareAddr) []byte {
		return icmpv6Packet(euiLL, "ff02::1", neighborAdvertTLL(target, tll))
	}
	nonce := []byte{14, 1, 1, 2, 3, 4, 5, 6} // a Nonce option (RFC 3971), ahead of the SLLA
	smuggled := icmpv6Packet(euiLL, "ff02::1:ff00:9", icmpv6(135, append(append(append([]byte{0, 0, 0, 0},
		net.ParseIP("2001:db8::9").To16()...), nonce...), append([]byte{1, 1}, foreign...)...)))
	type v6row struct {
		name                   string
		pkt                    []byte
		untagged, vlan10, vid0 bool
	}
	allowV6 := []v6row{
		{"RA", icmpv6Packet(euiLL, "ff02::1", routerAdvert()), false, false, false},
		{"NS with its own MAC", ns(am), true, true, true},
		{"NS naming another MAC", ns(foreign), false, false, false},
		{"NS smuggling a foreign MAC in a second option", smuggled, false, false, false},
		{"NA for its own link-local, its own MAC", na(euiLL, am), true, true, true},
		{"NA naming another MAC", na(euiLL, foreign), false, false, false},
		{"NA for a foreign link-local", na("fe80::dead:1", am), false, true, false},
	}
	for _, c := range allowV6 {
		for _, tag := range []struct {
			vid  int
			want bool
		}{{-1, c.untagged}, {10, c.vlan10}, {0, c.vid0}} {
			if got := l.deliveredV6(t, "lvag0", "lvag1", am, tag.vid, c.pkt); got != tag.want {
				t.Errorf("allow-vlan-tags guard: %s, vid %d (-1 untagged): delivered=%v, want %v", c.name, tag.vid, got, tag.want)
			}
		}
	}

	// A trunk on a bridge with no VLAN filtering of its own (a plain managed
	// bridge with an uplink): a VLAN the tenant chose, which its network does
	// not allow, does not leave through the uplink, in either mode.
	hop := tagged(ga, 0x8100, udp(5000), 102)
	allowed := tagged(ga, 0x8100, udp(5000), 100)
	plainTrunk := Plan{NICs: []NICBinding{{NICDev: "lvvh0", VMName: "tenant", Bridge: "lvvb0", TrunkVIDs: []int{100},
		Guard: &NICGuard{MAC: ga.String()}}, {NICDev: "lvvh1", VMName: "b", Bridge: "lvvb0"}}}
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		plainTrunk.NICMode = mode
		apply(plainTrunk)
		if l.deliveredFrom(t, "lvvg0", "lvvg2", hop) {
			t.Errorf("%s: a tenant-chosen VLAN (102) left through the uplink", mode)
		}
		if !l.deliveredFrom(t, "lvvg0", "lvvg2", allowed) {
			t.Errorf("%s: the allowed VLAN 100 did not leave through the uplink", mode)
		}
	}
	// A trunk none of whose VLANs its network allows (re-review R3-I1): a
	// trunk that predates guards — no record, so no guard — whose VLANs are
	// not on its network's recorded list. Nothing tagged leaves, in either
	// mode: in observe mode the plain VLAN rule only counts.
	deniedTrunk := Plan{NICs: []NICBinding{{NICDev: "lvvh0", VMName: "legacy", Bridge: "lvvb0", TrunkDenied: true},
		{NICDev: "lvvh1", VMName: "b", Bridge: "lvvb0"}}}
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		deniedTrunk.NICMode = mode
		apply(deniedTrunk)
		for _, f := range [][]byte{hop, allowed} {
			if l.deliveredFrom(t, "lvvg0", "lvvg2", f) {
				t.Errorf("%s: a trunk with no allowed VLAN sent a tagged frame through the uplink", mode)
			}
		}
		if !l.deliveredFrom(t, "lvvg0", "lvvg2", ether(ga, 0x0800, udp(5000))) {
			t.Errorf("%s: a trunk with no allowed VLAN lost its untagged (native VLAN) traffic", mode)
		}
	}
	if t.Failed() {
		t.Logf("ruleset:\n%s", sh(t, "nft", "list", "table", "bridge", NICTableName))
	}

	// No table: every frame dropped above passes, so the drops were ours.
	apply(Plan{})
	for _, c := range toNIC {
		if !l.deliveredFrom(t, "lvvg2", "lvvg0", c.frame) {
			t.Errorf("no table: %s still dropped — the drop above was not the rule's", c.name)
		}
	}
	for _, c := range trunk {
		if got := l.deliveredFrom(t, "lvtg0", "lvtg1", c.frame); got != c.empty {
			t.Errorf("no table: %s: delivered=%v, want %v", c.name, got, c.empty)
		}
	}
	for _, c := range allow {
		// With no table nothing is held, whatever the frame (the doubled and
		// forged ones go through).
		if !l.deliveredFrom(t, "lvag0", "lvag1", c.frame) {
			t.Errorf("no table: %s still dropped — the drop above was not the rule's", c.name)
		}
	}
	for _, c := range allowV6 {
		for _, vid := range []int{-1, 10, 0} {
			if !l.deliveredV6(t, "lvag0", "lvag1", am, vid, c.pkt) {
				t.Errorf("no table: allow-vlan-tags %s, vid %d still dropped — the drop above was not the rule's", c.name, vid)
			}
		}
	}
	for _, c := range trunkV6 {
		for _, vid := range []int{-1, 100} {
			if !l.deliveredV6(t, "lvtg0", "lvtg1", tr, vid, c.pkt) {
				t.Errorf("no table: trunk %s, vid %d still dropped — the drop above was not the rule's", c.name, vid)
			}
		}
	}
	if !l.deliveredFrom(t, "lvvg0", "lvvg2", hop) {
		t.Error("no table: VLAN 102 still does not leave — the drop above was not the rule's")
	}
}

// compatCorpusModules are the modules the compat corpus's rulesets make the
// kernel use beyond kernelTestModules: reject in the inet table, and the NAT
// chain's snat and masquerade.
var compatCorpusModules = []string{"nf_tables", "nf_conntrack", "nft_ct", "nf_conntrack_bridge", "nft_meta_bridge", "bridge",
	"nft_reject", "nft_reject_inet", "nf_reject_ipv4", "nf_reject_ipv6", "nf_nat", "nft_nat", "nft_masq", "nft_chain_nat"}

// TestKernelChild_CompatCorpusLoads: every row that applies on the build
// before the rule grammar (the compat corpus, render_compat_golden_test.go)
// still renders into a ruleset a real nft accepts, in enforce and observe
// mode, with the comment `a; b #1`, a 127-byte comment and a port an older
// peer stored as `SSH` (spec §0.4; review I-1, I-2). `nft -c` checks the
// whole transaction against the namespace's own nf_tables and changes
// nothing.
//
// The corpus's DNS-named CIDR is swapped for an address: resolving a name is
// nft's dependency on the host's resolver, which the namespace has none of.
//
// Mutation: render a port as stored — `dport SSH` is refused, red.
func TestKernelChild_CompatCorpusLoads(t *testing.T) {
	inNetns(t)
	if missing := missingModules(compatCorpusModules...); len(missing) > 0 {
		t.Skipf("the corpus rulesets would make the kernel load %v, which is not loaded on this host", missing)
	}
	plan := loadCompatPlan(t)
	var rules []Rule
	for _, r := range plan.ClusterRules {
		if r.CIDR == "gw.example.com" {
			r.CIDR = "192.0.2.53"
		}
		rules = append(rules, r)
	}
	rules = append(rules,
		Rule{Direction: Ingress, Proto: "tcp", PortRange: "2200", Action: Accept, Comment: "a; b #1"},
		Rule{Direction: Ingress, Proto: "tcp", PortRange: "2201", Action: Accept, Comment: strings.Repeat("x", 127)},
		Rule{Direction: Ingress, Proto: "TCP", PortRange: "SSH", CIDR: "10.7.0.0/16", Action: Drop},
	)
	plan.ClusterRules = rules
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		p := plan
		p.NICMode = mode
		p.NICs = []NICBinding{{NICDev: "tap0", VMName: "vm", SecurityGroups: []string{"web"}}}
		script, err := Render(p)
		if err != nil {
			t.Fatalf("%s: Render refused the corpus: %v", mode, err)
		}
		cmd := exec.Command("nft", "-c", "-f", "-")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Errorf("%s: nft -c refused the corpus ruleset: %v\n%s", mode, err, out)
		}
	}
}
