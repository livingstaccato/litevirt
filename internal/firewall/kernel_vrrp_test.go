//go:build linux

package firewall

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// vrrpLab is a bridge lvrb0 (the host at 10.50.0.254) with two guest NIC
// ports (lvrh0, lvrh1) and an uplink port (lvrh2) that is not a guest NIC,
// like the vxlan port a peer LB host's adverts arrive on; and a second bridge
// lvrb1 (10.51.0.254) with a port lvrh3, so the host routes between them.
// Frames are sent from, and received on, the far ends lvrgN.
type vrrpLab struct {
	brMAC net.HardwareAddr
	host  int // raw IP socket for protocol 112, bound to lvrb0, in 224.0.0.18
}

func newVRRPLab(t *testing.T) *vrrpLab {
	t.Helper()
	t.Cleanup(func() {
		for _, l := range []string{"lvrh0", "lvrh1", "lvrh2", "lvrh3", "lvrb0", "lvrb1"} {
			_ = exec.Command("ip", "link", "del", l).Run()
		}
	})
	sh(t, "sysctl", "-qw", "net.ipv4.ip_forward=1")
	sh(t, "sysctl", "-qw", "net.ipv4.conf.all.rp_filter=0")
	sh(t, "sysctl", "-qw", "net.ipv4.conf.default.rp_filter=0")
	for br, cidr := range map[string]string{"lvrb0": "10.50.0.254/24", "lvrb1": "10.51.0.254/24"} {
		sh(t, "ip", "link", "add", br, "type", "bridge", "stp_state", "0", "forward_delay", "0")
		sh(t, "ip", "addr", "add", cidr, "dev", br)
		sh(t, "ip", "link", "set", br, "up")
	}
	for i, br := range []string{"lvrb0", "lvrb0", "lvrb0", "lvrb1"} {
		h, g := fmt.Sprintf("lvrh%d", i), fmt.Sprintf("lvrg%d", i)
		sh(t, "ip", "link", "add", g, "type", "veth", "peer", "name", h)
		sh(t, "ip", "link", "set", h, "master", br)
		sh(t, "ip", "link", "set", h, "up")
		sh(t, "ip", "link", "set", g, "up")
	}
	g3, err := net.InterfaceByName("lvrg3")
	if err != nil {
		t.Fatal(err)
	}
	sh(t, "ip", "neigh", "replace", "10.51.0.5", "lladdr", g3.HardwareAddr.String(), "dev", "lvrb1")
	br, err := net.InterfaceByName("lvrb0")
	if err != nil {
		t.Fatal(err)
	}

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, 112)
	if err != nil {
		t.Fatalf("raw socket: %v", err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	if err := syscall.SetsockoptString(fd, syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, "lvrb0"); err != nil {
		t.Fatalf("bind to lvrb0: %v", err)
	}
	if err := syscall.SetsockoptIPMreqn(fd, syscall.IPPROTO_IP, syscall.IP_ADD_MEMBERSHIP,
		&syscall.IPMreqn{Multiaddr: [4]byte{224, 0, 0, 18}, Ifindex: int32(br.Index)}); err != nil {
		t.Fatalf("join 224.0.0.18: %v", err)
	}
	tv := syscall.NsecToTimeval(int64(50 * time.Millisecond))
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		t.Fatal(err)
	}
	return &vrrpLab{brMAC: br.HardwareAddr, host: fd}
}

var vrrpGroupMAC = net.HardwareAddr{0x01, 0x00, 0x5e, 0x00, 0x00, 0x12}

// vrrpFrame is an IPv4 VRRP advert (protocol 112, TTL 255) carrying marker.
func vrrpFrame(dst, src net.HardwareAddr, saddr, daddr string, marker []byte) []byte {
	payload := append([]byte{0x21, 77, 254, 1, 0, 1, 0, 0}, marker...)
	h := make([]byte, 20)
	h[0], h[1] = 0x45, 0xc0
	binary.BigEndian.PutUint16(h[2:], uint16(20+len(payload)))
	h[8], h[9] = 255, 112
	copy(h[12:], net.ParseIP(saddr).To4())
	copy(h[16:], net.ParseIP(daddr).To4())
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(h[i:]))
	}
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(h[10:], ^uint16(sum))
	f := append(append(append([]byte(nil), dst...), src...), 0x08, 0x00)
	return append(append(f, h...), payload...)
}

// send puts a VRRP advert into the bridge from the far end of a port and
// reports whether the host's VRRP socket got it and whether it came out of
// the far end of port `to` ("" checks the host only).
func (l *vrrpLab) send(t *testing.T, from, to string, dst net.HardwareAddr, saddr, daddr string) (host, port bool) {
	t.Helper()
	marker := []byte(fmt.Sprintf("LVVRRP%026d", time.Now().UnixNano()))
	tx := packetSocket(t, from)
	var rx int
	if to != "" {
		rx = packetSocket(t, to)
	}
	src, _ := net.InterfaceByName(from)
	frame := vrrpFrame(dst, src.HardwareAddr, saddr, daddr, marker)
	if err := syscall.Sendto(tx, frame, 0, &syscall.SockaddrLinklayer{Ifindex: src.Index, Halen: 6}); err != nil {
		t.Fatalf("send: %v", err)
	}
	buf := make([]byte, 4096)
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) && !host {
		if n, _, err := syscall.Recvfrom(l.host, buf, 0); err == nil && bytes.Contains(buf[:n], marker) {
			host = true
		}
	}
	if to != "" {
		deadline = time.Now().Add(500 * time.Millisecond)
		for time.Now().Before(deadline) && !port {
			if n, _, err := syscall.Recvfrom(rx, buf, 0); err == nil && bytes.Contains(buf[:n], marker) {
				port = true
			}
		}
	}
	return host, port
}

// TestKernelChild_GuestVRRPNeverReachesTheHost: a guest's VRRP adverts — to
// the VRRP group, or forged to the host's own address — never reach the
// host's keepalived, in enforce and observe mode alike, so a guest cannot
// answer a load balancer's VRRP and take its VIP. What a guest's VRRP may do
// still works: it reaches another guest on the bridge, and is routed to a
// guest on another network (keepalived unicast between guests). A peer LB
// host's adverts, which come in over the uplink, still reach the host. With
// the tables removed the guest's adverts reach the host, so it was the
// tables.
//
// Mutation: drop the guest_vrrp chain's rule, or the bridge input's mark —
// the "to the host" cases go red; drop VRRP at the bridge input instead —
// the routed case goes red.
func TestKernelChild_GuestVRRPNeverReachesTheHost(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "this test", "nf_conntrack_bridge")
	l := newVRRPLab(t)
	plan := func(mode string) Plan {
		return Plan{NICMode: mode, NICs: []NICBinding{
			{NICDev: "lvrh0", VMName: "va", Bridge: "lvrb0"},
			{NICDev: "lvrh1", VMName: "vb", Bridge: "lvrb0"},
			{NICDev: "lvrh3", VMName: "vd", Bridge: "lvrb1"},
		}}
	}
	check := func(phase string, guestReachesHost bool) {
		t.Helper()
		failed := false
		expect := func(what string, got, want bool) {
			if got != want {
				failed = true
				t.Errorf("%s: %s: %v, want %v", phase, what, got, want)
			}
		}
		host, peer := l.send(t, "lvrg0", "lvrg1", vrrpGroupMAC, "10.50.0.5", "224.0.0.18")
		expect("a guest's advert to the VRRP group reached the host", host, guestReachesHost)
		expect("a guest's advert to the VRRP group reached the other guest", peer, true)
		host, _ = l.send(t, "lvrg0", "", l.brMAC, "10.50.0.9", "10.50.0.254")
		expect("a guest's advert forged to the host's address reached the host", host, guestReachesHost)
		_, routed := l.send(t, "lvrg0", "lvrg3", l.brMAC, "10.50.0.5", "10.51.0.5")
		expect("a guest's unicast advert was routed to a guest on another network", routed, true)
		host, _ = l.send(t, "lvrg2", "", vrrpGroupMAC, "10.50.0.9", "224.0.0.18")
		expect("a peer host's advert from the uplink reached the host", host, true)
		if failed {
			t.Logf("ruleset:\n%s", sh(t, "nft", "list", "ruleset"))
		}
	}
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		applyPlan(t, plan(mode))
		check(mode, false)
	}
	applyPlan(t, Plan{})
	check("no tables", true)
}
