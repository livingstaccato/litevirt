//go:build linux

package firewall

import (
	"context"
	"encoding/binary"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"syscall"
	"testing"
	"time"
)

// synFloodWireModules are the modules TestKernelChild_SynFloodOnTheWire makes
// the kernel use: synFloodModules (the meters' nft_limit among them) plus
// veth for its ports.
var synFloodWireModules = append(append([]string(nil), synFloodModules...), "veth")

// etherTo is a frame to dst from src.
func etherTo(dst, src net.HardwareAddr, etype uint16, payload []byte) []byte {
	f := append(append([]byte(nil), dst...), src...)
	f = binary.BigEndian.AppendUint16(f, etype)
	return append(f, payload...)
}

// csum16 is the internet checksum of b, folded, not yet inverted.
func csum16(sum uint32, b []byte) uint32 {
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}

func fold(sum uint32) uint16 {
	for sum > 0xffff {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

// ipv4TCP is an IPv4 TCP segment with no payload and valid checksums (bridge
// conntrack checks them: a bad one is ct state invalid, dropped before the
// SYN-flood line).
func ipv4TCP(src, dst string, sport, dport uint16, seq, ack uint32, flags byte) []byte {
	s4, d4 := net.ParseIP(src).To4(), net.ParseIP(dst).To4()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	pseudo := append(append(append([]byte(nil), s4...), d4...), 0, 6, 0, 20)
	binary.BigEndian.PutUint16(tcp[16:], fold(csum16(csum16(0, pseudo), tcp)))
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:], 40)
	h[8] = 64
	h[9] = 6
	copy(h[12:], s4)
	copy(h[16:], d4)
	binary.BigEndian.PutUint16(h[10:], fold(csum16(0, h)))
	return append(h, tcp...)
}

const (
	tcpSYN = 0x02
	tcpACK = 0x10
)

// synFloodWireResult is what one run of synFloodWire let through.
type synFloodWireResult struct {
	syn1, syn2, ack1 int     // SYNs to NIC 1 and NIC 2, then ACKs to NIC 1, that passed
	elapsed          float64 // seconds the SYNs took to send
}

// synFloodWire builds a bridge with a source port (sfh0, no guest NIC) and two
// guest NICs (sfh1, sfh2), applies plan with those NICs, and from ONE source
// sends n SYNs to each NIC, interleaved, as fast as it can, then n ACKs to
// NIC 1, each the first packet conntrack sees of its flow (a flow already
// open across a table reload or a migration, which conntrack picks up as
// new). What passed is counted at the bridge's postrouting hook, after the
// per-NIC table's verdict, so nothing is lost to a receive buffer.
func synFloodWire(t *testing.T, plan Plan, n int) synFloodWireResult {
	t.Helper()
	sh(t, "ip", "link", "add", "sfbr0", "type", "bridge", "stp_state", "0", "forward_delay", "0")
	macs := map[string]net.HardwareAddr{}
	for _, p := range []string{"0", "1", "2"} {
		sh(t, "ip", "link", "add", "sfg"+p, "type", "veth", "peer", "name", "sfh"+p)
		sh(t, "ip", "link", "set", "sfh"+p, "master", "sfbr0")
		sh(t, "ip", "link", "set", "sfh"+p, "up")
		sh(t, "ip", "link", "set", "sfg"+p, "up")
		ifc, err := net.InterfaceByName("sfg" + p)
		if err != nil {
			t.Fatal(err)
		}
		macs[p] = ifc.HardwareAddr
	}
	sh(t, "ip", "link", "set", "sfbr0", "up")
	t.Cleanup(func() {
		_ = exec.Command("ip", "link", "del", "sfbr0").Run()
		for _, p := range []string{"0", "1", "2"} {
			_ = exec.Command("ip", "link", "del", "sfg"+p).Run()
		}
		_ = exec.Command("nft", "delete", "table", "bridge", "sfcount").Run()
	})

	plan.NICs = []NICBinding{{NICDev: "sfh1", VMName: "vm1", Bridge: "sfbr0"}, {NICDev: "sfh2", VMName: "vm2", Bridge: "sfbr0"}}
	applyPlan(t, plan)
	sh(t, "sh", "-c", `nft add table bridge sfcount && `+
		`nft add chain bridge sfcount post '{ type filter hook postrouting priority 100; policy accept; }' && `+
		`nft add rule bridge sfcount post oifname sfh1 ip saddr 10.30.0.9 tcp flags syn counter comment '"syn1"' && `+
		`nft add rule bridge sfcount post oifname sfh2 ip saddr 10.30.0.9 tcp flags syn counter comment '"syn2"' && `+
		`nft add rule bridge sfcount post oifname sfh1 ip saddr 10.30.0.9 tcp flags ack counter comment '"ack1"'`)

	// The bridge learns where each guest's MAC is, so a SYN to one NIC is
	// not flooded to the other.
	for _, p := range []string{"1", "2"} {
		fd := packetSocket(t, "sfg"+p)
		ifc, _ := net.InterfaceByName("sfg" + p)
		frame := etherTo(bcast, macs[p], 0x0806, arpRequest(macs[p], "10.30.0."+p, "10.30.0.9"))
		if err := syscall.Sendto(fd, frame, 0, &syscall.SockaddrLinklayer{Ifindex: ifc.Index, Halen: 6}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(100 * time.Millisecond)

	tx := packetSocket(t, "sfg0")
	src, _ := net.InterfaceByName("sfg0")
	send := func(p string, sport uint16, flags byte) {
		var ack uint32
		if flags&tcpACK != 0 {
			ack = 1 // mid-flow
		}
		seg := ipv4TCP("10.30.0.9", "10.30.0."+p, sport, 80, uint32(sport)*7919, ack, flags)
		if err := syscall.Sendto(tx, etherTo(macs[p], src.HardwareAddr, 0x0800, seg), 0,
			&syscall.SockaddrLinklayer{Ifindex: src.Index, Halen: 6}); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	var r synFloodWireResult
	start := time.Now()
	for i := 0; i < n; i++ {
		send("1", uint16(10000+i), tcpSYN)
		send("2", uint16(10000+i), tcpSYN)
	}
	r.elapsed = time.Since(start).Seconds()
	for i := 0; i < n; i++ {
		send("1", uint16(30000+i), tcpACK)
	}
	time.Sleep(200 * time.Millisecond)

	counters := sh(t, "nft", "list", "table", "bridge", "sfcount")
	count := func(name string) int {
		m := regexp.MustCompile(`packets ([0-9]+) bytes [0-9]+ comment "` + name + `"`).FindStringSubmatch(counters)
		if m == nil {
			t.Fatalf("no counter %s in:\n%s", name, counters)
		}
		v, _ := strconv.Atoi(m[1])
		return v
	}
	r.syn1, r.syn2, r.ack1 = count("syn1"), count("syn2"), count("ack1")
	t.Logf("sent %d SYNs to each NIC in %.3fs, then %d ACKs: passed SYNs NIC 1 %d, NIC 2 %d; ACKs %d",
		n, r.elapsed, n, r.syn1, r.syn2, r.ack1)
	return r
}

// TestKernelChild_SynFloodWireHarness runs synFloodWire with no SYN-flood
// protection: every SYN and every ACK arrives where it was sent, and nowhere
// else. It needs no nft_limit, so it proves the harness (frames, checksums,
// the bridge's learning, the counters) wherever the kernel tests run, and
// TestKernelChild_SynFloodOnTheWire's shortfalls are then the limit's.
func TestKernelChild_SynFloodWireHarness(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the SYN-flood wire harness", append(append([]string(nil), kernelTestModules...), "veth")...)
	const n = 1500
	r := synFloodWire(t, Plan{NICMode: NICModeEnforce}, n)
	if r.syn1 != n || r.syn2 != n || r.ack1 != n {
		t.Errorf("with no protection: %d and %d SYNs and %d ACKs passed, want %d each", r.syn1, r.syn2, r.ack1, n)
	}
}

// TestKernelChild_SynFloodOnTheWire pushes real SYNs through a real bridge
// with SYN-flood protection in force (spec §1.7): ONE source sends 1500 SYNs
// to each of two guest NICs, interleaved, as fast as it can. Each NIC lets
// through its own budget, because the meter is keyed per (NIC, source): at
// least the burst B, at most B + R plus what the rate refills while the SYNs
// are sent, plus 10%. Then 1500 ACKs from the same source, each new to
// conntrack: every one arrives, because only SYNs are limited.
//
// Mutations: key the sets on the source address only — NIC 2 shares NIC 1's
// budget and gets well under B: red; drop the `tcp flags` match — the ACKs are
// limited too: red.
func TestKernelChild_SynFloodOnTheWire(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the SYN-flood wire test", synFloodWireModules...)
	const rate, burst, n = 200, 1000, 1500
	r := synFloodWire(t, Plan{NICMode: NICModeEnforce, SynFlood: SynFlood{On: true, Rate: rate, Burst: burst}}, n)
	hi := int(float64(burst+rate) + float64(rate)*r.elapsed)
	hi += hi / 10
	for i, got := range []int{r.syn1, r.syn2} {
		if got < burst || got > hi {
			t.Errorf("NIC %d: %d SYNs passed, want %d-%d", i+1, got, burst, hi)
		}
	}
	if r.ack1 != n {
		t.Errorf("%d of %d ACKs arrived after the SYN budget was spent, want all", r.ack1, n)
	}
}

// TestKernelChild_SynFloodProbeAccepted: the daemon's start probe
// (ProbeSynFlood) is accepted by a kernel with nft_limit, so a host that can
// limit SYNs does not report itself unavailable.
//
// Mutation: probe a line nft refuses (the comment before the drop) — red.
func TestKernelChild_SynFloodProbeAccepted(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the SYN-flood probe", synFloodModules...)
	if err := ProbeSynFlood(context.Background()); err != nil {
		t.Errorf("the kernel refused the SYN-flood probe: %v", err)
	}
}
