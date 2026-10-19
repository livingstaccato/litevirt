//go:build linux

package firewall

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
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

// synIPv4TCP is an IPv4 TCP segment with no payload and valid checksums (bridge
// conntrack checks them: a bad one is ct state invalid, dropped before the
// SYN-flood line).
func synIPv4TCP(src, dst string, sport, dport uint16, seq, ack uint32, flags byte) []byte {
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

// ipv6TCP is an IPv6 TCP segment with no payload and a valid checksum.
func ipv6TCP(src, dst string, sport, dport uint16, seq, ack uint32, flags byte) []byte {
	s6, d6 := net.ParseIP(src).To16(), net.ParseIP(dst).To16()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], sport)
	binary.BigEndian.PutUint16(tcp[2:], dport)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	binary.BigEndian.PutUint32(tcp[8:], ack)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 64240)
	pseudo := append(append(append([]byte(nil), s6...), d6...), 0, 0, 0, 20, 0, 0, 0, 6)
	binary.BigEndian.PutUint16(tcp[16:], fold(csum16(csum16(0, pseudo), tcp)))
	h := make([]byte, 40)
	h[0] = 0x60
	binary.BigEndian.PutUint16(h[4:], 20)
	h[6] = 6
	h[7] = 64
	copy(h[8:], s6)
	copy(h[24:], d6)
	return append(h, tcp...)
}

// synFloodWireResult is what one run of synFloodWire let through.
type synFloodWireResult struct {
	syn1, syn2, ack1 int     // SYNs to NIC 1 and NIC 2, then ACKs to NIC 1, that passed
	elapsed          float64 // seconds the SYNs took to send
}

// synFloodWire builds a bridge with a source port (sfh0, no guest NIC) and two
// guest NICs (sfh1, sfh2), applies plan with those NICs, and sends n SYNs to
// each NIC, interleaved, as fast as it can, then n ACKs to NIC 1, each the
// first packet conntrack sees of its flow (a flow already open across a table
// reload or a migration, which conntrack picks up as new). IPv4 comes from
// ONE source, 10.30.0.9. With v6 every segment comes from its own address in
// ONE /64, 2001:db8:9::/64, as a host rotating addresses within its prefix
// does. What passed is counted at the bridge's postrouting hook, after the
// per-NIC table's verdict, so nothing is lost to a receive buffer.
func synFloodWire(t *testing.T, plan Plan, n int, v6 bool, vid int) synFloodWireResult {
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
		_ = exec.Command("nft", "delete", "table", "bridge", NICTableName).Run()
	})

	plan.NICs = []NICBinding{{NICDev: "sfh1", VMName: "vm1", Bridge: "sfbr0"}, {NICDev: "sfh2", VMName: "vm2", Bridge: "sfbr0"}}
	if vid > 0 {
		// Both guest NICs are trunks carrying VLAN vid.
		for i := range plan.NICs {
			plan.NICs[i].TrunkVIDs = []int{vid}
		}
	}
	applyPlan(t, plan)
	// meta protocol first, so a tagged frame is counted too.
	src := "meta protocol ip ip saddr 10.30.0.9 meta l4proto tcp"
	if v6 {
		src = "meta protocol ip6 ip6 saddr 2001:db8:9::/64 meta l4proto tcp"
	}
	sh(t, "sh", "-c", `nft add table bridge sfcount && `+
		`nft add chain bridge sfcount post '{ type filter hook postrouting priority 100; policy accept; }' && `+
		`nft add rule bridge sfcount post oifname sfh1 `+src+` tcp flags syn counter comment '"syn1"' && `+
		`nft add rule bridge sfcount post oifname sfh2 `+src+` tcp flags syn counter comment '"syn2"' && `+
		`nft add rule bridge sfcount post oifname sfh1 `+src+` tcp flags ack counter comment '"ack1"'`)

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
	srcIfc, _ := net.InterfaceByName("sfg0")
	send := func(p string, i int, flags byte) {
		sport := uint16(10000 + i)
		var ack uint32
		if flags&tcpACK != 0 {
			sport, ack = uint16(30000+i), 1 // mid-flow
		}
		etype, seg := uint16(0x0800), synIPv4TCP("10.30.0.9", "10.30.0."+p, sport, 80, uint32(sport)*7919, ack, flags)
		if v6 {
			etype = 0x86dd
			seg = ipv6TCP(fmt.Sprintf("2001:db8:9::%x:%x", i>>16+1, i&0xffff), "2001:db8::"+p, sport, 80, uint32(sport)*7919, ack, flags)
		}
		frame := etherTo(macs[p], srcIfc.HardwareAddr, etype, seg)
		if vid > 0 {
			frame = taggedType(srcIfc.HardwareAddr, 0x8100, etype, seg, uint16(vid))
			copy(frame[0:6], macs[p])
		}
		if err := syscall.Sendto(tx, frame, 0,
			&syscall.SockaddrLinklayer{Ifindex: srcIfc.Index, Halen: 6}); err != nil {
			t.Fatalf("send: %v", err)
		}
	}
	var r synFloodWireResult
	start := time.Now()
	for i := 0; i < n; i++ {
		send("1", i, tcpSYN)
		send("2", i, tcpSYN)
	}
	r.elapsed = time.Since(start).Seconds()
	for i := 0; i < n; i++ {
		send("1", i, tcpACK)
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
	t.Logf("v6=%v vid=%d: sent %d SYNs to each NIC in %.3fs, then %d ACKs: passed SYNs NIC 1 %d, NIC 2 %d; ACKs %d",
		v6, vid, n, r.elapsed, n, r.syn1, r.syn2, r.ack1)
	return r
}

// TestKernelChild_SynFloodWireHarness runs synFloodWire with no SYN-flood
// protection, for each family: every SYN and every ACK arrives where it was
// sent, and nowhere else. It needs no nft_limit, so it proves the harness
// (frames, checksums, the bridge's learning, the counters) wherever the
// kernel tests run, and TestKernelChild_SynFloodOnTheWire's shortfalls are
// then the limit's.
func TestKernelChild_SynFloodWireHarness(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the SYN-flood wire harness", kernelTestModules...)
	const n = 1500
	for _, c := range []struct {
		v6  bool
		vid int
	}{{false, 0}, {true, 0}, {false, 100}} {
		t.Run(fmt.Sprintf("v6=%v vid=%d", c.v6, c.vid), func(t *testing.T) {
			r := synFloodWire(t, Plan{NICMode: NICModeEnforce}, n, c.v6, c.vid)
			if r.syn1 != n || r.syn2 != n || r.ack1 != n {
				t.Errorf("with no protection: %d and %d SYNs and %d ACKs passed, want %d each", r.syn1, r.syn2, r.ack1, n)
			}
		})
	}
}

// TestKernelChild_SynFloodOnTheWire pushes real SYNs through a real bridge
// with SYN-flood protection in force (spec §1.7). Each NIC lets through its
// own budget, because the meter is keyed per (NIC, source): at least the
// burst B, at most B + R plus what the rate refills while the SYNs are sent,
// plus 10%. Every ACK new to conntrack arrives, because only SYNs are
// limited. The cases:
//   - one IPv4 source;
//   - the same source in lv_lb_src4 (a routed network's gateway or an LB
//     host: what a masqueraded guest's SYNs carry) — still limited (Track B
//     review I-1);
//   - a load-balancer flow (source in lv_lb_src4, NIC 1's address and port in
//     lv_lb4): every SYN to NIC 1 passes, accepted before the limiter; NIC 2's
//     are limited;
//   - IPv6 from a new address in one /64 for every SYN: limited as one source
//     (review m-7);
//   - 802.1Q-tagged SYNs into trunk NICs carrying the VLAN: limited, and a
//     tagged LB flow passes (round-1 re-review N-m1).
//
// Mutations: key the sets on the source address only — NIC 2 shares NIC 1's
// budget and gets well under B: red; drop the `tcp flags` match — the ACKs
// are limited too: red; exempt lv_lb_src4 again — the gateway case passes
// all: red; key IPv6 per address — the v6 case passes all: red.
func TestKernelChild_SynFloodOnTheWire(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the SYN-flood wire test", synFloodWireModules...)
	const rate, burst, n = 200, 1000, 1500
	on := SynFlood{On: true, Rate: rate, Burst: burst}
	limited := func(t *testing.T, r synFloodWireResult, got int, what string) {
		t.Helper()
		hi := int(float64(burst+rate) + float64(rate)*r.elapsed)
		hi += hi / 10
		if got < burst || got > hi {
			t.Errorf("%s: %d SYNs passed, want %d-%d", what, got, burst, hi)
		}
	}
	for _, tc := range []struct {
		name  string
		plan  Plan
		v6    bool
		lbNIC bool // NIC 1 is an LB backend on port 80
		vid   int  // tagged into trunk NICs carrying this VLAN
	}{
		{"one source", Plan{NICMode: NICModeEnforce, SynFlood: on}, false, false, 0},
		{"gateway source", Plan{NICMode: NICModeEnforce, SynFlood: on, LBSources: []string{"10.30.0.9"}}, false, false, 0},
		{"lb flow", Plan{NICMode: NICModeEnforce, SynFlood: on, LBSources: []string{"10.30.0.9"},
			LBBackends: []LBBackend{{Addr: "10.30.0.1", Port: 80}}}, false, true, 0},
		{"ipv6 one /64", Plan{NICMode: NICModeEnforce, SynFlood: on}, true, false, 0},
		{"one source, tagged", Plan{NICMode: NICModeEnforce, SynFlood: on}, false, false, 100},
		{"lb flow, tagged", Plan{NICMode: NICModeEnforce, SynFlood: on, LBSources: []string{"10.30.0.9"},
			LBBackends: []LBBackend{{Addr: "10.30.0.1", Port: 80}}}, false, true, 100},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := synFloodWire(t, tc.plan, n, tc.v6, tc.vid)
			if tc.lbNIC {
				if r.syn1 != n {
					t.Errorf("LB flow: %d of %d SYNs to the backend passed, want all", r.syn1, n)
				}
			} else {
				limited(t, r, r.syn1, "NIC 1")
			}
			limited(t, r, r.syn2, "NIC 2")
			if r.ack1 != n {
				t.Errorf("%d of %d ACKs arrived after the SYN budget was spent, want all", r.ack1, n)
			}
		})
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
	if r := ProbeSynFlood(context.Background()); r.V4 != nil || r.V6 != nil {
		t.Errorf("the kernel refused the SYN-flood probe: IPv4 %v, IPv6 %v", r.V4, r.V6)
	}
}

// TestKernelChild_SynFloodDropsReadsTheTable: SynFloodDrops reads a real
// kernel's per-NIC table. With no table it is zero and no error; with the
// SYN-flood ruleset loaded (its limit taken out, so nft_limit is not needed)
// and each lv-sf counter preset, it sums them per family over forward and
// output.
//
// Mutation: read the counter from the wrong JSON place (the rule's handle) —
// red.
func TestKernelChild_SynFloodDropsReadsTheTable(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the SYN-flood counters", "nf_tables", "nf_conntrack", "nft_ct", "nf_conntrack_bridge", "nft_meta_bridge", "bridge")
	_ = exec.Command("nft", "delete", "table", "bridge", NICTableName).Run()
	if v4, v6, err := SynFloodDrops(context.Background()); err != nil || v4 != 0 || v6 != 0 {
		t.Fatalf("no table: %d, %d, %v; want 0, 0, nil", v4, v6, err)
	}
	script := synFloodScripts(t)[NICModeEnforce]
	script = regexp.MustCompile(` limit rate over [0-9]+/second burst [0-9]+ packets`).ReplaceAllString(script, "")
	script = strings.ReplaceAll(script, `counter drop comment "lv-sf 4"`, `counter packets 5 bytes 300 drop comment "lv-sf 4"`)
	script = strings.ReplaceAll(script, `counter drop comment "lv-sf 6"`, `counter packets 3 bytes 240 drop comment "lv-sf 6"`)
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("load: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "bridge", NICTableName).Run() })
	if v4, v6, err := SynFloodDrops(context.Background()); err != nil || v4 != 10 || v6 != 6 {
		t.Errorf("preset counters: %d, %d, %v; want 10, 6", v4, v6, err)
	}
}

// TestKernelChild_ProbeRefusedByTheKernel: ProbeRuleset reports a body a real
// kernel refuses (a jump to a chain that does not exist, refused by the
// kernel, not by nft's parser) and accepts one it takes; neither is loaded.
// The daemon's SYN-flood probe relies on exactly this path to render nothing
// on a kernel without nft_limit (Track B review m-6).
//
// Mutation: ProbeRuleset ignores nft's exit status — red.
func TestKernelChild_ProbeRefusedByTheKernel(t *testing.T) {
	inNetns(t)
	skipUnlessModules(t, "the probe", "nf_tables", "bridge")
	ctx := context.Background()
	if err := ProbeRuleset(ctx, "    chain forward {\n        type filter hook forward priority 0; policy accept;\n        counter\n    }\n"); err != nil {
		t.Fatalf("the kernel refused a plain probe: %v", err)
	}
	err := ProbeRuleset(ctx, "    chain forward {\n        type filter hook forward priority 0; policy accept;\n        jump lv_no_such_chain\n    }\n")
	if err == nil {
		t.Fatal("a probe the kernel refuses was reported as accepted")
	}
	t.Logf("refused as expected: %v", err)
	if out := sh(t, "nft", "list", "tables"); strings.Contains(out, ProbeTableName()) {
		t.Errorf("a probe left its table behind: %s", out)
	}
}

// TestKernelChild_SynFloodAndLogLoad: a plan with SYN-flood protection AND
// firewall logging both on (a new cluster records SYN-flood on, and a log
// policy is set on top) renders one ruleset a real nft accepts, in enforce
// and observe mode. `nft -c` changes nothing. Each feature's own child proves
// it alone; this proves them together (B+C merge review m-2).
//
// Mutation: render the SYN-flood counter's comment before its verdict — nft
// refuses the combined ruleset: red.
func TestKernelChild_SynFloodAndLogLoad(t *testing.T) {
	inNetns(t)
	mods := append(append([]string(nil), logFormsModules...), synFloodModules...)
	skipUnlessModules(t, "the SYN-flood and log ruleset", mods...)
	for _, mode := range []string{NICModeEnforce, NICModeObserve} {
		p := goldenLogPlan(mode)
		p.SynFlood = SynFlood{On: true, Rate: 200, Burst: 1000}
		script, err := Render(p)
		if err != nil {
			t.Fatalf("%s: Render: %v", mode, err)
		}
		if !strings.Contains(script, "update @"+setSyn4) || !strings.Contains(script, "update @"+setSyn6) || !strings.Contains(script, " log group ") {
			t.Fatalf("%s: the ruleset does not carry both SYN-flood lines and a log line", mode)
		}
		if err := nftCheck(t, script); err != nil {
			t.Errorf("%s: nft -c refused the SYN-flood and log ruleset: %v", mode, err)
		}
	}
}
