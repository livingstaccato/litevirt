package e2e

// SYN-flood protection proven with real traffic on a lab node (spec §1.7,
// plan B9). The flood comes from a network namespace on the guest's host,
// attached to the guest's bridge by a veth (a port that is no guest NIC, as
// the uplink or another host's traffic is), and what reaches the guest is
// counted at the bridge's postrouting hook, after the per-NIC table's
// verdict. The injector is a short python3 script sending raw frames, so the
// guests need nothing installed.

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// synfloodInjector is the python3 script that floods: argv is the interface,
// the destination MAC, source and destination IPv4, the VLAN (0 for none),
// SYNs per second and seconds. It prints the seconds it took.
const synfloodInjector = `
import socket, struct, sys, time
dev, dmac, src, dst, vid, rate, secs = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], int(sys.argv[5]), int(sys.argv[6]), float(sys.argv[7])
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((dev, 0))
smac = s.getsockname()[4]
def csum(b):
    if len(b) % 2: b += b"\0"
    t = sum(struct.unpack("!%dH" % (len(b)//2), b))
    while t >> 16: t = (t & 0xffff) + (t >> 16)
    return (~t) & 0xffff
sa, da = socket.inet_aton(src), socket.inet_aton(dst)
def frame(sport):
    tcp = struct.pack("!HHIIBBHHH", sport, 22, sport * 7919 & 0xffffffff, 0, 5 << 4, 0x02, 64240, 0, 0)
    tcp = tcp[:16] + struct.pack("!H", csum(sa + da + struct.pack("!BBH", 0, 6, 20) + tcp)) + tcp[18:]
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40, 0, 0, 64, 6, 0, sa, da)
    ip = ip[:10] + struct.pack("!H", csum(ip)) + ip[12:]
    eth = bytes.fromhex(dmac.replace(":", "")) + smac
    if vid:
        eth += struct.pack("!HH", 0x8100, vid)
    return eth + struct.pack("!H", 0x0800) + ip + tcp
n, total, start = 0, int(rate * secs), time.time()
while n < total:
    due = start + n / rate
    now = time.time()
    if now < due:
        time.sleep(due - now)
    s.send(frame(1024 + n % 60000))
    n += 1
print("%.3f" % (time.time() - start))
`

// TestFirewall_SynfloodLimitsPerNICAndSource: with SYN-flood protection on at
// 200/1000 and per-NIC rules enforced, 10k SYN/s for 10 s from ONE source to a
// guest's open port reaches the guest at least B and at most B + R + 10R plus
// 10% times (the measured send time), the host's `lv-sf 4` counter is above
// zero, and `lv firewall synflood status` reports the host's drops. The same
// holds for 802.1Q-tagged SYNs into a trunk NIC (spec §1.5: `meta protocol`
// first, so the bridge family adds no implicit `ether type` that would miss
// them).
//
// Mutations (run on the lab): place the line after the NIC's ingress accept —
// the guest sees all 100k: red; drop `meta protocol` — the tagged case is not
// limited: red.
func TestFirewall_SynfloodLimitsPerNICAndSource(t *testing.T) {
	l := newLab(t)
	host := l.hosts[0]
	const rate, burst, pps, secs = 200, 1000, 10000, 10

	prevMode := "observe"
	if strings.Contains(l.mustLV(host, "firewall", "enforce", "status"), "per-NIC enforcement: enforce") {
		prevMode = "enforce"
	}
	l.onRestore(func() {
		arg := "off"
		if prevMode == "enforce" {
			arg = "on"
		}
		_, _ = l.lv(host, "firewall", "enforce", arg)
	})
	l.mustLV(host, "firewall", "enforce", "on")

	prevSF := regexp.MustCompile(`^cluster: on, ([0-9]+)/second burst ([0-9]+)`).FindStringSubmatch(l.mustLV(host, "firewall", "synflood", "status"))
	l.onRestore(func() {
		if prevSF != nil {
			_, _ = l.lv(host, "firewall", "synflood", "on", "--rate", prevSF[1], "--burst", prevSF[2])
			return
		}
		_, _ = l.lv(host, "firewall", "synflood", "off")
	})
	l.mustLV(host, "firewall", "synflood", "on", "--rate", strconv.Itoa(rate), "--burst", strconv.Itoa(burst))

	stack := uniqueName("sfl")
	yaml := fmt.Sprintf(`name: %[1]s
networks:
  sf:
    type: bridge
    interface: e2esfbr
    subnet: 10.207.0.0/24
    dhcp: true
  sf2:
    type: bridge
    interface: e2esf2br
vms:
  d:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: sf}]
    placement: {host: %[4]s}
  t:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: sf}, {name: sf2, trunk: [100]}]
    placement: {host: %[4]s}
`, stack, drillImage(), drillMemory(), host)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(host, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	l.onRestore(func() {
		_, _ = l.ssh(host, 30*time.Second, "ip netns del e2esfns 2>/dev/null; ip link del e2esfh 2>/dev/null; ip link del e2esfh2 2>/dev/null")
		_, _ = l.lv(host, "compose", "down", "-f", file, "-y")
		_, _ = l.ssh(host, 30*time.Second, "ip link del e2esfbr 2>/dev/null; ip link del e2esf2br 2>/dev/null; rm -f "+file)
	})
	l.mustLV(host, "compose", "up", "-f", file, "-y")

	names := map[string]string{}
	for _, n := range []string{"d", "t"} {
		names[n] = n
		for _, cand := range []string{n, stack + "_" + n, stack + "-" + n} {
			if rows, _ := l.sql(host, "SELECT name FROM vms WHERE name = '"+cand+"' AND deleted_at IS NULL"); len(rows) == 1 {
				names[n] = cand
				break
			}
		}
		if !l.waitDomainState(host, names[n], "running", 4*time.Minute) {
			t.Fatalf("%s never ran", names[n])
		}
	}
	dIP := l.guestIP(host, names["d"], 5*time.Minute)
	nic := func(vm, netSuffix string) (mac, tap, network string) {
		rows := l.mustSQL(host, "SELECT mac, network_name FROM vm_interfaces WHERE vm_name = '"+vm+"' AND network_name LIKE '%"+netSuffix+
			"' AND deleted_at IS NULL")
		if len(rows) == 0 {
			t.Fatalf("no NIC of %s on %s", vm, netSuffix)
		}
		mac = strings.ToLower(rows[0][0])
		return mac, "lvt" + strings.ReplaceAll(mac, ":", ""), rows[0][1]
	}
	dMAC, dTap, _ := nic(names["d"], "sf")
	tMAC, tTap, trunkNet := nic(names["t"], "sf2")
	l.mustLV(host, "network", "set", trunkNet, "--allowed-vlans", "100")
	l.mustLV(host, "firewall", "reload")

	// The injector: one namespace, one veth into each bridge.
	l.mustSSH(host, 30*time.Second, strings.Join([]string{
		"ip netns add e2esfns",
		"ip link add e2esfi type veth peer name e2esfh", "ip link set e2esfi netns e2esfns",
		"ip link set e2esfh master e2esfbr", "ip link set e2esfh up",
		"ip link add e2esfi2 type veth peer name e2esfh2", "ip link set e2esfi2 netns e2esfns",
		"ip link set e2esfh2 master e2esf2br", "ip link set e2esfh2 up",
		"ip -n e2esfns link set e2esfi up", "ip -n e2esfns link set e2esfi2 up",
		// A VLAN-filtering bridge admits VLAN 100 on the injector's port.
		"if [ \"$(cat /sys/class/net/e2esf2br/bridge/vlan_filtering)\" = 1 ]; then bridge vlan add dev e2esfh2 vid 100; fi",
	}, " && "))
	injMAC := func(dev string) string {
		return strings.TrimSpace(l.mustSSH(host, 20*time.Second, "ip netns exec e2esfns cat /sys/class/net/"+dev+"/address"))
	}
	script := base64.StdEncoding.EncodeToString([]byte(synfloodInjector))
	flood := func(dev, dmac, dst string, vid int) float64 {
		out := l.mustSSH(host, 2*time.Minute, fmt.Sprintf("echo %s | base64 -d > /tmp/e2esf.py && ip netns exec e2esfns python3 /tmp/e2esf.py %s %s 10.207.0.250 %s %d %d %d",
			script, dev, dmac, dst, vid, pps, secs))
		d, err := strconv.ParseFloat(strings.TrimSpace(out), 64)
		if err != nil {
			t.Fatalf("injector: %q", out)
		}
		return d
	}
	bounds := func(elapsed float64) (int, int) {
		hi := float64(burst+rate) + float64(rate)*elapsed
		return burst, int(hi * 1.1)
	}

	t.Run("untagged", func(t *testing.T) {
		count := l.probe(host, "sf", "bridge", "postrouting", 100,
			"oifname "+dTap+" ether saddr "+injMAC("e2esfi")+" tcp flags syn")
		elapsed := flood("e2esfi", dMAC, dIP, 0)
		time.Sleep(2 * time.Second)
		got := count()
		lo, hi := bounds(elapsed)
		l.mark("untagged: %d of %d SYNs reached %s in %.1fs (want %d-%d)", got, pps*secs, dTap, elapsed, lo, hi)
		if got < lo || got > hi {
			t.Errorf("%d SYNs reached the guest, want %d-%d", got, lo, hi)
		}
		ruleset := l.mustSSH(host, 30*time.Second, "nft list table bridge litevirt-nic")
		l.saveEvidence("synflood-ruleset.txt", ruleset)
		var dropped int
		for _, m := range regexp.MustCompile(`counter packets ([0-9]+) bytes [0-9]+ drop comment "lv-sf 4"`).FindAllStringSubmatch(ruleset, -1) {
			n, _ := strconv.Atoi(m[1])
			dropped += n
		}
		if dropped == 0 {
			t.Error("the host's lv-sf 4 counters are zero after the flood")
		}
		status := l.mustLV(host, "firewall", "synflood", "status")
		l.saveEvidence("synflood-status.txt", status)
		row := regexp.MustCompile(`(?m)^` + regexp.QuoteMeta(host) + `\s.*$`).FindString(status)
		if f := strings.Fields(row); len(f) < 8 || f[6] == "0" || f[6] == "-" {
			t.Errorf("status does not report this host's IPv4 drops: %q", row)
		}
	})

	t.Run("tagged into a trunk NIC", func(t *testing.T) {
		count := l.probe(host, "sft", "bridge", "postrouting", 100,
			"oifname "+tTap+" ether saddr "+injMAC("e2esfi2"))
		elapsed := flood("e2esfi2", tMAC, "10.217.100.2", 100)
		time.Sleep(2 * time.Second)
		got := count()
		lo, hi := bounds(elapsed)
		l.mark("tagged: %d of %d SYNs reached %s in %.1fs (want %d-%d)", got, pps*secs, tTap, elapsed, lo, hi)
		if got > hi {
			t.Errorf("%d tagged SYNs reached the trunk NIC, want at most %d: the limiter misses tagged frames", got, hi)
		}
		if got < lo {
			t.Errorf("only %d tagged SYNs reached the trunk NIC, want at least %d (VLAN 100 allowed)", got, lo)
		}
	})
}
