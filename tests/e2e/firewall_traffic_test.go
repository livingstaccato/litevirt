package e2e

// Firewall enforcement proven with real traffic between real guests.
//
// The older TestFirewall inspects the rendered ruleset only, which is how a
// per-NIC chain that matched the tap in the inet forward hook — a hook bridged
// traffic between two guests never reaches — passed for a long time while
// enforcing nothing (lab 2, 2026-10-10). These cases send packets from inside
// guests and assert what arrives.
//
// Guests are cirros (E2E_DRILL_IMAGE). The test logs into a guest over SSH
// through its host node (`ssh -W`), with cirros' default credentials unless
// E2E_GUEST_USER / E2E_GUEST_PASSWORD say otherwise. cirros can spend many
// minutes retrying a metadata service before its SSH server starts, so the
// budget for that is generous.

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// stdioConn adapts an `ssh -W` process's stdin/stdout to a net.Conn.
type stdioConn struct {
	io.Reader
	io.WriteCloser
	cmd *exec.Cmd
}

func (c *stdioConn) Close() error {
	c.WriteCloser.Close()
	_ = c.cmd.Process.Kill()
	_ = c.cmd.Wait()
	return nil
}
func (c *stdioConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (c *stdioConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c *stdioConn) SetDeadline(time.Time) error      { return nil }
func (c *stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stdioConn) SetWriteDeadline(time.Time) error { return nil }

// guestRun runs cmd inside the guest at ip, reached through node host. It
// returns the combined output and whether the command exited 0; err is a
// failure to reach or log into the guest.
func (l *lab) guestRun(host, ip, cmd string) (string, bool, error) {
	args := append(l.sshArgs(host)[:len(l.sshArgs(host))-1], "-W", ip+":22", "root@127.0.0.1")
	c := exec.Command("ssh", args...)
	in, err := c.StdinPipe()
	if err != nil {
		return "", false, err
	}
	out, err := c.StdoutPipe()
	if err != nil {
		return "", false, err
	}
	if err := c.Start(); err != nil {
		return "", false, err
	}
	conn := &stdioConn{Reader: out, WriteCloser: in, cmd: c}
	cfg := &ssh.ClientConfig{
		User:            envOr("E2E_GUEST_USER", "cirros"),
		Auth:            []ssh.AuthMethod{ssh.Password(envOr("E2E_GUEST_PASSWORD", "gocubsgo"))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a throwaway test guest
		Timeout:         20 * time.Second,
	}
	sc, chans, reqs, err := ssh.NewClientConn(conn, ip+":22", cfg)
	if err != nil {
		conn.Close()
		return "", false, err
	}
	client := ssh.NewClient(sc, chans, reqs)
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", false, err
	}
	defer sess.Close()
	b, rerr := sess.CombinedOutput(cmd)
	return string(b), rerr == nil, nil
}

// waitGuestSSH waits until the guest at ip accepts a login.
func (l *lab) waitGuestSSH(host, ip string, timeout time.Duration) {
	l.t.Helper()
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		if _, ok, err := l.guestRun(host, ip, "true"); err == nil && ok {
			return
		} else {
			last = err
		}
		time.Sleep(10 * time.Second)
	}
	l.t.Fatalf("guest %s never accepted a login within %v: %v", ip, timeout, last)
}

// guestIP finds a VM's address in its host's dnsmasq leases, by the MAC its
// NIC row records.
func (l *lab) guestIP(host, vm string, timeout time.Duration) string {
	l.t.Helper()
	rows := l.mustSQL(host, fmt.Sprintf(`SELECT mac FROM vm_interfaces WHERE vm_name = '%s' AND deleted_at IS NULL`, vm))
	if len(rows) == 0 {
		l.t.Fatalf("no NIC row for %s", vm)
	}
	mac := strings.ToLower(rows[0][0])
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := l.ssh(host, 20*time.Second,
			"cat /var/lib/libvirt/dnsmasq/litevirt-*.leases 2>/dev/null | awk 'tolower($2)==\""+mac+"\" {print $3}' | tail -1")
		if ip := strings.TrimSpace(out); ip != "" {
			return ip
		}
		time.Sleep(10 * time.Second)
	}
	if v := guestBootVerdict(l.domStats(host, vm)); v != "" {
		l.t.Fatalf("%s (%s) on %s: %s", vm, mac, host, v)
	}
	l.t.Fatalf("%s (%s) never took a DHCP lease on %s", vm, mac, host)
	return ""
}

// domStats is virsh's per-interface counters for vm, or "" when they cannot be
// read.
func (l *lab) domStats(host, vm string) string {
	out, _ := l.ssh(host, 20*time.Second, "virsh -c qemu:///system domstats --interface "+shellQuote(vm)+" 2>/dev/null")
	return out
}

var netTxPkts = regexp.MustCompile(`(?m)^\s*net\.\d+\.tx\.pkts=(\d+)`)

// guestBootVerdict reads `virsh domstats --interface` output: when every NIC
// shows zero transmitted packets the guest never sent a frame (not even a DHCP
// discover), so it never booted and the missing lease says nothing about
// DHCP. It returns "" when the counters are unreadable or show traffic.
func guestBootVerdict(domstats string) string {
	m := netTxPkts.FindAllStringSubmatch(domstats, -1)
	if len(m) == 0 {
		return ""
	}
	for _, x := range m {
		if x[1] != "0" {
			return ""
		}
	}
	return "guest never booted: no frames sent from any NIC (check its firmware and memory; a small cirros needs BIOS), so it never asked for a DHCP lease"
}

// guestTap is the host device of vm's (only) NIC.
func (l *lab) guestTap(host, vm string) string {
	l.t.Helper()
	out := l.mustSSH(host, 20*time.Second, "virsh domiflist "+shellQuote(vm)+" | awk 'NR>2 && $1!=\"\" {print $1; exit}'")
	tap := strings.TrimSpace(out)
	if tap == "" {
		l.t.Fatalf("no tap for %s on %s", vm, host)
	}
	return tap
}

// probe installs a counting rule on host in its own table and returns a
// reader for the count. family/hook/priority place it; match is the nft
// match. The table is removed when the test ends.
func (l *lab) probe(host, name, family, hook string, priority int, match string) func() int {
	l.t.Helper()
	tbl := "e2eprobe_" + name
	l.mustSSH(host, 20*time.Second, fmt.Sprintf(
		`nft add table %[1]s %[2]s && nft add chain %[1]s %[2]s c '{ type filter hook %[3]s priority %[4]d; policy accept; }' && nft add rule %[1]s %[2]s c %[5]s counter`,
		family, tbl, hook, priority, match))
	l.onRestore(func() { _, _ = l.ssh(host, 20*time.Second, "nft delete table "+family+" "+tbl) })
	return func() int {
		out := l.mustSSH(host, 20*time.Second, "nft list chain "+family+" "+tbl+" c | grep -o 'packets [0-9]*' | awk '{print $2}'")
		n, _ := strconv.Atoi(strings.TrimSpace(out))
		return n
	}
}

// TestFirewall_TrafficBetweenVMs: per-NIC rules hold for traffic between two
// guests on ONE bridge, the allowed case passes, replies to a guest's own
// connection come back through a drop-everything ingress policy (stateful),
// and every critical finding of the 2026-10-10 review holds on real traffic:
//
//   - C1: a security group with a reject rule loads (it renders as drop on
//     the bridge), drops, and leaves NAT and the rest of the firewall applied;
//   - C2: a guest whose egress is denied cannot reach a routed UDP/67 by
//     using DHCP's ports;
//   - C3: a tagged frame from an UNGUARDED guest is dropped (and passes once
//     the NIC and every other NIC on its bridge are allowed tags);
//   - I2: a trunk NIC is guarded like any other new NIC and carries only the
//     VLANs its network allows (`lv network set --allowed-vlans`);
//   - C4: a guarded guest on a DHCP network cannot use a neighbour's address
//     or an unassigned one (its exact reservation is all it may use);
//   - observe mode drops nothing and counts what it would have dropped.
//
// Five cirros guests on one host and one bridge:
//
//	a: no security group — the prober
//	b: rejects icmp ingress
//	c: may receive only tcp/22 (so the test can log in), nothing else
//	d: no security group — the allowed target
//	e: may send nothing (and receive only tcp/22)
func TestFirewall_TrafficBetweenVMs(t *testing.T) {
	l := newLab(t)
	host := l.hosts[0]

	// The cluster's per-NIC mode is restored afterwards; this test needs
	// enforcement (and checks observe on the way).
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

	stack := uniqueName("fwt")
	yaml := fmt.Sprintf(`name: %[1]s
security-groups:
  noicmp:
    rules:
      - {direction: ingress, proto: icmp, action: reject}
  sshonly:
    rules:
      - {direction: ingress, proto: tcp, port: "22", action: accept}
      - {direction: ingress, proto: all, action: drop}
  silent:
    rules:
      - {direction: ingress, proto: tcp, port: "22", action: accept}
      - {direction: ingress, proto: all, action: drop}
      - {direction: egress, proto: all, action: drop}
networks:
  fwt:
    type: bridge
    interface: e2efwtbr
    subnet: 10.205.0.0/24
    dhcp: true
  fwt2:
    type: bridge
    interface: e2efwt2br
vms:
  a:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: fwt}]
    placement: {host: %[4]s}
  b:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: fwt, security-groups: [noicmp]}]
    placement: {host: %[4]s}
  c:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: fwt, security-groups: [sshonly]}]
    placement: {host: %[4]s}
  d:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: fwt}]
    placement: {host: %[4]s}
  e:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: fwt, security-groups: [silent]}]
    placement: {host: %[4]s}
  t:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    firmware: bios
    network: [{name: fwt}, {name: fwt2, trunk: [100, 101]}]
    placement: {host: %[4]s}
`, stack, drillImage(), drillMemory(), host)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(host, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	l.onRestore(func() {
		_, _ = l.lv(host, "compose", "down", "-f", file, "-y")
		_, _ = l.ssh(host, 30*time.Second, "ip link del e2efwtbr 2>/dev/null; ip link del e2efwt2br 2>/dev/null; rm -f "+file)
	})
	l.mustLV(host, "compose", "up", "-f", file, "-y")

	short := []string{"a", "b", "c", "d", "e", "t"}
	names := map[string]string{}
	for _, n := range short {
		names[n] = n
		for _, cand := range []string{n, stack + "_" + n, stack + "-" + n} {
			if rows, _ := l.sql(host, "SELECT name FROM vms WHERE name = '"+cand+"' AND deleted_at IS NULL"); len(rows) == 1 {
				names[n] = cand
				break
			}
		}
	}
	ip := map[string]string{}
	for _, n := range short {
		if !l.waitDomainState(host, names[n], "running", 4*time.Minute) {
			t.Fatalf("%s never ran", names[n])
		}
		ip[n] = l.guestIP(host, names[n], 5*time.Minute)
	}
	l.mark("guests: %v", ip)
	for _, n := range []string{"a", "c", "e", "t"} {
		l.waitGuestSSH(host, ip[n], 20*time.Minute)
	}
	l.saveEvidence("ruleset.txt", l.mustSSH(host, 30*time.Second, "nft list ruleset"))

	try := func(from, cmd string) bool {
		out, ok, err := l.guestRun(host, ip[from], cmd)
		if err != nil {
			t.Fatalf("log into %s: %v", from, err)
		}
		l.mark("%s$ %s -> ok=%v %s", from, cmd, ok, strings.TrimSpace(out))
		return ok
	}
	ping := func(dst string) string { return "ping -c 3 -W 2 " + dst }
	gw := strings.SplitN(strings.TrimSpace(l.mustSSH(host, 20*time.Second,
		"ip -4 -o addr show dev e2efwtbr | awk '{print $4}' | head -1")), "/", 2)[0]
	if gw == "" {
		t.Fatal("no gateway address on e2efwtbr")
	}
	netName := l.mustSQL(host, "SELECT network_name FROM vm_interfaces WHERE vm_name = '"+names["a"]+"' AND deleted_at IS NULL")[0][0]

	t.Run("SameBridgeDropIsEnforced", func(t *testing.T) {
		if try("a", ping(ip["b"])) {
			t.Errorf("a reached b by icmp; b's group rejects icmp ingress")
		}
		if try("a", ping(ip["c"])) {
			t.Errorf("a reached c by icmp; c's group drops everything but tcp/22")
		}
	})
	t.Run("SameBridgeAllowPasses", func(t *testing.T) {
		if !try("a", ping(ip["d"])) {
			t.Errorf("a could not reach d, which has no group")
		}
		if !try("a", "echo | nc -w 3 "+ip["c"]+" 22 | grep -q SSH-") {
			t.Errorf("a could not reach c's allowed tcp/22")
		}
	})
	t.Run("RepliesToOwnConnectionsAreStateful", func(t *testing.T) {
		if !try("c", ping(ip["d"])) {
			t.Errorf("c's own ping to d got no replies: replies on bridge ports are not tracked "+
				"(is nf_conntrack_bridge loaded on %s?)", host)
		}
	})
	t.Run("C1_RejectRuleLoadsAndLeavesTheRestApplied", func(t *testing.T) {
		show := l.mustLV(host, "firewall", "show")
		if !strings.Contains(show, "table bridge litevirt-nic") {
			t.Errorf("the per-NIC table is not loaded (a reject rule must not get it refused):\n%s", show)
		}
		if st := l.mustLV(host, "firewall", "enforce", "status"); strings.Contains(st, "refused") {
			t.Errorf("a host reports its per-NIC table refused:\n%s", st)
		}
		if nat := l.mustSSH(host, 20*time.Second, "nft list table inet litevirt-fw"); !strings.Contains(nat, "10.205.0.0/24") {
			t.Errorf("NAT for the test network is missing from the inet table:\n%s", nat)
		}
	})
	t.Run("C2_DHCPPortsDoNotBypassEgressDeny", func(t *testing.T) {
		if !try("e", "nc --help 2>&1 | grep -q -- '-u'") {
			t.Skip("the guest's nc cannot send UDP; C2 is proven by the kernel test instead")
		}
		// Port 68 is privileged: the guest's own user cannot bind it (lab 1:
		// "bind: Permission denied"), so both sends run as root in the guest.
		if !try("e", "sudo -n true") || !try("a", "sudo -n true") {
			t.Skip("no passwordless sudo in the guest to bind port 68; C2 is proven by the kernel test instead")
		}
		const target = "192.0.2.67" // TEST-NET-1: routed out through the host
		count := l.probe(host, "c2", "inet", "prerouting", -400, "ip daddr "+target+" udp dport 67")
		try("e", "echo x | sudo nc -u -w 1 -p 68 "+target+" 67; true")
		if n := count(); n != 0 {
			t.Errorf("%d datagrams from a guest whose egress is denied reached the host through DHCP's ports", n)
		}
		try("a", "echo x | sudo nc -u -w 1 -p 68 "+target+" 67; true")
		if count() == 0 {
			t.Error("not even the unrestricted guest's datagram was counted; the zero above proves nothing")
		}
	})
	t.Run("C4_NeighbourAndUnassignedAddressCannotBeClaimed", func(t *testing.T) {
		// Not the gateway's address: it is the source of the harness's own
		// `ssh -W` session into the guest, and a guest that claims it cuts
		// that session (lab 1). Claiming the gateway is proven by the kernel
		// test; here a neighbour's address and one no NIC holds are claimed,
		// which the same exact guard must drop.
		const unassigned = "10.205.0.240"
		tap := l.guestTap(host, names["a"])
		count := l.probe(host, "c4", "bridge", "input", 100,
			"iifname "+tap+" ip saddr { "+unassigned+", "+ip["d"]+" }")
		own := l.probe(host, "c4own", "bridge", "input", 100, "iifname "+tap+" ip saddr "+ip["a"])
		try("a", ping(gw)) // the gateway's MAC is cached from the real address first
		if own() == 0 {
			t.Fatal("a's own packets never reached the probe; it would count nothing either way")
		}
		try("a", "sudo ip addr add "+unassigned+"/32 dev eth0 2>/dev/null; sudo ip addr add "+ip["d"]+"/32 dev eth0 2>/dev/null; true")
		try("a", "ping -c 2 -W 1 -I "+unassigned+" "+gw+"; ping -c 2 -W 1 -I "+ip["d"]+" "+gw+"; true")
		if n := count(); n != 0 {
			t.Errorf("%d packets claiming a neighbour's or an unassigned address got past a's guard", n)
		}
		try("a", "sudo ip addr del "+unassigned+"/32 dev eth0; sudo ip addr del "+ip["d"]+"/32 dev eth0; true")
	})
	t.Run("C3_TaggedFramesFromAnUnguardedNIC", func(t *testing.T) {
		if !try("a", "sudo ip link add link eth0 name eth0.10 type vlan id 10 && sudo ip addr add 10.215.0.1/24 dev eth0.10 && sudo ip link set eth0.10 up") {
			t.Skip("the guest kernel cannot make a VLAN interface; C3 is proven by the kernel test instead")
		}
		l.mustLV(host, "firewall", "nic-guard", "set", names["a"], "--network", netName, "--mode", "off")
		l.mustLV(host, "firewall", "reload")
		tap := l.guestTap(host, names["a"])
		count := l.probe(host, "c3", "bridge", "forward", 100, "iifname "+tap+" ether type 8021q")
		try("a", "ping -c 3 -W 1 10.215.0.2; true")
		if n := count(); n != 0 {
			t.Errorf("%d tagged frames from an unguarded NIC got past the VLAN rule", n)
		}
		// Positive control. Allowing a to send tags is not enough: a tagged
		// frame is flooded to the bridge's other ports, and the forward chain
		// drops it to every guest NIC that was not itself allowed tags (I1),
		// before this probe at forward priority 100 can count it. So every
		// other NIC on the bridge is allowed tags too, and the frame goes end to
		// end.
		others := []string{"b", "c", "d", "e", "t"}
		// Restored however this ends, so a failure partway through the loop
		// below cannot leave b..t allowed tags for I1. `set` replaces the whole
		// guard, so `--mode on` is the default guard again; this fixture has
		// no other relaxation to lose.
		defer func() {
			for _, n := range append([]string{"a"}, others...) {
				_, _ = l.lv(host, "firewall", "nic-guard", "set", names[n], "--network", netName, "--mode", "on")
			}
			_, _ = l.lv(host, "firewall", "reload")
		}()
		for _, n := range append([]string{"a"}, others...) {
			mode := "on"
			if n == "a" {
				mode = "off"
			}
			l.mustLV(host, "firewall", "nic-guard", "set", names[n], "--network", netName, "--mode", mode, "--allow-vlan-tags")
		}
		l.mustLV(host, "firewall", "reload")
		try("a", "ping -c 3 -W 1 10.215.0.2; true")
		if count() == 0 {
			t.Error("tagged frames from a NIC allowed tags were dropped too (every other NIC on the bridge is allowed them as well); the zero above proves nothing")
		}
		try("a", "sudo ip link del eth0.10; true")
	})
	t.Run("SpoofedSourceIsDropped", func(t *testing.T) {
		const spoof = "10.206.0.199"
		count := l.probe(host, "spoof", "inet", "prerouting", -400, "ip saddr "+spoof)
		try("a", ping(gw))
		try("a", "sudo ip addr add "+spoof+"/32 dev eth0 2>/dev/null; true")
		try("a", "ping -c 3 -W 1 -I "+spoof+" "+gw)
		if n := count(); n != 0 {
			t.Errorf("%d packets from the spoofed %s reached the host; a's guard is on by default", n, spoof)
		}
		l.mustLV(host, "firewall", "nic-guard", "set", names["a"], "--network", netName, "--mode", "off")
		l.mustLV(host, "firewall", "reload")
		try("a", "ping -c 3 -W 1 -I "+spoof+" "+gw)
		if count() == 0 {
			t.Errorf("with a's guard off no spoofed packet reached the host either, so the drop above proves nothing")
		}
		try("a", "sudo ip addr del "+spoof+"/32 dev eth0; true")
		l.mustLV(host, "firewall", "nic-guard", "set", names["a"], "--network", netName, "--mode", "on")
	})
	t.Run("ObserveDropsNothingAndCounts", func(t *testing.T) {
		l.mustLV(host, "firewall", "enforce", "off")
		l.mustLV(host, "firewall", "reload")
		if !try("a", ping(ip["b"])) {
			t.Errorf("in observe mode a still cannot reach b")
		}
		st := l.mustLV(host, "firewall", "enforce", "status")
		if !strings.Contains(st, "observe") || !strings.Contains(st, "sg:noicmp") {
			t.Errorf("observe status does not show b's would-drop:\n%s", st)
		}
		l.mustLV(host, "firewall", "enforce", "on")
	})
	t.Run("I1_TaggedFramesToANICAreDropped", func(t *testing.T) {
		// The host sends tagged frames out of the bridge (a port that is no
		// guest NIC): they must not reach a guest's port, where its guest
		// would strip the tag past its rules.
		l.mustSSH(host, 30*time.Second, "ip link add link e2efwtbr name e2efwtbr.10 type vlan id 10 && "+
			"ip addr add 10.216.0.254/24 dev e2efwtbr.10 && ip link set e2efwtbr.10 up")
		defer l.ssh(host, 30*time.Second, "ip link del e2efwtbr.10") //nolint:errcheck
		tap := l.guestTap(host, names["d"])
		count := l.probe(host, "i1", "bridge", "output", 100, "oifname "+tap+" ether type 8021q")
		l.ssh(host, 30*time.Second, "ping -c 3 -W 1 -I e2efwtbr.10 10.216.0.1; true") //nolint:errcheck
		if n := count(); n != 0 {
			t.Errorf("%d tagged frames from the host's side reached guest d's port", n)
		}
		l.mustLV(host, "firewall", "nic-guard", "set", names["d"], "--network", netName, "--mode", "on", "--allow-vlan-tags")
		l.mustLV(host, "firewall", "reload")
		l.ssh(host, 30*time.Second, "ping -c 3 -W 1 -I e2efwtbr.10 10.216.0.1; true") //nolint:errcheck
		if count() == 0 {
			t.Error("with d allowed tags none reached its port either; the zero above proves nothing")
		}
		l.mustLV(host, "firewall", "nic-guard", "set", names["d"], "--network", netName, "--mode", "on")
		l.mustLV(host, "firewall", "reload")
	})
	t.Run("I2_TrunkNICCarriesTheVLANsItsNetworkAllows", func(t *testing.T) {
		// t's second NIC is on the trunk: feature with VLANs 100 and 101, on a
		// network created after the upgrade with no allowed VLANs (re-review
		// R2-I1, round 3 and later): the NIC is guarded like any other new NIC,
		// its VLANs are dropped in either mode until the network allows them,
		// and the host says so.
		if !try("t", "sudo ip link add link eth1 name eth1.100 type vlan id 100 && sudo ip addr add 10.217.0.1/24 dev eth1.100 && "+
			"sudo ip link set eth1 up && sudo ip link set eth1.100 up && "+
			"sudo ip link add link eth1 name eth1.102 type vlan id 102 && sudo ip addr add 10.218.0.1/24 dev eth1.102 && sudo ip link set eth1.102 up") {
			t.Skip("the guest kernel cannot make VLAN interfaces; I-2 is proven by the kernel test instead")
		}
		row := l.mustSQL(host, "SELECT mac, network_name FROM vm_interfaces WHERE vm_name = '"+names["t"]+"' AND network_name LIKE '%fwt2' AND deleted_at IS NULL")[0]
		mac, trunkNet := strings.ToLower(row[0]), row[1]
		if rows := l.mustSQL(host, "SELECT value FROM cluster_policies WHERE key = 'nic_guard/"+names["t"]+"/"+mac+"' AND deleted_at IS NULL"); len(rows) == 0 ||
			!strings.Contains(rows[0][0], `"mode":"on"`) {
			t.Errorf("a new trunk NIC has no default guard: %v", rows)
		}
		tap := "lvt" + strings.ReplaceAll(mac, ":", "")
		in100 := l.probe(host, "i2a", "bridge", "input", 100, "iifname "+tap+" vlan id 100")
		in102 := l.probe(host, "i2b", "bridge", "input", 100, "iifname "+tap+" vlan id 102")
		send := func() { try("t", "ping -c 3 -W 1 10.217.0.254; ping -c 3 -W 1 10.218.0.254; true") }

		send()
		if n := in100(); n != 0 {
			t.Errorf("%d frames on VLAN 100 got through before the network allowed it", n)
		}
		if rows := l.mustSQL(host, "SELECT evidence FROM health_conditions WHERE code = 'firewall.nic.trunk_vlans' AND subject_id = '"+host+
			"' AND lifecycle != 'resolved' AND deleted_at IS NULL"); len(rows) == 0 || !strings.Contains(rows[0][0], "lv network set "+trunkNet) {
			t.Errorf("no firewall.nic.trunk_vlans condition naming `lv network set %s`: %v", trunkNet, rows)
		}

		l.mustLV(host, "network", "set", trunkNet, "--allowed-vlans", "100")
		l.mustLV(host, "firewall", "reload")
		send()
		if in100() == 0 {
			t.Errorf("the trunk NIC's VLAN 100 frames were dropped after the network allowed VLAN 100")
		}
		if n := in102(); n != 0 {
			t.Errorf("%d frames on VLAN 102, which the trunk was not given, got through", n)
		}
	})
	t.Run("I10_GuardInForceBeforeTheGuestRuns", func(t *testing.T) {
		mac := l.mustSQL(host, "SELECT mac FROM vm_interfaces WHERE vm_name = '"+names["a"]+"' AND deleted_at IS NULL")[0][0]
		tap := "lvt" + strings.ReplaceAll(strings.ToLower(mac), ":", "")
		if got := l.guestTap(host, names["a"]); got != tap {
			t.Fatalf("a's tap is %q, want the one its MAC names (%s)", got, tap)
		}
		l.mustLV(host, "stop", names["a"])
		if !l.waitDomainState(host, names["a"], "shut off", 3*time.Minute) {
			t.Fatalf("%s did not stop", names["a"])
		}
		if nic := l.mustSSH(host, 20*time.Second, "nft list table bridge litevirt-nic"); !strings.Contains(nic, "chain guard_"+tap+" {") {
			t.Errorf("a's guard is not in force while it is stopped, so its first frames would run unguarded:\n%s", nic)
		}
		l.mustLV(host, "start", names["a"])
		if !l.waitDomainState(host, names["a"], "running", 3*time.Minute) {
			t.Fatalf("%s did not start", names["a"])
		}
		if got := l.guestTap(host, names["a"]); got != tap {
			t.Errorf("after a restart a's tap is %q, want %s", got, tap)
		}
	})
	t.Run("I11_RebuildKeepsEachNICsGuard", func(t *testing.T) {
		l.mustLV(host, "firewall", "nic-guard", "set", names["d"], "--network", netName, "--mode", "on", "--allow", "10.205.0.250")
		l.mustLV(host, "rebuild", names["d"])
		if !l.waitDomainState(host, names["d"], "running", 4*time.Minute) {
			t.Fatalf("%s never ran after its rebuild", names["d"])
		}
		ls := l.mustLV(host, "firewall", "nic-guard", "ls", names["d"])
		if !strings.Contains(ls, "10.205.0.250") {
			t.Errorf("a rebuild dropped the NIC's relaxation:\n%s", ls)
		}
		guard := func(vm string) string {
			rows := l.mustSQL(host, "SELECT value FROM cluster_policies WHERE key LIKE 'nic_guard/"+vm+"/%' AND deleted_at IS NULL")
			if len(rows) == 0 {
				return ""
			}
			return rows[0][0]
		}
		if !strings.Contains(guard(names["e"]), `"mode":"on"`) {
			t.Fatalf("fixture: e is not guarded: %q", guard(names["e"]))
		}
		l.mustLV(host, "rebuild", names["e"])
		if !l.waitDomainState(host, names["e"], "running", 4*time.Minute) {
			t.Fatalf("%s never ran after its rebuild", names["e"])
		}
		if g := guard(names["e"]); !strings.Contains(g, `"mode":"on"`) {
			t.Errorf("a rebuild dropped a guard: %q", g)
		}
	})
}
