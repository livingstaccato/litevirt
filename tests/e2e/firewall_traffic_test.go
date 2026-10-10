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
	l.t.Fatalf("%s (%s) never took a DHCP lease on %s", vm, mac, host)
	return ""
}

// TestFirewall_TrafficBetweenVMs: per-NIC rules hold for traffic between two
// guests on ONE bridge, the allowed case passes, replies to a guest's own
// connection come back through a drop-everything ingress policy (stateful),
// and a guarded guest's spoofed source is dropped — and passes once the guard
// is turned off, so the drop was the guard's.
//
// Four cirros guests on one host and one bridge:
//
//	a: no security group — the prober
//	b: may not receive icmp
//	c: may receive only tcp/22 (so the test can log in), nothing else
//	d: no security group — the allowed target
func TestFirewall_TrafficBetweenVMs(t *testing.T) {
	l := newLab(t)
	host := l.hosts[0]
	stack := uniqueName("fwt")
	yaml := fmt.Sprintf(`name: %[1]s
security-groups:
  noicmp:
    rules:
      - {direction: ingress, proto: icmp, action: drop}
  sshonly:
    rules:
      - {direction: ingress, proto: tcp, port: "22", action: accept}
      - {direction: ingress, proto: all, action: drop}
networks:
  fwt:
    type: bridge
    interface: e2efwtbr
    subnet: 10.205.0.0/24
    dhcp: true
vms:
  a:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    network: [{name: fwt}]
    placement: {host: %[4]s}
  b:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    network: [{name: fwt, security-groups: [noicmp]}]
    placement: {host: %[4]s}
  c:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    network: [{name: fwt, security-groups: [sshonly]}]
    placement: {host: %[4]s}
  d:
    image: %[2]s
    cpu: 1
    memory: %[3]s
    network: [{name: fwt}]
    placement: {host: %[4]s}
`, stack, drillImage(), drillMemory(), host)
	file := "/tmp/" + stack + ".yaml"
	l.mustSSH(host, 30*time.Second, "echo "+base64.StdEncoding.EncodeToString([]byte(yaml))+" | base64 -d > "+file)
	l.onRestore(func() {
		_, _ = l.lv(host, "compose", "down", "-f", file, "-y")
		_, _ = l.ssh(host, 30*time.Second, "ip link del e2efwtbr 2>/dev/null; rm -f "+file)
	})
	l.mustLV(host, "compose", "up", "-f", file, "-y")

	vm := func(n string) string { return stack + "_" + n }
	names := []string{"a", "b", "c", "d"}
	// Compose may scope VM names; take them from the cluster rather than guess.
	for i, n := range names {
		for _, cand := range []string{n, vm(n), stack + "-" + n} {
			if rows, _ := l.sql(host, "SELECT name FROM vms WHERE name = '"+cand+"' AND deleted_at IS NULL"); len(rows) == 1 {
				names[i] = cand
				break
			}
		}
	}
	ip := map[string]string{}
	for i, n := range []string{"a", "b", "c", "d"} {
		if !l.waitDomainState(host, names[i], "running", 4*time.Minute) {
			t.Fatalf("%s never ran", names[i])
		}
		ip[n] = l.guestIP(host, names[i], 5*time.Minute)
	}
	l.mark("guests: %v", ip)
	l.waitGuestSSH(host, ip["a"], 20*time.Minute)
	l.waitGuestSSH(host, ip["c"], 20*time.Minute)
	l.saveEvidence("ruleset.txt", l.mustSSH(host, 30*time.Second, "nft list ruleset"))

	try := func(from, cmd string) bool {
		out, ok, err := l.guestRun(host, ip[from], cmd)
		if err != nil {
			t.Fatalf("log into %s: %v", from, err)
		}
		l.mark("%s$ %s -> ok=%v %s", from, cmd, ok, strings.TrimSpace(out))
		return ok
	}
	ping := func(src string) string { return "ping -c 3 -W 2 " + src }

	t.Run("SameBridgeDropIsEnforced", func(t *testing.T) {
		if try("a", ping(ip["b"])) {
			t.Errorf("a reached b by icmp; b's group drops icmp ingress")
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
		// c drops every new inbound connection but tcp/22; the replies to
		// its own ping are not new, so they must come back.
		if !try("c", ping(ip["d"])) {
			t.Errorf("c's own ping to d got no replies: replies on bridge ports are not tracked "+
				"(is nf_conntrack_bridge loaded on %s?)", host)
		}
	})
	t.Run("SpoofedSourceIsDropped", func(t *testing.T) {
		// The spoofed source is outside the network's subnet: for a guest on
		// a DHCP network litevirt knows the subnet, not the lease, so any
		// address inside it is the guest's to use (docs/firewall.md).
		gw := strings.SplitN(strings.TrimSpace(l.mustSSH(host, 20*time.Second,
			"ip -4 -o addr show dev e2efwtbr | awk '{print $4}' | head -1")), "/", 2)[0]
		if gw == "" {
			t.Fatal("no gateway address on e2efwtbr")
		}
		// Count, on the host, IPv4 packets from the spoofed source that got
		// past the bridge into the host's stack.
		const spoof = "10.206.0.199"
		l.mustSSH(host, 20*time.Second, `nft add table inet e2espoof && nft add chain inet e2espoof c '{ type filter hook prerouting priority -400; policy accept; }' && nft add rule inet e2espoof c ip saddr `+spoof+` counter`)
		l.onRestore(func() { _, _ = l.ssh(host, 20*time.Second, "nft delete table inet e2espoof") })
		count := func() string {
			out := l.mustSSH(host, 20*time.Second, "nft list chain inet e2espoof c | grep -o 'packets [0-9]*' | awk '{print $2}'")
			return strings.TrimSpace(out)
		}
		try("a", ping(gw)) // the gateway's MAC is cached from the real address first
		try("a", "sudo ip addr add "+spoof+"/32 dev eth0 2>/dev/null; true")
		try("a", "ping -c 3 -W 1 -I "+spoof+" "+gw)
		if n := count(); n != "0" {
			t.Errorf("%s packets from the spoofed %s reached the host; a's guard is on by default", n, spoof)
		}
		netName := l.mustSQL(host, "SELECT network_name FROM vm_interfaces WHERE vm_name = '"+names[0]+"' AND deleted_at IS NULL")[0][0]
		l.mustLV(host, "firewall", "nic-guard", "set", names[0], "--network", netName, "--mode", "off")
		l.mustLV(host, "firewall", "reload")
		try("a", "ping -c 3 -W 1 -I "+spoof+" "+gw)
		if n := count(); n == "0" || n == "" {
			t.Errorf("with a's guard off no spoofed packet reached the host either, so the drop above proves nothing")
		}
	})
}
