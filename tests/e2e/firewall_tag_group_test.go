package e2e

// Firewall tag groups proven with real traffic (spec §4.9, docs/firewall.md
// "Tag groups").
//
// A cirros DB VM listens on tcp 5432 behind a security group that accepts
// tcp/22 (so the test can log in), accepts tcp/5432 only from `tag:<group>`,
// and drops every other ingress: the NIC's default deny. The client is an
// alpine container on the same network. It is a container, not a VM, because
// a member's addresses are its allocator leases, and only a container holds
// one on a network not bound to NetBox (a VM there gets its address from DHCP
// and is in no set, see `tag-group ls --members`).
//
//   - untagged, the client is refused;
//   - tagged, it connects within 60 s, and its lease is in lv_tg_<group> in
//     both of this host's tables;
//   - untagged again, a NEW connection is refused within 60 s, while a
//     connection opened while it was a member keeps passing (no conntrack
//     flush, T-3);
//   - tagged once more, it connects again, so the refusals above were the
//     rule's and not a dead listener's;
//   - `tag-group rm` is refused while the security group references it.
//
// Runs ON a cluster node with LXC (local mode): the container is created
// there, nft is read there, and the VM is reached over the network's own
// bridge, whose gateway address is this host's.

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// tagGroupBound is how long the test waits for a tag change to show in
// traffic. docs/firewall.md bounds it by L + T + pass with T = 30 s; the
// writing host reconciles at once, and this is that host.
const tagGroupBound = 60 * time.Second

// guestDirect runs cmd inside the guest at ip, dialled directly from this
// node. It returns the combined output and whether the command exited 0; err
// is a failure to reach or log into the guest.
func guestDirect(ip, cmd string) (string, bool, error) {
	cfg := &ssh.ClientConfig{
		User:            envOr("E2E_GUEST_USER", "cirros"),
		Auth:            []ssh.AuthMethod{ssh.Password(envOr("E2E_GUEST_PASSWORD", "gocubsgo"))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // a throwaway test guest
		Timeout:         20 * time.Second,
	}
	client, err := ssh.Dial("tcp", net.JoinHostPort(ip, "22"), cfg)
	if err != nil {
		return "", false, err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", false, err
	}
	defer sess.Close()
	b, rerr := sess.CombinedOutput(cmd)
	return string(b), rerr == nil, nil
}

// vmIPOf waits for `lv ls` to report an IPv4 address for vm.
func vmIPOf(t *testing.T, vm string, timeout time.Duration) string {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, line := range strings.Split(lv(t, "ls"), "\n") {
			f := strings.Fields(line)
			if len(f) >= 6 && f[0] == vm {
				if ip := net.ParseIP(f[len(f)-1]); ip != nil && ip.To4() != nil {
					return ip.String()
				}
			}
		}
		time.Sleep(5 * time.Second)
	}
	t.Fatalf("%s reported no IPv4 address within %v", vm, timeout)
	return ""
}

// memberAddrs is the ADDRESSES column of `tag-group ls --members` for one
// group and workload, or "" when it is not listed.
func memberAddrs(t *testing.T, group, workload string) string {
	t.Helper()
	for _, line := range strings.Split(lv(t, "firewall", "tag-group", "ls", "--members"), "\n") {
		f := strings.Fields(line)
		if len(f) >= 5 && f[0] == group && f[2] == workload {
			return strings.Join(f[4:], " ")
		}
	}
	return ""
}

// nftSet lists one set of this host's ruleset, or "" when it is not there.
func nftSet(family, table, set string) string {
	out, err := exec.Command("nft", "list", "set", family, table, set).CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func TestFirewall_TagGroupAdmitsMembersOnly(t *testing.T) {
	requireLXC(t)
	ensureTopology(t)
	host := localHost
	if host == "" {
		t.Skip("cannot tell which cluster host this node is")
	}
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft not installed on this node")
	}
	pid := os.Getpid() % 100000

	// Per-NIC enforcement is cluster-wide; restore whatever it was.
	if !strings.Contains(lv(t, "firewall", "enforce", "status"), "per-NIC enforcement: enforce") {
		cleanup(t, func() { lvErr(t, "firewall", "enforce", "off") })
	}
	lv(t, "firewall", "enforce", "on")

	// The group first: a rule naming a group that does not exist is refused.
	group := fmt.Sprintf("e2etg%d", pid)
	tagVal := fmt.Sprintf("web%d", pid)
	lv(t, "firewall", "tag-group", "set", group, "--match", "role="+tagVal)
	cleanup(t, func() { lvErr(t, "firewall", "tag-group", "rm", group) })

	netName := uniqueName("tgn")
	lv(t, "network", "create", netName, "--type", "isolated", "--subnet", "10.207.0.0/24", "--dhcp")
	cleanup(t, func() { lvErr(t, "network", "rm", netName, "--force") })

	stack := uniqueName("tgs")
	db := uniqueName("tgdb")
	sg := fmt.Sprintf("tgdb%d", pid)
	compose := fmt.Sprintf(`name: %[1]s
security-groups:
  %[2]s:
    rules:
      - {direction: ingress, proto: tcp, port: "22", action: accept}
      - {direction: ingress, proto: tcp, port: "5432", cidr: "tag:%[3]s", action: accept}
      - {direction: ingress, proto: all, action: drop}
networks:
  %[4]s:
    external: true
vms:
  %[5]s:
    image: %[6]s
    cpu: 1
    memory: %[7]s
    firmware: bios
    network: [{name: %[4]s, security-groups: [%[2]s]}]
    placement: {host: %[8]s}
`, stack, sg, group, netName, db, drillImage(), drillMemory(), host)
	file := writeComposeFile(t, stack, compose)
	lv(t, "compose", "up", "-f", file, "-y")
	cleanup(t, func() { lvErr(t, "compose", "down", "-f", file, "-y") })

	ct := uniqueName("tgc")
	if out, err := lvErr(t, "ct", "create", ct, "--host", host, "--network", "network="+netName); err != nil {
		t.Skipf("cannot create a container on %s (lxc image server reachable?): %v\n%s", host, err, out)
	}
	cleanup(t, func() {
		lvErr(t, "ct", "stop", ct, "--host", host)
		lvErr(t, "ct", "rm", ct, "--host", host, "--force")
	})
	lv(t, "ct", "start", ct, "--host", host)
	waitCT(t, ct, "running", 2*time.Minute)

	waitVM(t, db, "RUNNING", 4*time.Minute)
	dbIP := vmIPOf(t, db, 5*time.Minute)
	deadline := time.Now().Add(20 * time.Minute) // cirros may retry a metadata service for minutes
	for {
		if _, ok, err := guestDirect(dbIP, "true"); err == nil && ok {
			break
		} else if time.Now().After(deadline) {
			t.Fatalf("DB VM %s (%s) never accepted a login: %v", db, dbIP, err)
		}
		time.Sleep(10 * time.Second)
	}
	// An echo server on 5432 that serves every connection (-ll), so a held
	// connection does not keep a new one from being accepted.
	if out, _, err := guestDirect(dbIP, "setsid sh -c 'while :; do nc -ll -p 5432 -e /bin/cat; sleep 1; done' </dev/null >/dev/null 2>&1 & sleep 2; netstat -ltn | grep ':5432 '"); err != nil || !strings.Contains(out, ":5432") {
		t.Fatalf("no listener on the DB VM's 5432: %v\n%s", err, out)
	}

	// connects sends a token from the container and reports whether it came
	// back: a dropped SYN and a reset both leave it unanswered.
	try := 0
	connects := func() bool {
		try++
		tok := fmt.Sprintf("tok-%d-%d", pid, try)
		out, _ := lvErr(t, "ct", "exec", ct, "--host", host, "--", "sh", "-c",
			fmt.Sprintf("echo %s | nc -w 3 %s 5432", tok, dbIP))
		return strings.Contains(out, tok)
	}
	// within polls want for the bound, and returns how long it took.
	within := func(t *testing.T, what string, want func() bool) time.Duration {
		t.Helper()
		start := time.Now()
		for {
			if want() {
				d := time.Since(start)
				t.Logf("%s after %v", what, d.Round(time.Second))
				return d
			}
			if time.Since(start) > tagGroupBound {
				t.Fatalf("%s: not within %v", what, tagGroupBound)
			}
			time.Sleep(2 * time.Second)
		}
	}

	t.Run("UntaggedClientIsRefused", func(t *testing.T) {
		if connects() {
			t.Fatalf("an untagged container reached the DB's 5432, which accepts only tag:%s", group)
		}
	})

	var ctIP string
	t.Run("TaggedClientConnects", func(t *testing.T) {
		lv(t, "firewall", "tag", "set", ct, "--container", "--host", host, "role="+tagVal)
		within(t, "tagged client connects", connects)
		addrs := memberAddrs(t, group, ct)
		ip := net.ParseIP(strings.Split(addrs, ",")[0])
		if ip == nil {
			t.Fatalf("tag-group ls --members shows %q for %s, want its lease", addrs, ct)
		}
		ctIP = ip.String()
		for _, tbl := range [][2]string{{"bridge", "litevirt-nic"}, {"inet", "litevirt-fw"}} {
			set := nftSet(tbl[0], tbl[1], "lv_tg_"+group)
			if !regexp.MustCompile(`\b` + regexp.QuoteMeta(ctIP) + `\b`).MatchString(set) {
				t.Errorf("%s %s lv_tg_%s does not hold the member's lease %s:\n%s", tbl[0], tbl[1], group, ctIP, set)
			}
		}
	})
	if ctIP == "" {
		t.FailNow()
	}

	// A connection opened while the container is a member, kept open.
	lv(t, "ct", "exec", ct, "--host", host, "--", "sh", "-c",
		fmt.Sprintf("setsid sh -c '(while :; do echo tick; sleep 1; done) | nc %s 5432 > /tmp/held 2>&1' </dev/null >/dev/null 2>&1 &", dbIP))
	held := func() int {
		out, _ := lvErr(t, "ct", "exec", ct, "--host", host, "--", "sh", "-c", "grep -c tick /tmp/held")
		n, _ := strconv.Atoi(strings.TrimSpace(out))
		return n
	}
	within(t, "held connection echoes", func() bool { return held() >= 2 })

	t.Run("RemovedMemberIsRefusedNewConnections", func(t *testing.T) {
		lv(t, "firewall", "tag", "rm", ct, "--container", "--host", host, "role")
		within(t, "untagged client refused", func() bool { return !connects() })
		if set := nftSet("bridge", "litevirt-nic", "lv_tg_"+group); strings.Contains(set, ctIP) {
			t.Errorf("lv_tg_%s still holds %s after the tag was removed:\n%s", group, ctIP, set)
		}
	})

	t.Run("EstablishedConnectionSurvivesRemoval", func(t *testing.T) {
		n1 := held()
		time.Sleep(5 * time.Second)
		if n2 := held(); n2 <= n1 {
			t.Errorf("the connection opened while a member stopped passing after the removal (%d then %d echoes); "+
				"docs/firewall.md says established connections survive", n1, n2)
		}
	})

	t.Run("RetaggedClientConnectsAgain", func(t *testing.T) {
		lv(t, "firewall", "tag", "set", ct, "--container", "--host", host, "role="+tagVal)
		within(t, "re-tagged client connects", connects)
	})

	t.Run("RmRefusedWhileReferenced", func(t *testing.T) {
		if out, err := lvErr(t, "firewall", "tag-group", "rm", group); err == nil {
			t.Errorf("tag-group rm %s succeeded while security group %s references it:\n%s", group, sg, out)
		}
		if !strings.Contains(lv(t, "firewall", "tag-group", "ls"), group) {
			t.Errorf("group %s is gone after a refused rm", group)
		}
	})

	lvErr(t, "ct", "exec", ct, "--host", host, "--", "sh", "-c", "pkill -f 'nc "+dbIP+"'; true")
	lvErr(t, "firewall", "tag", "rm", ct, "--container", "--host", host, "role")
}
