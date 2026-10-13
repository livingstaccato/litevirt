package e2e

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"
	"time"
)

// Network teardown against real hosts: the Linux bridge, the record of who
// created it (/run/litevirt/bridges), and dnsmasq's hold on a gateway address
// are host facts tests/fleet cannot see (its NetProvFake never reaches the
// bridge code). Every assertion reads `ip link` / `ip addr` / the record ON
// EACH NODE, never litevirt's report.
//
// Lab findings P-5 (`lv network rm` left a bridge litevirt created on every
// node) and N3 (a same-subnet create after `rm --force` failed with only
// dnsmasq's exit status).

// netRmPass is how long a network change may take to reach every node: the
// network reconciler runs every 30 s, so two passes and some slack.
const netRmPass = 2 * time.Minute

// shortNetName returns a name that fits a Linux interface name (15 bytes) so a
// bridge network may take it as its bridge name; uniqueName's can exceed it.
func shortNetName(tag string) string {
	return fmt.Sprintf("e2%s%d", tag, os.Getpid()%100000)
}

// onHosts runs script on each host and returns the hosts for which it exited 0,
// sorted, plus the outputs of those for which it did not.
func onHosts(hosts []string, script string) (ok []string, failed map[string]string) {
	failed = map[string]string{}
	for _, h := range hosts {
		if out, err := nodeOut(h, script); err == nil {
			ok = append(ok, h)
		} else {
			failed[h] = fmt.Sprintf("%v: %s", err, strings.TrimSpace(out))
		}
	}
	sort.Strings(ok)
	return ok, failed
}

// waitOnHosts polls until script exits 0 on every one of hosts, or budget
// passes; it returns the hosts where it still fails, with their output.
func waitOnHosts(hosts []string, script string, budget time.Duration) map[string]string {
	deadline := time.Now().Add(budget)
	for {
		_, failed := onHosts(hosts, script)
		if len(failed) == 0 || time.Now().After(deadline) {
			return failed
		}
		time.Sleep(5 * time.Second)
	}
}

func bridgePresent(br string) string { return "ip link show " + br + " >/dev/null 2>&1" }
func bridgeAbsent(br string) string  { return "! ip link show " + br + " >/dev/null 2>&1" }
func recordPresent(br string) string { return "test -e /run/litevirt/bridges/" + br }
func recordAbsent(br string) string  { return "! test -e /run/litevirt/bridges/" + br }

// delTestLink removes link on every host if it is still there. Only for names
// this file generated (shortNetName / e2tap…), in a cleanup.
func delTestLink(t *testing.T, link string) {
	t.Helper()
	if !strings.HasPrefix(link, "e2") {
		t.Logf("refusing to delete %q: not a name this test generated", link)
		return
	}
	for _, h := range hostNames {
		if out, err := nodeOut(h, "if ip link show "+link+" >/dev/null 2>&1; then ip link del "+link+"; fi"); err != nil {
			t.Logf("cleanup: ip link del %s on %s: %v\n%s", link, h, err, out)
		}
	}
}

// (a) A bridge network created without --interface makes its bridge on every
// node; `lv network rm` removes it, and its record, from every node.
func TestNetwork_RmRemovesTheBridgeLitevirtCreatedOnEveryNode(t *testing.T) {
	requireHosts(t, 2)
	name := shortNetName("nb")
	subnet := fmt.Sprintf("10.237.%d.0/24", 20+os.Getpid()%200)
	cleanup(t, func() {
		lvErr(t, "network", "rm", name, "--force")
		delTestLink(t, name)
	})
	lv(t, "network", "create", name, "--type", "bridge", "--subnet", subnet, "--dhcp")

	// Every node provisions it: the bridge and its creation record appear.
	if failed := waitOnHosts(hostNames, bridgePresent(name)+" && "+recordPresent(name), netRmPass); len(failed) > 0 {
		t.Fatalf("bridge %s or its record /run/litevirt/bridges/%s missing after %s on: %v", name, name, netRmPass, failed)
	}

	lv(t, "network", "rm", name)

	if failed := waitOnHosts(hostNames, bridgeAbsent(name)+" && "+recordAbsent(name), netRmPass); len(failed) > 0 {
		t.Errorf("after `lv network rm %s`, bridge %s (or its record) still on %d node(s) after %s: %v",
			name, name, len(failed), netRmPass, failed)
	}
}

// (b) A bridge an operator made outside litevirt, which a bridge network uses
// with --interface, survives `lv network rm` on every node, and litevirt never
// records it as its own.
func TestNetwork_RmKeepsAnOperatorsBridge(t *testing.T) {
	requireHosts(t, 2)
	br := shortNetName("ob")
	name := shortNetName("on")
	cleanup(t, func() {
		lvErr(t, "network", "rm", name, "--force")
		delTestLink(t, br)
	})
	// The operator's bridge exists before litevirt hears of it.
	if _, failed := onHosts(hostNames, "ip link add "+br+" type bridge && ip link set "+br+" up"); len(failed) > 0 {
		t.Fatalf("creating operator bridge %s: %v", br, failed)
	}
	lv(t, "network", "create", name, "--type", "bridge", "--interface", br)

	// Let every node's reconciler provision the network onto the bridge.
	time.Sleep(netRmPass / 2)
	if _, failed := onHosts(hostNames, recordAbsent(br)); len(failed) > 0 {
		t.Errorf("litevirt recorded operator bridge %s as one it created on: %v", br, failed)
	}

	lv(t, "network", "rm", name)
	// Give every node's teardown time to run, then the bridge must still be there.
	time.Sleep(netRmPass)
	if _, failed := onHosts(hostNames, bridgePresent(br)); len(failed) > 0 {
		t.Errorf("`lv network rm %s` removed operator bridge %s on: %v", name, br, failed)
	}
}

// (c) N3. `rm --force` of a network a guest port still uses defers its
// teardown, and its dnsmasq keeps the gateway. A new network on the same
// subnet is still created, but on such a host the create fails naming the
// deleted network, its subnet and the port. Once the port goes, every node
// tears the old network down (bridge included) and provisions the new one.
//
// The "guest" is a real tap device on the bridge (what a VM's NIC is to the
// host), on every node, so the deferral holds wherever the CLI's daemon runs.
func TestNetwork_SameSubnetCreateAfterForceRmNamesTheDeferredNetwork(t *testing.T) {
	requireHosts(t, 2)
	oldNet, newNet := shortNetName("na"), shortNetName("nn")
	tap := shortNetName("tp")
	third := 20 + (os.Getpid()+101)%200
	subnet := fmt.Sprintf("10.238.%d.0/24", third)
	gateway := fmt.Sprintf("10.238.%d.1/24", third)
	cleanup(t, func() {
		delTestLink(t, tap)
		lvErr(t, "network", "rm", newNet, "--force")
		lvErr(t, "network", "rm", oldNet, "--force")
		delTestLink(t, oldNet)
		delTestLink(t, newNet)
	})

	lv(t, "network", "create", oldNet, "--type", "bridge", "--subnet", subnet, "--dhcp")
	if failed := waitOnHosts(hostNames, bridgePresent(oldNet)+" && ip -br addr show "+oldNet+" | grep -qF "+gateway, netRmPass); len(failed) > 0 {
		t.Fatalf("%s not provisioned (bridge with %s) on: %v", oldNet, gateway, failed)
	}
	if _, failed := onHosts(hostNames, "ip tuntap add dev "+tap+" mode tap && ip link set "+tap+" master "+oldNet+" && ip link set "+tap+" up"); len(failed) > 0 {
		t.Fatalf("plugging tap %s into %s: %v", tap, oldNet, failed)
	}

	lv(t, "network", "rm", oldNet, "--force")
	// The teardown waits for the tap: the gateway stays everywhere.
	time.Sleep(netRmPass / 2)
	if _, failed := onHosts(hostNames, "ip -br addr show "+oldNet+" | grep -qF "+gateway); len(failed) > 0 {
		t.Fatalf("%s was torn down while tap %s is on it, on: %v", oldNet, tap, failed)
	}

	out, err := lvErr(t, "network", "create", newNet, "--type", "bridge", "--subnet", subnet, "--dhcp")
	if err == nil {
		t.Fatalf("create %s on %s succeeded while deleted %s still holds the gateway on this host:\n%s", newNet, subnet, oldNet, out)
	}
	for _, want := range []string{`deleted network "` + oldNet + `"`, subnet, tap} {
		if !strings.Contains(out, want) {
			t.Errorf("create %s error does not name %s:\n%s", newNet, want, out)
		}
	}
	if _, err := lvErr(t, "network", "inspect", newNet); err != nil {
		t.Errorf("%s was not recorded by the failed create (main records it): %v", newNet, err)
	}

	// The guest leaves. Every node tears oldNet down, bridge and all, and
	// provisions newNet with the gateway.
	delTestLink(t, tap)
	if failed := waitOnHosts(hostNames,
		bridgeAbsent(oldNet)+" && ip -br addr show "+newNet+" | grep -qF "+gateway, netRmPass); len(failed) > 0 {
		t.Errorf("after tap %s left: %s still present or %s not serving %s on: %v", tap, oldNet, newNet, gateway, failed)
	}

	lv(t, "network", "rm", newNet)
	if failed := waitOnHosts(hostNames, bridgeAbsent(newNet), netRmPass); len(failed) > 0 {
		t.Errorf("bridge %s still present after `lv network rm` on: %v", newNet, failed)
	}
}
