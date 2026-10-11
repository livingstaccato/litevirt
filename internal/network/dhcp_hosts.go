package network

// DHCP host reservations: the exact address litevirt reserved for a guarded
// NIC on a network it serves DHCP for, handed to dnsmasq as `mac,ip` lines in
// a per-bridge --dhcp-hostsfile. A NIC's guard then allows exactly that
// address, not the whole subnet.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	lv "github.com/litevirt/litevirt/internal/libvirt"
)

// DHCPHostsFile is the reservations file of the dnsmasq serving bridge.
func DHCPHostsFile(bridge string) string {
	return filepath.Join(dnsmasqLeaseDir, "litevirt-"+bridge+".hosts")
}

var hostsMu sync.Mutex

// SyncDHCPHosts makes bridge's reservations exactly hosts (mac → ip) and asks
// its dnsmasq to re-read them when they changed. A bridge with no hosts file
// has no dnsmasq of litevirt's on this host, and is left alone. It reports
// whether the file changed.
func SyncDHCPHosts(bridge string, hosts map[string]string) (bool, error) {
	hostsMu.Lock()
	defer hostsMu.Unlock()
	path := DHCPHostsFile(bridge)
	old, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	want := renderDHCPHosts(hosts)
	if bytes.Equal(old, want) {
		return false, nil
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, want, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, path); err != nil {
		return false, err
	}
	return true, hupDnsmasqFor(path)
}

// ErrNoLocalDHCPServer: no dnsmasq of litevirt's serves the bridge on this
// host, so a reservation here would reserve nothing.
var ErrNoLocalDHCPServer = errors.New("no litevirt DHCP server for this bridge on this host")

// AddDHCPHost adds one reservation now, ahead of the periodic sync — a guest
// asks for an address within seconds of starting, before its rows are
// replicated anywhere. A bridge with no hosts file has no dnsmasq of
// litevirt's here: that is ErrNoLocalDHCPServer, never a silent success, since
// the guest would then take a dynamic address its exact guard drops.
func AddDHCPHost(bridge, mac, ip string) error {
	hostsMu.Lock()
	path := DHCPHostsFile(bridge)
	old, err := os.ReadFile(path)
	if err != nil {
		hostsMu.Unlock()
		if os.IsNotExist(err) {
			return fmt.Errorf("%w: %s", ErrNoLocalDHCPServer, bridge)
		}
		return err
	}
	hosts := parseDHCPHosts(old)
	mac = strings.ToLower(mac)
	// One address, one MAC: a line another MAC still holds for ip — left by
	// a host that was down when the network was deleted — would make dnsmasq
	// refuse this one (re-review 5, L1).
	for m, a := range hosts {
		if a == ip && m != mac {
			delete(hosts, m)
		}
	}
	hosts[mac] = ip
	hostsMu.Unlock()
	_, err = SyncDHCPHosts(bridge, hosts)
	return err
}

func renderDHCPHosts(hosts map[string]string) []byte {
	macs := make([]string, 0, len(hosts))
	for m := range hosts {
		macs = append(macs, m)
	}
	sort.Strings(macs)
	var b bytes.Buffer
	for _, m := range macs {
		if a, err := netip.ParseAddr(hosts[m]); err == nil && a.Is4() {
			fmt.Fprintf(&b, "%s,%s\n", strings.ToLower(m), a)
		}
	}
	return b.Bytes()
}

func parseDHCPHosts(data []byte) map[string]string {
	out := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Split(strings.TrimSpace(sc.Text()), ",")
		if len(f) == 2 {
			out[strings.ToLower(f[0])] = f[1]
		}
	}
	return out
}

// hupDnsmasqFor signals the litevirt dnsmasq reading hostsFile to re-read it.
func hupDnsmasqFor(hostsFile string) error {
	pids, _ := filepath.Glob("/var/run/litevirt-dnsmasq-*.pid")
	for _, pf := range pids {
		pid := readPidFile(pf)
		if pid <= 0 || !processRunning(pid) || !procIsOurDnsmasq(pid, pf) {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if err != nil || !bytes.Contains(cmdline, []byte("--dhcp-hostsfile="+hostsFile+"\x00")) {
			continue
		}
		return syscall.Kill(pid, syscall.SIGHUP)
	}
	return nil
}

// LeasedAddrs is every address bridge's dnsmasq has leased (dynamic leases
// included): a reservation must not take one a guest is using.
func LeasedAddrs(bridge string) []string {
	data, err := os.ReadFile(lv.DHCPLeaseFile(dnsmasqLeaseDir, bridge))
	if err != nil {
		return nil
	}
	var out []string
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 3 {
			out = append(out, f[2])
		}
	}
	return out
}

// DHCPServedHere reports whether a live dnsmasq of litevirt's on this host
// reads bridge's reservations file — whether a reservation made here is one a
// DHCP server will honour.
func DHCPServedHere(bridge string) bool {
	path := DHCPHostsFile(bridge)
	if _, err := os.Stat(path); err != nil {
		return false
	}
	pids, _ := filepath.Glob("/var/run/litevirt-dnsmasq-*.pid")
	for _, pf := range pids {
		pid := readPidFile(pf)
		if pid <= 0 || !processRunning(pid) || !procIsOurDnsmasq(pid, pf) {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
		if err == nil && bytes.Contains(cmdline, []byte("--dhcp-hostsfile="+path+"\x00")) {
			return true
		}
	}
	return false
}

// LeasedAddrFor is the address bridge's dnsmasq has leased to mac, or "".
func LeasedAddrFor(bridge, mac string) string {
	data, err := os.ReadFile(lv.DHCPLeaseFile(dnsmasqLeaseDir, bridge))
	if err != nil {
		return ""
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) >= 3 && strings.EqualFold(f[1], mac) {
			return f[2]
		}
	}
	return ""
}

// NextFreeIP returns the lowest host address of subnet not in used (the
// network address and the gateway — the first host — are never handed out).
func NextFreeIP(subnet string, used []string) (string, error) { return nextFreeIP(subnet, used) }
