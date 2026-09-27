package libvirt

import (
	"bufio"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// arpTablePath is the kernel's ARP table; a variable so a test can point
// GetIPFromARP at a fixture.
var arpTablePath = "/proc/net/arp"

// GetIPFromARP scans /proc/net/arp to find the IP for a given MAC address.
// Returns empty string if not found.
func GetIPFromARP(mac string) string {
	mac = strings.ToLower(mac)
	f, err := os.Open(arpTablePath)
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Scan() // skip header
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		// fields: IP, HW type, Flags, HW address, Mask, Device
		if len(fields) < 4 {
			continue
		}
		// Only a COMPLETE entry says the MAC answers at that IP. An
		// incomplete one carries a zero address, and a FAILED one keeps the
		// hardware address it once resolved to — after a guest moves to a new
		// lease, its old address can linger here with its MAC — so both are
		// skipped.
		if !arpEntryComplete(fields[2]) || fields[3] == zeroMAC {
			continue
		}
		if strings.ToLower(fields[3]) == mac {
			return fields[0]
		}
	}
	return ""
}

// atfCom is ATF_COM from <net/if_arp.h>: the entry is complete. The kernel
// sets it for every entry in a valid state (REACHABLE, STALE, DELAY, PROBE,
// PERMANENT) and clears it for INCOMPLETE and FAILED ones.
const atfCom = 0x2

const zeroMAC = "00:00:00:00:00:00"

// arpEntryComplete parses a /proc/net/arp Flags column ("0x2").
func arpEntryComplete(flags string) bool {
	v, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(flags), "0x"), 16, 32)
	return err == nil && v&atfCom != 0
}

// dhcpLeaseDir is where litevirt's per-bridge dnsmasq writes its leases
// (network.dnsmasqLeaseDir must name the same directory). A variable so a test
// can point DiscoverIPForMAC at a fixture.
var dhcpLeaseDir = "/var/lib/libvirt/dnsmasq"

// DiscoverIPForMAC is where THIS host sees a MAC: the one MAC→IP lookup every
// discovery path uses (grpcapi's IP scanner, read RPCs, LB render and NetBox
// discovery gate, and the VM healthcheck's address check), so the order below
// cannot drift between them.
//
// dnsmasq's lease first, then a complete ARP entry. The lease is dnsmasq's
// one current answer for the MAC. The ARP cache can hold several complete
// entries for it: after a guest moves to a new lease its OLD address can stay
// there as a STALE entry — complete, and on a small table never
// garbage-collected until next used — and /proc/net/arp lists entries in hash
// order. ARP first could therefore return the old address, and a path that
// records what it discovers would record it. ARP still answers for a MAC with
// no lease here (a static address, an external DHCP server).
func DiscoverIPForMAC(mac string) string {
	return DiscoverIPForMACOnBridge(mac, "")
}

// DiscoverIPForMACOnBridge is DiscoverIPForMAC for a NIC whose bridge is
// known: only that bridge's dnsmasq lease file is read. Every lease file
// litevirt ever wrote on this host is otherwise a candidate — including one a
// deprovisioned network left behind, or another network's lease for a MAC
// that has since moved — and none of those is where the NIC is now. An empty
// bridge reads every file, as DiscoverIPForMAC does.
func DiscoverIPForMACOnBridge(mac, bridge string) string {
	var ip string
	if bridge == "" {
		ip = GetIPFromDHCPLeases(dhcpLeaseDir, mac)
	} else {
		ip = leaseIPFromFiles([]string{DHCPLeaseFile(dhcpLeaseDir, bridge)}, mac)
	}
	if ip != "" {
		return ip
	}
	return GetIPFromARP(mac)
}

// DHCPLeaseFile is the lease file litevirt's dnsmasq for bridge writes under
// leaseDir (network's dnsmasq args name the same file).
func DHCPLeaseFile(leaseDir, bridge string) string {
	return filepath.Join(leaseDir, "litevirt-"+bridge+".leases")
}

// leaseNow is the clock lease expiry is judged against; a variable so a test
// can fix it.
var leaseNow = time.Now

// GetIPFromDHCPLeases scans dnsmasq lease files under leaseDir for a MAC address.
// Standard libvirt lease dir is /var/lib/libvirt/dnsmasq.
//
// An expired lease is not an answer, and where several files lease the MAC
// the latest expiry — the lease dnsmasq granted most recently — wins, not the
// first file in glob order.
func GetIPFromDHCPLeases(leaseDir, mac string) string {
	files, err := filepath.Glob(filepath.Join(leaseDir, "*.leases"))
	if err != nil {
		return ""
	}
	return leaseIPFromFiles(files, mac)
}

// leaseIPFromFiles returns the address of the unexpired lease for mac with the
// latest expiry across files. dnsmasq's lease format is
// "<expiry> <mac> <ip> <hostname> <clientid>", where expiry is a Unix epoch and
// 0 means an infinite lease.
func leaseIPFromFiles(files []string, mac string) string {
	mac = strings.ToLower(mac)
	now := leaseNow().Unix()
	var best string
	var bestExpiry int64 = -1
	for _, lf := range files {
		f, err := os.Open(lf)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 3 || strings.ToLower(fields[1]) != mac {
				continue
			}
			expiry, err := strconv.ParseInt(fields[0], 10, 64)
			if err != nil {
				continue
			}
			if expiry == 0 {
				expiry = math.MaxInt64 // infinite
			} else if expiry <= now {
				continue // expired: dnsmasq no longer holds this address for the MAC
			}
			if expiry > bestExpiry {
				best, bestExpiry = fields[2], expiry
			}
		}
		f.Close()
	}
	return best
}
