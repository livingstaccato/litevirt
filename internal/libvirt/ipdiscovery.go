package libvirt

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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

// GetIPFromDHCPLeases scans dnsmasq lease files under leaseDir for a MAC address.
// Standard libvirt lease dir is /var/lib/libvirt/dnsmasq.
func GetIPFromDHCPLeases(leaseDir, mac string) string {
	mac = strings.ToLower(mac)
	pattern := filepath.Join(leaseDir, "*.leases")
	files, err := filepath.Glob(pattern)
	if err != nil || len(files) == 0 {
		return ""
	}

	for _, lf := range files {
		f, err := os.Open(lf)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			// dnsmasq lease format: <expiry> <mac> <ip> <hostname> <clientid>
			fields := strings.Fields(scanner.Text())
			if len(fields) >= 3 && strings.ToLower(fields[1]) == mac {
				f.Close()
				return fields[2]
			}
		}
		f.Close()
	}
	return ""
}
