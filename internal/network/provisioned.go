package network

import (
	"errors"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/litevirt/litevirt/internal/compose"
)

// hostProbe answers the two host facts ProvisionedHere needs. It is a seam so
// a unit test can fix both answers; production reads the kernel's interface
// table and /proc, never exec.
type hostProbe struct {
	ifaceExists func(name string) bool
	// dnsmasq reports whether pidFile exists, and whether the pid in it is one
	// of our running dnsmasq instances.
	dnsmasq func(pidFile string) (present, alive bool)
}

var realHostProbe = hostProbe{
	ifaceExists: BridgeExists,
	dnsmasq: func(pidFile string) (bool, bool) {
		data, err := os.ReadFile(pidFile)
		if errors.Is(err, fs.ErrNotExist) {
			return false, false
		}
		if err != nil {
			return true, false
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return true, false
		}
		return true, procIsOurDnsmasq(pid, pidFile)
	},
}

// ProvisionedHere reports whether this host still has what Provision set up
// for def: the network's bridge exists, and where litevirt runs dnsmasq for
// it, that dnsmasq is alive. The network reconciler asks it every pass, so a
// bridge someone deleted or a dnsmasq that died is provisioned again rather
// than left broken until the next restart.
//
// It is cheap on purpose: one interface lookup and at most one pidfile and
// one /proc read per network, no exec.
//
// Where it cannot know whether dnsmasq should run, it does not guess no: a
// pidfile whose process is gone always means dnsmasq died. With no pidfile at
// all it expects dnsmasq only where every host serves DHCP for this shape
// regardless of local state (an isolated network with a subnet, or a bridge
// with --dhcp); a vxlan network's gateway election and a bridge's
// pre-existence are not re-derived here.
func ProvisionedHere(networkName string, def compose.NetworkDef) bool {
	return provisionedHere(networkName, def, realHostProbe)
}

func provisionedHere(networkName string, def compose.NetworkDef, p hostProbe) bool {
	switch def.Type {
	case "sriov", "direct":
		// Hardware litevirt attaches to but does not create.
		return true
	}
	dev := BridgeName(networkName, def)
	if !p.ifaceExists(dev) {
		return false
	}
	pidFile := dnsmasqPidFile(dev)
	if def.Type == "vxlan" {
		pidFile = dnsmasqPidFileVNI(def.VNI)
	}
	present, alive := p.dnsmasq(pidFile)
	if present {
		return alive
	}
	return !DHCPWouldServe(def, DHCPHostFacts{BridgePreExisted: true})
}
