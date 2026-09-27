package network

import (
	"errors"
	"io/fs"
	"log/slog"
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
	dnsmasq:     func(pidFile string) (bool, bool) { return dnsmasqState(pidFile) },
}

// dnsmasqState reports whether a litevirt dnsmasq pidfile exists at pidFile,
// and whether the pid in it is one of our running dnsmasq instances. A seam:
// Provision reads it too, and a test fixes its answers.
var dnsmasqState = func(pidFile string) (present, alive bool) {
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
}

// removePidFile deletes a pidfile; a seam for the same reason.
var removePidFile = func(path string) error { return os.Remove(path) }

// litevirtServedDHCP reports whether a litevirt dnsmasq pidfile exists for
// pidFile, live or not. dnsmasq is started only on a bridge litevirt created
// or one --dhcp names, and Deprovision removes the pidfile, so it is the one
// durable record that litevirt served DHCP on this bridge. Provision reads it
// because "the bridge already exists" says nothing on the second pass: every
// bridge litevirt made exists by then.
func litevirtServedDHCP(pidFile string) bool {
	present, _ := dnsmasqState(pidFile)
	return present
}

// clearStaleDnsmasqPidFile removes pidFile when its dnsmasq is dead. Provision
// calls it wherever this host serves no DHCP for the network: ProvisionedHere
// reads a dead dnsmasq's pidfile as "dnsmasq died", so leaving it would make the
// network reconciler provision again on every pass, forever. A live dnsmasq's
// pidfile is left alone.
func clearStaleDnsmasqPidFile(pidFile string) {
	present, alive := dnsmasqState(pidFile)
	if !present || alive {
		return
	}
	if err := removePidFile(pidFile); err != nil && !errors.Is(err, fs.ErrNotExist) {
		slog.Warn("remove stale dnsmasq pidfile", "pidfile", pidFile, "error", err)
	}
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
