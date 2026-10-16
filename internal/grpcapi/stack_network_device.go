package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

func isBridgeType(t string) bool { return t == "" || t == "bridge" }

// stackNetWarning is one deploy warning about a stack network's device: the
// event it is published as, and its text.
type stackNetWarning struct {
	Event, Detail string
}

// Events a stack network's device warning is published as.
const (
	// eventBridgeShared: the network is on a bridge another stack's network
	// is on too.
	eventBridgeShared = "network.bridge_shared"
)

// defaultStackNetworkDevices gives each network f declares with no interface
// its device (compose.DefaultNetworkInterfaces). For a bridge network that is,
// in order:
//   - the device its live row already records, so a deployed network is never
//     moved. A row whose config does not parse records none: the deploy goes
//     on and writes the row over, as it always did;
//   - its own name, when that is a bridge already on this (the entry) host
//     that litevirt did not make and no stack network is recorded on: naming
//     a host bridge attaches to it. Decided here once, so every peer gets the
//     same device. When another stack's network is on that host bridge it is
//     not shared (sharing across stacks takes an explicit interface): the
//     network gets its scoped name and a warning says how to share;
//   - else its stack-scoped name.
//
// Every bridge network whose device was defaulted and is also another stack's
// network's device shares one L2 segment with it on every host. It is not
// moved; each such pair comes back as a warning naming both stacks, the device
// and the remedy if the sharing is not intended. Network rows that cannot be
// read fail the deploy: guessing would move a deployed network.
func (s *Server) defaultStackNetworkDevices(ctx context.Context, f *compose.File) ([]stackNetWarning, error) {
	rows, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("read network rows: %w", err)
	}
	byName := make(map[string]corrosion.NetworkRecord, len(rows))
	stackDevices := map[string]map[string]bool{} // device → stacks with a network recorded on it
	for _, r := range rows {
		byName[r.Name] = r
		if r.StackName == "" {
			continue
		}
		if def, err := networkRowDef(networkRow{name: r.Name, typ: r.Type, config: r.Config}); err == nil {
			dev := network.BridgeName(r.Name, def)
			if stackDevices[dev] == nil {
				stackDevices[dev] = map[string]bool{}
			}
			stackDevices[dev][r.StackName] = true
		}
	}
	// The bridges litevirt made here: read once, only when a host bridge is a
	// candidate. createdOK is false when they could not be read.
	var created map[string]bool
	createdRead, createdOK := false, false

	kept := map[string]string{}
	var defaulted []string
	var warnings []stackNetWarning
	for name, nd := range f.Networks {
		if nd.External || nd.Interface != "" || !isBridgeType(nd.Type) {
			continue
		}
		defaulted = append(defaulted, name)
		scoped := compose.ScopedNetworkName(f.Name, name)
		if r, ok := byName[scoped]; ok {
			var def compose.NetworkDef
			if err := json.Unmarshal([]byte(r.Config), &def); err != nil {
				slog.Warn("deploy: a network row's config does not parse; it records no device", "network", scoped, "error", err)
			} else if def.Interface != "" {
				kept[name] = def.Interface
				continue
			}
		}
		if !s.bridgeExistsHere(name) {
			continue
		}
		if !createdRead {
			created, createdOK = s.bridgesLitevirtMadeHere()
			createdRead = true
		}
		if !createdOK || created[name] {
			continue
		}
		// A host bridge: taken by name only when no stack network is on it.
		// Another stack on it means sharing it, which must be explicit.
		if users := stackDevices[name]; len(users) > 0 {
			var others []string
			for st := range users {
				if st != f.Name {
					others = append(others, fmt.Sprintf("%q", st))
				}
			}
			if len(others) > 0 {
				sort.Strings(others)
				warnings = append(warnings, stackNetWarning{Event: eventHostBridgeNotShared, Detail: fmt.Sprintf(
					"network %q of stack %q is named after host bridge %q, which stack %s is already on, so it is put on its own bridge %q instead; "+
						"to share it, set \"interface: %s\" and redeploy",
					scoped, f.Name, name, strings.Join(others, ", "), compose.FlatBridgeName(scoped), name)})
			}
			continue
		}
		kept[name] = name
	}
	f.DefaultNetworkInterfaces(kept)

	for _, name := range defaulted {
		dev := f.Networks[name].Interface
		scoped := compose.ScopedNetworkName(f.Name, name)
		var others []corrosion.NetworkRecord
		for _, r := range rows {
			if r.StackName == "" || r.StackName == f.Name || !isBridgeType(r.Type) {
				continue
			}
			def, err := networkRowDef(networkRow{name: r.Name, typ: r.Type, config: r.Config})
			if err != nil || network.BridgeName(r.Name, def) != dev {
				continue
			}
			others = append(others, r)
		}
		sort.Slice(others, func(i, j int) bool { return others[i].Name < others[j].Name })
		for _, o := range others {
			warnings = append(warnings, stackNetWarning{Event: eventBridgeShared, Detail: fmt.Sprintf(
				"network %q of stack %q is on bridge %q, which network %q of stack %q is also on: the two stacks share one L2 segment on every host. "+
					"If that is not intended, set \"interface: %s\" on %s in stack %q's file and redeploy; the network moves to its own bridge, and each guest on it follows at its next restart",
				scoped, f.Name, dev, o.Name, o.StackName, compose.FlatBridgeName(scoped), name, f.Name)})
		}
	}
	sort.Slice(warnings, func(i, j int) bool { return warnings[i].Detail < warnings[j].Detail })
	return warnings, nil
}

// bridgesLitevirtMadeHere is the set of bridges litevirt recorded creating on
// this host. When it cannot be read every existing bridge counts as
// litevirt's (ok false), so a stack network is never put on one by its name
// alone.
func (s *Server) bridgesLitevirtMadeHere() (map[string]bool, bool) {
	out := map[string]bool{}
	sw, ok := s.networkProvisioner().(orphanBridgeSweeper)
	if !ok {
		return out, true
	}
	names, err := sw.CreatedBridges()
	if err != nil {
		slog.Warn("deploy: list the bridges litevirt created; no host bridge is taken by name", "error", err)
		return nil, false
	}
	for _, n := range names {
		out[n] = true
	}
	return out, true
}

// eventHostBridgeNotShared: the network is named after a host bridge another
// stack's network is on, and was given its own scoped bridge instead.
const eventHostBridgeNotShared = "network.host_bridge_not_shared"
