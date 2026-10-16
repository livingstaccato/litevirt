package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sort"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

func isBridgeType(t string) bool { return t == "" || t == "bridge" }

// defaultStackNetworkDevices gives each network f declares with no interface
// its device (compose.DefaultNetworkInterfaces). For a bridge network that is,
// in order:
//   - the device its live row already records, so a deployed network is never
//     moved. A row whose config does not parse records none: the deploy goes
//     on and writes the row over, as it always did;
//   - its own name, when that is a bridge already on this (the entry) host
//     that litevirt did not make and no stack network is recorded on: naming
//     a host bridge attaches to it. Decided here once, so every peer gets the
//     same device;
//   - else its stack-scoped name.
//
// Every bridge network whose device was defaulted and is also another stack's
// network's device shares one L2 segment with it on every host. It is not
// moved; each such pair comes back as a warning naming both stacks, the device
// and the remedy if the sharing is not intended. Network rows that cannot be
// read fail the deploy: guessing would move a deployed network.
func (s *Server) defaultStackNetworkDevices(ctx context.Context, f *compose.File) ([]string, error) {
	rows, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("read network rows: %w", err)
	}
	byName := make(map[string]corrosion.NetworkRecord, len(rows))
	stackDevices := map[string]bool{} // devices a stack network is recorded on
	for _, r := range rows {
		byName[r.Name] = r
		if r.StackName == "" {
			continue
		}
		if def, err := networkRowDef(networkRow{name: r.Name, typ: r.Type, config: r.Config}); err == nil {
			stackDevices[network.BridgeName(r.Name, def)] = true
		}
	}
	// The bridges litevirt made here: read once, only when a host bridge is a
	// candidate. createdOK is false when they could not be read.
	var created map[string]bool
	createdRead, createdOK := false, false

	kept := map[string]string{}
	var defaulted []string
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
		if stackDevices[name] || !s.bridgeExistsHere(name) {
			continue
		}
		if !createdRead {
			created, createdOK = s.bridgesLitevirtMadeHere()
			createdRead = true
		}
		if createdOK && !created[name] {
			kept[name] = name
		}
	}
	f.DefaultNetworkInterfaces(kept)

	var warnings []string
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
			warnings = append(warnings, fmt.Sprintf(
				"network %q of stack %q is on bridge %q, which network %q of stack %q is also on: the two stacks share one L2 segment on every host. "+
					"If that is not intended, set \"interface: %s\" on %s in stack %q's file and redeploy; the network moves to its own bridge, and each guest on it follows at its next restart",
				scoped, f.Name, dev, o.Name, o.StackName, compose.FlatBridgeName(scoped), name, f.Name))
		}
	}
	sort.Strings(warnings)
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
