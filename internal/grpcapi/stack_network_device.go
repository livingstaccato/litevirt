package grpcapi

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/litevirt/litevirt/internal/compose"
	"github.com/litevirt/litevirt/internal/corrosion"
	"github.com/litevirt/litevirt/internal/network"
)

// defaultStackNetworkDevices gives each network f declares with no interface
// its device (compose.DefaultNetworkInterfaces): the device its live row
// already records, so a deployed network is never moved, else its
// stack-scoped name. A network kept on a device another stack's network is
// recorded on too (two stacks deployed when a stack network defaulted to its
// short name) shares one L2 segment with it on every host; it is not moved,
// and each such pair comes back as a warning naming both stacks, the device
// and the remedy. A row that cannot be read fails the deploy: guessing would
// move a deployed network.
func (s *Server) defaultStackNetworkDevices(ctx context.Context, f *compose.File) ([]string, error) {
	rows, err := corrosion.ListNetworks(ctx, s.db)
	if err != nil {
		return nil, fmt.Errorf("read network rows: %w", err)
	}
	byName := make(map[string]corrosion.NetworkRecord, len(rows))
	for _, r := range rows {
		byName[r.Name] = r
	}
	recorded := map[string]string{}
	for name, nd := range f.Networks {
		if nd.External || nd.Interface != "" {
			continue
		}
		r, ok := byName[compose.ScopedNetworkName(f.Name, name)]
		if !ok {
			continue
		}
		var def compose.NetworkDef
		if err := json.Unmarshal([]byte(r.Config), &def); err != nil {
			continue // a row this build cannot read records no device
		}
		recorded[name] = def.Interface
	}
	f.DefaultNetworkInterfaces(recorded)

	var warnings []string
	for name, dev := range recorded {
		if dev == "" {
			continue
		}
		scoped := compose.ScopedNetworkName(f.Name, name)
		ntype := f.Networks[name].Type
		if ntype != "" && ntype != "bridge" {
			continue
		}
		var others []corrosion.NetworkRecord
		for _, r := range rows {
			if r.StackName == "" || r.StackName == f.Name || (r.Type != "" && r.Type != "bridge") {
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
				"network %q of stack %q stays on bridge %q, which network %q of stack %q is also on: the two stacks share one L2 segment on every host. "+
					"To separate them, set \"interface: %s\" on %s in stack %q's file and redeploy; the network moves to its own bridge, and each guest on it follows at its next restart",
				scoped, f.Name, dev, o.Name, o.StackName, compose.FlatBridgeName(scoped), name, f.Name))
		}
	}
	sort.Strings(warnings)
	return warnings, nil
}
