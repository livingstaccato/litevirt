package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/litevirt/litevirt/internal/cmdbound"
)

// WouldDrop is one observe-mode counter: what the per-NIC rules would have
// dropped on this host had they been enforced.
type WouldDrop struct {
	Device  string // the guest's tap or veth; "-" for table-wide counters
	Side    string // in | out | state | vlan
	Rule    string // cluster#N, host#N, sg:<name>#N, nic#N, default, invalid, tagged
	Packets uint64
	Bytes   uint64
}

// WouldDrops reads the observe-mode counters of the per-NIC table from the
// kernel. No table (nothing to enforce, or enforce mode) is no counters.
func WouldDrops(ctx context.Context) ([]WouldDrop, error) {
	out, err := cmdbound.Command(ctx, "nft", "-j", "list", "table", "bridge", NICTableName).Output()
	if err != nil {
		return nil, nil
	}
	return parseWouldDrops(out)
}

// parseWouldDrops extracts the lv-wd counters from `nft -j` output.
func parseWouldDrops(js []byte) ([]WouldDrop, error) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(js, &doc); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}
	var out []WouldDrop
	for _, obj := range doc.Nftables {
		raw, ok := obj["rule"]
		if !ok {
			continue
		}
		var rule struct {
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(raw, &rule) != nil {
			continue
		}
		// The counter's comment sits on the rule.
		f := strings.Fields(rule.Comment)
		if len(f) < 4 || f[0] != WouldDropComment {
			continue
		}
		wd := WouldDrop{Device: f[1], Side: f[2], Rule: strings.Join(f[3:], " ")}
		for _, e := range rule.Expr {
			var c struct {
				Counter *struct {
					Packets uint64 `json:"packets"`
					Bytes   uint64 `json:"bytes"`
				} `json:"counter"`
			}
			if json.Unmarshal(e, &c) == nil && c.Counter != nil {
				wd.Packets, wd.Bytes = c.Counter.Packets, c.Counter.Bytes
			}
		}
		out = append(out, wd)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Device != out[j].Device {
			return out[i].Device < out[j].Device
		}
		return out[i].Rule < out[j].Rule
	})
	return out, nil
}
