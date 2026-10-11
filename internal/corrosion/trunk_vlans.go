package corrosion

// The trunk VLANs a network allows beyond its row (re-review R4-I1, R4-I2,
// m6): what an operator allows on a flat bridge — a network name with no
// network row, whose NICs attach to a bridge of that name — and the
// read-modify-write of a network row's VLANs together with the policy keys
// that record them, under compare-and-swap.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
)

// FlatBridgeVLANsKey is the cluster_policies key holding, per flat bridge
// (a network name with no row), the trunk VLANs an operator allows on it
// (`lv network set <bridge> --allowed-vlans`): a JSON object of name → VIDs.
// It is the flat bridge's counterpart of a network row's allowed-vlans; the
// loader allows a flat-bridge trunk these and the VLANs recorded for the
// bridge at upgrade (TrunkVLANsRecordedKey).
const FlatBridgeVLANsKey = "firewall_flat_bridge_vlans"

// DecodeVLANMap parses a name → VIDs JSON object. A value that does not parse
// is empty: it allows nothing.
func DecodeVLANMap(raw string) map[string][]int {
	out := map[string][]int{}
	if json.Unmarshal([]byte(raw), &out) != nil {
		return map[string][]int{}
	}
	return out
}

// EncodeVLANMap renders a name → VIDs map, dropping names with no VLAN.
func EncodeVLANMap(m map[string][]int) string {
	clean := map[string][]int{}
	for k, v := range m {
		if len(v) > 0 {
			clean[k] = v
		}
	}
	b, _ := json.Marshal(clean)
	return string(b)
}

// FlatBridgeVLANs is the operator's allowed VLANs per flat bridge.
func FlatBridgeVLANs(ctx context.Context, c *Client) (map[string][]int, error) {
	raw, have, err := clusterPolicyValue(ctx, c, FlatBridgeVLANsKey)
	if err != nil || !have {
		return map[string][]int{}, err
	}
	return DecodeVLANMap(raw), nil
}

func clusterPolicyValue(ctx context.Context, c *Client, key string) (string, bool, error) {
	rows, err := c.Query(ctx, `SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, key)
	if err != nil || len(rows) == 0 {
		return "", false, err
	}
	return rows[0].String("value"), true, nil
}

// VLANSnapshot is a network row and some cluster_policies keys as one read
// saw them, for WriteNetworkVLANsCAS to compare against.
type VLANSnapshot struct {
	Network string
	// Row is the live network row, nil when there is none.
	Row  *NetworkRecord
	Keys map[string]PolicyValue
}

// PolicyValue is one cluster_policies value as read; Have is false when the
// key has no live row.
type PolicyValue struct {
	Value string
	Have  bool
}

// ReadVLANSnapshot reads network's live row and keys.
func ReadVLANSnapshot(ctx context.Context, c *Client, network string, keys ...string) (VLANSnapshot, error) {
	snap := VLANSnapshot{Network: network, Keys: map[string]PolicyValue{}}
	if network != "" {
		row, err := GetNetwork(ctx, c, network)
		if err != nil {
			return snap, err
		}
		snap.Row = row
	}
	for _, k := range keys {
		v, have, err := clusterPolicyValue(ctx, c, k)
		if err != nil {
			return snap, err
		}
		snap.Keys[k] = PolicyValue{Value: v, Have: have}
	}
	return snap, nil
}

// WriteNetworkVLANsCAS writes row (nil: leave the row) and the keys' new
// values in one transaction, only while the row and every key in snap are as
// snap read them. applied=false (no error) when something changed between:
// the caller reads again. The statements are the tables' ordinary upserts
// (networkUpsertSQL, clusterPolicyUpsertSQL), so nothing new crosses the
// wire; a key write needs the cluster_policies gate open.
func WriteNetworkVLANsCAS(ctx context.Context, c *Client, snap VLANSnapshot, row *NetworkRecord, keys map[string]string, setBy string) (bool, error) {
	if len(keys) > 0 && !c.MayWriteClusterPolicy() {
		return false, ErrClusterPolicyGateClosed
	}
	now := c.NowTS()
	var stmts []Statement
	if row != nil {
		stmts = append(stmts, Statement{SQL: networkUpsertSQL,
			Params: []interface{}{row.Name, row.StackName, row.Type, row.Config, row.Project, nowRFC3339(), now}})
	}
	names := make([]string, 0, len(keys))
	for k := range keys {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		stmts = append(stmts, Statement{SQL: clusterPolicyUpsertSQL, Params: []interface{}{k, keys[k], setBy, now}})
	}
	if len(stmts) == 0 {
		return true, nil
	}
	return c.ExecuteBatchGuarded(ctx, func(tx *sql.Tx) (bool, error) {
		if snap.Network != "" {
			var cfg, upd string
			err := tx.QueryRowContext(ctx, `SELECT config, updated_at FROM networks WHERE name = ? AND deleted_at IS NULL`, snap.Network).
				Scan(&cfg, &upd)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if snap.Row != nil {
					return false, nil
				}
			case err != nil:
				return false, err
			case snap.Row == nil || cfg != snap.Row.Config || upd != snap.Row.UpdatedAt:
				return false, nil
			}
		}
		for k, want := range snap.Keys {
			var v string
			err := tx.QueryRowContext(ctx, `SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, k).Scan(&v)
			switch {
			case errors.Is(err, sql.ErrNoRows):
				if want.Have {
					return false, nil
				}
			case err != nil:
				return false, err
			case !want.Have || v != want.Value:
				return false, nil
			}
		}
		return true, nil
	}, stmts)
}
