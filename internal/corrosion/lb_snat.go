package corrosion

// An explicit load balancer's outbound NAT (`lv lb create --snat`).
//
// A stack LB's `snat:` lives in its compose file. An explicit LB has no such
// file, and an explicit LB stored before this setting existed SNATs on a
// host-isolated network, so its absence must keep meaning "SNAT". The
// setting is one cluster_policies row per LB, lb_snat/<name>, written through
// clusterPolicyUpsertSQL (no new table or statement shape) in the same batch
// as the LB's own row, and bound to the LB's generation: a row left by an
// earlier incarnation of the same name, or none at all, is not a setting.

import (
	"context"
	"encoding/json"
	"errors"
)

// LBSNATKeyPrefix prefixes the cluster_policies key of an explicit LB's
// outbound NAT setting: lb_snat/<lb name>.
const LBSNATKeyPrefix = "lb_snat/"

// ErrLBSNATGateClosed is returned by a write of an LB's outbound NAT setting
// attempted before failover_scope_v1 has latched (cluster_policies' gate).
var ErrLBSNATGateClosed = errors.New("a load balancer's snat setting cannot be recorded until failover_scope_v1 has latched on every host")

// lbSNATValue is the value of an lb_snat/<name> row.
type lbSNATValue struct {
	SNAT       bool   `json:"snat"`
	Generation string `json:"generation"`
}

// lbSNATStmt records an explicit LB's outbound NAT for its generation.
func lbSNATStmt(name, generation string, snat bool, setBy, now string) Statement {
	b, _ := json.Marshal(lbSNATValue{SNAT: snat, Generation: generation})
	return Statement{SQL: clusterPolicyUpsertSQL, Params: []interface{}{LBSNATKeyPrefix + name, string(b), setBy, now}}
}

// GetLBSNAT reads the outbound NAT setting of the explicit LB name whose
// current generation is generation. recorded is false when there is no
// setting for that generation: the LB was stored before the setting existed,
// by a build without it, or while it could not be written.
func GetLBSNAT(ctx context.Context, c *Client, name, generation string) (snat, recorded bool, err error) {
	rows, err := c.Query(ctx,
		`SELECT value FROM cluster_policies WHERE key = ? AND deleted_at IS NULL`, LBSNATKeyPrefix+name)
	if err != nil {
		return false, false, err
	}
	if len(rows) == 0 {
		return false, false, nil
	}
	var v lbSNATValue
	if json.Unmarshal([]byte(rows[0].String("value")), &v) != nil || v.Generation != generation {
		return false, false, nil
	}
	return v.SNAT, true, nil
}

// PersistLBFullWithSNAT is PersistLBFull with the LB's outbound NAT setting
// in the same batch, so no replica holds the LB without it.
func PersistLBFullWithSNAT(ctx context.Context, c *Client, cfg LBConfigRecord, backends []LBBackendRecord, snat bool, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return ErrLBSNATGateClosed
	}
	now := c.NowTS()
	stmts := append(lbFullStmts(cfg, backends, now), lbSNATStmt(cfg.Name, cfg.Generation, snat, setBy, now))
	return c.ExecuteBatch(ctx, stmts)
}

// PersistLBIncrementalWithSNAT is PersistLBIncremental with the LB's outbound
// NAT setting in the same batch.
func PersistLBIncrementalWithSNAT(ctx context.Context, c *Client, cfg LBConfigRecord, upserts []LBBackendRecord, tombstones []string, snat bool, setBy string) error {
	if !c.MayWriteClusterPolicy() {
		return ErrLBSNATGateClosed
	}
	now := c.NowTS()
	stmts := append(lbIncrementalStmts(cfg, upserts, tombstones, now), lbSNATStmt(cfg.Name, cfg.Generation, snat, setBy, now))
	return c.ExecuteBatch(ctx, stmts)
}
