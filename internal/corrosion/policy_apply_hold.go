package corrosion

import "sync"

// policyApplyHolds is a test seam: per client, the cluster_policies keys whose
// incoming rows it does not apply, by either path (a WAL push or an
// anti-entropy merge). It models a node replication has not reached for one
// row while every other row, and all other traffic, still reach it
// (tests/fleet's apply filter). Empty in production.
var policyApplyHolds sync.Map // *Client → func(key string) bool

// SetPolicyApplyHoldForTest makes c skip every incoming cluster_policies row
// whose key hold reports true. A skipped WAL statement is acknowledged like
// any other, so the row reaches c afterwards only by anti-entropy. nil clears
// it. Tests only.
func (c *Client) SetPolicyApplyHoldForTest(hold func(key string) bool) {
	if hold == nil {
		policyApplyHolds.Delete(c)
		return
	}
	policyApplyHolds.Store(c, hold)
}

// policyApplyHeld reports whether an incoming cluster_policies row of key is
// held off this client.
func (c *Client) policyApplyHeld(key string) bool {
	v, ok := policyApplyHolds.Load(c)
	return ok && v.(func(string) bool)(key)
}

// walPolicyApplyHeld is policyApplyHeld for one incoming WAL statement.
func (c *Client) walPolicyApplyHeld(s Statement) bool {
	if _, ok := policyApplyHolds.Load(c); !ok || len(s.Params) == 0 {
		return false
	}
	return structuralTableLabel(s.SQL) == "cluster_policies" && c.policyApplyHeld(coerceString(s.Params[0]))
}

// mergePolicyApplyHeld is policyApplyHeld for one incoming anti-entropy row.
func (c *Client) mergePolicyApplyHeld(table string, columns []string, row []interface{}) bool {
	if table != "cluster_policies" {
		return false
	}
	if _, ok := policyApplyHolds.Load(c); !ok {
		return false
	}
	i := indexOf(columns, "key")
	return i >= 0 && i < len(row) && c.policyApplyHeld(coerceString(row[i]))
}
