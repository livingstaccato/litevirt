package fleet

// openClusterPolicyGate opens the cluster-policy gate on every node, as the
// durable failover_scope_v1 latch does on a cluster whose hosts all run this
// release: placement generations are kept, and a migration target's stub
// records are honoured (an unlatched target honours none).
func (c *Cluster) openClusterPolicyGate() {
	for _, n := range c.Nodes {
		n.DB.SetClusterPolicyGate(func() bool { return true })
	}
}
