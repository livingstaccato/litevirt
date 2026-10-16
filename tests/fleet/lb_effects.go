package fleet

// Every fleet node owns these effects; no command or global runner is used.
func (f *NetProvFake) DefaultRouteIface() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lbRoutes++
	return "fleet-uplink"
}
func (f *NetProvFake) EnableIPForwarding() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lbForwards++
	return nil
}
func (f *NetProvFake) InterfaceForIP(string) string { return "fleet-uplink" }

// waitLBWork requires the scenario to finish its producer requests first.
// Peer requests can still register new work on an earlier node in the scan.
func (c *Cluster) waitLBWork() { c.waitLBWorkObserved(nil) }
func (c *Cluster) waitLBWorkObserved(observe func(*Node)) {
	previous := make([]uint64, len(c.Nodes))
	havePrevious := false
	for {
		stable := havePrevious
		for i, n := range c.Nodes {
			generation := n.Server.WaitNetworkWork()
			if !havePrevious || generation != previous[i] {
				stable = false
			}
			previous[i] = generation
			if observe != nil {
				observe(n)
			}
		}
		if stable {
			return
		}
		havePrevious = true
	}
}
