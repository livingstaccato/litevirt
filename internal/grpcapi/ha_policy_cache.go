package grpcapi

import "sync"

// haPolicyCache is this node's in-memory copy of the cluster HA policy row.
// known is false until the first successful load.
type haPolicyCache struct {
	mu       sync.RWMutex
	known    bool
	disarmed bool
	policyAt string // the row's updated_at exactly as stored; "" when there is no row
}
