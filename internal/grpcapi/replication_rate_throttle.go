package grpcapi

import (
	"sync"

	"github.com/litevirt/litevirt/internal/pbsstore"
)

// replicationRateThrottles holds one shared throttle per replication schedule
// with a bandwidth limit, keyed by the schedule.
type replicationRateThrottles struct {
	mu sync.Mutex
	m  map[string]*pbsstore.Throttle
}
