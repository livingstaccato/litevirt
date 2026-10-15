package daemon

import (
	"context"

	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/grpcapi"
)

// wirePeerHAState sets fc.PeerHAState from the server's recorded Ready
// answers. No-op until HA disarm is implemented.
func (d *Daemon) wirePeerHAState(fc *failover.Coordinator, svc *grpcapi.Server) {}

// wireFenceCandidates installs the server's fence-candidate hook. No-op until
// HA disarm is implemented.
func (d *Daemon) wireFenceCandidates(svc *grpcapi.Server) {}

// startHAPolicyCache starts the refresher of the server's HA policy cache.
// No-op until HA disarm is implemented.
func (d *Daemon) startHAPolicyCache(ctx context.Context, svc *grpcapi.Server) {}

// startHADisarmPreRecord starts the lease holder's first-use record of
// ha_disarm. No-op until HA disarm is implemented.
func (d *Daemon) startHADisarmPreRecord(ctx context.Context, fc *failover.Coordinator) {}
