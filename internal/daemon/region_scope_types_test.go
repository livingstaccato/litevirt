package daemon

import (
	"github.com/litevirt/litevirt/internal/failover"
	"github.com/litevirt/litevirt/internal/grpcapi"
	"github.com/litevirt/litevirt/internal/health"
)

// The failover coordinator finds the region-scoped decide gate and promoter by
// type assertion on what the daemon wires into it (fc.Gate = d.checker,
// fc.Promoter = svc). A production type that stopped implementing either would
// still compile and would quietly refuse every region-scoped recovery. These
// fail the build instead.
var (
	_ failover.RegionGate           = (*health.Checker)(nil)
	_ failover.RegionScopedPromoter = (*grpcapi.Server)(nil)
	// The pre-fence fence_state_v1 read uses Latched (no Ping) when the gate
	// has it; without it every fence would wait on a Ping sweep first.
	_ failover.LatchReader = (*health.Checker)(nil)
)
