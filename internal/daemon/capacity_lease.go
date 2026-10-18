package daemon

import "github.com/litevirt/litevirt/internal/corrosion"

// capacityLeaseMaxAge is how long an admission lease may sit nonterminal before the
// sweep treats it as orphaned. See corrosion.RPCScopedLeaseMaxAge.
//
// Resize is never affected (its lease rides the workload operation id, outside
// the capacity kind); migration/drain leases span the whole transfer and age
// against corrosion.TransferCapacityLeaseMaxAge inside the sweep instead of this
// RPC-scoped ceiling.
const capacityLeaseMaxAge = corrosion.RPCScopedLeaseMaxAge
